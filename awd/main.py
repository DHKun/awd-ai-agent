"""CLI 入口（plan: main.py）。

数据流（IMPLEMENTATION_PLAN §3）：
config → scheduler.spawn(targets)
  → probe (并发) → context_builder 压缩
  → llm.analyze(ctx) → schema 校验 → payload_gen
  → runner 执行 → evidence 回流 Finding
  → flag_submit 提取+提交
  → DEFENSE: hash_monitor 基线 + waf 热加载

用法：
  python -m awd.main run          # 全流程（侦察→打点→提交）
  python -m awd.main recon        # 仅侦察（打印 TargetContext）
  python -m awd.main defense      # 防御端（基线+轮询，Ctrl-C 退出）
  python -m awd.main report       # 输出 findings 汇总
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Optional

from loguru import logger

from awd.config import Settings, load_settings
from awd.config import ScopeGuard
from awd.defense.hash_monitor import HashMonitor
from awd.defense.rollback import Rollback
from awd.defense.waf import Waf
from awd.exploit.flag_submit import FlagSubmitter
from awd.exploit.payload_gen import SemanticDict, generate_payloads
from awd.exploit.runner import ExploitRunner
from awd.llm.analyze import Analyzer
from awd.llm.client import LLMClient
from awd.models import Finding, TargetContext, TaskState
from awd.recon.probe import Prober
from awd.scheduler import run_probe_pool
from awd.store import Store


def _setup_logging(settings: Settings) -> None:
    logger.remove()
    logger.add(sys.stderr, level=settings.logging.level)
    if settings.logging.file:
        logger.add(settings.logging.file, level="DEBUG", rotation="10 MB", retention=3)


class Agent:
    """全流水线编排：唯一持有各模块实例的地方（模块间只经 models 类型流转）。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope = ScopeGuard(settings.scope)
        self.store = Store(settings.storage.db_path)
        self.prober = Prober(
            settings.recon,
            scope_guard=self.scope,
            probe_timeout=settings.concurrency.probe_timeout,
            token_budget=settings.budgets.context_token_budget,
            tls_verify=settings.recon.tls_verify,
        )
        self.llm_client = LLMClient(settings.llm)
        self.analyzer = Analyzer(
            self.llm_client, settings.llm,
            llm_timeout=settings.concurrency.llm_timeout,
        )
        self.semantic = SemanticDict()
        self.runner = ExploitRunner(
            settings.flags,
            exploit_timeout=settings.concurrency.exploit_timeout,
            failure_cap=settings.retry.exploit_failure_cap,
            tls_verify=settings.recon.tls_verify,
        )
        self.submitter = FlagSubmitter(settings.flags)
        self.waf = Waf(settings.defense.waf_rules_path) if settings.defense.waf_enabled else None
        self.rollback = Rollback() if settings.defense.rollback_enabled else None
        self.defense_state = None

    # ---- 侦察（RECON） -----------------------------------------------------------

    async def recon(self, targets: Optional[list[str]] = None) -> list[TargetContext]:
        """并发探测池：scope 内目标 → TargetContext 列表（坏目标降级留痕）。"""
        urls = targets or self.settings.targets
        # scope 守卫：越界目标拒绝（并留痕），不进入调度
        allowed, rejected = [], []
        for url in urls:
            try:
                self.scope.check(url)
                allowed.append(url)
            except Exception as e:  # ScopeError
                logger.error("scope 拒绝目标 {}: {}", url, e)
                rejected.append(url)
        if rejected:
            logger.error("被 scope 拒绝的目标（不调度）: {}", rejected)

        async def on_degraded(target: str, reason: str) -> None:
            await self.store.mark_state(target, TaskState.FAILED.value, error=reason)

        contexts, degraded = await run_probe_pool(
            allowed,
            self.prober.probe,
            max_concurrency=self.settings.concurrency.max_concurrency,
            timeout=self.settings.concurrency.probe_timeout,
            on_degraded=on_degraded,
            grace_timeout=self.settings.concurrency.scheduler_grace,
        )
        # 上下文也学进语义字典（动态词典）
        for ctx in contexts:
            self.semantic.learn_from_text("\n".join(ctx.recon_evidence))
        return contexts

    # ---- 分析 + 打点（ANALYZE → EXPLOIT → EXTRACT → SUBMIT） -----------------------

    async def exploit_target(self, ctx: TargetContext) -> list[Finding]:
        """单目标：分析 → 用例（LLM 优先 + 字典补充）→ 执行 → Finding 落库。"""
        # ANALYZE：LLM 定向用例（超时/失败自动降级字典）
        result = await self.analyzer.analyze(ctx)
        test_cases = [dict(tc, _source=result.source) for tc in result.test_cases]

        # EXPLOIT 用例补充：字典模板（指纹定向）
        dict_cases = generate_payloads(ctx, self.semantic)
        for tc in dict_cases:
            tc["_source"] = "dict"
        test_cases = test_cases + dict_cases

        # 执行（QUEUED→RUNNING→VERIFIED/CANDIDATE/FAILED）
        findings: list[Finding] = []
        for tc in test_cases:
            finding = await self.runner.run_case(ctx, tc)
            if finding is None:
                continue
            await self.store.upsert_finding(finding)
            findings.append(finding)
            # EXTRACT/SUBMIT：证据里带 flag 就提取（提交由 submit_url 决定）
            if "flag{" in finding.evidence.lower():
                for sr in await self.submitter.extract_and_submit(finding.evidence):
                    logger.info("flag {} submitted={} accepted={} ({})",
                                sr.flag, sr.submitted, sr.accepted, sr.detail)
        return findings

    # ---- 全流程 ---------------------------------------------------------------------

    async def run(self) -> None:
        """RECON → ANALYZE → EXPLOIT → EXTRACT → SUBMIT 全链路。"""
        await self.store.connect()
        try:
            contexts = await self.recon()
            if not contexts:
                logger.warning("无可用目标上下文（全部降级或为空）")
                return
            logger.info("侦察完成：{} 个上下文，开始打点", len(contexts))
            total_findings = 0
            for ctx in contexts:
                findings = await self.exploit_target(ctx)
                confirmed = [f for f in findings if f.status.value == "confirmed"]
                logger.info(
                    "target {} → {} findings（{} confirmed）",
                    ctx.url, len(findings), len(confirmed),
                )
                total_findings += len(findings)
            logger.info("全流程完成：共 {} findings，flag 台账 {} 条",
                        total_findings, len(self.submitter.ledger.flags))
        finally:
            await self.store.close()

    # ---- 防御端 -----------------------------------------------------------------------

    async def defense(self) -> None:
        """DEFENSE：基线快照 + 哈希轮询 + WAF 热加载（Ctrl-C 退出）。"""
        await self.store.connect()
        try:
            monitor = HashMonitor(
                self.settings.defense.watch_paths,
                poll_interval=self.settings.defense.hash_poll_interval,
            )
            state = monitor.snapshot_baseline()
            logger.info("防御基线就绪：{} 文件", len(state.baselines))
            rollback = self.rollback or Rollback()

            async def on_change(path: str, diff: str) -> None:
                # 变化段喂语义字典（挖高频 token）+ 尝试恢复
                self.semantic.learn_from_text(diff)
                logger.warning("文件变化：{}\n{}", path, diff[:500])
                rollback.try_restore(state, path)
                await self.store.save_defense_state(state)

            monitor.on_change = on_change
            logger.info("轮询中（{}s 间隔）— Ctrl-C 退出", self.settings.defense.hash_poll_interval)
            await monitor.run_forever()
        finally:
            await self.store.close()

    # ---- 报表 --------------------------------------------------------------------------

    async def report(self) -> None:
        await self.store.connect()
        try:
            findings = await self.store.get_findings()
            tasks = await self.store.list_tasks()
            print("=== AWD Agent 报表 ===")
            print(f"目标任务: {len(tasks)}")
            degraded = [t for t in tasks if t.state.value in ("failed", "blacklisted")]
            print(f"  降级/黑名单: {len(degraded)}")
            for t in degraded:
                print(f"    {t.target_id} [{t.state.value}] {t.error}")
            print(f"Findings: {len(findings)}")
            for f in findings:
                print(f"  [{f.status.value:9s}] {f.type.value:9s} {f.target_id} conf={f.confidence:.2f} "
                      f"payload={f.payload[:60]!r}")
            print(f"flag 台账: {len(self.submitter.ledger.flags)}")
        finally:
            await self.store.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="awd-agent", description="AWD 智能攻防半自动化 Agent")
    p.add_argument("command", choices=["run", "recon", "defense", "report"],
                   help="run=全流程 recon=仅侦察 defense=防御端 report=汇总")
    p.add_argument("--config", default=None, help="settings.yaml 路径（默认 config/settings.yaml）")
    p.add_argument("--targets", nargs="*", default=None, help="覆盖目标列表（仍受 scope 约束）")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings(args.config)
    if args.targets:
        settings.targets = args.targets
    _setup_logging(settings)
    agent = Agent(settings)

    if args.command == "run":
        asyncio.run(agent.run())
    elif args.command == "recon":
        asyncio.run(_recon_only(agent))
    elif args.command == "defense":
        try:
            asyncio.run(agent.defense())
        except KeyboardInterrupt:
            logger.info("防御端停止")
    elif args.command == "report":
        asyncio.run(agent.report())
    return 0


async def _recon_only(agent: Agent) -> None:
    await agent.store.connect()
    try:
        contexts = await agent.recon()
        for ctx in contexts:
            print(ctx.model_dump_json(indent=2, exclude={"recon_evidence"}))
            print("  evidence:", *ctx.recon_evidence, sep="\n    ")
    finally:
        await agent.store.close()


if __name__ == "__main__":
    sys.exit(main())
