"""并发调度池 — Semaphore + wait_for + gather(return_exceptions=True)（plan §4）。

验收（agent.md §6）：50 目标含 3 超时，整体完成且坏目标被降级记录。
单点超时/异常只降级该目标（记 failed + error），绝不阻塞全局调度。
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

from loguru import logger

from awd.models import TargetContext


class Scheduler:
    """asyncio 并发池：对 targets 并发执行 probe_fn，产出 TargetContext 流。

    - Semaphore(max_concurrency) 限并发。
    - 每目标 asyncio.wait_for(timeout) 保证单点超时可抛 TimeoutError。
    - gather(..., return_exceptions=True) 保证整体不因单点异常中断。
    - 失败目标经 on_degraded 回调落库（mark_state failed），首次超时只记 failed，
      进 blacklist 由重试计数触达 retry_cap 决定（状态机，见 models/agent.md §4）。
    """

    def __init__(
        self,
        probe_fn: Callable[[str], Awaitable[TargetContext]],
        *,
        max_concurrency: int = 50,
        timeout: float = 8.0,
        on_result: Optional[Callable[[TargetContext], Awaitable[None]]] = None,
        on_degraded: Optional[Callable[[str, str], Awaitable[None]]] = None,
        grace_timeout: Optional[float] = None,
    ):
        self.probe_fn = probe_fn
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.on_result = on_result
        self.on_degraded = on_degraded
        self.grace_timeout = grace_timeout
        self.results: list[TargetContext] = []
        self.degraded: list[tuple[str, str]] = []  # (target, reason)

    async def _worker(self, sem: asyncio.Semaphore, target: str) -> Optional[TargetContext]:
        async with sem:
            try:
                # wait_for 确保单目标超时可抛 TimeoutError，不阻塞全局
                ctx = await asyncio.wait_for(self.probe_fn(target), timeout=self.timeout)
            except asyncio.TimeoutError:
                # 首次超时只标记 failed（进 blacklist 由重试计数触达 retry_cap 决定，见状态机）
                await self._degrade(target, "timeout")
                return None
            except Exception as e:  # noqa: BLE001 — 单点异常只降级该目标
                await self._degrade(target, str(e) or type(e).__name__)
                return None
            if ctx is None:
                await self._degrade(target, "no-context")
                return None
            self.results.append(ctx)
            if self.on_result is not None:
                await self.on_result(ctx)
            return ctx

    async def _degrade(self, target: str, reason: str) -> None:
        logger.warning("probe {} degraded: {}", target, reason)
        self.degraded.append((target, reason))
        if self.on_degraded is not None:
            try:
                await self.on_degraded(target, reason)
            except Exception as e:  # noqa: BLE001 — 降级回调失败不反噬调度
                logger.error("on_degraded callback failed for {}: {}", target, e)

    async def run(self, targets: list[str]) -> list[TargetContext]:
        """并发执行全部目标；返回成功产出的 TargetContext 列表（坏目标已降级记录）。

        grace_timeout 到期时取消剩余 worker —— 但已完成的降级记录/结果保留。
        """
        sem = asyncio.Semaphore(self.max_concurrency)
        tasks = [asyncio.ensure_future(self._worker(sem, t)) for t in targets]
        try:
            if self.grace_timeout is not None:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.grace_timeout,
                )
            else:
                await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.TimeoutError:
            # 整体兜底超时：取消剩余 worker（已完成的降级记录保留），不向上抛
            logger.error(
                "probe pool grace timeout ({}s) — cancelling {} remaining workers",
                self.grace_timeout, sum(not t.done() for t in tasks),
            )
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(
            "probe pool done: {} ok / {} degraded / {} total",
            len(self.results), len(self.degraded), len(targets),
        )
        return self.results


async def run_probe_pool(
    targets: list[str],
    probe_fn: Callable[[str], Awaitable[TargetContext]],
    *,
    max_concurrency: int = 50,
    timeout: float = 8.0,
    on_result: Optional[Callable[[TargetContext], Awaitable[None]]] = None,
    on_degraded: Optional[Callable[[str, str], Awaitable[None]]] = None,
    grace_timeout: Optional[float] = None,
) -> tuple[list[TargetContext], list[tuple[str, str]]]:
    """函数式入口（plan §4 伪代码对应物）。

    Returns:
        (contexts, degraded)：成功上下文列表 + [(target, reason)] 降级记录。
    """
    scheduler = Scheduler(
        probe_fn,
        max_concurrency=max_concurrency,
        timeout=timeout,
        on_result=on_result,
        on_degraded=on_degraded,
        grace_timeout=grace_timeout,
    )
    contexts = await scheduler.run(targets)
    return contexts, scheduler.degraded
