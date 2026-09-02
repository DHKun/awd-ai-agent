"""test_scheduler — 并发池验收（agent.md §6 / AI_INIT 第一阶段启动动作 #3）。

验收：50 个假目标、3 个模拟超时，断言整体完成且坏目标被降级记录。
附加：并发上限约束生效、单点异常不阻塞全局、降级回调被调用。
"""

from __future__ import annotations

import asyncio

import pytest

from awd.models import TargetContext
from awd.scheduler import Scheduler, run_probe_pool

# AI_INIT 验收场景：50 假目标，其中 3 个模拟超时
TOTAL = 50
SLOW = 3
FAST = TOTAL - SLOW


def make_targets() -> list[str]:
    return [f"http://10.0.0.{i}:8080" for i in range(1, TOTAL + 1)]


def slow_target(url: str) -> bool:
    return url.endswith((":8080",)) and int(url.rsplit(".", 1)[1].split(":")[0]) in (17, 33, 49)


async def fake_probe(url: str) -> TargetContext:
    if slow_target(url):
        await asyncio.sleep(30)  # 模拟超时（远超 pool timeout）
    await asyncio.sleep(0.01)
    return TargetContext(url=url)


@pytest.mark.asyncio
async def test_pool_completes_with_degraded_bad_targets():
    """50 目标含 3 超时：整体完成，坏目标降级记录，好目标全部产出。"""
    degraded_seen: list[str] = []
    degraded_reasons: list[str] = []

    async def on_degraded(target: str, reason: str) -> None:
        degraded_seen.append(target)
        degraded_reasons.append(reason)

    contexts, degraded = await run_probe_pool(
        make_targets(),
        fake_probe,
        max_concurrency=50,
        timeout=0.5,
        on_degraded=on_degraded,
    )

    assert len(contexts) == FAST, "好目标应全部产出上下文"
    assert len(degraded) == SLOW, "3 个慢目标应被降级"
    assert all(r == "timeout" for _, r in degraded), "降级原因应为 timeout"
    assert degraded_seen == [t for t, _ in degraded], "on_degraded 回调应覆盖全部降级"
    # 坏目标不在成功列表里
    degraded_urls = {t for t, _ in degraded}
    assert all(c.url not in degraded_urls for c in contexts)


@pytest.mark.asyncio
async def test_semaphore_limits_concurrency():
    """max_concurrency 生效：同时在飞的探测数不超过上限。"""
    inflight = 0
    peak = 0

    async def probe(url: str) -> TargetContext:
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0.02)
        inflight -= 1
        return TargetContext(url=url)

    targets = [f"http://10.0.1.{i}:80" for i in range(40)]
    await run_probe_pool(targets, probe, max_concurrency=5, timeout=5.0)

    assert peak <= 5, f"并发峰值 {peak} 超过 Semaphore 上限 5"
    assert peak > 1, "应有并发发生（否则测试无意义）"


@pytest.mark.asyncio
async def test_single_exception_degrades_only_that_target():
    """单目标抛异常：只降级该目标，其余全部完成（不阻塞全局）。"""

    async def probe(url: str) -> TargetContext:
        if url.endswith(".7:80"):
            raise ConnectionError("connection refused")
        await asyncio.sleep(0.01)
        return TargetContext(url=url)

    targets = [f"http://10.0.2.{i}:80" for i in range(1, 21)]
    contexts, degraded = await run_probe_pool(targets, probe, timeout=2.0)

    assert len(contexts) == 19
    assert degraded == [("http://10.0.2.7:80", "connection refused")]


@pytest.mark.asyncio
async def test_scheduler_records_state_via_store(tmp_path):
    """降级路径走 store.mark_state(failed, error=...) 留痕（plan §4 伪代码行为）。

    注意：调度器以 URL 字符串为调度目标键，on_degraded 收到的即 URL；
    mark_state 对未入库键自动 INSERT 兜底留痕。
    """
    from awd.store import Store
    from awd.models import TaskState

    store = Store(tmp_path / "s.db")
    await store.connect()

    async def on_degraded(target: str, reason: str) -> None:
        await store.mark_state(target, TaskState.FAILED.value, error=reason)

    targets = make_targets()
    contexts, degraded = await run_probe_pool(
        targets, fake_probe, timeout=0.3, on_degraded=on_degraded,
    )

    assert len(degraded) == SLOW
    # 每个降级目标都以 URL 为键留痕（state=failed, error=timeout）
    for degraded_url, reason in degraded:
        task = await store.get_task(degraded_url)
        assert task is not None, f"降级目标 {degraded_url} 应落库留痕"
        assert task.state == TaskState.FAILED
        assert task.error == reason
    await store.close()


@pytest.mark.asyncio
async def test_grace_timeout_bounds_entire_pool():
    """gather 整体兜底超时：即使 worker 内部挂死，run 也能返回。"""

    async def hung_probe(url: str) -> TargetContext:
        await asyncio.sleep(60)

    # timeout 设很大（单目标不超时），靠 grace_timeout 兜底
    scheduler = Scheduler(
        hung_probe, max_concurrency=2, timeout=60.0, grace_timeout=0.2,
    )
    results = await scheduler.run(["http://10.9.9.1:80", "http://10.9.9.2:80"])
    assert results == []
