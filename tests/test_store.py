"""test_store — aiosqlite 持久化层测试（tmp_path 隔离，原 61% 覆盖）。

补齐：upsert 覆盖更新 / list_tasks 排序 / get_findings 全表 /
put_state/get_state 往返 / save+load_defense_state / 未 connect 报错。
"""

from __future__ import annotations

import pytest

from awd.models import (
    AgentTask,
    DefenseState,
    Finding,
    FindingStatus,
    FindingType,
    GeneratedBy,
    TaskState,
)
from awd.store import Store


@pytest.fixture
async def store(tmp_path):
    s = Store(tmp_path / "t.db")
    await s.connect()
    yield s
    await s.close()


def make_task(tid: str, state: TaskState = TaskState.RECON) -> AgentTask:
    return AgentTask(target_id=tid, url=f"http://10.0.0.{tid}:80", state=state)


@pytest.mark.asyncio
async def test_upsert_task_overwrites(store):
    """同 target_id 二次 upsert：更新而非报错/重复。"""
    t = make_task("t-1")
    await store.upsert_task(t)
    t.state = TaskState.EXPLOIT
    t.attempts = 2
    await store.upsert_task(t)

    got = await store.get_task("t-1")
    assert got.state == TaskState.EXPLOIT
    assert got.attempts == 2

    tasks = await store.list_tasks()
    assert len(tasks) == 1


@pytest.mark.asyncio
async def test_list_tasks_order_and_blacklist(store):
    """多任务列表 + blacklisted 字段落库保真。"""
    for i in ("t-3", "t-1", "t-2"):
        await store.upsert_task(make_task(i))
    t = make_task("t-4", TaskState.BLACKLISTED)
    t.blacklisted = True
    await store.upsert_task(t)

    tasks = await store.list_tasks()
    assert [x.target_id for x in tasks] == ["t-3", "t-1", "t-2", "t-4"]
    assert tasks[3].blacklisted is True
    assert tasks[3].state == TaskState.BLACKLISTED


@pytest.mark.asyncio
async def test_mark_state_with_extra_fields(store):
    """mark_state 支持附加字段（failure_count 等）。"""
    await store.upsert_task(make_task("t-9"))
    await store.mark_state("t-9", TaskState.FAILED.value, error="boom",
                           failure_count=2, blacklisted=1)
    got = await store.get_task("t-9")
    assert got.state == TaskState.FAILED
    assert got.error == "boom"
    assert got.failure_count == 2
    assert got.blacklisted is True


@pytest.mark.asyncio
async def test_get_findings_all_and_filter(store):
    """get_findings() 全表 + 按 target 过滤。"""
    for tid in ("t-a", "t-a", "t-b"):
        f = Finding(target_id=tid, type=FindingType.RCE, payload="p",
                    evidence="uid=0", confidence=0.9,
                    status=FindingStatus.CONFIRMED, generated_by=GeneratedBy.DICT)
        await store.upsert_finding(f)

    assert len(await store.get_findings()) == 3
    only_a = await store.get_findings("t-a")
    assert len(only_a) == 2 and all(x.target_id == "t-a" for x in only_a)
    assert await store.get_findings("t-none") == []


@pytest.mark.asyncio
async def test_upsert_finding_updates_status(store):
    """同 finding id 二次 upsert：candidate → confirmed 状态更新。"""
    f = Finding(target_id="t-1", type=FindingType.DEBUG, payload="p",
                evidence="phpinfo", confidence=0.4,
                status=FindingStatus.CANDIDATE, generated_by=GeneratedBy.LLM)
    await store.upsert_finding(f)
    f.status = FindingStatus.CONFIRMED
    f.confidence = 0.95
    await store.upsert_finding(f)

    got = (await store.get_findings("t-1"))[0]
    assert got.status == FindingStatus.CONFIRMED
    assert got.confidence == 0.95
    assert len(await store.get_findings()) == 1  # 不产生重复行


@pytest.mark.asyncio
async def test_state_kv_roundtrip(store):
    """put_state/get_state：JSON dict / 纯字符串 / 缺键 None。"""
    await store.put_state("cfg", {"a": 1, "b": ["x"]})
    assert await store.get_state("cfg") == {"a": 1, "b": ["x"]}

    await store.put_state("plain", "hello")
    assert await store.get_state("plain") == "hello"

    assert await store.get_state("missing") is None


@pytest.mark.asyncio
async def test_defense_state_roundtrip(store):
    """DefenseState 序列化往返（baselines/waf_hits/changed_files）。"""
    from awd.models import FileBaseline

    ds = DefenseState(
        target_id="defense",
        baselines={"/var/www/index.php": FileBaseline(
            path="/var/www/index.php", size=100, mtime=1.5,
            sha256="abc" * 20 + "f")},
        changed_files=["/var/www/index.php"],
        waf_hits=[{"time": 1.0, "request": "GET /", "rules": ["waf-001"],
                   "actions": ["block"], "blocked": True}],
        last_rollback="restored /var/www/index.php",
    )
    await store.save_defense_state(ds)
    loaded = await store.load_defense_state()
    assert loaded is not None
    assert loaded.changed_files == ["/var/www/index.php"]
    assert loaded.baselines["/var/www/index.php"].sha256 == "abc" * 20 + "f"
    assert loaded.waf_hits[0]["blocked"] is True
    assert loaded.last_rollback.startswith("restored")


@pytest.mark.asyncio
async def test_store_requires_connect(tmp_path):
    """未 connect() 直接用 → RuntimeError 提示显式建连。"""
    s = Store(tmp_path / "nc.db")
    with pytest.raises(RuntimeError, match="connect"):
        await s.get_task("x")
    await s.connect()  # 幂等
    await s.connect()
    await s.close()
    await s.close()    # 幂等
