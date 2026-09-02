"""持久化层 — aiosqlite（jobs / results / state）。

约束（agent.md §6）：
- main 里显式 `await store.connect()` 后才可用。
- 单写入者即可（读并发低），不做额外写并发优化。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import aiosqlite
from loguru import logger

from awd.models import AgentTask, DefenseState, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    target_id   TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    state       TEXT NOT NULL,
    exploit_state TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    blacklisted     INTEGER NOT NULL DEFAULT 0,
    error           TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    id           TEXT PRIMARY KEY,
    target_id    TEXT NOT NULL,
    type         TEXT NOT NULL,
    payload      TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '',
    confidence   REAL NOT NULL,
    status       TEXT NOT NULL,
    generated_by TEXT NOT NULL,
    created_at   REAL NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_id);

CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    """aiosqlite 持久化封装（jobs=AgentTask / results=Finding / state=kv）。"""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """显式建连 + 建表（幂等）。"""
        if self._db is not None:
            return
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        logger.debug("store connected: {}", self.db_path)

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
            logger.debug("store closed: {}", self.db_path)

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Store 未 connect()，先在 main 中显式调用")
        return self._db

    # ---- jobs（状态机） -----------------------------------------------------

    async def upsert_task(self, task: AgentTask) -> None:
        await self.db.execute(
            """INSERT INTO jobs (target_id,url,state,exploit_state,attempts,failure_count,
                                 blacklisted,error,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(target_id) DO UPDATE SET
                 url=excluded.url, state=excluded.state, exploit_state=excluded.exploit_state,
                 attempts=excluded.attempts, failure_count=excluded.failure_count,
                 blacklisted=excluded.blacklisted, error=excluded.error,
                 updated_at=excluded.updated_at""",
            (task.target_id, task.url, task.state.value, task.exploit_state.value,
             task.attempts, task.failure_count, int(task.blacklisted),
             task.error, task.created_at, task.updated_at),
        )
        await self.db.commit()

    async def mark_state(self, target_id: str, state: str, error: str = "", **fields: Any) -> None:
        """状态机落库（scheduler 降级路径用它记 failed）。"""
        sets = ["state = ?", "error = ?", "updated_at = strftime('%s','now')"]
        params: list[Any] = [state, error]
        for key, value in fields.items():
            sets.append(f"{key} = ?")
            params.append(value)
        params.append(target_id)
        cur = await self.db.execute(
            f"UPDATE jobs SET {', '.join(sets)} WHERE target_id = ?", params)
        if cur.rowcount == 0:  # 尚未入库的目标降级时也要留痕
            await self.db.execute(
                """INSERT INTO jobs (target_id,url,state,exploit_state,attempts,failure_count,
                                     blacklisted,error,created_at,updated_at)
                   VALUES (?,?,'failed','failed',0,0,0,?,strftime('%s','now'),strftime('%s','now'))""",
                (target_id, target_id, error))
        await self.db.commit()
        # 提交后失效游标，避免 rowcount 读到陈旧值影响后续判断
        await cur.close()

    async def get_task(self, target_id: str) -> Optional[AgentTask]:
        async with self.db.execute("SELECT * FROM jobs WHERE target_id = ?", (target_id,)) as cur:
            row = await cur.fetchone()
        return self._row_to_task(row) if row else None

    async def list_tasks(self) -> list[AgentTask]:
        async with self.db.execute("SELECT * FROM jobs ORDER BY created_at") as cur:
            rows = await cur.fetchall()
        return [self._row_to_task(r) for r in rows]

    @staticmethod
    def _row_to_task(row: Any) -> AgentTask:
        return AgentTask(
            target_id=row[0], url=row[1], state=row[2], exploit_state=row[3],
            attempts=row[4], failure_count=row[5], blacklisted=bool(row[6]),
            error=row[7] or "", created_at=row[8], updated_at=row[9],
        )

    # ---- results（Finding） ---------------------------------------------------

    async def upsert_finding(self, finding: Finding) -> None:
        await self.db.execute(
            """INSERT INTO results (id,target_id,type,payload,evidence,evidence_refs,
                                    confidence,status,generated_by)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 evidence=excluded.evidence, confidence=excluded.confidence,
                 status=excluded.status""",
            (finding.id, finding.target_id, finding.type.value, finding.payload,
             finding.evidence, finding.evidence_refs, finding.confidence,
             finding.status.value, finding.generated_by.value),
        )
        await self.db.commit()

    async def get_findings(self, target_id: Optional[str] = None) -> list[Finding]:
        if target_id is None:
            q, params = "SELECT * FROM results ORDER BY created_at", ()
        else:
            q, params = "SELECT * FROM results WHERE target_id = ? ORDER BY created_at", (target_id,)
        async with self.db.execute(q, params) as cur:
            rows = await cur.fetchall()
        return [
            Finding(
                id=r[0], target_id=r[1], type=r[2], payload=r[3], evidence=r[4],
                evidence_refs=r[5] or "", confidence=r[6], status=r[7], generated_by=r[8],
            )
            for r in rows
        ]

    # ---- state（kv：DefenseState 等） -----------------------------------------

    async def put_state(self, key: str, value: Any) -> None:
        blob = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        await self.db.execute(
            "INSERT INTO state (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, blob),
        )
        await self.db.commit()

    async def get_state(self, key: str) -> Any:
        async with self.db.execute("SELECT value FROM state WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        blob = row[0]
        try:
            return json.loads(blob)
        except (json.JSONDecodeError, TypeError):
            return blob

    async def save_defense_state(self, ds: DefenseState) -> None:
        await self.put_state("defense_state", ds.model_dump(mode="json"))

    async def load_defense_state(self) -> Optional[DefenseState]:
        raw = await self.get_state("defense_state")
        if raw is None:
            return None
        return DefenseState.model_validate(raw)
