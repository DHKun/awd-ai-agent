"""降级/恢复编排（plan: rollback.py）。

防御端事件 → 动作编排：
- 文件被篡改（hash_monitor 检出变化段）→ 记录 + 尝试从基线恢复（如有备份）。
- WAF block 事件 → 聚合记录（DefenseState.waf_hits）。
- 恢复失败 → 降级（标记 last_rollback 失败原因），不抛出阻塞主流程。
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from loguru import logger

from awd.models import DefenseState


class Rollback:
    """降级/恢复编排器。

    restore(path, backup_text)：写回基线内容（备份存在时）。
    失败只记录到 DefenseState.last_rollback，不抛异常。
    """

    def __init__(self, backup_dir: str | Path = "defense_backup"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def save_backup(self, path: str | Path, content: str) -> Path:
        """为文件留基线备份（path 的 slug 命名）。"""
        p = Path(path)
        slug = str(p).replace("/", "_").lstrip("_")
        backup = self.backup_dir / slug
        backup.write_text(content, encoding="utf-8")
        logger.debug("backup saved: {} → {}", p, backup)
        return backup

    def try_restore(self, state: DefenseState, path: str) -> bool:
        """尝试从备份恢复文件。成功 true；无备份/失败 false（记录降级原因）。"""
        p = Path(path)
        slug = str(p).replace("/", "_").lstrip("_")
        backup = self.backup_dir / slug
        if not backup.exists():
            state.last_rollback = f"no backup for {path}"
            logger.warning("rollback: no backup for {}", path)
            return False
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
            state.last_rollback = f"restored {path}"
            logger.info("rollback: restored {}", path)
            return True
        except OSError as e:
            state.last_rollback = f"restore failed {path}: {e}"
            logger.error("rollback failed for {}: {}", path, e)
            return False

    def record_waf_hit(self, state: DefenseState, hit: dict) -> None:
        state.waf_hits.append(hit)
        # 只保留最近 200 条（防御日志滚动）
        if len(state.waf_hits) > 200:
            state.waf_hits = state.waf_hits[-200:]
