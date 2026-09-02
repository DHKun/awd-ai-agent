"""文件哈希监控（plan: hash_monitor.py — asyncio 轮询，仅变化段喂 LLM）。

基线快照 (size, mtime, sha256) → 轮询比较；仅将变化段（diff 文本）交给下游，
避免全量重算/全量重分析。
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from awd.models import DefenseState, FileBaseline


def _stat(path: Path) -> tuple[int, float, str]:
    data = path.read_bytes()
    stat = path.stat()
    return stat.st_size, stat.st_mtime, hashlib.sha256(data).hexdigest()


class HashMonitor:
    """轮询 watch_paths，产出变化文件清单与差异文本（变化段）。"""

    def __init__(
        self,
        watch_paths: list[str],
        *,
        poll_interval: float = 5.0,
        on_change: Optional[Callable[[str, str], object]] = None,  # (path, diff_text)
    ):
        self.watch_paths = [Path(p) for p in watch_paths]
        self.poll_interval = poll_interval
        self.on_change = on_change
        self.state = DefenseState()
        self._file_cache: dict[str, str] = {}   # path → 上一版内容（算 diff 用）
        self._running = False

    # ---- 基线 -----------------------------------------------------------------

    def snapshot_baseline(self) -> DefenseState:
        """建立/刷新基线快照 (size, mtime, sha256)。"""
        baselines: dict[str, FileBaseline] = {}
        for root in self.watch_paths:
            if not root.exists():
                logger.debug("watch path not exists: {}", root)
                continue
            files = [root] if root.is_file() else sorted(root.rglob("*"))
            for p in files:
                if not p.is_file():
                    continue
                try:
                    size, mtime, sha = _stat(p)
                except OSError as e:
                    logger.debug("cannot stat {}: {}", p, e)
                    continue
                baselines[str(p)] = FileBaseline(path=str(p), size=size, mtime=mtime, sha256=sha)
                self._file_cache[str(p)] = p.read_text(errors="replace")
        self.state.baselines = baselines
        return self.state

    # ---- 轮询 -----------------------------------------------------------------

    async def poll_once(self) -> dict[str, str]:
        """单轮比较。返回 {path: diff_text（仅变化段）}。

        新文件 → 全文；删除 → 标记；修改 → unified diff。
        """
        changed: dict[str, str] = {}
        current: dict[str, FileBaseline] = {}
        seen: set[str] = set()

        for root in self.watch_paths:
            if not root.exists():
                continue
            files = [root] if root.is_file() else sorted(root.rglob("*"))
            for p in files:
                if not p.is_file():
                    continue
                key = str(p)
                seen.add(key)
                try:
                    size, mtime, sha = _stat(p)
                except OSError:
                    continue
                current[key] = FileBaseline(path=key, size=size, mtime=mtime, sha256=sha)
                old = self.state.baselines.get(key)
                if old is None or old.sha256 != sha:
                    new_text = p.read_text(errors="replace")
                    old_text = self._file_cache.get(key, "")
                    diff = "\n".join(difflib.unified_diff(
                        old_text.splitlines(), new_text.splitlines(),
                        fromfile=key + " (baseline)", tofile=key + " (current)", lineterm="",
                    )) or f"[new file] {key} ({size}B)"
                    changed[key] = diff
                    self._file_cache[key] = new_text

        deleted = set(self.state.baselines) - seen
        for key in deleted:
            changed[key] = f"[deleted] {key}"
            self._file_cache.pop(key, None)
            current.pop(key, None)

        if changed:
            self.state.changed_files = sorted(changed)
            if self.on_change is not None:
                for path, diff in changed.items():
                    try:
                        r = self.on_change(path, diff)
                        if asyncio.iscoroutine(r):
                            await r
                    except Exception as e:  # noqa: BLE001 — 单文件回调失败不影响轮询
                        logger.warning("on_change({}) failed: {}", path, e)

        # 刷新基线（含新文件），删除的从基线移除
        self.state.baselines = current
        return changed

    async def run_forever(self) -> None:  # pragma: no cover — 编排层负责取消
        """轮询主循环（main 里 asyncio.create_task 启动，取消即停）。"""
        self._running = True
        while self._running:
            try:
                changed = await self.poll_once()
                if changed:
                    logger.warning("file changes detected: {}", list(changed))
            except Exception as e:  # noqa: BLE001 — 轮询永不因单轮异常退出
                logger.error("hash poll error: {}", e)
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        self._running = False
