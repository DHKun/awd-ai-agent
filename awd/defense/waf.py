"""轻量 WAF（plan: waf.py — yaml 规则热加载匹配）。

- 规则结构与 rules/waf_rules.yaml 对齐：pattern + location + action + enabled。
- 热加载：rules 文件 mtime 变化即自动重读（无需重启）。
- match() 判定请求是否命中拦截规则。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from loguru import logger


@dataclass
class WafRule:
    id: str
    name: str
    pattern: str
    location: list[str] = field(default_factory=lambda: ["query"])
    action: str = "log"        # block | log
    enabled: bool = True
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compile(self) -> "WafRule":
        self._compiled = re.compile(self.pattern)
        return self

    def matches(self, text: str) -> bool:
        if self._compiled is None:
            self.compile()
        return bool(self._compiled.search(text))  # type: ignore[union-attr]


@dataclass
class WafVerdict:
    blocked: bool = False
    rule_ids: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


class Waf:
    """规则匹配器（热加载）。输入是「请求特征文本」的各 location 切片。"""

    def __init__(self, rules_path: str | Path):
        self.rules_path = Path(rules_path)
        self.rules: list[WafRule] = []
        self._loaded_mtime: float = 0.0
        self._load()

    # ---- 加载 / 热加载 -----------------------------------------------------------

    def _load(self) -> None:
        if not self.rules_path.exists():
            logger.warning("waf rules not found: {}（空规则启动）", self.rules_path)
            self.rules = []
            return
        mtime = self.rules_path.stat().st_mtime
        if mtime == self._loaded_mtime and self.rules:
            return  # 未变化
        raw = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        rules: list[WafRule] = []
        for item in raw.get("rules", []):
            try:
                rule = WafRule(
                    id=item["id"], name=item.get("name", item["id"]),
                    pattern=item["pattern"],
                    location=item.get("location", ["query"]),
                    action=item.get("action", "log"),
                    enabled=item.get("enabled", True),
                ).compile()
                rules.append(rule)
            except (KeyError, re.error) as e:
                logger.error("waf rule invalid, skipped: {} ({})", item.get("id"), e)
        self.rules = rules
        self._loaded_mtime = mtime
        logger.info("waf loaded {} rules from {}", len(rules), self.rules_path)

    def hot_reload_if_changed(self) -> bool:
        """热加载入口：文件 mtime 变了就重读。返回是否发生了重载。"""
        if not self.rules_path.exists():
            return False
        mtime = self.rules_path.stat().st_mtime
        if mtime != self._loaded_mtime:
            self._loaded_mtime = 0.0  # 强制重读
            self._load()
            return True
        return False

    # ---- 匹配 -----------------------------------------------------------------

    def match(
        self,
        *,
        path: str = "",
        query: str = "",
        body: str = "",
        header: str = "",
    ) -> WafVerdict:
        """对请求特征做规则匹配。location 决定看哪个切片。"""
        verdict = WafVerdict()
        self.hot_reload_if_changed()  # 每次匹配前检查热加载（读 mtime 廉价）

        sections = {"path": path, "query": query, "body": body, "header": header}
        for rule in self.rules:
            if not rule.enabled:
                continue
            target_text = " ".join(sections.get(loc, "") for loc in rule.location)
            if target_text and rule.matches(target_text):
                verdict.rule_ids.append(rule.id)
                verdict.actions.append(rule.action)
                if rule.action == "block":
                    verdict.blocked = True
        return verdict

    # ---- 防御动作记录 ------------------------------------------------------------

    def record_hit(self, verdict: WafVerdict, request_desc: str) -> dict:
        hit = {
            "time": time.time(),
            "request": request_desc[:200],
            "rules": verdict.rule_ids,
            "actions": verdict.actions,
            "blocked": verdict.blocked,
        }
        return hit
