"""test_waf / test_defense — WAF 规则匹配 + 热加载 + 哈希监控 + 回滚。

验收（路线图 Day 11-14）：WAF/校验单测通过。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from awd.defense.hash_monitor import HashMonitor
from awd.defense.rollback import Rollback
from awd.defense.waf import Waf
from awd.models import DefenseState

RULES_YAML = """\
rules:
  - id: waf-001
    name: sql-probe
    pattern: "(?i)(union\\\\s+select|sleep\\\\(\\\\d+\\\\))"
    location: [query, body]
    action: block
    enabled: true
  - id: waf-002
    name: path-traversal
    pattern: "(\\\\.\\\\./){2,}|/etc/passwd"
    location: [query, path]
    action: block
    enabled: true
  - id: waf-003
    name: disabled-rule
    pattern: "(?i)never-matches-me"
    location: [query]
    action: block
    enabled: false
"""


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    p = tmp_path / "waf_rules.yaml"
    p.write_text(RULES_YAML, encoding="utf-8")
    return p


# ---- WAF -----------------------------------------------------------------------

def test_waf_blocks_sqli(rules_file):
    waf = Waf(rules_file)
    v = waf.match(query="?id=1 UNION SELECT password FROM users--")
    assert v.blocked
    assert "waf-001" in v.rule_ids


def test_waf_blocks_traversal_in_path(rules_file):
    waf = Waf(rules_file)
    v = waf.match(path="/download?file=../../../etc/passwd")
    assert v.blocked
    assert "waf-002" in v.rule_ids


def test_waf_clean_request_passes(rules_file):
    waf = Waf(rules_file)
    v = waf.match(path="/index.php", query="?page=about", body="hello world")
    assert not v.blocked
    assert v.rule_ids == []


def test_waf_location_scoping(rules_file):
    """规则只看声明的 location：body 规则不看 header。"""
    waf = Waf(rules_file)
    # union select 只出现在 header → waf-001 的 location 是 [query, body]，不命中
    v = waf.match(header="X-Custom: UNION SELECT")
    assert not v.blocked


def test_waf_disabled_rule_skipped(rules_file):
    waf = Waf(rules_file)
    v = waf.match(query="?q=never-matches-me")
    assert not v.blocked and "waf-003" not in v.rule_ids


def test_waf_hot_reload(rules_file):
    """规则文件变化 → 自动热加载（不重启）。"""
    waf = Waf(rules_file)
    assert not waf.match(path="/admin-backdoor").blocked

    new_rules = RULES_YAML + """\
  - id: waf-099
    name: backdoor
    pattern: "admin-backdoor"
    location: [path]
    action: block
    enabled: true
"""
    # mtime 必须变化：写新内容
    rules_file.write_text(new_rules, encoding="utf-8")
    v = waf.match(path="/admin-backdoor")
    assert v.blocked
    assert "waf-099" in v.rule_ids


def test_waf_invalid_rule_skipped(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("rules:\n  - id: bad-1\n    name: x\n    pattern: '(unclosed'\n    location: [query]\n")
    waf = Waf(p)  # 不应抛异常
    assert all(r.id != "bad-1" for r in waf.rules)


def test_waf_missing_file_starts_empty(tmp_path):
    waf = Waf(tmp_path / "nonexistent.yaml")
    assert waf.rules == []
    assert not waf.match(query="?id=1 UNION SELECT").blocked


# ---- HashMonitor ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_hash_monitor_detects_modification(tmp_path):
    site = tmp_path / "www"
    site.mkdir()
    f = site / "index.php"
    f.write_text("<?php echo 'clean'; ?>\n")

    changes_seen: list[str] = []
    m = HashMonitor([str(site)], poll_interval=0.05,
                    on_change=lambda p, d: changes_seen.append(p))
    m.snapshot_baseline()

    # 无变化 → 空
    assert await m.poll_once() == {}

    # 篡改 → 检出变化段（含 diff 上下文）
    f.write_text("<?php echo 'hacked'; eval($_GET['c']); ?>\n")
    changed = await m.poll_once()
    assert str(f) in changed
    assert "eval" in changed[str(f)]
    assert changes_seen == [str(f)]
    # 变化后基线刷新：再 poll 无新变化
    assert await m.poll_once() == {}


@pytest.mark.asyncio
async def test_hash_monitor_detects_new_and_deleted(tmp_path):
    site = tmp_path / "www"
    site.mkdir()
    (site / "keep.txt").write_text("keep")

    m = HashMonitor([str(site)], poll_interval=0.05)
    m.snapshot_baseline()

    new_f = site / "webshell.php"
    new_f.write_text("<?php @eval($_POST[1]);")
    changed = await m.poll_once()
    assert str(new_f) in changed
    assert "[new file]" not in changed[str(new_f)] or "webshell" in changed[str(new_f)]

    new_f.unlink()
    changed = await m.poll_once()
    assert str(new_f) in changed
    assert changed[str(new_f)].startswith("[deleted]")


# ---- Rollback --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rollback_save_and_restore(tmp_path):
    rb = Rollback(tmp_path / "backup")
    victim = tmp_path / "www" / "index.php"
    victim.parent.mkdir(parents=True)
    original = "<?php echo 'clean'; ?>\n"
    victim.write_text(original)
    rb.save_backup(victim, original)

    # 攻击者篡改
    victim.write_text("<?php eval($_GET['c']); ?>\n")
    state = DefenseState()
    assert rb.try_restore(state, str(victim)) is True
    assert victim.read_text() == original
    assert state.last_rollback.startswith("restored")


def test_rollback_no_backup_degrades(tmp_path):
    rb = Rollback(tmp_path / "backup")
    state = DefenseState()
    assert rb.try_restore(state, "/nonexistent/path.php") is False
    assert "no backup" in state.last_rollback  # 降级记录，不抛异常


def test_rollback_record_waf_hit_rolls():
    rb = Rollback()
    state = DefenseState()
    for i in range(250):
        rb.record_waf_hit(state, {"i": i})
    assert len(state.waf_hits) == 200  # 滚动上限
