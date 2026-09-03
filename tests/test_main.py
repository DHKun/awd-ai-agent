"""test_main — CLI Agent 编排层测试（tmp db + 本地假靶机 + 假 LLM）。

覆盖 awd/main.py（原 0% 覆盖）：
- Agent.run 全流程（recon → exploit → flag 提取落库）
- scope 越界目标拒绝
- report 输出格式
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from awd.config import load_settings
from awd.main import Agent, _setup_logging


class FakeTP(BaseHTTPRequestHandler):
    """假 ThinkPHP 靶机：invokefunction RCE + flag。"""

    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/index.php") and "invokefunction" in self.path and "vars" in self.path:
            body = b"uid=0(root) gid=0(root) groups=0(root)\nflag{main-e2e-ok}\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/" or self.path.startswith("/index.php"):
            body = b"<html><title>Home</title>index</html>"
            self.send_response(200)
            self.send_header("X-Powered-By", "ThinkPHP 5.0.24")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture(scope="module")
def target_url():
    srv = HTTPServer(("127.0.0.1", 0), FakeTP)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def make_agent(tmp_path, targets: list[str]) -> Agent:
    settings = load_settings()
    settings.targets = targets
    settings.storage.db_path = str(tmp_path / "awd.db")
    settings.logging.file = ""  # 不写日志文件
    _setup_logging(settings)
    return Agent(settings)


@pytest.mark.asyncio
async def test_agent_run_end_to_end(tmp_path, target_url):
    """全流程：假靶机 → LLM 不可用字典降级 → confirmed finding + flag 台账。"""
    agent = make_agent(tmp_path, [target_url])
    await agent.run()

    # finding 已落库（run 内部 close 了 store，重开读）
    await agent.store.connect()
    findings = await agent.store.get_findings()
    await agent.store.close()
    confirmed = [f for f in findings if f.status.value == "confirmed"]
    assert confirmed, "invokefunction RCE 应产生 confirmed finding"
    assert any("uid=0" in f.evidence for f in confirmed)
    assert agent.submitter.ledger.flags == ["flag{main-e2e-ok}"]


@pytest.mark.asyncio
async def test_agent_run_rejects_out_of_scope(tmp_path, capsys):
    """越界目标：scope 拒绝 + 不产生任何 finding/上下文。"""
    agent = make_agent(tmp_path, ["http://8.8.8.8:80"])
    await agent.run()  # 不应抛异常（拒绝并留痕）
    await agent.store.connect()
    findings = await agent.store.get_findings()
    await agent.store.close()
    assert findings == []
    assert agent.submitter.ledger.flags == []


@pytest.mark.asyncio
async def test_agent_run_all_targets_down(tmp_path):
    """全部目标不可达：优雅完成，无 findings。"""
    agent = make_agent(tmp_path, ["http://127.0.0.1:59906"])
    await agent.run()
    await agent.store.connect()
    findings = await agent.store.get_findings()
    await agent.store.close()
    assert findings == []


@pytest.mark.asyncio
async def test_agent_report_prints_summary(tmp_path, target_url, capsys):
    """report：打印目标任务数 / findings / flag 台账。"""
    agent = make_agent(tmp_path, [target_url])
    await agent.run()
    await agent.report()
    out = capsys.readouterr().out
    assert "AWD Agent 报表" in out
    assert "Findings:" in out


@pytest.mark.asyncio
async def test_agent_defense_detects_and_restores_tamper(tmp_path, target_url):
    """defense：基线 → 篡改 → 轮询检出 + 回滚恢复 + 状态落库。"""
    from awd.defense.hash_monitor import HashMonitor

    agent = make_agent(tmp_path, [target_url])
    await agent.store.connect()

    site = tmp_path / "www"
    site.mkdir()
    victim = site / "index.php"
    original = "<?php echo 'clean'; ?>\n"
    victim.write_text(original)

    agent.settings.defense.watch_paths = [str(site)]
    agent.settings.defense.hash_poll_interval = 0.05

    monitor = HashMonitor(
        agent.settings.defense.watch_paths,
        poll_interval=agent.settings.defense.hash_poll_interval,
    )
    state = monitor.snapshot_baseline()
    assert len(state.baselines) == 1

    rollback = agent.rollback
    # 回滚需要基线备份：先保存原始内容
    rollback.save_backup(victim, original)

    async def on_change(path: str, diff: str) -> None:
        agent.semantic.learn_from_text(diff)
        rollback.try_restore(state, path)
        await agent.store.save_defense_state(state)

    monitor.on_change = on_change

    # 模拟篡改
    victim.write_text("<?php eval($_GET['c']); ?>\n")
    changed = await monitor.poll_once()
    assert str(victim) in changed
    assert "eval" in changed[str(victim)]
    # 回滚已恢复原文
    assert victim.read_text() == original
    # 防御状态已落库
    ds = await agent.store.load_defense_state()
    assert ds is not None and ds.last_rollback.startswith("restored")
    await agent.store.close()


@pytest.mark.asyncio
async def test_agent_report_shows_degraded_targets(tmp_path, capsys):
    """report：降级目标（failed/blacklisted）列入报表。"""
    from awd.models import AgentTask, TaskState

    agent = make_agent(tmp_path, [])
    await agent.store.connect()
    t = AgentTask(target_id="bad-target", url="http://127.0.0.1:59908",
                  state=TaskState.FAILED, error="timeout")
    await agent.store.upsert_task(t)
    await agent.store.close()

    agent.submitter.ledger.add("flag{rep}")
    await agent.report()
    out = capsys.readouterr().out
    assert "bad-target [failed] timeout" in out
    assert "flag 台账: 1" in out
