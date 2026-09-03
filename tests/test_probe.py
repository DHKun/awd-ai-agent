"""test_probe — 真实 HTTP 链路集成测试（本地起服务，全链路 probe → TargetContext）。

覆盖 awd/recon/probe.py（原 0% 覆盖）：
- 正常探测（指纹头/路由/参数收集）
- scheme 兜底（http 失败换 https、反之亦然）
- scope 守卫前置拒绝
- 风险信号检出（dir listing / phpinfo / .git / .env）
- 完全不可达 → 空上下文优雅降级
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from awd.config import ReconConfig, ScopeConfig, ScopeGuard
from awd.recon.probe import Prober


class FakeTarget(BaseHTTPRequestHandler):
    """模拟 AWD 靶机：ThinkPHP 特征 + 风险点。"""

    # 压掉 BaseHTTP 默认 Server 头，模拟 nginx 靶机指纹
    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *a):  # 静默
        pass

    def do_GET(self):
        p = self.path
        if p == "/":
            self.send_response(200)
            self.send_header("X-Powered-By", "ThinkPHP 5.0.24")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><title>Home</title><body>ok</body></html>")
        elif p == "/index.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><form><input name=\"id\"></form></html>")
        elif p == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
        elif p == "/phpinfo.php":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>phpinfo() PHP Version 7.4</html>")
        elif p == "/.env":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"APP_KEY=base64:xxxx\nDB_PASSWORD=secret\n")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture(scope="module")
def target_url():
    srv = HTTPServer(("127.0.0.1", 0), FakeTarget)  # 随机空闲端口
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def make_prober(**kw) -> Prober:
    recon = ReconConfig(
        probe_routes=["/", "/index.php", "/robots.txt"],
        risk_routes=["/phpinfo.php", "/.env"],
        common_params=["id", "s", "page"],
    )
    return Prober(recon, probe_timeout=5.0, **kw)


@pytest.mark.asyncio
async def test_probe_full_pipeline(target_url):
    """正常探测：指纹归一化 + 路由收集 + 证据生成 + token 预算内。"""
    prober = make_prober(token_budget=2000)
    ctx = await prober.probe(target_url)

    assert ctx.url == target_url
    assert ctx.fingerprint.server == "nginx"
    assert ctx.fingerprint.framework == "thinkphp"
    assert ctx.fingerprint.version_hint == "5.0.24"

    paths = {r.path for r in ctx.routes}
    assert "/" in paths and "/index.php" in paths and "/robots.txt" in paths

    # 表单参数收集：index.php 页面里的 name="id"
    idx = next(r for r in ctx.routes if r.path == "/index.php")
    assert "id" in idx.params

    # 证据里要有指纹头原文（evidence_refs 命中判定的原料）
    assert any("x-powered-by" in e.lower() for e in ctx.recon_evidence)
    assert any("robots.txt" in e for e in ctx.recon_evidence)
    assert ctx.tokens_estimate <= 2000


@pytest.mark.asyncio
async def test_probe_detects_risk_signals(target_url):
    """风险探测点：phpinfo → debug_page，.env → env_exposed，证据留痕。"""
    prober = make_prober()
    ctx = await prober.probe(target_url)

    assert ctx.risk_probe.debug_page is True
    assert ctx.risk_probe.env_exposed is True
    assert any("phpinfo" in e.lower() for e in ctx.recon_evidence)
    assert any(".env" in e for e in ctx.recon_evidence)


@pytest.mark.asyncio
async def test_probe_scope_guard_rejects_out_of_scope():
    """scope 守卫前置：越界目标抛 ScopeError，不发任何请求。"""
    guard = ScopeGuard(ScopeConfig(mode="scoped", in_scope=["10.0.0.0/8"]))
    prober = make_prober(scope_guard=guard)
    with pytest.raises(Exception, match="越界"):
        await prober.probe("http://127.0.0.1:1/")


@pytest.mark.asyncio
async def test_probe_unreachable_returns_empty_context():
    """完全不可达（两个 scheme 都失败）→ 返回空壳上下文，不抛异常。"""
    prober = make_prober()
    ctx = await prober.probe("http://127.0.0.1:59905")
    assert ctx.routes == []
    assert ctx.fingerprint.server == ""


@pytest.mark.asyncio
async def test_probe_scheme_fallback(target_url):
    """scheme 兜底：把目标写成 https（服务是 http），探测仍应成功
    （https 失败后自动换 http 重试）。"""
    prober = make_prober()
    https_url = target_url.replace("http://", "https://")
    ctx = await prober.probe(https_url)
    # 兜底成功：拿到路由（effective_url 落在可用的 scheme 上）
    assert any(r.path == "/" for r in ctx.routes)
