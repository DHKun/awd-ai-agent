"""test_context — 上下文压缩验收（agent.md §6：压缩率 ≥ 98%）。

- 构造一个典型 AWD 靶机 raw HTTP 响应（nginx + ThinkPHP 首页，几十 KB 噪声）。
- 断言 TargetContext token 远小于 raw token（≥98% 压缩）且 token 预算生效。
- 断言 evidence 片段可被 TargetContext.evidence_contains 命中（防幻觉判据的原料）。
"""

from __future__ import annotations

import random
import string

from awd.models import RouteInfo
from awd.recon.context_builder import (
    build_context,
    compression_ratio,
    estimate_tokens,
)
from awd.recon.fingerprint import fingerprint_headers, is_known


def _make_raw_response(size_kb: int = 120) -> str:
    """模拟一个 ~120KB 的 raw HTTP 响应（含大量噪声 HTML）。"""
    noise = "".join(random.choices(string.ascii_letters + " \n<>", k=size_kb * 1024))
    return (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.18.0\r\n"
        "X-Powered-By: ThinkPHP 5.0.24\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "\r\n"
        "<html><head><title>Home</title></head><body>"
        + noise
        + "</body></html>"
    )


def _routes() -> list[RouteInfo]:
    return [
        RouteInfo(path="/", method="GET", status=200, params=["s", "id"], content_type="text/html", length=122880),
        RouteInfo(path="/index.php", method="GET", status=200, params=["s"], content_type="text/html", length=53210),
        RouteInfo(path="/robots.txt", method="GET", status=200, params=[], content_type="text/plain", length=233),
        RouteInfo(path="/.git/config", method="GET", status=404, params=[], content_type="text/html", length=153),
    ]


def test_fingerprint_normalization():
    fp = fingerprint_headers({
        "server": "nginx/1.18.0",
        "x-powered-by": "ThinkPHP 5.0.24",
    })
    assert fp.server == "nginx"
    assert fp.framework == "thinkphp"
    assert fp.version_hint == "5.0.24"
    assert is_known(fp)

    fp2 = fingerprint_headers({"server": "Apache/2.4.29 (Ubuntu)"})
    assert fp2.server == "apache" and fp2.version_hint == "2.4.29" and not is_known(fp2)

    fp3 = fingerprint_headers({"set-cookie": "laravel_session=xyz; path=/"})
    assert fp3.framework == "laravel"


def test_compression_ratio_meets_98_percent():
    raw = _make_raw_response()
    ctx = build_context(
        url="http://10.0.0.5:8080",
        routes=_routes(),
        header_samples={"server": "nginx/1.18.0", "x-powered-by": "ThinkPHP 5.0.24"},
        evidence_fragments=["Server: nginx/1.18.0", "X-Powered-By: ThinkPHP 5.0.24"],
        risk={"dir_listing": False, "debug_page": False, "git_exposed": False, "env_exposed": False},
        token_budget=2000,
    )
    ratio = compression_ratio(raw, ctx)
    assert ratio >= 0.98, f"压缩率 {ratio:.4f} 未达 98%"
    assert ctx.tokens_estimate <= 2000, "token 预算应生效"
    assert ctx.fingerprint.framework == "thinkphp"


def test_evidence_fragments_survive_and_are_hit():
    """recon_evidence 保留的片段必须能被 evidence_contains 命中（防幻觉原料）。"""
    ev = ["Server: nginx/1.18.0", ".git exposed: /.git/config", "phpinfo page detected"]
    ctx = build_context(
        url="http://10.0.0.5:8080",
        routes=_routes(),
        header_samples={"server": "nginx/1.18.0"},
        evidence_fragments=ev,
        risk={"dir_listing": False, "debug_page": True, "git_exposed": True, "env_exposed": False},
        token_budget=2000,
    )
    # 命中的应是"保留下来的原文子串"
    hit = [e for e in ev if ctx.evidence_contains(e)]
    assert len(hit) >= 2, "多数证据应存活并可命中"
    # 幻觉片段（原文不存在）必须不命中
    assert not ctx.evidence_contains("wordpress 6.2 detected")


def test_token_budget_trims_excess_evidence():
    """证据远超预算时从尾部裁剪，且 tokens_estimate 不超预算。"""
    many = [f"evidence fragment number {i} with some padding text to consume tokens" for i in range(200)]
    ctx = build_context(
        url="http://10.0.0.6:80/",
        routes=_routes(),
        header_samples={"server": "apache"},
        evidence_fragments=many,
        risk={},
        token_budget=300,  # 极小预算
        evidence_window=60,
    )
    assert ctx.tokens_estimate <= 300
    assert len(ctx.recon_evidence) < len(many), "超预算证据应被裁剪"


def test_estimate_tokens_monotonic():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 400) == 100
    assert estimate_tokens("a" * 800) > estimate_tokens("a" * 400)
