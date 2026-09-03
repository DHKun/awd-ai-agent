"""raw → TargetContext 压缩（plan: context_builder.py — token 预算）。

验收（agent.md §6）：raw HTTP 响应 → TargetContext，token 压缩 ≥ 98%。
- 证据片段截窗（budgets.evidence_window）。
- tokens_estimate 以 BPE 近似（字符/4）计数并受 context_token_budget 约束。
- 超预算时按优先级裁剪（指纹头 > 风险证据 > 路由证据 > 路由表尾部）。
"""

from __future__ import annotations

from urllib.parse import urlsplit

from awd.models import RouteInfo, TargetContext
from awd.recon.fingerprint import fingerprint_headers

# GPT 系列 BPE 的工程近似：1 token ≈ 4 chars（英文/HTTP 文本经验值）。
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """token 估算（BPE 近似：字符数 / 4，最少 1）。"""
    if not text:
        return 0
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _clip(s: str, window: int) -> str:
    s = " ".join(s.split())  # 压平空白
    return s[:window]


def _dedup(fragments: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for f in fragments:
        key = f.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(f)
    return out


def build_context(
    url: str,
    routes: list[RouteInfo],
    header_samples: dict[str, str],
    evidence_fragments: list[str],
    risk: dict[str, bool],
    token_budget: int = 2000,
    evidence_window: int = 120,
) -> TargetContext:
    """把原始探测产物压缩成 TargetContext（token 预算内）。

    压缩优先级：指纹头证据 > 风险证据 > 路由证据 > 路由表（尾部裁剪）。
    recon_evidence 里保留的片段就是 evidence_refs 命中判定的原文。
    """
    host = urlsplit(url).hostname or url
    fp = fingerprint_headers(header_samples)

    evidence = _dedup([
        f"{h}: {v}" for h, v in header_samples.items() if h in ("server", "x-powered-by")
    ] + [
        _clip(f, evidence_window) for f in evidence_fragments
    ])

    # 风险证据置顶（LLM 最需要的信号）
    risk_evidence = [e for e in evidence if any(
        kw in e.lower() for kw in ("dir listing", "phpinfo", ".git", ".env", "robots"))]
    rest = [e for e in evidence if e not in risk_evidence]
    ordered = risk_evidence + rest

    def _tokens(items: list[str], n_routes: int | None = None) -> int:
        blob = " ".join(items)
        t = estimate_tokens(blob)
        if n_routes:
            t += estimate_tokens(str([r.model_dump() for r in routes[:n_routes]]))
        return t

    # 预算内尽量多保留证据；超预算从尾部裁
    kept = ordered
    while kept and _tokens(kept, len(routes)) > token_budget:
        kept = kept[:-1]
    kept_routes = routes
    while kept_routes and _tokens(kept, len(kept_routes)) > token_budget:
        kept_routes = kept_routes[:-1]

    tokens = _tokens(kept, len(kept_routes))
    return TargetContext(
        target_id=_target_id_for(host, url),
        url=url,
        fingerprint=fp,
        routes=kept_routes,
        recon_evidence=kept,
        risk_probe={
            "dir_listing": risk.get("dir_listing", False),
            "debug_page": risk.get("debug_page", False),
            "git_exposed": risk.get("git_exposed", False),
            "env_exposed": risk.get("env_exposed", False),
        },
        tokens_estimate=tokens,
    )


def _target_id_for(host: str, url: str) -> str:
    """稳定 target_id（同 host 复用，便于跨轮状态聚合）。"""
    suffix = urlsplit(url).port or ""
    slug = host.replace(".", "-").replace(":", "-")
    return f"t-{slug}" + (f"-{suffix}" if suffix else "")


def compression_ratio(raw_text: str, ctx: TargetContext) -> float:
    """验收用：raw 字符 → TargetContext 序列化 token 的压缩率。"""
    raw_tokens = estimate_tokens(raw_text) or 1
    ctx_tokens = estimate_tokens(ctx.model_dump_json()) or 1
    return 1.0 - (ctx_tokens / raw_tokens)
