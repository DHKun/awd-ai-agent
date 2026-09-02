"""单目标异步探测（plan: probe.py — http/https, 兜底 raw）。

- httpx.AsyncClient 异步探测 config.recon.probe_routes + risk_routes。
- scheme 兜底：http 失败自动尝试 https（反之亦然）。
- 全部结果交给 context_builder 压缩成 TargetContext。
"""

from __future__ import annotations

from typing import Optional

import httpx
from loguru import logger

from awd.config import ReconConfig, ScopeGuard
from awd.models import RouteInfo, TargetContext
from awd.recon.context_builder import build_context
from awd.recon.fingerprint import fingerprint_headers

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}


def _swap_scheme(url: str) -> str:
    if url.startswith("https://"):
        return "http://" + url[len("https://"):]
    if url.startswith("http://"):
        return "https://" + url[len("http://"):]
    return url


def _params_from_url(path_with_q: str, common_params: list[str]) -> list[str]:
    """从响应里发现的 query 参数（限 common_params 词典内的才算有效命名）。"""
    from urllib.parse import parse_qs, urlsplit
    qs = urlsplit(path_with_q).query
    if not qs:
        return []
    names = set(parse_qs(qs).keys())
    return [p for p in common_params if p in names]


class Prober:
    """单目标探测器：并发打 probe_routes + risk_routes，产出 TargetContext。"""

    def __init__(
        self,
        recon: ReconConfig,
        scope_guard: Optional[ScopeGuard] = None,
        *,
        probe_timeout: float = 8.0,
        token_budget: int = 2000,
        tls_verify: bool = True,
    ):
        self.recon = recon
        self.scope_guard = scope_guard
        self.probe_timeout = probe_timeout
        self.token_budget = token_budget
        self.tls_verify = tls_verify

    async def probe(self, url: str) -> TargetContext:
        """入口：探测单目标 → TargetContext。越界即抛 ScopeError。

        https 目标默认开启证书校验；竞赛环境自签证书场景经
        settings.yaml `recon.tls_verify: false` 显式放行（默认仍为校验）。
        """
        if self.scope_guard is not None:
            self.scope_guard.check(url)

        routes: list[RouteInfo] = []
        evidence: list[str] = []
        fp_headers: dict[str, str] = {}
        risk = {"dir_listing": False, "debug_page": False,
                "git_exposed": False, "env_exposed": False}
        effective_url = url

        for attempt_url in (url, _swap_scheme(url)):
            try:
                async with httpx.AsyncClient(
                    timeout=self.probe_timeout, follow_redirects=True,
                    verify=self.tls_verify, headers=DEFAULT_HEADERS,
                ) as client:
                    effective_url = attempt_url
                    for path in self.recon.probe_routes + self.recon.risk_routes:
                        route, ev, fp, risk_hit = await self._probe_one(client, attempt_url, path)
                        if route is not None:
                            routes.append(route)
                            evidence.extend(ev)
                            fp_headers.update(fp)
                            for k, v in risk_hit.items():
                                risk[k] = risk[k] or v
                break  # 首个 scheme 成功即止（兜底：另一 scheme 下轮重试）
            except httpx.HTTPError as e:
                logger.debug("probe {} failed ({}), trying fallback scheme", attempt_url, type(e).__name__)
                continue

        return build_context(
            url=effective_url,
            routes=routes,
            header_samples=fp_headers,
            evidence_fragments=evidence,
            risk=risk,
            token_budget=self.token_budget,
        )

    async def _probe_one(
        self, client: httpx.AsyncClient, base: str, path: str,
    ) -> tuple[Optional[RouteInfo], list[str], dict[str, str], dict[str, bool]]:
        route: Optional[RouteInfo] = None
        evidence: list[str] = []
        fp_headers: dict[str, str] = {}
        risk_hit = {"dir_listing": False, "debug_page": False,
                    "git_exposed": False, "env_exposed": False}
        try:
            resp = await client.get(base.rstrip("/") + path)
        except httpx.HTTPError as e:
            logger.debug("GET {}{} -> {}", base, path, type(e).__name__)
            return None, evidence, fp_headers, risk_hit

        params = _params_from_url(str(resp.url), self.recon.common_params)
        route = RouteInfo(
            path=path,
            method="GET",
            status=resp.status_code,
            params=params,
            content_type=resp.headers.get("content-type", ""),
            length=len(resp.content),
        )
        for h in ("server", "x-powered-by", "set-cookie", "via"):
            v = resp.headers.get(h)
            if v:
                fp_headers[h] = v
                if h in ("server", "x-powered-by"):
                    evidence.append(f"{h}: {v}")

        body = resp.text[:4096]
        low = body.lower()
        if path.endswith("/robots.txt") and resp.status_code == 200 and "disallow" in low:
            evidence.append(f"robots.txt ok ({len(resp.content)}B): " + body[:100].replace("\n", "; "))
        if resp.status_code == 200:
            if "<title>index of</title>" in low or "directory listing" in low:
                risk_hit["dir_listing"] = True
                evidence.append("dir listing: " + body[:100].replace("\n", "; "))
            if "phpinfo()" in low or "php-version" in low:
                risk_hit["debug_page"] = True
                evidence.append("phpinfo page detected")
            if path.startswith("/.git"):
                risk_hit["git_exposed"] = True
                evidence.append(".git exposed: " + path)
            if path == "/.env" and ("=" in body and len(body) > 10):
                risk_hit["env_exposed"] = True
                evidence.append(".env exposed: " + body[:100].replace("\n", "; "))
            # 页面里出现的表单参数也收集（common_params 命中）
            for p in self.recon.common_params:
                if f'name="{p}"' in low and p not in params:
                    params.append(p)
            route.params = params
        return route, evidence, fp_headers, risk_hit
