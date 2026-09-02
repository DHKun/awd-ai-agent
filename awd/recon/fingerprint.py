"""指纹归一化（plan: fingerprint.py — server/框架/CMS → Fingerprint）。

从响应头/页面内容证据中提取并归一化为 server / framework / version_hint。
"""

from __future__ import annotations

import re

from awd.models import Fingerprint

# (正则, 归一化名) —— 命中即认为是该 server
_SERVER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)^nginx/([\w.]+)"), "nginx"),
    (re.compile(r"(?i)^apache(?:/([\w.]+))?"), "apache"),
    (re.compile(r"(?i)^lighttpd/([\w.]+)"), "lighttpd"),
    (re.compile(r"(?i)^iis(?:/([\w.]+))?"), "iis"),
    (re.compile(r"(?i)^caddy/?([\w.]*)"), "caddy"),
    (re.compile(r"(?i)^tomcat/?([\w.]*)"), "tomcat"),
    (re.compile(r"(?i)^jetty/?([\w.]*)"), "jetty"),
]

_FRAMEWORK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)thinkphp[\s/_v]*([\d.]+)"), "thinkphp"),
    (re.compile(r"(?i)laravel[\s/_v]*([\d.]*)"), "laravel"),
    (re.compile(r"(?i)django/?([\d.]*)"), "django"),
    (re.compile(r"(?i)flask"), "flask"),
    (re.compile(r"(?i)express/?([\d.]*)"), "express"),
    (re.compile(r"(?i)php/([\d.]+)"), "php"),
    (re.compile(r"(?i)think\\\\app|invokefunction"), "thinkphp"),
    (re.compile(r"(?i)wordpress/?([\d.]*)"), "wordpress"),
    (re.compile(r"(?i)discuz"), "discuz"),
    (re.compile(r"(?i)phpunit"), "phpunit"),
    (re.compile(r"(?i)spring|spring-boot"), "spring"),
    (re.compile(r"(?i)struts"), "struts"),
]

# Set-Cookie 特征 → 框架（服务端框架常用会话名）
_COOKIE_HINTS = {
    "thinkphp_show_page_trace": "thinkphp",
    "laravel_session": "laravel",
    "django_sessionid": "django",
    "jsessionid": "java",
    "ci_session": "codeigniter",
    "cakephp": "cakephp",
}


def fingerprint_headers(header_samples: dict[str, str], body_hint: str = "") -> Fingerprint:
    """从采样响应头 + 页面提示归一化出 Fingerprint。

    Args:
        header_samples: 探测到的响应头（server / x-powered-by / set-cookie / via）。
        body_hint: 页面内容摘要（用于框架/CMS 识别的补充证据）。
    """
    server, version = "", ""
    raw_server = (header_samples.get("server") or "").strip()
    if raw_server:
        for pat, name in _SERVER_PATTERNS:
            m = pat.search(raw_server)
            if m:
                server = name
                if m.groups() and m.group(1):
                    version = m.group(1)
                break
        if not server:
            server = raw_server.split("/")[0].lower()

    framework, fw_version = "", ""
    signals: list[str] = [
        header_samples.get("x-powered-by", ""),
        header_samples.get("via", ""),
    ]
    cookie = (header_samples.get("set-cookie") or "").lower()
    for key, name in _COOKIE_HINTS.items():
        if key in cookie:
            framework = name
            break
    for sig in signals + [body_hint]:
        if framework and not sig:
            continue
        for pat, name in _FRAMEWORK_PATTERNS:
            m = pat.search(sig or "")
            if m:
                framework = framework or name
                if m.groups() and m.group(1) and not fw_version:
                    fw_version = m.group(1)
                break
        if framework:
            break

    version_hint = fw_version or version
    return Fingerprint(server=server, framework=framework, version_hint=version_hint)


def is_known(fp: Fingerprint) -> bool:
    """已知指纹判定：有 framework 归一化结果即视为已知（可走定向模板）。"""
    return bool(fp.framework)
