"""配置层：读取 config/settings.yaml → 校验 → Settings。

- 值支持 ${ENV_VAR:-default} 展开。
- scope 守卫：mode: scoped 时仅放行 in_scope 网段内的目标，越界即拒绝。
- 禁止任何业务参数写死在代码里，全部从这里读取。
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, field_validator

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"


class ScopeError(ValueError):
    """目标越界（不在授权范围内）— 拒绝并抛出。"""


class ScopeConfig(BaseModel):
    mode: str = "scoped"
    in_scope: list[str] = Field(default_factory=list)

    @field_validator("mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v not in ("scoped", "open"):
            raise ValueError(f"scope.mode 只允许 scoped|open，得到 {v!r}")
        return v




class ConcurrencyConfig(BaseModel):
    max_concurrency: int = 50
    probe_timeout: float = 8.0
    exploit_timeout: float = 10.0
    llm_timeout: float = 20.0
    scheduler_grace: float = 30.0


class OpenAIConfig(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"


class OllamaConfig(BaseModel):
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b"


class LLMConfig(BaseModel):
    backend: str = "ollama"
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    temperature: float = 0.1
    retry_cap: int = 3
    analysis_attempts_cap: int = 2
    max_output_tokens: int = 2048

    @field_validator("backend")
    @classmethod
    def _check_backend(cls, v: str) -> str:
        if v not in ("openai", "ollama"):
            raise ValueError(f"llm.backend 只允许 openai|ollama，得到 {v!r}")
        return v


class BudgetsConfig(BaseModel):
    context_token_budget: int = 2000
    evidence_window: int = 120


class RetryConfig(BaseModel):
    exploit_failure_cap: int = 3


class FlagsConfig(BaseModel):
    pattern: str = r"flag\{[^\}]{1,256}\}"
    submit_url: str = ""


class StorageConfig(BaseModel):
    db_path: str = "awd_state.db"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "awd_agent.log"


class DefenseConfig(BaseModel):
    hash_poll_interval: float = 5.0
    watch_paths: list[str] = Field(default_factory=list)
    waf_rules_path: str = "rules/waf_rules.yaml"
    waf_enabled: bool = True
    rollback_enabled: bool = True


class ReconConfig(BaseModel):
    probe_routes: list[str] = Field(default_factory=lambda: ["/", "/index.php", "/robots.txt"])
    risk_routes: list[str] = Field(default_factory=list)
    common_params: list[str] = Field(default_factory=lambda: ["id", "s", "page", "file", "cmd", "name"])
    tls_verify: bool = True


class Settings(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    targets: list[str] = Field(default_factory=list)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    budgets: BudgetsConfig = Field(default_factory=BudgetsConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    flags: FlagsConfig = Field(default_factory=FlagsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    defense: DefenseConfig = Field(default_factory=DefenseConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)


def _expand_env(value: Any) -> Any:
    """递归展开 ${VAR} / ${VAR:-default}；未定义且无默认值时替换为空串。"""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(
            lambda m: os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else ""),
            value,
        )
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def load_settings(path: str | Path | None = None) -> Settings:
    """读取并校验 settings.yaml → Settings。路径缺省取 config/settings.yaml。"""
    p = Path(path) if path is not None else DEFAULT_SETTINGS_PATH
    if not p.exists():
        raise FileNotFoundError(f"settings 文件不存在: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    raw = _expand_env(raw)
    return Settings.model_validate(raw)


class ScopeGuard:
    """授权范围守卫：scoped 模式下，目标 IP 必须命中 in_scope 网段，越界即拒绝。"""

    def __init__(self, scope: ScopeConfig):
        self.mode = scope.mode
        self._nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._hosts: set[str] = set()
        if self.mode == "scoped":
            for entry in scope.in_scope:
                try:
                    self._nets.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    self._hosts.add(entry)  # 单主机名/IP 字面量

    def is_in_scope(self, url: str) -> bool:
        if self.mode != "scoped":
            return True
        host = urlparse(url).hostname or ""
        if host in self._hosts:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False  # 非 scoped 内的域名一律拒绝
        return any(ip in net for net in self._nets)

    def check(self, url: str) -> None:
        """越界即抛 ScopeError（调用方拒绝该目标，不静默放行）。"""
        if not self.is_in_scope(url):
            raise ScopeError(f"目标越界（未在 scope.in_scope 授权内）: {url}")
