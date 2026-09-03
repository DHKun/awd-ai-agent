"""数据模型层 — 模块间唯一上下文（与 IMPLEMENTATION_PLAN §2 / agent.md §4 严格对齐）。

字段以 plan 为准，不自行增删：
- TargetContext：侦察压缩后的目标上下文（模块间流转唯一载体）
- Finding：打点结果（含真实证据 + evidence_refs 命中校验所需字段）
- AgentTask：状态机载体（RECON→ANALYZE→EXPLOIT→EXTRACT→SUBMIT / DEFENSE）
- DefenseState：防御端（哈希基线/WAF/回滚）状态

AI 防幻觉约束落在模型上：
- Finding.status 只有执行器验证后才允许 confirmed（LLM 只能产 candidate）。
- Finding.evidence 必须命中 recon_evidence 原文（schema.analyze 校验）。
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ---- 状态机（agent.md §4）------------------------------------------------

class TaskState(str, Enum):
    RECON = "recon"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    EXTRACT = "extract"
    SUBMIT = "submit"
    DEFENSE = "defense"
    FAILED = "failed"      # 探测/执行降级（scheduler mark_state 用，不入状态机图）
    BLACKLISTED = "blacklisted"  # 失败达 retry cap 后的终态


class ExploitState(str, Enum):
    """EXPLOIT 子状态：QUEUED→RUNNING→VERIFIED/CANDIDATE/FAILED。"""
    QUEUED = "queued"
    RUNNING = "running"
    VERIFIED = "verified"
    CANDIDATE = "candidate"
    FAILED = "failed"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    CANDIDATE = "candidate"


class FindingType(str, Enum):
    RCE = "rce"
    SQLI = "sqli"
    FILE_READ = "file_read"
    DEBUG = "debug"
    WEAK_AUTH = "weak_auth"


class GeneratedBy(str, Enum):
    LLM = "llm"
    DICT = "dict"
    MANUAL = "manual"


# ---- 侦察层 ---------------------------------------------------------------

class RouteInfo(BaseModel):
    """探测到的路由摘要（plan: routes[]）。"""
    path: str
    method: str = "GET"
    status: int = 0
    params: list[str] = Field(default_factory=list)
    content_type: str = ""
    length: int = 0


class Fingerprint(BaseModel):
    """指纹归一化（plan: fingerprint）。"""
    server: str = ""
    framework: str = ""
    version_hint: str = ""


class RiskProbe(BaseModel):
    """风险探测点（plan: risk_probe）。"""
    dir_listing: bool = False
    debug_page: bool = False
    git_exposed: bool = False
    env_exposed: bool = False


class TargetContext(BaseModel):
    """侦察压缩后的目标上下文 — 模块间唯一流转载体。"""
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(default_factory=lambda: _new_id("t"))
    url: str
    fingerprint: Fingerprint = Field(default_factory=Fingerprint)
    routes: list[RouteInfo] = Field(default_factory=list)
    recon_evidence: list[str] = Field(
        default_factory=list,
        description="对原文的摘要片段，Finding.evidence_refs 必须能命中这里",
    )
    risk_probe: RiskProbe = Field(default_factory=RiskProbe)
    tokens_estimate: int = 0

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        if "://" not in v:
            raise ValueError(f"url 需带 scheme: {v!r}")
        return v

    def evidence_contains(self, fragment: str) -> bool:
        """evidence 命中判定（防幻觉第一原则的判据）。"""
        if not fragment:
            return False
        frag = fragment.strip()
        return any(frag in ev for ev in self.recon_evidence)


# ---- 打点层 ---------------------------------------------------------------

class Finding(BaseModel):
    """打点结果（plan: Finding，含真实证据）。"""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("f"))
    target_id: str
    type: FindingType
    payload: str
    evidence: str = Field(description="执行验证后的真实证据片段")
    evidence_refs: str = Field(
        default="",
        description="LLM 引用的 recon_evidence 片段（防幻觉：必须命中原文）",
    )
    confidence: float = 0.0
    status: FindingStatus = FindingStatus.CANDIDATE
    generated_by: GeneratedBy = GeneratedBy.MANUAL

    @field_validator("confidence")
    @classmethod
    def _check_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence 必须在 [0,1]: {v}")
        return v


# ---- 状态机载体 -------------------------------------------------------------

class AgentTask(BaseModel):
    """单目标的调度载体：状态机 + 重试计数 + 黑名单。"""
    model_config = ConfigDict(extra="forbid")

    target_id: str
    url: str
    state: TaskState = TaskState.RECON
    exploit_state: ExploitState = ExploitState.QUEUED
    attempts: int = 0
    failure_count: int = 0
    blacklisted: bool = False
    error: str = ""
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    def touch(self) -> None:
        self.updated_at = time.time()


# ---- 防御层 -----------------------------------------------------------------

class FileBaseline(BaseModel):
    """文件哈希监控基线 (size, mtime, sha256)（plan §4）。"""
    path: str
    size: int
    mtime: float
    sha256: str


class DefenseState(BaseModel):
    """防御端状态：哈希基线 + WAF 命中 + 回滚记录。"""
    model_config = ConfigDict(extra="forbid")

    target_id: str = "defense"
    baselines: dict[str, FileBaseline] = Field(default_factory=dict)
    changed_files: list[str] = Field(default_factory=list)
    waf_hits: list[dict[str, Any]] = Field(default_factory=list)
    last_rollback: str = ""
    updated_at: float = Field(default_factory=time.time)


__all__ = [
    "TaskState", "ExploitState", "FindingStatus", "FindingType", "GeneratedBy",
    "RouteInfo", "Fingerprint", "RiskProbe", "TargetContext",
    "Finding", "AgentTask", "FileBaseline", "DefenseState",
]
