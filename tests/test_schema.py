"""test_schema — 防幻觉/防死循环校验 + LLM client JSON 解析 + analyze 降级。

验收（路线图 Day 11-14）：
- 输出 100% 合法 JSON（结构校验拦截非法输出）。
- evidence_refs 不命中原文 → 整条 test_case 丢弃。
- LLM 超时/网络错误 → 字典降级，不阻塞。
- retry_cap / analysis_attempts_cap 生效。
"""

from __future__ import annotations

import asyncio

import pytest

from awd.config import LLMConfig
from awd.llm.analyze import Analyzer, fallback_test_cases
from awd.llm.client import LLMClient, LLMError
from awd.llm.prompt import ANALYZE_SYSTEM, build_analyze_user
from awd.llm.schema import SchemaValidator, clamp_confidence
from awd.models import Fingerprint, RouteInfo, TargetContext


def make_ctx() -> TargetContext:
    return TargetContext(
        target_id="t-test",
        url="http://10.0.0.5:8080",
        fingerprint=Fingerprint(server="nginx", framework="thinkphp", version_hint="5.0.24"),
        routes=[RouteInfo(path="/index.php", method="GET", status=200, params=["s"])],
        recon_evidence=[
            "server: nginx/1.18.0",
            "x-powered-by: ThinkPHP 5.0.24",
            "phpinfo page detected",
        ],
    )


class FakeClient(LLMClient):
    """伪 LLM：按脚本回放响应。"""

    def __init__(self, responses: list):
        # 不调用 super().__init__（不发真请求）；只借用类型
        self.cfg = LLMConfig(backend="ollama")
        self.responses = list(responses)
        self.calls = 0

    async def chat_json(self, system, user, **kw):
        self.calls += 1
        item = self.responses.pop(0) if self.responses else {"test_cases": []}
        if isinstance(item, Exception):
            raise item
        return item


GOOD_OUTPUT = {
    "test_cases": [
        {
            "type": "rce",
            "payload": "/index.php?s=index/\\think\\app/invokefunction&function=system&vars[0]=id",
            "target_route": "/index.php",
            "target_param": "s",
            "evidence_refs": "x-powered-by: ThinkPHP 5.0.24",
            "hypothesis": "ThinkPHP 5.0 invokefunction RCE",
            "confidence": 0.9,
        }
    ]
}


# ---- SchemaValidator ------------------------------------------------------

def test_structure_valid_passes():
    v = SchemaValidator()
    tcs = v.validate_structure(GOOD_OUTPUT)
    assert len(tcs) == 1 and tcs[0]["type"] == "rce"


@pytest.mark.parametrize("bad", [
    {"test_cases": "not-a-list"},
    {"test_cases": [{"type": "gopher", "payload": "x", "evidence_refs": "y", "confidence": 0.5}]},
    {"test_cases": [{"type": "rce", "payload": "", "evidence_refs": "y", "confidence": 0.5}]},
    {"test_cases": [{"type": "rce", "payload": "p", "evidence_refs": "y", "confidence": 5}]},
    {"test_cases": [{"type": "rce", "payload": "p", "evidence_refs": "y"}]},
    {"unexpected_key": 1},
])
def test_structure_invalid_raises(bad):
    v = SchemaValidator()
    with pytest.raises(Exception):
        v.validate_structure(bad)


def test_grounding_keeps_hit_and_drops_miss():
    v = SchemaValidator()
    ctx = make_ctx()
    tcs = [
        {"type": "rce", "payload": "p1", "evidence_refs": "x-powered-by: ThinkPHP 5.0.24", "confidence": 0.5},
        {"type": "debug", "payload": "p2", "evidence_refs": "phpinfo page detected", "confidence": 0.4},
        {"type": "sqli", "payload": "p3", "evidence_refs": "wordpress 6.2 detected", "confidence": 0.9},  # 幻觉
        {"type": "sqli", "payload": "p4", "evidence_refs": "", "confidence": 0.9},  # 空引用
    ]
    kept, dropped = v.filter_grounding(tcs, ctx)
    assert len(kept) == 2
    assert len(dropped) == 2
    assert dropped[0]["_drop_reason"] == "evidence_refs not grounded"
    assert dropped[1]["_drop_reason"] == "empty evidence_refs"


def test_clamp_confidence_caps_llm_claim():
    """LLM 自报 0.99 也会被钳到 ≤0.89 —— 未经验证不得高置信。"""
    tc = clamp_confidence({"confidence": 0.99})
    assert tc["confidence"] == 0.89
    tc2 = clamp_confidence({"confidence": 0.3})
    assert tc2["confidence"] == 0.3


# ---- LLMClient._parse_json --------------------------------------------------

def test_parse_json_plain():
    assert LLMClient._parse_json('{"a": 1}') == {"a": 1}


def test_parse_json_strips_markdown_fence():
    fenced = '```json\n{"a": 1}\n```'
    assert LLMClient._parse_json(fenced) == {"a": 1}


def test_parse_json_rejects_garbage():
    with pytest.raises(LLMError):
        LLMClient._parse_json("I think the target is vulnerable")
    with pytest.raises(LLMError):
        LLMClient._parse_json("[1,2,3]")  # 合法 JSON 但不是对象


# ---- prompt -----------------------------------------------------------------

def test_prompt_embeds_evidence_verbatim():
    ctx = make_ctx()
    user = build_analyze_user(ctx)
    for ev in ctx.recon_evidence:
        assert ev in user, f"证据原文应进 prompt: {ev}"
    assert ctx.url in user


# ---- Analyzer：重试/降级/防死循环 ----------------------------------------------

@pytest.mark.asyncio
async def test_analyzer_success_keeps_grounded():
    client = FakeClient([GOOD_OUTPUT])
    a = Analyzer(client, LLMConfig(), llm_timeout=1.0)
    res = await a.analyze(make_ctx())
    assert res.source == "llm"
    assert len(res.test_cases) == 1
    assert res.test_cases[0]["confidence"] <= 0.89  # 钳制生效
    assert client.calls == 1


@pytest.mark.asyncio
async def test_analyzer_retries_invalid_then_succeeds():
    client = FakeClient([
        {"bad": "shape"},       # 非法结构 → 重试
        GOOD_OUTPUT,            # 第二次合法
    ])
    a = Analyzer(client, LLMConfig(retry_cap=3), llm_timeout=1.0)
    res = await a.analyze(make_ctx())
    assert res.source == "llm"
    assert client.calls == 2


@pytest.mark.asyncio
async def test_analyzer_falls_back_to_dict_on_llm_timeout():
    client = FakeClient([LLMError("llm timeout after 20s")] * 3)
    a = Analyzer(client, LLMConfig(retry_cap=3), llm_timeout=1.0)
    res = await a.analyze(make_ctx())
    assert res.source == "dict"
    assert res.test_cases and all(tc["payload"].startswith("/") for tc in res.test_cases)
    assert "timeout" in res.error


@pytest.mark.asyncio
async def test_analyzer_all_ungrounded_counts_as_failure():
    # 输出合法但 evidence_refs 全部幻觉 → 丢弃并重试 → 耗尽后降级
    hallucinated = {
        "test_cases": [
            {"type": "rce", "payload": "p", "evidence_refs": "made up evidence", "confidence": 0.5}
        ]
    }
    client = FakeClient([hallucinated] * 3)
    a = Analyzer(client, LLMConfig(retry_cap=3), llm_timeout=1.0)
    res = await a.analyze(make_ctx())
    assert res.source == "dict"
    assert client.calls == 3  # 重试耗尽


@pytest.mark.asyncio
async def test_analyzer_attempts_cap_prevents_loop():
    """analysis_attempts_cap：同一目标超限后不再调用 LLM，直接字典降级。"""
    client = FakeClient([LLMError("down")] * 10)
    cfg = LLMConfig(retry_cap=1, analysis_attempts_cap=2)
    a = Analyzer(client, cfg, llm_timeout=1.0)
    ctx = make_ctx()
    await a.analyze(ctx)   # attempt 1
    await a.analyze(ctx)   # attempt 2
    calls_before = client.calls
    res = await a.analyze(ctx)  # attempt 3 → 直接降级，无 LLM 调用
    assert res.source == "dict"
    assert res.error == "analysis_attempts_cap"
    assert client.calls == calls_before
    assert a.attempts(ctx.target_id) == 2


@pytest.mark.asyncio
async def test_fallback_test_cases_route_normalized():
    ctx = make_ctx()
    tcs = fallback_test_cases(ctx)
    assert all(tc["payload"].startswith("/index.php") for tc in tcs)


# ---- 真 client 的超时语义（不起服务，只验证 wait_for 包装） ---------------------

@pytest.mark.asyncio
async def test_ollama_backend_times_out_fast():
    """Ollama 后端连不上时应在 llm_timeout 内抛 LLMError（而非挂死）。"""

    class SlowOllama(LLMClient):
        async def _chat_ollama(self, system, user, timeout, max_tokens):
            await asyncio.sleep(30)  # 模拟网络卡死

    cfg = LLMConfig(backend="ollama")
    cfg.ollama.base_url = "http://127.0.0.1:1"  # 不可达端口
    slow = SlowOllama(cfg)
    # chat_json 的 wait_for 应在 0.2s 内切掉挂死的后端调用
    with pytest.raises(LLMError, match="timeout"):
        await asyncio.wait_for(slow.chat_json("s", "u", timeout=0.2), timeout=2.0)
