"""System Prompt 模板（plan: prompt.py）。

只有这一处定义 LLM 的措辞与输出契约（awd/llm/schema.py 与之对齐）。
"""

from __future__ import annotations

from awd.models import TargetContext

ANALYZE_SYSTEM = """\
You are a security analyst assistant for an authorized Capture-The-Flag (AWD) training environment.

HARD RULES:
1. Output STRICT JSON only, matching this contract:
   {"test_cases": [{"type": "rce|sqli|file_read|debug|weak_auth",
                    "payload": "string, the exact request path+query to send",
                    "target_route": "string, optional",
                    "target_param": "string, optional",
                    "evidence_refs": "string, MUST be a verbatim fragment copied from the recon_evidence provided",
                    "hypothesis": "string, why you think this works",
                    "confidence": number in [0,1]}],
    "notes": "string, optional"}
2. GROUNDING: every test_case's evidence_refs MUST be copied verbatim from the
   recon_evidence lines given to you. If you cannot ground a hypothesis in that
   evidence, do not emit the test case.
3. You only propose hypotheses. Never claim a test is confirmed — that decision
   belongs to the executor after verification.
4. Target only the given routes/params of this single target. No targets outside it.
5. Max 10 test cases. Prefer precision over recall.
"""


def build_analyze_user(ctx: TargetContext) -> str:
    """User 消息：压缩后的 TargetContext（token 预算已在上游控制）。"""
    routes = "\n".join(
        f"  - {r.method} {r.path} status={r.status} params={r.params}"
        for r in ctx.routes
    ) or "  (none)"
    evidence = "\n".join(f"  - {e}" for e in ctx.recon_evidence) or "  (none)"
    risk = ", ".join(k for k, v in ctx.risk_probe.model_dump().items() if v) or "(none)"
    fp = ctx.fingerprint
    fp_line = f"{fp.server} / {fp.framework} {fp.version_hint}".strip(" /") or "(unknown)"

    return f"""Target: {ctx.url} (id={ctx.target_id})
Fingerprint: {fp_line}
Risk probes: {risk}

Routes:
{routes}

Recon evidence (verbatim — evidence_refs MUST quote from these lines):
{evidence}

Task: propose up to 10 precise test cases for this target, grounded ONLY in the
evidence above. Respond with strict JSON per the system contract."""
