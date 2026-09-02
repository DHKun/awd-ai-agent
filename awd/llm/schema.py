"""Strict JSON 输出 Schema + 防幻觉/防死循环校验（plan: schema.py）。

- jsonschema 校验 LLM 输出结构，非法即视为无效（触发重试或丢弃）。
- evidence_refs 必须命中 TargetContext.recon_evidence 原文，否则整条 test_case 丢弃。
- confidence 上限钳制：LLM 产出只能是 candidate（执行器验证后才可 confirmed）。
"""

from __future__ import annotations

from typing import Any

import jsonschema

from awd.models import TargetContext

# LLM analyze 输出 Schema（Strict JSON 契约）
TEST_CASE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "test_cases": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "object",
                "properties": {
                    "type": {"enum": ["rce", "sqli", "file_read", "debug", "weak_auth"]},
                    "payload": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "target_route": {"type": "string", "maxLength": 512},
                    "target_param": {"type": "string", "maxLength": 64},
                    "evidence_refs": {"type": "string", "maxLength": 512},
                    "hypothesis": {"type": "string", "maxLength": 512},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "required": ["type", "payload", "evidence_refs", "confidence"],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "string", "maxLength": 512},
    },
    "required": ["test_cases"],
    "additionalProperties": False,
}


class SchemaValidator:
    """结构校验 + 防幻觉校验（两道闸）。"""

    def __init__(self, schema: dict[str, Any] = TEST_CASE_SCHEMA):
        self._validator = jsonschema.Draft202012Validator(schema)

    def validate_structure(self, output: dict) -> list[dict]:
        """结构校验。通过返回 test_cases 列表；非法抛 jsonschema.ValidationError。"""
        self._validator.validate(output)
        return output["test_cases"]

    def filter_grounding(
        self, test_cases: list[dict], ctx: TargetContext
    ) -> tuple[list[dict], list[dict]]:
        """防幻觉过滤：evidence_refs 必须命中 recon_evidence 原文。

        Returns:
            (kept, dropped)：存活的用例 / 被丢弃的用例（原因附在 dropped 条目里）。
        """
        kept: list[dict] = []
        dropped: list[dict] = []
        for tc in test_cases:
            refs = (tc.get("evidence_refs") or "").strip()
            if not refs:
                dropped.append({**tc, "_drop_reason": "empty evidence_refs"})
                continue
            # 命中判定：refs 的任一非空分片需出现在某条 recon_evidence 原文里
            pieces = [p for p in refs.split("|") if p.strip()]
            if not any(ctx.evidence_contains(p) for p in pieces):
                dropped.append({**tc, "_drop_reason": "evidence_refs not grounded"})
                continue
            kept.append(tc)
        return kept, dropped


def clamp_confidence(tc: dict) -> dict:
    """LLM 只提假设：把过高的 confidence 钳到 0.89（<0.9 高置信线），
    确保未经执行验证的用例不会被误当成高置信结论。"""
    c = float(tc.get("confidence", 0.0))
    tc["confidence"] = min(c, 0.89)
    return tc
