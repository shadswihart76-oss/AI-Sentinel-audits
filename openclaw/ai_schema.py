from __future__ import annotations

from typing import Any

from .contracts import (
    AI_FINDING_ALLOWED_KEYS,
    AI_FINDING_ALLOWED_SEVERITIES,
    AI_FINDING_SCHEMA_VERSION,
)
from .scoring import normalize_severity


def validate_ai_finding(
    raw_item: Any,
    *,
    target: str,
    component: str,
    prompt_key: str,
    allow_unknown_fields: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    if not isinstance(raw_item, dict):
        return None, ["item is not an object"]

    unknown_fields = sorted(set(raw_item.keys()) - AI_FINDING_ALLOWED_KEYS)
    if unknown_fields and not allow_unknown_fields:
        errors.append(f"unknown fields present: {','.join(unknown_fields)}")

    normalized: dict[str, Any] = {}

    title = str(raw_item.get("title", "")).strip()
    if not title:
        errors.append("title is required")
        title = "AI security lead"
    normalized["title"] = title

    summary = str(raw_item.get("summary", "")).strip()
    if not summary:
        errors.append("summary is required")
        summary = "AI model flagged a potential security issue."
    normalized["summary"] = summary

    severity = normalize_severity(str(raw_item.get("severity", "Medium")))
    if severity not in AI_FINDING_ALLOWED_SEVERITIES:
        errors.append(f"severity must be one of: {','.join(AI_FINDING_ALLOWED_SEVERITIES)}")
        severity = "Medium"
    normalized["severity"] = severity

    category = str(raw_item.get("category", "")).strip() or prompt_key
    normalized["category"] = category
    normalized["asset"] = str(raw_item.get("asset", target)).strip() or target
    normalized["component"] = str(raw_item.get("component", component)).strip() or component
    normalized["source"] = str(raw_item.get("source", "ai_code_review")).strip() or "ai_code_review"

    recs = raw_item.get("recommendations", [])
    if isinstance(recs, str):
        recs = [recs]
    if not isinstance(recs, list):
        errors.append("recommendations must be a list or string")
        recs = []
    normalized["recommendations"] = [str(item).strip() for item in recs if str(item).strip()]

    metadata = raw_item.get("metadata", {})
    if not isinstance(metadata, dict):
        errors.append("metadata must be an object")
        metadata = {}

    likely_impact_raw = raw_item.get("likely_impact", 2)
    pattern_severity_raw = raw_item.get("pattern_severity", 2)
    code_confidence_raw = raw_item.get("code_confidence", 0.6)

    try:
        normalized["likely_impact"] = int(likely_impact_raw)
    except Exception:
        errors.append("likely_impact must be an integer")
        normalized["likely_impact"] = 2
    normalized["likely_impact"] = max(0, min(4, normalized["likely_impact"]))

    try:
        normalized["pattern_severity"] = int(pattern_severity_raw)
    except Exception:
        errors.append("pattern_severity must be an integer")
        normalized["pattern_severity"] = 2
    normalized["pattern_severity"] = max(0, min(4, normalized["pattern_severity"]))

    try:
        normalized["code_confidence"] = float(code_confidence_raw)
    except Exception:
        errors.append("code_confidence must be a number")
        normalized["code_confidence"] = 0.6
    normalized["code_confidence"] = max(0.0, min(1.0, normalized["code_confidence"]))

    metadata = dict(metadata)
    metadata.setdefault("ai_finding_schema_version", AI_FINDING_SCHEMA_VERSION)
    if errors:
        metadata["validation_errors"] = errors
    normalized["metadata"] = metadata

    return normalized, errors
