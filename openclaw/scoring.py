from __future__ import annotations

from typing import Any

from .contracts import SCORING_API_VERSION

SEVERITY_LABELS = ["Info", "Low", "Medium", "High", "Critical"]
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_ALIASES = {
    "warn": "medium",
    "warning": "medium",
    "moderate": "medium",
    "severe": "high",
}

CRITICAL_KEYWORDS = {
    "remote code execution",
    "rce",
    "private key",
    "secret key exposure",
    "wallet drain",
    "arbitrary code",
}

HIGH_KEYWORDS = {
    "authentication bypass",
    "authorization bypass",
    "privilege escalation",
    "idor",
    "insecure direct object reference",
    "fund transfer",
    "sensitive financial information",
}

MEDIUM_KEYWORDS = {
    "ssrf",
    "missing authorization",
    "input validation",
    "access control",
    "unsafe assumption",
}

LOW_KEYWORDS = {
    "logging issue",
    "hardening",
    "best practice",
    "defense in depth",
}

SOURCE_BASE_CONFIDENCE = {
    "semgrep": 0.82,
    "bandit": 0.78,
    "ai_code_review": 0.56,
    "unknown": 0.5,
}

HEDGING_WORDS = {"might", "could", "appears", "potential", "possibly"}


def clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(max_value, value))


def normalize_severity(value: str) -> str:
    lowered = str(value or "Medium").strip().lower()
    lowered = SEVERITY_ALIASES.get(lowered, lowered)
    score = SEVERITY_ORDER.get(lowered, SEVERITY_ORDER["medium"])
    return SEVERITY_LABELS[score]


def severity_score(value: str) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value).lower(), 2)


def _text_blob(finding_like: Any) -> str:
    title = str(getattr(finding_like, "title", "") or "")
    summary = str(getattr(finding_like, "summary", "") or "")
    recs = getattr(finding_like, "recommendations", []) or []
    source = str(getattr(finding_like, "source", "") or "")
    joined_recs = " ".join(str(x) for x in recs)
    return f"{title} {summary} {joined_recs} {source}".strip().lower()


def apply_severity_heuristic(existing_severity: str, finding_like: Any) -> str:
    text = _text_blob(finding_like)
    base_score = severity_score(existing_severity)

    if any(keyword in text for keyword in CRITICAL_KEYWORDS):
        base_score = max(base_score, 4)
    elif any(keyword in text for keyword in HIGH_KEYWORDS):
        base_score = max(base_score, 3)
    elif any(keyword in text for keyword in MEDIUM_KEYWORDS):
        base_score = max(base_score, 2)
    elif any(keyword in text for keyword in LOW_KEYWORDS):
        base_score = max(base_score, 1)

    return SEVERITY_LABELS[base_score]


def infer_likely_impact(severity: str, finding_like: Any) -> int:
    score = severity_score(severity)
    text = _text_blob(finding_like)
    if "financial" in text or "fund" in text or "wallet" in text:
        score = min(4, score + 1)
    return int(clamp(float(score), 0.0, 4.0))


def infer_pattern_severity(severity: str) -> int:
    return int(clamp(float(severity_score(severity)), 0.0, 4.0))


def infer_confidence(existing: float, finding_like: Any) -> float:
    source = str(getattr(finding_like, "source", "unknown") or "unknown").strip().lower()
    base = SOURCE_BASE_CONFIDENCE.get(source, SOURCE_BASE_CONFIDENCE["unknown"])
    confidence = max(float(existing), base)

    title = str(getattr(finding_like, "title", "") or "")
    summary = str(getattr(finding_like, "summary", "") or "")
    metadata = getattr(finding_like, "metadata", {}) or {}
    recs = getattr(finding_like, "recommendations", []) or []
    text = _text_blob(finding_like)

    if len(title) >= 12:
        confidence += 0.03
    if len(summary) >= 60:
        confidence += 0.06
    if recs:
        confidence += min(0.08, 0.03 * len(recs))
    if isinstance(metadata, dict) and metadata:
        confidence += 0.04
    if isinstance(metadata, dict) and (
        "line_number" in metadata
        or "start" in metadata
        or "end" in metadata
        or "check_id" in metadata
    ):
        confidence += 0.03
    if any(word in text for word in HEDGING_WORDS):
        confidence -= 0.06

    return round(clamp(confidence, 0.0, 1.0), 4)


def score_finding(existing_severity: str, finding_like: Any, existing_confidence: float) -> dict[str, Any]:
    """
    Stable scoring API contract v1.

    Returns normalized scoring fields for a finding-like object.
    """
    severity = apply_severity_heuristic(existing_severity, finding_like)
    return {
        "severity": severity,
        "likely_impact": infer_likely_impact(severity, finding_like),
        "pattern_severity": infer_pattern_severity(severity),
        "code_confidence": infer_confidence(existing_confidence, finding_like),
        "scoring_contract_version": SCORING_API_VERSION,
    }


__all__ = [
    "SCORING_API_VERSION",
    "normalize_severity",
    "severity_score",
    "apply_severity_heuristic",
    "infer_likely_impact",
    "infer_pattern_severity",
    "infer_confidence",
    "score_finding",
]
