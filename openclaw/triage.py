from __future__ import annotations

from typing import Any

NOISE_PATH_TOKENS = (
    "/test/",
    "\\test\\",
    "/tests/",
    "\\tests\\",
    "/__tests__/",
    "\\__tests__\\",
    "/example/",
    "\\example\\",
    "/examples/",
    "\\examples\\",
    "/assets/",
    "\\assets\\",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _severity(value: Any) -> str:
    text = _text(value).lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    return mapping.get(text, "Medium")


def is_chain_candidate(finding: dict[str, Any]) -> bool:
    title = _text(finding.get("title")).lower()
    component = _text(finding.get("component")).lower()
    return "chain candidate" in title or component == "cross_file_reasoning"


def is_non_production_component(component: str) -> bool:
    value = component.lower()
    if ".test." in value or ".spec." in value:
        return True
    for token in NOISE_PATH_TOKENS:
        if token in value:
            return True
    return False


def is_report_ready_finding(finding: dict[str, Any]) -> bool:
    component = _text(finding.get("component"))
    if is_chain_candidate(finding):
        return False
    if component and is_non_production_component(component):
        return False
    return True


def filter_report_ready_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in findings if is_report_ready_finding(item)]


def is_validated_ready_finding(finding: dict[str, Any]) -> bool:
    if not is_report_ready_finding(finding):
        return False
    status = _text(finding.get("validation_status")).lower()
    if status in {"rejected", "invalid", "noise"}:
        return False
    severity = _severity(finding.get("severity"))
    # Validated queue focuses on likely bounty-submittable issues.
    if severity not in {"Critical", "High", "Medium"}:
        return False
    component = _text(finding.get("component"))
    summary = _text(finding.get("summary"))
    if not component or len(summary) < 20:
        return False
    recommendations = finding.get("recommendations", [])
    if not isinstance(recommendations, list) or not any(_text(item) for item in recommendations):
        return False
    return True


def filter_validated_ready_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in findings if is_validated_ready_finding(item)]


def validation_checklist_for_finding(finding: dict[str, Any]) -> list[str]:
    category = _text(finding.get("category")).lower()
    checks = [
        "Confirm this path executes in production runtime (not tests/examples/assets).",
        "Trace input source -> validation -> security-sensitive sink.",
    ]
    if category in {"auth_access", "authorization", "idor"}:
        checks.extend(
            [
                "Verify identity is derived from authenticated context, not caller-controlled parameters.",
                "Verify per-resource ownership/role checks before data access or state changes.",
            ]
        )
    elif category == "ssrf":
        checks.extend(
            [
                "Verify destination host/scheme allowlist enforcement before outbound requests.",
                "Verify private/loopback/link-local destinations are blocked at resolution time.",
            ]
        )
    elif category in {"logic_flaw", "trust_boundaries"}:
        checks.extend(
            [
                "Trace cross-file trust assumptions and verify each boundary enforces authorization.",
                "Verify security checks cannot be bypassed via alternate code paths.",
            ]
        )
    else:
        checks.append("Verify mitigation is covered by unit/integration tests for negative cases.")
    return checks
