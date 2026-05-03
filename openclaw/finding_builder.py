from __future__ import annotations

import re
from pathlib import Path

from .logging_utils import get_module_logger, setup_logging
from .models import Finding
from .scoring import (
    score_finding,
)
from .scope_guard import set_scope_config, validate

_OWNERSHIP_SIGNAL_TERMS = (
    "ownership",
    "insecure direct object reference",
    "idor",
    "authenticated identity",
    "user identifier",
    "per-resource authorization",
)

_AUTH_BINDING_PATTERNS = (
    re.compile(r"get_current_user_id\s*\(", re.IGNORECASE),
    re.compile(r"wp_get_current_user\s*\(", re.IGNORECASE),
    re.compile(r"\bcurrent_user_can\s*\(", re.IGNORECASE),
    re.compile(r"\breq\.user\b", re.IGNORECASE),
    re.compile(r"\brequest\.user\b", re.IGNORECASE),
    re.compile(r"\bauth\(\)\s*->\s*id\s*\(", re.IGNORECASE),
    re.compile(r"\buser_from_token\b", re.IGNORECASE),
    re.compile(r"\bprincipal\b", re.IGNORECASE),
)

_REQUEST_IDENTITY_PATTERNS = (
    re.compile(r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"](?:user|user_id|userid|account|account_id)['\"]", re.IGNORECASE),
    re.compile(r"\breq\.(?:params|query|body)\.(?:user|userId|user_id|account|accountId|account_id)\b", re.IGNORECASE),
    re.compile(
        r"\brequest\.(?:args|get|post|params|query|form|values|json)\s*\(\s*['\"](?:user|user_id|userid|account|account_id)['\"]",
        re.IGNORECASE,
    ),
    re.compile(r"\bparams\s*\[\s*['\"](?:user_id|userid|account_id)['\"]\s*\]", re.IGNORECASE),
)


def _normalize_item(target: str, item: Finding | dict) -> Finding:
    if isinstance(item, Finding):
        if not item.asset:
            item.asset = target
        return item

    raw = dict(item)
    raw.setdefault("asset", target)
    return Finding.from_dict(raw)


def _sort_key(item: Finding, rank_by: list[str]) -> tuple:
    rank_values = []
    for criterion in rank_by:
        if criterion == "likely_impact":
            rank_values.append(item.likely_impact)
        elif criterion == "code_confidence":
            rank_values.append(item.code_confidence)
        elif criterion == "pattern_severity":
            rank_values.append(item.pattern_severity)
        elif criterion == "severity":
            rank_values.append(item.severity_score())
        else:
            rank_values.append(0)
    rank_values.append(item.severity_score())
    return tuple(rank_values)


def _apply_scoring_heuristics(finding: Finding, module_cfg: dict) -> Finding:
    scoring_cfg = module_cfg.get("scoring", {})
    severity_enabled = bool(scoring_cfg.get("severity_heuristics", True))
    confidence_enabled = bool(scoring_cfg.get("confidence_heuristics", True))
    impact_enabled = bool(scoring_cfg.get("impact_heuristics", True))
    pattern_enabled = bool(scoring_cfg.get("pattern_severity_heuristics", True))

    scored = score_finding(finding.severity, finding, finding.code_confidence)
    if severity_enabled:
        finding.severity = scored["severity"]
    if confidence_enabled:
        finding.code_confidence = scored["code_confidence"]
    if impact_enabled:
        finding.likely_impact = scored["likely_impact"]
    if pattern_enabled:
        finding.pattern_severity = scored["pattern_severity"]
    finding.metadata = dict(finding.metadata or {})
    finding.metadata.setdefault("scoring_contract_version", scored["scoring_contract_version"])
    return finding


def _is_ownership_auth_finding(finding: Finding) -> bool:
    if finding.category.strip().lower() != "auth_access":
        return False
    text = f"{finding.title} {finding.summary}".lower()
    return any(term in text for term in _OWNERSHIP_SIGNAL_TERMS)


def _load_component_text(component: str, cache: dict[str, str | None]) -> str | None:
    key = component.strip()
    if not key:
        return None
    if key in cache:
        return cache[key]
    try:
        path = Path(key)
        if not path.exists() or not path.is_file():
            cache[key] = None
            return None
        text = path.read_text(encoding="utf-8", errors="ignore")
        cache[key] = text
        return text
    except Exception:
        cache[key] = None
        return None


def _passes_precision_gates(finding: Finding, module_cfg: dict, component_cache: dict[str, str | None], logger) -> bool:
    precision_cfg = module_cfg.get("precision_gates", {}) if isinstance(module_cfg, dict) else {}
    ownership_gate_enabled = bool(precision_cfg.get("auth_ownership_binding", True))
    if not ownership_gate_enabled:
        return True
    if not _is_ownership_auth_finding(finding):
        return True

    text = _load_component_text(finding.component, component_cache)
    if not text:
        return True

    has_auth_binding = any(pattern.search(text) for pattern in _AUTH_BINDING_PATTERNS)
    has_request_identity = any(pattern.search(text) for pattern in _REQUEST_IDENTITY_PATTERNS)

    if has_auth_binding and not has_request_identity:
        logger.info(
            "Precision gate dropped auth ownership finding component=%s title=%s",
            finding.component,
            finding.title,
        )
        return False
    return True


def normalize_and_rank_findings(
    target: str,
    raw_findings: list[Finding | dict],
    config: dict,
) -> list[Finding]:
    logger = get_module_logger("finding_builder")
    setup_logging(config)
    set_scope_config(config)
    validate(target)

    module_cfg = config.get("modules", {}).get("findings", {})
    deduplicate = bool(module_cfg.get("deduplicate", True))
    rank_by = [str(x) for x in module_cfg.get("rank_by", [])]
    component_cache: dict[str, str | None] = {}

    normalized = [_normalize_item(target, item) for item in raw_findings]
    normalized = [_apply_scoring_heuristics(item, module_cfg) for item in normalized]
    normalized = [
        item
        for item in normalized
        if _passes_precision_gates(item, module_cfg, component_cache, logger)
    ]

    if deduplicate:
        deduped: dict[str, Finding] = {}
        for finding in normalized:
            deduped[finding.fingerprint()] = finding
        normalized = list(deduped.values())

    normalized.sort(key=lambda item: _sort_key(item, rank_by), reverse=True)
    logger.info(
        "Finding builder complete target=%s raw=%s normalized=%s deduplicate=%s",
        target,
        len(raw_findings),
        len(normalized),
        deduplicate,
    )
    return normalized
