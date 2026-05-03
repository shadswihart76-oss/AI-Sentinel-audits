from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from .logging_utils import get_module_logger, setup_logging
from .scope_guard import set_scope_config, validate

CATEGORY_TOKENS: dict[str, tuple[str, ...]] = {
    "auth_access": ("user_id", "owner_id", "role", "permission", "authorize", "admin"),
    "ssrf": ("requests.get(", "requests.post(", "http://", "https://", "urlparse", "fetch("),
    "injection": ("eval(", "exec(", "select ", "insert ", "update ", "delete "),
    "logic_flaw": ("balance", "transaction", "transfer", "withdraw", "deposit"),
}


def _scan_file_tokens(file_path: Path) -> set[str]:
    text = file_path.read_text(encoding="utf-8", errors="ignore").lower()
    hits: set[str] = set()
    for token_group in CATEGORY_TOKENS.values():
        for token in token_group:
            if token in text:
                hits.add(token)
    return hits


def _category_for_tokens(tokens: set[str]) -> set[str]:
    categories: set[str] = set()
    for category, category_tokens in CATEGORY_TOKENS.items():
        if any(token in tokens for token in category_tokens):
            categories.add(category)
    return categories


def run_cross_file_reasoning(
    target: str,
    file_paths: list[str],
    ai_findings: list[dict[str, Any]],
    static_findings: list[dict[str, Any]],
    config: dict,
) -> list[dict[str, Any]]:
    logger = get_module_logger("cross_file_reasoning")
    setup_logging(config)
    set_scope_config(config)
    validate(target)

    module_cfg = config.get("modules", {}).get("cross_file_reasoning", {})
    if not module_cfg.get("enabled", False):
        return []

    min_files = max(2, int(module_cfg.get("min_files_for_chain", 2)))
    file_categories: dict[str, set[str]] = {}
    category_to_files: dict[str, set[str]] = defaultdict(set)

    for file_name in file_paths:
        path = Path(file_name)
        if not path.exists() or not path.is_file():
            continue
        tokens = _scan_file_tokens(path)
        categories = _category_for_tokens(tokens)
        if not categories:
            continue
        file_categories[str(path)] = categories
        for category in categories:
            category_to_files[category].add(str(path))

    output: list[dict[str, Any]] = []
    for category, files in category_to_files.items():
        if len(files) < min_files:
            continue
        severity = "High" if category in {"auth_access", "logic_flaw"} else "Medium"
        output.append(
            {
                "title": f"Cross-file {category} chain candidate",
                "asset": target,
                "component": "cross_file_reasoning",
                "summary": (
                    f"Detected {category} signals across {len(files)} files. "
                    "Review trust boundaries and data flow end-to-end."
                ),
                "severity": severity,
                "category": category,
                "source": "cross_file_reasoning",
                "likely_impact": 3 if severity == "High" else 2,
                "code_confidence": 0.62,
                "pattern_severity": 3 if severity == "High" else 2,
                "recommendations": [
                    "Trace identity/resource ownership checks across all involved files.",
                    "Verify input origin, validation, and sink protections across the full flow.",
                ],
                "metadata": {
                    "involved_files": sorted(files),
                    "cross_file_reasoning": True,
                },
            }
        )

    # Composite auth+ssrf multi-file chain heuristic.
    auth_files = category_to_files.get("auth_access", set())
    ssrf_files = category_to_files.get("ssrf", set())
    if len(auth_files) >= min_files and len(ssrf_files) >= min_files:
        output.append(
            {
                "title": "Cross-file trust-boundary chain (auth + SSRF signals)",
                "asset": target,
                "component": "cross_file_reasoning",
                "summary": (
                    "Authorization-sensitive and outbound request patterns co-exist across multiple files. "
                    "Review chained trust assumptions and destination validation."
                ),
                "severity": "High",
                "category": "trust_boundaries",
                "source": "cross_file_reasoning",
                "likely_impact": 3,
                "code_confidence": 0.68,
                "pattern_severity": 3,
                "recommendations": [
                    "Confirm per-request authorization is enforced before outbound interactions.",
                    "Enforce strict destination controls and data minimization for outbound requests.",
                ],
                "metadata": {
                    "auth_files": sorted(auth_files),
                    "ssrf_files": sorted(ssrf_files),
                    "cross_file_reasoning": True,
                },
            }
        )

    # If there are no chains but many raw findings, emit one low-confidence integrative hint.
    if not output and (len(ai_findings) + len(static_findings)) >= 10:
        output.append(
            {
                "title": "Cross-file review recommended",
                "asset": target,
                "component": "cross_file_reasoning",
                "summary": "High finding volume suggests manual cross-file data-flow review for chain-level risk.",
                "severity": "Low",
                "category": "cross_file_review",
                "source": "cross_file_reasoning",
                "likely_impact": 1,
                "code_confidence": 0.45,
                "pattern_severity": 1,
                "recommendations": [
                    "Trace identity, authorization, and input-validation boundaries across modules.",
                ],
                "metadata": {"cross_file_reasoning": True},
            }
        )

    logger.info("Cross-file reasoning complete target=%s findings=%s", target, len(output))
    return output
