from __future__ import annotations

from typing import Any

from .contracts import ENSEMBLE_SCORING_API_VERSION
from .scoring import clamp, normalize_severity, severity_score


def _group_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            str(item.get("component", "")).strip().lower(),
            str(item.get("category", "")).strip().lower(),
            str(item.get("title", "")).strip().lower(),
            str(item.get("summary", "")).strip().lower(),
        ]
    )


def _severity_from_weighted_score(value: float) -> str:
    if value >= 3.5:
        return "Critical"
    if value >= 2.5:
        return "High"
    if value >= 1.5:
        return "Medium"
    if value >= 0.5:
        return "Low"
    return "Info"


def merge_findings_with_ensemble(
    findings: list[dict[str, Any]],
    ensemble_cfg: dict[str, Any],
    static_hints: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if not bool(ensemble_cfg.get("enabled", False)):
        return findings

    model_weights_raw = ensemble_cfg.get("model_weights", {})
    model_weights: dict[str, float] = {}
    if isinstance(model_weights_raw, dict):
        for key, val in model_weights_raw.items():
            try:
                model_weights[str(key)] = float(val)
            except Exception:
                model_weights[str(key)] = 1.0

    category_priority_raw = ensemble_cfg.get("category_priority", {})
    category_priority: dict[str, float] = {}
    if isinstance(category_priority_raw, dict):
        for key, val in category_priority_raw.items():
            try:
                category_priority[str(key)] = float(val)
            except Exception:
                category_priority[str(key)] = 0.0

    min_consensus_models = max(1, int(ensemble_cfg.get("min_consensus_models", 2)))
    require_consensus = bool(ensemble_cfg.get("require_consensus", False))

    static_hint_components = {
        str(item.get("component", "")).strip().lower()
        for item in (static_hints or [])
        if str(item.get("component", "")).strip()
    }

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in findings:
        grouped.setdefault(_group_key(item), []).append(item)

    merged: list[dict[str, Any]] = []
    for items in grouped.values():
        per_model: dict[str, dict[str, Any]] = {}
        for item in items:
            model = str((item.get("metadata") or {}).get("review_model", "")).strip().lower() or "unknown"
            per_model.setdefault(model, item)

        consensus_models = sorted(per_model.keys())
        consensus_count = len(consensus_models)
        if require_consensus and consensus_count < min_consensus_models:
            continue

        weighted_severity_sum = 0.0
        weight_total = 0.0
        weighted_confidence_sum = 0.0
        severity_values: list[int] = []
        for model_name, item in per_model.items():
            weight = model_weights.get(model_name, 1.0)
            sev_score = float(severity_score(str(item.get("severity", "Medium"))))
            conf = float(item.get("code_confidence", 0.6))
            weighted_severity_sum += sev_score * weight
            weighted_confidence_sum += conf * weight
            weight_total += weight
            severity_values.append(int(sev_score))

        if weight_total <= 0:
            weight_total = 1.0
        weighted_severity = weighted_severity_sum / weight_total
        weighted_confidence = weighted_confidence_sum / weight_total

        selected = dict(items[0])
        selected_category = str(selected.get("category", "general_security"))
        category_boost = category_priority.get(selected_category, 0.0)
        weighted_severity += category_boost

        component = str(selected.get("component", "")).strip().lower()
        if component and component in static_hint_components:
            weighted_confidence += 0.08

        # Disagreement penalty (larger spread in severity among models lowers confidence).
        spread = (max(severity_values) - min(severity_values)) if severity_values else 0
        disagreement_penalty = 0.03 * spread
        weighted_confidence -= disagreement_penalty

        selected["severity"] = normalize_severity(_severity_from_weighted_score(weighted_severity))
        selected["code_confidence"] = round(clamp(weighted_confidence, 0.0, 1.0), 4)

        metadata = dict(selected.get("metadata") or {})
        metadata["ensemble_enabled"] = True
        metadata["ensemble_scoring_contract_version"] = ENSEMBLE_SCORING_API_VERSION
        metadata["consensus_models"] = consensus_models
        metadata["consensus_count"] = consensus_count
        metadata["disagreement_penalty"] = round(disagreement_penalty, 4)
        metadata["weighted_severity_raw"] = round(weighted_severity, 4)
        selected["metadata"] = metadata
        merged.append(selected)

    return merged
