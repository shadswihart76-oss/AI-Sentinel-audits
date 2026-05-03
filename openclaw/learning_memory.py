from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _load_store(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "records": []}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "records": []}
    if not isinstance(parsed, dict):
        return {"version": 1, "records": []}
    records = parsed.get("records", [])
    if not isinstance(records, list):
        records = []
    return {"version": 1, "records": records}


def _to_record(item: dict[str, Any]) -> dict[str, Any]:
    recommendations = item.get("recommendations", [])
    rec = ""
    if isinstance(recommendations, list) and recommendations:
        rec = str(recommendations[0])
    return {
        "title": str(item.get("title", "Untitled finding")),
        "category": str(item.get("category", "general_security")),
        "severity": str(item.get("severity", "Medium")),
        "summary": str(item.get("summary", "")),
        "recommendation": rec,
        "source": str(item.get("source", "unknown")),
    }


def update_learning_memory(
    *,
    memory_path: str,
    findings: list[dict[str, Any]],
    max_records: int = 3000,
) -> None:
    path = Path(memory_path).resolve()
    _ensure_parent(path)
    store = _load_store(path)
    records = list(store.get("records", []))
    records.extend(_to_record(item) for item in findings)
    if len(records) > max_records:
        records = records[-max_records:]
    store = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "records": records,
    }
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")


def build_learning_context(
    *,
    memory_path: str,
    max_entries: int = 20,
) -> str:
    path = Path(memory_path).resolve()
    store = _load_store(path)
    records = store.get("records", [])
    if not isinstance(records, list) or not records:
        return ""

    recent = records[-max_entries:]
    category_counter = Counter(str(item.get("category", "general_security")) for item in recent)
    severity_counter = Counter(str(item.get("severity", "Medium")) for item in recent)

    lines: list[str] = [
        "Prior confirmed finding patterns from earlier runs:",
        "Category frequency:",
    ]
    for key, count in category_counter.most_common():
        lines.append(f"- {key}: {count}")
    lines.append("Severity frequency:")
    for key, count in severity_counter.most_common():
        lines.append(f"- {key}: {count}")
    lines.append("Representative prior findings:")
    for item in recent[-10:]:
        lines.append(
            "- "
            + str(item.get("title", "Untitled"))
            + " | "
            + str(item.get("category", "general_security"))
            + " | "
            + str(item.get("severity", "Medium"))
        )
        rec = str(item.get("recommendation", "")).strip()
        if rec:
            lines.append(f"  Fix hint: {rec}")
    return "\n".join(lines).strip()
