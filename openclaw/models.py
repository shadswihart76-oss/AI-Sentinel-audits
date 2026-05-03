from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from .scoring import normalize_severity, severity_score


@dataclass
class Finding:
    title: str
    asset: str
    component: str
    summary: str
    severity: str = "Medium"
    category: str = "general_security"
    recommendations: list[str] = field(default_factory=list)
    source: str = "unknown"
    likely_impact: int = 2
    code_confidence: float = 0.5
    pattern_severity: int = 2
    metadata: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        basis = "|".join(
            [
                self.asset.strip().lower(),
                self.component.strip().lower(),
                self.title.strip().lower(),
                self.summary.strip().lower(),
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def severity_score(self) -> int:
        return severity_score(self.severity)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["fingerprint"] = self.fingerprint()
        result["severity_score"] = self.severity_score()
        return result

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Finding":
        recs = raw.get("recommendations") or []
        if isinstance(recs, str):
            recs = [recs]

        metadata = raw.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        return cls(
            title=str(raw.get("title", "Untitled finding")),
            asset=str(raw.get("asset", "")),
            component=str(raw.get("component", "")),
            summary=str(raw.get("summary", "")),
            severity=normalize_severity(str(raw.get("severity", "Medium"))),
            category=str(raw.get("category", "general_security")),
            recommendations=[str(x) for x in recs],
            source=str(raw.get("source", "unknown")),
            likely_impact=int(raw.get("likely_impact", 2)),
            code_confidence=float(raw.get("code_confidence", 0.5)),
            pattern_severity=int(raw.get("pattern_severity", 2)),
            metadata=metadata,
        )
