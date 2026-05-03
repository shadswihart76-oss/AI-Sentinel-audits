from __future__ import annotations

from typing import Final

# Stable release-level API identity
OPENCLAW_API_VERSION: Final[str] = "0.3.0"

# Interface contract versions (lock these for external contributors)
STATIC_TOOL_CONTRACT_VERSION: Final[str] = "1"
MODEL_PROVIDER_CONTRACT_VERSION: Final[str] = "1"
AI_FINDING_SCHEMA_VERSION: Final[str] = "1"
SCORING_API_VERSION: Final[str] = "1"
ENSEMBLE_SCORING_API_VERSION: Final[str] = "1"
LOGGING_FORMAT_VERSION: Final[str] = "1"

# Locked finding schema for normalized AI outputs
AI_FINDING_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "title",
    "summary",
    "severity",
    "category",
)

AI_FINDING_OPTIONAL_KEYS: Final[tuple[str, ...]] = (
    "asset",
    "component",
    "source",
    "recommendations",
    "metadata",
    "likely_impact",
    "pattern_severity",
    "code_confidence",
)

AI_FINDING_ALLOWED_KEYS: Final[set[str]] = set(AI_FINDING_REQUIRED_KEYS + AI_FINDING_OPTIONAL_KEYS)

AI_FINDING_ALLOWED_SEVERITIES: Final[tuple[str, ...]] = (
    "Info",
    "Low",
    "Medium",
    "High",
    "Critical",
)

# Locked deterministic logging format for v0.3 API.
LOCKED_LOG_FORMAT: Final[str] = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
LOCKED_LOG_DATEFMT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"
