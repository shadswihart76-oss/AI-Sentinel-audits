"""OpenClaw security review pipeline."""

from .contracts import (
    AI_FINDING_SCHEMA_VERSION,
    ENSEMBLE_SCORING_API_VERSION,
    LOGGING_FORMAT_VERSION,
    MODEL_PROVIDER_CONTRACT_VERSION,
    OPENCLAW_API_VERSION,
    SCORING_API_VERSION,
    STATIC_TOOL_CONTRACT_VERSION,
)
from .model_runtime import build_model_caller_from_config, register_model_provider
from .pipeline import OpenClawPipeline, PipelineResult
from .static_analysis import register_static_tool

__version__ = "0.3.0"

__all__ = [
    "OpenClawPipeline",
    "PipelineResult",
    "build_model_caller_from_config",
    "register_model_provider",
    "register_static_tool",
    "OPENCLAW_API_VERSION",
    "STATIC_TOOL_CONTRACT_VERSION",
    "MODEL_PROVIDER_CONTRACT_VERSION",
    "AI_FINDING_SCHEMA_VERSION",
    "SCORING_API_VERSION",
    "ENSEMBLE_SCORING_API_VERSION",
    "LOGGING_FORMAT_VERSION",
]
