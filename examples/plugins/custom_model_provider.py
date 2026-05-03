from __future__ import annotations

import json

from openclaw import MODEL_PROVIDER_CONTRACT_VERSION
from openclaw.model_runtime import register_model_provider


def _build_echo_provider(_runtime_cfg: dict):
    def _caller(_model: str, _prompt: str) -> str:
        return json.dumps(
            {
                "findings": [
                    {
                        "title": "Custom model provider sample",
                        "summary": "This sample provider returns a deterministic test finding.",
                        "severity": "Low",
                        "category": "general_security",
                        "recommendations": ["Swap with your real provider implementation."],
                    }
                ]
            }
        )

    return _caller


register_model_provider(
    "custom_echo",
    _build_echo_provider,
    contract_version=MODEL_PROVIDER_CONTRACT_VERSION,
)
