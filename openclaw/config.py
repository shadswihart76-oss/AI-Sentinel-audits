from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .contracts import (
    AI_FINDING_SCHEMA_VERSION,
    ENSEMBLE_SCORING_API_VERSION,
    LOGGING_FORMAT_VERSION,
    MODEL_PROVIDER_CONTRACT_VERSION,
    SCORING_API_VERSION,
    STATIC_TOOL_CONTRACT_VERSION,
)


class ConfigError(Exception):
    """Raised when OpenClaw configuration is missing or invalid."""


def _resolve_path(value: Any, base_dir: Path) -> Any:
    if not isinstance(value, str):
        return value
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((base_dir / path).resolve())


def _resolve_relative_paths(config: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    modules = config.get("modules", {})
    if not isinstance(modules, dict):
        return config

    static_cfg = modules.get("static_analysis", {})
    if isinstance(static_cfg, dict):
        if "semgrep_rules" in static_cfg:
            static_cfg["semgrep_rules"] = _resolve_path(static_cfg.get("semgrep_rules"), base_dir)
        if "regex_rules_file" in static_cfg and static_cfg.get("regex_rules_file"):
            static_cfg["regex_rules_file"] = _resolve_path(static_cfg.get("regex_rules_file"), base_dir)
        plugin_modules = static_cfg.get("plugin_modules", [])
        if isinstance(plugin_modules, list):
            static_cfg["plugin_modules"] = [
                _resolve_path(item, base_dir) if str(item).endswith(".py") else item
                for item in plugin_modules
            ]

    ai_cfg = modules.get("ai_code_review", {})
    if isinstance(ai_cfg, dict):
        prompts = ai_cfg.get("prompts", {})
        if isinstance(prompts, dict):
            for key, val in list(prompts.items()):
                prompts[key] = _resolve_path(val, base_dir)

        runtime = ai_cfg.get("runtime", {})
        if isinstance(runtime, dict):
            if "workdir" in runtime and runtime.get("workdir"):
                runtime["workdir"] = _resolve_path(runtime.get("workdir"), base_dir)
            plugin_modules = runtime.get("plugin_modules", [])
            if isinstance(plugin_modules, list):
                runtime["plugin_modules"] = [
                    _resolve_path(item, base_dir) if str(item).endswith(".py") else item
                    for item in plugin_modules
                ]
            command = runtime.get("command", [])
            if isinstance(command, list):
                resolved_command: list[Any] = []
                for idx, token in enumerate(command):
                    token_str = str(token)
                    # Resolve script path token for patterns like: python3 script.py ...
                    if idx == 1 and token_str.endswith(".py"):
                        resolved_command.append(_resolve_path(token_str, base_dir))
                    else:
                        resolved_command.append(token)
                runtime["command"] = resolved_command

    reporting_cfg = modules.get("reporting", {})
    if isinstance(reporting_cfg, dict):
        if "template" in reporting_cfg:
            reporting_cfg["template"] = _resolve_path(reporting_cfg.get("template"), base_dir)
        if "output_dir" in reporting_cfg:
            reporting_cfg["output_dir"] = _resolve_path(reporting_cfg.get("output_dir"), base_dir)

    return config


def _validate_contract_versions(config: dict[str, Any]) -> None:
    contracts = config.get("contracts", {})
    if not isinstance(contracts, dict):
        raise ConfigError("`contracts` must be a mapping when present.")

    expected = {
        "static_tool": STATIC_TOOL_CONTRACT_VERSION,
        "model_provider": MODEL_PROVIDER_CONTRACT_VERSION,
        "ai_finding_schema": AI_FINDING_SCHEMA_VERSION,
        "scoring_api": SCORING_API_VERSION,
        "ensemble_scoring": ENSEMBLE_SCORING_API_VERSION,
        "logging_format": LOGGING_FORMAT_VERSION,
    }
    for key, expected_value in expected.items():
        configured = str(contracts.get(key, expected_value))
        if configured != expected_value:
            raise ConfigError(
                f"Unsupported contract version for '{key}': {configured}. "
                f"Expected {expected_value}."
            )


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    suffix = config_path.suffix.lower()

    if suffix in {".yaml", ".yml"}:
        parsed = yaml.safe_load(raw_text)
    elif suffix == ".json":
        parsed = json.loads(raw_text)
    else:
        # Fallback for unknown extensions.
        try:
            parsed = yaml.safe_load(raw_text)
        except Exception:
            parsed = json.loads(raw_text)

    if not isinstance(parsed, dict):
        raise ConfigError("Top-level config must be a mapping object.")

    openclaw = parsed.get("openclaw")
    if not isinstance(openclaw, dict):
        raise ConfigError("Expected top-level `openclaw` object in config.")

    resolved = _resolve_relative_paths(openclaw, config_path.resolve().parent)
    _validate_contract_versions(resolved)
    return resolved
