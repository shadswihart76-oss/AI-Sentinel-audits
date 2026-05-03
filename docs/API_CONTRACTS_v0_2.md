# OpenClaw v0.2 API Contracts

This document locks stable extension/API contracts for external contributors.

## Contract Versions
- OpenClaw API version: `0.2.0`
- Static tool contract: `1`
- Model provider contract: `1`
- AI finding schema contract: `1`
- Scoring API contract: `1`
- Logging format contract: `1`

Source of truth: [contracts.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/openclaw/contracts.py)

## Static Tool Plugin Contract (v1)
Register via:
- `register_static_tool(name, plugin, contract_version=STATIC_TOOL_CONTRACT_VERSION)`

Requirements:
- `name` must be non-empty.
- `plugin` must be callable with exactly one positional argument: `StaticToolContext`.
- `plugin` must return `StaticToolPluginOutput`.
- `StaticToolPluginOutput.run` must be `ToolRun`.
- `StaticToolPluginOutput.findings` must be a `list`.

Primary interface file:
- [static_analysis.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/openclaw/static_analysis.py)

## Model Provider Contract (v1)
Register via:
- `register_model_provider(name, builder, contract_version=MODEL_PROVIDER_CONTRACT_VERSION)`

Requirements:
- `builder` must be callable with exactly one positional argument: `runtime_cfg`.
- `builder(runtime_cfg)` must return a caller callable with exactly two positional args: `(model, prompt)`.
- Caller return type must be `str` (JSON string expected by AI review parser).

Primary interface file:
- [model_runtime.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/openclaw/model_runtime.py)

## AI Finding Schema Contract (v1)
Normalized AI findings must conform to:

Required keys:
- `title` (string)
- `summary` (string)
- `severity` (`Info|Low|Medium|High|Critical`)
- `category` (string)

Optional keys:
- `asset` (string)
- `component` (string)
- `source` (string)
- `recommendations` (list of strings)
- `metadata` (object)
- `likely_impact` (int 0..4)
- `pattern_severity` (int 0..4)
- `code_confidence` (float 0..1)

Unknown fields:
- Rejected when `schema_validation.allow_unknown_fields=false`.

Primary interface file:
- [ai_schema.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/openclaw/ai_schema.py)

## Scoring API Contract (v1)
Stable public scoring API:
- `normalize_severity(value)`
- `severity_score(value)`
- `apply_severity_heuristic(existing_severity, finding_like)`
- `infer_likely_impact(severity, finding_like)`
- `infer_pattern_severity(severity)`
- `infer_confidence(existing, finding_like)`
- `score_finding(existing_severity, finding_like, existing_confidence)`

`score_finding` output includes:
- `severity`
- `likely_impact`
- `pattern_severity`
- `code_confidence`
- `scoring_contract_version`

Primary interface file:
- [scoring.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/openclaw/scoring.py)

## Logging Format Contract (v1)
When `logging.lock_format=true` (default):
- Format is locked to: `%(asctime)s %(levelname)s [%(name)s] %(message)s`
- Date format is locked to: `%Y-%m-%dT%H:%M:%SZ`
- UTC timestamps are enforced.

Primary interface file:
- [logging_utils.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/openclaw/logging_utils.py)
