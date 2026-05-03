# OpenClaw v0.3 API Contracts

OpenClaw v0.3 preserves the v1 extension contracts introduced in v0.2 and adds a stable ensemble scoring module contract.

## Contract Versions
- OpenClaw API version: `0.3.0`
- Static tool contract: `1`
- Model provider contract: `1`
- AI finding schema contract: `1`
- Scoring API contract: `1`
- Ensemble scoring contract: `1`
- Logging format contract: `1`

## Static Tool Plugin Contract (v1)
- Register with `register_static_tool(name, plugin, contract_version="1")`
- Plugin signature: `plugin(context: StaticToolContext) -> StaticToolPluginOutput`
- Return type is strict and validated at runtime.

## Model Provider Contract (v1)
- Register with `register_model_provider(name, builder, contract_version="1")`
- Builder signature: `builder(runtime_cfg: dict) -> ModelCaller`
- Caller signature: `caller(model: str, prompt: str) -> str`
- String return type is enforced.

## AI Finding Schema Contract (v1)
Required keys:
- `title`, `summary`, `severity`, `category`

Optional keys:
- `asset`, `component`, `source`, `recommendations`, `metadata`
- `likely_impact`, `pattern_severity`, `code_confidence`

Controls:
- Unknown-field handling via `schema_validation.allow_unknown_fields`
- Strict rejection via `schema_validation.strict`

## Scoring API Contract (v1)
Stable public functions:
- `normalize_severity`
- `severity_score`
- `apply_severity_heuristic`
- `infer_likely_impact`
- `infer_pattern_severity`
- `infer_confidence`
- `score_finding`

`score_finding` includes `scoring_contract_version`.

## Ensemble Scoring Contract (v1)
Stable public entrypoint:
- `merge_findings_with_ensemble(findings, ensemble_cfg, static_hints=None)`

Outputs annotate:
- `metadata.ensemble_scoring_contract_version`
- `metadata.consensus_models`
- `metadata.consensus_count`
- `metadata.disagreement_penalty`
- `metadata.weighted_severity_raw`

## Cross-File Reasoning Module Contract (v1)
Stable entrypoint:
- `run_cross_file_reasoning(target, file_paths, ai_findings, static_findings, config)`

Behavior:
- Returns normalized finding dictionaries
- Never mutates input finding lists
- Respects module toggle: `modules.cross_file_reasoning.enabled`

## Logging Format Contract (v1)
When `logging.lock_format=true`:
- format: `%(asctime)s %(levelname)s [%(name)s] %(message)s`
- datefmt: `%Y-%m-%dT%H:%M:%SZ`
- UTC timestamps
