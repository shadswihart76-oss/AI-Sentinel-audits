# Changelog

## 0.3.0 - Intelligence Upgrade
- Added local dashboard UI for paste-in snippet review and copy-ready HackerOne findings output.
- Added multi-model specialization by category (`model_specialization`).
- Added ensemble scoring engine with consensus, model weighting, disagreement penalties, and static-hint boosts.
- Added parallel multi-model execution for AI review tasks.
- Added model fallback chains for resilience.
- Added cross-file reasoning stage to synthesize chain-level findings.
- Added built-in regex static scanner plugin plus Semgrep/Bandit advanced args/profile support.
- Added specialized prompt set: input validation, crypto security, business logic, trust boundaries.
- Added v0.3 API contracts document and extended tests for contract enforcement.

## 0.2.0 - Stability + Reliability Release
- Locked v0.2 API contracts for static plugins, model providers, AI schema, scoring API, and logging format.
- Added scoring heuristics for severity, confidence, impact, and pattern severity.
- Added AI finding schema validation with strict/non-strict modes.
- Added parallel chunk processing for AI code review.
- Added deterministic UTC logging and per-module logging hooks.
- Added graceful fallback behavior and stage-level error capture.
- Added plugin architecture for static analysis tools and model runtime providers.
- Added CLI `--json-only`, `--quiet`, and `--verbose` modes.
- Improved report formatting with severity/source metric tables.
- Added unit tests for scope, recon, static analysis, AI review, finding builder, reports, and pipeline.
- Bumped package version to `0.2.0`.
