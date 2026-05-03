# OpenClaw v0.3 (Intelligence Upgrade)

OpenClaw is a passive, read-only security review pipeline for in-scope public code.

Execution order:
1. Config + Scope Guard
2. Passive Recon (local clone only)
3. Static Analysis (plugin-based)
4. AI Code Review (prompt-driven, schema-validated)
5. Finding Builder (heuristics + dedup + ranking)
6. Report Generator

## Guardrails
- No active network requests
- No HTTP clients in OpenClaw pipeline logic
- No port scanning
- No socket usage
- Read-only analysis only

## v0.3 Highlights
- Multi-model specialization by category (`model_specialization`)
- Ensemble scoring with consensus, weighting, and disagreement penalties
- Multi-model parallel stage-4 execution
- Cross-file reasoning stage for chain-level leads
- Extended static analysis stack with regex rules plugin
- Specialized prompt lenses: auth, SSRF, crypto, input validation, business logic, trust boundaries
- Locked extension contracts preserved from v0.2

## Stable API Contracts
OpenClaw v0.3 keeps extension interfaces and schema contracts stable for contributors:
- Static tool plugin contract v1
- Model provider contract v1
- AI finding schema contract v1
- Scoring API contract v1
- Logging format contract v1

Reference:
- [API_CONTRACTS_v0_3.md](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/docs/API_CONTRACTS_v0_3.md)
- [QUICKSTART.md](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/docs/QUICKSTART.md)
- [TUNING_GUIDE.md](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/docs/TUNING_GUIDE.md)

## Install
```bash
python3 -m pip install -r requirements.txt
```

Optional editable install:
```bash
python3 -m pip install --user -e .
```

## Run
Default summary:
```bash
python3 -m openclaw --config openclaw.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path .
```

Full run summary JSON:
```bash
python3 -m openclaw --config openclaw.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --print-json
```

Findings JSON only:
```bash
python3 -m openclaw --config openclaw.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --json-only
```

Verbose logging:
```bash
python3 -m openclaw --config openclaw.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --verbose
```

Quiet mode:
```bash
python3 -m openclaw --config openclaw.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --quiet
```

## Dashboard (Snippet + ZIP + Folder + History)
Launch from the folder:
- Windows: double-click [OpenClaw-Dashboard.bat](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/OpenClaw-Dashboard.bat)
- PowerShell: run [OpenClaw-Dashboard.ps1](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/OpenClaw-Dashboard.ps1)

Or run from terminal:
```bash
python3 -m openclaw.dashboard
```

Workflow in dashboard:
1. Set config + target.
2. Choose one input mode:
   - Paste snippet: `Run Snippet Review`
   - ZIP archive: `Run ZIP Review`
   - Local cloned repo folder: `Run Folder Review`
3. Optional: click `Auto Register ZIP Target` to infer repo slug from ZIP, update `scope.github_repos`, and auto-set `Target`.
4. Watch live progress for stages (extract, root detection, static analysis, AI review, merge, reporting).
5. Apply severity filters (`Critical/High/Medium/Low/Info`), optional `Report-Ready Mode`, and `Zero-Knowledge Mode`.
6. Copy findings, copy JSON, or `Save Report` (Markdown/JSON).
7. Use `Show Validation Guide` for safe manual verification checklists.
8. Re-open prior runs from `Session History`.

ZIP review behavior:
- ZIP extraction is local and read-only.
- Unsafe ZIP paths (path traversal/symlink entries) are rejected.
- OpenClaw runs against the extracted repo and writes detailed reports into the run session folder.
- Auto-register writes a timestamped config backup before changing scope entries.

Learning memory behavior:
- OpenClaw stores normalized findings in `reports/learning_memory.json`.
- Later runs use this as prior-pattern context for AI review calibration.
- Disable via config:
```yaml
modules:
  ai_code_review:
    learning:
      enabled: false
```

Troubleshooting on WSL:
- If you see `No module named 'tkinter'`:
```bash
sudo apt update
sudo apt install -y python3-tk
```
- If `openclaw-dashboard` command is missing, run from repo directly:
```bash
python3 -m openclaw.dashboard
```

## WSL Quick Start
```bash
cd /mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline
python3 -m openclaw --config openclaw.localstub.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --print-json
```

Full workflow:
- [QUICKSTART.md](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/docs/QUICKSTART.md)
- [quickstart.sh](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/workflows/quickstart.sh)
- [quickstart.ps1](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/workflows/quickstart.ps1)

## Configuration Notes
- Scope enforcement: `scope_guard.validate(target)` is called by every stage.
- AI runtime providers: `none`, `ollama_cli`, `command`, or plugin-registered providers.
- Static tools: configured in `modules.static_analysis.tools` and resolved through plugin registry.
- AI findings schema validation:
  - `modules.ai_code_review.schema_validation.strict: false|true`
- AI parallel chunk processing:
  - `modules.ai_code_review.parallel.enabled: true|false`
  - `modules.ai_code_review.parallel.max_workers: <int>`

## Plugin Examples
Static tool plugin loading:
```yaml
modules:
  static_analysis:
    plugin_modules:
      - "examples/plugins/custom_static_plugin.py"
    tools:
      - "custom_tool"
```

Model provider plugin loading:
```yaml
modules:
  ai_code_review:
    runtime:
      plugin_modules:
        - "examples/plugins/custom_model_provider.py"
      provider: "custom_echo"
```

Config snippets:
- [static_plugin_snippet.yaml](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/configs/static_plugin_snippet.yaml)
- [model_provider_snippet.yaml](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/configs/model_provider_snippet.yaml)

Additional plugin templates:
- [config_linter_plugin.py](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/plugins/config_linter_plugin.py)
- [dependency_checker_plugin.py](/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/plugins/dependency_checker_plugin.py)

## Tests
Run unit tests:
```bash
python3 -m unittest discover -s tests -v
```
