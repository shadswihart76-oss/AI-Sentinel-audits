# OpenClaw Quickstart Workflow (v0.3)

## 1) Move to project directory
```bash
cd /mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline
```

## 2) Install dependencies
```bash
python3 -m pip install -r requirements.txt
```

## 3) Run local stub workflow (no external model dependency)
```bash
python3 -m openclaw --config openclaw.localstub.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --print-json
```

## 4) Run JSON-only mode for automation pipes
```bash
python3 -m openclaw --config openclaw.localstub.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --json-only
```

## 5) Enable verbose diagnostics
```bash
python3 -m openclaw --config openclaw.localstub.yaml --target "coinbase/<IN_SCOPE_REPO_1>" --repo-path . --verbose
```

## 6) Add a custom static plugin
1. Create plugin file using [custom_static_plugin.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/plugins/custom_static_plugin.py) as template.
2. Add plugin path to config:
```yaml
modules:
  static_analysis:
    plugin_modules:
      - "examples/plugins/custom_static_plugin.py"
    tools:
      - "custom_tool"
```

## 7) Add a custom model provider
1. Create provider file using [custom_model_provider.py](C:/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/examples/plugins/custom_model_provider.py) as template.
2. Add provider to config:
```yaml
modules:
  ai_code_review:
    runtime:
      plugin_modules:
        - "examples/plugins/custom_model_provider.py"
      provider: "custom_echo"
```

## 8) Validate with unit tests
```bash
python3 -m unittest discover -s tests -v
```

## 9) Enable deeper intelligence features
The default v0.3 config already includes:
- adaptive chunking (`modules.ai_code_review.chunking.mode=auto`)
- multi-model specialization (`modules.ai_code_review.model_specialization`)
- ensemble scoring (`modules.ai_code_review.ensemble`)
- cross-file reasoning (`modules.cross_file_reasoning.enabled=true`)

## 10) Use dashboard mode (snippet, ZIP, or local folder)
Windows:
- Double-click `/mnt/c/Users/shads/Documents/Codex/2026-05-02/build-make-me-a-openclaw-pipeline/OpenClaw-Dashboard.bat`

CLI launch:
```bash
python3 -m openclaw.dashboard
```

Then either:
- Paste code and click `Run Snippet Review`, or
- Select a repository `.zip` and click `Run ZIP Review`.
- Select a local cloned repo folder and click `Run Folder Review`.

Optional:
- Click `Auto Register ZIP Target` to auto-infer repo slug, append it to `scope.github_repos`, and set the `Target` field.
- Toggle `Zero-Knowledge Mode` for non-technical output (bug/impact/severity/fix).
- Keep `Report-Ready Mode` on to suppress common noise (test/example/asset + chain-only lead items).
- Click `Show Validation Guide` for safe code-review checks per finding.
- Use `Session History` to reload prior run output.

Copy findings directly from the output chat panel (`Copy Findings` / `Copy Full JSON`).
