# OpenClaw Tuning Guide For Deeper Bugs

## 1) Adaptive chunking
Tune in `modules.ai_code_review.chunking`:
```yaml
chunking:
  mode: "auto"
  min_chunk_size: 1200
  max_chunk_size: 8000
```

Guideline:
- Utility-heavy repos: bias smaller chunk windows.
- Controller/API repos: medium chunk windows.
- Business-logic-heavy repos: larger chunks for flow continuity.

## 2) Expand static depth
Combine static tools:
```yaml
static_analysis:
  tools: ["semgrep", "bandit", "regex"]
  semgrep_rules: "custom_rules/semgrep_rules.yml"
  bandit_profile: ""
  regex_rules_file: "custom_rules/regex_rules.yml"
```

You can also add plugins for config linters and dependency checks via `plugin_modules`.

## 3) Strengthen prompt context
Use specialized prompt files:
- `prompts/auth_access.txt`
- `prompts/ssrf.txt`
- `prompts/input_validation.txt`
- `prompts/crypto_security.txt`
- `prompts/business_logic.txt`
- `prompts/trust_boundaries.txt`

## 4) Model specialization
```yaml
model_specialization:
  auth_access: "model-auth"
  ssrf: "model-ssrf"
  crypto_security: "model-crypto"
  input_validation: "model-input"
  business_logic: "model-logic"
```

## 5) Ensemble scoring
```yaml
ensemble:
  enabled: true
  models: ["model-a", "model-b"]
  model_weights:
    model-a: 1.0
    model-b: 0.9
  require_consensus: false
  min_consensus_models: 2
```

## 6) Cross-file reasoning
```yaml
cross_file_reasoning:
  enabled: true
  min_files_for_chain: 2
```

This stage synthesizes multi-file chain leads (auth, SSRF, trust-boundary, and logic-flow signals).
