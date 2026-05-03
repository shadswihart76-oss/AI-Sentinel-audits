from __future__ import annotations

from pathlib import Path


def make_base_config(tmp_dir: Path) -> dict:
    prompts_dir = tmp_dir / "prompts"
    templates_dir = tmp_dir / "templates"
    rules_dir = tmp_dir / "custom_rules"
    reports_dir = tmp_dir / "reports"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)
    rules_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    (prompts_dir / "general_security.txt").write_text("<CODE_SNIPPET>", encoding="utf-8")
    (prompts_dir / "auth_access.txt").write_text("<CODE_SNIPPET>", encoding="utf-8")
    (prompts_dir / "ssrf.txt").write_text("<CODE_SNIPPET>", encoding="utf-8")
    (templates_dir / "triage_friendly_report.md").write_text(
        "# Report\n{findings_markdown}\n{severity_breakdown}\n{source_breakdown}",
        encoding="utf-8",
    )
    (rules_dir / "semgrep_rules.yml").write_text("rules: []", encoding="utf-8")

    return {
        "version": "0.3.0",
        "program": {"name": "Test Program", "platform": "H1"},
        "scope": {
            "domains": ["example.com", "*.example.com"],
            "github_repos": ["org/repo"],
            "mobile_packages": ["com.example.app"],
        },
        "guardrails": {
            "allow_active_requests": False,
            "allow_internal_ips": False,
            "allow_metadata_endpoints": False,
            "allow_bruteforce": False,
            "allow_auth_bypass_testing": False,
        },
        "hardening": {"graceful_fallback": True},
        "logging": {"level": "ERROR", "lock_format": True},
        "modules": {
            "passive_recon": {"enabled": True, "sources": ["github"]},
            "static_analysis": {
                "enabled": True,
                "tools": ["semgrep", "bandit"],
                "plugin_modules": [],
                "semgrep_rules": str(rules_dir / "semgrep_rules.yml"),
            },
            "ai_code_review": {
                "enabled": True,
                "model": "test-model",
                "max_chunk_size": 2000,
                "chunking": {"mode": "manual", "min_chunk_size": 500, "max_chunk_size": 3000},
                "parallel": {"enabled": True, "max_workers": 2},
                "model_specialization": {},
                "model_fallback": {"default": []},
                "ensemble": {"enabled": False},
                "schema_validation": {"strict": False, "allow_unknown_fields": False},
                "runtime": {"provider": "none"},
                "prompts": {
                    "general_security": str(prompts_dir / "general_security.txt"),
                    "auth_access": str(prompts_dir / "auth_access.txt"),
                    "ssrf": str(prompts_dir / "ssrf.txt"),
                },
            },
            "findings": {
                "deduplicate": True,
                "rank_by": ["likely_impact", "code_confidence", "pattern_severity"],
                "scoring": {
                    "severity_heuristics": True,
                    "confidence_heuristics": True,
                    "impact_heuristics": True,
                    "pattern_severity_heuristics": True,
                },
            },
            "reporting": {
                "enabled": True,
                "template": str(templates_dir / "triage_friendly_report.md"),
                "output_dir": str(reports_dir),
            },
            "cross_file_reasoning": {"enabled": False},
        },
    }
