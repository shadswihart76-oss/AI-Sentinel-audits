from __future__ import annotations

from pathlib import Path

from openclaw import STATIC_TOOL_CONTRACT_VERSION
from openclaw.static_analysis import StaticToolContext, StaticToolPluginOutput, ToolRun, register_static_tool


def run_config_linter(context: StaticToolContext) -> StaticToolPluginOutput:
    findings: list[dict] = []
    for file_path in context.repo_root.rglob("*.y*ml"):
        text = file_path.read_text(encoding="utf-8", errors="ignore").lower()
        if "debug: true" in text or "allow_all: true" in text:
            findings.append(
                {
                    "title": "Config linter: permissive debug/allow-all setting",
                    "asset": context.target,
                    "component": str(file_path),
                    "summary": "Potentially permissive configuration detected; verify production-safe settings.",
                    "severity": "Low",
                    "category": "config_lint",
                    "source": "config_linter",
                    "recommendations": ["Disable permissive debug/allow-all settings in production paths."],
                }
            )

    return StaticToolPluginOutput(run=ToolRun(tool="config_linter", status="ok"), findings=findings)


register_static_tool(
    "config_linter",
    run_config_linter,
    contract_version=STATIC_TOOL_CONTRACT_VERSION,
)
