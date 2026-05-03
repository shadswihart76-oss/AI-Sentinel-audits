from __future__ import annotations

from pathlib import Path

from openclaw import STATIC_TOOL_CONTRACT_VERSION
from openclaw.static_analysis import StaticToolContext, StaticToolPluginOutput, ToolRun, register_static_tool


def run_dependency_checker(context: StaticToolContext) -> StaticToolPluginOutput:
    findings: list[dict] = []
    requirements = list(context.repo_root.rglob("requirements*.txt"))
    for req in requirements:
        text = req.read_text(encoding="utf-8", errors="ignore").lower()
        if "pyyaml>=" in text:
            findings.append(
                {
                    "title": "Dependency checker: unpinned dependency",
                    "asset": context.target,
                    "component": str(req),
                    "summary": "Unpinned dependency range detected; prefer locked versions for reproducibility.",
                    "severity": "Low",
                    "category": "dependency_hardening",
                    "source": "dependency_checker",
                    "recommendations": ["Pin critical dependencies to exact versions in release builds."],
                }
            )

    return StaticToolPluginOutput(run=ToolRun(tool="dependency_checker", status="ok"), findings=findings)


register_static_tool(
    "dependency_checker",
    run_dependency_checker,
    contract_version=STATIC_TOOL_CONTRACT_VERSION,
)
