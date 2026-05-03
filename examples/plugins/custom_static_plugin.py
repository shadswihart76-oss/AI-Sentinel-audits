from __future__ import annotations

from openclaw import STATIC_TOOL_CONTRACT_VERSION
from openclaw.static_analysis import StaticToolContext, StaticToolPluginOutput, ToolRun, register_static_tool


def run_custom_tool(context: StaticToolContext) -> StaticToolPluginOutput:
    finding = {
        "title": "Custom SAST plugin sample finding",
        "asset": context.target,
        "component": "custom_plugin.py",
        "summary": "This is a sample result from a custom static tool plugin.",
        "severity": "Low",
        "category": "static_analysis",
        "source": "custom_static_plugin",
        "recommendations": ["Replace this plugin with your real static scanner integration."],
    }
    return StaticToolPluginOutput(
        run=ToolRun(tool="custom_tool", status="ok"),
        findings=[finding],
    )


register_static_tool("custom_tool", run_custom_tool, contract_version=STATIC_TOOL_CONTRACT_VERSION)
