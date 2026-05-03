from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
import yaml

from .contracts import STATIC_TOOL_CONTRACT_VERSION
from .logging_utils import get_module_logger, setup_logging
from .scope_guard import set_scope_config, validate


@dataclass
class ToolRun:
    tool: str
    status: str
    output_file: str = ""
    stdout: str = ""
    stderr: str = ""


@dataclass
class StaticAnalysisResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    tool_runs: list[ToolRun] = field(default_factory=list)


@dataclass
class StaticToolContext:
    target: str
    repo_root: Path
    reports_dir: Path
    module_cfg: dict[str, Any]
    contract_version: str = STATIC_TOOL_CONTRACT_VERSION


@dataclass
class StaticToolPluginOutput:
    run: ToolRun
    findings: list[dict[str, Any]] = field(default_factory=list)


StaticToolPlugin = Callable[[StaticToolContext], StaticToolPluginOutput]
STATIC_TOOL_REGISTRY: dict[str, StaticToolPlugin] = {}


def _validate_static_tool_callable(plugin: StaticToolPlugin) -> None:
    if not callable(plugin):
        raise TypeError("Static tool plugin must be callable.")
    sig = inspect.signature(plugin)
    positional = [
        p
        for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) != 1:
        raise TypeError(
            "Static tool plugin contract requires exactly one positional parameter: StaticToolContext."
        )


def register_static_tool(
    name: str,
    plugin: StaticToolPlugin,
    *,
    contract_version: str = STATIC_TOOL_CONTRACT_VERSION,
) -> None:
    if contract_version != STATIC_TOOL_CONTRACT_VERSION:
        raise ValueError(
            f"Unsupported static tool contract_version={contract_version}. "
            f"Expected {STATIC_TOOL_CONTRACT_VERSION}."
        )
    clean_name = name.strip().lower()
    if not clean_name:
        raise ValueError("Static tool name cannot be empty.")
    _validate_static_tool_callable(plugin)
    STATIC_TOOL_REGISTRY[clean_name] = plugin


def _validate_plugin_output(output: Any, tool_name: str) -> StaticToolPluginOutput:
    if not isinstance(output, StaticToolPluginOutput):
        raise TypeError(
            f"Static tool '{tool_name}' must return StaticToolPluginOutput "
            f"(contract {STATIC_TOOL_CONTRACT_VERSION})."
        )
    if not isinstance(output.run, ToolRun):
        raise TypeError(
            f"Static tool '{tool_name}' output.run must be ToolRun "
            f"(contract {STATIC_TOOL_CONTRACT_VERSION})."
        )
    if not isinstance(output.findings, list):
        raise TypeError(
            f"Static tool '{tool_name}' output.findings must be a list "
            f"(contract {STATIC_TOOL_CONTRACT_VERSION})."
        )
    return output


def _run_command(cmd: list[str], workdir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(workdir),
        text=True,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def _parse_semgrep_results(raw: dict[str, Any], target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in raw.get("results", []):
        extra = item.get("extra", {})
        findings.append(
            {
                "title": f"Semgrep: {item.get('check_id', 'rule')}",
                "asset": target,
                "component": item.get("path", ""),
                "summary": extra.get("message", "Semgrep flagged a code pattern."),
                "severity": str(extra.get("severity", "MEDIUM")).title(),
                "category": "static_analysis",
                "source": "semgrep",
                "likely_impact": 2,
                "code_confidence": 0.8,
                "pattern_severity": 2,
                "metadata": {
                    "check_id": item.get("check_id"),
                    "start": item.get("start"),
                    "end": item.get("end"),
                },
                "recommendations": [
                    "Review this code path for security relevance.",
                    "Add explicit validation or authorization checks where applicable.",
                ],
            }
        )
    return findings


def _parse_bandit_results(raw: dict[str, Any], target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in raw.get("results", []):
        severity = str(item.get("issue_severity", "MEDIUM")).title()
        findings.append(
            {
                "title": f"Bandit: {item.get('test_id', 'rule')}",
                "asset": target,
                "component": item.get("filename", ""),
                "summary": item.get("issue_text", "Bandit flagged a security pattern."),
                "severity": severity,
                "category": "static_analysis",
                "source": "bandit",
                "likely_impact": 2,
                "code_confidence": 0.75,
                "pattern_severity": 2,
                "metadata": {
                    "line_number": item.get("line_number"),
                    "test_name": item.get("test_name"),
                },
                "recommendations": [
                    "Review this result in source context.",
                    "Adjust implementation to remove the unsafe pattern if confirmed.",
                ],
            }
        )
    return findings


def _semgrep_plugin(context: StaticToolContext) -> StaticToolPluginOutput:
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin is None:
        return StaticToolPluginOutput(run=ToolRun(tool="semgrep", status="missing"))

    semgrep_out = context.reports_dir / "semgrep_results.json"
    semgrep_rules = context.module_cfg.get("semgrep_rules", "custom_rules/semgrep_rules.yml")
    cmd = [
        semgrep_bin,
        "scan",
        "--config",
        str(semgrep_rules),
        "--json",
        "--output",
        str(semgrep_out),
        str(context.repo_root),
    ]
    extra_args = context.module_cfg.get("semgrep_args", [])
    if isinstance(extra_args, list):
        cmd.extend(str(x) for x in extra_args if str(x).strip())
    completed = _run_command(cmd, context.repo_root)
    status = "ok" if completed.returncode in {0, 1} else "error"
    run = ToolRun(
        tool="semgrep",
        status=status,
        output_file=str(semgrep_out),
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if not semgrep_out.exists():
        return StaticToolPluginOutput(run=run)

    raw = json.loads(semgrep_out.read_text(encoding="utf-8"))
    findings = _parse_semgrep_results(raw, context.target)
    return StaticToolPluginOutput(run=run, findings=findings)


def _bandit_plugin(context: StaticToolContext) -> StaticToolPluginOutput:
    bandit_bin = shutil.which("bandit")
    if bandit_bin is None:
        return StaticToolPluginOutput(run=ToolRun(tool="bandit", status="missing"))

    bandit_out = context.reports_dir / "bandit_results.json"
    cmd = [
        bandit_bin,
        "-r",
        str(context.repo_root),
        "-f",
        "json",
        "-o",
        str(bandit_out),
    ]
    profile = str(context.module_cfg.get("bandit_profile", "")).strip()
    if profile:
        cmd.extend(["-p", profile])
    extra_args = context.module_cfg.get("bandit_args", [])
    if isinstance(extra_args, list):
        cmd.extend(str(x) for x in extra_args if str(x).strip())
    completed = _run_command(cmd, context.repo_root)
    status = "ok" if completed.returncode in {0, 1} else "error"
    run = ToolRun(
        tool="bandit",
        status=status,
        output_file=str(bandit_out),
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if not bandit_out.exists():
        return StaticToolPluginOutput(run=run)

    raw = json.loads(bandit_out.read_text(encoding="utf-8"))
    findings = _parse_bandit_results(raw, context.target)
    return StaticToolPluginOutput(run=run, findings=findings)


register_static_tool("semgrep", _semgrep_plugin)
register_static_tool("bandit", _bandit_plugin)


def _load_regex_rules(module_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    configured = module_cfg.get("regex_rules", [])
    if isinstance(configured, list):
        rules = [rule for rule in configured if isinstance(rule, dict)]
    else:
        rules = []

    rules_file = module_cfg.get("regex_rules_file")
    if rules_file:
        path = Path(str(rules_file))
        if path.exists():
            text = path.read_text(encoding="utf-8")
            if path.suffix.lower() == ".json":
                parsed = json.loads(text)
            else:
                parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                parsed = parsed.get("rules", [])
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        rules.append(item)
    return rules


def _regex_plugin(context: StaticToolContext) -> StaticToolPluginOutput:
    rules = _load_regex_rules(context.module_cfg)
    if not rules:
        return StaticToolPluginOutput(run=ToolRun(tool="regex", status="ok"), findings=[])

    findings: list[dict[str, Any]] = []
    files_scanned = 0
    for path in context.repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".py", ".go", ".js", ".ts", ".tsx", ".java", ".kt", ".rb", ".php"}:
            continue
        files_scanned += 1
        text = path.read_text(encoding="utf-8", errors="ignore")
        for rule in rules:
            pattern = str(rule.get("pattern", ""))
            if not pattern:
                continue
            if not re.search(pattern, text, flags=re.MULTILINE):
                continue
            findings.append(
                {
                    "title": str(rule.get("id", "Regex rule match")),
                    "asset": context.target,
                    "component": str(path),
                    "summary": str(rule.get("message", "Regex scanner matched a configured pattern.")),
                    "severity": str(rule.get("severity", "Medium")),
                    "category": str(rule.get("category", "static_analysis")),
                    "source": "regex",
                    "likely_impact": int(rule.get("likely_impact", 2)),
                    "code_confidence": float(rule.get("code_confidence", 0.7)),
                    "pattern_severity": int(rule.get("pattern_severity", 2)),
                    "recommendations": [str(x) for x in rule.get("recommendations", [])]
                    if isinstance(rule.get("recommendations", []), list)
                    else [],
                    "metadata": {"pattern": pattern},
                }
            )

    run = ToolRun(
        tool="regex",
        status="ok",
        stdout=f"files_scanned={files_scanned}",
    )
    return StaticToolPluginOutput(run=run, findings=findings)


register_static_tool("regex", _regex_plugin)


def _load_static_plugins(module_cfg: dict[str, Any]) -> None:
    logger = get_module_logger("static_analysis")
    plugin_entries = module_cfg.get("plugin_modules", [])
    if not isinstance(plugin_entries, list):
        logger.warning("static_analysis.plugin_modules must be a list.")
        return

    for idx, entry in enumerate(plugin_entries):
        plugin_ref = str(entry).strip()
        if not plugin_ref:
            continue
        try:
            if plugin_ref.endswith(".py"):
                path = Path(plugin_ref).resolve()
                module_name = f"openclaw_ext_static_plugin_{idx}"
                spec = importlib.util.spec_from_file_location(module_name, path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Unable to load plugin path: {path}")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            else:
                importlib.import_module(plugin_ref)
            logger.info("Loaded static plugin module: %s", plugin_ref)
        except Exception:
            logger.exception("Failed to load static plugin module: %s", plugin_ref)


def run_static_analysis(
    target: str,
    repo_path: str | Path,
    config: dict,
    output_dir: str | Path,
) -> StaticAnalysisResult:
    logger = get_module_logger("static_analysis")
    setup_logging(config)
    set_scope_config(config)
    validate(target)

    module_cfg = config.get("modules", {}).get("static_analysis", {})
    if not module_cfg.get("enabled", True):
        logger.info("Static analysis disabled for target=%s", target)
        return StaticAnalysisResult()

    _load_static_plugins(module_cfg)

    root = Path(repo_path).resolve()
    reports = Path(output_dir).resolve()
    reports.mkdir(parents=True, exist_ok=True)

    tools = [str(x).strip().lower() for x in module_cfg.get("tools", []) if str(x).strip()]
    logger.info("Starting static analysis target=%s tools=%s", target, tools)
    result = StaticAnalysisResult()
    context = StaticToolContext(
        target=target,
        repo_root=root,
        reports_dir=reports,
        module_cfg=module_cfg,
    )

    for tool_name in tools:
        plugin = STATIC_TOOL_REGISTRY.get(tool_name)
        if plugin is None:
            logger.warning("No registered static tool plugin for '%s'.", tool_name)
            result.tool_runs.append(ToolRun(tool=tool_name, status="unsupported"))
            continue

        try:
            output = plugin(context)
            output = _validate_plugin_output(output, tool_name)
            result.tool_runs.append(output.run)
            result.findings.extend(output.findings)
            logger.info(
                "Static tool completed tool=%s status=%s findings=%s",
                output.run.tool,
                output.run.status,
                len(output.findings),
            )
        except Exception:
            logger.exception("Static tool plugin failed: %s", tool_name)
            result.tool_runs.append(ToolRun(tool=tool_name, status="error"))

    logger.info(
        "Static analysis complete target=%s findings=%s tool_runs=%s",
        target,
        len(result.findings),
        len(result.tool_runs),
    )
    return result
