from __future__ import annotations

import collections
import json
from datetime import datetime, timezone
from pathlib import Path

from .logging_utils import get_module_logger, setup_logging
from .models import Finding
from .scope_guard import set_scope_config, validate


def _findings_to_markdown(findings: list[Finding]) -> str:
    lines: list[str] = []
    if not findings:
        return "- No findings generated in this run."

    ordered = sorted(findings, key=lambda item: item.severity_score(), reverse=True)
    for idx, finding in enumerate(ordered, start=1):
        lines.append(f"### {idx}. {finding.title}")
        lines.append(f"- Severity: {finding.severity}")
        lines.append(f"- Confidence: {finding.code_confidence}")
        lines.append(f"- Likely Impact: {finding.likely_impact}")
        lines.append(f"- Asset: {finding.asset}")
        lines.append(f"- Component: {finding.component}")
        lines.append(f"- Category: {finding.category}")
        lines.append(f"- Source: {finding.source}")
        lines.append(f"- Summary: {finding.summary}")
        if finding.recommendations:
            lines.append("- Recommendations:")
            for rec in finding.recommendations:
                lines.append(f"  - {rec}")
        lines.append("")
    return "\n".join(lines).strip()


def _counts_markdown(title: str, counter: collections.Counter[str]) -> str:
    if not counter:
        return f"### {title}\n- None"

    lines = [f"### {title}", "| Key | Count |", "| --- | ---: |"]
    for key in sorted(counter.keys()):
        lines.append(f"| {key} | {counter[key]} |")
    return "\n".join(lines)


def generate_report(
    target: str,
    findings: list[Finding],
    config: dict,
    output_dir: str | Path | None = None,
) -> dict[str, str]:
    logger = get_module_logger("report_generator")
    setup_logging(config)
    set_scope_config(config)
    validate(target)

    reporting_cfg = config.get("modules", {}).get("reporting", {})
    out_dir = Path(output_dir or reporting_cfg.get("output_dir", "./reports")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    template_path = Path(str(reporting_cfg.get("template", "templates/triage_friendly_report.md")))
    template_text = template_path.read_text(encoding="utf-8")

    generated_at = datetime.now(timezone.utc).isoformat()
    severity_counter = collections.Counter(item.severity for item in findings)
    source_counter = collections.Counter(item.source for item in findings)
    findings_markdown = _findings_to_markdown(findings)
    rendered = template_text.format(
        target=target,
        generated_at=generated_at,
        finding_count=len(findings),
        severity_breakdown=_counts_markdown("Severity Breakdown", severity_counter),
        source_breakdown=_counts_markdown("Source Breakdown", source_counter),
        findings_markdown=findings_markdown,
        program_name=config.get("program", {}).get("name", "Unknown Program"),
        program_platform=config.get("program", {}).get("platform", "Unknown Platform"),
    )

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    markdown_path = out_dir / f"openclaw_report_{stamp}.md"
    json_path = out_dir / f"openclaw_report_{stamp}.json"

    markdown_path.write_text(rendered, encoding="utf-8")
    json_path.write_text(
        json.dumps([item.to_dict() for item in findings], indent=2),
        encoding="utf-8",
    )

    logger.info(
        "Generated reports target=%s findings=%s markdown=%s json=%s",
        target,
        len(findings),
        str(markdown_path),
        str(json_path),
    )
    return {
        "markdown_report": str(markdown_path),
        "json_report": str(json_path),
    }
