from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from typing import Any
import zipfile

from .triage import validation_checklist_for_finding


def _safe_copy_file(src: Path, dest: Path) -> bool:
    try:
        if not src.exists() or not src.is_file():
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return True
    except Exception:
        return False


def _write_zip_from_dir(source_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in source_dir.rglob("*"):
            if item == zip_path or item.is_dir():
                continue
            archive.write(item, arcname=str(item.relative_to(source_dir)))


def _render_findings_markdown(
    *,
    target: str,
    generated_at: str,
    finding_count: int,
    filter_mode: str,
    selected_severities: list[str],
    findings_text: str,
) -> str:
    return (
        "# OpenClaw Bounty Report Pack\n\n"
        f"- Generated (UTC): {generated_at}\n"
        f"- Target: {target}\n"
        f"- Findings: {finding_count}\n"
        f"- Filter mode: {filter_mode}\n"
        f"- Active severities: {', '.join(selected_severities) if selected_severities else 'none'}\n\n"
        "## Copy/Paste Findings\n\n"
        f"{findings_text.strip() or 'No findings were generated.'}\n"
    )


def _render_validation_markdown(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "# Validation Checklist\n\nNo findings in the current filter set.\n"
    lines: list[str] = ["# Validation Checklist", ""]
    for idx, finding in enumerate(findings, start=1):
        lines.append(f"## {idx}. {finding.get('title', 'Untitled finding')}")
        lines.append(f"- Severity: {finding.get('severity', 'Medium')}")
        lines.append(f"- Category: {finding.get('category', 'general_security')}")
        lines.append(f"- Component: {finding.get('component', '')}")
        lines.append("")
        for check in validation_checklist_for_finding(finding):
            lines.append(f"- [ ] {check}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def export_bounty_pack(
    *,
    output_root: str | Path,
    target: str,
    findings: list[dict[str, Any]],
    findings_text: str,
    summary: dict[str, Any],
    filter_mode: str,
    selected_severities: list[str] | None = None,
) -> dict[str, str]:
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    pack_dir = root / f"bounty_pack_{stamp}"
    pack_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = pack_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    selected = selected_severities or []
    findings_md_path = pack_dir / "findings.md"
    findings_json_path = pack_dir / "findings.json"
    summary_json_path = pack_dir / "summary.json"
    checklist_md_path = pack_dir / "validation_checklist.md"
    zip_path = root / f"{pack_dir.name}.zip"

    findings_md_path.write_text(
        _render_findings_markdown(
            target=target,
            generated_at=generated_at,
            finding_count=len(findings),
            filter_mode=filter_mode,
            selected_severities=selected,
            findings_text=findings_text,
        ),
        encoding="utf-8",
    )
    findings_json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    checklist_md_path.write_text(_render_validation_markdown(findings), encoding="utf-8")

    copied_evidence: list[str] = []
    report_paths = summary.get("report_paths", {}) if isinstance(summary, dict) else {}
    if isinstance(report_paths, dict):
        for key, value in report_paths.items():
            src = Path(str(value or "")).resolve()
            dest_name = f"{key}{src.suffix or '.txt'}"
            if _safe_copy_file(src, evidence_dir / dest_name):
                copied_evidence.append(str((evidence_dir / dest_name).resolve()))

    config_path = Path(str(summary.get("config_path", "") or "")).resolve() if isinstance(summary, dict) else None
    if config_path and _safe_copy_file(config_path, evidence_dir / f"config_snapshot{config_path.suffix or '.yaml'}"):
        copied_evidence.append(str((evidence_dir / f"config_snapshot{config_path.suffix or '.yaml'}").resolve()))

    summary_payload = {
        "generated_at": generated_at,
        "target": target,
        "finding_count": len(findings),
        "filter_mode": filter_mode,
        "selected_severities": selected,
        "copied_evidence_files": copied_evidence,
        "summary": summary if isinstance(summary, dict) else {},
    }
    summary_json_path.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")

    _write_zip_from_dir(pack_dir, zip_path)

    return {
        "pack_dir": str(pack_dir),
        "zip_path": str(zip_path),
        "findings_markdown": str(findings_md_path),
        "findings_json": str(findings_json_path),
        "summary_json": str(summary_json_path),
        "checklist_markdown": str(checklist_md_path),
        "evidence_dir": str(evidence_dir),
    }
