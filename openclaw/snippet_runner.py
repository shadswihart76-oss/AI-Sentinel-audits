from __future__ import annotations

import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .model_runtime import build_model_caller_from_config
from .pipeline import OpenClawPipeline


@dataclass
class SnippetRunResult:
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    markdown_report: str
    json_report: str


@dataclass
class ZipRunResult:
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    markdown_report: str
    json_report: str


@dataclass
class RepoRunResult:
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    markdown_report: str
    json_report: str


@dataclass
class FileRunResult:
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    markdown_report: str
    json_report: str


ProgressCallback = Callable[[str, str, dict[str, Any]], None]
TAR_EXTENSIONS = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
)


def _build_session_root(workspace_root: str | None, default_subdir: str) -> Path:
    base_root = Path(workspace_root).resolve() if workspace_root else Path.cwd() / "reports" / default_subdir
    base_root.mkdir(parents=True, exist_ok=True)
    return base_root


def _build_zip_session_root(workspace_root: str | None) -> Path:
    if workspace_root:
        root = Path(workspace_root).resolve()
    elif os.name == "nt":
        # Keep extraction paths short on Windows to avoid MAX_PATH issues in deep repos.
        root = Path(tempfile.gettempdir()) / "openclaw_zip_sessions"
    else:
        root = Path.cwd() / "reports" / "zip_sessions"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _build_zip_report_root(workspace_root: str | None, session_dir: Path) -> Path:
    if workspace_root:
        root = session_dir / "reports"
    else:
        root = (Path.cwd() / "reports" / "zip_runs").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _is_path_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    # UNIX file type bits are stored in the high 16 bits of external_attr.
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _detect_archive_kind(file_path: Path) -> str | None:
    lower = file_path.name.lower()
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith(TAR_EXTENSIONS):
        return "tar"
    # Signature fallback for oddly named uploads (e.g., no extension).
    try:
        if zipfile.is_zipfile(file_path):
            return "zip"
    except Exception:
        pass
    try:
        if tarfile.is_tarfile(file_path):
            return "tar"
    except Exception:
        pass
    return None


def _safe_extract_zip(zip_path: Path, extract_dir: Path) -> None:
    if zip_path.suffix.lower() != ".zip":
        raise ValueError(f"Expected a .zip file, got: {zip_path.name}")

    extract_root = extract_dir.resolve()
    extract_root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as archive:
        for info in archive.infolist():
            if _is_zip_symlink(info):
                raise ValueError(f"ZIP contains symlink entry, which is not allowed: {info.filename}")

            destination = (extract_root / info.filename).resolve()
            if not _is_path_within(extract_root, destination):
                raise ValueError(f"Unsafe ZIP entry outside extraction root: {info.filename}")

            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, destination.open("wb") as sink:
                shutil.copyfileobj(source, sink)


def _safe_extract_tar(tar_path: Path, extract_dir: Path) -> None:
    if _detect_archive_kind(tar_path) != "tar":
        raise ValueError(f"Expected a supported TAR archive, got: {tar_path.name}")

    extract_root = extract_dir.resolve()
    extract_root.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "r:*") as archive:
        for member in archive.getmembers():
            member_name = (member.name or "").strip()
            if not member_name:
                continue
            if member.issym() or member.islnk():
                raise ValueError(f"TAR contains link entry, which is not allowed: {member.name}")
            destination = (extract_root / member_name).resolve()
            if not _is_path_within(extract_root, destination):
                raise ValueError(f"Unsafe TAR entry outside extraction root: {member.name}")

            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if member.isfile():
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Could not extract TAR file entry: {member.name}")
                with source, destination.open("wb") as sink:
                    shutil.copyfileobj(source, sink)
                continue

            raise ValueError(f"Unsupported TAR entry type: {member.name}")


def _safe_extract_archive(archive_path: Path, extract_dir: Path) -> str:
    kind = _detect_archive_kind(archive_path)
    if kind == "zip":
        _safe_extract_zip(archive_path, extract_dir)
        return "zip"
    if kind == "tar":
        _safe_extract_tar(archive_path, extract_dir)
        return "tar"
    raise ValueError(
        "Unsupported archive type. Use .zip or TAR family (.tar/.tar.gz/.tgz/.tar.bz2/.tar.xz)."
    )


def _detect_repo_root(extract_root: Path) -> Path:
    candidates = [item for item in extract_root.iterdir() if item.name != "__MACOSX"]
    if len(candidates) == 1 and candidates[0].is_dir():
        return candidates[0].resolve()
    return extract_root.resolve()


def _build_summary(result: Any, *, extras: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": result.target,
        "repo_path": result.repo_path,
        "config_path": result.config_path,
        "static_findings": len(result.static_analysis.findings),
        "ai_findings": result.ai_findings_count,
        "cross_file_findings": result.cross_file_findings_count,
        "final_findings": len(result.final_findings),
        "stage_errors": result.stage_errors,
        "report_paths": result.report_paths,
        **extras,
    }


def format_hackerone_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No findings were generated."

    lines: list[str] = []
    for idx, item in enumerate(findings, start=1):
        lines.append(f"{idx}. {item.get('title', 'Untitled finding')}")
        lines.append(f"Severity: {item.get('severity', 'Medium')}")
        lines.append(f"Category: {item.get('category', 'general_security')}")
        lines.append(f"Component: {item.get('component', '')}")
        lines.append(f"Summary: {item.get('summary', '')}")
        recs = item.get("recommendations", [])
        if isinstance(recs, list) and recs:
            lines.append("Recommendations:")
            for rec in recs:
                lines.append(f"- {rec}")
        lines.append("")
    return "\n".join(lines).strip()


def run_snippet_pipeline(
    *,
    config_path: str,
    target: str,
    code_snippet: str,
    file_name: str = "snippet.py",
    workspace_root: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> SnippetRunResult:
    def progress(stage: str, status: str, **details: Any) -> None:
        if progress_callback is not None:
            progress_callback(stage, status, details)

    pipeline = OpenClawPipeline(config_path=config_path)
    model_caller = build_model_caller_from_config(pipeline.config)
    progress("snippet_input", "start", file_name=file_name)

    base_root = _build_session_root(workspace_root, "snippet_sessions")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    session_dir = base_root / f"session_{stamp}"
    session_dir.mkdir(parents=True, exist_ok=True)

    safe_name = file_name.strip() or "snippet.py"
    if Path(safe_name).name != safe_name:
        safe_name = Path(safe_name).name
    snippet_path = session_dir / safe_name
    snippet_path.write_text(code_snippet, encoding="utf-8")
    progress("snippet_input", "done", snippet_file=str(snippet_path))

    result = pipeline.run(
        target=target,
        repo_path=str(session_dir),
        output_dir=str(session_dir / "reports"),
        model_caller=model_caller,
        max_ai_files=200,
        progress_callback=progress_callback,
    )

    summary = _build_summary(
        result,
        extras={
        "snippet_file": str(snippet_path),
        "session_dir": str(session_dir),
        },
    )

    return SnippetRunResult(
        summary=summary,
        findings=result.final_findings,
        markdown_report=str(result.report_paths.get("markdown_report", "")),
        json_report=str(result.report_paths.get("json_report", "")),
    )


def run_zip_pipeline(
    *,
    config_path: str,
    target: str,
    zip_path: str,
    workspace_root: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> ZipRunResult:
    def progress(stage: str, status: str, **details: Any) -> None:
        if progress_callback is not None:
            progress_callback(stage, status, details)

    archive_path = Path(zip_path).resolve()
    if not archive_path.exists():
        raise FileNotFoundError(f"ZIP file not found: {archive_path}")
    if not archive_path.is_file():
        raise ValueError(f"ZIP path must be a file: {archive_path}")

    pipeline = OpenClawPipeline(config_path=config_path)
    model_caller = build_model_caller_from_config(pipeline.config)

    base_root = _build_zip_session_root(workspace_root)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    session_dir = base_root / f"s_{stamp}"
    session_dir.mkdir(parents=True, exist_ok=True)

    extract_dir = session_dir / "x"
    progress("zip_extract", "start", zip_file=str(archive_path), extract_dir=str(extract_dir))
    _safe_extract_zip(archive_path, extract_dir)
    progress("zip_extract", "done", extract_dir=str(extract_dir))
    progress("detect_repo_root", "start", extract_dir=str(extract_dir))
    repo_root = _detect_repo_root(extract_dir)
    progress("detect_repo_root", "done", repo_root=str(repo_root))
    report_root = _build_zip_report_root(workspace_root, session_dir)

    result = pipeline.run(
        target=target,
        repo_path=str(repo_root),
        output_dir=str(report_root),
        model_caller=model_caller,
        max_ai_files=1000,
        progress_callback=progress_callback,
    )

    extracted_files = [p for p in repo_root.rglob("*") if p.is_file()]
    summary = _build_summary(
        result,
        extras={
            "zip_file": str(archive_path),
            "session_dir": str(session_dir),
            "extract_dir": str(extract_dir),
            "extracted_repo_path": str(repo_root),
            "extracted_file_count": len(extracted_files),
        },
    )

    return ZipRunResult(
        summary=summary,
        findings=result.final_findings,
        markdown_report=str(result.report_paths.get("markdown_report", "")),
        json_report=str(result.report_paths.get("json_report", "")),
    )


def run_repo_pipeline(
    *,
    config_path: str,
    target: str,
    repo_path: str,
    workspace_root: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> RepoRunResult:
    def progress(stage: str, status: str, **details: Any) -> None:
        if progress_callback is not None:
            progress_callback(stage, status, details)

    repo_root = Path(repo_path).resolve()
    if not repo_root.exists():
        raise FileNotFoundError(f"Repo folder not found: {repo_root}")
    if not repo_root.is_dir():
        raise NotADirectoryError(f"Repo path must be a directory: {repo_root}")

    pipeline = OpenClawPipeline(config_path=config_path)
    model_caller = build_model_caller_from_config(pipeline.config)

    base_root = _build_session_root(workspace_root, "folder_sessions")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    session_dir = base_root / f"session_{stamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    report_root = session_dir / "reports"
    report_root.mkdir(parents=True, exist_ok=True)

    progress("folder_input", "done", repo_root=str(repo_root))
    result = pipeline.run(
        target=target,
        repo_path=str(repo_root),
        output_dir=str(report_root),
        model_caller=model_caller,
        max_ai_files=2000,
        progress_callback=progress_callback,
    )

    summary = _build_summary(
        result,
        extras={
            "repo_input_path": str(repo_root),
            "session_dir": str(session_dir),
            "report_dir": str(report_root),
        },
    )
    return RepoRunResult(
        summary=summary,
        findings=result.final_findings,
        markdown_report=str(result.report_paths.get("markdown_report", "")),
        json_report=str(result.report_paths.get("json_report", "")),
    )


def run_file_pipeline(
    *,
    config_path: str,
    target: str,
    file_path: str,
    workspace_root: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> FileRunResult:
    def progress(stage: str, status: str, **details: Any) -> None:
        if progress_callback is not None:
            progress_callback(stage, status, details)

    upload_path = Path(file_path).resolve()
    if not upload_path.exists():
        raise FileNotFoundError(f"Upload file not found: {upload_path}")
    if not upload_path.is_file():
        raise ValueError(f"Upload path must be a file: {upload_path}")

    archive_kind = _detect_archive_kind(upload_path)

    # Keep existing ZIP path behavior for compatibility and stronger ZIP safety checks.
    if archive_kind == "zip":
        zip_result = run_zip_pipeline(
            config_path=config_path,
            target=target,
            zip_path=str(upload_path),
            workspace_root=workspace_root,
            progress_callback=progress_callback,
        )
        return FileRunResult(
            summary=zip_result.summary,
            findings=zip_result.findings,
            markdown_report=zip_result.markdown_report,
            json_report=zip_result.json_report,
        )

    pipeline = OpenClawPipeline(config_path=config_path)
    model_caller = build_model_caller_from_config(pipeline.config)

    base_root = _build_session_root(workspace_root, "file_sessions")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    session_dir = base_root / f"session_{stamp}"
    repo_root = session_dir / "repo"
    report_root = session_dir / "reports"
    repo_root.mkdir(parents=True, exist_ok=True)
    report_root.mkdir(parents=True, exist_ok=True)

    copied_file = repo_root / upload_path.name
    extracted_repo_path = ""
    if archive_kind == "tar":
        extract_dir = session_dir / "x"
        progress("archive_extract", "start", upload_file=str(upload_path), extract_dir=str(extract_dir))
        extracted_type = _safe_extract_archive(upload_path, extract_dir)
        progress("archive_extract", "done", extract_dir=str(extract_dir), archive_type=extracted_type)
        progress("detect_repo_root", "start", extract_dir=str(extract_dir))
        repo_root = _detect_repo_root(extract_dir)
        progress("detect_repo_root", "done", repo_root=str(repo_root))
        extracted_repo_path = str(repo_root)
    else:
        progress("file_input", "start", upload_file=str(upload_path), copied_file=str(copied_file))
        shutil.copy2(upload_path, copied_file)
        progress("file_input", "done", copied_file=str(copied_file))

    result = pipeline.run(
        target=target,
        repo_path=str(repo_root),
        output_dir=str(report_root),
        model_caller=model_caller,
        max_ai_files=500,
        progress_callback=progress_callback,
    )

    summary = _build_summary(
        result,
        extras={
            "upload_file": str(upload_path),
            "session_dir": str(session_dir),
            "archive_kind": archive_kind or "single_file",
            "repo_input_path": str(repo_root),
            "copied_file": str(copied_file) if not archive_kind else "",
            "extracted_repo_path": extracted_repo_path,
        },
    )
    return FileRunResult(
        summary=summary,
        findings=result.final_findings,
        markdown_report=str(result.report_paths.get("markdown_report", "")),
        json_report=str(result.report_paths.get("json_report", "")),
    )
