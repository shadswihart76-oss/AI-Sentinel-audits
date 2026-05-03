from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .logging_utils import get_module_logger, setup_logging
from .scope_guard import set_scope_config, validate

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "reports",
}

CODE_EXTENSIONS = {
    ".py",
    ".go",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".swift",
    ".rb",
    ".php",
    ".rs",
    ".sol",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
}

DOC_EXTENSIONS = {".md", ".rst", ".txt"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}


@dataclass
class PassiveReconResult:
    repo_path: str
    code_files: list[str] = field(default_factory=list)
    doc_files: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _collect_git_metadata(repo_path: Path) -> list[str]:
    notes: list[str] = []
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        notes.append("No .git directory found. Recon is local-file-only.")
        return notes

    head_file = git_dir / "HEAD"
    if head_file.exists():
        head_value = head_file.read_text(encoding="utf-8", errors="ignore").strip()
        notes.append(f"git_head={head_value}")

    config_file = git_dir / "config"
    if config_file.exists():
        notes.append("git_config_present=true")
    else:
        notes.append("git_config_present=false")

    return notes


def run_passive_recon(target: str, repo_path: str | Path, config: dict) -> PassiveReconResult:
    logger = get_module_logger("passive_recon")
    setup_logging(config)
    set_scope_config(config)
    validate(target)

    guardrails = config.get("guardrails", {})
    if guardrails.get("allow_active_requests", False):
        raise ValueError("v0 disallows active requests. Set allow_active_requests=false.")

    root = Path(repo_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repo path not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Repo path must be a directory: {root}")

    result = PassiveReconResult(repo_path=str(root))
    result.notes.append("passive_mode=read_only")
    result.notes.append("network_usage=disabled")
    result.notes.extend(_collect_git_metadata(root))

    for current_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        base = Path(current_root)
        for file_name in files:
            path = base / file_name
            suffix = path.suffix.lower()
            full_path = str(path.resolve())
            if suffix in CODE_EXTENSIONS:
                result.code_files.append(full_path)
            if suffix in DOC_EXTENSIONS:
                result.doc_files.append(full_path)
            if suffix in JS_EXTENSIONS:
                result.js_files.append(full_path)

    result.code_files.sort()
    result.doc_files.sort()
    result.js_files.sort()
    logger.info(
        "Passive recon complete target=%s code_files=%s doc_files=%s js_files=%s",
        target,
        len(result.code_files),
        len(result.doc_files),
        len(result.js_files),
    )
    return result
