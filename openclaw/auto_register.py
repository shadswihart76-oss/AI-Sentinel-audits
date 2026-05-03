from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
import zipfile
from typing import Any

import yaml


class AutoRegisterError(Exception):
    """Raised when auto-registration cannot determine or persist scope info."""


@dataclass
class AutoRegisterResult:
    target: str
    repo_slug: str
    owner: str
    repo_name: str
    config_path: str
    backup_path: str
    added_to_scope: bool


_BRANCH_SUFFIXES = ("master", "main", "develop", "development", "dev", "trunk", "head")
_COMMIT_SUFFIX_RE = re.compile(r"-[0-9a-fA-F]{7,40}$")
_INVALID_REPO_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]+")
_PLACEHOLDER_RE = re.compile(r"<[^>]+>")
_VALID_SLUG_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _sanitize_repo_name(value: str) -> str:
    name = value.strip()
    if name.endswith(".git"):
        name = name[:-4]
    lower = name.lower()
    for suffix in _BRANCH_SUFFIXES:
        token = f"-{suffix}"
        if lower.endswith(token):
            name = name[: -len(token)]
            break
    name = _COMMIT_SUFFIX_RE.sub("", name)
    name = _INVALID_REPO_CHARS_RE.sub("-", name).strip("._-")
    if not name:
        raise AutoRegisterError("Could not derive repository name from ZIP.")
    return name


def _zip_top_level_name(zip_path: Path) -> str | None:
    with zipfile.ZipFile(zip_path, "r") as archive:
        top_levels: set[str] = set()
        for info in archive.infolist():
            filename = info.filename.strip()
            if not filename or filename.startswith("__MACOSX/"):
                continue
            top = filename.split("/", maxsplit=1)[0].strip()
            if top:
                top_levels.add(top)
        if len(top_levels) == 1:
            return next(iter(top_levels))
    return None


def _extract_owner_from_target(target: str) -> str | None:
    text = target.strip()
    if "/" not in text:
        return None
    owner = text.split("/", maxsplit=1)[0].strip()
    if not owner or _PLACEHOLDER_RE.search(owner):
        return None
    if not _VALID_SLUG_SEGMENT_RE.match(owner):
        return None
    return owner


def _extract_owner_from_config(config: dict[str, Any]) -> str | None:
    scope = config.get("scope", {})
    repos = scope.get("github_repos", []) if isinstance(scope, dict) else []
    if not isinstance(repos, list):
        return None
    for item in repos:
        value = str(item).strip()
        if "/" not in value:
            continue
        owner = value.split("/", maxsplit=1)[0].strip()
        if not owner or _PLACEHOLDER_RE.search(owner):
            continue
        if not _VALID_SLUG_SEGMENT_RE.match(owner):
            continue
        return owner
    return None


def _load_raw_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        raise AutoRegisterError(f"Config file not found: {config_path}")
    text = config_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise AutoRegisterError("Config must be a mapping.")
    openclaw = parsed.get("openclaw")
    if not isinstance(openclaw, dict):
        raise AutoRegisterError("Config must contain top-level `openclaw` mapping.")
    return parsed


def _write_config_with_backup(config_path: Path, doc: dict[str, Any]) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(config_path.suffix + f".bak_{stamp}")
    backup_path.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")
    dumped = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    config_path.write_text(dumped, encoding="utf-8")
    return backup_path


def auto_register_repo_from_zip(
    *,
    config_path: str,
    zip_path: str,
    current_target: str = "",
    default_owner: str = "coinbase",
) -> AutoRegisterResult:
    cfg_path = Path(config_path).resolve()
    archive_path = Path(zip_path).resolve()
    if not archive_path.exists() or not archive_path.is_file():
        raise AutoRegisterError(f"ZIP file not found: {archive_path}")

    parsed = _load_raw_config(cfg_path)
    openclaw = parsed["openclaw"]

    top_level = _zip_top_level_name(archive_path)
    candidate = top_level or archive_path.stem
    repo_name = _sanitize_repo_name(candidate)

    owner = (
        _extract_owner_from_target(current_target)
        or _extract_owner_from_config(openclaw)
        or default_owner
    )
    owner = owner.strip()
    if not owner or _PLACEHOLDER_RE.search(owner) or not _VALID_SLUG_SEGMENT_RE.match(owner):
        raise AutoRegisterError("Could not determine repository owner for target.")

    repo_slug = f"{owner}/{repo_name}"
    target = repo_slug

    scope = openclaw.setdefault("scope", {})
    if not isinstance(scope, dict):
        raise AutoRegisterError("`openclaw.scope` must be a mapping.")
    repos = scope.setdefault("github_repos", [])
    if not isinstance(repos, list):
        raise AutoRegisterError("`openclaw.scope.github_repos` must be a list.")

    normalized_repos = [str(item).strip().lower() for item in repos]
    added = repo_slug.lower() not in normalized_repos
    if added:
        repos.append(repo_slug)

    backup = _write_config_with_backup(cfg_path, parsed)
    return AutoRegisterResult(
        target=target,
        repo_slug=repo_slug,
        owner=owner,
        repo_name=repo_name,
        config_path=str(cfg_path),
        backup_path=str(backup),
        added_to_scope=added,
    )
