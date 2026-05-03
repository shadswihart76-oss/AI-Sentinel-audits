from __future__ import annotations

from urllib.parse import urlparse

from .logging_utils import get_module_logger


class ScopeViolation(Exception):
    """Raised when a target is outside configured scope."""


_ACTIVE_CONFIG: dict | None = None


def _extract_host(target: str) -> str:
    value = target.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").lower()
    if "/" not in value and "." in value:
        return value.split(":", maxsplit=1)[0]
    return ""


def matches_domain(target: str, domain_pattern: str) -> bool:
    host = _extract_host(target)
    if not host:
        return False

    pattern = domain_pattern.strip().lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base)
    return host == pattern


def is_in_scope(target: str, config: dict) -> bool:
    scope = config.get("scope", {})
    normalized = target.strip().lower()

    for domain in scope.get("domains", []):
        if matches_domain(normalized, str(domain)):
            return True

    for repo in scope.get("github_repos", []):
        repo_value = str(repo).strip().lower()
        if normalized == repo_value or normalized.startswith(repo_value + "/"):
            return True

    for package_name in scope.get("mobile_packages", []):
        if normalized == str(package_name).strip().lower():
            return True

    return False


def guard_target(target: str, config: dict) -> bool:
    logger = get_module_logger("scope_guard")
    if not is_in_scope(target, config):
        logger.error("Scope validation failed for target=%s", target)
        raise ScopeViolation(f"Target out of scope: {target}")
    logger.debug("Scope validation passed for target=%s", target)
    return True


def set_scope_config(config: dict) -> None:
    global _ACTIVE_CONFIG
    _ACTIVE_CONFIG = config


def validate(target: str, config: dict | None = None) -> bool:
    """
    Validate scope using explicit config or pre-loaded module config.

    Supports both:
      - scope_guard.validate(target, config)
      - scope_guard.validate(target) after scope_guard.set_scope_config(config)
    """
    effective = config or _ACTIVE_CONFIG
    if effective is None:
        raise ValueError("Scope config not set. Pass config or call set_scope_config(config).")
    return guard_target(target, effective)


class ScopeGuard:
    def __init__(self, config: dict):
        self.config = config

    def validate(self, target: str) -> bool:
        return validate(target, self.config)
