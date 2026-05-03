from __future__ import annotations

import logging
import time
from pathlib import Path

from .contracts import LOCKED_LOG_DATEFMT, LOCKED_LOG_FORMAT, LOGGING_FORMAT_VERSION


def setup_logging(config: dict) -> None:
    logging_cfg = config.get("logging", {})
    level_name = str(logging_cfg.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    lock_format = bool(logging_cfg.get("lock_format", True))
    if lock_format:
        fmt = LOCKED_LOG_FORMAT
        datefmt = LOCKED_LOG_DATEFMT
    else:
        fmt = str(logging_cfg.get("format", LOCKED_LOG_FORMAT))
        datefmt = str(logging_cfg.get("datefmt", LOCKED_LOG_DATEFMT))

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    log_file = logging_cfg.get("file")
    if log_file:
        path = Path(str(log_file)).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))

    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
    formatter.converter = time.gmtime
    for handler in handlers:
        handler.setFormatter(formatter)
    logging.basicConfig(level=level, handlers=handlers, force=True)

    # Expose active logging contract version for downstream tooling.
    logging.getLogger("openclaw.logging_utils").debug(
        "logging_format_contract_version=%s lock_format=%s",
        LOGGING_FORMAT_VERSION,
        lock_format,
    )


def get_module_logger(module_name: str) -> logging.Logger:
    return logging.getLogger(f"openclaw.{module_name}")
