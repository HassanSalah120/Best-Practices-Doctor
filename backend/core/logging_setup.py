"""
Structured logging setup (local-first).
"""

from __future__ import annotations

import logging
import os

import structlog


_CONFIGURED = False


def configure_logging() -> None:
    """
    Configure stdlib + structlog once.

    Uses concise console logs in dev and JSON logs when
    `BPD_LOG_FORMAT=json` is set.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = str(os.environ.get("BPD_LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_format = str(os.environ.get("BPD_LOG_FORMAT", "console")).strip().lower()

    renderer = (
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer()
    )

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=False)
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    logging.basicConfig(level=level, format="%(message)s")

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)

    _CONFIGURED = True
