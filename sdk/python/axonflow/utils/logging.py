"""Logging utilities for AxonFlow SDK."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure_logging(
    level: int = logging.INFO,
    json_format: bool = False,
) -> None:
    """Configure structured logging for AxonFlow SDK.

    Args:
        level: Logging level (default: INFO)
        json_format: Use JSON format for logs (default: False)
    """
    # Configure structlog processors
    processors: list[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger.

    Args:
        name: Logger name

    Returns:
        Configured structured logger
    """
    return structlog.get_logger(name)


class LogContext:
    """Context manager for adding log context."""

    def __init__(self, logger: structlog.stdlib.BoundLogger, **context: Any) -> None:
        """Initialize log context.

        Args:
            logger: Logger to bind context to
            **context: Context key-value pairs
        """
        self._logger = logger
        self._context = context
        self._original_context: dict[str, Any] = {}

    def __enter__(self) -> structlog.stdlib.BoundLogger:
        """Enter context and bind values."""
        self._original_context = dict(self._logger._context)  # type: ignore[attr-defined]
        return self._logger.bind(**self._context)

    def __exit__(self, *args: Any) -> None:
        """Exit context and restore original values."""
        # Restore original context
        self._logger._context = self._original_context  # type: ignore[attr-defined]
