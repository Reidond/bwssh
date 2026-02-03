"""Structured logging configuration for bwssh.

Configures Python stdlib logging with timestamp, level, module, and message.
Logs to stderr. Audit logging for sign operations includes fingerprint, peer_pid,
peer_exe, and result (allow/deny).

CRITICAL: Never logs sensitive data (session tokens, private keys, signature payloads).
"""

from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging to stderr.

    Args:
        level: Log level as string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               Defaults to INFO.

    Raises:
        ValueError: If level is not a valid logging level.
    """
    # Validate and convert level string to logging constant
    try:
        log_level = getattr(logging, level.upper(), None)
        if log_level is None or not isinstance(log_level, int):
            raise ValueError(f"Invalid log level: {level}")
    except (AttributeError, TypeError) as e:
        raise ValueError(f"Invalid log level: {level}") from e

    # Configure root logger with structured format
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
        force=True,  # Override any existing config
    )
