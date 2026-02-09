"""Base types and protocol for unlock UI implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class UnlockResult:
    """Result of an unlock UI interaction.

    Attributes:
        session_key: The Bitwarden session key, or None on failure/cancel.
        error: Human-readable error message, or None on success.
    """

    session_key: str | None = None
    error: str | None = None


class UnlockUI(Protocol):
    """Protocol for unlock UI implementations.

    Each implementation owns the terminal/window for its lifetime
    and returns an ``UnlockResult`` when done.  The ``run()`` method
    is synchronous and blocking.
    """

    def run(self) -> UnlockResult:
        """Show UI, collect password, run bw unlock, return result."""
        ...
