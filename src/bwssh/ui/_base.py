"""Base types and protocol for unlock UI implementations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

# Async callback the TUI invokes once it has a valid session key.
# Receives the session key; returns a dict that must contain "key_count"
# and optionally "keys" (list of dicts with fingerprint/algorithm/comment).
PostUnlockHook = Callable[[str], Awaitable[dict[str, Any]]]


@dataclass
class UnlockResult:
    """Result of an unlock UI interaction.

    Attributes:
        session_key: The Bitwarden session key, or None on failure/cancel.
        key_count: Number of SSH keys loaded by the daemon (0 if unknown).
        keys: Details of each loaded key (fingerprint, algorithm, comment).
        error: Human-readable error message, or None on success.
    """

    session_key: str | None = None
    key_count: int = 0
    keys: list[dict[str, str]] = field(default_factory=list)
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
