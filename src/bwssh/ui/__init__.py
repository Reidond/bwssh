"""Unlock UI abstraction layer.

Provides pluggable UI implementations for the Bitwarden vault unlock
flow.  Three tiers are available for graphical sessions:

1. **GTK 4 + Adwaita** -- native dialog (best experience).
2. **Terminal emulator + TUI** -- ``xdg-terminal-exec bwssh unlock``.
3. **Direct TUI** -- last resort (may fail without a tty).
"""

from __future__ import annotations

import logging

from bwssh.ui._base import PostUnlockHook, UnlockResult, UnlockUI
from bwssh.ui._detect import detect_ui_mode
from bwssh.ui._graphical import GTK_AVAILABLE, GraphicalUnlockUI
from bwssh.ui._terminal import TERMINAL_AVAILABLE, TerminalUnlockUI
from bwssh.ui._tui import TuiUnlockUI

logger = logging.getLogger(__name__)

__all__ = [
    "GraphicalUnlockUI",
    "PostUnlockHook",
    "TerminalUnlockUI",
    "TuiUnlockUI",
    "UnlockResult",
    "UnlockUI",
    "create_unlock_ui",
]


def create_unlock_ui(
    bw_path: str = "bw",
    on_session_ready: PostUnlockHook | None = None,
    ui_mode: str | None = None,
) -> UnlockUI:
    """Create the appropriate unlock UI for the current environment.

    Detection is based on :func:`detect_ui_mode`.  In graphical mode
    the factory uses a three-tier fallback:

    1. :class:`GraphicalUnlockUI` if GTK 4 + libadwaita is available.
    2. :class:`TerminalUnlockUI` if ``xdg-terminal-exec`` is on PATH.
    3. :class:`TuiUnlockUI` as a last resort.

    When mode is ``"tui"``, :class:`TuiUnlockUI` is returned directly.

    Parameters:
        bw_path: Path to the ``bw`` CLI binary.
        on_session_ready: Async hook called after a successful
            ``bw unlock``.  Receives the session key and should return
            a dict with at least ``"key_count"``.
        ui_mode: Force a specific UI mode (``"tui"`` or ``"graphical"``).
            When *None*, auto-detection via :func:`detect_ui_mode` is used.
    """
    mode = ui_mode if ui_mode in ("tui", "graphical") else detect_ui_mode()

    if mode == "graphical":
        if GTK_AVAILABLE:
            logger.debug("Using GraphicalUnlockUI (GTK 4 + Adwaita)")
            return GraphicalUnlockUI(bw_path, on_session_ready=on_session_ready)

        if TERMINAL_AVAILABLE:
            logger.debug(
                "GTK 4 not available; falling back to TerminalUnlockUI "
                "(xdg-terminal-exec)"
            )
            return TerminalUnlockUI(bw_path, on_session_ready=on_session_ready)

        logger.debug(
            "GTK 4 and xdg-terminal-exec not available; falling back to TuiUnlockUI"
        )

    return TuiUnlockUI(bw_path, on_session_ready=on_session_ready)
