"""Unlock UI abstraction layer.

Provides pluggable UI implementations for the Bitwarden vault unlock
flow.  Currently supports TUI (via *textual*); graphical mode is
planned for when ``bwssh`` is running inside a desktop session.
"""

from __future__ import annotations

from bwssh.ui._base import UnlockResult, UnlockUI
from bwssh.ui._detect import detect_ui_mode
from bwssh.ui._tui import TuiUnlockUI

__all__ = ["TuiUnlockUI", "UnlockResult", "UnlockUI", "create_unlock_ui"]


def create_unlock_ui(bw_path: str = "bw") -> UnlockUI:
    """Create the appropriate unlock UI for the current environment.

    Detection is based on :func:`detect_ui_mode`.  When graphical mode
    is implemented this factory will return the graphical variant
    automatically when a display server is detected.  For now it always
    returns :class:`TuiUnlockUI`.
    """
    mode = detect_ui_mode()
    if mode == "graphical":
        # Future: return GraphicalUnlockUI(bw_path)
        # Fall back to TUI until graphical mode is implemented.
        pass
    return TuiUnlockUI(bw_path)
