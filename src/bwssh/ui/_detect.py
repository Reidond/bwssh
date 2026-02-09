"""Environment detection for UI mode selection."""

from __future__ import annotations

import os
from typing import Literal

UIMode = Literal["tui", "graphical"]


def detect_ui_mode() -> UIMode:
    """Detect the appropriate UI mode based on environment.

    Checks in order:

    1. ``$BWSSH_UNLOCK_MODE`` override (``"tui"`` or ``"graphical"``).
    2. ``$DISPLAY`` or ``$WAYLAND_DISPLAY`` for a graphical session.
    3. Default to ``"tui"``.
    """
    override = os.environ.get("BWSSH_UNLOCK_MODE", "").lower()
    if override in ("tui", "graphical"):
        return override  # type: ignore[return-value]

    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return "graphical"

    return "tui"
