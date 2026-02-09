"""Graphical unlock UI — placeholder for future implementation."""

from __future__ import annotations

from typing import NoReturn


class GraphicalUnlockUI:
    """Graphical unlock UI using a desktop utility window.

    This is a placeholder for future implementation.  When complete it
    will show a GTK / Qt utility window with a password input field,
    suitable for use inside a graphical desktop session.
    """

    def __init__(self, bw_path: str = "bw") -> None:
        self._bw_path = bw_path

    def run(self) -> NoReturn:
        """Show graphical unlock dialog.

        Raises:
            NotImplementedError: Always — graphical mode is not yet available.
        """
        raise NotImplementedError(
            "Graphical unlock UI is not yet implemented. "
            "Set BWSSH_UNLOCK_MODE=tui to use the TUI instead."
        )
