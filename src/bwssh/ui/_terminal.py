"""Terminal-emulator fallback for graphical unlock.

When GTK 4 is not available but a graphical session is detected, this
module spawns the user's preferred terminal emulator via
``xdg-terminal-exec`` (the freedesktop.org standard) and runs
``bwssh unlock`` inside it with forced TUI mode.

After the spawned process exits, success is determined by querying the
daemon's control socket for its current status.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
from typing import TYPE_CHECKING

from bwssh.ui._base import UnlockResult

if TYPE_CHECKING:
    from bwssh.ui._base import PostUnlockHook

logger = logging.getLogger(__name__)

# --- Availability detection ------------------------------------------------

TERMINAL_AVAILABLE = shutil.which("xdg-terminal-exec") is not None

if not TERMINAL_AVAILABLE:
    logger.debug("xdg-terminal-exec not found on $PATH")


class TerminalUnlockUI:
    """Unlock UI that spawns ``xdg-terminal-exec bwssh unlock``.

    This is the middle-tier fallback used when a graphical session is
    detected but GTK 4 is not available.  It relies on
    ``xdg-terminal-exec`` to launch the user's preferred terminal
    emulator with ``bwssh unlock`` running in forced TUI mode.

    After the child process exits, the daemon control socket is queried
    to determine whether the unlock succeeded and how many keys were
    loaded (avoids needing IPC between the two processes).

    Parameters:
        bw_path: Path to the ``bw`` CLI binary (unused directly, but
            accepted for interface compatibility).
        on_session_ready: Not used — the spawned ``bwssh unlock``
            handles the full pipeline including key loading.  Accepted
            for interface compatibility.
    """

    def __init__(
        self,
        bw_path: str = "bw",
        on_session_ready: PostUnlockHook | None = None,
    ) -> None:
        self._bw_path = bw_path
        self._on_session_ready = on_session_ready

    def run(self) -> UnlockResult:
        """Spawn a terminal with ``bwssh unlock`` and return the result."""
        bwssh_exe = shutil.which("bwssh")
        if bwssh_exe is None:
            return UnlockResult(error="bwssh executable not found on $PATH")

        xdg_exe = shutil.which("xdg-terminal-exec")
        if xdg_exe is None:
            return UnlockResult(error="xdg-terminal-exec not found on $PATH")

        # Force TUI mode in the child so it doesn't recurse into
        # graphical detection.
        env = os.environ.copy()
        env["BWSSH_UNLOCK_MODE"] = "tui"

        logger.debug("Spawning terminal: %s %s unlock", xdg_exe, bwssh_exe)

        try:
            proc = subprocess.run(
                [xdg_exe, bwssh_exe, "unlock"],
                env=env,
                check=False,
            )
        except FileNotFoundError:
            return UnlockResult(error="Failed to spawn terminal emulator")
        except OSError as exc:
            return UnlockResult(error=f"Terminal spawn error: {exc}")

        if proc.returncode != 0:
            logger.debug("Terminal process exited with code %d", proc.returncode)
            return UnlockResult(error="Unlock was cancelled or failed")

        # Query daemon status to determine outcome.
        return self._query_daemon_status()

    def _query_daemon_status(self) -> UnlockResult:
        """Check daemon state via the control socket after child exits."""
        try:
            from bwssh.config import load_config  # noqa: PLC0415
            from bwssh.control import (  # noqa: PLC0415
                ControlClient,
                ControlError,
            )

            config = load_config()
            xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
            if config.daemon.runtime_dir is not None:
                socket_path = config.daemon.runtime_dir / config.daemon.control_socket
            else:
                from pathlib import Path  # noqa: PLC0415

                socket_path = Path(xdg) / "bwssh" / config.daemon.control_socket

            client = ControlClient(socket_path)
            result = asyncio.run(client.send_command("status", {}))

            locked = result.get("locked", True)
            key_count = result.get("key_count", 0)

            if locked:
                return UnlockResult(error="Vault is still locked")

            # Fetch key details for the caller
            keys: list[dict[str, str]] = []
            try:
                keys_result = asyncio.run(client.send_command("list_keys", {}))
                keys = keys_result.get("keys", [])
            except (ControlError, OSError):
                pass

            return UnlockResult(
                session_key="<managed-by-daemon>",
                key_count=key_count,
                keys=keys,
            )
        except (ControlError, OSError) as exc:
            logger.debug("Failed to query daemon status: %s", exc)
            return UnlockResult(
                error="Could not verify unlock status (daemon unreachable)"
            )
