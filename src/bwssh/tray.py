"""System tray icon using AppIndicator3.

Shows the bwssh agent status (locked / unlocked / disconnected) as a
system tray icon with a context menu for quick actions.

All ``gi`` imports are guarded so the module can be imported safely
even when the required system libraries are not installed.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from typing import TYPE_CHECKING, Any

from bwssh.control import ControlClient, ControlError

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# --- Graceful AppIndicator3 availability detection --------------------------

TRAY_AVAILABLE = False
_NOTIFY_AVAILABLE = False

try:
    import gi  # pyright: ignore[reportMissingImports]

    # GTK 3.0 is required for AppIndicator3 menus.  If another module
    # (e.g. _graphical.py) has already called require_version("Gtk", "4.0")
    # in this process, requiring 3.0 will raise ValueError.  We catch that
    # below, but to help users diagnose the problem we log it explicitly.
    try:
        gi.require_version("Gtk", "3.0")
    except ValueError:
        raise ValueError(  # noqa: B904
            "Gtk 3.0 cannot be loaded because Gtk 4.0 was already "
            "required in this process.  Run 'bwssh tray' as a "
            "separate command (not from a GTK-4 context)."
        )

    try:
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import (  # pyright: ignore[reportMissingImports]
            AyatanaAppIndicator3 as AppIndicator3,
        )
    except ValueError:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import (  # pyright: ignore[reportMissingImports]
            AppIndicator3,
        )

    from gi.repository import GLib, Gtk  # pyright: ignore[reportMissingImports]

    TRAY_AVAILABLE = True

    # Desktop notifications (optional; tray works without them).
    try:
        gi.require_version("Notify", "0.7")
        from gi.repository import (  # pyright: ignore[reportMissingImports]
            Notify as _Notify,
        )

        _NOTIFY_AVAILABLE = True
    except (ImportError, ValueError):
        logger.debug("libnotify not available; notifications disabled")
except (ImportError, ValueError) as _exc:
    logger.debug("AppIndicator3 not available: %s", _exc)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_POLL_INTERVAL_SECONDS = 5

_ICON_LOCKED = "system-lock-screen-symbolic"
_ICON_UNLOCKED = "security-high-symbolic"
_ICON_DISCONNECTED = "network-offline-symbolic"


# ---------------------------------------------------------------------------
# TrayIcon
# ---------------------------------------------------------------------------


class TrayIcon:
    """System tray icon that displays bwssh agent status.

    Polls the daemon via the control socket every few seconds and
    updates the icon and menu to reflect the current state.

    Parameters:
        socket_path: Path to the daemon control socket.
    """

    def __init__(self, socket_path: Path) -> None:
        if not TRAY_AVAILABLE:
            raise RuntimeError(
                "AppIndicator3 is not available. "
                "Install libayatana-appindicator3-1 or libappindicator-gtk3."
            )

        self._socket_path = socket_path
        self._client = ControlClient(socket_path)

        # Current state
        self._locked: bool | None = None
        self._key_count: int = 0
        self._connected: bool = False
        self._first_poll: bool = True

        # Desktop notifications (optional)
        self._notifications_enabled: bool = False
        if _NOTIFY_AVAILABLE:
            try:
                _Notify.init("bwssh")
                self._notifications_enabled = True
            except Exception:
                logger.debug("Failed to initialise libnotify", exc_info=True)

        # Build the indicator
        self._indicator = AppIndicator3.Indicator.new(
            "bwssh",
            _ICON_DISCONNECTED,
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        self._indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self._indicator.set_title("bwssh SSH Agent")

        # Attach an initial menu (required before entering the main loop)
        self._build_menu()

    def run(self) -> None:
        """Start the tray icon and enter the GTK main loop.

        Blocks until the user selects *Quit* or the process is killed.
        """
        # Run an initial poll so the icon reflects reality right away
        self._do_poll()

        # Schedule periodic polling
        GLib.timeout_add_seconds(_POLL_INTERVAL_SECONDS, self._periodic_poll)

        Gtk.main()

    # -- Polling --------------------------------------------------------------

    def _do_poll(self) -> None:
        """Poll daemon status and update icon + menu."""
        prev_locked = self._locked
        prev_connected = self._connected

        try:
            result = asyncio.run(self._client.send_command("status", {}))
            self._connected = True
            self._locked = result.get("locked", True)
            self._key_count = result.get("key_count", 0)
        except (ControlError, OSError):
            self._connected = False
            self._locked = None
            self._key_count = 0

        self._update_icon()
        self._build_menu()

        # Fire desktop notification on state transitions (skip first poll)
        if not self._first_poll:
            self._notify_state_change(prev_locked, prev_connected)
        self._first_poll = False

    def _periodic_poll(self) -> bool:
        """GLib timeout callback — poll and keep the timer alive."""
        self._do_poll()
        return True  # GLib.SOURCE_CONTINUE

    def _oneshot_poll(self) -> bool:
        """GLib timeout callback — poll once then remove the timer."""
        self._do_poll()
        return False  # GLib.SOURCE_REMOVE

    # -- Notifications --------------------------------------------------------

    def _notify_state_change(
        self, prev_locked: bool | None, prev_connected: bool
    ) -> None:
        """Send a desktop notification when the daemon state changes."""
        if not self._notifications_enabled:
            return

        # Disconnected -> Connected
        if not prev_connected and self._connected:
            if self._locked:
                self._send_notification(
                    "Agent Connected", "Vault is locked", _ICON_LOCKED
                )
            else:
                self._send_notification(
                    "Agent Connected",
                    f"Vault is unlocked ({self._key_count} keys)",
                    _ICON_UNLOCKED,
                )
            return

        # Connected -> Disconnected
        if prev_connected and not self._connected:
            self._send_notification(
                "Agent Disconnected", "Daemon is not running", _ICON_DISCONNECTED
            )
            return

        # Locked -> Unlocked
        if self._connected and prev_locked is True and self._locked is False:
            self._send_notification(
                "Vault Unlocked",
                f"{self._key_count} SSH key(s) loaded",
                _ICON_UNLOCKED,
            )
            return

        # Unlocked -> Locked
        if self._connected and prev_locked is False and self._locked is True:
            self._send_notification("Vault Locked", "SSH keys cleared", _ICON_LOCKED)

    def _send_notification(self, summary: str, body: str, icon: str) -> None:
        """Show a desktop notification via libnotify."""
        try:
            notification = _Notify.Notification.new(summary, body, icon)
            notification.show()
        except Exception:
            logger.debug("Failed to send notification", exc_info=True)

    # -- Icon -----------------------------------------------------------------

    def _update_icon(self) -> None:
        """Set the tray icon based on current state."""
        if not self._connected:
            icon = _ICON_DISCONNECTED
        elif self._locked:
            icon = _ICON_LOCKED
        else:
            icon = _ICON_UNLOCKED

        self._indicator.set_icon_full(icon, self._status_text())

    def _status_text(self) -> str:
        """Human-readable status for accessibility / tooltip."""
        if not self._connected:
            return "bwssh: Daemon not running"
        if self._locked:
            return "bwssh: Locked"
        return f"bwssh: Unlocked ({self._key_count} keys)"

    # -- Menu -----------------------------------------------------------------

    def _build_menu(self) -> None:
        """Rebuild the context menu to reflect current state."""
        menu = Gtk.Menu()

        # Status label (insensitive = non-clickable)
        status_item = Gtk.MenuItem(label=self._status_label())
        status_item.set_sensitive(False)
        menu.append(status_item)

        if self._connected:
            keys_item = Gtk.MenuItem(label=f"Keys: {self._key_count} loaded")
            keys_item.set_sensitive(False)
            menu.append(keys_item)

        menu.append(Gtk.SeparatorMenuItem())

        if self._connected:
            if self._locked:
                unlock_item = Gtk.MenuItem(label="Unlock\u2026")
                unlock_item.connect("activate", self._on_unlock)
                menu.append(unlock_item)
            else:
                lock_item = Gtk.MenuItem(label="Lock")
                lock_item.connect("activate", self._on_lock)
                menu.append(lock_item)

                sync_item = Gtk.MenuItem(label="Sync")
                sync_item.connect("activate", self._on_sync)
                menu.append(sync_item)

            menu.append(Gtk.SeparatorMenuItem())

        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", self._on_quit)
        menu.append(quit_item)

        menu.show_all()
        self._indicator.set_menu(menu)

    def _status_label(self) -> str:
        """Text for the non-clickable status menu item."""
        if not self._connected:
            return "Daemon not running"
        if self._locked:
            return "Status: Locked"
        return "Status: Unlocked"

    # -- Actions --------------------------------------------------------------

    def _on_unlock(self, _item: Any) -> None:
        """Launch ``bwssh unlock`` in a separate process."""
        bwssh_path = shutil.which("bwssh") or "bwssh"
        try:
            subprocess.Popen(
                [bwssh_path, "unlock"],
                start_new_session=True,
            )
        except OSError:
            logger.error("Failed to launch bwssh unlock")

        # Schedule a one-shot poll to pick up the state change sooner
        GLib.timeout_add_seconds(3, self._oneshot_poll)

    def _on_lock(self, _item: Any) -> None:
        """Send the ``lock`` command to the daemon."""
        try:
            asyncio.run(self._client.send_command("lock", {}))
        except (ControlError, OSError):
            logger.error("Failed to lock agent")
        self._do_poll()

    def _on_sync(self, _item: Any) -> None:
        """Send the ``sync`` command to the daemon."""
        try:
            asyncio.run(self._client.send_command("sync", {}))
        except (ControlError, OSError):
            logger.error("Failed to sync keys")
        self._do_poll()

    def _on_quit(self, _item: Any) -> None:
        """Exit the tray application."""
        if self._notifications_enabled:
            _Notify.uninit()
        Gtk.main_quit()
