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
import tempfile
from pathlib import Path
from typing import Any

from bwssh.control import ControlClient, ControlError

logger = logging.getLogger(__name__)

# --- Graceful AppIndicator3 availability detection --------------------------

TRAY_AVAILABLE = False
_NOTIFY_AVAILABLE = False

# Tracks which dependency is missing so the CLI can show a precise hint.
_TRAY_MISSING: str | None = None  # None = nothing missing, str = what failed

try:
    import gi  # pyright: ignore[reportMissingImports]
except ImportError:
    _TRAY_MISSING = "gi"
    logger.debug("PyGObject (gi) not importable")

if _TRAY_MISSING is None:
    try:
        # GTK 3.0 is required for AppIndicator3 menus.  If another module
        # (e.g. _graphical.py) has already called require_version("Gtk", "4.0")
        # in this process, requiring 3.0 will raise ValueError.
        try:
            gi.require_version("Gtk", "3.0")
        except ValueError:
            raise ValueError(  # noqa: B904
                "Gtk 3.0 cannot be loaded because Gtk 4.0 was already "
                "required in this process.  Run 'bwssh tray' as a "
                "separate command (not from a GTK-4 context)."
            )

        from gi.repository import GLib, Gtk  # pyright: ignore[reportMissingImports]
    except (ImportError, ValueError) as _exc:
        _TRAY_MISSING = "gtk3"
        logger.debug("GTK 3.0 not available: %s", _exc)

if _TRAY_MISSING is None:
    try:
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

        TRAY_AVAILABLE = True
    except (ImportError, ValueError) as _exc:
        _TRAY_MISSING = "appindicator3"
        logger.debug("AppIndicator3 not available: %s", _exc)

if TRAY_AVAILABLE:
    # Desktop notifications (optional; tray works without them).
    try:
        gi.require_version("Notify", "0.7")
        from gi.repository import (  # pyright: ignore[reportMissingImports]
            Notify as _Notify,
        )

        _NOTIFY_AVAILABLE = True
    except (ImportError, ValueError):
        logger.debug("libnotify not available; notifications disabled")


def _parse_distro_ids(os_release: str) -> set[str]:
    """Extract distro IDs from os-release content."""
    id_line = ""
    id_like_line = ""
    for line in os_release.splitlines():
        if line.startswith("ID="):
            id_line = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("ID_LIKE="):
            id_like_line = line.split("=", 1)[1].strip().strip('"')
    return {id_line} | set(id_like_line.split())


def _install_hint_for_os_release(
    os_release: str,
    missing: str = "appindicator3",
) -> str:
    """Return a distro-specific install hint based on what is missing.

    *missing* is one of ``"gi"``, ``"gtk3"``, or ``"appindicator3"``.
    """
    distro_ids = _parse_distro_ids(os_release)

    if missing == "gi":
        return _gi_hint(distro_ids)
    if missing == "gtk3":
        return _gtk3_hint(distro_ids)
    return _appindicator3_hint(distro_ids)


def _gi_hint(distro_ids: set[str]) -> str:
    """Hint for missing PyGObject (``import gi`` fails)."""
    if distro_ids & {"fedora", "rhel", "centos"}:
        return "sudo dnf install python3-gobject"
    if distro_ids & {"arch", "manjaro", "endeavouros"}:
        return "sudo pacman -S python-gobject"
    if distro_ids & {"opensuse", "suse", "sles"}:
        return "sudo zypper install python3-gobject"
    return "sudo apt install python3-gi"


def _gtk3_hint(distro_ids: set[str]) -> str:
    """Hint for missing GTK 3.0 typelib."""
    if distro_ids & {"fedora", "rhel", "centos"}:
        return "sudo dnf install gtk3"
    if distro_ids & {"arch", "manjaro", "endeavouros"}:
        return "sudo pacman -S gtk3"
    if distro_ids & {"opensuse", "suse", "sles"}:
        return "sudo zypper install gtk3"
    return "sudo apt install gir1.2-gtk-3.0"


def _appindicator3_hint(distro_ids: set[str]) -> str:
    """Hint for missing AppIndicator3 typelib."""
    if distro_ids & {"fedora", "rhel", "centos"}:
        return "sudo dnf install libayatana-appindicator-gtk3"
    if distro_ids & {"arch", "manjaro", "endeavouros"}:
        return "sudo pacman -S libayatana-appindicator"
    if distro_ids & {"opensuse", "suse", "sles"}:
        return "sudo zypper install typelib-1_0-AyatanaAppIndicator3-0_1"
    return (
        "sudo apt install libayatana-appindicator3-1"
        " gir1.2-ayatanaappindicator3-0.1"
    )


_MISSING_LABELS = {
    "gi": "PyGObject is not installed",
    "gtk3": "GTK 3.0 typelib is not available",
    "appindicator3": "AppIndicator3 typelib is not available",
}


def _appindicator_install_hint() -> str:
    """Return a distro-aware install hint for the first missing dependency."""
    missing = _TRAY_MISSING or "appindicator3"
    try:
        os_release = Path("/etc/os-release").read_text()
    except OSError:
        os_release = ""
    label = _MISSING_LABELS[missing]
    command = _install_hint_for_os_release(os_release, missing)
    return f"{label}.\n  {command}"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_POLL_INTERVAL_SECONDS = 5

# Fallback themed icons used for notifications (these don't appear in panel)
_NOTIFY_ICON_LOCKED = "system-lock-screen-symbolic"
_NOTIFY_ICON_UNLOCKED = "security-high-symbolic"
_NOTIFY_ICON_DISCONNECTED = "network-offline-symbolic"

# ---------------------------------------------------------------------------
# Icon generation — SVG icons using absolute paths
# ---------------------------------------------------------------------------

# We write SVG files to a temp directory and pass their *absolute paths*
# (without extension) as icon names to AppIndicator3.  This is the most
# reliable approach across desktop environments — it avoids icon theme
# lookup issues where the tray (a separate process) cannot find the icons.
#
# The SVGs use a medium grey (#5a5a5a) fill which is visible on both dark
# and light panels.  On dark panels it appears as a mid-tone; on light
# panels it's clearly dark enough to see.

_LOCKED_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"
 viewBox="0 0 24 24">
  <g fill="none" stroke="#5a5a5a" stroke-width="1.8"
   stroke-linecap="round" stroke-linejoin="round">
    <path d="M8 11V7a4 4 0 0 1 8 0v4"/>
    <rect x="5" y="11" width="14" height="10" rx="2"
     fill="#5a5a5a" stroke="none"/>
  </g>
</svg>"""

_UNLOCKED_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"
 viewBox="0 0 24 24">
  <g fill="none" stroke="#5a5a5a" stroke-width="1.8"
   stroke-linecap="round" stroke-linejoin="round">
    <path d="M5 12l1.2 7.5A2 2 0 0 0 8.2 21h7.6a2 2 0 0 0 2-1.5L19 12z"/>
    <path d="M5 12L12 3l7 9"/>
    <path d="M9.5 15.5l2 2 3.5-4.5"/>
  </g>
</svg>"""

_DISCONNECTED_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
  <g fill="none" stroke="#5a5a5a" stroke-width="1.8" stroke-linecap="round">
    <circle cx="12" cy="12" r="9"/>
    <line x1="5.6" y1="5.6" x2="18.4" y2="18.4"/>
  </g>
</svg>"""


def _create_icon_dir() -> tuple[Path, str, str, str]:
    """Create a temp directory with SVG icons and return absolute paths.

    Returns ``(icon_dir, locked_path, unlocked_path, disconnected_path)``
    where each ``*_path`` is an absolute path **without** the ``.svg``
    extension, suitable for passing directly to ``set_icon_full``.
    """
    icon_dir = Path(tempfile.mkdtemp(prefix="bwssh-icons-"))

    locked = icon_dir / "bwssh-locked"
    unlocked = icon_dir / "bwssh-unlocked"
    disconnected = icon_dir / "bwssh-disconnected"

    locked.with_suffix(".svg").write_text(_LOCKED_SVG)
    unlocked.with_suffix(".svg").write_text(_UNLOCKED_SVG)
    disconnected.with_suffix(".svg").write_text(_DISCONNECTED_SVG)

    return icon_dir, str(locked), str(unlocked), str(disconnected)


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
                + _appindicator_install_hint()
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

        # Generate SVG icons and get their absolute paths (without extension)
        (
            self._icon_dir,
            self._icon_locked,
            self._icon_unlocked,
            self._icon_disconnected,
        ) = _create_icon_dir()

        # Build the indicator — use absolute path so AppIndicator finds the
        # icon immediately without needing an icon theme lookup.
        self._indicator = AppIndicator3.Indicator.new(
            "bwssh",
            self._icon_disconnected,
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
                    "Agent Connected", "Vault is locked", _NOTIFY_ICON_LOCKED
                )
            else:
                self._send_notification(
                    "Agent Connected",
                    f"Vault is unlocked ({self._key_count} keys)",
                    _NOTIFY_ICON_UNLOCKED,
                )
            return

        # Connected -> Disconnected
        if prev_connected and not self._connected:
            self._send_notification(
                "Agent Disconnected",
                "Daemon is not running",
                _NOTIFY_ICON_DISCONNECTED,
            )
            return

        # Locked -> Unlocked
        if self._connected and prev_locked is True and self._locked is False:
            self._send_notification(
                "Vault Unlocked",
                f"{self._key_count} SSH key(s) loaded",
                _NOTIFY_ICON_UNLOCKED,
            )
            return

        # Unlocked -> Locked
        if self._connected and prev_locked is False and self._locked is True:
            self._send_notification(
                "Vault Locked", "SSH keys cleared", _NOTIFY_ICON_LOCKED
            )

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
            icon = self._icon_disconnected
        elif self._locked:
            icon = self._icon_locked
        else:
            icon = self._icon_unlocked

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
        # Clean up generated icon files
        shutil.rmtree(self._icon_dir, ignore_errors=True)
        Gtk.main_quit()
