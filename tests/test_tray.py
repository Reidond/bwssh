"""Tests for bwssh.tray — system tray icon."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bwssh.control import ControlError

# The module must always be importable even when AppIndicator3 is missing.
from bwssh.tray import TRAY_AVAILABLE, TrayIcon


class TestTrayAvailability:
    """Verify the module loads cleanly regardless of system libraries."""

    def test_import_does_not_crash(self) -> None:
        """Module-level import should never raise."""
        assert isinstance(TRAY_AVAILABLE, bool)

    def test_tray_icon_class_importable(self) -> None:
        """TrayIcon can always be referenced at import time."""
        assert TrayIcon is not None

    def test_raises_without_appindicator(self) -> None:
        """Instantiation fails clearly when AppIndicator3 is absent."""
        with (
            patch("bwssh.tray.TRAY_AVAILABLE", False),
            pytest.raises(RuntimeError, match="AppIndicator3"),
        ):
            TrayIcon(Path("/tmp/control.sock"))


# ---------------------------------------------------------------------------
# For the remaining tests we mock the entire gi layer so we can exercise
# the polling and menu logic without requiring system libraries.
# ---------------------------------------------------------------------------


def _make_gi_mocks() -> dict[str, MagicMock]:
    """Create a set of mocks that stand in for the gi.repository objects."""
    mocks: dict[str, MagicMock] = {}

    # AppIndicator3
    indicator = MagicMock()
    indicator_class = MagicMock()
    indicator_class.Indicator.new.return_value = indicator
    indicator_class.IndicatorCategory.APPLICATION_STATUS = 0
    indicator_class.IndicatorStatus.ACTIVE = 1
    mocks["AppIndicator3"] = indicator_class
    mocks["indicator"] = indicator

    # Gtk (GTK 3 subset used by the tray)
    gtk = MagicMock()

    def _menu_init(*_a: Any, **_kw: Any) -> MagicMock:
        m = MagicMock()
        m.show_all = MagicMock()
        m.append = MagicMock()
        return m

    gtk.Menu = _menu_init
    gtk.MenuItem = MagicMock(return_value=MagicMock())
    gtk.SeparatorMenuItem = MagicMock(return_value=MagicMock())
    gtk.main = MagicMock()
    gtk.main_quit = MagicMock()
    mocks["Gtk"] = gtk

    # GLib
    glib = MagicMock()
    glib.timeout_add_seconds = MagicMock()
    mocks["GLib"] = glib

    return mocks


@pytest.fixture
def gi_mocks() -> dict[str, MagicMock]:
    return _make_gi_mocks()


@pytest.fixture
def gi_patched(
    gi_mocks: dict[str, MagicMock],
) -> Generator[dict[str, MagicMock]]:
    """Patch gi libraries on the _tray module for the full test duration."""
    with (
        patch("bwssh.tray.TRAY_AVAILABLE", True),
        patch(
            "bwssh.tray.AppIndicator3",
            gi_mocks["AppIndicator3"],
            create=True,
        ),
        patch("bwssh.tray.Gtk", gi_mocks["Gtk"], create=True),
        patch("bwssh.tray.GLib", gi_mocks["GLib"], create=True),
    ):
        yield gi_mocks


@pytest.fixture
def tray(tmp_path: Path, gi_patched: dict[str, MagicMock]) -> TrayIcon:  # noqa: ARG001
    """Create a TrayIcon with mocked gi libraries.

    The gi patches remain active for the entire test because the
    ``gi_patched`` fixture is a context-manager style fixture.
    """
    socket_path = tmp_path / "control.sock"
    return TrayIcon(socket_path)


class TestTrayIconInit:
    def test_creates_indicator(
        self,
        tray: TrayIcon,  # noqa: ARG002
        gi_patched: dict[str, MagicMock],
    ) -> None:
        gi_patched["AppIndicator3"].Indicator.new.assert_called_once()

    def test_sets_active_status(
        self,
        tray: TrayIcon,  # noqa: ARG002
        gi_patched: dict[str, MagicMock],
    ) -> None:
        gi_patched["indicator"].set_status.assert_called_once_with(1)

    def test_sets_title(
        self,
        tray: TrayIcon,  # noqa: ARG002
        gi_patched: dict[str, MagicMock],
    ) -> None:
        gi_patched["indicator"].set_title.assert_called_once_with("bwssh SSH Agent")

    def test_initial_state_disconnected(self, tray: TrayIcon) -> None:
        assert tray._connected is False
        assert tray._locked is None
        assert tray._key_count == 0


class TestPollDaemonStatus:
    """Test _do_poll with mocked ControlClient responses."""

    def test_poll_connected_unlocked(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        mock_result = {
            "locked": False,
            "key_count": 3,
            "pid": 1234,
            "uptime": 60.0,
        }
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            tray._do_poll()

        assert tray._connected is True
        assert tray._locked is False
        assert tray._key_count == 3

    def test_poll_connected_locked(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        mock_result = {
            "locked": True,
            "key_count": 0,
            "pid": 1234,
            "uptime": 10.0,
        }
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            tray._do_poll()

        assert tray._connected is True
        assert tray._locked is True
        assert tray._key_count == 0

    def test_poll_disconnected(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            side_effect=OSError,
        ):
            tray._do_poll()

        assert tray._connected is False
        assert tray._locked is None
        assert tray._key_count == 0

    def test_poll_control_error(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            side_effect=ControlError(-1, "fail"),
        ):
            tray._do_poll()

        assert tray._connected is False


class TestIconStateTransitions:
    """Verify the icon name changes with state."""

    def test_icon_disconnected(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        tray._connected = False
        tray._update_icon()
        gi_patched["indicator"].set_icon_full.assert_called_with(
            "network-offline-symbolic", "bwssh: Daemon not running"
        )

    def test_icon_locked(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        tray._connected = True
        tray._locked = True
        tray._update_icon()
        gi_patched["indicator"].set_icon_full.assert_called_with(
            "system-lock-screen-symbolic", "bwssh: Locked"
        )

    def test_icon_unlocked(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        tray._connected = True
        tray._locked = False
        tray._key_count = 5
        tray._update_icon()
        gi_patched["indicator"].set_icon_full.assert_called_with(
            "security-high-symbolic", "bwssh: Unlocked (5 keys)"
        )


class TestStatusText:
    def test_disconnected(self, tray: TrayIcon) -> None:
        tray._connected = False
        assert tray._status_text() == "bwssh: Daemon not running"

    def test_locked(self, tray: TrayIcon) -> None:
        tray._connected = True
        tray._locked = True
        assert tray._status_text() == "bwssh: Locked"

    def test_unlocked_with_keys(self, tray: TrayIcon) -> None:
        tray._connected = True
        tray._locked = False
        tray._key_count = 2
        assert tray._status_text() == "bwssh: Unlocked (2 keys)"


class TestStatusLabel:
    def test_disconnected(self, tray: TrayIcon) -> None:
        tray._connected = False
        assert tray._status_label() == "Daemon not running"

    def test_locked(self, tray: TrayIcon) -> None:
        tray._connected = True
        tray._locked = True
        assert tray._status_label() == "Status: Locked"

    def test_unlocked(self, tray: TrayIcon) -> None:
        tray._connected = True
        tray._locked = False
        assert tray._status_label() == "Status: Unlocked"


class TestPeriodicPollReturn:
    """Verify the GLib timeout callbacks return correct values."""

    def test_periodic_poll_returns_true(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            side_effect=OSError,
        ):
            assert tray._periodic_poll() is True

    def test_oneshot_poll_returns_false(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            side_effect=OSError,
        ):
            assert tray._oneshot_poll() is False


class TestActions:
    def test_on_lock_sends_command(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        mock_result = {"locked": True}
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_cmd:
            tray._connected = True
            tray._on_lock(MagicMock())

        mock_cmd.assert_any_call("lock", {})

    def test_on_sync_sends_command(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        mock_result = {"synced": True, "key_count": 2}
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_cmd:
            tray._connected = True
            tray._on_sync(MagicMock())

        mock_cmd.assert_any_call("sync", {})

    def test_on_lock_handles_error(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        """Lock action does not raise when daemon is unreachable."""
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            side_effect=OSError,
        ):
            tray._on_lock(MagicMock())  # should not raise

    def test_on_sync_handles_error(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        """Sync action does not raise when daemon is unreachable."""
        with patch.object(
            tray._client,
            "send_command",
            new_callable=AsyncMock,
            side_effect=OSError,
        ):
            tray._on_sync(MagicMock())  # should not raise

    def test_on_unlock_launches_subprocess(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        with (
            patch("bwssh.tray.subprocess.Popen") as mock_popen,
            patch(
                "bwssh.tray.shutil.which",
                return_value="/usr/bin/bwssh",
            ),
        ):
            tray._on_unlock(MagicMock())

        mock_popen.assert_called_once_with(
            ["/usr/bin/bwssh", "unlock"],
            start_new_session=True,
        )

    def test_on_unlock_schedules_oneshot_poll(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        with (
            patch("bwssh.tray.subprocess.Popen"),
            patch(
                "bwssh.tray.shutil.which",
                return_value="bwssh",
            ),
        ):
            tray._on_unlock(MagicMock())

        gi_patched["GLib"].timeout_add_seconds.assert_called_with(3, tray._oneshot_poll)

    def test_on_quit_calls_main_quit(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        tray._on_quit(MagicMock())
        gi_patched["Gtk"].main_quit.assert_called_once()


class TestRun:
    def test_run_starts_gtk_main_loop(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        with patch.object(tray, "_do_poll"):
            tray.run()

        gi_patched["Gtk"].main.assert_called_once()

    def test_run_schedules_periodic_poll(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],
    ) -> None:
        with patch.object(tray, "_do_poll"):
            tray.run()

        gi_patched["GLib"].timeout_add_seconds.assert_called_with(
            5, tray._periodic_poll
        )

    def test_run_does_initial_poll(
        self,
        tray: TrayIcon,
        gi_patched: dict[str, MagicMock],  # noqa: ARG002
    ) -> None:
        with patch.object(tray, "_do_poll") as mock_poll:
            tray.run()

        mock_poll.assert_called_once()
