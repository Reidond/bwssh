"""Tests for bwssh.ui — unlock UI abstraction layer."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from bwssh.ui import create_unlock_ui
from bwssh.ui._base import UnlockResult
from bwssh.ui._detect import detect_ui_mode
from bwssh.ui._graphical import GraphicalUnlockUI
from bwssh.ui._tui import TuiUnlockUI, _UnlockApp


class TestUnlockResult:
    def test_default_values(self) -> None:
        result = UnlockResult()
        assert result.session_key is None
        assert result.key_count == 0
        assert result.error is None

    def test_success_result(self) -> None:
        result = UnlockResult(session_key="abc123", key_count=3)
        assert result.session_key == "abc123"
        assert result.key_count == 3
        assert result.error is None

    def test_error_result(self) -> None:
        result = UnlockResult(error="cancelled")
        assert result.session_key is None
        assert result.key_count == 0
        assert result.error == "cancelled"


class TestDetectUiMode:
    def test_default_is_tui(self) -> None:
        """Without any env vars, default to TUI."""
        with patch.dict("os.environ", {}, clear=True):
            assert detect_ui_mode() == "tui"

    def test_override_tui(self) -> None:
        with patch.dict("os.environ", {"BWSSH_UNLOCK_MODE": "tui"}, clear=True):
            assert detect_ui_mode() == "tui"

    def test_override_graphical(self) -> None:
        with patch.dict("os.environ", {"BWSSH_UNLOCK_MODE": "graphical"}, clear=True):
            assert detect_ui_mode() == "graphical"

    def test_override_case_insensitive(self) -> None:
        with patch.dict("os.environ", {"BWSSH_UNLOCK_MODE": "TUI"}, clear=True):
            assert detect_ui_mode() == "tui"

    def test_override_invalid_falls_through(self) -> None:
        with patch.dict("os.environ", {"BWSSH_UNLOCK_MODE": "invalid"}, clear=True):
            assert detect_ui_mode() == "tui"

    def test_display_env_detects_graphical(self) -> None:
        with patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True):
            assert detect_ui_mode() == "graphical"

    def test_wayland_display_detects_graphical(self) -> None:
        with patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"}, clear=True):
            assert detect_ui_mode() == "graphical"

    def test_override_takes_precedence_over_display(self) -> None:
        with patch.dict(
            "os.environ",
            {"BWSSH_UNLOCK_MODE": "tui", "DISPLAY": ":0"},
            clear=True,
        ):
            assert detect_ui_mode() == "tui"


class TestGraphicalUnlockUI:
    def test_raises_without_gtk(self) -> None:
        with patch("bwssh.ui._graphical.GTK_AVAILABLE", False):
            ui = GraphicalUnlockUI()
            with pytest.raises(
                RuntimeError, match="GTK 4 / libadwaita is not available"
            ):
                ui.run()

    def test_accepts_bw_path(self) -> None:
        ui = GraphicalUnlockUI(bw_path="/usr/bin/bw")
        assert ui._bw_path == "/usr/bin/bw"

    def test_accepts_on_session_ready(self) -> None:
        async def hook(_key: str) -> dict[str, Any]:
            return {"key_count": 1}

        ui = GraphicalUnlockUI(on_session_ready=hook)
        assert ui._on_session_ready is hook


class TestCreateUnlockUi:
    def test_returns_tui_by_default(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            ui = create_unlock_ui()
        assert isinstance(ui, TuiUnlockUI)

    def test_returns_graphical_when_gtk_available(self) -> None:
        """With GTK available and DISPLAY set, factory returns GraphicalUnlockUI."""
        with (
            patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True),
            patch("bwssh.ui.GTK_AVAILABLE", True),
        ):
            ui = create_unlock_ui()
        assert isinstance(ui, GraphicalUnlockUI)

    def test_returns_tui_when_graphical_unavailable(self) -> None:
        """Without GTK or terminal, factory falls back to TUI."""
        with (
            patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True),
            patch("bwssh.ui.GTK_AVAILABLE", False),
            patch("bwssh.ui.TERMINAL_AVAILABLE", False),
        ):
            ui = create_unlock_ui()
        assert isinstance(ui, TuiUnlockUI)

    def test_passes_bw_path(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            ui = create_unlock_ui(bw_path="/custom/bw")
        assert isinstance(ui, TuiUnlockUI)
        assert ui._bw_path == "/custom/bw"

    def test_passes_on_session_ready(self) -> None:
        async def hook(_key: str) -> dict[str, Any]:
            return {"key_count": 1}

        with patch.dict("os.environ", {}, clear=True):
            ui = create_unlock_ui(on_session_ready=hook)
        assert isinstance(ui, TuiUnlockUI)
        assert ui._on_session_ready is hook


class TestBwUnlockSubprocess:
    """Test the bw unlock subprocess logic without running the full TUI."""

    @pytest.mark.asyncio
    async def test_run_bw_unlock_success(self) -> None:
        """Successful bw unlock returns session key."""
        app = _UnlockApp(bw_path="bw")

        mock_proc = type("MockProc", (), {"returncode": 0})()

        async def fake_communicate(
            input: bytes | None = None,  # noqa: ARG001
        ) -> tuple[bytes, bytes]:
            return (b"session-key-abc123", b"")

        mock_proc.communicate = fake_communicate

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await app._run_bw_unlock("my-password")

        assert result == "session-key-abc123"

    @pytest.mark.asyncio
    async def test_run_bw_unlock_failure(self) -> None:
        """Failed bw unlock raises RuntimeError."""
        app = _UnlockApp(bw_path="bw")

        mock_proc = type("MockProc", (), {"returncode": 1})()

        async def fake_communicate(
            input: bytes | None = None,  # noqa: ARG001
        ) -> tuple[bytes, bytes]:
            return (b"", b"Invalid master password")

        mock_proc.communicate = fake_communicate

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            pytest.raises(RuntimeError, match="Invalid master password"),
        ):
            await app._run_bw_unlock("wrong-password")

    @pytest.mark.asyncio
    async def test_run_bw_unlock_empty_output(self) -> None:
        """Empty stdout from bw returns None."""
        app = _UnlockApp(bw_path="bw")

        mock_proc = type("MockProc", (), {"returncode": 0})()

        async def fake_communicate(
            input: bytes | None = None,  # noqa: ARG001
        ) -> tuple[bytes, bytes]:
            return (b"", b"")

        mock_proc.communicate = fake_communicate

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await app._run_bw_unlock("my-password")

        assert result is None

    @pytest.mark.asyncio
    async def test_run_bw_unlock_not_found(self) -> None:
        """Missing bw binary raises FileNotFoundError."""
        app = _UnlockApp(bw_path="/nonexistent/bw")

        with (
            patch(
                "asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError("/nonexistent/bw"),
            ),
            pytest.raises(FileNotFoundError),
        ):
            await app._run_bw_unlock("password")

    @pytest.mark.asyncio
    async def test_run_bw_unlock_pipes_password(self) -> None:
        """Password is piped to stdin, not passed as CLI argument."""
        app = _UnlockApp(bw_path="bw")

        mock_proc = type("MockProc", (), {"returncode": 0})()
        captured_input: bytes | None = None

        async def fake_communicate(
            input: bytes | None = None,
        ) -> tuple[bytes, bytes]:
            nonlocal captured_input
            captured_input = input
            return (b"session-key", b"")

        mock_proc.communicate = fake_communicate

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_proc
        ) as mock_exec:
            await app._run_bw_unlock("my-secret-pass")

        # Password piped to stdin with trailing newline
        assert captured_input == b"my-secret-pass\n"

        # bw called with only "unlock" and "--raw" — no password in args
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0]
        assert call_args == ("bw", "unlock", "--raw")


class TestTuiUnlockUIInit:
    """Test TuiUnlockUI and _UnlockApp construction."""

    def test_stores_on_session_ready(self) -> None:
        async def hook(_key: str) -> dict[str, Any]:
            return {"key_count": 2}

        ui = TuiUnlockUI(bw_path="bw", on_session_ready=hook)
        assert ui._on_session_ready is hook

    def test_default_no_hook(self) -> None:
        ui = TuiUnlockUI(bw_path="bw")
        assert ui._on_session_ready is None

    def test_app_receives_hook(self) -> None:
        async def hook(_key: str) -> dict[str, Any]:
            return {"key_count": 5}

        app = _UnlockApp(bw_path="bw", on_session_ready=hook)
        assert app._on_session_ready is hook
        assert app.result == UnlockResult()
