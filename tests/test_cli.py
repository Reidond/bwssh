"""Tests for bwssh.cli module — Click-based CLI with all subcommands."""

from __future__ import annotations

import tomllib
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from bwssh.cli import _write_config_file, main
from bwssh.config import load_config
from bwssh.control import ControlError
from bwssh.ui._base import UnlockResult

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Group & help
# ---------------------------------------------------------------------------


class TestMainGroup:
    def test_help_shows_all_subcommands(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        for cmd in (
            "status",
            "start",
            "stop",
            "install",
            "unlock",
            "lock",
            "sync",
            "keys",
        ):
            assert cmd in result.output

    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_no_args_shows_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [])
        assert result.exit_code == 0
        assert "Usage" in result.output


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_status_running(self, runner: CliRunner) -> None:
        mock_result: dict[str, Any] = {
            "pid": 12345,
            "uptime": 3661.5,
            "key_count": 3,
            "locked": False,
        }
        with patch("bwssh.cli._send_command", return_value=mock_result):
            result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "12345" in result.output
        assert "3" in result.output
        assert "unlocked" in result.output.lower()

    def test_status_locked(self, runner: CliRunner) -> None:
        mock_result: dict[str, Any] = {
            "pid": 999,
            "uptime": 10.0,
            "key_count": 0,
            "locked": True,
        }
        with patch("bwssh.cli._send_command", return_value=mock_result):
            result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "locked" in result.output.lower()

    def test_status_daemon_not_running(self, runner: CliRunner) -> None:
        with patch(
            "bwssh.cli._send_command",
            side_effect=ControlError(-1, "Connection refused"),
        ):
            result = runner.invoke(main, ["status"])
        assert result.exit_code != 0
        assert "not running" in result.output.lower() or "bwssh start" in result.output


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------


class TestStartCommand:
    def test_start_via_systemd(self, runner: CliRunner) -> None:
        with patch("bwssh.cli._try_systemd_start", return_value=True):
            result = runner.invoke(main, ["start"])
        assert result.exit_code == 0
        assert "started" in result.output.lower()

    def test_start_fallback(self, runner: CliRunner) -> None:
        with (
            patch("bwssh.cli._try_systemd_start", return_value=False),
            patch("bwssh.cli._start_daemon_direct", return_value=True),
        ):
            result = runner.invoke(main, ["start"])
        assert result.exit_code == 0
        assert "started" in result.output.lower()

    def test_start_failure(self, runner: CliRunner) -> None:
        with (
            patch("bwssh.cli._try_systemd_start", return_value=False),
            patch("bwssh.cli._start_daemon_direct", return_value=False),
        ):
            result = runner.invoke(main, ["start"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------


class TestStopCommand:
    def test_stop_via_systemd(self, runner: CliRunner) -> None:
        with patch("bwssh.cli._try_systemd_stop", return_value=True):
            result = runner.invoke(main, ["stop"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_stop_fallback_pid(self, runner: CliRunner) -> None:
        with (
            patch("bwssh.cli._try_systemd_stop", return_value=False),
            patch("bwssh.cli._stop_daemon_direct", return_value=True),
        ):
            result = runner.invoke(main, ["stop"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_stop_failure(self, runner: CliRunner) -> None:
        with (
            patch("bwssh.cli._try_systemd_stop", return_value=False),
            patch("bwssh.cli._stop_daemon_direct", return_value=False),
        ):
            result = runner.invoke(main, ["stop"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------


class TestInstallCommand:
    def test_install_no_flags(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["install"])
        assert result.exit_code != 0

    def test_install_user_systemd(self, runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "systemd" / "user"
        with patch("bwssh.cli._systemd_user_dir", return_value=target):
            result = runner.invoke(main, ["install", "--user-systemd"])
        assert result.exit_code == 0
        assert "systemctl" in result.output
        assert (target / "bwssh-agent.service").exists()
        assert (target / "bwssh-agent.socket").exists()
        assert (target / "bwssh-tray.service").exists()

    def test_install_polkit(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["install", "--polkit"])
        assert result.exit_code == 0
        assert "io.github.reidond.bwssh" in result.output
        assert "polkit" in result.output.lower() or "policy" in result.output.lower()


# ---------------------------------------------------------------------------
# unlock
# ---------------------------------------------------------------------------


class TestUnlockCommand:
    def test_unlock_via_env_session(self, runner: CliRunner) -> None:
        """Unlock with BW_SESSION env var sends to daemon directly."""
        with (
            patch("bwssh.cli._get_bw_session_from_env", return_value="mock-session"),
            patch(
                "bwssh.cli._send_command",
                return_value={"unlocked": True, "key_count": 1},
            ),
        ):
            result = runner.invoke(main, ["unlock"])
        assert result.exit_code == 0
        assert "unlocked" in result.output.lower()
        assert "1 key(s)" in result.output

    def test_unlock_with_session_option(self, runner: CliRunner) -> None:
        """Unlock with --session sends to daemon directly."""
        with patch(
            "bwssh.cli._send_command", return_value={"unlocked": True, "key_count": 2}
        ) as mock_send:
            result = runner.invoke(main, ["unlock", "--session", "my-secret-key"])
        assert result.exit_code == 0
        mock_send.assert_called_once_with("unlock", {"session_key": "my-secret-key"})

    def test_unlock_via_tui_success(self, runner: CliRunner) -> None:
        """Interactive unlock uses TUI and returns key count."""
        mock_result = UnlockResult(session_key="tui-session", key_count=3)
        with (
            patch("bwssh.cli._get_bw_session_from_env", return_value=None),
            patch("bwssh.cli._run_unlock_ui", return_value=mock_result),
        ):
            result = runner.invoke(main, ["unlock"])
        assert result.exit_code == 0
        assert "3 key(s)" in result.output

    def test_unlock_via_tui_cancelled(self, runner: CliRunner) -> None:
        """Cancelled TUI exits silently."""
        mock_result = UnlockResult(error="cancelled")
        with (
            patch("bwssh.cli._get_bw_session_from_env", return_value=None),
            patch("bwssh.cli._run_unlock_ui", return_value=mock_result),
        ):
            result = runner.invoke(main, ["unlock"])
        assert result.exit_code != 0
        # "cancelled" should not produce an error message
        assert "error" not in result.output.lower()

    def test_unlock_via_tui_error(self, runner: CliRunner) -> None:
        """TUI error is printed to stderr."""
        mock_result = UnlockResult(error="Connection refused")
        with (
            patch("bwssh.cli._get_bw_session_from_env", return_value=None),
            patch("bwssh.cli._run_unlock_ui", return_value=mock_result),
        ):
            result = runner.invoke(main, ["unlock"])
        assert result.exit_code != 0
        assert "connection refused" in result.output.lower()

    def test_unlock_daemon_not_running(self, runner: CliRunner) -> None:
        with (
            patch("bwssh.cli._get_bw_session_from_env", return_value="mock-session"),
            patch(
                "bwssh.cli._send_command",
                side_effect=OSError("Connection refused"),
            ),
        ):
            result = runner.invoke(main, ["unlock"])
        assert result.exit_code != 0

    def test_unlock_denied_by_polkit(self, runner: CliRunner) -> None:
        """Unlock denied by polkit shows appropriate error."""
        with (
            patch("bwssh.cli._get_bw_session_from_env", return_value="mock-session"),
            patch(
                "bwssh.cli._send_command",
                side_effect=ControlError(-32001, "Unlock denied by polkit"),
            ),
        ):
            result = runner.invoke(main, ["unlock"])
        assert result.exit_code != 0
        assert "polkit" in result.output.lower()


# ---------------------------------------------------------------------------
# lock
# ---------------------------------------------------------------------------


class TestLockCommand:
    def test_lock_success(self, runner: CliRunner) -> None:
        with patch("bwssh.cli._send_command", return_value={"locked": True}):
            result = runner.invoke(main, ["lock"])
        assert result.exit_code == 0
        assert "locked" in result.output.lower()

    def test_lock_daemon_not_running(self, runner: CliRunner) -> None:
        with patch(
            "bwssh.cli._send_command",
            side_effect=ControlError(-1, "Connection refused"),
        ):
            result = runner.invoke(main, ["lock"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------


class TestSyncCommand:
    def test_sync_success(self, runner: CliRunner) -> None:
        with patch("bwssh.cli._send_command", return_value={"synced": True}):
            result = runner.invoke(main, ["sync"])
        assert result.exit_code == 0
        assert "sync" in result.output.lower()

    def test_sync_daemon_not_running(self, runner: CliRunner) -> None:
        with patch(
            "bwssh.cli._send_command",
            side_effect=ControlError(-1, "Connection refused"),
        ):
            result = runner.invoke(main, ["sync"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


class TestKeysCommand:
    def test_keys_with_loaded_keys(self, runner: CliRunner) -> None:
        mock_result: dict[str, Any] = {
            "keys": [
                {
                    "fingerprint": "SHA256:abc123",
                    "algorithm": "ssh-ed25519",
                    "comment": "test@example",
                },
                {
                    "fingerprint": "SHA256:def456",
                    "algorithm": "ssh-rsa",
                    "comment": "rsa@example",
                },
            ]
        }
        with patch("bwssh.cli._send_command", return_value=mock_result):
            result = runner.invoke(main, ["keys"])
        assert result.exit_code == 0
        assert "SHA256:abc123" in result.output
        assert "ssh-ed25519" in result.output
        assert "test@example" in result.output
        assert "SHA256:def456" in result.output

    def test_keys_empty(self, runner: CliRunner) -> None:
        mock_result: dict[str, Any] = {"keys": []}
        with patch("bwssh.cli._send_command", return_value=mock_result):
            result = runner.invoke(main, ["keys"])
        assert result.exit_code == 0
        assert "no keys" in result.output.lower()

    def test_keys_daemon_not_running(self, runner: CliRunner) -> None:
        with patch(
            "bwssh.cli._send_command",
            side_effect=ControlError(-1, "Connection refused"),
        ):
            result = runner.invoke(main, ["keys"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# config init — _write_config_file
# ---------------------------------------------------------------------------


class TestWriteConfigFile:
    """Tests for _write_config_file using config.toml.example template."""

    def test_generated_config_is_valid_toml(self, tmp_path: Path) -> None:
        """Generated config should be parseable TOML."""
        config_path = tmp_path / "bwssh" / "config.toml"
        _write_config_file(config_path, "bw", [])

        with config_path.open("rb") as f:
            data = tomllib.load(f)

        assert "daemon" in data
        assert "bitwarden" in data
        assert "auth" in data
        assert "ssh" in data

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """Should create parent directories if they don't exist."""
        config_path = tmp_path / "deep" / "nested" / "config.toml"
        _write_config_file(config_path, "bw", [])

        assert config_path.exists()

    def test_substitutes_bw_path(self, tmp_path: Path) -> None:
        """Custom bw_path should be written into the config."""
        config_path = tmp_path / "config.toml"
        _write_config_file(config_path, "/usr/local/bin/bw", [])

        with config_path.open("rb") as f:
            data = tomllib.load(f)

        assert data["bitwarden"]["bw_path"] == "/usr/local/bin/bw"

    def test_substitutes_item_ids(self, tmp_path: Path) -> None:
        """Discovered item_ids should be written into the config."""
        config_path = tmp_path / "config.toml"
        ids = ["aaa-111", "bbb-222", "ccc-333"]
        _write_config_file(config_path, "bw", ids)

        with config_path.open("rb") as f:
            data = tomllib.load(f)

        assert data["bitwarden"]["item_ids"] == ids

    def test_empty_item_ids(self, tmp_path: Path) -> None:
        """Empty item_ids should produce an empty list."""
        config_path = tmp_path / "config.toml"
        _write_config_file(config_path, "bw", [])

        with config_path.open("rb") as f:
            data = tomllib.load(f)

        assert data["bitwarden"]["item_ids"] == []

    def test_has_all_default_values(self, tmp_path: Path) -> None:
        """Generated config should contain all default values from config.py."""
        config_path = tmp_path / "config.toml"
        _write_config_file(config_path, "bw", [])

        with config_path.open("rb") as f:
            data = tomllib.load(f)

        # daemon defaults
        assert data["daemon"]["agent_socket"] == "agent.sock"
        assert data["daemon"]["control_socket"] == "control.sock"
        assert data["daemon"]["log_level"] == "INFO"
        assert data["daemon"]["lock_on_sleep"] is True

        # bitwarden defaults
        assert data["bitwarden"]["mode"] == "explicit"

        # auth defaults
        assert data["auth"]["require_polkit"] is False
        assert data["auth"]["approval_mode"] == "per_connection"
        assert data["auth"]["approval_ttl_seconds"] == 300
        assert data["auth"]["deny_forwarded_by_default"] is True

        # ssh defaults
        assert data["ssh"]["allow_ed25519"] is True
        assert data["ssh"]["allow_ecdsa"] is True
        assert data["ssh"]["allow_rsa"] is True
        assert data["ssh"]["prefer_rsa_sha2"] is True

    def test_config_roundtrips_through_load_config(self, tmp_path: Path) -> None:
        """Generated config should load correctly via load_config."""
        config_path = tmp_path / "config.toml"
        ids = ["id-1", "id-2"]
        _write_config_file(config_path, "/opt/bw", ids)

        cfg = load_config(config_path)

        assert cfg.bitwarden.bw_path == "/opt/bw"
        assert cfg.bitwarden.item_ids == ids
        assert cfg.daemon.log_level == "INFO"
        assert cfg.auth.require_polkit is False
        assert cfg.ssh.allow_ed25519 is True
