"""Tests for TOML configuration module."""

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from bwssh.config import (
    AuthConfig,
    BitwardenConfig,
    BwsshConfig,
    DaemonConfig,
    SshConfig,
    load_config,
)


class TestDaemonConfig:
    """Tests for DaemonConfig dataclass."""

    def test_defaults(self) -> None:
        """Test DaemonConfig default values."""
        config = DaemonConfig()
        assert config.runtime_dir is None
        assert config.agent_socket == "agent.sock"
        assert config.control_socket == "control.sock"
        assert config.log_level == "INFO"

    def test_custom_values(self) -> None:
        """Test DaemonConfig with custom values."""
        config = DaemonConfig(
            runtime_dir=Path("/tmp/bwssh"),
            agent_socket="custom.sock",
            log_level="DEBUG",
        )
        assert config.runtime_dir == Path("/tmp/bwssh")
        assert config.agent_socket == "custom.sock"
        assert config.log_level == "DEBUG"


class TestBitwardenConfig:
    """Tests for BitwardenConfig dataclass."""

    def test_defaults(self) -> None:
        """Test BitwardenConfig default values."""
        config = BitwardenConfig()
        assert config.bw_path == "bw"
        assert config.mode == "explicit"
        assert config.item_ids == []
        assert config.windows_pipe_command
        assert config.auto_unlock_poll_seconds == 5

    def test_custom_values(self) -> None:
        """Test BitwardenConfig with custom values."""
        config = BitwardenConfig(
            bw_path="/usr/bin/bw",
            item_ids=["id1", "id2"],
        )
        assert config.bw_path == "/usr/bin/bw"
        assert config.item_ids == ["id1", "id2"]


class TestAuthConfig:
    """Tests for AuthConfig dataclass."""

    def test_defaults(self) -> None:
        """Test AuthConfig default values."""
        config = AuthConfig()
        assert config.approval_mode == "per_connection"
        assert config.approval_ttl_seconds == 300
        assert config.deny_forwarded_by_default is True

    def test_custom_values(self) -> None:
        """Test AuthConfig with custom values."""
        config = AuthConfig(
            approval_mode="always",
            approval_ttl_seconds=600,
            deny_forwarded_by_default=False,
        )
        assert config.approval_mode == "always"
        assert config.approval_ttl_seconds == 600
        assert config.deny_forwarded_by_default is False


class TestSshConfig:
    """Tests for SshConfig dataclass."""

    def test_defaults(self) -> None:
        """Test SshConfig default values."""
        config = SshConfig()
        assert config.allow_ed25519 is True
        assert config.allow_ecdsa is True
        assert config.allow_rsa is True
        assert config.prefer_rsa_sha2 is True

    def test_custom_values(self) -> None:
        """Test SshConfig with custom values."""
        config = SshConfig(
            allow_ed25519=False,
            allow_rsa=False,
        )
        assert config.allow_ed25519 is False
        assert config.allow_ecdsa is True
        assert config.allow_rsa is False
        assert config.prefer_rsa_sha2 is True


class TestBwsshConfig:
    """Tests for BwsshConfig root dataclass."""

    def test_defaults(self) -> None:
        """Test BwsshConfig default values."""
        config = BwsshConfig()
        assert isinstance(config.daemon, DaemonConfig)
        assert isinstance(config.bitwarden, BitwardenConfig)
        assert isinstance(config.auth, AuthConfig)
        assert isinstance(config.ssh, SshConfig)

    def test_custom_sections(self) -> None:
        """Test BwsshConfig with custom sections."""
        daemon = DaemonConfig(log_level="DEBUG")
        auth = AuthConfig(approval_mode="always")
        config = BwsshConfig(daemon=daemon, auth=auth)
        assert config.daemon.log_level == "DEBUG"
        assert config.auth.approval_mode == "always"


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_nonexistent_file_returns_defaults(self) -> None:
        """Test loading nonexistent config file returns defaults."""
        config = load_config(Path("/nonexistent/config.toml"))
        assert config.daemon.log_level == "INFO"
        assert config.daemon.agent_socket == "agent.sock"
        assert config.auth.approval_mode == "per_connection"
        assert config.ssh.allow_ed25519 is True

    def test_load_valid_config_file(self, tmp_path: Path) -> None:
        """Test loading valid config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
log_level = "DEBUG"
agent_socket = "custom.sock"

[auth]
approval_mode = "always"
approval_ttl_seconds = 600

[ssh]
allow_rsa = false
"""
        )

        config = load_config(config_file)
        assert config.daemon.log_level == "DEBUG"
        assert config.daemon.agent_socket == "custom.sock"
        assert config.daemon.control_socket == "control.sock"  # default
        assert config.auth.approval_mode == "always"
        assert config.auth.approval_ttl_seconds == 600
        assert config.ssh.allow_rsa is False
        assert config.ssh.allow_ed25519 is True  # default

    def test_load_partial_config_fills_defaults(self, tmp_path: Path) -> None:
        """Test that missing config values use defaults."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
log_level = "WARNING"
"""
        )

        config = load_config(config_file)
        assert config.daemon.log_level == "WARNING"
        assert config.daemon.agent_socket == "agent.sock"
        assert config.bitwarden.bw_path == "bw"
        assert config.auth.approval_mode == "per_connection"

    def test_load_empty_config_returns_defaults(self, tmp_path: Path) -> None:
        """Test loading empty config file returns all defaults."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("")

        config = load_config(config_file)
        assert config.daemon.log_level == "INFO"
        assert config.auth.approval_mode == "per_connection"
        assert config.ssh.allow_ed25519 is True

    def test_load_invalid_toml_raises_error(self, tmp_path: Path) -> None:
        """Test loading invalid TOML raises ValueError."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[daemon\nlog_level = DEBUG")  # Invalid TOML

        with pytest.raises(ValueError, match="Invalid TOML"):
            load_config(config_file)

    def test_daemon_runtime_dir_from_config(self, tmp_path: Path) -> None:
        """Test loading runtime_dir from config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
runtime_dir = "/run/user/1000/bwssh"
"""
        )

        config = load_config(config_file)
        assert config.daemon.runtime_dir == Path("/run/user/1000/bwssh")

    def test_bitwarden_item_ids_from_config(self, tmp_path: Path) -> None:
        """Test loading item_ids from config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[bitwarden]
item_ids = ["uuid-1", "uuid-2", "uuid-3"]
"""
        )

        config = load_config(config_file)
        assert config.bitwarden.item_ids == ["uuid-1", "uuid-2", "uuid-3"]

    def test_bitwarden_windows_bridge_options_from_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[bitwarden]
mode = "windows_bridge"
windows_pipe_command = ["npiperelay.exe", "-ei", "-s", "//./pipe/custom-agent"]
auto_unlock_poll_seconds = 3
"""
        )

        config = load_config(config_file)
        assert config.bitwarden.mode == "windows_bridge"
        assert config.bitwarden.windows_pipe_command[-1] == "//./pipe/custom-agent"
        assert config.bitwarden.auto_unlock_poll_seconds == 3

    def test_env_override_runtime_dir(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """Test BWSSH_RUNTIME_DIR environment variable override."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
runtime_dir = "/config/path"
"""
        )

        monkeypatch.setenv("BWSSH_RUNTIME_DIR", "/env/path")
        config = load_config(config_file)
        assert config.daemon.runtime_dir == Path("/env/path")

    def test_env_override_log_level(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """Test BWSSH_LOG_LEVEL environment variable override."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
log_level = "INFO"
"""
        )

        monkeypatch.setenv("BWSSH_LOG_LEVEL", "ERROR")
        config = load_config(config_file)
        assert config.daemon.log_level == "ERROR"

    def test_env_override_without_config_file(self, monkeypatch: MonkeyPatch) -> None:
        """Test environment variable override when config file doesn't exist."""
        monkeypatch.setenv("BWSSH_LOG_LEVEL", "DEBUG")
        config = load_config(Path("/nonexistent/config.toml"))
        assert config.daemon.log_level == "DEBUG"

    def test_env_override_takes_precedence(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """Test that env override takes precedence over config file."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
runtime_dir = "/config/path"
log_level = "INFO"
"""
        )

        monkeypatch.setenv("BWSSH_RUNTIME_DIR", "/env/path")
        monkeypatch.setenv("BWSSH_LOG_LEVEL", "WARNING")
        config = load_config(config_file)
        assert config.daemon.runtime_dir == Path("/env/path")
        assert config.daemon.log_level == "WARNING"

    def test_xdg_config_home_respected(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """Test that XDG_CONFIG_HOME is respected for default path."""
        # Create config in custom XDG location
        xdg_dir = tmp_path / "xdg_config"
        xdg_dir.mkdir()
        config_dir = xdg_dir / "bwssh"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text(
            """
[daemon]
log_level = "DEBUG"
"""
        )

        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
        # Don't pass path, let it use default
        config = load_config(None)
        assert config.daemon.log_level == "DEBUG"

    def test_default_path_without_xdg_config_home(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """Test default path uses ~/.config when XDG_CONFIG_HOME not set."""
        # Create a fake home directory
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        config_dir = fake_home / ".config" / "bwssh"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.toml"
        config_file.write_text(
            """
[daemon]
log_level = "WARNING"
"""
        )

        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        config = load_config(None)
        assert config.daemon.log_level == "WARNING"

    def test_all_sections_together(self, tmp_path: Path) -> None:
        """Test loading config with all sections populated."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
[daemon]
runtime_dir = "/run/bwssh"
agent_socket = "agent.sock"
control_socket = "control.sock"
log_level = "DEBUG"

[bitwarden]
bw_path = "/usr/bin/bw"
mode = "explicit"
item_ids = ["id1", "id2"]

[auth]
approval_mode = "ttl"
approval_ttl_seconds = 600
deny_forwarded_by_default = false

[ssh]
allow_ed25519 = true
allow_ecdsa = false
allow_rsa = true
prefer_rsa_sha2 = true
"""
        )

        config = load_config(config_file)
        assert config.daemon.runtime_dir == Path("/run/bwssh")
        assert config.daemon.log_level == "DEBUG"
        assert config.bitwarden.bw_path == "/usr/bin/bw"
        assert config.bitwarden.item_ids == ["id1", "id2"]
        assert config.auth.approval_mode == "ttl"
        assert config.auth.approval_ttl_seconds == 600
        assert config.auth.deny_forwarded_by_default is False
        assert config.ssh.allow_ecdsa is False
