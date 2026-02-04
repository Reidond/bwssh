"""TOML configuration module for bwssh.

Loads configuration from ${XDG_CONFIG_HOME:-~/.config}/bwssh/config.toml
with sensible defaults and environment variable overrides.
"""

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DaemonConfig:
    """Daemon configuration section."""

    runtime_dir: Path | None = None
    agent_socket: str = "agent.sock"
    control_socket: str = "control.sock"
    log_level: str = "INFO"


@dataclass
class BitwardenConfig:
    """Bitwarden configuration section."""

    bw_path: str = "bw"
    mode: str = "explicit"
    item_ids: list[str] = field(default_factory=list)


@dataclass
class AuthConfig:
    """Authorization configuration section."""

    approval_mode: str = "per_connection"
    approval_ttl_seconds: int = 300
    deny_forwarded_by_default: bool = True
    require_polkit: bool = False  # If true, deny all signing when polkit unavailable


@dataclass
class SshConfig:
    """SSH key algorithm configuration section."""

    allow_ed25519: bool = True
    allow_ecdsa: bool = True
    allow_rsa: bool = True
    prefer_rsa_sha2: bool = True


@dataclass
class BwsshConfig:
    """Root configuration object."""

    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    bitwarden: BitwardenConfig = field(default_factory=BitwardenConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    ssh: SshConfig = field(default_factory=SshConfig)


def _default_config_path() -> Path:
    """Get default config file path respecting XDG_CONFIG_HOME."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "bwssh" / "config.toml"


def load_config(path: Path | None = None) -> BwsshConfig:
    """Load configuration from TOML file with sensible defaults.

    Args:
        path: Path to config file. If None, uses default location.

    Returns:
        BwsshConfig with loaded values and defaults.

    Raises:
        ValueError: If config file is invalid TOML.
    """
    config_path = path or _default_config_path()

    # Start with defaults
    config = BwsshConfig()

    # Load from file if exists
    if config_path.exists():
        try:
            with config_path.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"Invalid TOML in {config_path}: {e}") from e

        # Parse daemon section
        if "daemon" in data:
            daemon_data = data["daemon"]
            config.daemon = DaemonConfig(
                runtime_dir=(
                    Path(daemon_data["runtime_dir"])
                    if "runtime_dir" in daemon_data
                    else None
                ),
                agent_socket=daemon_data.get(
                    "agent_socket", config.daemon.agent_socket
                ),
                control_socket=daemon_data.get(
                    "control_socket", config.daemon.control_socket
                ),
                log_level=daemon_data.get("log_level", config.daemon.log_level),
            )

        # Parse bitwarden section
        if "bitwarden" in data:
            bw_data = data["bitwarden"]
            config.bitwarden = BitwardenConfig(
                bw_path=bw_data.get("bw_path", config.bitwarden.bw_path),
                mode=bw_data.get("mode", config.bitwarden.mode),
                item_ids=bw_data.get("item_ids", config.bitwarden.item_ids),
            )

        # Parse auth section
        if "auth" in data:
            auth_data = data["auth"]
            config.auth = AuthConfig(
                approval_mode=auth_data.get("approval_mode", config.auth.approval_mode),
                approval_ttl_seconds=auth_data.get(
                    "approval_ttl_seconds", config.auth.approval_ttl_seconds
                ),
                deny_forwarded_by_default=auth_data.get(
                    "deny_forwarded_by_default", config.auth.deny_forwarded_by_default
                ),
                require_polkit=auth_data.get(
                    "require_polkit", config.auth.require_polkit
                ),
            )

        # Parse ssh section
        if "ssh" in data:
            ssh_data = data["ssh"]
            config.ssh = SshConfig(
                allow_ed25519=ssh_data.get("allow_ed25519", config.ssh.allow_ed25519),
                allow_ecdsa=ssh_data.get("allow_ecdsa", config.ssh.allow_ecdsa),
                allow_rsa=ssh_data.get("allow_rsa", config.ssh.allow_rsa),
                prefer_rsa_sha2=ssh_data.get(
                    "prefer_rsa_sha2", config.ssh.prefer_rsa_sha2
                ),
            )

    # Apply environment variable overrides
    if "BWSSH_RUNTIME_DIR" in os.environ:
        config.daemon.runtime_dir = Path(os.environ["BWSSH_RUNTIME_DIR"])
    if "BWSSH_LOG_LEVEL" in os.environ:
        config.daemon.log_level = os.environ["BWSSH_LOG_LEVEL"]

    return config
