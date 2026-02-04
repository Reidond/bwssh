"""Click-based CLI for bwssh — Bitwarden-backed SSH agent."""

from __future__ import annotations

import asyncio
import json as _json
import os
import shutil
import signal
import subprocess
import time
from importlib.resources import files
from pathlib import Path
from typing import Any

import click

from bwssh import __version__
from bwssh.config import _default_config_path, load_config
from bwssh.control import ControlClient, ControlError

_DAEMON_NOT_RUNNING = "Error: daemon not running. Start with: bwssh start"


def _read_package_data(path: str) -> str:
    """Read a file from the package data directory."""
    return files("bwssh").joinpath("data", path).read_text()


def _get_control_socket() -> Path:
    config = load_config()
    if config.daemon.runtime_dir is not None:
        return config.daemon.runtime_dir / config.daemon.control_socket
    xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return Path(xdg) / "bwssh" / config.daemon.control_socket


def _send_command(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    socket_path = _get_control_socket()
    client = ControlClient(socket_path)
    return asyncio.run(client.send_command(method, params or {}))


def _format_uptime(seconds: float) -> str:
    hours = int(seconds) // 3600
    minutes = (int(seconds) % 3600) // 60
    secs = int(seconds) % 60
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _try_systemd_start() -> bool:
    if shutil.which("systemctl") is None:
        return False
    try:
        subprocess.run(
            ["systemctl", "--user", "start", "bwssh-agent.service"],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def _start_daemon_direct() -> bool:
    exe = shutil.which("bwssh-agentd")
    if exe is None:
        return False
    try:
        subprocess.Popen(
            [exe],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    time.sleep(0.5)
    socket_path = _get_control_socket()
    return socket_path.exists()


def _try_systemd_stop() -> bool:
    if shutil.which("systemctl") is None:
        return False
    try:
        subprocess.run(
            ["systemctl", "--user", "stop", "bwssh-agent.service"],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def _stop_daemon_direct() -> bool:
    try:
        result = _send_command("status")
        pid = result.get("pid")
        if pid is None:
            return False
        os.kill(int(pid), signal.SIGTERM)
        time.sleep(0.5)
        return True
    except (ControlError, OSError):
        return False


def _systemd_user_dir() -> Path:
    return Path.home() / ".config" / "systemd" / "user"


def _run_bw_unlock() -> str | None:
    # First, check if BW_SESSION is already set in the environment
    session_from_env = os.environ.get("BW_SESSION")
    if session_from_env:
        # Validate the session is still valid
        bw_path = shutil.which("bw") or "bw"
        try:
            result = subprocess.run(
                [bw_path, "status", "--session", session_from_env],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                status = _json.loads(result.stdout)
                if status.get("status") == "unlocked":
                    return session_from_env
        except (FileNotFoundError, OSError, ValueError):
            pass  # Fall through to interactive unlock

    # Fall back to interactive unlock
    bw_path = shutil.which("bw") or "bw"
    try:
        result = subprocess.run(
            [bw_path, "unlock", "--raw"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        session_key = result.stdout.strip()
        return session_key if session_key else None
    except (FileNotFoundError, OSError):
        return None


def _handle_control_error(_e: ControlError | OSError) -> None:
    click.echo(_DAEMON_NOT_RUNNING, err=True)
    raise SystemExit(1)


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="bwssh")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Bitwarden-backed SSH agent for Linux."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
def status() -> None:
    """Show daemon status."""
    try:
        result = _send_command("status")
    except (ControlError, OSError) as e:
        _handle_control_error(e)
        return

    pid = result.get("pid", "?")
    uptime = _format_uptime(float(result.get("uptime", 0)))
    key_count = result.get("key_count", 0)
    locked = result.get("locked", False)
    polkit_available = result.get("polkit_available", True)
    polkit_error = result.get("polkit_error")

    state = (
        click.style("locked", fg="red")
        if locked
        else click.style("unlocked", fg="green")
    )
    if polkit_available:
        polkit_status = click.style("enabled", fg="green")
    elif polkit_error:
        polkit_status = click.style("failed", fg="red")
    else:
        polkit_status = click.style("disabled", fg="yellow")

    click.echo(f"Daemon PID:  {pid}")
    click.echo(f"Uptime:      {uptime}")
    click.echo(f"Keys loaded: {key_count}")
    click.echo(f"State:       {state}")
    click.echo(f"Polkit:      {polkit_status}")

    if polkit_error:
        click.echo()
        click.echo(
            click.style("Warning: ", fg="red")
            + "Polkit failed - sign requests will be denied."
        )
        click.echo(f"  Error: {polkit_error}")
        click.echo("  Fix D-Bus/polkit configuration or set auth.require_polkit=false.")


@main.command()
def start() -> None:
    """Start the bwssh agent daemon."""
    if _try_systemd_start():
        click.echo("Daemon started via systemd.")
        return

    if _start_daemon_direct():
        click.echo("Daemon started.")
        return

    click.echo("Error: failed to start daemon.", err=True)
    raise SystemExit(1)


@main.command()
def stop() -> None:
    """Stop the bwssh agent daemon."""
    if _try_systemd_stop():
        click.echo("Daemon stopped via systemd.")
        return

    if _stop_daemon_direct():
        click.echo("Daemon stopped.")
        return

    click.echo("Error: failed to stop daemon.", err=True)
    raise SystemExit(1)


@main.command()
@click.option("--user-systemd", is_flag=True, help="Install systemd user units")
@click.option("--polkit", is_flag=True, help="Print polkit policy file")
def install(user_systemd: bool, polkit: bool) -> None:
    """Install systemd units or polkit policy."""
    if not (user_systemd or polkit):
        click.echo("Error: specify --user-systemd or --polkit", err=True)
        raise SystemExit(1)

    if user_systemd:
        target = _systemd_user_dir()
        target.mkdir(parents=True, exist_ok=True)

        exe_path = shutil.which("bwssh-agentd") or "bwssh-agentd"
        service_template = _read_package_data("systemd/bwssh-agent.service")
        (target / "bwssh-agent.service").write_text(
            service_template.format(exe_path=exe_path)
        )
        (target / "bwssh-agent.socket").write_text(
            _read_package_data("systemd/bwssh-agent.socket")
        )

        click.echo(f"Installed systemd units to {target}")
        click.echo(
            "Run: systemctl --user daemon-reload && "
            "systemctl --user enable bwssh-agent.socket"
        )

    if polkit:
        click.echo(_read_package_data("polkit/io.github.reidond.bwssh.policy"))
        # Print instructions to stderr so they don't pollute piped output
        click.echo(err=True)
        click.echo("Install with:", err=True)
        click.echo(
            "  bwssh install --polkit | sudo tee "
            "/usr/share/polkit-1/actions/io.github.reidond.bwssh.policy > /dev/null",
            err=True,
        )


@main.command()
def unlock() -> None:
    """Unlock Bitwarden vault and load keys."""
    session_key = _run_bw_unlock()
    if session_key is None:
        click.echo("Error: failed to unlock Bitwarden vault.", err=True)
        raise SystemExit(1)

    try:
        _send_command("unlock", {"session_key": session_key})
    except (ControlError, OSError) as e:
        _handle_control_error(e)
        return

    click.echo("Vault unlocked. Keys loaded.")


@main.command()
def lock() -> None:
    """Lock the agent and clear keys."""
    try:
        _send_command("lock")
    except (ControlError, OSError) as e:
        _handle_control_error(e)
        return

    click.echo("Agent locked. Keys cleared.")


@main.command()
def sync() -> None:
    """Sync keys from Bitwarden."""
    try:
        _send_command("sync")
    except (ControlError, OSError) as e:
        _handle_control_error(e)
        return

    click.echo("Sync complete.")


@main.command()
def keys() -> None:
    """List loaded SSH keys."""
    try:
        result = _send_command("list_keys")
    except (ControlError, OSError) as e:
        _handle_control_error(e)
        return

    key_list: list[dict[str, str]] = result.get("keys", [])
    if not key_list:
        click.echo("No keys loaded.")
        return

    header = f"{'Fingerprint':<50} {'Algorithm':<25} {'Comment'}"
    click.echo(header)
    click.echo("-" * len(header))
    for key in key_list:
        fp = key.get("fingerprint", "?")
        algo = key.get("algorithm", "?")
        comment = key.get("comment", "")
        click.echo(f"{fp:<50} {algo:<25} {comment}")


# --- Config management commands ---


def _get_bw_session() -> str | None:
    """Get BW_SESSION from environment or return None."""
    return os.environ.get("BW_SESSION")


def _list_bw_ssh_keys(bw_path: str, session: str) -> list[dict[str, Any]]:
    """List all Bitwarden items that contain SSH keys."""
    try:
        result = subprocess.run(
            [bw_path, "list", "items", "--session", session],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        items = _json.loads(result.stdout)
        return [item for item in items if "sshKey" in item]
    except (FileNotFoundError, OSError, ValueError):
        return []


def _write_config_file(config_path: Path, bw_path: str, item_ids: list[str]) -> None:
    """Write a minimal config file with the given item IDs."""
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Format item_ids as TOML array
    if item_ids:
        ids_str = ",\n    ".join(f'"{id}"' for id in item_ids)
        ids_toml = f"[\n    {ids_str},\n]"
    else:
        ids_toml = "[]"

    content = f'''# bwssh configuration
# Generated by: bwssh config init

[bitwarden]
bw_path = "{bw_path}"
item_ids = {ids_toml}

[auth]
require_polkit = false
deny_forwarded_by_default = true
'''
    config_path.write_text(content)


@main.group()
def config() -> None:
    """Manage bwssh configuration."""
    pass


@config.command("show")
def config_show() -> None:
    """Show current configuration."""
    config_path = _default_config_path()
    cfg = load_config()

    click.echo(f"Config file: {config_path}")
    click.echo(f"  Exists: {config_path.exists()}")
    click.echo()
    click.echo("[daemon]")
    click.echo(f"  lock_on_sleep: {cfg.daemon.lock_on_sleep}")
    click.echo()
    click.echo("[bitwarden]")
    click.echo(f"  bw_path: {cfg.bitwarden.bw_path}")
    click.echo(f"  item_ids: {len(cfg.bitwarden.item_ids)} configured")
    for item_id in cfg.bitwarden.item_ids:
        click.echo(f"    - {item_id}")
    click.echo()
    click.echo("[auth]")
    click.echo(f"  require_polkit: {cfg.auth.require_polkit}")
    click.echo(f"  deny_forwarded_by_default: {cfg.auth.deny_forwarded_by_default}")


@config.command("init")
@click.option("--bw-path", default=None, help="Path to bw CLI (auto-detected)")
def config_init(bw_path: str | None) -> None:
    """Initialize config by discovering SSH keys in Bitwarden.

    This command finds all SSH keys in your Bitwarden vault and creates
    a config file with them.
    """
    config_path = _default_config_path()

    # Check for BW_SESSION
    session = _get_bw_session()
    if not session:
        click.echo("Error: BW_SESSION not set. Run 'bw unlock' first.", err=True)
        click.echo("  export BW_SESSION=$(bw unlock --raw)", err=True)
        raise SystemExit(1)

    # Find bw path
    if bw_path is None:
        bw_path = shutil.which("bw")
        if bw_path is None:
            click.echo(
                "Error: 'bw' not found in PATH. Install Bitwarden CLI.", err=True
            )
            raise SystemExit(1)

    click.echo(f"Using bw: {bw_path}")
    click.echo("Searching for SSH keys in Bitwarden...")

    # Sync first
    subprocess.run(
        [bw_path, "sync", "--session", session], capture_output=True, check=False
    )

    # Find SSH keys
    ssh_items = _list_bw_ssh_keys(bw_path, session)

    if not ssh_items:
        click.echo("No SSH keys found in Bitwarden vault.")
        click.echo("Add SSH keys to Bitwarden first, then run this command again.")
        raise SystemExit(1)

    click.echo(f"\nFound {len(ssh_items)} SSH key(s):\n")

    for i, item in enumerate(ssh_items, 1):
        click.echo(f"  {i}. {item['name']} ({item['id'][:8]}...)")

    click.echo()

    # Confirm overwrite if config exists
    if config_path.exists() and not click.confirm(
        f"Config exists at {config_path}. Overwrite?"
    ):
        click.echo("Aborted.")
        raise SystemExit(0)

    # Write config
    item_ids = [item["id"] for item in ssh_items]
    _write_config_file(config_path, bw_path, item_ids)

    click.echo(f"\nConfig written to {config_path}")
    click.echo(f"Added {len(item_ids)} SSH key(s).")
    click.echo()
    click.echo("Next steps:")
    click.echo("  1. Restart daemon: bwssh stop && bwssh start")
    click.echo("  2. Unlock vault:   bwssh unlock")
    click.echo("  3. Test SSH:       ssh -T git@github.com")
