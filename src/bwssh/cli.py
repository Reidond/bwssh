"""Click-based CLI for bwssh — Bitwarden-backed SSH agent."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import click

from bwssh import __version__
from bwssh.config import load_config
from bwssh.control import ControlClient, ControlError

_DAEMON_NOT_RUNNING = "Error: daemon not running. Start with: bwssh start"

_SERVICE_UNIT = """\
[Unit]
Description=bwssh SSH agent daemon
Documentation=https://github.com/reidond/bwssh

[Service]
Type=simple
ExecStart={exe_path}
Restart=on-failure

[Install]
WantedBy=default.target
"""

_SOCKET_UNIT = """\
[Unit]
Description=bwssh SSH agent socket

[Socket]
ListenStream=%t/bwssh/agent.sock
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
"""

_POLKIT_POLICY = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>bwssh</vendor>
  <vendor_url>https://github.com/reidond/bwssh</vendor_url>

  <action id="io.github.reidond.bwssh.sign">
    <description>Authorize SSH signing via bwssh agent</description>
    <message>An application wants to use your SSH key</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>

  <action id="io.github.reidond.bwssh.unlock">
    <description>Unlock Bitwarden session for bwssh</description>
    <message>bwssh wants to unlock your Bitwarden vault</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
"""


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
    state = (
        click.style("locked", fg="red")
        if locked
        else click.style("unlocked", fg="green")
    )

    click.echo(f"Daemon PID:  {pid}")
    click.echo(f"Uptime:      {uptime}")
    click.echo(f"Keys loaded: {key_count}")
    click.echo(f"State:       {state}")


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
        (target / "bwssh-agent.service").write_text(
            _SERVICE_UNIT.format(exe_path=exe_path)
        )
        (target / "bwssh-agent.socket").write_text(_SOCKET_UNIT)

        click.echo(f"Installed systemd units to {target}")
        click.echo(
            "Run: systemctl --user daemon-reload && "
            "systemctl --user enable bwssh-agent.socket"
        )

    if polkit:
        click.echo(_POLKIT_POLICY)
        click.echo("Save to /etc/polkit-1/actions/io.github.reidond.bwssh.policy")


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
