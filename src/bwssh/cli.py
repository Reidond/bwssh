"""Click-based CLI for bwssh — Bitwarden-backed SSH agent."""

from __future__ import annotations

import asyncio
import json as _json
import os
import shutil
import signal
import subprocess
import sys
import time
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

if TYPE_CHECKING:
    from bwssh.ui._base import UnlockResult

from bwssh import __version__
from bwssh.config import _default_config_path, load_config
from bwssh.control import ControlClient, ControlError

_DAEMON_NOT_RUNNING = "Error: daemon not running. Start with: bwssh start"
_DEFAULT_SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin"


def _read_package_data(path: str) -> str:
    """Read a file from the package data directory."""
    return files("bwssh").joinpath("data", path).read_text()


def _get_control_socket() -> Path:
    from bwssh.platform import get_runtime_dir  # noqa: PLC0415

    config = load_config()
    if config.daemon.runtime_dir is not None:
        return config.daemon.runtime_dir / config.daemon.control_socket
    return get_runtime_dir() / config.daemon.control_socket


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
    from bwssh.platform import try_service_start  # noqa: PLC0415

    return try_service_start()


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
    from bwssh.platform import try_service_stop  # noqa: PLC0415

    return try_service_stop()


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


def _get_bw_session_from_env() -> str | None:
    """Get BW_SESSION from environment.

    This is used for backward compatibility with legacy workflows.
    Returns None if not set. Validation is skipped for speed - the daemon
    will return an error if the session is invalid.
    """
    return os.environ.get("BW_SESSION") or None


def _build_unlock_params(
    session_key: str, bw_path: str | None = None
) -> dict[str, str]:
    configured_bw_path = bw_path or load_config().bitwarden.bw_path
    bw_exec_path = shutil.which(configured_bw_path) or configured_bw_path
    params = {
        "session_key": session_key,
        "bw_exec_path": bw_exec_path,
    }
    env_path = os.environ.get("PATH")
    if env_path and shutil.which("node", path=env_path):
        params["env_path"] = env_path
    return params


def _runtime_env_path() -> str:
    base_paths: list[str] = []
    mise_shims = Path.home() / ".local" / "share" / "mise" / "shims"
    local_bin = Path.home() / ".local" / "bin"
    for candidate in (mise_shims, local_bin):
        if candidate.exists():
            base_paths.append(str(candidate))

    env_path = os.environ.get("PATH")
    if env_path:
        base_paths.extend(part for part in env_path.split(":") if part)
    else:
        base_paths.extend(_DEFAULT_SYSTEM_PATH.split(":"))

    unique_paths: list[str] = []
    seen: set[str] = set()
    for path_part in base_paths:
        if path_part in seen:
            continue
        seen.add(path_part)
        unique_paths.append(path_part)

    return ":".join(unique_paths)


def _run_unlock_ui(ui_mode: str | None = None) -> UnlockResult:
    """Run interactive unlock UI and return the full result.

    Launches the TUI or graphical unlock screen, which collects the
    master password, runs ``bw unlock --raw``, and sends the session
    to the daemon to load keys — all while showing a loading indicator.

    Parameters:
        ui_mode: Force a specific UI mode (``"tui"`` or ``"graphical"``).
            When *None*, auto-detection is used.
    """
    from bwssh.ui import create_unlock_ui  # noqa: PLC0415

    bw_path = load_config().bitwarden.bw_path
    socket_path = _get_control_socket()

    async def _send_session(session_key: str) -> dict[str, Any]:
        client = ControlClient(socket_path)
        result = await client.send_command(
            "unlock", _build_unlock_params(session_key, bw_path=bw_path)
        )
        # Fetch detailed key info for the success screen
        try:
            keys_result = await client.send_command("list_keys", {})
            result["keys"] = keys_result.get("keys", [])
        except (ControlError, OSError):
            result["keys"] = []
        return result

    return create_unlock_ui(
        bw_path, on_session_ready=_send_session, ui_mode=ui_mode
    ).run()


def _handle_control_error(_e: ControlError | OSError) -> None:
    click.echo(_DAEMON_NOT_RUNNING, err=True)
    raise SystemExit(1)


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="bwssh")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Bitwarden-backed SSH agent."""
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
    mode = result.get("mode", "explicit")

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
    click.echo(f"Mode:        {mode}")

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


def _xdg_autostart_dir() -> Path:
    return Path.home() / ".config" / "autostart"


@main.command()
@click.option("--user-systemd", is_flag=True, help="Install systemd user units (Linux)")
@click.option("--launchd", is_flag=True, help="Install launchd user agent (macOS)")
@click.option("--polkit", is_flag=True, help="Print polkit policy file (Linux)")
@click.option(
    "--tray-autostart",
    is_flag=True,
    help="Install XDG autostart entry for the tray icon (Linux)",
)
def install(
    user_systemd: bool, launchd: bool, polkit: bool, tray_autostart: bool
) -> None:
    """Install service integration (systemd/launchd), polkit policy, or tray autostart.

    When no flags are given, auto-detects the platform:
    - macOS: installs launchd agent
    - Linux: installs systemd user units

    Flags can be combined, e.g.
    ``bwssh install --user-systemd --tray-autostart``.
    """
    if not (user_systemd or launchd or polkit or tray_autostart):
        if sys.platform == "darwin":
            launchd = True
        else:
            user_systemd = True

    if user_systemd:
        target = _systemd_user_dir()
        target.mkdir(parents=True, exist_ok=True)
        env_path = _runtime_env_path()

        # Agent daemon units
        agentd_path = shutil.which("bwssh-agentd") or "bwssh-agentd"
        service_template = _read_package_data("systemd/bwssh-agent.service")
        (target / "bwssh-agent.service").write_text(
            service_template.format(exe_path=agentd_path, env_path=env_path)
        )
        (target / "bwssh-agent.socket").write_text(
            _read_package_data("systemd/bwssh-agent.socket")
        )

        # Tray unit
        bwssh_path = shutil.which("bwssh") or "bwssh"
        tray_service_template = _read_package_data("systemd/bwssh-tray.service")
        (target / "bwssh-tray.service").write_text(
            tray_service_template.format(exe_path=bwssh_path, env_path=env_path)
        )

        click.echo(f"Installed systemd units to {target}")
        click.echo(
            "Run: systemctl --user daemon-reload && "
            "systemctl --user enable bwssh-agent.socket bwssh-tray.service"
        )

    if launchd:
        _install_launchd()

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

    if tray_autostart:
        bwssh_path = shutil.which("bwssh") or "bwssh"

        autostart_dir = _xdg_autostart_dir()
        autostart_dir.mkdir(parents=True, exist_ok=True)

        desktop_template = _read_package_data("autostart/bwssh-tray.desktop")
        desktop_path = autostart_dir / "bwssh-tray.desktop"
        desktop_path.write_text(desktop_template.format(exe_path=bwssh_path))
        click.echo(f"Installed XDG autostart entry: {desktop_path}")
        click.echo("The tray will start automatically on next login.")


def _install_launchd() -> None:
    """Install launchd user agent plist for macOS."""
    agentd_path = shutil.which("bwssh-agentd") or "bwssh-agentd"
    env_path = _runtime_env_path()

    launch_agents = Path.home() / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True, exist_ok=True)

    plist_template = _read_package_data("launchd/io.github.reidond.bwssh-agent.plist")
    plist_path = launch_agents / "io.github.reidond.bwssh-agent.plist"
    plist_path.write_text(
        plist_template.format(exe_path=agentd_path, env_path=env_path)
    )

    click.echo(f"Installed launchd agent to {plist_path}")
    click.echo("Run: launchctl load " + str(plist_path))


@main.command()
@click.option(
    "--session",
    "session_key",
    default=None,
    help="Use provided session key instead of interactive unlock",
)
@click.option(
    "--ui",
    "ui_mode",
    type=click.Choice(["tui", "graphical"], case_sensitive=False),
    default=None,
    help="Force a specific UI mode (default: auto-detect)",
)
def unlock(session_key: str | None, ui_mode: str | None) -> None:
    """Unlock Bitwarden vault and load keys.

    Prompts for your Bitwarden master password, then loads SSH keys
    from your vault into the agent.
    """
    config = load_config()
    if config.bitwarden.mode == "windows_bridge":
        try:
            result = _send_command("unlock")
        except (ControlError, OSError) as e:
            _handle_control_error(e)
            return

        message = result.get("message")
        if message:
            click.echo(str(message))
        if result.get("unlocked"):
            click.echo(
                f"Windows bridge ready. {result.get('key_count', 0)} key(s) available."
            )
        return

    # Check for BW_SESSION env var if no --session provided
    if session_key is None:
        session_key = _get_bw_session_from_env()

    # If still no session, run interactive unlock
    if session_key is None:
        ui_result = _run_unlock_ui(ui_mode=ui_mode)
        if ui_result.session_key is None:
            if ui_result.error and ui_result.error != "cancelled":
                click.echo(f"Error: {ui_result.error}", err=True)
            raise SystemExit(1)
        click.echo(f"Vault unlocked. {ui_result.key_count} key(s) loaded.")
        return

    # Direct session key provided — send to daemon without TUI
    try:
        result = _send_command("unlock", _build_unlock_params(session_key))
        key_count = result.get("key_count", 0)
        click.echo(f"Vault unlocked. {key_count} key(s) loaded.")
    except ControlError as e:
        if "denied by polkit" in str(e).lower():
            click.echo("Error: unlock denied by polkit authorization.", err=True)
        else:
            click.echo(f"Error: {e}", err=True)
        raise SystemExit(1) from None
    except OSError as e:
        _handle_control_error(e)


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
    """Sync keys from Bitwarden.

    Requires the agent to be unlocked first.
    """
    try:
        result = _send_command("sync")
        message = result.get("message")
        if message:
            click.echo(str(message))
        key_count = result.get("key_count", 0)
        click.echo(f"Sync complete. {key_count} key(s) loaded.")
    except ControlError as e:
        if "locked" in str(e).lower():
            click.echo("Error: agent is locked. Run 'bwssh unlock' first.", err=True)
        else:
            click.echo(f"Error: {e}", err=True)
        raise SystemExit(1) from None
    except OSError as e:
        _handle_control_error(e)


def _tray_lock_path() -> Path:
    """Return the path used for tray single-instance locking."""
    from bwssh.platform import get_runtime_dir  # noqa: PLC0415

    lock_dir = get_runtime_dir()
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / "tray.lock"


@main.command()
def tray() -> None:
    """Run system tray icon showing agent status.

    Displays a persistent tray icon that reflects the current daemon
    state (locked / unlocked / disconnected) and offers quick actions
    via a context menu.  Requires AppIndicator3 (libayatana-appindicator).

    Only one instance can run at a time; a second invocation exits
    immediately so that overlapping autostart mechanisms (systemd +
    XDG autostart) do not produce duplicate tray icons.
    """
    import fcntl  # noqa: PLC0415

    from bwssh.tray import TRAY_AVAILABLE, TrayIcon  # noqa: PLC0415

    if not TRAY_AVAILABLE:
        from bwssh.tray import _appindicator_install_hint  # noqa: PLC0415

        click.echo(
            "Error: " + _appindicator_install_hint(),
            err=True,
        )
        raise SystemExit(1)

    # Single-instance guard: acquire an exclusive lock so that only one
    # ``bwssh tray`` process runs at a time.  If another instance already
    # holds the lock we exit silently (this is expected when both systemd
    # and XDG autostart are enabled).
    lock_path = _tray_lock_path()
    lock_file = lock_path.open("w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        # Another tray instance is already running.
        lock_file.close()
        click.echo("Another bwssh tray is already running.", err=True)
        raise SystemExit(0) from None

    # Keep lock_file open (and thus locked) for the lifetime of the process.

    socket_path = _get_control_socket()
    tray_icon = TrayIcon(socket_path)
    tray_icon.run()


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
    """Write a config file using the example template with all defaults.

    Reads ``config.toml.example`` from package data and substitutes the
    user-specific *bw_path* and *item_ids* values.
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)

    template = _read_package_data("config.toml.example")

    # Format item_ids as TOML array
    if item_ids:
        ids_str = ",\n    ".join(f'"{id}"' for id in item_ids)
        ids_toml = f"[\n    {ids_str},\n]"
    else:
        ids_toml = "[]"

    # Replace the placeholder values in the template
    content = template.replace('bw_path = "bw"', f'bw_path = "{bw_path}"')
    content = content.replace("item_ids = []", f"item_ids = {ids_toml}")

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
