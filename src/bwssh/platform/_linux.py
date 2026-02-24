"""Linux-specific platform implementations.

Provides SO_PEERCRED credential extraction, /proc metadata reading,
D-Bus polkit authorization, logind sleep watching, systemd service
management, and XDG runtime/config directory resolution.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bwssh.control import ControlServer
    from bwssh.peercred import PeerCredentials, ProcessMetadata
    from bwssh.polkit import Authorizer

logger = logging.getLogger(__name__)

# SO_PEERCRED returns struct ucred: pid_t pid, uid_t uid, gid_t gid
# All three are 32-bit signed ints on Linux, but we unpack as unsigned
# since negative values are not meaningful here.
_UCRED_FORMAT = "III"  # 3 x uint32
_UCRED_SIZE = struct.calcsize(_UCRED_FORMAT)


def get_peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Extract peer PID, UID, GID via SO_PEERCRED (Linux-specific)."""
    from bwssh.peercred import PeerCredentials  # noqa: PLC0415

    cred_bytes = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
    pid, uid, gid = struct.unpack(_UCRED_FORMAT, cred_bytes)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def get_process_metadata(pid: int) -> ProcessMetadata:
    """Read process metadata from /proc/<pid>/*, with graceful degradation."""
    from bwssh.peercred import ProcessMetadata  # noqa: PLC0415

    exe_path = _read_exe(pid)
    cmdline = _read_cmdline(pid)
    start_time = _read_start_time(pid)
    return ProcessMetadata(exe_path=exe_path, cmdline=cmdline, start_time=start_time)


def _read_exe(pid: int) -> str | None:
    """Read /proc/<pid>/exe symlink target."""
    try:
        return str(Path(f"/proc/{pid}/exe").readlink())
    except (OSError, ValueError):
        return None


def _read_cmdline(pid: int) -> list[str] | None:
    """Read /proc/<pid>/cmdline (null-separated arguments)."""
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
        if not data:
            return None
        return [
            arg.decode("utf-8", errors="replace") for arg in data.split(b"\0") if arg
        ]
    except (OSError, ValueError):
        return None


def _read_start_time(pid: int) -> int | None:
    """Read process start time from /proc/<pid>/stat.

    The start time is field 22 (1-indexed) in /proc/pid/stat, measured in
    clock ticks since boot. The tricky part is that field 2 (comm) is
    enclosed in parentheses and may itself contain spaces or parentheses,
    so we find the *last* closing paren to safely skip it.
    """
    try:
        stat_content = Path(f"/proc/{pid}/stat").read_text()
        # Find closing paren of the comm field — everything after is space-separated
        close_paren = stat_content.rfind(")")
        if close_paren == -1:
            return None
        # Fields after comm start at field 3 (state); starttime is field 22
        # So it's index 22-3 = 19 in the remaining fields
        remaining = stat_content[close_paren + 2 :]  # skip ") "
        fields = remaining.split()
        return int(fields[19])  # field 22 (1-indexed) = index 19 after comm
    except (OSError, ValueError, IndexError):
        return None


def get_runtime_dir() -> Path:
    """Return the runtime directory for bwssh on Linux."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "bwssh"
    return Path(f"/tmp/bwssh-{os.getuid()}")


def get_config_dir() -> Path:
    """Return the config directory for bwssh on Linux."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "bwssh"


async def create_authorizer(
    config: object,
) -> tuple[Authorizer, bool, str | None]:
    """Connect to system D-Bus for polkit authorization."""
    from dbus_fast import BusType  # noqa: PLC0415
    from dbus_fast.aio import MessageBus  # noqa: PLC0415

    from bwssh.polkit import (  # noqa: PLC0415
        MockPolkitAuthorizer,
        PolkitAuthorizer,
    )

    auth_cfg = getattr(config, "auth", None)
    require_polkit: bool = getattr(auth_cfg, "require_polkit", False)

    if not require_polkit:
        logger.info(
            "Polkit disabled (require_polkit=false); signing allowed without prompts."
        )
        return MockPolkitAuthorizer(always_allow=True), False, None

    try:
        bus = MessageBus(bus_type=BusType.SYSTEM)
        await bus.connect()
        return PolkitAuthorizer(bus), True, None
    except Exception as e:
        logger.warning(
            "Failed to connect to system D-Bus for polkit; "
            "sign requests will be denied. Run 'bwssh status' for details.",
            exc_info=True,
        )
        return MockPolkitAuthorizer(always_allow=False), False, str(e)


async def create_sleep_watcher(
    control_server: ControlServer,
    shutdown_event: asyncio.Event,
) -> None:
    """Watch for system sleep events via logind and lock the agent."""
    try:
        from dbus_fast import BusType  # noqa: PLC0415
        from dbus_fast.aio import MessageBus  # noqa: PLC0415

        bus = MessageBus(bus_type=BusType.SYSTEM)
        await asyncio.wait_for(bus.connect(), timeout=5.0)

        introspection = await asyncio.wait_for(
            bus.introspect("org.freedesktop.login1", "/org/freedesktop/login1"),
            timeout=5.0,
        )
        proxy = bus.get_proxy_object(
            "org.freedesktop.login1", "/org/freedesktop/login1", introspection
        )
        manager = proxy.get_interface("org.freedesktop.login1.Manager")

        def on_prepare_for_sleep(going_to_sleep: bool) -> None:
            if going_to_sleep:
                logger.info("System going to sleep, locking agent")
                control_server.lock()

        manager.on_prepare_for_sleep(on_prepare_for_sleep)  # type: ignore[attr-defined]
        logger.info("Sleep watcher active: will lock on system sleep")

        await shutdown_event.wait()

    except TimeoutError:
        logger.info("Sleep watcher: D-Bus connection timed out (logind unavailable)")
    except Exception:
        logger.debug("Sleep watcher setup failed (non-critical)", exc_info=True)


def try_service_start() -> bool:
    """Try to start the daemon via systemd."""
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


def try_service_stop() -> bool:
    """Try to stop the daemon via systemd."""
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
