"""macOS (Darwin) platform implementations.

Provides LOCAL_PEERCRED / LOCAL_PEERPID credential extraction, libproc-based
process metadata, socket-permission-based authorization (no polkit), IOKit
sleep watching, launchd service management, and macOS directory conventions.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import shutil
import struct
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio
    import socket

    from bwssh.control import ControlServer
    from bwssh.peercred import PeerCredentials, ProcessMetadata
    from bwssh.polkit import Authorizer

logger = logging.getLogger(__name__)

# --- macOS socket options for peer credentials ---
# From <sys/un.h>:
#   LOCAL_PEERCRED  0x001  (returns struct xucred)
#   LOCAL_PEERPID   0x002  (returns pid_t)
_SOL_LOCAL = 0
_LOCAL_PEERCRED = 0x001
_LOCAL_PEERPID = 0x002

# struct xucred layout:
#   u_int   cr_version;  (uint32)
#   uid_t   cr_uid;      (uint32)
#   short   cr_ngroups;  (int16)
#   gid_t   cr_groups[16]; (16 x uint32)
_XUCRED_FORMAT = "IIh16I"
_XUCRED_SIZE = struct.calcsize(_XUCRED_FORMAT)

# --- libproc constants ---
_PROC_PIDPATHINFO_MAXSIZE = 4096
_PROC_PIDT_SHORTBSDINFO = 13
_PROC_BSDSHORTINFO_SIZE = 105

# --- Load libproc ---
_libproc = None
try:
    _libproc_path = ctypes.util.find_library("proc")
    if _libproc_path:
        _libproc = ctypes.CDLL(_libproc_path)
except OSError:
    logger.debug("Failed to load libproc", exc_info=True)

# --- Load libc for sysctl ---
_libc = None
try:
    _libc_path = ctypes.util.find_library("c")
    if _libc_path:
        _libc = ctypes.CDLL(_libc_path)
except OSError:
    logger.debug("Failed to load libc", exc_info=True)


def get_peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Extract peer PID, UID, GID via LOCAL_PEERCRED and LOCAL_PEERPID (macOS)."""
    from bwssh.peercred import PeerCredentials  # noqa: PLC0415

    cred_bytes = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, _XUCRED_SIZE)
    fields = struct.unpack(_XUCRED_FORMAT, cred_bytes)
    uid = fields[1]  # cr_uid
    gid = fields[3]  # cr_groups[0] (primary group)

    pid_bytes = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4)
    pid = struct.unpack("i", pid_bytes)[0]

    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def get_process_metadata(pid: int) -> ProcessMetadata:
    """Read process metadata via libproc and sysctl, with graceful degradation."""
    from bwssh.peercred import ProcessMetadata  # noqa: PLC0415

    exe_path = _read_exe(pid)
    cmdline = _read_cmdline(pid)
    start_time = _read_start_time(pid)
    return ProcessMetadata(exe_path=exe_path, cmdline=cmdline, start_time=start_time)


def _read_exe(pid: int) -> str | None:
    """Get executable path via proc_pidpath()."""
    if _libproc is None:
        return None
    try:
        buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
        ret = _libproc.proc_pidpath(pid, buf, _PROC_PIDPATHINFO_MAXSIZE)
        if ret > 0:
            return buf.value.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        pass
    return None


def _read_cmdline(pid: int) -> list[str] | None:  # noqa: PLR0911
    """Get command line arguments via sysctl KERN_PROCARGS2."""
    if _libc is None:
        return None
    try:
        ctl_kern = 1
        kern_procargs2 = 49

        mib = (ctypes.c_int * 3)(ctl_kern, kern_procargs2, pid)
        size = ctypes.c_size_t(0)
        ret = _libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0)
        if ret != 0 or size.value == 0:
            return None

        buf = ctypes.create_string_buffer(size.value)
        ret = _libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0)
        if ret != 0:
            return None

        data = buf.raw[: size.value]
        if len(data) < 4:
            return None

        argc = struct.unpack("I", data[:4])[0]
        rest = data[4:]

        null_pos = rest.find(b"\x00")
        if null_pos == -1:
            return None
        rest = rest[null_pos + 1 :]

        while rest and rest[0:1] == b"\x00":
            rest = rest[1:]

        args: list[str] = []
        for _ in range(argc):
            null_pos = rest.find(b"\x00")
            if null_pos == -1:
                break
            args.append(rest[:null_pos].decode("utf-8", errors="replace"))
            rest = rest[null_pos + 1 :]

        return args if args else None
    except (OSError, ValueError):
        return None


def _read_start_time(pid: int) -> int | None:  # noqa: PLR0911
    """Get process start time via sysctl KERN_PROC.

    Returns the start time as microseconds since epoch, which can be used
    as a unique process identifier (similar to Linux's clock-tick start time).
    """
    if _libc is None:
        return None
    try:
        ctl_kern = 1
        kern_proc = 14
        kern_proc_pid = 1

        mib = (ctypes.c_int * 4)(ctl_kern, kern_proc, kern_proc_pid, pid)
        size = ctypes.c_size_t(0)
        ret = _libc.sysctl(mib, 4, None, ctypes.byref(size), None, 0)
        if ret != 0 or size.value == 0:
            return None

        buf = ctypes.create_string_buffer(size.value)
        ret = _libc.sysctl(mib, 4, buf, ctypes.byref(size), None, 0)
        if ret != 0:
            return None

        # kp_proc.p_starttime is a timeval at offset 128 in kinfo_proc
        if size.value < 144:
            return None
        tv_sec, tv_usec = struct.unpack("qq", buf.raw[128:144])
        if tv_sec <= 0:
            return None
        return tv_sec * 1_000_000 + tv_usec
    except (OSError, ValueError, struct.error):
        return None


def get_runtime_dir() -> Path:
    """Return the runtime directory for bwssh on macOS."""
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        return Path(tmpdir) / "bwssh"
    return Path(f"/tmp/bwssh-{os.getuid()}")


def get_config_dir() -> Path:
    """Return the config directory for bwssh on macOS.

    Uses ~/.config/bwssh for XDG compatibility (same as Linux).
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "bwssh"


async def create_authorizer(
    config: object,
) -> tuple[Authorizer, bool, str | None]:
    """Create an authorizer for macOS.

    macOS has no polkit/D-Bus. Authorization is based on Unix socket
    permissions (only the user's processes can connect to the 0600 socket)
    and the interactive unlock prompt.
    """
    from bwssh.polkit import MockPolkitAuthorizer  # noqa: PLC0415

    auth_cfg = getattr(config, "auth", None)
    require_polkit: bool = getattr(auth_cfg, "require_polkit", False)

    if require_polkit:
        logger.warning(
            "require_polkit=true is not supported on macOS (no D-Bus). "
            "Falling back to socket-permission-based authorization."
        )

    logger.info("macOS: authorization via socket permissions (polkit not available)")
    return MockPolkitAuthorizer(always_allow=True), False, None


async def create_sleep_watcher(
    control_server: ControlServer,
    shutdown_event: asyncio.Event,
) -> None:
    """Watch for system sleep events on macOS and lock the agent.

    Uses NSWorkspace distributed notifications for sleep/wake events
    via pyobjc. Falls back to no-op if pyobjc is not installed.
    """
    try:
        from AppKit import NSWorkspace  # type: ignore[import-not-found]  # noqa: PLC0415, I001

        workspace = NSWorkspace.sharedWorkspace()
        center = workspace.notificationCenter()

        class SleepObserver:  # type: ignore[type-arg]
            def handleSleepNotification_(self, _notification: object) -> None:
                logger.info("System going to sleep, locking agent")
                control_server.lock()

        observer = SleepObserver()

        center.addObserver_selector_name_object_(
            observer,
            "handleSleepNotification:",
            "NSWorkspaceWillSleepNotification",
            None,
        )
        logger.info("Sleep watcher active: will lock on system sleep (macOS)")

        await shutdown_event.wait()

        center.removeObserver_(observer)

    except ImportError:
        logger.info(
            "Sleep watcher: pyobjc not available; sleep-lock disabled. "
            "Install pyobjc-framework-Cocoa to enable."
        )
    except Exception:
        logger.debug("Sleep watcher setup failed (non-critical)", exc_info=True)


def try_service_start() -> bool:
    """Try to start the daemon via launchctl."""
    plist_path = _launchd_plist_path()
    if not plist_path.exists():
        return False
    if shutil.which("launchctl") is None:
        return False
    try:
        subprocess.run(
            ["launchctl", "load", str(plist_path)],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def try_service_stop() -> bool:
    """Try to stop the daemon via launchctl."""
    plist_path = _launchd_plist_path()
    if not plist_path.exists():
        return False
    if shutil.which("launchctl") is None:
        return False
    try:
        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def _launchd_plist_path() -> Path:
    """Return path to the launchd plist for the agent."""
    return (
        Path.home() / "Library" / "LaunchAgents" / "io.github.reidond.bwssh-agent.plist"
    )
