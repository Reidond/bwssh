"""Process attribution via SO_PEERCRED and /proc metadata."""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# SO_PEERCRED returns struct ucred: pid_t pid, uid_t uid, gid_t gid
# All three are 32-bit signed ints on Linux, but we unpack as unsigned
# since negative values are not meaningful here.
_UCRED_FORMAT = "III"  # 3 x uint32
_UCRED_SIZE = struct.calcsize(_UCRED_FORMAT)


@dataclass(frozen=True)
class PeerCredentials:
    """Credentials extracted from SO_PEERCRED on a Unix socket."""

    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class ProcessMetadata:
    """Process metadata read from /proc/<pid>/*.

    All fields are None when the corresponding /proc entry is unreadable
    (process exited, permission denied, etc.).
    """

    exe_path: str | None
    cmdline: list[str] | None
    start_time: int | None  # clock ticks since boot (field 22 of /proc/pid/stat)


@dataclass(frozen=True)
class ConnectionContext:
    """Full connection context combining peer credentials and process metadata.

    Used for polkit authorization (pid + start_time) and audit logging.
    """

    peer_pid: int
    peer_uid: int
    peer_gid: int
    peer_start_time: int | None
    exe_path: str | None
    cmdline: list[str] | None
    is_forwarded: bool
    first_seen_at: datetime


def get_peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Extract peer PID, UID, GID via SO_PEERCRED (Linux-specific).

    Raises
    ------
    OSError
        If the socket does not support SO_PEERCRED (e.g. not AF_UNIX).
    """
    cred_bytes = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
    pid, uid, gid = struct.unpack(_UCRED_FORMAT, cred_bytes)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def get_process_metadata(pid: int) -> ProcessMetadata:
    """Read process metadata from /proc/<pid>/*, with graceful degradation.

    Every individual read that fails returns None for that field — never raises.
    """
    exe_path = _read_exe(pid)
    cmdline = _read_cmdline(pid)
    start_time = _read_start_time(pid)
    return ProcessMetadata(exe_path=exe_path, cmdline=cmdline, start_time=start_time)


def build_connection_context(sock: socket.socket) -> ConnectionContext:
    """Build full connection context from a connected Unix socket.

    Combines SO_PEERCRED credentials with /proc metadata.
    """
    creds = get_peer_credentials(sock)
    metadata = get_process_metadata(creds.pid)

    ctx = ConnectionContext(
        peer_pid=creds.pid,
        peer_uid=creds.uid,
        peer_gid=creds.gid,
        peer_start_time=metadata.start_time,
        exe_path=metadata.exe_path,
        cmdline=metadata.cmdline,
        is_forwarded=False,
        first_seen_at=datetime.now(UTC),
    )

    logger.debug(
        "Connection from pid=%d uid=%d exe=%s",
        ctx.peer_pid,
        ctx.peer_uid,
        ctx.exe_path,
    )
    return ctx


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
