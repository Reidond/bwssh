"""Process attribution via platform-specific credential extraction.

Delegates to :mod:`bwssh.platform` for the OS-specific peer credential
and process metadata implementations. This module owns the data classes
and the high-level ``build_connection_context`` helper.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from bwssh.platform import (
    get_peer_credentials as _platform_get_peer_credentials,
)
from bwssh.platform import (
    get_process_metadata as _platform_get_process_metadata,
)

if TYPE_CHECKING:
    import socket

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PeerCredentials:
    """Credentials extracted from a Unix domain socket peer."""

    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class ProcessMetadata:
    """Process metadata obtained from the OS.

    All fields are None when the corresponding OS query fails
    (process exited, permission denied, etc.).
    """

    exe_path: str | None
    cmdline: list[str] | None
    start_time: int | None


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
    """Extract peer PID, UID, GID from a connected Unix domain socket.

    Delegates to the platform-specific implementation (SO_PEERCRED on
    Linux, LOCAL_PEERCRED/LOCAL_PEERPID on macOS).

    Raises
    ------
    OSError
        If the socket does not support peer credential extraction.
    """
    return _platform_get_peer_credentials(sock)


def get_process_metadata(pid: int) -> ProcessMetadata:
    """Read process metadata for *pid*, with graceful degradation.

    Delegates to the platform-specific implementation (/proc on Linux,
    libproc/sysctl on macOS).
    """
    return _platform_get_process_metadata(pid)


def build_connection_context(sock: socket.socket) -> ConnectionContext:
    """Build full connection context from a connected Unix socket.

    Combines peer credentials with process metadata.
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
