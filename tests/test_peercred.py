"""Tests for SO_PEERCRED and /proc metadata collection."""

from __future__ import annotations

import os
import socket
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

import pytest

from bwssh.peercred import (
    ConnectionContext,
    PeerCredentials,
    ProcessMetadata,
    build_connection_context,
    get_peer_credentials,
    get_process_metadata,
)


class TestGetPeerCredentials:
    def test_returns_current_process_credentials(self, tmp_path: object) -> None:
        sock_path = str(tmp_path) + "/test.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(sock_path)
            server.listen(1)

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(sock_path)
                conn, _ = server.accept()
                try:
                    creds = get_peer_credentials(conn)
                    assert creds.pid == os.getpid()
                    assert creds.uid == os.getuid()
                    assert creds.gid == os.getgid()
                finally:
                    conn.close()
            finally:
                client.close()
        finally:
            server.close()

    def test_returns_peercredentials_dataclass(self, tmp_path: object) -> None:
        sock_path = str(tmp_path) + "/test.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(sock_path)
            server.listen(1)

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(sock_path)
                conn, _ = server.accept()
                try:
                    creds = get_peer_credentials(conn)
                    assert isinstance(creds, PeerCredentials)
                    assert isinstance(creds.pid, int)
                    assert isinstance(creds.uid, int)
                    assert isinstance(creds.gid, int)
                finally:
                    conn.close()
            finally:
                client.close()
        finally:
            server.close()

    def test_credentials_are_frozen(self, tmp_path: object) -> None:
        sock_path = str(tmp_path) + "/test.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(sock_path)
            server.listen(1)

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(sock_path)
                conn, _ = server.accept()
                try:
                    creds = get_peer_credentials(conn)
                    with pytest.raises(AttributeError):
                        creds.pid = 0  # type: ignore[misc]
                finally:
                    conn.close()
            finally:
                client.close()
        finally:
            server.close()


@pytest.fixture
def _unix_socket_pair(
    tmp_path: object,
) -> Generator[tuple[socket.socket, socket.socket], None, None]:
    sock_path = str(tmp_path) + "/test.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(sock_path)
    conn, _ = server.accept()

    server.close()
    yield conn, client
    conn.close()
    client.close()


class TestGetProcessMetadata:
    def test_current_process_exe(self) -> None:
        metadata = get_process_metadata(os.getpid())
        assert metadata.exe_path is not None
        assert (
            "python" in metadata.exe_path.lower()
            or "pytest" in metadata.exe_path.lower()
        )

    def test_current_process_cmdline(self) -> None:
        metadata = get_process_metadata(os.getpid())
        assert metadata.cmdline is not None
        assert len(metadata.cmdline) > 0

    def test_current_process_start_time(self) -> None:
        metadata = get_process_metadata(os.getpid())
        assert metadata.start_time is not None
        assert metadata.start_time > 0

    def test_returns_processmetadata_dataclass(self) -> None:
        metadata = get_process_metadata(os.getpid())
        assert isinstance(metadata, ProcessMetadata)

    def test_invalid_pid_returns_none_fields(self) -> None:
        metadata = get_process_metadata(999_999_999)
        assert metadata.exe_path is None
        assert metadata.cmdline is None
        assert metadata.start_time is None

    def test_negative_pid_returns_none_fields(self) -> None:
        metadata = get_process_metadata(-1)
        assert metadata.exe_path is None
        assert metadata.cmdline is None
        assert metadata.start_time is None

    def test_zero_pid_returns_none_fields(self) -> None:
        metadata = get_process_metadata(0)
        assert metadata.exe_path is None

    def test_exe_path_is_absolute(self) -> None:
        metadata = get_process_metadata(os.getpid())
        if metadata.exe_path is not None:
            assert metadata.exe_path.startswith("/")

    def test_cmdline_matches_sys_executable(self) -> None:
        metadata = get_process_metadata(os.getpid())
        assert metadata.cmdline is not None
        assert any(
            "python" in arg.lower() or "pytest" in arg.lower()
            for arg in metadata.cmdline
        )


class TestBuildConnectionContext:
    def test_populates_all_fields(
        self, _unix_socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        conn, _client = _unix_socket_pair
        ctx = build_connection_context(conn)

        assert isinstance(ctx, ConnectionContext)
        assert ctx.peer_pid == os.getpid()
        assert ctx.peer_uid == os.getuid()
        assert ctx.peer_gid == os.getgid()
        assert ctx.peer_start_time is not None
        assert ctx.exe_path is not None
        assert ctx.cmdline is not None
        assert ctx.is_forwarded is False
        assert ctx.first_seen_at.tzinfo == UTC

    def test_first_seen_at_is_recent(
        self, _unix_socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        conn, _client = _unix_socket_pair
        before = datetime.now(UTC)
        ctx = build_connection_context(conn)
        after = datetime.now(UTC)

        assert before <= ctx.first_seen_at <= after

    def test_frozen_dataclass(
        self, _unix_socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        conn, _client = _unix_socket_pair
        ctx = build_connection_context(conn)

        with pytest.raises(AttributeError):
            ctx.peer_pid = 0  # type: ignore[misc]


class TestConnectionContextDataclass:
    def test_immutable(self) -> None:
        ctx = ConnectionContext(
            peer_pid=1,
            peer_uid=1000,
            peer_gid=1000,
            peer_start_time=12345,
            exe_path="/usr/bin/ssh",
            cmdline=["ssh", "user@host"],
            is_forwarded=False,
            first_seen_at=datetime.now(UTC),
        )
        with pytest.raises(AttributeError):
            ctx.peer_pid = 2  # type: ignore[misc]

    def test_none_metadata_fields(self) -> None:
        ctx = ConnectionContext(
            peer_pid=1,
            peer_uid=0,
            peer_gid=0,
            peer_start_time=None,
            exe_path=None,
            cmdline=None,
            is_forwarded=False,
            first_seen_at=datetime.now(UTC),
        )
        assert ctx.peer_start_time is None
        assert ctx.exe_path is None
        assert ctx.cmdline is None
