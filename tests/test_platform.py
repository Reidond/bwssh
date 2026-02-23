"""Tests for the platform abstraction layer."""

from __future__ import annotations

import os
import socket
import sys
from datetime import UTC
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from bwssh.peercred import (
    ConnectionContext,
    PeerCredentials,
    ProcessMetadata,
    build_connection_context,
    get_peer_credentials,
    get_process_metadata,
)

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


class TestPlatformImport:
    """Verify the platform layer loads the correct backend."""

    def test_imports_without_error(self) -> None:
        import bwssh.platform  # noqa: F401, PLC0415

    def test_exports_expected_names(self) -> None:
        import bwssh.platform  # noqa: PLC0415

        for name in (
            "get_peer_credentials",
            "get_process_metadata",
            "create_authorizer",
            "create_sleep_watcher",
            "get_runtime_dir",
            "get_config_dir",
            "try_service_start",
            "try_service_stop",
        ):
            assert hasattr(bwssh.platform, name), f"Missing export: {name}"


class TestGetRuntimeDir:
    def test_returns_path(self) -> None:
        from bwssh.platform import get_runtime_dir  # noqa: PLC0415

        result = get_runtime_dir()
        assert result is not None
        assert "bwssh" in str(result)


class TestGetConfigDir:
    def test_returns_path(self) -> None:
        from bwssh.platform import get_config_dir  # noqa: PLC0415

        result = get_config_dir()
        assert result is not None
        assert "bwssh" in str(result)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only test")
class TestLinuxBackend:
    """Tests that verify the Linux platform backend works correctly.

    These duplicate some test_peercred.py tests to ensure the platform
    delegation path works end-to-end.
    """

    def test_runtime_dir_uses_xdg(self) -> None:
        from bwssh.platform._linux import get_runtime_dir  # noqa: PLC0415

        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}):
            result = get_runtime_dir()
        assert str(result) == "/run/user/1000/bwssh"

    def test_runtime_dir_fallback(self) -> None:
        from bwssh.platform._linux import get_runtime_dir  # noqa: PLC0415

        with patch.dict(os.environ, {}, clear=True):
            result = get_runtime_dir()
        assert "bwssh" in str(result)
        assert "/tmp/" in str(result)

    def test_config_dir_uses_xdg(self) -> None:
        from bwssh.platform._linux import get_config_dir  # noqa: PLC0415

        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/home/user/.config"}):
            result = get_config_dir()
        assert str(result) == "/home/user/.config/bwssh"

    def test_peer_credentials_returns_current_process(self, tmp_path: Path) -> None:
        from bwssh.platform._linux import get_peer_credentials  # noqa: PLC0415

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

    def test_process_metadata_current_process(self) -> None:
        from bwssh.platform._linux import get_process_metadata  # noqa: PLC0415

        metadata = get_process_metadata(os.getpid())
        assert metadata.exe_path is not None
        assert metadata.cmdline is not None
        assert metadata.start_time is not None

    def test_process_metadata_invalid_pid(self) -> None:
        from bwssh.platform._linux import get_process_metadata  # noqa: PLC0415

        metadata = get_process_metadata(999_999_999)
        assert metadata.exe_path is None
        assert metadata.cmdline is None
        assert metadata.start_time is None


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
class TestDarwinBackend:
    """Tests that verify the macOS platform backend works correctly."""

    def test_runtime_dir_uses_tmpdir(self) -> None:
        from bwssh.platform._darwin import get_runtime_dir  # noqa: PLC0415

        with patch.dict(os.environ, {"TMPDIR": "/var/folders/xx/tmp"}):
            result = get_runtime_dir()
        assert str(result) == "/var/folders/xx/tmp/bwssh"

    def test_config_dir(self) -> None:
        from bwssh.platform._darwin import get_config_dir  # noqa: PLC0415

        result = get_config_dir()
        assert "bwssh" in str(result)

    def test_peer_credentials_returns_current_process(self, tmp_path: Path) -> None:
        from bwssh.platform._darwin import get_peer_credentials  # noqa: PLC0415

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
                finally:
                    conn.close()
            finally:
                client.close()
        finally:
            server.close()

    def test_process_metadata_current_process(self) -> None:
        from bwssh.platform._darwin import get_process_metadata  # noqa: PLC0415

        metadata = get_process_metadata(os.getpid())
        assert metadata.exe_path is not None

    def test_process_metadata_invalid_pid(self) -> None:
        from bwssh.platform._darwin import get_process_metadata  # noqa: PLC0415

        metadata = get_process_metadata(999_999_999)
        assert metadata.exe_path is None


class TestPeercredDelegation:
    """Ensure peercred.py correctly delegates to the platform layer."""

    @pytest.fixture
    def _unix_socket_pair(
        self, tmp_path: Path
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

    def test_get_peer_credentials_returns_peercredentials(
        self, _unix_socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        conn, _client = _unix_socket_pair
        creds = get_peer_credentials(conn)
        assert isinstance(creds, PeerCredentials)
        assert creds.pid == os.getpid()

    def test_get_process_metadata_returns_processmetadata(self) -> None:
        metadata = get_process_metadata(os.getpid())
        assert isinstance(metadata, ProcessMetadata)

    def test_build_connection_context_works(
        self, _unix_socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        conn, _client = _unix_socket_pair
        ctx = build_connection_context(conn)
        assert isinstance(ctx, ConnectionContext)
        assert ctx.peer_pid == os.getpid()
        assert ctx.is_forwarded is False
        assert ctx.first_seen_at.tzinfo == UTC


class TestCreateAuthorizer:
    @pytest.mark.asyncio
    async def test_create_authorizer_returns_tuple(self) -> None:
        from bwssh.config import BwsshConfig  # noqa: PLC0415
        from bwssh.platform import create_authorizer  # noqa: PLC0415

        config = BwsshConfig()
        authorizer, available, _error = await create_authorizer(config)
        assert authorizer is not None
        assert isinstance(available, bool)
