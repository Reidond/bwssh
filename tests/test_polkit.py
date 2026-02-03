"""Tests for polkit authorization gate."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bwssh import constants
from bwssh.agent_proto import (
    pack_string,
    pack_uint32,
    read_message,
    unpack_string,
    unpack_uint32,
    write_message,
)
from bwssh.daemon import AgentServer
from bwssh.peercred import ConnectionContext
from bwssh.polkit import (
    ACTION_LIST,
    ACTION_SIGN,
    ACTION_UNLOCK,
    CachingAuthorizer,
    MockPolkitAuthorizer,
    PolkitAuthorizer,
    build_details,
)

if TYPE_CHECKING:
    from pathlib import Path


_SENTINEL_CMDLINE = object()


def _make_conn_ctx(
    pid: int = 1234,
    uid: int = 1000,
    start_time: int | None = 5678,
    exe_path: str | None = "/usr/bin/ssh",
    cmdline: list[str] | None | object = _SENTINEL_CMDLINE,
    is_forwarded: bool = False,
) -> ConnectionContext:
    resolved_cmdline: list[str] | None
    if cmdline is _SENTINEL_CMDLINE:
        resolved_cmdline = ["ssh", "git@github.com"]
    else:
        resolved_cmdline = cmdline  # type: ignore[assignment]
    return ConnectionContext(
        peer_pid=pid,
        peer_uid=uid,
        peer_gid=uid,
        peer_start_time=start_time,
        exe_path=exe_path,
        cmdline=resolved_cmdline,
        is_forwarded=is_forwarded,
        first_seen_at=datetime.now(UTC),
    )


class TestActionIDs:
    def test_canonical_action_ids(self) -> None:
        assert ACTION_SIGN == "io.github.reidond.bwssh.sign"
        assert ACTION_UNLOCK == "io.github.reidond.bwssh.unlock"
        assert ACTION_LIST == "io.github.reidond.bwssh.list"


class TestBuildDetails:
    def test_all_fields_populated(self) -> None:
        ctx = _make_conn_ctx(
            pid=42,
            exe_path="/usr/bin/git",
            cmdline=["git", "push", "origin", "main"],
            is_forwarded=False,
        )
        details = build_details("SHA256:abc123", "my-key", ctx)

        assert details["bwssh.key_fingerprint"] == "SHA256:abc123"
        assert details["bwssh.key_label"] == "my-key"
        assert details["bwssh.request.pid"] == "42"
        assert details["bwssh.request.exe"] == "/usr/bin/git"
        assert details["bwssh.request.cmdline"] == "git push origin main"
        assert details["bwssh.forwarded"] == "false"
        assert "SHA256:abc123" in details["polkit.message"]

    def test_missing_exe_path(self) -> None:
        ctx = _make_conn_ctx(exe_path=None)
        details = build_details("fp", "label", ctx)
        assert details["bwssh.request.exe"] == "unknown"

    def test_missing_cmdline(self) -> None:
        ctx = _make_conn_ctx(cmdline=None)
        details = build_details("fp", "label", ctx)
        assert details["bwssh.request.cmdline"] == ""

    def test_forwarded_flag(self) -> None:
        ctx = _make_conn_ctx(is_forwarded=True)
        details = build_details("fp", "label", ctx)
        assert details["bwssh.forwarded"] == "true"


class TestMockPolkitAuthorizer:
    @pytest.mark.asyncio
    async def test_always_allow(self) -> None:
        mock = MockPolkitAuthorizer(always_allow=True)
        ctx = _make_conn_ctx()
        result = await mock.check_authorization(ACTION_SIGN, ctx, {"k": "v"})
        assert result is True

    @pytest.mark.asyncio
    async def test_always_deny(self) -> None:
        mock = MockPolkitAuthorizer(always_allow=False)
        ctx = _make_conn_ctx()
        result = await mock.check_authorization(ACTION_SIGN, ctx, {"k": "v"})
        assert result is False

    @pytest.mark.asyncio
    async def test_records_calls(self) -> None:
        mock = MockPolkitAuthorizer()
        ctx = _make_conn_ctx(pid=99)
        details = {"bwssh.key_fingerprint": "SHA256:test"}
        await mock.check_authorization(ACTION_SIGN, ctx, details)
        await mock.check_authorization(ACTION_UNLOCK, ctx, {})

        assert len(mock.calls) == 2
        assert mock.calls[0][0] == ACTION_SIGN
        assert mock.calls[0][2] == details
        assert mock.calls[1][0] == ACTION_UNLOCK


class TestPolkitAuthorizer:
    @pytest.mark.asyncio
    async def test_authorized_returns_true(self) -> None:
        bus = MagicMock()
        authority = AsyncMock()
        authority.call_check_authorization = AsyncMock(return_value=(True, False, {}))
        interface = MagicMock()
        interface.get_interface.return_value = authority
        bus.introspect = AsyncMock(return_value=MagicMock())
        bus.get_proxy_object = MagicMock(return_value=interface)

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx()
        result = await authorizer.check_authorization(ACTION_SIGN, ctx, {})
        assert result is True

    @pytest.mark.asyncio
    async def test_denied_returns_false(self) -> None:
        bus = MagicMock()
        authority = AsyncMock()
        authority.call_check_authorization = AsyncMock(return_value=(False, False, {}))
        interface = MagicMock()
        interface.get_interface.return_value = authority
        bus.introspect = AsyncMock(return_value=MagicMock())
        bus.get_proxy_object = MagicMock(return_value=interface)

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx()
        result = await authorizer.check_authorization(ACTION_SIGN, ctx, {})
        assert result is False

    @pytest.mark.asyncio
    async def test_dbus_error_fails_closed(self) -> None:
        bus = MagicMock()
        bus.introspect = AsyncMock(side_effect=ConnectionError("no dbus"))

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx()
        result = await authorizer.check_authorization(ACTION_SIGN, ctx, {})
        assert result is False

    @pytest.mark.asyncio
    async def test_introspect_timeout_fails_closed(self) -> None:
        bus = MagicMock()
        bus.introspect = AsyncMock(side_effect=asyncio.TimeoutError)

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx()
        result = await authorizer.check_authorization(ACTION_SIGN, ctx, {})
        assert result is False

    @pytest.mark.asyncio
    async def test_none_start_time_uses_zero(self) -> None:
        bus = MagicMock()
        authority = AsyncMock()
        authority.call_check_authorization = AsyncMock(return_value=(True, False, {}))
        interface = MagicMock()
        interface.get_interface.return_value = authority
        bus.introspect = AsyncMock(return_value=MagicMock())
        bus.get_proxy_object = MagicMock(return_value=interface)

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx(start_time=None)
        result = await authorizer.check_authorization(ACTION_SIGN, ctx, {})
        assert result is True

        call_args = authority.call_check_authorization.call_args
        subject = call_args[0][0]
        assert subject[0] == "unix-process"
        assert subject[1]["start-time"].value == 0

    @pytest.mark.asyncio
    async def test_subject_contains_pid(self) -> None:
        bus = MagicMock()
        authority = AsyncMock()
        authority.call_check_authorization = AsyncMock(return_value=(True, False, {}))
        interface = MagicMock()
        interface.get_interface.return_value = authority
        bus.introspect = AsyncMock(return_value=MagicMock())
        bus.get_proxy_object = MagicMock(return_value=interface)

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx(pid=9999, start_time=12345)
        await authorizer.check_authorization(ACTION_SIGN, ctx, {})

        call_args = authority.call_check_authorization.call_args
        subject = call_args[0][0]
        assert subject[1]["pid"].value == 9999
        assert subject[1]["start-time"].value == 12345

    @pytest.mark.asyncio
    async def test_passes_allow_user_interaction_flag(self) -> None:
        bus = MagicMock()
        authority = AsyncMock()
        authority.call_check_authorization = AsyncMock(return_value=(True, False, {}))
        interface = MagicMock()
        interface.get_interface.return_value = authority
        bus.introspect = AsyncMock(return_value=MagicMock())
        bus.get_proxy_object = MagicMock(return_value=interface)

        authorizer = PolkitAuthorizer(bus)
        ctx = _make_conn_ctx()
        await authorizer.check_authorization(ACTION_SIGN, ctx, {})

        call_args = authority.call_check_authorization.call_args
        flags = call_args[0][3]
        assert flags == 1


async def _start_server(server: AgentServer) -> asyncio.Task[None]:
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.05)
    return task


async def _connect(
    socket_path: Path,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_unix_connection(str(socket_path))


async def _get_key_blob(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> bytes:
    await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
    msg_type, payload = await read_message(reader)
    assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
    nkeys, offset = unpack_uint32(payload, 0)
    assert nkeys >= 1
    key_blob, _offset = unpack_string(payload, offset)
    return key_blob


class CountingAuthorizer:
    """Test double that counts authorization calls."""

    def __init__(self, always_allow: bool = True) -> None:
        self._always_allow = always_allow
        self.call_count = 0
        self.calls: list[tuple[str, ConnectionContext, dict[str, str]]] = []

    async def check_authorization(
        self,
        action_id: str,
        connection_ctx: ConnectionContext,
        details: dict[str, str],
    ) -> bool:
        self.call_count += 1
        self.calls.append((action_id, connection_ctx, details))
        return self._always_allow


class TestDaemonPolkitIntegration:
    @pytest.mark.asyncio
    async def test_sign_allowed_by_polkit(
        self, tmp_path: Path, ed25519_key_path: Path
    ) -> None:
        mock_polkit = MockPolkitAuthorizer(always_allow=True)
        server = AgentServer(runtime_dir=tmp_path, polkit=mock_polkit)
        server.load_key(ed25519_key_path, "test-key", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(server.socket_path)
            key_blob = await _get_key_blob(reader, writer)

            request = pack_string(key_blob) + pack_string(b"sign me") + pack_uint32(0)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, _payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE

            assert len(mock_polkit.calls) == 1
            assert mock_polkit.calls[0][0] == ACTION_SIGN

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_sign_denied_by_polkit(
        self, tmp_path: Path, ed25519_key_path: Path
    ) -> None:
        mock_polkit = MockPolkitAuthorizer(always_allow=False)
        server = AgentServer(runtime_dir=tmp_path, polkit=mock_polkit)
        server.load_key(ed25519_key_path, "test-key", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(server.socket_path)
            key_blob = await _get_key_blob(reader, writer)

            request = pack_string(key_blob) + pack_string(b"sign me") + pack_uint32(0)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE
            assert payload == b""

            assert len(mock_polkit.calls) == 1

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_polkit_details_populated(
        self, tmp_path: Path, ed25519_key_path: Path
    ) -> None:
        mock_polkit = MockPolkitAuthorizer(always_allow=True)
        server = AgentServer(runtime_dir=tmp_path, polkit=mock_polkit)
        server.load_key(ed25519_key_path, "my-comment", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(server.socket_path)
            key_blob = await _get_key_blob(reader, writer)

            request = pack_string(key_blob) + pack_string(b"data") + pack_uint32(0)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, _ = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE

            assert len(mock_polkit.calls) == 1
            _action, _ctx, details = mock_polkit.calls[0]
            assert "bwssh.key_fingerprint" in details
            assert details["bwssh.key_label"] == "my-comment"
            assert "bwssh.request.pid" in details
            assert "polkit.message" in details

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_denied_sign_doesnt_produce_signature(
        self, tmp_path: Path, ed25519_key_path: Path
    ) -> None:
        mock_polkit = MockPolkitAuthorizer(always_allow=False)
        server = AgentServer(runtime_dir=tmp_path, polkit=mock_polkit)
        server.load_key(ed25519_key_path, "test-key", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(server.socket_path)
            key_blob = await _get_key_blob(reader, writer)

            request = (
                pack_string(key_blob) + pack_string(b"secret data") + pack_uint32(0)
            )
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, _payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE

            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, _ = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_list_identities_not_gated(
        self, tmp_path: Path, ed25519_key_path: Path
    ) -> None:
        mock_polkit = MockPolkitAuthorizer(always_allow=False)
        server = AgentServer(runtime_dir=tmp_path, polkit=mock_polkit)
        server.load_key(ed25519_key_path, "test-key", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(server.socket_path)
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER

            nkeys, _ = unpack_uint32(payload, 0)
            assert nkeys == 1
            assert len(mock_polkit.calls) == 0

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await asyncio.sleep(0.05)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


class TestCachingAuthorizer:
    @pytest.mark.asyncio
    async def test_always_mode_never_caches(self) -> None:
        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="always", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        result1 = await caching.check_authorization(ACTION_SIGN, ctx, details)
        result2 = await caching.check_authorization(ACTION_SIGN, ctx, details)
        result3 = await caching.check_authorization(ACTION_SIGN, ctx, details)

        assert result1 is True
        assert result2 is True
        assert result3 is True
        assert underlying.call_count == 3

    @pytest.mark.asyncio
    async def test_per_connection_mode_caches_by_connection_id(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="per_connection", ttl_seconds=300)

        ctx1 = _make_conn_ctx(pid=100)
        ctx2 = _make_conn_ctx(pid=200)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx1, details)
        await caching.check_authorization(ACTION_SIGN, ctx1, details)
        await caching.check_authorization(ACTION_SIGN, ctx1, details)

        assert underlying.call_count == 1

        await caching.check_authorization(ACTION_SIGN, ctx2, details)
        await caching.check_authorization(ACTION_SIGN, ctx2, details)

        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_per_connection_mode_different_keys_same_connection(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="per_connection", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100)
        details1 = {"bwssh.key_fingerprint": "SHA256:key1"}
        details2 = {"bwssh.key_fingerprint": "SHA256:key2"}

        await caching.check_authorization(ACTION_SIGN, ctx, details1)
        await caching.check_authorization(ACTION_SIGN, ctx, details2)

        assert underlying.call_count == 1

    @pytest.mark.asyncio
    async def test_ttl_mode_caches_by_fingerprint_and_exe(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=300)

        ctx1 = _make_conn_ctx(pid=100, exe_path="/usr/bin/ssh")
        ctx2 = _make_conn_ctx(pid=200, exe_path="/usr/bin/ssh")
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx1, details)
        await caching.check_authorization(ACTION_SIGN, ctx2, details)
        await caching.check_authorization(ACTION_SIGN, ctx1, details)

        assert underlying.call_count == 1

    @pytest.mark.asyncio
    async def test_ttl_mode_different_fingerprints(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100, exe_path="/usr/bin/ssh")
        details1 = {"bwssh.key_fingerprint": "SHA256:key1"}
        details2 = {"bwssh.key_fingerprint": "SHA256:key2"}

        await caching.check_authorization(ACTION_SIGN, ctx, details1)
        await caching.check_authorization(ACTION_SIGN, ctx, details2)

        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_ttl_mode_different_exe_paths(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=300)

        ctx1 = _make_conn_ctx(pid=100, exe_path="/usr/bin/ssh")
        ctx2 = _make_conn_ctx(pid=100, exe_path="/usr/bin/git")
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx1, details)
        await caching.check_authorization(ACTION_SIGN, ctx2, details)

        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_ttl_mode_expires_after_ttl(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=1)

        ctx = _make_conn_ctx(pid=100, exe_path="/usr/bin/ssh")
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0
            await caching.check_authorization(ACTION_SIGN, ctx, details)
            assert underlying.call_count == 1

            mock_time.return_value = 1000.5
            await caching.check_authorization(ACTION_SIGN, ctx, details)
            assert underlying.call_count == 1

            mock_time.return_value = 1001.1
            await caching.check_authorization(ACTION_SIGN, ctx, details)
            assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_forwarded_connection_always_bypasses_cache(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="per_connection", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100, is_forwarded=True)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        await caching.check_authorization(ACTION_SIGN, ctx, details)
        await caching.check_authorization(ACTION_SIGN, ctx, details)

        assert underlying.call_count == 3

    @pytest.mark.asyncio
    async def test_forwarded_bypasses_cache_in_ttl_mode(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100, exe_path="/usr/bin/ssh", is_forwarded=True)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        await caching.check_authorization(ACTION_SIGN, ctx, details)

        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_clear_cache_removes_all_entries(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="per_connection", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        assert underlying.call_count == 1

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        assert underlying.call_count == 1

        caching.clear_cache()

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_clear_cache_in_ttl_mode(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100, exe_path="/usr/bin/ssh")
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        assert underlying.call_count == 1

        caching.clear_cache()

        await caching.check_authorization(ACTION_SIGN, ctx, details)
        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_denied_authorization_not_cached(self) -> None:

        underlying = CountingAuthorizer(always_allow=False)
        caching = CachingAuthorizer(underlying, mode="per_connection", ttl_seconds=300)

        ctx = _make_conn_ctx(pid=100)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        result1 = await caching.check_authorization(ACTION_SIGN, ctx, details)
        result2 = await caching.check_authorization(ACTION_SIGN, ctx, details)

        assert result1 is False
        assert result2 is False
        assert underlying.call_count == 2

    @pytest.mark.asyncio
    async def test_ttl_mode_with_none_exe_path(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="ttl", ttl_seconds=300)

        ctx1 = _make_conn_ctx(pid=100, exe_path=None)
        ctx2 = _make_conn_ctx(pid=200, exe_path=None)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx1, details)
        await caching.check_authorization(ACTION_SIGN, ctx2, details)

        assert underlying.call_count == 1

    @pytest.mark.asyncio
    async def test_per_connection_uses_connection_id(self) -> None:

        underlying = CountingAuthorizer(always_allow=True)
        caching = CachingAuthorizer(underlying, mode="per_connection", ttl_seconds=300)

        ctx1 = _make_conn_ctx(pid=100)
        ctx2 = _make_conn_ctx(pid=100)
        details = {"bwssh.key_fingerprint": "SHA256:abc"}

        await caching.check_authorization(ACTION_SIGN, ctx1, details)
        await caching.check_authorization(ACTION_SIGN, ctx2, details)

        assert underlying.call_count == 2
