"""End-to-end integration tests for the full bwssh daemon lifecycle.

Exercises all components together: AgentServer + ControlServer + MockBitwardenProvider
+ MockPolkitAuthorizer + CachingAuthorizer, with real SSH agent protocol messages,
control socket JSON-lines, and cryptographic signature verification.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import ed25519

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

from bwssh.agent_proto import (
    pack_string,
    pack_uint32,
    read_message,
    unpack_string,
    unpack_uint32,
    write_message,
)
from bwssh.bitwarden import MockBitwardenProvider
from bwssh.config import BwsshConfig, DaemonConfig
from bwssh.constants import (
    SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST,
)
from bwssh.control import ControlClient, ControlServer
from bwssh.daemon import AgentServer, _main_async
from bwssh.keys import load_private_key
from bwssh.polkit import CachingAuthorizer, MockPolkitAuthorizer

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_DaemonTuple = tuple[
    AgentServer, ControlServer, Path, MockBitwardenProvider, MockPolkitAuthorizer
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _agent_request_identities(
    socket_path: Path,
) -> tuple[int, list[tuple[bytes, bytes]]]:
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    try:
        await write_message(writer, SSH_AGENTC_REQUEST_IDENTITIES, b"")
        msg_type, payload = await read_message(reader)
        assert msg_type == SSH_AGENT_IDENTITIES_ANSWER

        nkeys, offset = unpack_uint32(payload, 0)
        keys: list[tuple[bytes, bytes]] = []
        for _ in range(nkeys):
            blob, offset = unpack_string(payload, offset)
            comment, offset = unpack_string(payload, offset)
            keys.append((blob, comment))
        return nkeys, keys
    finally:
        writer.close()
        await writer.wait_closed()


async def _agent_sign_request(
    socket_path: Path, key_blob: bytes, data: bytes, flags: int = 0
) -> tuple[int, bytes]:
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    try:
        request = pack_string(key_blob) + pack_string(data) + pack_uint32(flags)
        await write_message(writer, SSH_AGENTC_SIGN_REQUEST, request)
        msg_type, payload = await read_message(reader)
        return msg_type, payload
    finally:
        writer.close()
        await writer.wait_closed()


async def _control_command(
    socket_path: Path, method: str, params: dict[str, object] | None = None
) -> dict[str, object]:
    client = ControlClient(socket_path)
    result: dict[str, object] = await client.send_command(method, params or {})
    return result


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def integration_daemon(
    tmp_path: Path,
) -> AsyncGenerator[_DaemonTuple]:
    runtime_dir = tmp_path / "bwssh-integration"
    config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

    bw_provider = MockBitwardenProvider()
    polkit_mock = MockPolkitAuthorizer(always_allow=True)
    caching_auth = CachingAuthorizer(polkit_mock, "always", 300)

    agent_server = AgentServer(
        runtime_dir=runtime_dir,
        polkit=caching_auth,
        config=config,
        bitwarden=bw_provider,
    )
    control_server = ControlServer(
        runtime_dir=runtime_dir,
        agent_server=agent_server,
        bitwarden=bw_provider,
        config=config,
    )

    task = asyncio.create_task(_main_async(agent_server, control_server))
    await asyncio.sleep(0.1)

    yield agent_server, control_server, runtime_dir, bw_provider, polkit_mock

    agent_server.shutdown()
    control_server.shutdown()
    await asyncio.wait_for(task, timeout=3.0)


# ---------------------------------------------------------------------------
# Full lifecycle integration test
# ---------------------------------------------------------------------------


class TestFullDaemonLifecycle:
    @pytest.mark.asyncio
    async def test_full_lifecycle(  # noqa: PLR0915
        self,
        integration_daemon: _DaemonTuple,
    ) -> None:
        _agent, _control, runtime_dir, _bw, polkit_mock = integration_daemon

        agent_sock = runtime_dir / "agent.sock"
        control_sock = runtime_dir / "control.sock"

        # ---------------------------------------------------------------
        # 1. Verify sockets exist after startup
        # ---------------------------------------------------------------
        assert agent_sock.exists(), "Agent socket not created"
        assert control_sock.exists(), "Control socket not created"

        # ---------------------------------------------------------------
        # 2. No keys loaded initially → REQUEST_IDENTITIES returns 0
        # ---------------------------------------------------------------
        nkeys, keys = await _agent_request_identities(agent_sock)
        assert nkeys == 0
        assert keys == []

        # ---------------------------------------------------------------
        # 3. Status via control socket: running, 0 keys, not locked
        # ---------------------------------------------------------------
        status = await _control_command(control_sock, "status")
        assert status["pid"] == os.getpid()
        assert status["key_count"] == 0
        assert status["locked"] is False
        assert isinstance(status["uptime"], float)
        assert status["uptime"] >= 0.0

        # ---------------------------------------------------------------
        # 4. Unlock with mock session key → keys loaded from mock BW
        # ---------------------------------------------------------------
        unlock_result = await _control_command(
            control_sock, "unlock", {"session_key": "mock-session-key"}
        )
        assert unlock_result["unlocked"] is True
        assert unlock_result["key_count"] == 1

        # ---------------------------------------------------------------
        # 5. REQUEST_IDENTITIES now returns 1 key
        # ---------------------------------------------------------------
        nkeys, keys = await _agent_request_identities(agent_sock)
        assert nkeys == 1
        key_blob, comment = keys[0]
        assert comment == b"Mock ED25519 Key"

        # ---------------------------------------------------------------
        # 6. SIGN_REQUEST → valid signature
        # ---------------------------------------------------------------
        data_to_sign = b"integration test data"
        msg_type, payload = await _agent_sign_request(
            agent_sock, key_blob, data_to_sign
        )
        assert msg_type == SSH_AGENT_SIGN_RESPONSE

        # Parse and verify signature
        sig_blob, _ = unpack_string(payload, 0)
        algo, offset = unpack_string(sig_blob, 0)
        sig_bytes, _ = unpack_string(sig_blob, offset)
        assert algo == b"ssh-ed25519"

        # Verify using cryptography
        private_key = load_private_key((FIXTURES_DIR / "id_ed25519").read_bytes())
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        private_key.public_key().verify(sig_bytes, data_to_sign)

        # ---------------------------------------------------------------
        # 7. Status: 1 key loaded, not locked
        # ---------------------------------------------------------------
        status2 = await _control_command(control_sock, "status")
        assert status2["key_count"] == 1
        assert status2["locked"] is False

        # ---------------------------------------------------------------
        # 8. list_keys: verify key details
        # ---------------------------------------------------------------
        list_result = await _control_command(control_sock, "list_keys")
        assert isinstance(list_result, dict)
        key_list = list_result["keys"]
        assert isinstance(key_list, list)
        assert len(key_list) == 1
        assert key_list[0]["algorithm"] == "ssh-ed25519"
        assert key_list[0]["comment"] == "Mock ED25519 Key"
        assert key_list[0]["fingerprint"].startswith("SHA256:")

        # ---------------------------------------------------------------
        # 9. Lock → keys cleared
        # ---------------------------------------------------------------
        lock_result = await _control_command(control_sock, "lock")
        assert lock_result["locked"] is True

        # ---------------------------------------------------------------
        # 10. Status: 0 keys, locked
        # ---------------------------------------------------------------
        status3 = await _control_command(control_sock, "status")
        assert status3["key_count"] == 0
        assert status3["locked"] is True

        # ---------------------------------------------------------------
        # 11. SIGN_REQUEST → FAILURE (no keys)
        # ---------------------------------------------------------------
        msg_type_fail, _payload_fail = await _agent_sign_request(
            agent_sock, key_blob, b"should fail"
        )
        assert msg_type_fail == SSH_AGENT_FAILURE

        # ---------------------------------------------------------------
        # 12. REQUEST_IDENTITIES → 0 keys
        # ---------------------------------------------------------------
        nkeys_locked, _keys_locked = await _agent_request_identities(agent_sock)
        assert nkeys_locked == 0

        # ---------------------------------------------------------------
        # 13. Unlock again → keys reloaded
        # ---------------------------------------------------------------
        unlock2 = await _control_command(
            control_sock, "unlock", {"session_key": "mock-session-key-2"}
        )
        assert unlock2["unlocked"] is True
        assert unlock2["key_count"] == 1

        # ---------------------------------------------------------------
        # 14. REQUEST_IDENTITIES → 1 key again
        # ---------------------------------------------------------------
        nkeys_again, keys_again = await _agent_request_identities(agent_sock)
        assert nkeys_again == 1
        key_blob2, comment2 = keys_again[0]
        assert comment2 == b"Mock ED25519 Key"

        # ---------------------------------------------------------------
        # 15. SIGN_REQUEST → valid signature again
        # ---------------------------------------------------------------
        data2 = b"post-unlock signing test"
        msg_type2, payload2 = await _agent_sign_request(agent_sock, key_blob2, data2)
        assert msg_type2 == SSH_AGENT_SIGN_RESPONSE

        sig_blob2, _ = unpack_string(payload2, 0)
        algo2, offset2 = unpack_string(sig_blob2, 0)
        sig_bytes2, _ = unpack_string(sig_blob2, offset2)
        assert algo2 == b"ssh-ed25519"
        private_key.public_key().verify(sig_bytes2, data2)

        # ---------------------------------------------------------------
        # 16. Polkit was consulted for sign requests
        # ---------------------------------------------------------------
        # With "always" caching mode, every sign should go through polkit
        assert len(polkit_mock.calls) >= 2
        for action_id, _ctx, _details in polkit_mock.calls:
            assert action_id == "io.github.reidond.bwssh.sign"


class TestPolkitDenial:
    """Verify that polkit denial blocks signing."""

    @pytest.mark.asyncio
    async def test_sign_denied_by_polkit(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "polkit-deny"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

        bw = MockBitwardenProvider()
        polkit_deny = MockPolkitAuthorizer(always_allow=False)
        caching_auth = CachingAuthorizer(polkit_deny, "always", 300)

        agent = AgentServer(
            runtime_dir=runtime_dir,
            polkit=caching_auth,
            config=config,
            bitwarden=bw,
        )
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )

        task = asyncio.create_task(_main_async(agent, control))
        await asyncio.sleep(0.1)

        try:
            agent_sock = runtime_dir / "agent.sock"
            control_sock = runtime_dir / "control.sock"

            # Unlock to load keys
            unlock = await _control_command(
                control_sock, "unlock", {"session_key": "test"}
            )
            assert unlock["unlocked"] is True

            # Get key blob
            nkeys, keys = await _agent_request_identities(agent_sock)
            assert nkeys == 1
            key_blob = keys[0][0]

            # Sign → FAILURE because polkit denies
            msg_type, _payload = await _agent_sign_request(
                agent_sock, key_blob, b"should be denied"
            )
            assert msg_type == SSH_AGENT_FAILURE

            # Polkit was consulted
            assert len(polkit_deny.calls) >= 1
        finally:
            agent.shutdown()
            control.shutdown()
            await asyncio.wait_for(task, timeout=3.0)


class TestSyncCommand:
    """Test the sync control command reloads keys."""

    @pytest.mark.asyncio
    async def test_sync_reloads_keys(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "sync-test"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

        bw = MockBitwardenProvider()
        polkit = MockPolkitAuthorizer(always_allow=True)
        caching_auth = CachingAuthorizer(polkit, "always", 300)

        agent = AgentServer(
            runtime_dir=runtime_dir,
            polkit=caching_auth,
            config=config,
            bitwarden=bw,
        )
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )

        task = asyncio.create_task(_main_async(agent, control))
        await asyncio.sleep(0.1)

        try:
            control_sock = runtime_dir / "control.sock"
            agent_sock = runtime_dir / "agent.sock"

            # Unlock first
            await _control_command(
                control_sock, "unlock", {"session_key": "sync-session"}
            )

            # Verify key loaded
            nkeys, _ = await _agent_request_identities(agent_sock)
            assert nkeys == 1

            # Sync (re-fetches from mock BW, clears + reloads)
            sync_result = await _control_command(
                control_sock, "sync", {"session_key": "sync-session"}
            )
            assert sync_result["synced"] is True
            assert sync_result["key_count"] == 1

            # Keys still available after sync
            nkeys2, _ = await _agent_request_identities(agent_sock)
            assert nkeys2 == 1
        finally:
            agent.shutdown()
            control.shutdown()
            await asyncio.wait_for(task, timeout=3.0)


class TestReloadConfig:
    """Test reload_config control command."""

    @pytest.mark.asyncio
    async def test_reload_config(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "reload-cfg"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

        agent = AgentServer(runtime_dir=runtime_dir, config=config)
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            config=config,
        )

        task = asyncio.create_task(_main_async(agent, control))
        await asyncio.sleep(0.1)

        try:
            control_sock = runtime_dir / "control.sock"
            result = await _control_command(control_sock, "reload_config")
            assert result["reloaded"] is True
        finally:
            agent.shutdown()
            control.shutdown()
            await asyncio.wait_for(task, timeout=3.0)


class TestShutdownCleanup:
    """Verify daemon cleans up sockets on shutdown."""

    @pytest.mark.asyncio
    async def test_sockets_removed_on_shutdown(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "shutdown-cleanup"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

        agent = AgentServer(runtime_dir=runtime_dir, config=config)
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            config=config,
        )

        task = asyncio.create_task(_main_async(agent, control))
        await asyncio.sleep(0.1)

        agent_sock = runtime_dir / "agent.sock"
        control_sock = runtime_dir / "control.sock"

        # Both sockets exist
        assert agent_sock.exists()
        assert control_sock.exists()

        # Shutdown
        agent.shutdown()
        control.shutdown()
        await asyncio.wait_for(task, timeout=3.0)

        # Both sockets removed
        assert not agent_sock.exists()
        assert not control_sock.exists()

    @pytest.mark.asyncio
    async def test_keys_cleared_on_shutdown(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "shutdown-keys"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))
        bw = MockBitwardenProvider()

        agent = AgentServer(runtime_dir=runtime_dir, config=config, bitwarden=bw)
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )

        task = asyncio.create_task(_main_async(agent, control))
        await asyncio.sleep(0.1)

        control_sock = runtime_dir / "control.sock"

        # Load keys
        await _control_command(control_sock, "unlock", {"session_key": "test"})
        assert len(agent.registry.list_identities()) == 1

        # Shutdown → registry cleared
        agent.shutdown()
        control.shutdown()
        await asyncio.wait_for(task, timeout=3.0)

        assert len(agent.registry.list_identities()) == 0


class TestConcurrentAgentClients:
    """Verify multiple agent clients can operate concurrently."""

    @pytest.mark.asyncio
    async def test_concurrent_sign_requests(
        self,
        integration_daemon: _DaemonTuple,
    ) -> None:
        _agent, _control, runtime_dir, _bw, _polkit = integration_daemon
        agent_sock = runtime_dir / "agent.sock"
        control_sock = runtime_dir / "control.sock"

        await _control_command(
            control_sock, "unlock", {"session_key": "concurrent-test"}
        )

        nkeys, keys = await _agent_request_identities(agent_sock)
        assert nkeys == 1
        key_blob = keys[0][0]

        # Fire 10 concurrent sign requests
        async def _sign_one(i: int) -> int:
            msg_type, _payload = await _agent_sign_request(
                agent_sock, key_blob, f"concurrent data {i}".encode()
            )
            return msg_type

        results = await asyncio.gather(*[_sign_one(i) for i in range(10)])
        assert all(r == SSH_AGENT_SIGN_RESPONSE for r in results)


class TestErrorRecovery:
    """Test that the daemon recovers from protocol errors."""

    @pytest.mark.asyncio
    async def test_malformed_sign_request_no_crash(
        self,
        integration_daemon: _DaemonTuple,
    ) -> None:
        _agent, _control, runtime_dir, _bw, _polkit = integration_daemon
        agent_sock = runtime_dir / "agent.sock"

        # Send malformed sign request
        reader, writer = await asyncio.open_unix_connection(str(agent_sock))
        try:
            await write_message(writer, SSH_AGENTC_SIGN_REQUEST, b"\x00\x00\x00")
            msg_type, _ = await read_message(reader)
            assert msg_type == SSH_AGENT_FAILURE
        finally:
            writer.close()
            await writer.wait_closed()

        # Server is still alive — can handle new requests
        nkeys, _ = await _agent_request_identities(agent_sock)
        assert nkeys == 0  # No keys loaded yet

    @pytest.mark.asyncio
    async def test_malformed_control_request_no_crash(
        self,
        integration_daemon: _DaemonTuple,
    ) -> None:
        _agent, _control, runtime_dir, _bw, _polkit = integration_daemon
        control_sock = runtime_dir / "control.sock"

        # Send malformed JSON
        reader, writer = await asyncio.open_unix_connection(str(control_sock))
        try:
            writer.write(b"not json at all\n")
            await writer.drain()
            resp_line = await reader.readline()
            resp: dict[str, object] = json.loads(resp_line.decode())
            assert "error" in resp
        finally:
            writer.close()
            await writer.wait_closed()

        # Server still alive
        status = await _control_command(control_sock, "status")
        assert status["pid"] == os.getpid()


class TestBitwardenError:
    """Test behavior when Bitwarden provider returns an error."""

    @pytest.mark.asyncio
    async def test_unlock_with_bw_error(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "bw-error"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

        bw = MockBitwardenProvider(error=RuntimeError("bw CLI failed"))

        agent = AgentServer(runtime_dir=runtime_dir, config=config, bitwarden=bw)
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )

        task = asyncio.create_task(_main_async(agent, control))
        await asyncio.sleep(0.1)

        try:
            control_sock = runtime_dir / "control.sock"

            # Unlock should propagate error through control protocol
            reader, writer = await asyncio.open_unix_connection(str(control_sock))
            try:
                req = (
                    json.dumps(
                        {
                            "method": "unlock",
                            "id": 1,
                            "params": {"session_key": "will-fail"},
                        }
                    ).encode()
                    + b"\n"
                )
                writer.write(req)
                await writer.drain()
                resp_line = await reader.readline()
                resp: dict[str, object] = json.loads(resp_line.decode())
                assert "error" in resp
            finally:
                writer.close()
                await writer.wait_closed()

            # Server still alive after error
            status = await _control_command(control_sock, "status")
            assert status["pid"] == os.getpid()
        finally:
            agent.shutdown()
            control.shutdown()
            await asyncio.wait_for(task, timeout=3.0)
