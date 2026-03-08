"""Tests for bwssh control socket with JSON-lines protocol."""

from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING

import pytest

from bwssh.agent_proto import read_message, write_message
from bwssh.bitwarden import MockBitwardenProvider
from bwssh.config import BwsshConfig, DaemonConfig
from bwssh.constants import (
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENTC_REQUEST_IDENTITIES,
)
from bwssh.control import ControlClient, ControlError, ControlServer
from bwssh.daemon import AgentServer
from bwssh.keys import (
    Identity,
    KeyRegistry,
    compute_fingerprint,
    get_key_type_string,
    get_public_key_blob,
    load_private_key,
)
from bwssh.windows_bridge import BridgeIdentity

if TYPE_CHECKING:
    from pathlib import Path


def _make_registry(key_path: Path, comment: str) -> KeyRegistry:
    registry = KeyRegistry()
    key_data = key_path.read_bytes()
    private_key = load_private_key(key_data)
    blob = get_public_key_blob(private_key)
    identity = Identity(
        identity_id=compute_fingerprint(blob),
        comment=comment,
        public_key_blob=blob,
        fingerprint=compute_fingerprint(blob),
        algorithm=get_key_type_string(private_key),
        source="test",
    )
    registry.add_key(identity, private_key)
    return registry


@pytest.fixture
def runtime_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def control_socket_path(runtime_dir: Path) -> Path:
    return runtime_dir / "control.sock"


@pytest.fixture
def registry() -> KeyRegistry:
    return KeyRegistry()


@pytest.fixture
def config(runtime_dir: Path) -> BwsshConfig:
    return BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))


@pytest.fixture
def control_server(
    runtime_dir: Path, registry: KeyRegistry, config: BwsshConfig
) -> ControlServer:
    return ControlServer(
        runtime_dir=runtime_dir,
        registry=registry,
        config=config,
    )


async def _start_control(server: ControlServer) -> asyncio.Task[None]:
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.05)
    return task


async def _send_raw(socket_path: Path, request: dict[str, object]) -> dict[str, object]:
    """Send raw JSON-lines request and get response."""
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    line = json.dumps(request).encode() + b"\n"
    writer.write(line)
    await writer.drain()
    response_line = await reader.readline()
    writer.close()
    await writer.wait_closed()
    result: dict[str, object] = json.loads(response_line.decode())
    return result


class TestControlServerLifecycle:
    @pytest.mark.asyncio
    async def test_creates_socket(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            assert control_socket_path.exists()
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_socket_permissions(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            mode = control_socket_path.stat().st_mode & 0o777
            assert mode == 0o600
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_removes_socket_on_shutdown(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        control_server.shutdown()
        await task
        assert not control_socket_path.exists()

    @pytest.mark.asyncio
    async def test_cleans_stale_socket(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        registry: KeyRegistry,
        config: BwsshConfig,
    ) -> None:
        control_socket_path.touch()
        server = ControlServer(
            runtime_dir=runtime_dir,
            registry=registry,
            config=config,
        )
        task = await _start_control(server)
        try:
            assert control_socket_path.exists()
        finally:
            server.shutdown()
            await task


class TestStatusMethod:
    @pytest.mark.asyncio
    async def test_status_returns_pid(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "status", "id": 1, "params": {}},
            )
            assert resp["id"] == 1
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["pid"] == os.getpid()
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_status_returns_uptime(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "status", "id": 2, "params": {}},
            )
            result = resp["result"]
            assert isinstance(result, dict)
            assert isinstance(result["uptime"], float)
            assert result["uptime"] >= 0.0
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_status_returns_key_count(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "status", "id": 3, "params": {}},
            )
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["key_count"] == 0
            # Server starts locked by default
            assert result["locked"] is True
        finally:
            control_server.shutdown()
            await task


class TestListKeysMethod:
    @pytest.mark.asyncio
    async def test_list_keys_empty(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "list_keys", "id": 1, "params": {}},
            )
            assert resp["id"] == 1
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["keys"] == []
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_list_keys_with_keys(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
        ed25519_key_path: Path,
    ) -> None:
        registry = _make_registry(ed25519_key_path, "test-key")

        server = ControlServer(
            runtime_dir=runtime_dir,
            registry=registry,
            config=config,
        )
        task = await _start_control(server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "list_keys", "id": 2, "params": {}},
            )
            result = resp["result"]
            assert isinstance(result, dict)
            keys = result["keys"]
            assert len(keys) == 1
            assert keys[0]["comment"] == "test-key"
            assert keys[0]["algorithm"] == "ssh-ed25519"
            assert keys[0]["fingerprint"].startswith("SHA256:")
        finally:
            server.shutdown()
            await task


class TestLockMethod:
    @pytest.mark.asyncio
    async def test_lock_clears_keys(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
        ed25519_key_path: Path,
    ) -> None:
        registry = _make_registry(ed25519_key_path, "test-key")

        server = ControlServer(
            runtime_dir=runtime_dir,
            registry=registry,
            config=config,
        )
        task = await _start_control(server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "lock", "id": 1, "params": {}},
            )
            assert resp["id"] == 1
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["locked"] is True

            resp2 = await _send_raw(
                control_socket_path,
                {"method": "list_keys", "id": 2, "params": {}},
            )
            result2 = resp2["result"]
            assert isinstance(result2, dict)
            assert result2["keys"] == []
        finally:
            server.shutdown()
            await task


class TestPublicLockMethod:
    """Tests for ControlServer.lock() — the synchronous public method."""

    @pytest.mark.asyncio
    async def test_lock_sets_locked_flag(
        self,
        runtime_dir: Path,
        config: BwsshConfig,
    ) -> None:
        """Calling lock() must flip _locked to True."""
        bw = MockBitwardenProvider()
        agent = AgentServer(runtime_dir=runtime_dir, bitwarden=bw)
        server = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )
        # Simulate an unlocked state
        server._locked = False
        server.lock()
        assert server.is_locked is True

    @pytest.mark.asyncio
    async def test_lock_clears_registry_and_bitwarden(
        self,
        runtime_dir: Path,
        config: BwsshConfig,
        ed25519_key_path: Path,
    ) -> None:
        """lock() must clear keys and bitwarden session."""
        bw = MockBitwardenProvider()
        bw.unlock("test-session")
        agent = AgentServer(runtime_dir=runtime_dir, bitwarden=bw)
        agent.load_key(ed25519_key_path, "test-key", "test")
        assert len(agent.registry.list_identities()) == 1
        assert bw.is_unlocked

        server = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )
        server._locked = False
        server.lock()

        assert server.is_locked is True
        assert len(agent.registry.list_identities()) == 0
        assert not bw.is_unlocked

    @pytest.mark.asyncio
    async def test_lock_status_reflects_locked_after_direct_call(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
    ) -> None:
        """Status must report locked after ControlServer.lock() is called directly.

        This is the regression scenario: sleep watcher (or external code)
        calls lock() directly and status must stay in sync.
        """
        bw = MockBitwardenProvider()
        agent = AgentServer(runtime_dir=runtime_dir, bitwarden=bw)
        server = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )
        task = await _start_control(server)
        try:
            # Unlock first
            resp = await _send_raw(
                control_socket_path,
                {"method": "unlock", "id": 1, "params": {"session_key": "s"}},
            )
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["unlocked"] is True

            # Verify status shows unlocked
            resp2 = await _send_raw(
                control_socket_path,
                {"method": "status", "id": 2, "params": {}},
            )
            result2 = resp2["result"]
            assert isinstance(result2, dict)
            assert result2["locked"] is False

            # Simulate sleep watcher calling lock() directly
            server.lock()

            # Status must now show locked
            resp3 = await _send_raw(
                control_socket_path,
                {"method": "status", "id": 3, "params": {}},
            )
            result3 = resp3["result"]
            assert isinstance(result3, dict)
            assert result3["locked"] is True
            assert result3["key_count"] == 0
        finally:
            server.shutdown()
            await task


class TestUnlockMethod:
    @pytest.mark.asyncio
    async def test_unlock_stub(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "unlock", "id": 1, "params": {"session_key": "test"}},
            )
            assert resp["id"] == 1
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["unlocked"] is True
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_unlock_applies_runtime_bw_overrides(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
    ) -> None:
        class _BitwardenWithRuntimeOverrides(MockBitwardenProvider):
            def __init__(self) -> None:
                super().__init__()
                self.runtime_config: dict[str, str | None] = {
                    "bw_path": None,
                    "env_path": None,
                }

            def configure_runtime(
                self, *, bw_path: str | None = None, env_path: str | None = None
            ) -> None:
                self.runtime_config["bw_path"] = bw_path
                self.runtime_config["env_path"] = env_path

            async def list_identities(self, _session_key: str) -> list[Identity]:
                return []

            async def get_private_key(
                self, _identity_id: str, _session_key: str
            ) -> bytes:
                msg = "unexpected get_private_key call"
                raise AssertionError(msg)

        bw = _BitwardenWithRuntimeOverrides()
        agent = AgentServer(runtime_dir=runtime_dir, bitwarden=bw)
        server = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )

        task = await _start_control(server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {
                    "method": "unlock",
                    "id": 1,
                    "params": {
                        "session_key": "test",
                        "bw_exec_path": "/opt/bin/bw",
                        "env_path": "/opt/bin:/usr/bin",
                    },
                },
            )
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["unlocked"] is True
            assert bw.runtime_config == {
                "bw_path": "/opt/bin/bw",
                "env_path": "/opt/bin:/usr/bin",
            }
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_unlock_windows_bridge_mode(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
    ) -> None:
        class _Bridge:
            async def list_identities(self) -> list[BridgeIdentity]:
                return [
                    BridgeIdentity(
                        algorithm="ssh-ed25519",
                        comment="win-key",
                        fingerprint="SHA256:test",
                    )
                ]

        config.bitwarden.mode = "windows_bridge"
        server = ControlServer(
            runtime_dir=runtime_dir,
            config=config,
            windows_bridge=_Bridge(),  # type: ignore[arg-type]
        )

        task = await _start_control(server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "unlock", "id": 1, "params": {}},
            )
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["unlocked"] is True
            assert result["managed_by"] == "windows_app"
            assert result["key_count"] == 1
        finally:
            server.shutdown()
            await task


class TestSyncMethod:
    @pytest.mark.asyncio
    async def test_sync_when_locked_returns_error(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        """Sync returns error when agent is locked."""
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "sync", "id": 1, "params": {}},
            )
            assert resp["id"] == 1
            # Server is locked by default, so sync should fail
            assert "error" in resp
            error = resp["error"]
            assert isinstance(error, dict)
            assert "locked" in str(error["message"]).lower()
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_sync_after_unlock(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
    ) -> None:
        """Sync works after unlock with session key."""
        bw = MockBitwardenProvider()
        agent = AgentServer(runtime_dir=runtime_dir, bitwarden=bw)
        server = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            bitwarden=bw,
            config=config,
        )
        task = await _start_control(server)
        try:
            # First unlock with session key
            resp1 = await _send_raw(
                control_socket_path,
                {"method": "unlock", "id": 1, "params": {"session_key": "test"}},
            )
            assert "result" in resp1
            result1 = resp1["result"]
            assert isinstance(result1, dict)
            assert result1["unlocked"] is True

            # Now sync should work
            resp2 = await _send_raw(
                control_socket_path,
                {"method": "sync", "id": 2, "params": {}},
            )
            assert "result" in resp2
            result2 = resp2["result"]
            assert isinstance(result2, dict)
            assert result2["synced"] is True
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_sync_windows_bridge_mode_when_locked(
        self,
        runtime_dir: Path,
        control_socket_path: Path,
        config: BwsshConfig,
    ) -> None:
        class _Bridge:
            async def list_identities(self) -> list[BridgeIdentity]:
                return []

        config.bitwarden.mode = "windows_bridge"
        server = ControlServer(
            runtime_dir=runtime_dir,
            config=config,
            windows_bridge=_Bridge(),  # type: ignore[arg-type]
        )
        task = await _start_control(server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "sync", "id": 1, "params": {}},
            )
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["synced"] is False
            assert result["managed_by"] == "windows_app"
        finally:
            server.shutdown()
            await task


class TestReloadConfigMethod:
    @pytest.mark.asyncio
    async def test_reload_config(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "reload_config", "id": 1, "params": {}},
            )
            assert resp["id"] == 1
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["reloaded"] is True
        finally:
            control_server.shutdown()
            await task


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_malformed_json(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            reader, writer = await asyncio.open_unix_connection(
                str(control_socket_path)
            )
            writer.write(b"not valid json\n")
            await writer.drain()
            response_line = await reader.readline()
            resp: dict[str, object] = json.loads(response_line.decode())
            assert "error" in resp
            error = resp["error"]
            assert isinstance(error, dict)
            assert error["code"] == -32700
            assert "parse" in str(error["message"]).lower()
            writer.close()
            await writer.wait_closed()
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_unknown_method(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"method": "nonexistent", "id": 1, "params": {}},
            )
            assert resp["id"] == 1
            assert "error" in resp
            error = resp["error"]
            assert isinstance(error, dict)
            assert error["code"] == -32601
            assert "unknown" in str(error["message"]).lower()
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_missing_method_field(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            resp = await _send_raw(
                control_socket_path,
                {"id": 1, "params": {}},
            )
            assert "error" in resp
            error = resp["error"]
            assert isinstance(error, dict)
            assert error["code"] == -32600
        finally:
            control_server.shutdown()
            await task


class TestControlClient:
    @pytest.mark.asyncio
    async def test_client_sends_command(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            client = ControlClient(control_socket_path)
            result = await client.send_command("status", {})
            assert isinstance(result, dict)
            assert "pid" in result
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_client_raises_on_error(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            client = ControlClient(control_socket_path)
            with pytest.raises(ControlError, match="Unknown method"):
                await client.send_command("nonexistent", {})
        finally:
            control_server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_client_round_trip_list_keys(
        self, control_server: ControlServer, control_socket_path: Path
    ) -> None:
        task = await _start_control(control_server)
        try:
            client = ControlClient(control_socket_path)
            result = await client.send_command("list_keys", {})
            assert isinstance(result, dict)
            assert result["keys"] == []
        finally:
            control_server.shutdown()
            await task


class TestConcurrentSockets:
    @pytest.mark.asyncio
    async def test_agent_and_control_concurrent(
        self,
        runtime_dir: Path,
        ed25519_key_path: Path,
    ) -> None:
        """Both agent and control sockets run in same event loop."""
        registry = _make_registry(ed25519_key_path, "concurrent-test")

        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))
        agent = AgentServer(runtime_dir=runtime_dir)
        agent._registry = registry

        control = ControlServer(
            runtime_dir=runtime_dir,
            registry=registry,
            config=config,
        )

        agent_task = asyncio.create_task(agent.serve())
        control_task = asyncio.create_task(control.serve())
        await asyncio.sleep(0.05)

        try:
            agent_reader, agent_writer = await asyncio.open_unix_connection(
                str(agent.socket_path)
            )
            await write_message(agent_writer, SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, _payload = await read_message(agent_reader)
            assert msg_type == SSH_AGENT_IDENTITIES_ANSWER
            agent_writer.close()
            await agent_writer.wait_closed()

            control_path = runtime_dir / "control.sock"
            resp = await _send_raw(
                control_path,
                {"method": "status", "id": 1, "params": {}},
            )
            assert "result" in resp
            result = resp["result"]
            assert isinstance(result, dict)
            assert result["key_count"] == 1
        finally:
            agent.shutdown()
            control.shutdown()
            await agent_task
            await control_task
