"""Tests for bwssh daemon (Unix domain socket agent server)."""

from __future__ import annotations

import asyncio
import os
import signal
import stat
from typing import TYPE_CHECKING

import pytest

from bwssh import constants
from bwssh.agent_proto import read_message, unpack_uint32, write_message
from bwssh.daemon import AgentServer

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def runtime_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def socket_path(runtime_dir: Path) -> Path:
    return runtime_dir / "agent.sock"


@pytest.fixture
def server(runtime_dir: Path) -> AgentServer:
    return AgentServer(runtime_dir=runtime_dir)


async def _start_server(server: AgentServer) -> asyncio.Task[None]:
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.05)
    return task


async def _connect(
    socket_path: Path,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_unix_connection(str(socket_path))


class TestServerLifecycle:
    @pytest.mark.asyncio
    async def test_server_creates_socket(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            assert socket_path.exists()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_server_removes_socket_on_shutdown(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        server.shutdown()
        await task
        assert not socket_path.exists()

    @pytest.mark.asyncio
    async def test_server_cleans_stale_socket(
        self, runtime_dir: Path, socket_path: Path
    ) -> None:
        socket_path.touch()
        assert socket_path.exists()

        server = AgentServer(runtime_dir=runtime_dir)
        task = await _start_server(server)
        try:
            assert socket_path.exists()
            _reader, writer = await _connect(socket_path)
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_client_can_connect(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            _reader, writer = await _connect(socket_path)
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task


class TestRuntimeDirectory:
    @pytest.mark.asyncio
    async def test_creates_runtime_dir(self, tmp_path: Path) -> None:
        nested = tmp_path / "nested" / "bwssh"
        server = AgentServer(runtime_dir=nested)
        task = await _start_server(server)
        try:
            assert nested.exists()
            assert nested.is_dir()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_runtime_dir_permissions(self, tmp_path: Path) -> None:
        nested = tmp_path / "bwssh_perm"
        server = AgentServer(runtime_dir=nested)
        task = await _start_server(server)
        try:
            mode = nested.stat().st_mode & 0o777
            assert mode == 0o700
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_socket_permissions(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            mode = socket_path.stat().st_mode
            assert stat.S_ISSOCK(mode)
            perm = mode & 0o777
            assert perm == 0o600
        finally:
            server.shutdown()
            await task


class TestMessageDispatch:
    @pytest.mark.asyncio
    async def test_request_identities_returns_identities_answer(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            nkeys, _ = unpack_uint32(payload, 0)
            assert nkeys == 0
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_sign_request_returns_failure(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, b"\x00" * 20)
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE
            assert payload == b""
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_unknown_message_type_returns_failure(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, 255, b"garbage")
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE
            assert payload == b""
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_add_identity_returns_failure(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_ADD_IDENTITY, b"\x00")
            msg_type, _payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_lock_returns_failure(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_LOCK, b"pass")
            msg_type, _payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_multiple_messages_on_one_connection(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            for _ in range(5):
                await write_message(
                    writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b""
                )
                msg_type, _payload = await read_message(reader)
                assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task


class TestClientDisconnect:
    @pytest.mark.asyncio
    async def test_client_disconnect_no_crash(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            _reader, writer = await _connect(socket_path)
            writer.close()
            await writer.wait_closed()

            await asyncio.sleep(0.05)

            reader2, writer2 = await _connect(socket_path)
            await write_message(writer2, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, _ = await read_message(reader2)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            writer2.close()
            await writer2.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_client_disconnect_mid_message(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            _reader, writer = await _connect(socket_path)
            writer.write(b"\x00\x00")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            await asyncio.sleep(0.05)

            reader2, writer2 = await _connect(socket_path)
            await write_message(writer2, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, _ = await read_message(reader2)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            writer2.close()
            await writer2.wait_closed()
        finally:
            server.shutdown()
            await task


class TestConcurrentConnections:
    @pytest.mark.asyncio
    async def test_multiple_concurrent_clients(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:

            async def client_session(_client_id: int) -> int:
                r, w = await _connect(socket_path)
                await write_message(w, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
                msg_type, _ = await read_message(r)
                w.close()
                await w.wait_closed()
                return msg_type

            results = await asyncio.gather(*[client_session(i) for i in range(10)])
            assert all(r == constants.SSH_AGENT_IDENTITIES_ANSWER for r in results)
        finally:
            server.shutdown()
            await task


class TestSignalHandling:
    @pytest.mark.asyncio
    async def test_sigterm_triggers_shutdown(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, server.shutdown)
        try:
            task = await _start_server(server)

            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.1)

            await asyncio.wait_for(task, timeout=2.0)
            assert not socket_path.exists()
        finally:
            loop.remove_signal_handler(signal.SIGTERM)
