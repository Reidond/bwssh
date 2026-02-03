"""Tests for bwssh daemon (Unix domain socket agent server)."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from bwssh import constants
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
from bwssh.control import ControlServer
from bwssh.daemon import AgentServer, _main_async
from bwssh.keys import (
    Identity,
    compute_fingerprint,
    get_key_type_string,
    get_public_key_blob,
    load_private_key,
)
from bwssh.polkit import MockPolkitAuthorizer

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
    async def test_sign_request_unknown_key_returns_failure(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            unknown_blob = b"\xde\xad" * 16
            request = (
                pack_string(unknown_blob)
                + pack_string(b"data to sign")
                + pack_uint32(0)
            )
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_FAILURE
            assert payload == b""
            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_sign_request_malformed_payload_returns_failure(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, b"\x00" * 3)
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


class TestIdentitiesAnswer:
    @pytest.mark.asyncio
    async def test_single_key_identity(
        self, runtime_dir: Path, socket_path: Path, ed25519_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ed25519_key_path, "test-ed25519", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            nkeys, offset = unpack_uint32(payload, 0)
            assert nkeys == 1

            blob, offset = unpack_string(payload, offset)
            comment, offset = unpack_string(payload, offset)

            expected_blob = get_public_key_blob(
                load_private_key(ed25519_key_path.read_bytes())
            )
            assert blob == expected_blob
            assert comment == b"test-ed25519"

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_multiple_keys(
        self,
        runtime_dir: Path,
        socket_path: Path,
        ed25519_key_path: Path,
        rsa_key_path: Path,
        ecdsa_key_path: Path,
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ed25519_key_path, "key-ed25519", "test")
        server.load_key(rsa_key_path, "key-rsa", "test")
        server.load_key(ecdsa_key_path, "key-ecdsa", "test")

        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            nkeys, offset = unpack_uint32(payload, 0)
            assert nkeys == 3

            blobs: list[bytes] = []
            comments: list[bytes] = []
            for _ in range(nkeys):
                blob, offset = unpack_string(payload, offset)
                comment, offset = unpack_string(payload, offset)
                blobs.append(blob)
                comments.append(comment)

            assert set(comments) == {b"key-ed25519", b"key-rsa", b"key-ecdsa"}
            assert offset == len(payload)

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_empty_registry_returns_zero_keys(
        self, server: AgentServer, socket_path: Path
    ) -> None:
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            nkeys, offset = unpack_uint32(payload, 0)
            assert nkeys == 0
            assert offset == len(payload)

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_ssh_add_list_shows_key(
        self, runtime_dir: Path, socket_path: Path, ed25519_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ed25519_key_path, "smoke-test-key", "test")

        task = await _start_server(server)
        try:
            proc = await asyncio.create_subprocess_exec(
                "ssh-add",
                "-L",
                env={**os.environ, "SSH_AUTH_SOCK": str(socket_path)},
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            assert proc.returncode == 0, f"ssh-add -L failed: {stderr.decode()}"
            output = stdout.decode()
            assert "ssh-ed25519" in output
            assert "smoke-test-key" in output
        finally:
            server.shutdown()
            await task


class TestSignRequest:
    async def _get_key_blob(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bytes:
        await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
        msg_type, payload = await read_message(reader)
        assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
        nkeys, offset = unpack_uint32(payload, 0)
        assert nkeys >= 1
        key_blob, _offset = unpack_string(payload, offset)
        return key_blob

    @pytest.mark.asyncio
    async def test_ed25519_sign_request(
        self, runtime_dir: Path, socket_path: Path, ed25519_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ed25519_key_path, "test-ed25519", "test")
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            key_blob = await self._get_key_blob(reader, writer)

            data_to_sign = b"hello from test"
            request = pack_string(key_blob) + pack_string(data_to_sign) + pack_uint32(0)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE
            sig_blob, _ = unpack_string(payload, 0)

            algo, offset = unpack_string(sig_blob, 0)
            sig, _ = unpack_string(sig_blob, offset)
            assert algo == b"ssh-ed25519"

            private_key = load_private_key(ed25519_key_path.read_bytes())
            assert isinstance(private_key, ed25519.Ed25519PrivateKey)
            private_key.public_key().verify(sig, data_to_sign)

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_rsa_sha256_sign_request(
        self, runtime_dir: Path, socket_path: Path, rsa_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(rsa_key_path, "test-rsa", "test")
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            key_blob = await self._get_key_blob(reader, writer)

            data_to_sign = b"rsa test data"
            request = (
                pack_string(key_blob)
                + pack_string(data_to_sign)
                + pack_uint32(constants.SSH_AGENT_RSA_SHA2_256)
            )
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE
            sig_blob, _ = unpack_string(payload, 0)

            algo, offset = unpack_string(sig_blob, 0)
            sig, _ = unpack_string(sig_blob, offset)
            assert algo == b"rsa-sha2-256"

            private_key = load_private_key(rsa_key_path.read_bytes())
            assert isinstance(private_key, rsa.RSAPrivateKey)
            private_key.public_key().verify(
                sig, data_to_sign, padding.PKCS1v15(), hashes.SHA256()
            )

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_rsa_sha512_sign_request(
        self, runtime_dir: Path, socket_path: Path, rsa_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(rsa_key_path, "test-rsa", "test")
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            key_blob = await self._get_key_blob(reader, writer)

            data_to_sign = b"rsa 512 test"
            request = (
                pack_string(key_blob)
                + pack_string(data_to_sign)
                + pack_uint32(constants.SSH_AGENT_RSA_SHA2_512)
            )
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE
            sig_blob, _ = unpack_string(payload, 0)

            algo, offset = unpack_string(sig_blob, 0)
            sig, _ = unpack_string(sig_blob, offset)
            assert algo == b"rsa-sha2-512"

            private_key = load_private_key(rsa_key_path.read_bytes())
            assert isinstance(private_key, rsa.RSAPrivateKey)
            private_key.public_key().verify(
                sig, data_to_sign, padding.PKCS1v15(), hashes.SHA512()
            )

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_ecdsa_sign_request(
        self, runtime_dir: Path, socket_path: Path, ecdsa_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ecdsa_key_path, "test-ecdsa", "test")
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            key_blob = await self._get_key_blob(reader, writer)

            data_to_sign = b"ecdsa test data"
            request = pack_string(key_blob) + pack_string(data_to_sign) + pack_uint32(0)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, payload = await read_message(reader)

            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE
            sig_blob, _ = unpack_string(payload, 0)

            algo, offset = unpack_string(sig_blob, 0)
            raw_sig, _ = unpack_string(sig_blob, offset)
            assert algo == b"ecdsa-sha2-nistp256"

            r_bytes, off = unpack_string(raw_sig, 0)
            s_bytes, _ = unpack_string(raw_sig, off)
            r = int.from_bytes(r_bytes, byteorder="big")
            s = int.from_bytes(s_bytes, byteorder="big")

            der_sig = utils.encode_dss_signature(r, s)
            private_key = load_private_key(ecdsa_key_path.read_bytes())
            assert isinstance(private_key, ec.EllipticCurvePrivateKey)
            private_key.public_key().verify(
                der_sig, data_to_sign, ec.ECDSA(hashes.SHA256())
            )

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_sign_then_list_still_works(
        self, runtime_dir: Path, socket_path: Path, ed25519_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ed25519_key_path, "test-ed25519", "test")
        task = await _start_server(server)
        try:
            reader, writer = await _connect(socket_path)
            key_blob = await self._get_key_blob(reader, writer)

            request = pack_string(key_blob) + pack_string(b"data") + pack_uint32(0)
            await write_message(writer, constants.SSH_AGENTC_SIGN_REQUEST, request)
            msg_type, _ = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_SIGN_RESPONSE

            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type2, _ = await read_message(reader)
            assert msg_type2 == constants.SSH_AGENT_IDENTITIES_ANSWER

            writer.close()
            await writer.wait_closed()
        finally:
            server.shutdown()
            await task


class TestAgentServerLock:
    @pytest.mark.asyncio
    async def test_lock_clears_registry(
        self, runtime_dir: Path, ed25519_key_path: Path
    ) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key(ed25519_key_path, "test-key", "test")
        assert len(server.registry.list_identities()) == 1

        server.lock()
        assert len(server.registry.list_identities()) == 0

    @pytest.mark.asyncio
    async def test_lock_calls_bitwarden_lock(self, runtime_dir: Path) -> None:
        bw = MockBitwardenProvider()
        bw.unlock("test-session")
        assert bw._session_key == "test-session"

        server = AgentServer(runtime_dir=runtime_dir, bitwarden=bw)
        server.lock()
        assert bw._session_key is None

    @pytest.mark.asyncio
    async def test_lock_without_bitwarden(self, runtime_dir: Path) -> None:
        server = AgentServer(runtime_dir=runtime_dir)
        server.lock()
        assert len(server.registry.list_identities()) == 0


class TestLoadKeyFromBytes:
    @pytest.mark.asyncio
    async def test_load_key_from_bytes(
        self, runtime_dir: Path, ed25519_key_path: Path
    ) -> None:
        key_data = ed25519_key_path.read_bytes()
        private_key = load_private_key(key_data)
        blob = get_public_key_blob(private_key)
        identity = Identity(
            identity_id="test-id",
            comment="from-bytes",
            public_key_blob=blob,
            fingerprint=compute_fingerprint(blob),
            algorithm=get_key_type_string(private_key),
            source="test",
        )

        server = AgentServer(runtime_dir=runtime_dir)
        server.load_key_from_bytes(key_data, identity)

        identities = server.registry.list_identities()
        assert len(identities) == 1
        assert identities[0].comment == "from-bytes"


class TestPidFile:
    @pytest.mark.asyncio
    async def test_pid_file_written_on_start(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "bwssh-pid-test"
        runtime_dir.mkdir()
        pid_file = runtime_dir / "daemon.pid"
        pid_file.write_text(str(os.getpid()))

        assert pid_file.exists()
        assert pid_file.read_text() == str(os.getpid())

    @pytest.mark.asyncio
    async def test_pid_file_removed_on_cleanup(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "bwssh-pid-cleanup"
        runtime_dir.mkdir()
        pid_file = runtime_dir / "daemon.pid"
        pid_file.write_text(str(os.getpid()))

        assert pid_file.exists()
        pid_file.unlink()
        assert not pid_file.exists()


class TestMainAsync:
    @pytest.mark.asyncio
    async def test_main_async_both_servers_run(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "main-async-test"
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
            assert agent.socket_path.exists()
            assert control.socket_path.exists()

            reader, writer = await asyncio.open_unix_connection(str(agent.socket_path))
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, _ = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            writer.close()
            await writer.wait_closed()

            ctrl_reader, ctrl_writer = await asyncio.open_unix_connection(
                str(control.socket_path)
            )
            request = (
                json.dumps({"method": "status", "id": 1, "params": {}}).encode() + b"\n"
            )
            ctrl_writer.write(request)
            await ctrl_writer.drain()
            resp_line = await ctrl_reader.readline()
            resp = json.loads(resp_line.decode())
            assert "result" in resp
            assert resp["result"]["pid"] == os.getpid()
            ctrl_writer.close()
            await ctrl_writer.wait_closed()
        finally:
            agent.shutdown()
            control.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_main_async_signal_shuts_both_down(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "signal-test"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))

        agent = AgentServer(runtime_dir=runtime_dir, config=config)
        control = ControlServer(
            runtime_dir=runtime_dir,
            agent_server=agent,
            config=config,
        )

        loop = asyncio.get_running_loop()

        def _handler() -> None:
            agent.shutdown()
            control.shutdown()

        loop.add_signal_handler(signal.SIGTERM, _handler)
        try:
            task = asyncio.create_task(_main_async(agent, control))
            await asyncio.sleep(0.1)

            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.1)

            await asyncio.wait_for(task, timeout=2.0)
            assert not agent.socket_path.exists()
            assert not control.socket_path.exists()
        finally:
            loop.remove_signal_handler(signal.SIGTERM)


class TestDaemonIntegration:
    @pytest.mark.asyncio
    async def test_full_lifecycle_with_bitwarden(self, tmp_path: Path) -> None:
        runtime_dir = tmp_path / "full-lifecycle"
        config = BwsshConfig(daemon=DaemonConfig(runtime_dir=runtime_dir))
        bw = MockBitwardenProvider()
        polkit = MockPolkitAuthorizer(always_allow=True)

        agent = AgentServer(
            runtime_dir=runtime_dir,
            polkit=polkit,
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
            ctrl_reader, ctrl_writer = await asyncio.open_unix_connection(
                str(control.socket_path)
            )
            unlock_req = (
                json.dumps(
                    {
                        "method": "unlock",
                        "id": 1,
                        "params": {"session_key": "test-session"},
                    }
                ).encode()
                + b"\n"
            )
            ctrl_writer.write(unlock_req)
            await ctrl_writer.drain()
            resp_line = await ctrl_reader.readline()
            resp = json.loads(resp_line.decode())
            assert resp["result"]["unlocked"] is True
            assert resp["result"]["key_count"] == 1
            ctrl_writer.close()
            await ctrl_writer.wait_closed()

            reader, writer = await asyncio.open_unix_connection(str(agent.socket_path))
            await write_message(writer, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type, payload = await read_message(reader)
            assert msg_type == constants.SSH_AGENT_IDENTITIES_ANSWER
            nkeys, _ = unpack_uint32(payload, 0)
            assert nkeys == 1
            writer.close()
            await writer.wait_closed()

            ctrl_reader2, ctrl_writer2 = await asyncio.open_unix_connection(
                str(control.socket_path)
            )
            lock_req = (
                json.dumps(
                    {
                        "method": "lock",
                        "id": 2,
                        "params": {},
                    }
                ).encode()
                + b"\n"
            )
            ctrl_writer2.write(lock_req)
            await ctrl_writer2.drain()
            resp_line2 = await ctrl_reader2.readline()
            resp2 = json.loads(resp_line2.decode())
            assert resp2["result"]["locked"] is True
            ctrl_writer2.close()
            await ctrl_writer2.wait_closed()

            reader2, writer2 = await asyncio.open_unix_connection(
                str(agent.socket_path)
            )
            await write_message(writer2, constants.SSH_AGENTC_REQUEST_IDENTITIES, b"")
            msg_type3, payload2 = await read_message(reader2)
            assert msg_type3 == constants.SSH_AGENT_IDENTITIES_ANSWER
            nkeys2, _ = unpack_uint32(payload2, 0)
            assert nkeys2 == 0
            writer2.close()
            await writer2.wait_closed()
        finally:
            agent.shutdown()
            control.shutdown()
            await task

    @pytest.mark.asyncio
    async def test_shutdown_clears_keys(
        self, tmp_path: Path, ed25519_key_path: Path
    ) -> None:
        runtime_dir = tmp_path / "shutdown-clear"
        agent = AgentServer(runtime_dir=runtime_dir)
        agent.load_key(ed25519_key_path, "test-key", "test")
        assert len(agent.registry.list_identities()) == 1

        task = asyncio.create_task(agent.serve())
        await asyncio.sleep(0.05)

        agent.shutdown()
        await task

        assert len(agent.registry.list_identities()) == 0
