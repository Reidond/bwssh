"""SSH agent daemon — Unix domain socket server."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import struct
import sys
from pathlib import Path

from bwssh.agent_proto import (
    pack_string,
    pack_uint32,
    read_message,
    unpack_string,
    unpack_uint32,
    write_message,
)
from bwssh.constants import (
    SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST,
)
from bwssh.keys import (
    Identity,
    KeyRegistry,
    compute_fingerprint,
    get_key_type_string,
    get_public_key_blob,
    load_private_key,
)
from bwssh.peercred import build_connection_context
from bwssh.signing import build_signature_blob, sign_data

logger = logging.getLogger(__name__)

_SOCKET_NAME = "agent.sock"


def _default_runtime_dir() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "bwssh"
    return Path(f"/tmp/bwssh-{os.getuid()}")


class AgentServer:
    def __init__(self, runtime_dir: Path | None = None) -> None:
        self._runtime_dir = runtime_dir or _default_runtime_dir()
        self._socket_path = self._runtime_dir / _SOCKET_NAME
        self._server: asyncio.Server | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._registry = KeyRegistry()

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    def _prepare_runtime_dir(self) -> None:
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        self._runtime_dir.chmod(0o700)

    def load_key(self, key_path: Path, comment: str, source: str = "test") -> None:
        """Load a private key from *key_path* into the agent registry."""
        key_data = key_path.read_bytes()
        private_key = load_private_key(key_data)
        blob = get_public_key_blob(private_key)
        identity = Identity(
            identity_id=compute_fingerprint(blob),
            comment=comment,
            public_key_blob=blob,
            fingerprint=compute_fingerprint(blob),
            algorithm=get_key_type_string(private_key),
            source=source,
        )
        self._registry.add_key(identity, private_key)

    def _remove_stale_socket(self) -> None:
        if not self._socket_path.exists():
            return
        with contextlib.suppress(OSError):
            self._socket_path.unlink()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        sock = writer.get_extra_info("socket")
        _conn_ctx = None
        if sock is not None:
            try:
                _conn_ctx = build_connection_context(sock)
            except OSError:
                logger.warning("Failed to get peer credentials", exc_info=True)

        try:
            while True:
                msg_type, payload = await read_message(reader)
                if msg_type == SSH_AGENTC_REQUEST_IDENTITIES:
                    identities = self._registry.list_identities()
                    response = pack_uint32(len(identities))
                    for ident in identities:
                        response += pack_string(ident.public_key_blob)
                        response += pack_string(ident.comment.encode("utf-8"))
                    await write_message(writer, SSH_AGENT_IDENTITIES_ANSWER, response)
                elif msg_type == SSH_AGENTC_SIGN_REQUEST:
                    await self._handle_sign_request(writer, payload)
                else:
                    await write_message(writer, SSH_AGENT_FAILURE, b"")
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_sign_request(
        self, writer: asyncio.StreamWriter, payload: bytes
    ) -> None:
        try:
            key_blob, offset = unpack_string(payload, 0)
            data, offset = unpack_string(payload, offset)
            flags, _offset = unpack_uint32(payload, offset)
        except (ValueError, struct.error):
            await write_message(writer, SSH_AGENT_FAILURE, b"")
            return

        private_key = self._registry.get_private_key(key_blob)
        if private_key is None:
            await write_message(writer, SSH_AGENT_FAILURE, b"")
            return

        try:
            signature_bytes, algorithm = sign_data(private_key, data, flags)
        except (ValueError, TypeError):
            await write_message(writer, SSH_AGENT_FAILURE, b"")
            return

        sig_blob = build_signature_blob(algorithm, signature_bytes)
        await write_message(writer, SSH_AGENT_SIGN_RESPONSE, pack_string(sig_blob))

    async def serve(self) -> None:
        self._shutdown_event = asyncio.Event()
        self._prepare_runtime_dir()
        self._remove_stale_socket()

        self._server = await asyncio.start_unix_server(
            self.handle_client, path=str(self._socket_path)
        )
        self._socket_path.chmod(0o600)

        try:
            await self._shutdown_event.wait()
        finally:
            self._server.close()
            await self._server.wait_closed()
            if self._socket_path.exists():
                self._socket_path.unlink()

    def shutdown(self) -> None:
        if self._shutdown_event is not None:
            self._shutdown_event.set()


def main_entry() -> None:
    parser = argparse.ArgumentParser(
        prog="bwssh-agentd",
        description="Bitwarden-backed SSH agent daemon",
    )
    parser.add_argument(
        "--foreground",
        action="store_true",
        help="Run in foreground until signalled",
    )
    parser.add_argument(
        "--runtime-dir",
        type=Path,
        default=None,
        help="Override runtime directory path",
    )
    args = parser.parse_args()

    if not args.foreground:
        print("error: only --foreground mode is supported", file=sys.stderr)
        sys.exit(1)

    server = AgentServer(runtime_dir=args.runtime_dir)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, server.shutdown)

    try:
        loop.run_until_complete(server.serve())
    finally:
        loop.close()
