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

from dbus_fast import BusType
from dbus_fast.aio import MessageBus

from bwssh.agent_proto import (
    pack_string,
    pack_uint32,
    read_message,
    unpack_string,
    unpack_uint32,
    write_message,
)
from bwssh.bitwarden import BitwardenLike, BitwardenProvider
from bwssh.config import BwsshConfig, load_config
from bwssh.constants import (
    SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST,
)
from bwssh.control import ControlServer
from bwssh.keys import (
    Identity,
    KeyRegistry,
    compute_fingerprint,
    get_key_type_string,
    get_public_key_blob,
    load_private_key,
)
from bwssh.logging_config import setup_logging
from bwssh.peercred import ConnectionContext, build_connection_context
from bwssh.polkit import (
    ACTION_SIGN,
    Authorizer,
    CachingAuthorizer,
    MockPolkitAuthorizer,
    PolkitAuthorizer,
    build_details,
)
from bwssh.signing import build_signature_blob, sign_data

logger = logging.getLogger(__name__)

_SOCKET_NAME = "agent.sock"


def _default_runtime_dir() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "bwssh"
    return Path(f"/tmp/bwssh-{os.getuid()}")


class AgentServer:
    def __init__(
        self,
        runtime_dir: Path | None = None,
        polkit: Authorizer | None = None,
        config: BwsshConfig | None = None,
        bitwarden: BitwardenLike | None = None,
    ) -> None:
        self._runtime_dir = runtime_dir or _default_runtime_dir()
        self._socket_path = self._runtime_dir / _SOCKET_NAME
        self._server: asyncio.Server | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._registry = KeyRegistry()
        self._polkit: Authorizer = polkit or MockPolkitAuthorizer(always_allow=True)
        self._config = config or BwsshConfig()
        self._bitwarden = bitwarden

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    @property
    def registry(self) -> KeyRegistry:
        return self._registry

    def _prepare_runtime_dir(self) -> None:
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        self._runtime_dir.chmod(0o700)

    def load_key(self, key_path: Path, comment: str, source: str = "test") -> None:
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

    def load_key_from_bytes(self, key_data: bytes, identity: Identity) -> None:
        private_key = load_private_key(key_data)
        self._registry.add_key(identity, private_key)

    def lock(self) -> None:
        self._registry.clear()
        if self._bitwarden is not None:
            self._bitwarden.lock()
        logger.info("Agent locked: keys cleared")

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
                logger.info(
                    "Client connected: pid=%d, uid=%d, exe=%s",
                    _conn_ctx.peer_pid,
                    _conn_ctx.peer_uid,
                    _conn_ctx.exe_path or "unknown",
                )
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
                    await self._handle_sign_request(writer, payload, _conn_ctx)
                else:
                    await write_message(writer, SSH_AGENT_FAILURE, b"")
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_sign_request(
        self,
        writer: asyncio.StreamWriter,
        payload: bytes,
        conn_ctx: ConnectionContext | None = None,
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
            logger.warning("Sign request for unknown key")
            await write_message(writer, SSH_AGENT_FAILURE, b"")
            return

        identity = self._registry.get_identity(key_blob)
        fingerprint = identity.fingerprint if identity else "unknown"
        comment = identity.comment if identity else "unknown"

        if conn_ctx is not None:
            details = build_details(fingerprint, comment, conn_ctx)
            authorized = await self._polkit.check_authorization(
                ACTION_SIGN, conn_ctx, details
            )
            if not authorized:
                logger.info(
                    "Sign request denied by polkit: fingerprint=%s, pid=%d",
                    fingerprint,
                    conn_ctx.peer_pid,
                )
                await write_message(writer, SSH_AGENT_FAILURE, b"")
                return

        try:
            signature_bytes, algorithm = sign_data(private_key, data, flags)
        except (ValueError, TypeError):
            logger.error("Sign operation failed for key=%s", fingerprint)
            await write_message(writer, SSH_AGENT_FAILURE, b"")
            return

        if conn_ctx is not None:
            logger.info(
                "Sign operation: fingerprint=%s, peer_pid=%d, peer_exe=%s, "
                "result=allow",
                fingerprint,
                conn_ctx.peer_pid,
                conn_ctx.exe_path or "unknown",
            )

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

        logger.info("Starting bwssh-agentd on socket: %s", self._socket_path)

        try:
            await self._shutdown_event.wait()
        finally:
            logger.info("Shutting down bwssh-agentd")
            self._registry.clear()
            self._server.close()
            await self._server.wait_closed()
            if self._socket_path.exists():
                self._socket_path.unlink()

    def shutdown(self) -> None:
        if self._shutdown_event is not None:
            self._shutdown_event.set()


async def _sleep_watcher(
    agent_server: AgentServer, shutdown_event: asyncio.Event
) -> None:
    """Watch for system sleep events and lock the agent."""
    try:
        bus = MessageBus(bus_type=BusType.SYSTEM)
        await asyncio.wait_for(bus.connect(), timeout=5.0)

        # Subscribe to PrepareForSleep signal from logind
        introspection = await asyncio.wait_for(
            bus.introspect("org.freedesktop.login1", "/org/freedesktop/login1"),
            timeout=5.0,
        )
        proxy = bus.get_proxy_object(
            "org.freedesktop.login1", "/org/freedesktop/login1", introspection
        )
        manager = proxy.get_interface("org.freedesktop.login1.Manager")

        def on_prepare_for_sleep(going_to_sleep: bool) -> None:
            if going_to_sleep:
                logger.info("System going to sleep, locking agent")
                agent_server.lock()

        manager.on_prepare_for_sleep(on_prepare_for_sleep)  # type: ignore[attr-defined]
        logger.info("Sleep watcher active: will lock on system sleep")

        # Wait until shutdown
        await shutdown_event.wait()

    except TimeoutError:
        logger.info("Sleep watcher: D-Bus connection timed out (logind unavailable)")
    except Exception:
        logger.debug("Sleep watcher setup failed (non-critical)", exc_info=True)


async def _main_async(
    agent_server: AgentServer,
    control_server: ControlServer,
    lock_on_sleep: bool = False,
) -> None:
    shutdown_event = asyncio.Event()

    async def agent_with_shutdown() -> None:
        await agent_server.serve()
        shutdown_event.set()

    tasks: list[asyncio.Task[None]] = [
        asyncio.create_task(agent_with_shutdown()),
        asyncio.create_task(control_server.serve()),
    ]
    if lock_on_sleep:
        tasks.append(asyncio.create_task(_sleep_watcher(agent_server, shutdown_event)))

    await asyncio.gather(*tasks)


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
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    args = parser.parse_args()

    if not args.foreground:
        print("error: only --foreground mode is supported", file=sys.stderr)
        sys.exit(1)

    config = load_config()
    log_level = args.log_level or config.daemon.log_level
    setup_logging(log_level)

    runtime_dir = (
        args.runtime_dir or config.daemon.runtime_dir or _default_runtime_dir()
    )
    runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.chmod(0o700)

    pid_file = runtime_dir / "daemon.pid"
    pid_file.write_text(str(os.getpid()))
    logger.info("PID file written: %s (pid=%d)", pid_file, os.getpid())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _connect_polkit() -> tuple[Authorizer, bool, str | None]:
        """Connect to system D-Bus for polkit authorization."""
        if not config.auth.require_polkit:
            logger.info(
                "Polkit disabled (require_polkit=false); "
                "signing allowed without prompts."
            )
            return MockPolkitAuthorizer(always_allow=True), False, None

        try:
            bus = MessageBus(bus_type=BusType.SYSTEM)
            await bus.connect()
            return PolkitAuthorizer(bus), True, None
        except Exception as e:
            logger.warning(
                "Failed to connect to system D-Bus for polkit; "
                "sign requests will be denied. Run 'bwssh status' for details.",
                exc_info=True,
            )
            return MockPolkitAuthorizer(always_allow=False), False, str(e)

    bw_provider = BitwardenProvider(config.bitwarden.bw_path, config.bitwarden.item_ids)
    polkit_auth, polkit_available, polkit_error = loop.run_until_complete(
        _connect_polkit()
    )

    caching_auth = CachingAuthorizer(
        polkit_auth, config.auth.approval_mode, config.auth.approval_ttl_seconds
    )

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
        polkit_available=polkit_available,
        polkit_error=polkit_error,
    )

    def _shutdown_handler() -> None:
        logger.info("Received shutdown signal, stopping daemon")
        agent_server.shutdown()
        control_server.shutdown()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _shutdown_handler)

    try:
        loop.run_until_complete(
            _main_async(agent_server, control_server, config.daemon.lock_on_sleep)
        )
    finally:
        loop.close()
        if pid_file.exists():
            pid_file.unlink()
        logger.info("Daemon stopped, PID file removed")
