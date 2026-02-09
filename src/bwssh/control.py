"""Control socket server and client with JSON-lines protocol."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from typing import TYPE_CHECKING, Any

from bwssh.config import BwsshConfig, load_config
from bwssh.keys import KeyRegistry
from bwssh.peercred import ConnectionContext, build_connection_context
from bwssh.polkit import ACTION_UNLOCK, Authorizer, MockPolkitAuthorizer

if TYPE_CHECKING:
    from pathlib import Path

    from bwssh.bitwarden import BitwardenLike
    from bwssh.daemon import AgentServer

logger = logging.getLogger(__name__)

_CONTROL_SOCKET_NAME = "control.sock"

_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INTERNAL_ERROR = -32603
_UNAUTHORIZED = -32001


class ControlError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


class ControlServer:
    def __init__(
        self,
        runtime_dir: Path,
        registry: KeyRegistry | None = None,
        config: BwsshConfig | None = None,
        agent_server: AgentServer | None = None,
        bitwarden: BitwardenLike | None = None,
        polkit_available: bool = True,
        polkit_error: str | None = None,
        polkit: Authorizer | None = None,
    ) -> None:
        self._runtime_dir = runtime_dir
        self._socket_path = runtime_dir / _CONTROL_SOCKET_NAME
        self._server: asyncio.Server | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._agent_server = agent_server
        self._bitwarden = bitwarden
        self._polkit_available = polkit_available
        self._polkit_error = polkit_error
        self._polkit: Authorizer = polkit or MockPolkitAuthorizer(always_allow=True)

        if agent_server is not None:
            self._registry: KeyRegistry = agent_server.registry
        elif registry is not None:
            self._registry = registry
        else:
            self._registry = KeyRegistry()

        self._config = config or BwsshConfig()
        self._start_time = time.monotonic()
        self._locked = True  # Start locked until unlock is called
        self._methods: dict[str, Any] = {
            "status": self._handle_status,
            "list_keys": self._handle_list_keys,
            "lock": self._handle_lock,
            "unlock": self._handle_unlock,
            "sync": self._handle_sync,
            "reload_config": self._handle_reload_config,
        }
        # Connection context for current request (set by handle_client)
        self._current_conn_ctx: ConnectionContext | None = None

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    @property
    def is_locked(self) -> bool:
        return self._locked

    def lock(self) -> None:
        """Lock the agent: clear keys, bitwarden state, and set locked flag.

        This is the single source of truth for locking.  Call this instead
        of ``AgentServer.lock()`` so the ``_locked`` flag stays in sync.
        """
        if self._agent_server is not None:
            self._agent_server.lock()
        else:
            self._registry.clear()
        if self._bitwarden is not None:
            self._bitwarden.lock()
        self._locked = True
        logger.info("Agent locked")

    def _prepare_runtime_dir(self) -> None:
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        self._runtime_dir.chmod(0o700)

    def _remove_stale_socket(self) -> None:
        if not self._socket_path.exists():
            return
        with contextlib.suppress(OSError):
            self._socket_path.unlink()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Get connection context from socket for polkit authorization
        sock = writer.get_extra_info("socket")
        conn_ctx = None
        if sock is not None:
            try:
                conn_ctx = build_connection_context(sock)
                logger.debug(
                    "Control client connected: pid=%d, uid=%d",
                    conn_ctx.peer_pid,
                    conn_ctx.peer_uid,
                )
            except OSError:
                logger.warning("Failed to get peer credentials for control client")

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                # Set connection context for handler methods
                self._current_conn_ctx = conn_ctx
                response = await self._process_line(line)
                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._current_conn_ctx = None
            writer.close()
            await writer.wait_closed()

    async def _process_line(self, line: bytes) -> dict[str, Any]:
        try:
            request = json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {
                "id": None,
                "error": {"code": _PARSE_ERROR, "message": "Parse error"},
            }

        if not isinstance(request, dict) or "method" not in request:
            return {
                "id": request.get("id") if isinstance(request, dict) else None,
                "error": {
                    "code": _INVALID_REQUEST,
                    "message": "Invalid request: missing 'method' field",
                },
            }

        method = request["method"]
        request_id = request.get("id")
        params = request.get("params", {})

        handler = self._methods.get(method)
        if handler is None:
            return {
                "id": request_id,
                "error": {
                    "code": _METHOD_NOT_FOUND,
                    "message": f"Unknown method: {method}",
                },
            }

        try:
            result = await handler(params)
            return {"id": request_id, "result": result}
        except Exception as exc:
            logger.exception("Error handling method %s", method)
            return {
                "id": request_id,
                "error": {"code": _INTERNAL_ERROR, "message": str(exc)},
            }

    async def _handle_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        uptime = time.monotonic() - self._start_time
        result: dict[str, Any] = {
            "pid": os.getpid(),
            "uptime": uptime,
            "key_count": len(self._registry.list_identities()),
            "locked": self._locked,
            "polkit_available": self._polkit_available,
        }
        if self._polkit_error:
            result["polkit_error"] = self._polkit_error
        return result

    async def _handle_list_keys(self, _params: dict[str, Any]) -> dict[str, Any]:
        identities = self._registry.list_identities()
        keys = [
            {
                "fingerprint": ident.fingerprint,
                "comment": ident.comment,
                "algorithm": ident.algorithm,
            }
            for ident in identities
        ]
        return {"keys": keys}

    async def _handle_lock(self, _params: dict[str, Any]) -> dict[str, Any]:
        self.lock()
        return {"locked": True}

    async def _handle_unlock(self, params: dict[str, Any]) -> dict[str, Any]:
        # Check polkit authorization for unlock action
        if self._current_conn_ctx is not None and self._config.auth.require_polkit:
            authorized = await self._polkit.check_authorization(
                ACTION_UNLOCK, self._current_conn_ctx, {}
            )
            if not authorized:
                logger.warning(
                    "Unlock denied by polkit: pid=%d",
                    self._current_conn_ctx.peer_pid,
                )
                raise ControlError(_UNAUTHORIZED, "Unlock denied by polkit")

        session_key = params.get("session_key")
        if not session_key:
            raise ControlError(_INVALID_REQUEST, "Missing session_key parameter")

        if self._bitwarden is not None and self._agent_server is not None:
            # Store session key and load keys from Bitwarden
            self._bitwarden.unlock(session_key)
            identities = await self._bitwarden.list_identities(session_key)
            for identity in identities:
                key_data = await self._bitwarden.get_private_key(
                    identity.identity_id, session_key
                )
                self._agent_server.load_key_from_bytes(key_data, identity)
            self._locked = False
            logger.info("Agent unlocked with %d keys", len(identities))
            return {"unlocked": True, "key_count": len(identities)}

        self._locked = False
        return {"unlocked": True}

    async def _handle_sync(self, params: dict[str, Any]) -> dict[str, Any]:
        # Use provided session_key or fall back to stored session
        session_key = params.get("session_key")
        if not session_key and self._bitwarden is not None:
            session_key = self._bitwarden.session_key

        if (
            self._bitwarden is not None
            and session_key
            and self._agent_server is not None
        ):
            identities = await self._bitwarden.list_identities(session_key)
            self._registry.clear()
            for identity in identities:
                key_data = await self._bitwarden.get_private_key(
                    identity.identity_id, session_key
                )
                self._agent_server.load_key_from_bytes(key_data, identity)
            logger.info("Synced %d keys from Bitwarden", len(identities))
            return {"synced": True, "key_count": len(identities)}

        if self._locked:
            msg = "Agent is locked. Run 'bwssh unlock' first."
            raise ControlError(_UNAUTHORIZED, msg)
        return {"synced": True}

    async def _handle_reload_config(self, _params: dict[str, Any]) -> dict[str, Any]:
        self._config = load_config()
        return {"reloaded": True}

    async def serve(self) -> None:
        self._shutdown_event = asyncio.Event()
        self._start_time = time.monotonic()
        self._prepare_runtime_dir()
        self._remove_stale_socket()

        self._server = await asyncio.start_unix_server(
            self.handle_client, path=str(self._socket_path)
        )
        self._socket_path.chmod(0o600)

        logger.info("Control server listening on %s", self._socket_path)

        try:
            await self._shutdown_event.wait()
        finally:
            logger.info("Shutting down control server")
            self._server.close()
            await self._server.wait_closed()
            if self._socket_path.exists():
                self._socket_path.unlink()

    def shutdown(self) -> None:
        if self._shutdown_event is not None:
            self._shutdown_event.set()


class ControlClient:
    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path
        self._request_id = 0

    async def send_command(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._request_id += 1
        request = {"method": method, "id": self._request_id, "params": params}

        reader, writer = await asyncio.open_unix_connection(str(self._socket_path))
        try:
            writer.write(json.dumps(request).encode() + b"\n")
            await writer.drain()

            line = await reader.readline()
            response: dict[str, Any] = json.loads(line.decode())

            if "error" in response:
                error = response["error"]
                raise ControlError(error["code"], error["message"])

            return response["result"]  # type: ignore[no-any-return]
        finally:
            writer.close()
            await writer.wait_closed()
