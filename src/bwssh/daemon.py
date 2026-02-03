"""SSH agent daemon — Unix domain socket server."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path

from bwssh.agent_proto import read_message, write_message
from bwssh.constants import SSH_AGENT_FAILURE

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

    @property
    def socket_path(self) -> Path:
        return self._socket_path

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
        try:
            while True:
                _msg_type, _payload = await read_message(reader)
                await write_message(writer, SSH_AGENT_FAILURE, b"")
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

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
