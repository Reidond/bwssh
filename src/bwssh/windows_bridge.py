"""WSL bridge to a Windows SSH agent exposed via named pipe relay."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass

from bwssh.agent_proto import unpack_string, unpack_uint32
from bwssh.constants import SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENTC_REQUEST_IDENTITIES
from bwssh.keys import compute_fingerprint

logger = logging.getLogger(__name__)


@dataclass
class BridgeIdentity:
    """Public identity metadata returned by an upstream SSH agent."""

    algorithm: str
    comment: str
    fingerprint: str


class WindowsAgentBridge:
    """Proxy helper for talking to a Windows SSH agent from WSL.

    The relay command should bridge stdin/stdout to a Windows named pipe,
    e.g. with ``npiperelay.exe``.
    """

    def __init__(self, relay_command: list[str], timeout_seconds: float = 5.0) -> None:
        if not relay_command:
            raise ValueError("relay_command must not be empty")
        self._relay_command = relay_command
        self._timeout_seconds = timeout_seconds

    async def proxy_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Proxy a connected UNIX-socket client to the Windows relay process."""
        proc = await asyncio.create_subprocess_exec(
            *self._relay_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        relay_stdin = proc.stdin
        relay_stdout = proc.stdout
        assert relay_stdin is not None
        assert relay_stdout is not None

        async def _client_to_relay() -> None:
            try:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    relay_stdin.write(chunk)
                    await relay_stdin.drain()
            finally:
                with contextlib.suppress(BrokenPipeError):
                    relay_stdin.close()
                with contextlib.suppress(Exception):
                    await relay_stdin.wait_closed()

        async def _relay_to_client() -> None:
            while True:
                chunk = await relay_stdout.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()

        in_task = asyncio.create_task(_client_to_relay())
        out_task = asyncio.create_task(_relay_to_client())
        done, pending = await asyncio.wait(
            {in_task, out_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        if proc.returncode is None:
            proc.terminate()
            with contextlib.suppress(ProcessLookupError):
                await asyncio.wait_for(proc.wait(), timeout=0.5)

        for task in done:
            with contextlib.suppress(asyncio.CancelledError, BrokenPipeError):
                task.result()

        writer.close()
        await writer.wait_closed()

    async def list_identities(self) -> list[BridgeIdentity]:
        """Query identities from upstream agent via relay."""
        payload = await self._request(SSH_AGENTC_REQUEST_IDENTITIES, b"")
        count, offset = unpack_uint32(payload, 0)
        identities: list[BridgeIdentity] = []
        for _ in range(count):
            blob, offset = unpack_string(payload, offset)
            comment_bytes, offset = unpack_string(payload, offset)
            algorithm = self._algorithm_from_blob(blob)
            identities.append(
                BridgeIdentity(
                    algorithm=algorithm,
                    comment=comment_bytes.decode("utf-8", errors="replace"),
                    fingerprint=compute_fingerprint(blob),
                )
            )
        return identities

    async def is_unlocked(self) -> bool:
        """Treat the bridge as unlocked when at least one identity is visible."""
        try:
            return len(await self.list_identities()) > 0
        except Exception:
            logger.debug("Failed to query upstream identities", exc_info=True)
            return False

    async def _request(self, msg_type: int, payload: bytes) -> bytes:
        frame = (1 + len(payload)).to_bytes(4, "big") + bytes([msg_type]) + payload
        proc = await asyncio.create_subprocess_exec(
            *self._relay_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        relay_stdin = proc.stdin
        relay_stdout = proc.stdout
        assert relay_stdin is not None
        assert relay_stdout is not None

        relay_stdin.write(frame)
        await relay_stdin.drain()
        relay_stdin.close()
        with contextlib.suppress(Exception):
            await relay_stdin.wait_closed()

        raw_len = await asyncio.wait_for(
            relay_stdout.readexactly(4), timeout=self._timeout_seconds
        )
        resp_len = int.from_bytes(raw_len, "big")
        raw_body = await asyncio.wait_for(
            relay_stdout.readexactly(resp_len), timeout=self._timeout_seconds
        )
        msg = raw_body[0]
        body = raw_body[1:]

        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=0.5)

        if msg != SSH_AGENT_IDENTITIES_ANSWER:
            raise RuntimeError(f"Unexpected SSH agent reply type: {msg}")
        return body

    def _algorithm_from_blob(self, blob: bytes) -> str:
        try:
            algorithm, _ = unpack_string(blob, 0)
            algorithm_bytes = bytes(algorithm)
            return algorithm_bytes.decode("utf-8", errors="replace")
        except Exception:
            return "unknown"
