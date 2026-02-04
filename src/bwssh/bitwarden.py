"""Bitwarden CLI provider for SSH key material."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import os
import pty
import sys
import termios
import tty
from pathlib import Path
from typing import Any, Protocol

from bwssh.keys import Identity, compute_fingerprint

logger = logging.getLogger(__name__)

# Longer timeout for interactive unlock (user needs to type password)
_BW_UNLOCK_TIMEOUT_SECONDS = 120.0


class BitwardenLike(Protocol):
    """Protocol for Bitwarden provider implementations."""

    async def list_identities(self, session_key: str) -> list[Identity]: ...

    async def get_private_key(self, identity_id: str, session_key: str) -> bytes: ...

    def lock(self) -> None: ...

    def unlock(self, session_key: str) -> None: ...

    async def healthcheck(self) -> bool: ...

    async def unlock_interactive(self) -> str:
        """Run bw unlock interactively, returning session key."""
        ...

    @property
    def is_unlocked(self) -> bool:
        """Return True if the provider has a valid session."""
        ...

    @property
    def session_key(self) -> str | None:
        """Return the current session key, or None if locked."""
        ...


_BW_TIMEOUT_SECONDS = 10.0
_FIXTURES_DIR = Path(__file__).parent.parent.parent / "tests" / "fixtures"


class BitwardenProvider:
    def __init__(self, bw_path: str, item_ids: list[str]) -> None:
        self._bw_path = bw_path
        self._item_ids = item_ids
        self._session_key: str | None = None
        self._cached_identities: list[Identity] = []
        self._private_key_cache: dict[str, bytes] = {}  # identity_id -> private key

    async def _run_bw(self, *args: str) -> Any:
        proc = await asyncio.create_subprocess_exec(
            self._bw_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_BW_TIMEOUT_SECONDS
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            msg = f"bw command timed out after {_BW_TIMEOUT_SECONDS}s"
            raise TimeoutError(msg) from None

        if proc.returncode != 0:
            msg = f"bw failed (exit {proc.returncode}): {stderr.decode().strip()}"
            raise RuntimeError(msg)

        return json.loads(stdout)

    async def list_identities(self, session_key: str) -> list[Identity]:
        items: list[dict[str, Any]] = await self._run_bw(
            "list", "items", "--session", session_key
        )

        identities: list[Identity] = []
        for item in items:
            if item["id"] not in self._item_ids:
                continue
            if "sshKey" not in item:
                continue

            ssh_key = item["sshKey"]
            public_key_str: str = ssh_key["publicKey"]
            identity = self._parse_identity(item["id"], item["name"], public_key_str)
            identities.append(identity)

            # Cache private key to avoid separate get_private_key calls
            if "privateKey" in ssh_key:
                self._private_key_cache[item["id"]] = ssh_key["privateKey"].encode(
                    "utf-8"
                )

        self._cached_identities = identities
        return identities

    def _parse_identity(
        self, item_id: str, name: str, public_key_line: str
    ) -> Identity:
        parts = public_key_line.strip().split()
        algorithm = parts[0]
        public_key_blob = base64.b64decode(parts[1])
        fingerprint = compute_fingerprint(public_key_blob)

        return Identity(
            identity_id=item_id,
            comment=name,
            public_key_blob=public_key_blob,
            fingerprint=fingerprint,
            algorithm=algorithm,
            source="bitwarden",
        )

    async def get_private_key(self, identity_id: str, session_key: str) -> bytes:
        # Return from cache if available (populated by list_identities)
        if identity_id in self._private_key_cache:
            logger.debug("Using cached private key for %s", identity_id)
            return self._private_key_cache[identity_id]

        # Fallback: fetch individually (slower path)
        logger.debug("Fetching private key for %s (cache miss)", identity_id)
        item: dict[str, Any] = await self._run_bw(
            "get", "item", identity_id, "--session", session_key
        )

        if "sshKey" not in item:
            msg = f"Item {identity_id} does not contain SSH key data"
            raise ValueError(msg)

        private_key_str: str = item["sshKey"]["privateKey"]
        private_key_bytes = private_key_str.encode("utf-8")

        # Cache for future use
        self._private_key_cache[identity_id] = private_key_bytes
        return private_key_bytes

    def lock(self) -> None:
        self._session_key = None
        self._cached_identities = []
        self._private_key_cache.clear()
        logger.info("Bitwarden provider locked")

    def unlock(self, session_key: str) -> None:
        self._session_key = session_key
        logger.info("Bitwarden provider unlocked")

    @property
    def is_unlocked(self) -> bool:
        """Return True if the provider has a valid session."""
        return self._session_key is not None

    @property
    def session_key(self) -> str | None:
        """Return the current session key, or None if locked."""
        return self._session_key

    async def unlock_interactive(self) -> str:
        """Run bw unlock interactively, returning session key.

        This method allocates a PTY and forwards I/O to the user's terminal,
        allowing them to enter their Bitwarden master password. The session
        key is captured from stdout and returned.

        Raises:
            RuntimeError: If unlock fails or times out.
            OSError: If terminal I/O fails.
        """
        logger.info("Starting interactive Bitwarden unlock")

        # Create a pseudo-terminal for the bw process
        master_fd, slave_fd = pty.openpty()

        try:
            # Start bw unlock with PTY for password input
            proc = await asyncio.create_subprocess_exec(
                self._bw_path,
                "unlock",
                "--raw",
                stdin=slave_fd,
                stdout=asyncio.subprocess.PIPE,
                stderr=slave_fd,
            )
            os.close(slave_fd)
            slave_fd = -1

            # Forward I/O between user's terminal and bw process
            session_key = await self._forward_pty_io(master_fd, proc)

            if not session_key:
                msg = "Bitwarden unlock failed: no session key returned"
                raise RuntimeError(msg)

            # Store the session key
            self._session_key = session_key
            logger.info("Bitwarden unlock successful")
            return session_key

        finally:
            if slave_fd >= 0:
                os.close(slave_fd)
            os.close(master_fd)

    async def _forward_pty_io(
        self, master_fd: int, proc: asyncio.subprocess.Process
    ) -> str:
        """Forward I/O between user's terminal and PTY."""
        stdin_fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(stdin_fd) if sys.stdin.isatty() else None

        if old_settings is not None:
            tty.setraw(stdin_fd)

        try:
            stdout_data = await self._run_pty_io_loop(master_fd, stdin_fd, proc)
        finally:
            if old_settings is not None:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)
            print()  # Newline after password entry

        if proc.returncode != 0:
            msg = f"bw unlock failed with exit code {proc.returncode}"
            raise RuntimeError(msg)

        return stdout_data.decode().strip()

    async def _run_pty_io_loop(
        self, master_fd: int, stdin_fd: int, proc: asyncio.subprocess.Process
    ) -> bytes:
        """Run the PTY I/O loop, returning captured stdout."""
        loop = asyncio.get_event_loop()
        stdout_data = b""

        async def read_stdin() -> None:
            while proc.returncode is None:
                try:
                    data = await loop.run_in_executor(
                        None, lambda: os.read(stdin_fd, 1024)
                    )
                    if data:
                        os.write(master_fd, data)
                except OSError:
                    break

        async def read_pty() -> None:
            while proc.returncode is None:
                try:
                    data = await loop.run_in_executor(
                        None, lambda: os.read(master_fd, 1024)
                    )
                    if data:
                        os.write(sys.stdout.fileno(), data)
                        sys.stdout.flush()
                except OSError:
                    break

        async def read_stdout() -> bytes:
            nonlocal stdout_data
            assert proc.stdout is not None
            try:
                stdout_data = await asyncio.wait_for(
                    proc.stdout.read(), timeout=_BW_UNLOCK_TIMEOUT_SECONDS
                )
            except TimeoutError:
                proc.kill()
                msg = f"bw unlock timed out after {_BW_UNLOCK_TIMEOUT_SECONDS}s"
                raise TimeoutError(msg) from None
            return stdout_data

        stdin_task = asyncio.create_task(read_stdin())
        pty_task = asyncio.create_task(read_pty())
        stdout_task = asyncio.create_task(read_stdout())

        await proc.wait()
        stdin_task.cancel()
        pty_task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            stdout_data = await stdout_task

        return stdout_data

    async def healthcheck(self) -> bool:
        if self._session_key is None:
            return False

        try:
            status: dict[str, Any] = await self._run_bw(
                "status", "--session", self._session_key
            )
            return status.get("status") == "unlocked"
        except Exception:
            logger.warning("Bitwarden healthcheck failed", exc_info=True)
            return False


class MockBitwardenProvider:
    def __init__(
        self, error: Exception | None = None, mock_session_key: str = "mock-session"
    ) -> None:
        self._session_key: str | None = None
        self._error = error
        self._cached_identities: list[Identity] = []
        self._private_key_cache: dict[str, bytes] = {}
        self._mock_session_key = mock_session_key

    async def list_identities(self, _session_key: str) -> list[Identity]:
        if self._error is not None:
            raise self._error

        ed25519_pub = (_FIXTURES_DIR / "id_ed25519.pub").read_text()
        provider = BitwardenProvider(bw_path="bw", item_ids=["mock-id"])
        identity = provider._parse_identity("mock-id", "Mock ED25519 Key", ed25519_pub)
        return [identity]

    async def get_private_key(self, _identity_id: str, _session_key: str) -> bytes:
        if self._error is not None:
            raise self._error

        return (_FIXTURES_DIR / "id_ed25519").read_bytes()

    def lock(self) -> None:
        self._session_key = None
        self._cached_identities = []
        self._private_key_cache.clear()

    def unlock(self, session_key: str) -> None:
        self._session_key = session_key

    @property
    def is_unlocked(self) -> bool:
        """Return True if the provider has a valid session."""
        return self._session_key is not None

    @property
    def session_key(self) -> str | None:
        """Return the current session key, or None if locked."""
        return self._session_key

    async def unlock_interactive(self) -> str:
        """Mock interactive unlock - returns mock session key."""
        if self._error is not None:
            raise self._error
        self._session_key = self._mock_session_key
        return self._mock_session_key

    async def healthcheck(self) -> bool:
        if self._error is not None:
            raise self._error
        return self._session_key is not None
