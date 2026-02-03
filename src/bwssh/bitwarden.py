"""Bitwarden CLI provider for SSH key material."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Any

from bwssh.keys import Identity, compute_fingerprint

logger = logging.getLogger(__name__)

_BW_TIMEOUT_SECONDS = 10.0
_FIXTURES_DIR = Path(__file__).parent.parent.parent / "tests" / "fixtures"


class BitwardenProvider:
    def __init__(self, bw_path: str, item_ids: list[str]) -> None:
        self._bw_path = bw_path
        self._item_ids = item_ids
        self._session_key: str | None = None
        self._cached_identities: list[Identity] = []

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
        item: dict[str, Any] = await self._run_bw(
            "get", "item", identity_id, "--session", session_key
        )

        if "sshKey" not in item:
            msg = f"Item {identity_id} does not contain SSH key data"
            raise ValueError(msg)

        private_key_str: str = item["sshKey"]["privateKey"]
        return private_key_str.encode("utf-8")

    def lock(self) -> None:
        self._session_key = None
        self._cached_identities = []
        logger.info("Bitwarden provider locked")

    def unlock(self, session_key: str) -> None:
        self._session_key = session_key
        logger.info("Bitwarden provider unlocked")

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
    def __init__(self, error: Exception | None = None) -> None:
        self._session_key: str | None = None
        self._error = error
        self._cached_identities: list[Identity] = []

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

    def unlock(self, session_key: str) -> None:
        self._session_key = session_key

    async def healthcheck(self) -> bool:
        if self._error is not None:
            raise self._error
        return self._session_key is not None
