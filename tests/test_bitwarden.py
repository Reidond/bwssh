"""Tests for Bitwarden CLI provider."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from bwssh.bitwarden import BitwardenProvider, MockBitwardenProvider
from bwssh.keys import load_private_key

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_bw_item(
    item_id: str,
    name: str,
    private_key: str,
    public_key: str,
) -> dict[str, object]:
    return {
        "id": item_id,
        "name": name,
        "type": 2,
        "sshKey": {
            "privateKey": private_key,
            "publicKey": public_key,
        },
        "fields": None,
        "notes": None,
    }


def _load_fixture_key(name: str) -> str:
    return (FIXTURES_DIR / name).read_text()


def _make_bw_status(status: str) -> dict[str, object]:
    return {
        "serverUrl": "https://vault.bitwarden.com",
        "lastSync": "2025-01-01T00:00:00.000Z",
        "status": status,
    }


class TestRunBw:
    """Tests for the _run_bw subprocess wrapper."""

    @pytest.mark.asyncio
    async def test_run_bw_success(self) -> None:
        """Successful bw CLI call returns parsed JSON."""
        provider = BitwardenProvider(bw_path="bw", item_ids=["abc123"])

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b'{"status": "unlocked"}', b""))
        mock_proc.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_proc
        ) as mock_exec:
            result = await provider._run_bw("status", "--session", "test-key")

        assert result == {"status": "unlocked"}
        mock_exec.assert_called_once_with(
            "bw",
            "status",
            "--session",
            "test-key",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    @pytest.mark.asyncio
    async def test_run_bw_timeout(self) -> None:
        """bw CLI call that exceeds timeout raises TimeoutError."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError())
        mock_proc.kill = Mock()
        mock_proc.wait = AsyncMock()

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            pytest.raises(TimeoutError, match="timed out"),
        ):
            await provider._run_bw("list", "items")

        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_bw_nonzero_exit(self) -> None:
        """bw CLI non-zero exit code raises RuntimeError."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"Session key is invalid.")
        )
        mock_proc.returncode = 1

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            pytest.raises(RuntimeError, match="Session key is invalid"),
        ):
            await provider._run_bw("list", "items")

    @pytest.mark.asyncio
    async def test_run_bw_malformed_json(self) -> None:
        """bw CLI returning invalid JSON raises JSONDecodeError."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"not valid json", b""))
        mock_proc.returncode = 0

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            pytest.raises(json.JSONDecodeError),
        ):
            await provider._run_bw("status")

    @pytest.mark.asyncio
    async def test_run_bw_not_found(self) -> None:
        """bw binary not found raises FileNotFoundError."""
        provider = BitwardenProvider(bw_path="/nonexistent/bw", item_ids=[])

        with (
            patch(
                "asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError(
                    "No such file or directory: '/nonexistent/bw'"
                ),
            ),
            pytest.raises(FileNotFoundError, match="/nonexistent/bw"),
        ):
            await provider._run_bw("status")

    @pytest.mark.asyncio
    async def test_run_bw_uses_configured_path(self) -> None:
        """_run_bw uses the configured bw_path."""
        provider = BitwardenProvider(bw_path="/usr/local/bin/bw", item_ids=[])

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"{}", b""))
        mock_proc.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_proc
        ) as mock_exec:
            await provider._run_bw("status")

        mock_exec.assert_called_once_with(
            "/usr/local/bin/bw",
            "status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )


class TestListIdentities:
    """Tests for listing SSH key identities from Bitwarden."""

    @pytest.mark.asyncio
    async def test_list_identities_filtered_by_item_ids(self) -> None:
        """Only items matching configured item_ids are returned."""
        ed25519_priv = _load_fixture_key("id_ed25519")
        ed25519_pub = _load_fixture_key("id_ed25519.pub")

        items = [
            _make_bw_item("item-1", "Key 1", ed25519_priv, ed25519_pub),
            _make_bw_item("item-2", "Key 2", ed25519_priv, ed25519_pub),
            _make_bw_item("item-3", "Key 3", ed25519_priv, ed25519_pub),
        ]

        provider = BitwardenProvider(bw_path="bw", item_ids=["item-1", "item-3"])

        with patch.object(provider, "_run_bw", return_value=items):
            identities = await provider.list_identities("test-session")

        assert len(identities) == 2
        assert identities[0].identity_id == "item-1"
        assert identities[1].identity_id == "item-3"

    @pytest.mark.asyncio
    async def test_list_identities_skips_items_without_ssh_key(self) -> None:
        """Items without sshKey field are skipped."""
        items = [
            {
                "id": "item-1",
                "name": "Login Item",
                "type": 1,
                "fields": None,
                "notes": None,
            },
        ]

        provider = BitwardenProvider(bw_path="bw", item_ids=["item-1"])

        with patch.object(provider, "_run_bw", return_value=items):
            identities = await provider.list_identities("test-session")

        assert len(identities) == 0

    @pytest.mark.asyncio
    async def test_list_identities_extracts_correct_fields(self) -> None:
        """Identity fields are correctly extracted from Bitwarden item."""
        ed25519_priv = _load_fixture_key("id_ed25519")
        ed25519_pub = _load_fixture_key("id_ed25519.pub")

        items = [
            _make_bw_item("abc123", "My SSH Key", ed25519_priv, ed25519_pub),
        ]

        provider = BitwardenProvider(bw_path="bw", item_ids=["abc123"])

        with patch.object(provider, "_run_bw", return_value=items):
            identities = await provider.list_identities("test-session")

        assert len(identities) == 1
        identity = identities[0]
        assert identity.identity_id == "abc123"
        assert identity.comment == "My SSH Key"
        assert identity.algorithm == "ssh-ed25519"
        assert identity.source == "bitwarden"
        assert identity.fingerprint.startswith("SHA256:")
        assert len(identity.public_key_blob) > 0

    @pytest.mark.asyncio
    async def test_list_identities_passes_session_key(self) -> None:
        """Session key is passed to bw CLI."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])

        with patch.object(provider, "_run_bw", return_value=[]) as mock_run:
            await provider.list_identities("my-secret-session")

        mock_run.assert_called_once_with(
            "list", "items", "--session", "my-secret-session"
        )

    @pytest.mark.asyncio
    async def test_list_identities_empty_item_ids(self) -> None:
        """Empty item_ids returns empty list even with items available."""
        ed25519_priv = _load_fixture_key("id_ed25519")
        ed25519_pub = _load_fixture_key("id_ed25519.pub")

        items = [
            _make_bw_item("item-1", "Key 1", ed25519_priv, ed25519_pub),
        ]

        provider = BitwardenProvider(bw_path="bw", item_ids=[])

        with patch.object(provider, "_run_bw", return_value=items):
            identities = await provider.list_identities("test-session")

        assert len(identities) == 0


class TestGetPrivateKey:
    """Tests for retrieving private key material."""

    @pytest.mark.asyncio
    async def test_get_private_key_returns_bytes(self) -> None:
        """Private key is returned as raw bytes."""
        ed25519_priv = _load_fixture_key("id_ed25519")
        ed25519_pub = _load_fixture_key("id_ed25519.pub")

        item = _make_bw_item("abc123", "My Key", ed25519_priv, ed25519_pub)

        provider = BitwardenProvider(bw_path="bw", item_ids=["abc123"])

        with patch.object(provider, "_run_bw", return_value=item):
            key_bytes = await provider.get_private_key("abc123", "test-session")

        assert isinstance(key_bytes, bytes)
        assert b"OPENSSH PRIVATE KEY" in key_bytes

    @pytest.mark.asyncio
    async def test_get_private_key_passes_correct_args(self) -> None:
        """get_private_key calls bw get item with correct arguments."""
        ed25519_priv = _load_fixture_key("id_ed25519")
        ed25519_pub = _load_fixture_key("id_ed25519.pub")

        item = _make_bw_item("abc123", "My Key", ed25519_priv, ed25519_pub)

        provider = BitwardenProvider(bw_path="bw", item_ids=["abc123"])

        with patch.object(provider, "_run_bw", return_value=item) as mock_run:
            await provider.get_private_key("abc123", "my-session")

        mock_run.assert_called_once_with(
            "get", "item", "abc123", "--session", "my-session"
        )

    @pytest.mark.asyncio
    async def test_get_private_key_missing_ssh_key_field(self) -> None:
        """Item without sshKey field raises ValueError."""
        item: dict[str, object] = {
            "id": "abc123",
            "name": "Login Item",
            "type": 1,
        }

        provider = BitwardenProvider(bw_path="bw", item_ids=["abc123"])

        with (
            patch.object(provider, "_run_bw", return_value=item),
            pytest.raises(ValueError, match="does not contain SSH key"),
        ):
            await provider.get_private_key("abc123", "test-session")

    @pytest.mark.asyncio
    async def test_get_private_key_loadable(self) -> None:
        """Returned key bytes can be loaded by load_private_key."""
        ed25519_priv = _load_fixture_key("id_ed25519")
        ed25519_pub = _load_fixture_key("id_ed25519.pub")

        item = _make_bw_item("abc123", "My Key", ed25519_priv, ed25519_pub)

        provider = BitwardenProvider(bw_path="bw", item_ids=["abc123"])

        with patch.object(provider, "_run_bw", return_value=item):
            key_bytes = await provider.get_private_key("abc123", "test-session")

        key = load_private_key(key_bytes)
        assert key is not None


class TestHealthcheck:
    """Tests for the healthcheck method."""

    @pytest.mark.asyncio
    async def test_healthcheck_unlocked(self) -> None:
        """Healthcheck returns True when status is 'unlocked'."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider._session_key = "test-session"

        status = _make_bw_status("unlocked")

        with patch.object(provider, "_run_bw", return_value=status):
            result = await provider.healthcheck()

        assert result is True

    @pytest.mark.asyncio
    async def test_healthcheck_locked(self) -> None:
        """Healthcheck returns False when status is 'locked'."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider._session_key = "test-session"

        status = _make_bw_status("locked")

        with patch.object(provider, "_run_bw", return_value=status):
            result = await provider.healthcheck()

        assert result is False

    @pytest.mark.asyncio
    async def test_healthcheck_no_session_key(self) -> None:
        """Healthcheck returns False when no session key is stored."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])

        result = await provider.healthcheck()

        assert result is False

    @pytest.mark.asyncio
    async def test_healthcheck_bw_error(self) -> None:
        """Healthcheck returns False on bw CLI error."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider._session_key = "test-session"

        with patch.object(provider, "_run_bw", side_effect=RuntimeError("bw failed")):
            result = await provider.healthcheck()

        assert result is False

    @pytest.mark.asyncio
    async def test_healthcheck_passes_session_key(self) -> None:
        """Healthcheck passes stored session key to bw CLI."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider._session_key = "secret-session-key"

        status = _make_bw_status("unlocked")

        with patch.object(provider, "_run_bw", return_value=status) as mock_run:
            await provider.healthcheck()

        mock_run.assert_called_once_with("status", "--session", "secret-session-key")


class TestLockUnlock:
    """Tests for lock and unlock session key management."""

    def test_initial_state_no_session_key(self) -> None:
        """Provider starts with no session key."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        assert provider._session_key is None

    def test_unlock_stores_session_key(self) -> None:
        """Unlock stores the session key in memory."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider.unlock("new-session-key")
        assert provider._session_key == "new-session-key"

    def test_lock_clears_session_key(self) -> None:
        """Lock clears the stored session key."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider.unlock("session-key")
        provider.lock()
        assert provider._session_key is None

    def test_lock_clears_cached_identities(self) -> None:
        """Lock clears cached identities."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider._cached_identities = [object()]  # type: ignore[list-item]
        provider.lock()
        assert provider._cached_identities == []

    def test_unlock_replaces_session_key(self) -> None:
        """Unlock replaces existing session key."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        provider.unlock("first-key")
        provider.unlock("second-key")
        assert provider._session_key == "second-key"

    def test_is_unlocked_property(self) -> None:
        """is_unlocked property returns correct state."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        assert provider.is_unlocked is False
        provider.unlock("session-key")
        assert provider.is_unlocked is True
        provider.lock()
        assert provider.is_unlocked is False

    def test_session_key_property(self) -> None:
        """session_key property returns stored key or None."""
        provider = BitwardenProvider(bw_path="bw", item_ids=[])
        assert provider.session_key is None
        provider.unlock("my-secret-key")
        assert provider.session_key == "my-secret-key"
        provider.lock()
        assert provider.session_key is None


class TestMockBitwardenProvider:
    """Tests for the mock provider used in testing."""

    @pytest.mark.asyncio
    async def test_mock_list_identities(self) -> None:
        """Mock provider returns configured identities."""
        mock = MockBitwardenProvider()
        identities = await mock.list_identities("any-session")
        assert len(identities) >= 1
        assert identities[0].algorithm == "ssh-ed25519"

    @pytest.mark.asyncio
    async def test_mock_get_private_key(self) -> None:
        """Mock provider returns fixture key bytes."""
        mock = MockBitwardenProvider()
        key_bytes = await mock.get_private_key("test-id", "any-session")
        assert b"OPENSSH PRIVATE KEY" in key_bytes

    @pytest.mark.asyncio
    async def test_mock_healthcheck_unlocked(self) -> None:
        """Mock provider healthcheck returns True after unlock."""
        mock = MockBitwardenProvider()
        mock.unlock("session")
        assert await mock.healthcheck() is True

    @pytest.mark.asyncio
    async def test_mock_healthcheck_locked(self) -> None:
        """Mock provider healthcheck returns False when locked."""
        mock = MockBitwardenProvider()
        assert await mock.healthcheck() is False

    def test_mock_lock_unlock(self) -> None:
        """Mock provider lock/unlock toggles state."""
        mock = MockBitwardenProvider()
        mock.unlock("key")
        assert mock._session_key == "key"
        mock.lock()
        assert mock._session_key is None

    @pytest.mark.asyncio
    async def test_mock_configurable_error(self) -> None:
        """Mock provider can be configured to raise errors."""
        mock = MockBitwardenProvider(error=RuntimeError("bw failed"))
        with pytest.raises(RuntimeError, match="bw failed"):
            await mock.list_identities("session")

    def test_mock_is_unlocked_property(self) -> None:
        """Mock provider is_unlocked property works correctly."""
        mock = MockBitwardenProvider()
        assert mock.is_unlocked is False
        mock.unlock("session")
        assert mock.is_unlocked is True

    def test_mock_session_key_property(self) -> None:
        """Mock provider session_key property works correctly."""
        mock = MockBitwardenProvider()
        assert mock.session_key is None
        mock.unlock("my-session")
        assert mock.session_key == "my-session"

    @pytest.mark.asyncio
    async def test_mock_unlock_interactive(self) -> None:
        """Mock provider unlock_interactive returns mock session key."""
        mock = MockBitwardenProvider(mock_session_key="custom-session")
        session_key = await mock.unlock_interactive()
        assert session_key == "custom-session"
        assert mock._session_key == "custom-session"
        assert mock.is_unlocked is True

    @pytest.mark.asyncio
    async def test_mock_unlock_interactive_with_error(self) -> None:
        """Mock provider unlock_interactive raises configured error."""
        mock = MockBitwardenProvider(error=RuntimeError("unlock failed"))
        with pytest.raises(RuntimeError, match="unlock failed"):
            await mock.unlock_interactive()
