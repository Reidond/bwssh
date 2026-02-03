"""Tests for bwssh.keys — SSH key parsing, fingerprinting, and registry."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from bwssh.keys import (
    Identity,
    KeyRegistry,
    PrivateKeyTypes,
    compute_fingerprint,
    get_key_type_string,
    get_public_key_blob,
    load_private_key,
)


class TestLoadPrivateKey:
    def test_load_ed25519(self, ed25519_key_path: Path) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        assert key is not None

    def test_load_rsa(self, rsa_key_path: Path) -> None:
        key = load_private_key(rsa_key_path.read_bytes())
        assert key is not None

    def test_load_ecdsa(self, ecdsa_key_path: Path) -> None:
        key = load_private_key(ecdsa_key_path.read_bytes())
        assert key is not None

    def test_load_invalid_data_raises(self) -> None:
        with pytest.raises((ValueError, Exception)):
            load_private_key(b"not a valid key")

    def test_load_empty_data_raises(self) -> None:
        with pytest.raises((ValueError, Exception)):
            load_private_key(b"")


class TestGetKeyTypeString:
    def test_ed25519_type(self, ed25519_key_path: Path) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        assert get_key_type_string(key) == "ssh-ed25519"

    def test_rsa_type(self, rsa_key_path: Path) -> None:
        key = load_private_key(rsa_key_path.read_bytes())
        assert get_key_type_string(key) == "ssh-rsa"

    def test_ecdsa_type(self, ecdsa_key_path: Path) -> None:
        key = load_private_key(ecdsa_key_path.read_bytes())
        assert get_key_type_string(key) == "ecdsa-sha2-nistp256"


class TestGetPublicKeyBlob:
    def test_ed25519_blob_not_empty(self, ed25519_key_path: Path) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        blob = get_public_key_blob(key)
        assert len(blob) > 0

    def test_rsa_blob_not_empty(self, rsa_key_path: Path) -> None:
        key = load_private_key(rsa_key_path.read_bytes())
        blob = get_public_key_blob(key)
        assert len(blob) > 0

    def test_ecdsa_blob_not_empty(self, ecdsa_key_path: Path) -> None:
        key = load_private_key(ecdsa_key_path.read_bytes())
        blob = get_public_key_blob(key)
        assert len(blob) > 0

    def test_blob_starts_with_key_type(self, ed25519_key_path: Path) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        blob = get_public_key_blob(key)
        # Wire format: uint32 length prefix + key type string
        type_len = struct.unpack(">I", blob[:4])[0]
        type_str = blob[4 : 4 + type_len].decode("ascii")
        assert type_str == "ssh-ed25519"

    def test_deterministic_blob(self, rsa_key_path: Path) -> None:
        key = load_private_key(rsa_key_path.read_bytes())
        blob1 = get_public_key_blob(key)
        blob2 = get_public_key_blob(key)
        assert blob1 == blob2


class TestComputeFingerprint:
    def test_ed25519_fingerprint(
        self, ed25519_key_path: Path, expected_values: dict[str, dict[str, str]]
    ) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        blob = get_public_key_blob(key)
        fp = compute_fingerprint(blob)
        assert fp == expected_values["ed25519"]["fingerprint"]

    def test_rsa_fingerprint(
        self, rsa_key_path: Path, expected_values: dict[str, dict[str, str]]
    ) -> None:
        key = load_private_key(rsa_key_path.read_bytes())
        blob = get_public_key_blob(key)
        fp = compute_fingerprint(blob)
        assert fp == expected_values["rsa"]["fingerprint"]

    def test_ecdsa_fingerprint(
        self, ecdsa_key_path: Path, expected_values: dict[str, dict[str, str]]
    ) -> None:
        key = load_private_key(ecdsa_key_path.read_bytes())
        blob = get_public_key_blob(key)
        fp = compute_fingerprint(blob)
        assert fp == expected_values["ecdsa"]["fingerprint"]

    def test_fingerprint_format(self, ed25519_key_path: Path) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        blob = get_public_key_blob(key)
        fp = compute_fingerprint(blob)
        assert fp.startswith("SHA256:")
        assert not fp.endswith("=")

    def test_different_keys_different_fingerprints(
        self, ed25519_key_path: Path, rsa_key_path: Path
    ) -> None:
        k1 = load_private_key(ed25519_key_path.read_bytes())
        k2 = load_private_key(rsa_key_path.read_bytes())
        fp1 = compute_fingerprint(get_public_key_blob(k1))
        fp2 = compute_fingerprint(get_public_key_blob(k2))
        assert fp1 != fp2


class TestAllKeys:
    def test_load_and_fingerprint_all(
        self, all_test_keys: list[tuple[Path, str, str]]
    ) -> None:
        for key_path, expected_fp, expected_type in all_test_keys:
            key = load_private_key(key_path.read_bytes())
            blob = get_public_key_blob(key)
            assert compute_fingerprint(blob) == expected_fp
            assert get_key_type_string(key) == expected_type


class TestIdentity:
    def test_create_identity(self) -> None:
        ident = Identity(
            identity_id="test-id",
            comment="test key",
            public_key_blob=b"\x00\x01\x02",
            fingerprint="SHA256:abc",
            algorithm="ssh-ed25519",
            source="test",
        )
        assert ident.identity_id == "test-id"
        assert ident.comment == "test key"
        assert ident.public_key_blob == b"\x00\x01\x02"
        assert ident.fingerprint == "SHA256:abc"
        assert ident.algorithm == "ssh-ed25519"
        assert ident.source == "test"

    def test_identity_from_key(self, ed25519_key_path: Path) -> None:
        key = load_private_key(ed25519_key_path.read_bytes())
        blob = get_public_key_blob(key)
        fp = compute_fingerprint(blob)
        algo = get_key_type_string(key)

        ident = Identity(
            identity_id=fp,
            comment="ed25519 test key",
            public_key_blob=blob,
            fingerprint=fp,
            algorithm=algo,
            source="test",
        )
        assert ident.algorithm == "ssh-ed25519"
        assert ident.fingerprint.startswith("SHA256:")


class TestKeyRegistry:
    def _make_identity_and_key(
        self, key_path: Path
    ) -> tuple[Identity, PrivateKeyTypes]:
        key = load_private_key(key_path.read_bytes())
        blob = get_public_key_blob(key)
        fp = compute_fingerprint(blob)
        algo = get_key_type_string(key)
        ident = Identity(
            identity_id=fp,
            comment="test",
            public_key_blob=blob,
            fingerprint=fp,
            algorithm=algo,
            source="test",
        )
        return ident, key

    def test_add_and_get_identity(self, ed25519_key_path: Path) -> None:
        registry = KeyRegistry()
        ident, key = self._make_identity_and_key(ed25519_key_path)

        registry.add_key(ident, key)
        result = registry.get_identity(ident.public_key_blob)
        assert result is not None
        assert result.fingerprint == ident.fingerprint

    def test_get_private_key(self, ed25519_key_path: Path) -> None:
        registry = KeyRegistry()
        ident, key = self._make_identity_and_key(ed25519_key_path)

        registry.add_key(ident, key)
        result = registry.get_private_key(ident.public_key_blob)
        assert result is key

    def test_get_missing_identity_returns_none(self) -> None:
        registry = KeyRegistry()
        assert registry.get_identity(b"nonexistent") is None

    def test_get_missing_key_returns_none(self) -> None:
        registry = KeyRegistry()
        assert registry.get_private_key(b"nonexistent") is None

    def test_list_identities(
        self,
        ed25519_key_path: Path,
        rsa_key_path: Path,
        ecdsa_key_path: Path,
    ) -> None:
        registry = KeyRegistry()
        for path in (ed25519_key_path, rsa_key_path, ecdsa_key_path):
            ident, key = self._make_identity_and_key(path)
            registry.add_key(ident, key)

        identities = registry.list_identities()
        assert len(identities) == 3

    def test_clear(self, ed25519_key_path: Path) -> None:
        registry = KeyRegistry()
        ident, key = self._make_identity_and_key(ed25519_key_path)
        registry.add_key(ident, key)

        registry.clear()
        assert registry.list_identities() == []
        assert registry.get_identity(ident.public_key_blob) is None
        assert registry.get_private_key(ident.public_key_blob) is None
