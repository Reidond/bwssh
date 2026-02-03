"""Pytest configuration and shared fixtures for bwssh tests."""

import json
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def ed25519_key_path() -> Path:
    """Path to test ed25519 private key."""
    return FIXTURES_DIR / "id_ed25519"


@pytest.fixture
def rsa_key_path() -> Path:
    """Path to test RSA private key."""
    return FIXTURES_DIR / "id_rsa"


@pytest.fixture
def ecdsa_key_path() -> Path:
    """Path to test ECDSA private key."""
    return FIXTURES_DIR / "id_ecdsa"


@pytest.fixture
def expected_values() -> dict:
    """Load expected fingerprints and key types from JSON."""
    with open(FIXTURES_DIR / "expected.json") as f:
        return json.load(f)


@pytest.fixture
def all_test_keys(
    ed25519_key_path: Path,
    rsa_key_path: Path,
    ecdsa_key_path: Path,
    expected_values: dict,
) -> list[tuple[Path, str, str]]:
    """List of (key_path, expected_fingerprint, expected_type) tuples for all test keys."""
    return [
        (
            ed25519_key_path,
            expected_values["ed25519"]["fingerprint"],
            expected_values["ed25519"]["key_type"],
        ),
        (
            rsa_key_path,
            expected_values["rsa"]["fingerprint"],
            expected_values["rsa"]["key_type"],
        ),
        (
            ecdsa_key_path,
            expected_values["ecdsa"]["fingerprint"],
            expected_values["ecdsa"]["key_type"],
        ),
    ]
