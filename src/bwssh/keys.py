"""SSH key loading, fingerprinting, and registry."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

PrivateKeyTypes = (
    ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
)


def load_private_key(data: bytes, passphrase: bytes | None = None) -> PrivateKeyTypes:
    try:
        key = serialization.load_ssh_private_key(data, password=passphrase)
    except (ValueError, TypeError):
        raise
    except Exception as exc:
        raise ValueError(f"Failed to load SSH private key: {exc}") from exc

    if not isinstance(
        key,
        (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey),
    ):
        msg = f"Unsupported key type: {type(key).__name__}"
        raise ValueError(msg)

    return key


def get_key_type_string(private_key: PrivateKeyTypes) -> str:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return "ssh-ed25519"
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "ssh-rsa"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_name = private_key.curve.name
        curve_map = {
            "secp256r1": "ecdsa-sha2-nistp256",
            "secp384r1": "ecdsa-sha2-nistp384",
            "secp521r1": "ecdsa-sha2-nistp521",
        }
        key_type = curve_map.get(curve_name)
        if key_type is None:
            msg = f"Unsupported EC curve: {curve_name}"
            raise ValueError(msg)
        return key_type

    msg = f"Unsupported key type: {type(private_key).__name__}"
    raise ValueError(msg)


def get_public_key_blob(private_key: PrivateKeyTypes) -> bytes:
    public_key = private_key.public_key()
    ssh_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    # OpenSSH format: "<type> <base64_blob> [comment]"
    parts = ssh_bytes.split(b" ")
    return base64.b64decode(parts[1])


def compute_fingerprint(public_key_blob: bytes) -> str:
    digest = hashlib.sha256(public_key_blob).digest()
    b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64}"


@dataclass
class Identity:
    identity_id: str
    comment: str
    public_key_blob: bytes
    fingerprint: str
    algorithm: str
    source: str


class KeyRegistry:
    def __init__(self) -> None:
        self._identities: dict[bytes, Identity] = {}
        self._private_keys: dict[bytes, PrivateKeyTypes] = {}

    def add_key(self, identity: Identity, private_key: PrivateKeyTypes) -> None:
        self._identities[identity.public_key_blob] = identity
        self._private_keys[identity.public_key_blob] = private_key

    def get_identity(self, blob: bytes) -> Identity | None:
        return self._identities.get(blob)

    def get_private_key(self, blob: bytes) -> PrivateKeyTypes | None:
        return self._private_keys.get(blob)

    def list_identities(self) -> list[Identity]:
        return list(self._identities.values())

    def clear(self) -> None:
        self._identities.clear()
        self._private_keys.clear()
