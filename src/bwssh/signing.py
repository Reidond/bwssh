"""SSH agent signing operations for ed25519, RSA, and ECDSA keys.

Implements the cryptographic signing dispatched by SIGN_REQUEST and builds
SSH-format signature blobs per IETF draft-miller-ssh-agent §4.5.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from bwssh.agent_proto import pack_string
from bwssh.constants import SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512

if TYPE_CHECKING:
    from bwssh.keys import PrivateKeyTypes


def sign_ed25519(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign *data* with an Ed25519 key (pure EdDSA, no separate hash)."""
    return private_key.sign(data)


def sign_rsa(
    private_key: rsa.RSAPrivateKey, data: bytes, flags: int
) -> tuple[bytes, str]:
    """Sign *data* with an RSA key using PKCS1v15 padding.

    Returns ``(signature_bytes, algorithm_name)`` because the SSH algorithm
    string depends on the hash chosen via *flags*.
    """
    if flags & SSH_AGENT_RSA_SHA2_512:
        hash_algo: hashes.HashAlgorithm = hashes.SHA512()
        algorithm = "rsa-sha2-512"
    elif flags & SSH_AGENT_RSA_SHA2_256:
        hash_algo = hashes.SHA256()
        algorithm = "rsa-sha2-256"
    else:
        hash_algo = hashes.SHA1()
        algorithm = "ssh-rsa"

    signature = private_key.sign(data, padding.PKCS1v15(), hash_algo)
    return signature, algorithm


def _mpint(value: int) -> bytes:
    """Encode an integer as an SSH mpint (big-endian, minimal length, sign-extended)."""
    if value == 0:
        return b""
    byte_length = (value.bit_length() + 8) // 8  # +8 for sign bit
    return value.to_bytes(byte_length, byteorder="big")


def sign_ecdsa(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign *data* with an ECDSA key.

    The hash algorithm is determined by the curve.  The DER-encoded
    signature is converted to the raw ``r || s`` format used by SSH.
    """
    curve_name = private_key.curve.name
    curve_hashes: dict[str, hashes.HashAlgorithm] = {
        "secp256r1": hashes.SHA256(),
        "secp384r1": hashes.SHA384(),
        "secp521r1": hashes.SHA512(),
    }
    hash_algo = curve_hashes.get(curve_name)
    if hash_algo is None:
        msg = f"Unsupported ECDSA curve: {curve_name}"
        raise ValueError(msg)

    der_sig = private_key.sign(data, ec.ECDSA(hash_algo))
    r, s = utils.decode_dss_signature(der_sig)
    return pack_string(_mpint(r)) + pack_string(_mpint(s))


def sign_data(
    private_key: PrivateKeyTypes, data: bytes, flags: int
) -> tuple[bytes, str]:
    """Dispatch signing to the appropriate algorithm.

    Returns ``(raw_signature_bytes, algorithm_name)`` so the caller can
    build the SSH signature blob with the correct algorithm string.
    """
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return sign_ed25519(private_key, data), "ssh-ed25519"
    if isinstance(private_key, rsa.RSAPrivateKey):
        return sign_rsa(private_key, data, flags)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = _ecdsa_algorithm(private_key)
        return sign_ecdsa(private_key, data), algorithm

    msg = f"Unsupported key type: {type(private_key).__name__}"
    raise TypeError(msg)


def _ecdsa_algorithm(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Return the SSH algorithm string for an ECDSA key."""
    curve_map: dict[str, str] = {
        "secp256r1": "ecdsa-sha2-nistp256",
        "secp384r1": "ecdsa-sha2-nistp384",
        "secp521r1": "ecdsa-sha2-nistp521",
    }
    algo = curve_map.get(private_key.curve.name)
    if algo is None:
        msg = f"Unsupported ECDSA curve: {private_key.curve.name}"
        raise ValueError(msg)
    return algo


def build_signature_blob(algorithm: str, signature_bytes: bytes) -> bytes:
    """Build an SSH signature blob: ``string algorithm + string signature``."""
    return pack_string(algorithm.encode("utf-8")) + pack_string(signature_bytes)
