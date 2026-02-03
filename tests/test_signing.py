from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from bwssh.agent_proto import unpack_string
from bwssh.constants import SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512
from bwssh.keys import load_private_key
from bwssh.signing import (
    _mpint,
    build_signature_blob,
    sign_data,
    sign_ecdsa,
    sign_ed25519,
    sign_rsa,
)

if TYPE_CHECKING:
    from pathlib import Path

DATA = b"test data to sign"


class TestSignEd25519:
    def test_sign_verify_round_trip(self, ed25519_key_path: Path) -> None:
        private_key = load_private_key(ed25519_key_path.read_bytes())
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)

        signature = sign_ed25519(private_key, DATA)

        private_key.public_key().verify(signature, DATA)

    def test_different_data_different_signature(self, ed25519_key_path: Path) -> None:
        private_key = load_private_key(ed25519_key_path.read_bytes())
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)

        sig1 = sign_ed25519(private_key, b"data one")
        sig2 = sign_ed25519(private_key, b"data two")
        assert sig1 != sig2

    def test_signature_length(self, ed25519_key_path: Path) -> None:
        private_key = load_private_key(ed25519_key_path.read_bytes())
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)

        signature = sign_ed25519(private_key, DATA)
        assert len(signature) == 64


class TestSignRsa:
    def test_sha256_sign_verify(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        assert isinstance(private_key, rsa.RSAPrivateKey)

        signature, algorithm = sign_rsa(private_key, DATA, SSH_AGENT_RSA_SHA2_256)
        assert algorithm == "rsa-sha2-256"

        private_key.public_key().verify(
            signature, DATA, padding.PKCS1v15(), hashes.SHA256()
        )

    def test_sha512_sign_verify(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        assert isinstance(private_key, rsa.RSAPrivateKey)

        signature, algorithm = sign_rsa(private_key, DATA, SSH_AGENT_RSA_SHA2_512)
        assert algorithm == "rsa-sha2-512"

        private_key.public_key().verify(
            signature, DATA, padding.PKCS1v15(), hashes.SHA512()
        )

    def test_legacy_sha1_sign_verify(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        assert isinstance(private_key, rsa.RSAPrivateKey)

        signature, algorithm = sign_rsa(private_key, DATA, 0)
        assert algorithm == "ssh-rsa"

        private_key.public_key().verify(
            signature,
            DATA,
            padding.PKCS1v15(),
            hashes.SHA1(),
        )

    def test_sha512_flag_takes_precedence(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        assert isinstance(private_key, rsa.RSAPrivateKey)

        _signature, algorithm = sign_rsa(
            private_key, DATA, SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512
        )
        assert algorithm == "rsa-sha2-512"


class TestSignEcdsa:
    def test_sign_verify_round_trip(self, ecdsa_key_path: Path) -> None:
        private_key = load_private_key(ecdsa_key_path.read_bytes())
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

        raw_sig = sign_ecdsa(private_key, DATA)

        r_bytes, offset = unpack_string(raw_sig, 0)
        s_bytes, _offset = unpack_string(raw_sig, offset)
        r = int.from_bytes(r_bytes, byteorder="big")
        s = int.from_bytes(s_bytes, byteorder="big")

        der_sig = utils.encode_dss_signature(r, s)
        private_key.public_key().verify(der_sig, DATA, ec.ECDSA(hashes.SHA256()))

    def test_signature_is_ssh_format(self, ecdsa_key_path: Path) -> None:
        private_key = load_private_key(ecdsa_key_path.read_bytes())
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

        raw_sig = sign_ecdsa(private_key, DATA)

        r_bytes, offset = unpack_string(raw_sig, 0)
        s_bytes, offset = unpack_string(raw_sig, offset)
        assert offset == len(raw_sig)
        assert len(r_bytes) > 0
        assert len(s_bytes) > 0


class TestSignData:
    def test_ed25519_dispatch(self, ed25519_key_path: Path) -> None:
        private_key = load_private_key(ed25519_key_path.read_bytes())
        signature, algorithm = sign_data(private_key, DATA, 0)
        assert algorithm == "ssh-ed25519"
        assert len(signature) == 64

    def test_rsa_dispatch_sha256(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        signature, algorithm = sign_data(private_key, DATA, SSH_AGENT_RSA_SHA2_256)
        assert algorithm == "rsa-sha2-256"
        assert len(signature) > 0

    def test_rsa_dispatch_sha512(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        _signature, algorithm = sign_data(private_key, DATA, SSH_AGENT_RSA_SHA2_512)
        assert algorithm == "rsa-sha2-512"

    def test_ecdsa_dispatch(self, ecdsa_key_path: Path) -> None:
        private_key = load_private_key(ecdsa_key_path.read_bytes())
        signature, algorithm = sign_data(private_key, DATA, 0)
        assert algorithm == "ecdsa-sha2-nistp256"
        assert len(signature) > 0


class TestBuildSignatureBlob:
    def test_blob_structure(self) -> None:
        sig_bytes = b"\x01\x02\x03\x04"
        blob = build_signature_blob("ssh-ed25519", sig_bytes)

        algo, offset = unpack_string(blob, 0)
        sig, offset = unpack_string(blob, offset)

        assert algo == b"ssh-ed25519"
        assert sig == sig_bytes
        assert offset == len(blob)

    def test_rsa_blob(self) -> None:
        sig_bytes = b"\xff" * 256
        blob = build_signature_blob("rsa-sha2-256", sig_bytes)

        algo, offset = unpack_string(blob, 0)
        sig, _offset = unpack_string(blob, offset)

        assert algo == b"rsa-sha2-256"
        assert sig == sig_bytes


class TestMpint:
    def test_zero(self) -> None:
        assert _mpint(0) == b""

    def test_small_positive(self) -> None:
        result = _mpint(127)
        assert result == b"\x7f"

    def test_needs_sign_extension(self) -> None:
        result = _mpint(128)
        assert result == b"\x00\x80"

    def test_large_value(self) -> None:
        result = _mpint(0xDEADBEEF)
        assert result == b"\x00\xde\xad\xbe\xef"


class TestFullSignVerifyRoundTrip:
    def test_ed25519_full_blob(self, ed25519_key_path: Path) -> None:
        private_key = load_private_key(ed25519_key_path.read_bytes())
        sig_bytes, algorithm = sign_data(private_key, DATA, 0)
        blob = build_signature_blob(algorithm, sig_bytes)

        algo_parsed, offset = unpack_string(blob, 0)
        sig_parsed, _offset = unpack_string(blob, offset)

        assert algo_parsed == b"ssh-ed25519"
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        private_key.public_key().verify(sig_parsed, DATA)

    def test_rsa_sha256_full_blob(self, rsa_key_path: Path) -> None:
        private_key = load_private_key(rsa_key_path.read_bytes())
        sig_bytes, algorithm = sign_data(private_key, DATA, SSH_AGENT_RSA_SHA2_256)
        blob = build_signature_blob(algorithm, sig_bytes)

        algo_parsed, offset = unpack_string(blob, 0)
        sig_parsed, _offset = unpack_string(blob, offset)

        assert algo_parsed == b"rsa-sha2-256"

        assert isinstance(private_key, rsa.RSAPrivateKey)
        private_key.public_key().verify(
            sig_parsed, DATA, padding.PKCS1v15(), hashes.SHA256()
        )

    def test_ecdsa_full_blob(self, ecdsa_key_path: Path) -> None:
        private_key = load_private_key(ecdsa_key_path.read_bytes())
        sig_bytes, algorithm = sign_data(private_key, DATA, 0)
        blob = build_signature_blob(algorithm, sig_bytes)

        algo_parsed, offset = unpack_string(blob, 0)
        raw_sig_parsed, _offset = unpack_string(blob, offset)

        assert algo_parsed == b"ecdsa-sha2-nistp256"

        r_bytes, off = unpack_string(raw_sig_parsed, 0)
        s_bytes, _off = unpack_string(raw_sig_parsed, off)
        r = int.from_bytes(r_bytes, byteorder="big")
        s = int.from_bytes(s_bytes, byteorder="big")

        der_sig = utils.encode_dss_signature(r, s)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        private_key.public_key().verify(der_sig, DATA, ec.ECDSA(hashes.SHA256()))
