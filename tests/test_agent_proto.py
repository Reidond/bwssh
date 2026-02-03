"""Tests for SSH agent protocol message framing and encoding primitives."""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from bwssh.agent_proto import (
    pack_string,
    pack_uint32,
    read_message,
    unpack_string,
    unpack_uint32,
    write_message,
)
from bwssh.constants import (
    SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512,
    SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENT_SUCCESS,
    SSH_AGENTC_ADD_ID_CONSTRAINED,
    SSH_AGENTC_ADD_IDENTITY,
    SSH_AGENTC_EXTENSION,
    SSH_AGENTC_LOCK,
    SSH_AGENTC_REMOVE_ALL_IDENTITIES,
    SSH_AGENTC_REMOVE_IDENTITY,
    SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENTC_UNLOCK,
)


@pytest.fixture
def sample_payload() -> bytes:
    return b"\x01\x02\x03\x04\x05"


@pytest.fixture
def large_payload() -> bytes:
    return bytes(range(256)) * 1024


async def _make_stream_pair() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Create a connected StreamReader/StreamWriter pair via socket pair.

    Both sides use StreamReaderProtocol so drain() works on the writer.
    """
    rsock, wsock = socket.socketpair()
    rsock.setblocking(False)
    wsock.setblocking(False)

    reader = asyncio.StreamReader()
    loop = asyncio.get_running_loop()

    await loop.create_connection(
        lambda: asyncio.StreamReaderProtocol(reader), sock=rsock
    )

    write_reader = asyncio.StreamReader()
    write_protocol = asyncio.StreamReaderProtocol(write_reader)
    write_transport, _ = await loop.create_connection(
        lambda: write_protocol, sock=wsock
    )
    writer = asyncio.StreamWriter(
        write_transport,
        write_protocol,
        write_reader,
        loop,
    )

    return reader, writer


class TestConstants:
    def test_request_identities(self) -> None:
        assert SSH_AGENTC_REQUEST_IDENTITIES == 11

    def test_sign_request(self) -> None:
        assert SSH_AGENTC_SIGN_REQUEST == 13

    def test_extension(self) -> None:
        assert SSH_AGENTC_EXTENSION == 27

    def test_identities_answer(self) -> None:
        assert SSH_AGENT_IDENTITIES_ANSWER == 12

    def test_sign_response(self) -> None:
        assert SSH_AGENT_SIGN_RESPONSE == 14

    def test_failure(self) -> None:
        assert SSH_AGENT_FAILURE == 5

    def test_success(self) -> None:
        assert SSH_AGENT_SUCCESS == 6

    def test_add_identity(self) -> None:
        assert SSH_AGENTC_ADD_IDENTITY == 17

    def test_remove_identity(self) -> None:
        assert SSH_AGENTC_REMOVE_IDENTITY == 18

    def test_remove_all_identities(self) -> None:
        assert SSH_AGENTC_REMOVE_ALL_IDENTITIES == 19

    def test_lock(self) -> None:
        assert SSH_AGENTC_LOCK == 22

    def test_unlock(self) -> None:
        assert SSH_AGENTC_UNLOCK == 23

    def test_add_id_constrained(self) -> None:
        assert SSH_AGENTC_ADD_ID_CONSTRAINED == 25

    def test_rsa_sha2_256_flag(self) -> None:
        assert SSH_AGENT_RSA_SHA2_256 == 0x02

    def test_rsa_sha2_512_flag(self) -> None:
        assert SSH_AGENT_RSA_SHA2_512 == 0x04


class TestUint32:
    def test_pack_zero(self) -> None:
        assert pack_uint32(0) == b"\x00\x00\x00\x00"

    def test_pack_one(self) -> None:
        assert pack_uint32(1) == b"\x00\x00\x00\x01"

    def test_pack_max(self) -> None:
        assert pack_uint32(0xFFFFFFFF) == b"\xff\xff\xff\xff"

    def test_pack_known_value(self) -> None:
        assert pack_uint32(256) == b"\x00\x00\x01\x00"

    def test_roundtrip(self) -> None:
        for val in (0, 1, 42, 255, 256, 65535, 0xDEADBEEF, 0xFFFFFFFF):
            data = pack_uint32(val)
            result, offset = unpack_uint32(data, 0)
            assert result == val
            assert offset == 4

    def test_unpack_at_offset(self) -> None:
        buf = b"\xaa\xbb" + pack_uint32(1234) + b"\xcc"
        val, off = unpack_uint32(buf, 2)
        assert val == 1234
        assert off == 6

    def test_unpack_insufficient_data(self) -> None:
        with pytest.raises((struct.error, Exception)):
            unpack_uint32(b"\x00\x01", 0)


class TestSSHString:
    def test_empty_string(self) -> None:
        packed = pack_string(b"")
        assert packed == b"\x00\x00\x00\x00"

    def test_simple_string(self) -> None:
        packed = pack_string(b"hello")
        assert packed == b"\x00\x00\x00\x05hello"

    def test_roundtrip(self) -> None:
        for data in (b"", b"\x00", b"hello", b"x" * 1000):
            packed = pack_string(data)
            result, offset = unpack_string(packed, 0)
            assert result == data
            assert offset == 4 + len(data)

    def test_unpack_at_offset(self) -> None:
        prefix = b"\xff\xff"
        packed = prefix + pack_string(b"test")
        result, offset = unpack_string(packed, 2)
        assert result == b"test"
        assert offset == 2 + 4 + 4

    def test_multiple_strings(self) -> None:
        buf = pack_string(b"first") + pack_string(b"second")
        s1, off1 = unpack_string(buf, 0)
        s2, off2 = unpack_string(buf, off1)
        assert s1 == b"first"
        assert s2 == b"second"
        assert off2 == len(buf)

    def test_unpack_insufficient_data(self) -> None:
        bad = b"\x00\x00\x00\x0aabc"
        with pytest.raises(ValueError):
            unpack_string(bad, 0)

    def test_binary_data(self) -> None:
        data = bytes(range(256))
        packed = pack_string(data)
        result, _ = unpack_string(packed, 0)
        assert result == data


class TestMessageFraming:
    @pytest.mark.asyncio
    async def test_roundtrip_simple(self, sample_payload: bytes) -> None:
        reader, writer = await _make_stream_pair()
        try:
            msg_type = SSH_AGENTC_REQUEST_IDENTITIES
            await write_message(writer, msg_type, sample_payload)

            got_type, got_payload = await read_message(reader)
            assert got_type == msg_type
            assert got_payload == sample_payload
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_roundtrip_empty_payload(self) -> None:
        reader, writer = await _make_stream_pair()
        try:
            await write_message(writer, SSH_AGENTC_REQUEST_IDENTITIES, b"")

            got_type, got_payload = await read_message(reader)
            assert got_type == SSH_AGENTC_REQUEST_IDENTITIES
            assert got_payload == b""
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_roundtrip_large_payload(self, large_payload: bytes) -> None:
        reader, writer = await _make_stream_pair()
        try:
            await write_message(writer, SSH_AGENT_SIGN_RESPONSE, large_payload)

            got_type, got_payload = await read_message(reader)
            assert got_type == SSH_AGENT_SIGN_RESPONSE
            assert got_payload == large_payload
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_multiple_messages(self) -> None:
        reader, writer = await _make_stream_pair()
        try:
            messages = [
                (SSH_AGENTC_REQUEST_IDENTITIES, b""),
                (SSH_AGENT_IDENTITIES_ANSWER, b"\x00\x00\x00\x00"),
                (SSH_AGENTC_SIGN_REQUEST, b"sign-data"),
                (SSH_AGENT_FAILURE, b""),
            ]

            for msg_type, payload in messages:
                await write_message(writer, msg_type, payload)

            for expected_type, expected_payload in messages:
                got_type, got_payload = await read_message(reader)
                assert got_type == expected_type
                assert got_payload == expected_payload
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_wire_format(self) -> None:
        """Verify the exact wire bytes for a known message.

        REQUEST_IDENTITIES (type=11, no payload):
        Wire: 00 00 00 01 0B
              ^^^^^^^^^^^  ^^ type byte
              length=1
        """
        reader, writer = await _make_stream_pair()
        try:
            await write_message(writer, SSH_AGENTC_REQUEST_IDENTITIES, b"")

            raw_length = await reader.readexactly(4)
            assert raw_length == b"\x00\x00\x00\x01"

            raw_type = await reader.readexactly(1)
            assert raw_type == bytes([SSH_AGENTC_REQUEST_IDENTITIES])
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_wire_format_with_payload(self) -> None:
        """Verify wire format for a message with payload.

        Type=5 (FAILURE), payload=b"AB":
        Wire: 00 00 00 03 05 41 42
              ^^^^^^^^^^^  ^^  ^^^^
              length=3     type payload
        """
        reader, writer = await _make_stream_pair()
        try:
            await write_message(writer, SSH_AGENT_FAILURE, b"AB")

            raw_length = await reader.readexactly(4)
            assert raw_length == b"\x00\x00\x00\x03"

            raw_type = await reader.readexactly(1)
            assert raw_type == bytes([SSH_AGENT_FAILURE])

            raw_payload = await reader.readexactly(2)
            assert raw_payload == b"AB"
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_read_eof_raises(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_eof()

        with pytest.raises((asyncio.IncompleteReadError, ConnectionError, Exception)):
            await read_message(reader)

    @pytest.mark.asyncio
    async def test_read_incomplete_length(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x01")
        reader.feed_eof()

        with pytest.raises((asyncio.IncompleteReadError, Exception)):
            await read_message(reader)

    @pytest.mark.asyncio
    async def test_read_incomplete_payload(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x00\x00\x0a\x0b\x01\x02")
        reader.feed_eof()

        with pytest.raises((asyncio.IncompleteReadError, Exception)):
            await read_message(reader)

    @pytest.mark.asyncio
    async def test_all_response_types(self) -> None:
        reader, writer = await _make_stream_pair()
        try:
            response_types = [
                SSH_AGENT_FAILURE,
                SSH_AGENT_SUCCESS,
                SSH_AGENT_IDENTITIES_ANSWER,
                SSH_AGENT_SIGN_RESPONSE,
            ]

            for msg_type in response_types:
                await write_message(writer, msg_type, b"")

            for expected_type in response_types:
                got_type, _ = await read_message(reader)
                assert got_type == expected_type
        finally:
            writer.close()

    @pytest.mark.asyncio
    async def test_all_request_types(self) -> None:
        reader, writer = await _make_stream_pair()
        try:
            request_types = [
                SSH_AGENTC_REQUEST_IDENTITIES,
                SSH_AGENTC_SIGN_REQUEST,
                SSH_AGENTC_EXTENSION,
                SSH_AGENTC_ADD_IDENTITY,
                SSH_AGENTC_REMOVE_IDENTITY,
                SSH_AGENTC_REMOVE_ALL_IDENTITIES,
                SSH_AGENTC_LOCK,
                SSH_AGENTC_UNLOCK,
                SSH_AGENTC_ADD_ID_CONSTRAINED,
            ]

            for msg_type in request_types:
                await write_message(writer, msg_type, b"")

            for expected_type in request_types:
                got_type, _ = await read_message(reader)
                assert got_type == expected_type
        finally:
            writer.close()
