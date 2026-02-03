"""SSH agent protocol message framing over asyncio streams.

Wire format (per IETF draft-miller-ssh-agent-17 §3):
  [uint32 length][byte msg_type][payload...]

Length field = 1 (type byte) + len(payload).  All multi-byte integers are big-endian.

SSH string format:
  [uint32 length][data...]
"""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio

logger = logging.getLogger(__name__)

_UINT32 = struct.Struct(">I")


def pack_uint32(n: int) -> bytes:
    return _UINT32.pack(n)


def unpack_uint32(data: bytes, offset: int) -> tuple[int, int]:
    (value,) = _UINT32.unpack_from(data, offset)
    return value, offset + 4


def pack_string(data: bytes) -> bytes:
    return _UINT32.pack(len(data)) + data


def unpack_string(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = unpack_uint32(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError(
            f"SSH string at offset {offset - 4}: need {length} bytes, "
            f"have {len(data) - offset}"
        )
    return data[offset:end], end


async def read_message(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    raw_length = await reader.readexactly(4)
    (length,) = _UINT32.unpack(raw_length)

    raw_body = await reader.readexactly(length)
    msg_type = raw_body[0]
    payload = raw_body[1:]
    return msg_type, payload


async def write_message(
    writer: asyncio.StreamWriter, msg_type: int, payload: bytes
) -> None:
    length = 1 + len(payload)
    header = _UINT32.pack(length) + bytes([msg_type])
    writer.write(header + payload)
    await writer.drain()
