"""CM framing for the 2013-era Steam protocol.

Both legacy and protobuf messages on the TCP CM connection are length-prefixed:

    legacy:   [size:4LE][emsg:4LE][body...]
    protobuf: [size:4LE]["VT01"][emsg:4LE][header_len:4LE][header][body]

The magic "VT01" inside the length-prefixed payload distinguishes the two, and
is why the connection is self-describing. This matches the framing SteamKit
uses in `TcpConnection` (public source).
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

MAGIC_VT01 = b"VT01"
_MAX_FRAME = 16 * 1024 * 1024  # CM frames can be large (multi-message batches)


class FramingError(Exception):
    pass


@dataclass
class Frame:
    emsg: int
    body: bytes = b""
    header: bytes = b""  # protobuf header (empty for legacy messages)
    proto: bool = False  # True if this used VT01 framing
    raw: bytes = field(default=b"", repr=False)

    @property
    def name(self) -> str:
        from gateway.cm.emsg import emsg_name

        return emsg_name(self.emsg)


def encode_legacy(emsg: int, body: bytes) -> bytes:
    payload = struct.pack("<I", emsg) + body
    return struct.pack("<I", len(payload)) + payload


def encode_proto(emsg: int, header: bytes, body: bytes) -> bytes:
    payload = MAGIC_VT01 + struct.pack("<I", emsg) + struct.pack("<I", len(header)) + header + body
    return struct.pack("<I", len(payload)) + payload


def decode_frame(payload: bytes) -> Frame:
    """Decode one length-framed payload into a Frame (raw = the payload itself)."""
    if payload.startswith(MAGIC_VT01):
        if len(payload) < 12:
            raise FramingError("truncated VT01 header")
        emsg = struct.unpack_from("<I", payload, 4)[0]
        header_len = struct.unpack_from("<I", payload, 8)[0]
        header_end = 12 + header_len
        if header_end > len(payload):
            raise FramingError(f"header_len {header_len} exceeds payload {len(payload)}")
        return Frame(
            emsg=emsg,
            header=payload[12:header_end],
            body=payload[header_end:],
            proto=True,
            raw=payload,
        )
    if len(payload) < 4:
        raise FramingError("truncated legacy header")
    emsg = struct.unpack_from("<I", payload, 0)[0]
    return Frame(emsg=emsg, body=payload[4:], proto=False, raw=payload)


async def read_frame(reader: asyncio.StreamReader) -> Frame | None:
    """Read one length-prefixed frame from the stream. Returns None on clean EOF."""
    try:
        size_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None  # clean EOF / connection closed
    (size,) = struct.unpack("<I", size_bytes)
    if size == 0:
        return None
    if size > _MAX_FRAME:
        raise FramingError(f"frame too large: {size}")
    payload = await reader.readexactly(size)
    return decode_frame(payload)
