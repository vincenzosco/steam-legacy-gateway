"""Minimal Protocol Buffers (proto2 wire format) codec.

Enough to read/write the handful of CMsg* messages the legacy client uses:

    CMsgClientLogon           account_name = 1 (string), password = 2 (bytes), ...
    CMsgClientLogonResponse   eresult      = 1 (int32)
    CMsgClientSessionToken    token        = 1 (uint64)
    CMsgProtoBufHeader        client_steam_id = 1 (fixed64),
                              client_session_id = 2 (int32)
    CMsgMulti                 size_unzipped = 1? message_body = ... (see below)

Field numbers follow SteamDatabase/SteamTracking protobufs (public). Wire
format is deterministic per the protobuf spec. Verified-by-capture is still
recommended (see docs/PROTOCOL_ANALYSIS.md).

NOTE on CMsgMulti field numbers: the public definition (steammessages_base.proto)
uses `message_body = 1` (bytes) and `size_unzipped = 2` (int32). A hand-rolled
walker must therefore decode fields generically rather than trusting offsets.
"""
from __future__ import annotations

from dataclasses import dataclass

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5

# --- encoding ----------------------------------------------------------------


def varint(value: int) -> bytes:
    out = bytearray()
    value &= (1 << 64) - 1
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _key(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def varint_field(field: int, value: int) -> bytes:
    return _key(field, WIRE_VARINT) + varint(value)


def fixed64_field(field: int, value: int) -> bytes:
    import struct

    return _key(field, WIRE_FIXED64) + struct.pack("<Q", value & ((1 << 64) - 1))


def bytes_field(field: int, payload: bytes) -> bytes:
    return _key(field, WIRE_LEN) + varint(len(payload)) + payload


def string_field(field: int, value: str) -> bytes:
    return bytes_field(field, value.encode("utf-8"))


# --- decoding -----------------------------------------------------------------


@dataclass
class Field:
    number: int
    wire: int
    value: object  # int for varint/fixed, bytes for length-delimited


def parse_fields(data: bytes):
    """Yield Field objects for a serialized message (generous parser)."""
    off = 0
    while off < len(data):
        key, off = _read_varint(data, off)
        field, wire = key >> 3, key & 7
        if wire == WIRE_VARINT:
            value, off = _read_varint(data, off)
        elif wire == WIRE_FIXED64:
            value, off = data[off:off + 8], off + 8
        elif wire == WIRE_LEN:
            length, off = _read_varint(data, off)
            value, off = data[off:off + length], off + length
        elif wire == WIRE_FIXED32:
            value, off = data[off:off + 4], off + 4
        else:
            break  # unknown wire type; stop (we only need known fields)
        yield Field(number=field, wire=wire, value=value)


def _read_varint(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while off < len(data) and shift < 64:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7
    raise ValueError("truncated varint")


def field_text(field: int, data: bytes) -> str | None:
    """Decode field as utf-8 string, or None if absent/not a string."""
    for f in parse_fields(data):
        if f.number == field and f.wire == WIRE_LEN:
            return bytes(f.value).decode("utf-8", errors="replace")
    return None


def field_bytes(field: int, data: bytes) -> bytes | None:
    for f in parse_fields(data):
        if f.number == field and f.wire == WIRE_LEN:
            return bytes(f.value)
    return None


def field_varint(field: int, data: bytes, default: int = 0) -> int:
    for f in parse_fields(data):
        if f.number == field and f.wire == WIRE_VARINT:
            return int(f.value)
    return default
