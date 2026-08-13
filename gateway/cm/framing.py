"""CM framing for the Oct-2015 Steam protocol.

All CM TCP traffic is length-prefixed with the VT01 magic (TcpConnection.cs
2015: `[packet_len:4]["VT01"][data]`; the magic is constant 0x31305456):

    [len:4]["VT01"][emsg|proto-flag:4][...]

Inside the payload, the EMsg field discriminates the two layouts, exactly as
the client's `CMClient.GetPacketMsg` does (SteamKit 2015):

    struct (MsgHdr):      [emsg:4][target_job:8][source_job:8][body]
    protobuf (MsgHdrProtoBuf): [emsg|0x80000000:4][header_len:4][header][body]

The 0x80000000 "proto flag" is set by `MsgUtil.MakeMsg(msg, isProto=true)` and
IS present on the wire (MsgHdrProtoBuf.Serialize writes `MakeMsg(Msg, true)`).
The channel-encrypt handshake messages (1303/1304/1305) are always struct.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

MAGIC_VT01 = b"VT01"
_MAX_FRAME = 16 * 1024 * 1024  # CM frames can be large (multi-message batches)

# The channel-encrypt handshake messages are struct messages, never protobuf.
# SteamKit 2015: "certain message types are always MsgHdr". Struct header
# layout inside the VT01 payload: [emsg:4][target_job:8][source_job:8].
STRUCT_HEADER_LEN = 4 + 8 + 8  # emsg + target_job + source_job (after VT01)
# Informational: these messages are always struct-framed on the wire. decode
# actually dispatches on the 0x80000000 proto flag (structs carry no flag).
HANDSHAKE_EMSGS = {1303, 1304, 1305}  # ChannelEncryptRequest / Response / Result

# Proto flag OR'd into the wire EMsg for protobuf messages (MsgUtil.MakeMsg).
PROTO_FLAG = 0x80000000


class FramingError(Exception):
    pass


@dataclass
class Frame:
    emsg: int
    body: bytes = b""
    header: bytes = b""  # protobuf header (empty for struct messages)
    proto: bool = False  # True if this used protobuf VT01 framing
    struct: bool = False  # True if this used the struct-in-VT01 framing
    raw: bytes = field(default=b"", repr=False)

    @property
    def name(self) -> str:
        from gateway.cm.emsg import emsg_name

        return emsg_name(self.emsg)


def encode_legacy(emsg: int, body: bytes) -> bytes:
    """Legacy framing: [len][emsg][body] (pre-VT01 struct messages, UDP-era).

    Kept for completeness; the 2015 client never uses this on TCP.
    """
    payload = struct.pack("<I", emsg) + body
    return struct.pack("<I", len(payload)) + payload


def encode_struct(emsg: int, body: bytes,
                  target_job: int = 0, source_job: int = 0) -> bytes:
    """Struct-in-VT01 framing used by the channel-encrypt handshake.

    [len][VT01][emsg][target_job:8][source_job:8][body]. Job ids are not
    validated by the client for handshake messages.
    """
    payload = MAGIC_VT01 + struct.pack("<I", emsg)
    payload += struct.pack("<QQ", target_job, source_job) + body
    return struct.pack("<I", len(payload)) + payload


def encode_handshake(emsg: int, body: bytes) -> bytes:
    """Alias of encode_struct used by the handshake path."""
    return encode_struct(emsg, body)


def encode_proto(emsg: int, header: bytes, body: bytes) -> bytes:
    """Protobuf framing: [len][VT01][emsg|proto-flag][header_len][header][body].

    The proto flag is set on the wire (MsgHdrProtoBuf.Serialize).
    """
    payload = MAGIC_VT01 + struct.pack("<I", emsg | PROTO_FLAG)
    payload += struct.pack("<I", len(header)) + header + body
    return struct.pack("<I", len(payload)) + payload


def decode_frame(payload: bytes) -> Frame:
    """Decode one length-framed payload into a Frame (raw = the payload itself)."""
    if payload.startswith(MAGIC_VT01):
        if len(payload) < 8:
            raise FramingError("truncated VT01 header")
        raw_emsg = struct.unpack_from("<I", payload, 4)[0]
        if raw_emsg & PROTO_FLAG:
            # protobuf: [emsg|flag][header_len][header][body]
            emsg = raw_emsg & ~PROTO_FLAG
            if len(payload) < 12:
                raise FramingError("truncated proto header")
            header_len = struct.unpack_from("<I", payload, 8)[0]
            header_end = 12 + header_len
            if header_end > len(payload):
                raise FramingError(
                    f"header_len {header_len} exceeds payload {len(payload)}")
            return Frame(
                emsg=emsg,
                header=payload[12:header_end],
                body=payload[header_end:],
                proto=True,
                raw=payload,
            )
        # struct: [emsg][target_job:8][source_job:8][body] (handshake, legacy)
        emsg = raw_emsg
        if len(payload) < 4 + STRUCT_HEADER_LEN:
            raise FramingError("truncated struct header")
        return Frame(
            emsg=emsg,
            body=payload[4 + STRUCT_HEADER_LEN:],
            proto=False,
            struct=True,
            raw=payload,
        )
    if len(payload) < 4:
        raise FramingError("truncated legacy header")
    emsg = struct.unpack_from("<I", payload, 0)[0]
    return Frame(emsg=emsg, body=payload[4:], proto=False, raw=payload)


async def read_frame(reader: asyncio.StreamReader, decrypt=None,
                     on_raw=None) -> Frame | None:
    """Read one length-prefixed frame from the stream. Returns None on clean EOF.

    `decrypt` (optional) is applied to the payload before decoding — used by
    the CM server once the channel session key is established. `on_raw`
    (optional) receives the exact wire bytes (length prefix + payload) for
    capture/analysis, before any decryption.
    """
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
    if on_raw is not None:
        on_raw(size_bytes + payload)
    if decrypt is not None:
        payload = decrypt(payload)
    return decode_frame(payload)
