import struct

import pytest

from gateway.cm import emsg
from gateway.cm.framing import (
    STRUCT_HEADER_LEN,
    decode_frame,
    encode_handshake,
    encode_legacy,
    encode_proto,
)
from gateway.cm.translator import State, TranslatorSession


class FakeWriter:
    def __init__(self):
        self.data = bytearray()

    def write(self, chunk: bytes) -> None:
        self.data += chunk

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


def _session():
    cfg = {"account": {}}
    return TranslatorSession(FakeWriter(), cfg, modern=None)


def test_handshake_request_framing():
    s = _session()
    import asyncio

    asyncio.run(s.start_handshake())
    raw = bytes(s.writer.data)
    # [len:4][VT01][emsg:4][jobs:16][challenge:16]
    assert raw[:4] == struct.pack("<I", len(raw) - 4)
    assert raw[4:8] == b"VT01"
    (emsg_id,) = struct.unpack_from("<I", raw, 8)
    assert emsg_id == emsg.ChannelEncryptRequest
    assert len(raw) - 4 - STRUCT_HEADER_LEN == 16  # challenge


def test_channel_encrypt_response_flow():
    s = _session()
    assert s.state.value == "await_encrypt"

    # Client replies ChannelEncryptResponse (struct-in-VT01):
    # [protocol_version:4][key_size:4][key:128][crc:4][end_flag:4]
    body = struct.pack("<ii", 1, 128) + b"\xAA" * 128 + struct.pack("<II", 0xDEADBEEF, 0)
    frame = decode_frame(
        b"VT01" + struct.pack("<I", emsg.ChannelEncryptResponse) + struct.pack("<QQ", 0, 0) + body
    )
    assert frame.struct is True

    import asyncio

    asyncio.run(s.handle(frame))
    assert s.state.value == "channel_open"
    assert s._client_session_key_encrypted == b"\xAA" * 128

    raw = bytes(s.writer.data)
    (emsg_id,) = struct.unpack_from("<I", raw, 8)
    assert emsg_id == emsg.ChannelEncryptResult
    # body starts at [len:4] + STRUCT_HEADER_LEN payload header
    (eresult,) = struct.unpack_from("<i", raw[4:], STRUCT_HEADER_LEN)
    assert eresult == 1


def test_logon_without_modern_session_is_refused():
    import asyncio

    from gateway.cm import proto

    s = _session()
    s.state = State.CHANNEL_OPEN
    logon = proto.string_field(1, "someone")
    frame = decode_frame(
        b"VT01" + struct.pack("<I", emsg.ClientLogon) + struct.pack("<I", 0) + logon
    )
    asyncio.run(s.handle(frame))
    raw = bytes(s.writer.data)
    assert raw
    reply = decode_frame(raw[4:])  # protobuf ClientLogOnResponse (refusal)
    assert reply.emsg == emsg.ClientLogOnResponse
    assert reply.proto is True
    assert proto.field_varint(1, reply.body) == 3  # not EResult.OK


def test_encode_variants_roundtrip():
    legacy = encode_legacy(emsg.ClientHeartBeat, b"hb")
    f1 = decode_frame(legacy[4:])
    assert f1.emsg == emsg.ClientHeartBeat and f1.proto is False

    hs = encode_handshake(emsg.ChannelEncryptRequest, b"\x01" * 16)
    f2 = decode_frame(hs[4:])
    assert f2.struct is True and f2.body == b"\x01" * 16

    pr = encode_proto(emsg.ClientLogOnResponse, b"\x08\x01", b"\x08\x01")
    f3 = decode_frame(pr[4:])
    assert f3.proto is True and f3.header == b"\x08\x01"
