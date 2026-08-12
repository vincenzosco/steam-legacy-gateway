import asyncio
import struct

import pytest

from gateway.cm import emsg
from gateway.cm.framing import (
    PROTO_FLAG,
    FramingError,
    decode_frame,
    encode_legacy,
    encode_proto,
    read_frame,
)


def test_legacy_roundtrip():
    body = b"\x01\x02\x03"
    raw = encode_legacy(emsg.ClientHeartBeat, body)
    assert raw[:4] == struct.pack("<I", len(body) + 4)
    frame = decode_frame(raw[4:])
    assert frame.emsg == emsg.ClientHeartBeat
    assert frame.body == body
    assert frame.proto is False


def test_proto_roundtrip():
    header = b"\x08\x01"
    body = b"\x10\x02"
    raw = encode_proto(emsg.ClientLogOnResponse, header, body)
    assert raw[4:8] == b"VT01"
    # the wire EMsg must carry the 0x80000000 proto flag (MsgUtil.MakeMsg)
    (raw_emsg,) = __import__("struct").unpack_from("<I", raw[4:], 4)
    assert raw_emsg & PROTO_FLAG
    assert raw_emsg & ~PROTO_FLAG == emsg.ClientLogOnResponse
    frame = decode_frame(raw[4:])
    assert frame.emsg == emsg.ClientLogOnResponse
    assert frame.header == header
    assert frame.body == body
    assert frame.proto is True


def test_proto_flag_stripped_on_decode():
    # A client-sent proto message arrives with the flag; we must strip it.
    payload = (
        b"VT01"
        + __import__("struct").pack("<I", emsg.ClientLogon | PROTO_FLAG)
        + __import__("struct").pack("<I", 0)
        + b"\x08\x01"
    )
    frame = decode_frame(payload)
    assert frame.emsg == emsg.ClientLogon
    assert frame.proto is True
    assert frame.body == b"\x08\x01"


def test_truncated_frames_raise():
    with pytest.raises(FramingError):
        decode_frame(b"VT01\x01\x00\x00\x00")  # header len overruns payload
    with pytest.raises(FramingError):
        decode_frame(b"\x01\x02\x03")  # too short for a legacy header


async def _frames_in_one_loop(raw: bytes):
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    frames = []
    while True:
        frame = await read_frame(reader)
        if frame is None:
            break
        frames.append(frame)
    return frames


def test_read_frame_stream():
    raw = encode_legacy(emsg.ClientHeartBeat, b"hb") + encode_proto(
        emsg.ClientLogOnResponse, b"", b""
    )
    frames = asyncio.run(_frames_in_one_loop(raw))
    assert [f.emsg for f in frames] == [emsg.ClientHeartBeat, emsg.ClientLogOnResponse]


def test_read_frame_clean_eof():
    assert asyncio.run(_frames_in_one_loop(b"")) == []


def test_emsg_names():
    assert emsg.emsg_name(emsg.ClientLogon) == "ClientLogon"
    assert emsg.emsg_name(999999) == "EMsg_999999"
