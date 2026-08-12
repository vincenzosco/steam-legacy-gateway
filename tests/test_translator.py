import struct

import pytest

from gateway.cm import emsg, machineauth, proto
from gateway.cm.framing import (
    PROTO_FLAG,
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
    cfg = {"account": {}, "cm": {}, "gateway_ip": "127.0.0.1"}
    return TranslatorSession(FakeWriter(), cfg, modern=None,
                             sentry_store=machineauth.SentinelStore())


def test_handshake_request_framing():
    s = _session()
    import asyncio

    asyncio.run(s.start_handshake())
    raw = bytes(s.writer.data)
    # [len:4][VT01][emsg:4][jobs:16][protocol_version:4][universe:4]
    assert raw[:4] == struct.pack("<I", len(raw) - 4)
    assert raw[4:8] == b"VT01"
    (emsg_id,) = struct.unpack_from("<I", raw, 8)
    assert emsg_id == emsg.ChannelEncryptRequest
    body = raw[4 + 4 + STRUCT_HEADER_LEN:]  # len + VT01 + (emsg+jobs)
    proto_ver, universe = struct.unpack_from("<II", body, 0)
    assert proto_ver == 1
    assert universe == 1  # EUniverse.Public


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
    # body starts at [len:4] + VT01 + STRUCT_HEADER_LEN payload header
    (eresult,) = struct.unpack_from("<i", raw[4:], 4 + STRUCT_HEADER_LEN)
    assert eresult == 1


def test_logon_without_modern_session_is_refused():
    import asyncio

    from gateway.cm import proto

    s = _session()
    s.state = State.CHANNEL_OPEN
    # CMsgClientLogon: account_name = 50 (not 1!)
    logon = proto.string_field(50, "someone")
    frame = decode_frame(
        b"VT01" + struct.pack("<I", emsg.ClientLogon | PROTO_FLAG)
        + struct.pack("<I", 0) + logon
    )
    assert frame.proto is True
    asyncio.run(s.handle(frame))
    raw = bytes(s.writer.data)
    assert raw
    reply = decode_frame(raw[4:])  # protobuf ClientLogOnResponse (refusal)
    assert reply.emsg == emsg.ClientLogOnResponse
    assert reply.proto is True
    assert proto.field_varint(1, reply.body) == 3  # not EResult.OK


class _FakeModern:
    def __init__(self):
        self._ready_done = True

    def is_ready(self) -> bool:
        return True

    def steam_id(self) -> int:
        return 76561197960265728  # steamid for simuser's universe/type base


def test_logon_success_runs_machine_auth_flow():
    """After a successful logon the gateway pushes a sentry + login key."""
    import asyncio

    s = _session()
    s.modern = _FakeModern()
    s.state = State.CHANNEL_OPEN
    logon = (
        proto.varint_field(1, 65542)
        + proto.string_field(50, "simuser")
        + proto.bytes_field(51, b"\x00" * 128)
    )
    frame = decode_frame(
        b"VT01" + struct.pack("<I", emsg.ClientLogon | PROTO_FLAG)
        + struct.pack("<I", 0) + logon
    )
    asyncio.run(s.handle(frame))
    raw = bytes(s.writer.data)
    assert s.state == State.ACTIVE

    # Walk every outbound frame: expect 751, 850, 768, 783, then 5537, 5463.
    emitted = []
    rest = bytes(raw)
    while rest:
        (size,) = struct.unpack_from("<I", rest, 0)
        f = decode_frame(rest[4:4 + size])
        emitted.append(f.emsg)
        rest = rest[4 + size:]
    assert emitted[0] == emsg.ClientLogOnResponse
    assert emsg.ClientSessionToken in emitted
    assert emsg.ClientAccountInfo in emitted
    assert emsg.ClientCMList in emitted
    assert emsg.ClientUpdateMachineAuth in emitted
    assert emsg.ClientNewLoginKey in emitted


def test_update_machine_auth_response_stores_sentry():
    import asyncio

    s = _session()
    s.state = State.ACTIVE
    s._account = "simuser"
    sentry = b"\x01\x02\x03\x04" * 64
    import hashlib

    sha = hashlib.sha1(sentry).digest()
    filename = "ssfn1234567890abcdef1234567890abcdef1234567"

    s.sentry_store.put("simuser", machineauth.SentryEntry(
        filename=filename, filesize=len(sentry), sha_file=sha, data=sentry))

    body = machineauth.build_update_machine_auth_response(
        filename, eresult=1, filesize=len(sentry), sha_file=sha,
        offset=0, cubwrote=len(sentry))
    frame = decode_frame(
        b"VT01" + struct.pack("<I", emsg.ClientUpdateMachineAuthResponse | PROTO_FLAG)
        + struct.pack("<I", 0) + body
    )
    asyncio.run(s.handle(frame))
    stored = s.sentry_store.get("simuser", filename)
    assert stored is not None
    assert stored.sha_file == sha


def _proto_frame(emsg_id: int, body: bytes, header: bytes = b"") -> Frame:
    return decode_frame(
        b"VT01" + struct.pack("<I", emsg_id | PROTO_FLAG)
        + struct.pack("<I", len(header)) + header + body
    )


def test_client_read_machine_auth_is_served():
    import asyncio

    s = _session()
    s.state = State.ACTIVE
    s._account = "simuser"
    sentry = b"\xAB" * 64
    import hashlib

    sha = hashlib.sha1(sentry).digest()
    filename = "ssfn1234567890abcdef1234567890abcdef1234567"
    s.sentry_store.put("simuser", machineauth.SentryEntry(
        filename=filename, filesize=len(sentry), sha_file=sha, data=sentry))

    req = machineauth.build_read_machine_auth(filename, 0, len(sentry))
    # The client sets jobid_source on its request; the reply must echo it as
    # jobid_target (SteamKit job correlation).
    req_header = machineauth.header(jobid_source=0x1234)
    frame = _proto_frame(emsg.ClientReadMachineAuth, req, req_header)
    asyncio.run(s.handle(frame))
    raw = bytes(s.writer.data)
    reply = decode_frame(raw[4:])
    assert reply.emsg == emsg.ClientReadMachineAuthResponse
    assert machineauth.jobid_target(reply.header) == 0x1234
    parsed = machineauth.parse_read_machine_auth_response(reply.body)
    assert parsed.filesize == len(sentry)
    assert parsed.bytes_read == sentry


def test_client_request_machine_auth_echoes_job():
    import asyncio

    s = _session()
    s.state = State.ACTIVE
    s._account = "simuser"
    sha = b"\x11" * 20
    body = (proto.string_field(1, "ssfn1234567890abcdef1234567890abcdef1234567")
            + proto.varint_field(2, 0)
            + proto.varint_field(3, 128)
            + proto.bytes_field(4, sha))
    req_header = machineauth.header(jobid_source=0x2222)
    frame = _proto_frame(emsg.ClientRequestMachineAuth, body, req_header)
    asyncio.run(s.handle(frame))
    raw = bytes(s.writer.data)
    reply = decode_frame(raw[4:])
    assert reply.emsg == emsg.ClientRequestMachineAuthResponse
    assert machineauth.jobid_target(reply.header) == 0x2222
    assert proto.field_varint(1, reply.body) == 1  # eresult OK
    stored = s.sentry_store.get("simuser", "ssfn1234567890abcdef1234567890abcdef1234567")
    assert stored is not None and stored.sha_file == sha


def test_encode_variants_roundtrip():
    legacy = encode_legacy(emsg.ClientHeartBeat, b"hb")
    f1 = decode_frame(legacy[4:])
    assert f1.emsg == emsg.ClientHeartBeat and f1.proto is False

    hs = encode_handshake(emsg.ChannelEncryptRequest, struct.pack("<II", 1, 1))
    f2 = decode_frame(hs[4:])
    assert f2.struct is True and f2.body == struct.pack("<II", 1, 1)

    pr = encode_proto(emsg.ClientLogOnResponse, b"\x08\x01", b"\x08\x01")
    f3 = decode_frame(pr[4:])
    assert f3.proto is True and f3.header == b"\x08\x01"
    # the wire EMsg must carry the proto flag
    (raw_emsg,) = struct.unpack_from("<I", pr[4:], 4)
    assert raw_emsg & PROTO_FLAG
