"""Client simulator — stands in for the Lion-era Steam client.

Runs the exact protocol the Oct-2015 client uses (per docs/PROTOCOL_ANALYSIS.md)
against the gateway's CM listener, so the handshake bytes can be captured and
verified without a 32-bit Lion machine:

    1. server -> client  ChannelEncryptRequest (1303, struct-in-VT01,
                          body = [protocol_version][universe])
    2. client -> server  ChannelEncryptResponse (1304) — session key blob
    3. server -> client  ChannelEncryptResult (1305) — EResult
    4. client -> server  ClientLogon (5514, protobuf, proto-flagged) —
                          CMsgClientLogon account_name=50 / password=51
    5. server -> client  ClientLogOnResponse (751) [+ ClientSessionToken 850]
    6. server -> client  ClientUpdateMachineAuth (5537) — Steam Guard sentry
       client -> server  ClientUpdateMachineAuthResponse (5538) — SHA of written file
    7. server -> client  ClientNewLoginKey (5463) — passwordless re-logon token
       client -> server  ClientNewLoginKeyAccepted (5464)

If the gateway has no modern session configured, step 5 will be a *refusal* —
that still exercises the full wire path and is what gets captured.

The reusable function is `run_handshake()` (used by scripts/client_sim.py and
by the integration test).
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct
from dataclasses import dataclass, field

from gateway.cm import crypto as cmcrypto
from gateway.cm import emsg, machineauth, proto
from gateway.cm.framing import Frame, encode_handshake, encode_proto, read_frame

HEX = "0123456789abcdef"


def hexdump(data: bytes) -> str:
    """16-byte-per-line hexdump with an ASCII column (for capture files)."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        hx = hx.ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hx}  |{asc}|")
    return "\n".join(lines)


@dataclass
class CapturedFrame:
    direction: str  # "<" server->client, ">" client->server
    emsg_id: int
    name: str
    body: bytes
    raw: bytes
    note: str = ""


@dataclass
class HandshakeResult:
    ok: bool
    frames: list[CapturedFrame] = field(default_factory=list)
    channel_result: int | None = None
    logon_eresult: int | None = None
    session_token: int | None = None
    sentry_job_id: int | None = None
    sentry_filename: str = ""
    sentry_sha: bytes = b""
    login_key_unique_id: int | None = None
    error: str = ""

    def render_capture(self) -> str:
        """Annotated transcript of every frame, suitable for a capture file."""
        out = [f"# steam-legacy-gateway client simulator capture "
               f"({len(self.frames)} frames)"]
        for f in self.frames:
            out.append("")
            out.append(f"== {f.direction} {f.name} ({f.emsg_id}) "
                       f"{f.note.strip() or ''} ==")
            out.append(hexdump(f.raw))
        return "\n".join(out)


async def _read_expect(reader: asyncio.StreamReader, emsg_id: int,
                       what: str, timeout: float = 15,
                       decrypt=None) -> Frame | None:
    try:
        frame = await asyncio.wait_for(read_frame(reader, decrypt=decrypt),
                                       timeout=timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        raise ConnectionError(f"timed out waiting for {what}: {exc}") from exc
    if frame is None:
        raise ConnectionError(f"connection closed while waiting for {what}")
    return frame


async def run_handshake(host: str = "127.0.0.1", port: int = 27017,
                        account: str = "simuser",
                        password: bytes = b"\x00" * 128,
                        session_key: bytes = b"\x42" * 128,
                        encrypted: bool = False, key_pem: str = "",
                        password_text: str = "s3cret") -> HandshakeResult:
    """Perform the legacy handshake + MachineAuth exchange against a gateway.

    With `encrypted=True`, behaves like the real client after the key-swap:
    the session key is RSA-encrypted (PKCS#1) with the gateway's CM public
    key from `key_pem`, and every post-handshake frame payload is AES
    encrypted with the session key. The logon password is then also
    RSA-encrypted (as the real client does), so the gateway decrypts it.
    """
    result = HandshakeResult(ok=False)
    if encrypted:
        # The real client generates a 32-byte session key; the legacy default
        # here (b"\x42" * 128) is a stand-in blob only used in plaintext mode.
        session_key = (session_key[:32] if len(session_key) == 32
                       else os.urandom(32))
    reader, writer = await asyncio.open_connection(host, port)
    enc = {"key": None}  # session key once the handshake completes

    def _encrypt(payload: bytes) -> bytes:
        if enc["key"] is None:
            return payload
        return b"VT01" + cmcrypto.symmetric_encrypt(payload[4:], enc["key"])

    def _decrypt(payload: bytes) -> bytes:
        if enc["key"] is None:
            return payload
        return b"VT01" + cmcrypto.symmetric_decrypt(payload[4:], enc["key"])

    async def _write(payload: bytes) -> None:
        """Re-frame a length-prefixed frame with the channel filter applied."""
        inner = _encrypt(payload[4:])  # payload = [len][VT01][...]
        writer.write(struct.pack("<I", len(inner)) + inner)
        await writer.drain()

    try:
        # 1. server -> client: ChannelEncryptRequest ([protocol_version][universe])
        f = await _read_expect(reader, emsg.ChannelEncryptRequest,
                               "ChannelEncryptRequest", decrypt=_decrypt)
        if len(f.body) >= 8:
            proto_ver, universe = struct.unpack_from("<II", f.body, 0)
            note = f"proto_v={proto_ver} universe={universe}"
        else:
            note = f"challenge={len(f.body)}B"
        result.frames.append(CapturedFrame("<", f.emsg, f.name, f.body, f.raw,
                                           note=note))

        # 2. client -> server: ChannelEncryptResponse
        #    [protocol_version:4][key_size:4][key][crc32:4][end_flag:4]
        wire_key = session_key
        note = f"session_key={len(session_key)}B"
        if encrypted:
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.primitives.asymmetric import padding as _pad

            priv = _ser.load_pem_private_key(open(key_pem, "rb").read(),
                                              password=None)
            wire_key = priv.public_key().encrypt(session_key, _pad.PKCS1v15())
            note = f"RSA-encrypted session key ({len(wire_key)}B)"
        body = (
            struct.pack("<ii", 1, len(wire_key))
            + wire_key
            + struct.pack("<II", 0x12345678, 0)
        )
        out = encode_handshake(emsg.ChannelEncryptResponse, body)
        writer.write(out)
        await writer.drain()
        result.frames.append(CapturedFrame(">", emsg.ChannelEncryptResponse,
                                           "ChannelEncryptResponse", body, out,
                                           note=note))

        # 3. server -> client: ChannelEncryptResult
        f = await _read_expect(reader, emsg.ChannelEncryptResult,
                               "ChannelEncryptResult", decrypt=_decrypt)
        result.channel_result = struct.unpack_from("<i", f.body, 0)[0]
        result.frames.append(CapturedFrame("<", f.emsg, f.name, f.body, f.raw,
                                           note=f"eresult={result.channel_result}"))
        if result.channel_result != 1:
            result.error = f"channel encrypt refused: eresult {result.channel_result}"
            return result

        # The client arms its encryption filter on receiving the result
        # (CMClient.HandleEncryptResult) — everything after this is encrypted.
        if encrypted:
            enc["key"] = session_key

        # 4. client -> server: protobuf ClientLogon
        #    CMsgClientLogon: account_name=50, password=51, protocol_version=1.
        #    The real client RSA-encrypts the password with the same CM key.
        wire_password = password
        if encrypted:
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.primitives.asymmetric import padding as _pad

            priv = _ser.load_pem_private_key(open(key_pem, "rb").read(),
                                              password=None)
            wire_password = priv.public_key().encrypt(
                password_text.encode("utf-8"), _pad.PKCS1v15())
        logon = (
            proto.varint_field(1, 65542)  # protocol_version
            + proto.string_field(50, account)
            + proto.bytes_field(51, wire_password)
        )
        out = encode_proto(emsg.ClientLogon, b"", logon)
        await _write(out)
        result.frames.append(CapturedFrame(">", emsg.ClientLogon, "ClientLogon",
                                           logon, out, note=f"account={account}"))

        # 5. server -> client: ClientLogOnResponse (751)
        f = await _read_expect(reader, emsg.ClientLogOnResponse,
                               "ClientLogOnResponse", decrypt=_decrypt)
        result.logon_eresult = proto.field_varint(1, f.body)
        result.frames.append(CapturedFrame("<", f.emsg, f.name, f.body, f.raw,
                                           note=f"eresult={result.logon_eresult}"))

        if result.logon_eresult != 1:
            result.ok = True  # refusal is a valid (and capturable) outcome
            return result

        # 6. post-logon exchange — handle frames until MachineAuth + LoginKey done
        seen = {"token": False, "account_info": False, "cm_list": False,
                "machineauth": False, "login_key": False}
        timeout = 15
        while not (seen["machineauth"] and seen["login_key"]):
            f = await asyncio.wait_for(read_frame(reader, decrypt=_decrypt),
                                       timeout=timeout)
            if f is None:
                break
            if f.emsg == emsg.ClientSessionToken and not seen["token"]:
                result.session_token = proto.field_varint(1, f.body)
                result.frames.append(CapturedFrame(
                    "<", f.emsg, f.name, f.body, f.raw,
                    note=f"token={result.session_token}"))
                seen["token"] = True
            elif f.emsg == emsg.ClientAccountInfo:
                result.frames.append(CapturedFrame(
                    "<", f.emsg, f.name, f.body, f.raw,
                    note="persona/account info"))
                seen["account_info"] = True
            elif f.emsg == emsg.ClientCMList:
                result.frames.append(CapturedFrame(
                    "<", f.emsg, f.name, f.body, f.raw, note="cm rotation list"))
                seen["cm_list"] = True
            elif f.emsg == emsg.ClientUpdateMachineAuth and not seen["machineauth"]:
                result.frames.append(CapturedFrame(
                    "<", f.emsg, f.name, f.body, f.raw, note="sentry push"))
                seen["machineauth"] = True
                await _reply_machine_auth(_write, f, result)
            elif f.emsg == emsg.ClientNewLoginKey and not seen["login_key"]:
                key = machineauth.parse_new_login_key(f.body)
                result.login_key_unique_id = key.unique_id
                result.frames.append(CapturedFrame(
                    "<", f.emsg, f.name, f.body, f.raw,
                    note=f"unique_id={key.unique_id}"))
                seen["login_key"] = True
                accept = machineauth.build_new_login_key_accepted(key.unique_id)
                out = encode_proto(emsg.ClientNewLoginKeyAccepted, b"", accept)
                await _write(out)
                result.frames.append(CapturedFrame(
                    ">", emsg.ClientNewLoginKeyAccepted, "ClientNewLoginKeyAccepted",
                    accept, out, note=f"unique_id={key.unique_id}"))
            else:
                log_unhandled(result, f)
        result.ok = True
        return result
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _reply_machine_auth(write, frame: Frame,
                              result: HandshakeResult) -> None:
    """Client writes the pushed sentry file and confirms (5537 -> 5538)."""
    req = machineauth.parse_update_machine_auth(frame.body)
    result.sentry_job_id = machineauth.jobid_source(frame.header)
    result.sentry_filename = req.filename
    result.sentry_sha = hashlib.sha1(req.bytes_).digest()
    resp = machineauth.build_update_machine_auth_response(
        filename=req.filename,
        eresult=1,
        filesize=len(req.bytes_),
        sha_file=result.sentry_sha,
        offset=req.offset,
        cubwrote=len(req.bytes_),
    )
    header = machineauth.header(jobid_target=result.sentry_job_id)
    out = encode_proto(emsg.ClientUpdateMachineAuthResponse, header, resp)
    await write(out)
    result.frames.append(CapturedFrame(
        ">", emsg.ClientUpdateMachineAuthResponse, "ClientUpdateMachineAuthResponse",
        resp, out, note=f"job={result.sentry_job_id} sha={result.sentry_sha.hex()}"))


def log_unhandled(result: HandshakeResult, f: Frame) -> None:
    result.frames.append(CapturedFrame(
        "<", f.emsg, f.name, f.body, f.raw, note="(unhandled in sim)"))


def main() -> int:  # pragma: no cover - thin CLI
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="simulate the Lion-era client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27017)
    parser.add_argument("--account", default="simuser")
    parser.add_argument("--password-text", default="s3cret",
                        help="password sent when --encrypted (RSA-encrypted "
                             "like the real client)")
    parser.add_argument("--encrypted", action="store_true",
                        help="encrypt the session key + channel like the real "
                             "client (needs --key-pem = bridge's cm-rsa.key)")
    parser.add_argument("--key-pem", default="certs/cm-rsa.key",
                        help="bridge CM RSA key (default: certs/cm-rsa.key)")
    parser.add_argument("--out", default="", help="write the annotated capture here")
    args = parser.parse_args()

    async def _run() -> int:
        res = await run_handshake(args.host, args.port, args.account,
                                  encrypted=args.encrypted,
                                  key_pem=args.key_pem,
                                  password_text=args.password_text)
        print(res.render_capture())
        if args.out:
            from pathlib import Path

            p = Path(args.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(res.render_capture())
            print(f"\n[capture written to {p}]")
        print(f"\nchannel_eresult={res.channel_result} "
              f"logon_eresult={res.logon_eresult} "
              f"session_token={res.session_token} "
              f"sentry_sha={res.sentry_sha.hex() if res.sentry_sha else 'n/a'} "
              f"login_key_unique_id={res.login_key_unique_id} ok={res.ok}")
        return 0 if res.ok else 1

    return asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main())
