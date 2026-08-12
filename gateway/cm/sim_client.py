"""Client simulator — stands in for the Lion-era Steam client.

Runs the exact protocol the Oct-2015 client uses (per docs/PROTOCOL_ANALYSIS.md)
against the gateway's CM listener, so the handshake bytes can be captured and
verified without a 32-bit Lion machine:

    1. server -> client  ChannelEncryptRequest (130, struct-in-VT01, challenge)
    2. client -> server  ChannelEncryptResponse (131) — session key blob
    3. server -> client  ChannelEncryptResult (132) — EResult
    4. client -> server  ClientLogon (704, protobuf) — account + password
    5. server -> client  ClientLogOnResponse (940) [+ ClientSessionToken 761]

If the gateway has no modern session configured, step 5 will be a *refusal* —
that still exercises the full wire path and is what gets captured.

The reusable function is `run_handshake()` (used by scripts/client_sim.py and
by the integration test).
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

from gateway.cm import emsg, proto
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
                       what: str, timeout: float = 15) -> Frame | None:
    try:
        frame = await asyncio.wait_for(read_frame(reader), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        raise ConnectionError(f"timed out waiting for {what}: {exc}") from exc
    if frame is None:
        raise ConnectionError(f"connection closed while waiting for {what}")
    return frame


async def run_handshake(host: str = "127.0.0.1", port: int = 27017,
                        account: str = "simuser",
                        password: bytes = b"\x00" * 128,
                        session_key: bytes = b"\x42" * 128) -> HandshakeResult:
    """Perform the legacy handshake against a gateway CM listener."""
    result = HandshakeResult(ok=False)
    reader, writer = await asyncio.open_connection(host, port)
    try:
        # 1. server -> client: ChannelEncryptRequest (challenge)
        f = await _read_expect(reader, emsg.ChannelEncryptRequest, "ChannelEncryptRequest")
        result.frames.append(CapturedFrame("<", f.emsg, f.name, f.body, f.raw,
                                           note=f"challenge={len(f.body)}B"))

        # 2. client -> server: ChannelEncryptResponse
        #    [protocol_version:4][key_size:4][key][crc32:4][end_flag:4]
        body = (
            struct.pack("<ii", 1, len(session_key))
            + session_key
            + struct.pack("<II", 0x12345678, 0)
        )
        out = encode_handshake(emsg.ChannelEncryptResponse, body)
        writer.write(out)
        await writer.drain()
        result.frames.append(CapturedFrame(">", emsg.ChannelEncryptResponse,
                                           "ChannelEncryptResponse", body, out,
                                           note=f"session_key={len(session_key)}B"))

        # 3. server -> client: ChannelEncryptResult
        f = await _read_expect(reader, emsg.ChannelEncryptResult, "ChannelEncryptResult")
        result.channel_result = struct.unpack_from("<i", f.body, 0)[0]
        result.frames.append(CapturedFrame("<", f.emsg, f.name, f.body, f.raw,
                                           note=f"eresult={result.channel_result}"))
        if result.channel_result != 1:
            result.error = f"channel encrypt refused: eresult {result.channel_result}"
            return result

        # 4. client -> server: protobuf ClientLogon
        #    CMsgClientLogon: account_name=1, password=2, protocol_version=3
        logon = (
            proto.string_field(1, account)
            + proto.bytes_field(2, password)
            + proto.varint_field(3, 65542)
        )
        out = encode_proto(emsg.ClientLogon, b"", logon)
        writer.write(out)
        await writer.drain()
        result.frames.append(CapturedFrame(">", emsg.ClientLogon, "ClientLogon",
                                           logon, out, note=f"account={account}"))

        # 5. server -> client: ClientLogOnResponse (940)
        f = await _read_expect(reader, emsg.ClientLogOnResponse, "ClientLogOnResponse")
        result.logon_eresult = proto.field_varint(1, f.body)
        result.frames.append(CapturedFrame("<", f.emsg, f.name, f.body, f.raw,
                                           note=f"eresult={result.logon_eresult}"))

        # 6. on success the gateway also sends ClientSessionToken (761)
        if result.logon_eresult == 1:
            f = await asyncio.wait_for(read_frame(reader), timeout=5)
            if f is not None and f.emsg == emsg.ClientSessionToken:
                result.session_token = proto.field_varint(1, f.body)
                result.frames.append(CapturedFrame(
                    "<", f.emsg, f.name, f.body, f.raw,
                    note=f"token={result.session_token}"))
        result.ok = True
        return result
    finally:
        try:
            writer.close()
        except Exception:
            pass


def main() -> int:  # pragma: no cover - thin CLI
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="simulate the Lion-era client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27017)
    parser.add_argument("--account", default="simuser")
    parser.add_argument("--out", default="", help="write the annotated capture here")
    args = parser.parse_args()

    async def _run() -> int:
        res = await run_handshake(args.host, args.port, args.account)
        print(res.render_capture())
        if args.out:
            from pathlib import Path

            p = Path(args.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(res.render_capture())
            print(f"\n[capture written to {p}]")
        print(f"\nchannel_eresult={res.channel_result} "
              f"logon_eresult={res.logon_eresult} "
              f"session_token={res.session_token} ok={res.ok}")
        return 0 if res.ok else 1

    return asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main())
