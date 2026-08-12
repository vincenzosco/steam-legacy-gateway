"""Legacy <-> modern CM message translator.

Session state machine per legacy TCP connection:

    AWAIT_ENCRYPT -> CHANNEL_OPEN -> AWAIT_LOGON -> AUTHENTICATING -> ACTIVE
                        (130/131/132)      (704)          (modern    (heartbeats,
                                                          login)      games, etc.)

The 2013 client speaks legacy binary messages (EMsg <= ~720) and VT01 protobuf
messages (940+). Modern Valve servers speak only the modern protocol, so this
translator terminates the legacy side and drives the modern side through
`ModernSession` (ValvePython/steam).

HONESTY NOTE: the exact wire layouts of the 2013 logon handshake (RSA key
exchange via ChannelEncrypt* and the MsgClientLogon fields) must be verified
against packet captures from a real Lion-era client. The parsing below follows
SteamKit's public sources; fields marked TODO-VERIFY need capture confirmation.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from enum import Enum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gateway.auth.bridge import Credentials, credentials_from_config
from gateway.cm import emsg
from gateway.cm.framing import Frame, encode_legacy, encode_proto
from gateway.cm.modern import ModernSession

log = logging.getLogger("gateway.cm.translator")

PROTOCOL_VERSION_2013 = 17  # typical for the 2013-era client (see captures)


class State(str, Enum):
    AWAIT_ENCRYPT = "await_encrypt"
    CHANNEL_OPEN = "channel_open"
    AWAIT_LOGON = "await_logon"
    AUTHENTICATING = "authenticating"
    ACTIVE = "active"


class _LegacyLogon:
    """Best-effort parser for the 2013-era MsgClientLogon body.

    Layout (after the 4-byte EMsg), per SteamKit's MsgClientLogon serialization:

        ProtocolVersion : int32
        ClientOsType    : uint32
        ClientLanguage  : uint32
        ClientAppId     : uint32
        Unicode         : byte
        SupportsNewLogin: byte
        MachineId       : uint32 len + bytes
        SteamID         : uint64
        AccountName     : int16 len + utf8
        Password        : int16 len + bytes   (RSA-encrypted)
        ... (login key / remember / sentinel flags follow)

    TODO-VERIFY: the 2013 wire format likely used an ExtendedClientMsgHdr
    (SteamID u64 + SessionID u32 between the EMsg and the body), which would
    shift every offset here by 12 bytes. Confirm with captures before relying
    on field offsets — the parser is lenient on failure by design.
    """

    def __init__(self, body: bytes):
        self.body = body
        self.protocol_version = 0
        self.username = ""
        self.password_encrypted = b""

    def parse(self) -> bool:
        try:
            off = 0
            (self.protocol_version,) = struct.unpack_from("<i", self.body, off); off += 4
            off += 4 * 3  # ClientOsType, ClientLanguage, ClientAppId
            off += 2      # Unicode, SupportsNewLogin
            (mach_len,) = struct.unpack_from("<I", self.body, off); off += 4
            off += mach_len
            off += 8      # SteamID
            self.username = self._read_string(off)
            off += 2 + len(self.username.encode("utf-8"))
            self.password_encrypted = self._read_bytes(off)
            return True
        except (struct.error, IndexError):
            log.warning("could not parse legacy ClientLogon body "
                        "(%d bytes) - layout may differ from SteamKit docs", len(self.body))
            return False

    def _read_string(self, off: int) -> str:
        (n,) = struct.unpack_from("<H", self.body, off)
        return self.body[off + 2: off + 2 + n].decode("utf-8", errors="replace")

    def _read_bytes(self, off: int) -> bytes:
        (n,) = struct.unpack_from("<H", self.body, off)
        return self.body[off + 2: off + 2 + n]


# In the real protocol the CM serves one fixed RSA key for password
# encryption; share a single key across sessions instead of generating one per
# connection. (Placeholder until the 2013 key-exchange format is captured.)
_server_rsa_key: rsa.RSAPrivateKey | None = None


def _server_key() -> rsa.RSAPrivateKey:
    global _server_rsa_key
    if _server_rsa_key is None:
        _server_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _server_rsa_key


class TranslatorSession:
    """One legacy CM connection, translated onto the shared modern session."""

    def __init__(self, writer: asyncio.StreamWriter, cfg: dict,
                 modern: ModernSession):
        self.writer = writer
        self.cfg = cfg
        self.modern = modern
        self.state = State.AWAIT_ENCRYPT
        self.steam_id = 0
        self._rsa_key = _server_key()

    # -- public ----------------------------------------------------------------

    async def handle(self, frame: Frame) -> None:
        log.debug("[%s] %s (proto=%s, %d bytes)", self.state.value, frame.name,
                  frame.proto, len(frame.raw))

        if frame.emsg == emsg.Multi:
            await self._handle_multi(frame)
            return

        handler = getattr(self, f"_on_{frame.name}", None)
        if handler is None:
            log.info("unmapped legacy message %s (%d) in state %s",
                     frame.name, frame.emsg, self.state.value)
            await self._unmapped(frame)
            return
        await handler(frame)

    # -- channel encryption handshake ------------------------------------------

    async def _on_ChannelEncryptRequest(self, frame: Frame) -> None:
        if self.state != State.AWAIT_ENCRYPT:
            log.warning("unexpected ChannelEncryptRequest in %s", self.state.value)
            return
        pub = self._rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # ChannelEncryptResponse: [emsg:4][pubkey_len:4][pubkey DER][...]
        # TODO-VERIFY: exact 2013 layout (modulus/exponent vs DER) per captures.
        body = struct.pack("<I", len(pub)) + pub
        await self._send_legacy(emsg.ChannelEncryptResponse, body)

    async def _on_ChannelEncryptResult(self, frame: Frame) -> None:
        (result,) = struct.unpack_from("<I", frame.body, 0) if len(frame.body) >= 4 else (0,)
        if result == 1:
            self.state = State.CHANNEL_OPEN
            log.info("legacy channel encrypted (state=channel_open)")
        else:
            log.warning("legacy ChannelEncryptResult != 1 (%d)", result)

    # -- logon -----------------------------------------------------------------

    async def _on_ClientLogon(self, frame: Frame) -> None:
        if self.state not in (State.CHANNEL_OPEN, State.AWAIT_LOGON):
            log.warning("ClientLogon in unexpected state %s", self.state.value)
            return
        logon = _LegacyLogon(frame.body)
        parsed = logon.parse()
        self.state = State.AUTHENTICATING
        if not parsed:
            await self._send_logon_failure("logon parse failed")
            return

        # The gateway already owns a modern session (started at boot). Only let
        # the legacy logon through if the modern login actually succeeded — a
        # failed modern login (bad guard code, etc.) must refuse the legacy side.
        if not self.modern.is_ready():
            await self._send_logon_failure("modern session not ready")
            return

        log.info("legacy logon for %r (proto v%d, pw len %d)",
                 logon.username, logon.protocol_version, len(logon.password_encrypted))
        # TODO-VERIFY: decrypt password_encrypted with self._rsa_key once the
        # exact encryption (PKCS1v15 vs OAEP, key selection) is confirmed, and
        # cross-check the account against the modern session's account.
        self.steam_id = 0
        self.state = State.ACTIVE
        await self._send_logon_success()

    async def _send_logon_success(self) -> None:
        # Legacy ClientLogonResponse body (best-effort, per SteamKit):
        #   [emsg:4][session_id:4][steam_id:8][eresult:4][...]
        body = struct.pack("<iQi", 1, self.steam_id, 1)  # session, steamid, EResult.OK
        await self._send_legacy(emsg.ClientLogonResponse, body)
        log.info("legacy session ACTIVE (session %d)", 1)

    async def _send_logon_failure(self, reason: str) -> None:
        body = struct.pack("<iQi", 0, 0, 3)  # EResult=3 (InvalidPassword) placeholder
        await self._send_legacy(emsg.ClientLogonResponse, body)
        log.warning("legacy logon refused: %s", reason)

    # -- heartbeat / keepalive -------------------------------------------------

    async def _on_ClientHeartBeat(self, frame: Frame) -> None:
        # The 2013 server responded to heartbeats with ClientHeartBeat only when
        # the rate needed changing; silence is normal. TODO-VERIFY.
        log.debug("heartbeat")

    async def _on_ClientNewLoginKey(self, frame: Frame) -> None:
        # Client proposes a login key; server usually accepts it.
        await self._send_legacy(emsg.ClientNewLoginKeyAccepted, b"")

    async def _on_ClientSetHeartbeatRate(self, frame: Frame) -> None:
        await self._send_legacy(emsg.ClientSetHeartbeatRate, b"")

    # -- protobuf messages from the legacy client ------------------------------

    async def _on_ClientCMList(self, frame: Frame) -> None:
        log.info("legacy client asked for CM list (VT01) — ignored")

    async def _on_ClientUpdateAppInfo(self, frame: Frame) -> None:
        log.info("legacy client asked for app info (VT01) — ignored")

    # -- plumbing --------------------------------------------------------------

    async def _handle_multi(self, frame: Frame) -> None:
        from gateway.cm.framing import decode_frame, FramingError

        body = frame.body
        while body:
            try:
                nested = decode_frame(body)
            except FramingError as exc:
                log.warning("bad nested frame in Multi: %s", exc)
                break
            body = body[len(nested.raw):]
            await self.handle(nested)

    async def _unmapped(self, frame: Frame) -> None:
        # Register mappings here as the protocol is verified (see README status).
        pass

    async def _send_legacy(self, emsg_id: int, body: bytes) -> None:
        self.writer.write(encode_legacy(emsg_id, body))
        await self.writer.drain()

    async def _send_proto(self, emsg_id: int, header: bytes, body: bytes) -> None:
        self.writer.write(encode_proto(emsg_id, header, body))
        await self.writer.drain()

    async def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass
