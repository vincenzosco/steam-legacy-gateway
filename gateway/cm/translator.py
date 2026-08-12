"""Legacy <-> modern CM message translator.

Session state machine per legacy TCP connection (server = us, client = the
2015-era Steam app):

    AWAIT_ENCRYPT -> CHANNEL_OPEN -> AWAIT_LOGON -> ACTIVE
        (we send 130,          (client sends    (protobuf
         client replies 131,    protobuf 704,    logon response
         we send 132)            we reply 940)    + heartbeat loop)

The analysis in docs/PROTOCOL_ANALYSIS.md (grounded in the actual binary +
SteamKit2 + steamkit-python) establishes:

  * the channel-encrypt handshake is SERVER-INITIATED (we send
    ChannelEncryptRequest with a challenge; the client replies
    ChannelEncryptResponse with its AES session key; we confirm with
    ChannelEncryptResult). Earlier code had this backwards.
  * the client logs in with the PROTOBUF ClientLogon (EMsg 704 | proto flag)
    and expects the protobuf ClientLogOnResponse (940) + ClientSessionToken
    (761), not the pre-2013 binary logon response.
  * post-handshake payloads are AES-encrypted with the session key. Whether we
    can decrypt it (server-provided key vs key embedded in the client) is the
    open question — see docs/PROTOCOL_ANALYSIS.md §2.2. Until then we store the
    encrypted key blob for capture comparison.

VERIFY-BY-CAPTURE notes: exact handshake framing (struct-in-VT01 vs legacy),
protobuf header field numbers, and the AES scheme are marked inline.
"""
from __future__ import annotations

import asyncio
import gzip
import logging
import os
import struct
from enum import Enum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gateway.auth.bridge import Credentials, credentials_from_config
from gateway.cm import emsg, proto
from gateway.cm.framing import Frame, decode_frame, encode_handshake, encode_legacy, encode_proto
from gateway.cm.modern import ModernSession

log = logging.getLogger("gateway.cm.translator")

# Protocol version the gateway announces in ChannelEncryptRequest.
# TODO-VERIFY: exact value expected by the 2015 client (capture).
CHANNEL_PROTOCOL_VERSION = 1

CHALLENGE_LEN = 16  # per steamkit-python wire docs: 16-byte challenge


class State(str, Enum):
    AWAIT_ENCRYPT = "await_encrypt"  # we sent 130, awaiting client's 131
    CHANNEL_OPEN = "channel_open"    # client's 131 accepted, we sent 132
    AWAIT_LOGON = "await_logon"
    AUTHENTICATING = "authenticating"
    ACTIVE = "active"


class _ProtoLogon:
    """Minimal CMsgClientLogon reader (protobuf).

    CMsgClientLogon (SteamDatabase protobufs): account_name = 1 (string),
    password = 2 (bytes, RSA-encrypted), protocol_version = 3, client_os_type = 4,
    client_language = 5, machine_id = 8 (bytes) ...
    Only account_name is needed by the gateway (the modern session owns the
    real login). VERIFY-BY-CAPTURE: field numbers.
    """

    def __init__(self, body: bytes):
        self.body = body
        self.account_name = proto.field_text(1, body) or ""
        self.password_encrypted = proto.field_bytes(2, body) or b""


# The real CM serves one fixed RSA key; share a single key across sessions.
_server_rsa_key: rsa.RSAPrivateKey | None = None


def _server_key() -> rsa.RSAPrivateKey:
    global _server_rsa_key
    if _server_rsa_key is None:
        _server_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _server_rsa_key


class TranslatorSession:
    """One legacy CM connection, translated onto the shared modern session."""

    def __init__(self, writer: asyncio.StreamWriter, cfg: dict,
                 modern: ModernSession | None):
        self.writer = writer
        self.cfg = cfg
        self.modern = modern
        self.state = State.AWAIT_ENCRYPT
        self.steam_id = 0
        self.session_id = 1
        self.session_token = os.urandom(8).hex()
        self._client_session_key_encrypted = b""

    # -- public ----------------------------------------------------------------

    async def start_handshake(self) -> None:
        """Server-initiated channel encryption: send ChannelEncryptRequest(130)."""
        challenge = os.urandom(CHALLENGE_LEN)
        self.writer.write(encode_handshake(emsg.ChannelEncryptRequest, challenge))
        await self.writer.drain()
        log.debug("sent ChannelEncryptRequest (challenge %d bytes)", len(challenge))

    async def handle(self, frame: Frame) -> None:
        log.debug("[%s] %s (proto=%s struct=%s, %d bytes)", self.state.value,
                  frame.name, frame.proto, frame.struct, len(frame.raw))

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

    async def _on_ChannelEncryptResponse(self, frame: Frame) -> None:
        if self.state != State.AWAIT_ENCRYPT:
            log.warning("unexpected ChannelEncryptResponse in %s", self.state.value)
            return
        body = frame.body
        if len(body) < 16:
            log.warning("ChannelEncryptResponse too short (%d bytes)", len(body))
            return
        # [protocol_version:4][key_size:4][encrypted_session_key:keysize][crc32:4][end_flag:4]
        protocol_version, key_size = struct.unpack_from("<ii", body, 0)
        key = body[8:8 + key_size]
        crc = struct.unpack_from("<I", body, 8 + key_size)[0] if len(body) >= 12 + key_size else 0
        self._client_session_key_encrypted = key
        log.info(
            "client channel encrypt response: proto v%d, key_size %d, crc %08x, %d bytes",
            protocol_version, key_size, crc, len(body),
        )
        # TODO-VERIFY: decrypt `key` with our private key once the key story is
        # resolved (docs/PROTOCOL_ANALYSIS.md §2.2). The client encrypts it with
        # *something* — embedded Steam key or a server-provided key — and that
        # determines whether a pure MITM can read post-handshake traffic.
        # We store it so a capture can be compared byte-for-byte.
        result = struct.pack("<i", 1)  # EResult.OK
        self.writer.write(encode_handshake(emsg.ChannelEncryptResult, result))
        await self.writer.drain()
        self.state = State.CHANNEL_OPEN
        log.info("channel encrypted (channel_open)")

    async def _on_ChannelEncryptRequest(self, frame: Frame) -> None:
        # A legacy-era client would only send this if it expected to initiate;
        # the 2015 client waits for ours (start_handshake). Log it defensively.
        log.warning("client sent ChannelEncryptRequest (unexpected for this era)")

    async def _on_ChannelEncryptResult(self, frame: Frame) -> None:
        log.warning("client sent ChannelEncryptResult (unexpected for this era)")

    # -- logon -----------------------------------------------------------------

    async def _on_ClientLogon(self, frame: Frame) -> None:
        if self.state not in (State.CHANNEL_OPEN, State.AWAIT_LOGON):
            log.warning("ClientLogon in unexpected state %s", self.state.value)
            return
        logon = _ProtoLogon(frame.body)
        self.state = State.AUTHENTICATING

        if not logon.account_name:
            log.warning("protobuf ClientLogon without account_name "
                        "(%d bytes) — field numbers may differ", len(frame.body))
            await self._send_logon_failure("logon parse failed")
            return

        if not (self.modern and self.modern.is_ready()):
            await self._send_logon_failure("modern session not ready")
            return

        log.info("legacy logon for %r (password %d bytes, proto msg %d bytes)",
                 logon.account_name, len(logon.password_encrypted), len(frame.body))
        self.state = State.ACTIVE
        await self._send_logon_success()

    async def _send_logon_success(self) -> None:
        # Protobuf ClientLogOnResponse (940): header carries client_steam_id (1)
        # + client_session_id (2); body eresult (1) = EResult.OK.
        header = (
            proto.fixed64_field(1, self.steam_id)
            + proto.varint_field(2, self.session_id)
        )
        body = proto.varint_field(1, 1)  # EResult.OK
        await self._send_proto(emsg.ClientLogOnResponse, header, body)
        # ClientSessionToken (761): token (1, uint64).
        await self._send_proto(emsg.ClientSessionToken, b"",
                               proto.varint_field(1, int(self.session_token, 16)))
        log.info("legacy session ACTIVE (steamid %d, session %d)", self.steam_id,
                 self.session_id)

    async def _send_logon_failure(self, reason: str) -> None:
        body = proto.varint_field(1, 3)  # EResult.InvalidPassword placeholder
        await self._send_proto(emsg.ClientLogOnResponse, b"", body)
        log.warning("legacy logon refused: %s", reason)

    # -- heartbeat / keepalive -------------------------------------------------

    async def _on_ClientHeartBeat(self, frame: Frame) -> None:
        log.debug("heartbeat")

    async def _on_ClientNewLoginKey(self, frame: Frame) -> None:
        # Client proposes a login key (712); server usually accepts it (713).
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
        # CMsgMulti (protobuf): message_body = 1 (bytes), size_unzipped = 2 (varint).
        # When size_unzipped > 0 the body is gzip-compressed (SteamKit 2.5.0).
        payload = proto.field_bytes(1, frame.body) or b""
        size_unzipped = proto.field_varint(2, frame.body)
        if size_unzipped > 0:
            try:
                payload = gzip.decompress(payload)
            except (OSError, EOFError) as exc:
                log.warning("Multi gzip decompress failed: %s", exc)
                return
        while payload:
            try:
                nested = decode_frame(payload)
            except Exception as exc:
                log.warning("bad nested frame in Multi: %s", exc)
                break
            payload = payload[len(nested.raw):]
            await self.handle(nested)

    async def _unmapped(self, frame: Frame) -> None:
        # Register mappings here as the protocol is verified (docs/PROTOCOL_ANALYSIS.md).
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
