"""Legacy <-> modern CM message translator.

Session state machine per legacy TCP connection (server = us, client = the
Oct-2015 Steam app):

    AWAIT_ENCRYPT -> CHANNEL_OPEN -> AWAIT_LOGON -> ACTIVE
        (we send 1303,          (client sends    (protobuf
         client replies 1304,    protobuf 5514,    logon response 751
         we send 1305)            we reply 751)    + heartbeat loop
                                                   + MachineAuth 5537/5538
                                                   + NewLoginKey 5463/5464)

The analysis in docs/PROTOCOL_ANALYSIS.md (grounded in the actual binary +
2015-era SteamKit) establishes:

  * the channel-encrypt handshake is SERVER-INITIATED: we send
    ChannelEncryptRequest (1303) with `[protocol_version:4][universe:4]`
    (universe = EUniverse.Public = 1, matching SteamKit MsgChannelEncryptRequest);
    the client replies ChannelEncryptResponse (1304) with its RSA-encrypted
    session key; we confirm with ChannelEncryptResult (1305, eresult).
  * the client logs in with the PROTOBUF ClientLogon (5514) whose body uses
    CMsgClientLogon field numbers account_name=50 / password=51, and expects
    the protobuf ClientLogOnResponse (751) + ClientSessionToken (850).
  * protobuf messages carry the 0x80000000 proto flag on the wire
    (cm/framing.py) — without it the client parses them as struct messages.
  * after a successful logon the gateway completes the Steam Guard MachineAuth
    flow (ClientUpdateMachineAuth 5537 -> response 5538, job-id targeted) and
    offers a ClientNewLoginKey (5463) which the client accepts (5464), then
    pushes ClientAccountInfo (768) + ClientCMList (783) so the client's
    library/CM-rotation UI has data.

  * the channel crypto is implemented (gateway/cm/crypto.py): the client's
    session key is RSA-encrypted to the embedded CM public key — after the
    key-swap (`gen-cm-key` + `patch_client.py --swap-key`) that is the
    bridge's key, so the bridge decrypts it (PKCS#1 v1.5, OAEP fallback) and
    AES-256 encrypts/decrypts the post-handshake payloads with it. The logon
    password (CMsgClientLogon.password, also RSA-encrypted to the same key)
    is decrypted and forwarded to the modern session — the credentials come
    from the client's login screen, not from config.

VERIFY-BY-CAPTURE: the exact RSA padding on the wire (PKCS#1 assumed, OAEP
fallback built in) and the AES frame layout remain to be confirmed against a
real client capture (docs/PROTOCOL_ANALYSIS.md §2.3).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import struct
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gateway.auth.bridge import Credentials, credentials_from_config
from gateway.cm import crypto as cmcrypto
from gateway.cm import emsg, machineauth, proto
from gateway.cm.framing import Frame, decode_frame, encode_handshake, encode_legacy, encode_proto
from gateway.cm.modern import ModernSession

log = logging.getLogger("gateway.cm.translator")

# Protocol version the gateway announces in ChannelEncryptRequest.
# SteamKit MsgChannelEncryptRequest.PROTOCOL_VERSION = 1; the client asserts it.
CHANNEL_PROTOCOL_VERSION = 1
# EUniverse.Public = 1 (SteamKit EUniverse enum).
EUNIVERSE_PUBLIC = 1

# Heartbeat seconds advertised in the logon response body (field 2).
HEARTBEAT_SECONDS = 5


class State(str, Enum):
    AWAIT_ENCRYPT = "await_encrypt"  # we sent 1303, awaiting client's 1304
    CHANNEL_OPEN = "channel_open"    # client's 1304 accepted, we sent 1305
    AWAIT_LOGON = "await_logon"
    AUTHENTICATING = "authenticating"
    ACTIVE = "active"


class _ProtoLogon:
    """Minimal CMsgClientLogon reader (protobuf).

    CMsgClientLogon (Oct-2015 SteamKit): account_name = 50 (string),
    password = 51 (bytes, RSA-encrypted), protocol_version = 1,
    client_os_type = 7, client_language = 6, machine_id = 30,
    should_remember_password = 8, sha_sentryfile = 83 (bytes), auth_code = 84.
    Only account_name / sha_sentryfile are needed by the gateway (the modern
    session owns the real login).
    """

    def __init__(self, body: bytes):
        self.body = body
        self.account_name = proto.field_text(50, body) or ""
        self.password_encrypted = proto.field_bytes(51, body) or b""
        self.sha_sentryfile = proto.field_bytes(83, body) or b""


def _synthesize_steam_id(account: str) -> int:
    """Stable placeholder SteamID derived from the account name.

    universe=Public(1), type=Individual(1), instance=0, account_id from a
    SHA-1 of the account name. The real value should come from the modern
    session (ModernSession.steam_id) when available.
    """
    digest = hashlib.sha1(account.encode("utf-8")).digest()
    account_id = struct.unpack("<I", digest[:4])[0]
    return (1 << 56) | (1 << 52) | account_id


def _ip_u32(ip: str) -> int:
    """Dotted-quad IP -> uint32 as the client's NetHelpers expects (LE bytes)."""
    octets = [int(part) for part in ip.split(".")]
    return struct.unpack("<I", bytes(octets))[0]


# The real CM serves one fixed RSA key; share a single key across sessions.
_server_rsa_key: rsa.RSAPrivateKey | None = None


def _server_key() -> rsa.RSAPrivateKey:
    global _server_rsa_key
    if _server_rsa_key is None:
        _server_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _server_rsa_key


class TranslatorSession:
    """One legacy CM connection, translated onto its account's modern session.

    Each connection runs its own state machine; the modern session it rides on
    is the one for the account in the ClientLogon (per-user pool in
    ModernFactory), so several users can be logged in at once.
    """

    def __init__(self, writer: asyncio.StreamWriter, cfg: dict,
                 modern: ModernSession | None, sentry_store=None,
                 modern_factory=None, rsa_key=None):
        self.writer = writer
        self.cfg = cfg
        self.modern = modern
        self.modern_factory = modern_factory
        self.state = State.AWAIT_ENCRYPT
        self.steam_id = 0
        self.session_id = 1
        self.session_token = os.urandom(8).hex()
        self._client_session_key_encrypted = b""
        self._session_key: bytes | None = None  # set after the handshake
        # rsa_key may be a loaded key object or a path to the PEM.
        self._rsa_key = None
        key_path = rsa_key if isinstance(rsa_key, (str, Path)) else None
        if isinstance(rsa_key, rsa.RSAPrivateKey):
            self._rsa_key = rsa_key
        else:
            key_path = key_path or cfg.get("cm", {}).get("rsa_key", "") or ""
            if key_path and Path(key_path).is_file():
                try:
                    from cryptography.hazmat.primitives import serialization as _ser

                    self._rsa_key = _ser.load_pem_private_key(
                        Path(key_path).read_bytes(), password=None)
                except Exception as exc:
                    log.warning("could not load CM RSA key %s: %s", key_path, exc)
        self._account = ""
        self._next_job_id = 1
        self.sentry_store = sentry_store or machineauth.SentinelStore(
            cfg.get("cm", {}).get("sentry_store") or None
        )

    # -- public ----------------------------------------------------------------

    async def start_handshake(self) -> None:
        """Server-initiated channel encryption: send ChannelEncryptRequest(1303).

        Body is the MsgChannelEncryptRequest struct: [protocol_version:4]
        [universe:4] — NOT a challenge (SteamKit 2015).
        """
        body = struct.pack("<II", CHANNEL_PROTOCOL_VERSION, EUNIVERSE_PUBLIC)
        self.writer.write(encode_handshake(emsg.ChannelEncryptRequest, body))
        await self.writer.drain()
        log.debug("sent ChannelEncryptRequest (proto v%d, universe %d)",
                  CHANNEL_PROTOCOL_VERSION, EUNIVERSE_PUBLIC)

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
        # Decrypt the client's session key with the bridge's RSA key (the
        # client encrypted it to the *embedded* CM public key — after the
        # key-swap that is ours, see docs/PROTOCOL_ANALYSIS.md §2.3).
        if self._rsa_key is not None and key:
            plain = cmcrypto.rsa_decrypt(key, self._rsa_key)
            if plain is not None and len(plain) == cmcrypto.SESSION_KEY_LEN:
                self._session_key = plain
                log.info("channel session key decrypted (%d bytes) — "
                         "post-handshake frames will be encrypted", len(plain))
            elif plain is not None:
                log.warning("session key decrypted to %d bytes (expected %d) — "
                            "keeping plaintext mode",
                            len(plain), cmcrypto.SESSION_KEY_LEN)
            else:
                log.warning("could not decrypt session key with bridge RSA key "
                            "(client keys not swapped? run `gen-cm-key` + "
                            "`patch_client.py --swap-key`) — plaintext mode")
        elif self._rsa_key is None:
            log.warning("no bridge CM RSA key configured — post-handshake "
                        "frames will be treated as plaintext")
        # The ChannelEncryptResult goes out plaintext; the client only arms its
        # filter after receiving it (CMClient.HandleEncryptResult), so we arm
        # ours after sending it too.
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
        self._account = logon.account_name

        if not logon.account_name:
            log.warning("protobuf ClientLogon without account_name "
                        "(%d bytes) — field numbers may differ", len(frame.body))
            await self._send_logon_failure("logon parse failed")
            return

        # Decrypt the password the client typed into ITS login screen. With the
        # key-swap applied, CMsgClientLogon.password decrypts with the bridge
        # key; these are the credentials we forward to the modern servers.
        password = self._decrypt_logon_password(logon)
        if password is None:
            await self._send_logon_failure(
                "could not decrypt logon password (client keys not swapped?)")
            return

        if self.modern is not None and self.modern.is_ready():
            # Single-account mode (account.* in config): the pre-started
            # session serves only the account it was logged in as.
            preset_user = getattr(self.modern, "credentials", None)
            if preset_user is not None and preset_user.username != logon.account_name:
                log.warning("logon for %r refused: bridge's modern session is "
                            "configured for %r only",
                            logon.account_name, preset_user.username)
                await self._send_logon_failure("bridge configured for a different account")
                return
        elif self.modern_factory is not None:
            # Multi-user mode: fetch (or create) the session for THIS account.
            creds = Credentials(username=logon.account_name, password=password)
            auth_code = proto.field_text(84, frame.body) or ""
            if auth_code:
                creds.two_factor_code = auth_code
            try:
                self.modern = await self.modern_factory.get(creds)
            except Exception as exc:
                log.warning("modern login with client credentials failed: %s", exc)
                await self._send_logon_failure("modern login failed")
                return
        if not (self.modern and self.modern.is_ready()):
            await self._send_logon_failure("modern session not ready")
            return

        log.info("legacy logon for %r (password %d bytes, proto msg %d bytes, "
                 "sha_sentryfile=%s) — forwarding client credentials to modern",
                 logon.account_name, len(logon.password_encrypted), len(frame.body),
                 logon.sha_sentryfile.hex() if logon.sha_sentryfile else "none")
        self.state = State.ACTIVE
        await self._send_logon_success(logon)

    def _decrypt_logon_password(self, logon: _ProtoLogon) -> str | None:
        """RSA-decrypt the client's password blob.

        With no bridge key configured (simulator / tests) the blob is a
        stand-in and is passed through as-is.
        """
        if not logon.password_encrypted:
            return ""
        if self._rsa_key is not None:
            return cmcrypto.decrypt_password(logon.password_encrypted, self._rsa_key)
        try:
            return logon.password_encrypted.decode("utf-8")
        except UnicodeDecodeError:
            return None

    async def _send_logon_success(self, logon: _ProtoLogon) -> None:
        if self.steam_id == 0:
            self.steam_id = self.modern.steam_id() if self.modern else 0
        if self.steam_id == 0:
            self.steam_id = _synthesize_steam_id(logon.account_name)

        # Protobuf ClientLogOnResponse (751): header carries steamid (1) +
        # client_sessionid (2); body eresult (1) = OK, heartbeat seconds (2).
        header = machineauth.header(steamid=self.steam_id,
                                    client_sessionid=self.session_id)
        body = (
            proto.varint_field(1, 1)  # EResult.OK
            + proto.varint_field(2, HEARTBEAT_SECONDS)  # out_of_game_heartbeat_seconds
            + proto.varint_field(3, HEARTBEAT_SECONDS)  # in_game_heartbeat_seconds
            + proto.varint_field(5, 0)  # rtime32_server_time
            + proto.varint_field(6, 0)  # account_flags
            + proto.varint_field(7, 0)  # cell_id
            + proto.string_field(21, "US")  # ip_country_code
        )
        await self._send_proto(emsg.ClientLogOnResponse, header, body)

        # ClientSessionToken (850): token (1, uint64).
        await self._send_proto(emsg.ClientSessionToken,
                               machineauth.header(steamid=self.steam_id,
                                                  client_sessionid=self.session_id),
                               proto.varint_field(1, int(self.session_token, 16)))

        # ClientAccountInfo (768): persona_name=1, ip_country=2,
        # count_authed_computers=5, account_flags=7.
        info = (
            proto.string_field(1, logon.account_name)
            + proto.string_field(2, "US")
            + proto.varint_field(5, 1)
            + proto.varint_field(7, 0)
        )
        await self._send_proto(emsg.ClientAccountInfo,
                               machineauth.header(steamid=self.steam_id,
                                                  client_sessionid=self.session_id),
                               info)

        # ClientCMList (783): cm_addresses=1 (repeated uint32), cm_ports=2.
        listen_ports = self.cfg.get("cm", {}).get("listen_ports", [27017])
        gateway_ip = self.cfg.get("gateway_ip", "127.0.0.1")
        cm_list = b"".join(proto.varint_field(1, _ip_u32(gateway_ip))
                           for _ in listen_ports)
        cm_list += b"".join(proto.varint_field(2, port) for port in listen_ports)
        await self._send_proto(emsg.ClientCMList,
                               machineauth.header(steamid=self.steam_id,
                                                  client_sessionid=self.session_id),
                               cm_list)

        # Steam Guard MachineAuth flow: push a sentry file unless the client
        # already presented the one we handed out.
        stored_sha = self.sentry_store.sha_for(logon.account_name)
        if not logon.sha_sentryfile or logon.sha_sentryfile != stored_sha:
            await self._send_update_machine_auth(logon.account_name)

        # Login key: offer a passwordless re-logon token.
        await self._send_new_login_key(logon.account_name)

        log.info("legacy session ACTIVE (steamid %d, session %d, account %r)",
                 self.steam_id, self.session_id, logon.account_name)

    async def _send_logon_failure(self, reason: str) -> None:
        body = proto.varint_field(1, 3)  # EResult.NoConnection placeholder
        await self._send_proto(emsg.ClientLogOnResponse, b"", body)
        log.warning("legacy logon refused: %s", reason)

    # -- Steam Guard machine auth ----------------------------------------------

    async def _send_update_machine_auth(self, account: str) -> None:
        """Server -> client ClientUpdateMachineAuth (5537).

        Hands the client a sentry file to write to disk. The client replies
        ClientUpdateMachineAuthResponse (5538) targeting our job id with the
        SHA-1 of what it actually wrote. We remember the SHA so the next logon
        (which presents sha_sentryfile=83) skips the push.
        """
        filename = machineauth.sentry_filename(account)
        sentry_data = os.urandom(256)  # stand-in sentry blob for this era
        entry = machineauth.SentryEntry(
            filename=filename,
            filesize=len(sentry_data),
            sha_file=hashlib.sha1(sentry_data).digest(),
            data=sentry_data,
        )
        self.sentry_store.put(account, entry)

        job_id = self._next_job_id
        self._next_job_id += 1
        header = machineauth.header(jobid_source=job_id,
                                    steamid=self.steam_id,
                                    client_sessionid=self.session_id)
        body = machineauth.build_update_machine_auth(filename, 0, sentry_data)
        await self._send_proto(emsg.ClientUpdateMachineAuth, header, body)
        log.info("sent ClientUpdateMachineAuth job=%d filename=%s (%d bytes)",
                 job_id, filename, len(sentry_data))

    async def _on_ClientUpdateMachineAuthResponse(self, frame: Frame) -> None:
        """Client confirms it wrote our sentry file (5538)."""
        resp = machineauth.parse_update_machine_auth_response(frame.body)
        target_job = machineauth.jobid_target(frame.header)
        log.info(
            "ClientUpdateMachineAuthResponse job=%d filename=%s eresult=%d "
            "filesize=%d cubwrote=%d sha=%s",
            target_job, resp.filename, resp.eresult, resp.filesize,
            resp.cubwrote, resp.sha_file.hex() if resp.sha_file else "none",
        )
        entry = self.sentry_store.get(self._account, resp.filename)
        if entry is not None:
            entry.filesize = resp.filesize or entry.filesize
            entry.sha_file = resp.sha_file or entry.sha_file
            self.sentry_store.put(self._account, entry)

    async def _on_ClientReadMachineAuth(self, frame: Frame) -> None:
        """Client asks for its stored sentry back (5539) -> serve it (5540)."""
        req = machineauth.parse_read_machine_auth(frame.body)
        entry = self.sentry_store.get(self._account, req.filename)
        if entry is None:
            log.info("ReadMachineAuth miss filename=%s (account %r)",
                     req.filename, self._account)
            body = machineauth.build_read_machine_auth_response(
                req.filename, eresult=2, filesize=0, sha_file=b"",
                offset=req.offset, bytes_read=b"")
        else:
            log.info("ReadMachineAuth hit filename=%s", req.filename)
            body = machineauth.build_read_machine_auth_response(
                req.filename, eresult=1, filesize=entry.filesize,
                sha_file=entry.sha_file, offset=req.offset,
                bytes_read=entry.data[req.offset:req.offset + req.cubtoread]
                if req.cubtoread else entry.data)
        # Client->server request: the client set jobid_source; the reply must
        # echo it back as jobid_target (SteamKit job correlation).
        job_id = machineauth.jobid_source(frame.header)
        header = machineauth.header(jobid_target=job_id,
                                    steamid=self.steam_id,
                                    client_sessionid=self.session_id)
        await self._send_proto(emsg.ClientReadMachineAuthResponse, header, body)

    async def _on_ClientRequestMachineAuth(self, frame: Frame) -> None:
        """Client uploads its sentry (5541) -> ack (5542)."""
        req = machineauth.parse_request_machine_auth(frame.body)
        # CMsgClientRequestMachineAuth carries only metadata (filename, filesize,
        # sha_sentryfile) — no raw sentry bytes — so we record the hash.
        entry = machineauth.SentryEntry(
            filename=req.filename or machineauth.sentry_filename(self._account),
            filesize=req.filesize,
            sha_file=req.sha_sentryfile,
            data=b"",
        )
        self.sentry_store.put(self._account, entry)
        log.info("RequestMachineAuth filename=%s filesize=%d sha=%s",
                 entry.filename, req.filesize,
                 req.sha_sentryfile.hex() if req.sha_sentryfile else "none")
        # Echo the client's jobid_source back as our jobid_target.
        job_id = machineauth.jobid_source(frame.header)
        header = machineauth.header(jobid_target=job_id,
                                    steamid=self.steam_id,
                                    client_sessionid=self.session_id)
        await self._send_proto(emsg.ClientRequestMachineAuthResponse, header,
                               machineauth.build_request_machine_auth_response(1))

    # -- login key --------------------------------------------------------------

    async def _send_new_login_key(self, account: str) -> None:
        """Server -> client ClientNewLoginKey (5463); client accepts with 5464."""
        unique_id = struct.unpack("<I", os.urandom(4))[0]
        login_key = os.urandom(32).hex()
        header = machineauth.header(steamid=self.steam_id,
                                    client_sessionid=self.session_id)
        body = machineauth.build_new_login_key(unique_id, login_key)
        await self._send_proto(emsg.ClientNewLoginKey, header, body)
        log.info("sent ClientNewLoginKey unique_id=%d", unique_id)

    async def _on_ClientNewLoginKeyAccepted(self, frame: Frame) -> None:
        key = machineauth.parse_new_login_key(frame.body)
        log.info("client accepted new login key (unique_id=%d)", key.unique_id)

    # -- heartbeat / keepalive -------------------------------------------------

    async def _on_ClientHeartBeat(self, frame: Frame) -> None:
        log.debug("heartbeat")

    async def _on_ClientSetHeartbeatRate(self, frame: Frame) -> None:
        log.info("client set heartbeat rate (proto 755)")

    async def _on_ClientLogOff(self, frame: Frame) -> None:
        log.info("client logged off (706)")

    # -- protobuf messages from the legacy client ------------------------------

    async def _on_ClientCMList(self, frame: Frame) -> None:
        log.info("legacy client sent ClientCMList (unexpected direction)")

    async def _on_ClientAppInfoUpdate(self, frame: Frame) -> None:
        log.info("legacy client asked for app info (VT01) — ignored")

    # -- plumbing --------------------------------------------------------------

    async def _handle_multi(self, frame: Frame) -> None:
        # CMsgMulti (protobuf): size_unzipped = 1 (int32), message_body = 2
        # (bytes). When size_unzipped > 0 the body is gzip-compressed.
        size_unzipped = proto.field_varint(1, frame.body)
        payload = proto.field_bytes(2, frame.body) or b""
        if size_unzipped > 0:
            import gzip

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

    async def _send_proto(self, emsg_id: int, header: bytes, body: bytes) -> None:
        payload = encode_proto(emsg_id, header, body)
        # With the channel encrypted, only the post-VT01 data is encrypted
        # (TcpConnection.ProcessOutgoing); the length prefix + magic stay plain.
        if self._session_key is not None:
            inner = cmcrypto.encrypt_payload(payload[4:], self._session_key)
            payload = struct.pack("<I", len(inner)) + inner
        self.writer.write(payload)
        await self.writer.drain()

    def decrypt_payload(self, payload: bytes) -> bytes:
        """Decrypt an inbound frame payload if the channel is encrypted.

        Called by the server's read loop BEFORE decode_frame. The
        ChannelEncryptResponse itself arrives before the key is established,
        so it passes through untouched.
        """
        if self._session_key is None:
            return payload
        try:
            return cmcrypto.decrypt_payload(payload, self._session_key)
        except Exception as exc:
            log.warning("payload decrypt failed (%s) — dropping frame", exc)
            return payload

    async def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass
