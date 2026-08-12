"""Steam Guard MachineAuth messages + login key flow (Oct-2015 client).

The Steam Guard "remember this computer" flow, per the 2015-era SteamKit
`SteamUser.cs` (HandleUpdateMachineAuth / SendMachineAuthResponse) and the
client binary's message constants (5537-5542):

    server -> client  ClientUpdateMachineAuth (5537)
                      header: jobid_source set to a job id (fixed64, field 10)
                      body:   filename, offset, cubtowrite, bytes (the sentry)
    client -> server  ClientUpdateMachineAuthResponse (5538)
                      header: jobid_target = the request's source job id (11)
                      body:   filename, eresult, filesize, sha_file, offset,
                              cubwrote (how many bytes the client wrote to disk)

Two client-initiated variants complete the trio (SteamKit 2015 also ships
handlers for these):

    client -> server  ClientReadMachineAuth (5539)   client wants its sentry back
    server -> client  ClientReadMachineAuthResponse (5540)  bytes_read
    client -> server  ClientRequestMachineAuth (5541)  client uploads its sentry
    server -> client  ClientRequestMachineAuthResponse (5542)  eresult

And the login-key pair that lets the client re-login without a password:

    server -> client  ClientNewLoginKey (5463)       unique_id, login_key
    client -> server  ClientNewLoginKeyAccepted (5464)  unique_id

Field numbers below come from the Oct-2015-era generated SteamKit protos
(SteamMsgClientServer.cs / SteamMsgBase.cs at commit 9b4807eb), which mirror
SteamDatabase/SteamTracking.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.cm import emsg, proto

log = logging.getLogger("gateway.cm.machineauth")

# --- proto header helpers ------------------------------------------------------
# CMsgProtoBufHeader: steamid=1 (fixed64), client_sessionid=2 (int32),
# jobid_source=10 (fixed64), jobid_target=11 (fixed64).
# Job ids default to ulong.MaxValue (-1) meaning "no job"; the client maps -1
# to 0 when reading SourceJobID. We use a small positive counter.

JOB_NONE = 0xFFFFFFFFFFFFFFFF


def header(jobid_source: int = JOB_NONE, jobid_target: int = JOB_NONE,
           steamid: int = 0, client_sessionid: int = 0) -> bytes:
    """Build a CMsgProtoBufHeader. Job ids are omitted when unset (0 or -1)."""
    out = b""
    if steamid:
        out += proto.fixed64_field(1, steamid)
    if client_sessionid:
        out += proto.varint_field(2, client_sessionid)
    if jobid_source not in (0, JOB_NONE):
        out += proto.fixed64_field(10, jobid_source)
    if jobid_target not in (0, JOB_NONE):
        out += proto.fixed64_field(11, jobid_target)
    return out


def jobid_target(header_bytes: bytes) -> int:
    """Read jobid_target (field 11, fixed64) from a proto header."""
    return proto.field_fixed64(11, header_bytes, default=JOB_NONE)


def jobid_source(header_bytes: bytes) -> int:
    return proto.field_fixed64(10, header_bytes, default=JOB_NONE)


def steamid_of(header_bytes: bytes) -> int:
    return proto.field_fixed64(1, header_bytes)


# --- sentry file ----------------------------------------------------------------

SENTRY_PREFIX = "ssfn"  # Valve's sentry filename prefix


def sentry_filename(account: str) -> str:
    """Deterministic sentry filename for an account (mirrors Valve's scheme)."""
    import hashlib

    digest = hashlib.sha1(account.encode("utf-8")).hexdigest()
    return SENTRY_PREFIX + digest[:37]  # Valve uses a fixed-length hash string


# --- machine auth builders (server -> client) -----------------------------------

def build_update_machine_auth(filename: str, offset: int, data: bytes) -> bytes:
    """CMsgClientUpdateMachineAuth: filename=1, offset=2, cubtowrite=3, bytes=4."""
    return (
        proto.string_field(1, filename)
        + proto.varint_field(2, offset)
        + proto.varint_field(3, len(data))
        + proto.bytes_field(4, data)
    )


def build_read_machine_auth(filename: str, offset: int, cubtoread: int) -> bytes:
    """CMsgClientReadMachineAuth (client asks to read its sentry back)."""
    return (
        proto.string_field(1, filename)
        + proto.varint_field(2, offset)
        + proto.varint_field(3, cubtoread)
    )


def build_read_machine_auth_response(filename: str, eresult: int, filesize: int,
                                     sha_file: bytes, offset: int,
                                     bytes_read: bytes) -> bytes:
    """CMsgClientReadMachineAuthResponse."""
    return (
        proto.string_field(1, filename)
        + proto.varint_field(2, eresult)
        + proto.varint_field(3, filesize)
        + proto.bytes_field(4, sha_file)
        + proto.varint_field(6, offset)
        + proto.varint_field(7, len(bytes_read))
        + proto.bytes_field(8, bytes_read)
    )


def build_request_machine_auth_response(eresult: int) -> bytes:
    """CMsgClientRequestMachineAuthResponse: eresult=1."""
    return proto.varint_field(1, eresult)


def build_new_login_key(unique_id: int, login_key: str) -> bytes:
    """CMsgClientNewLoginKey: unique_id=1 (uint32), login_key=2 (string)."""
    return proto.varint_field(1, unique_id) + proto.string_field(2, login_key)


def build_new_login_key_accepted(unique_id: int) -> bytes:
    """CMsgClientNewLoginKeyAccepted: unique_id=1 (uint32)."""
    return proto.varint_field(1, unique_id)


def build_update_machine_auth_response(filename: str, eresult: int, filesize: int,
                                       sha_file: bytes, offset: int,
                                       cubwrote: int) -> bytes:
    """CMsgClientUpdateMachineAuthResponse (client confirms the write)."""
    return (
        proto.string_field(1, filename)
        + proto.varint_field(2, eresult)
        + proto.varint_field(3, filesize)
        + proto.bytes_field(4, sha_file)
        + proto.varint_field(6, offset)
        + proto.varint_field(7, cubwrote)
    )


# --- machine auth parsers (client -> server) ------------------------------------

@dataclass
class MachineAuthUpdate:
    filename: str = ""
    offset: int = 0
    cubtowrite: int = 0
    bytes_: bytes = b""
    otp_type: int = 0
    otp_identifier: str = ""
    otp_sharedsecret: bytes = b""
    otp_timedrift: int = 0


@dataclass
class MachineAuthUpdateResponse:
    filename: str = ""
    eresult: int = 0
    filesize: int = 0
    sha_file: bytes = b""
    getlasterror: int = 0
    offset: int = 0
    cubwrote: int = 0
    otp_type: int = 0
    otp_value: bytes = b""
    otp_identifier: str = ""


@dataclass
class MachineAuthRead:
    filename: str = ""
    offset: int = 0
    cubtoread: int = 0


@dataclass
class MachineAuthRequest:
    filename: str = ""
    eresult_sentryfile: int = 0
    filesize: int = 0
    sha_sentryfile: bytes = b""
    lock_account_action: int = 0
    otp_type: int = 0
    otp_identifier: str = ""
    otp_sharedsecret: bytes = b""
    otp_value: bytes = b""
    machine_name: str = ""
    machine_name_userchosen: str = ""


@dataclass
class NewLoginKey:
    unique_id: int = 0
    login_key: str = ""


def parse_update_machine_auth(body: bytes) -> MachineAuthUpdate:
    return MachineAuthUpdate(
        filename=proto.field_text(1, body) or "",
        offset=proto.field_varint(2, body),
        cubtowrite=proto.field_varint(3, body),
        bytes_=proto.field_bytes(4, body) or b"",
        otp_type=proto.field_varint(5, body),
        otp_identifier=proto.field_text(6, body) or "",
        otp_sharedsecret=proto.field_bytes(7, body) or b"",
        otp_timedrift=proto.field_varint(8, body),
    )


def parse_update_machine_auth_response(body: bytes) -> MachineAuthUpdateResponse:
    return MachineAuthUpdateResponse(
        filename=proto.field_text(1, body) or "",
        eresult=proto.field_varint(2, body),
        filesize=proto.field_varint(3, body),
        sha_file=proto.field_bytes(4, body) or b"",
        getlasterror=proto.field_varint(5, body),
        offset=proto.field_varint(6, body),
        cubwrote=proto.field_varint(7, body),
        otp_type=proto.field_varint(8, body),
        otp_value=proto.field_bytes(9, body) or b"",
        otp_identifier=proto.field_text(10, body) or "",
    )


def parse_read_machine_auth(body: bytes) -> MachineAuthRead:
    return MachineAuthRead(
        filename=proto.field_text(1, body) or "",
        offset=proto.field_varint(2, body),
        cubtoread=proto.field_varint(3, body),
    )


@dataclass
class MachineAuthReadResponse:
    filename: str = ""
    eresult: int = 0
    filesize: int = 0
    sha_file: bytes = b""
    getlasterror: int = 0
    offset: int = 0
    cubread: int = 0
    bytes_read: bytes = b""
    filename_sentry: str = ""


def parse_read_machine_auth_response(body: bytes) -> MachineAuthReadResponse:
    return MachineAuthReadResponse(
        filename=proto.field_text(1, body) or "",
        eresult=proto.field_varint(2, body),
        filesize=proto.field_varint(3, body),
        sha_file=proto.field_bytes(4, body) or b"",
        getlasterror=proto.field_varint(5, body),
        offset=proto.field_varint(6, body),
        cubread=proto.field_varint(7, body),
        bytes_read=proto.field_bytes(8, body) or b"",
        filename_sentry=proto.field_text(9, body) or "",
    )


def parse_request_machine_auth(body: bytes) -> MachineAuthRequest:
    return MachineAuthRequest(
        filename=proto.field_text(1, body) or "",
        eresult_sentryfile=proto.field_varint(2, body),
        filesize=proto.field_varint(3, body),
        sha_sentryfile=proto.field_bytes(4, body) or b"",
        lock_account_action=proto.field_varint(6, body),
        otp_type=proto.field_varint(7, body),
        otp_identifier=proto.field_text(8, body) or "",
        otp_sharedsecret=proto.field_bytes(9, body) or b"",
        otp_value=proto.field_bytes(10, body) or b"",
        machine_name=proto.field_text(11, body) or "",
        machine_name_userchosen=proto.field_text(12, body) or "",
    )


def parse_new_login_key(body: bytes) -> NewLoginKey:
    return NewLoginKey(
        unique_id=proto.field_varint(1, body),
        login_key=proto.field_text(2, body) or "",
    )


# --- sentinel store -------------------------------------------------------------

@dataclass
class SentryEntry:
    filename: str
    filesize: int
    sha_file: bytes
    data: bytes = b""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "filesize": self.filesize,
            "sha_file": base64.b64encode(self.sha_file).decode("ascii"),
            "data": base64.b64encode(self.data).decode("ascii"),
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SentryEntry":
        return cls(
            filename=d.get("filename", ""),
            filesize=d.get("filesize", 0),
            sha_file=base64.b64decode(d.get("sha_file", "")),
            data=base64.b64decode(d.get("data", "")),
            updated_at=d.get("updated_at", ""),
        )


class SentinelStore:
    """Persists per-account sentry files (Steam Guard machine auth state).

    The gateway acts as the CM server, so it hands the sentry file to the
    client via ClientUpdateMachineAuth and remembers the result. The store
    survives restarts so a re-connecting client can ReadMachineAuth its sentry
    back (and so the account's sentry stays stable across sessions).
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._entries: dict[str, SentryEntry] = {}  # key = account|filename
        self.load()

    # -- public -------------------------------------------------------------

    def get(self, account: str, filename: str) -> SentryEntry | None:
        return self._entries.get(f"{account}|{filename}")

    def put(self, account: str, entry: SentryEntry) -> None:
        import datetime

        entry.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._entries[f"{account}|{entry.filename}"] = entry
        self.save()

    def delete(self, account: str, filename: str) -> None:
        self._entries.pop(f"{account}|{filename}", None)
        self.save()

    def sha_for(self, account: str) -> bytes | None:
        """SHA-1 of the most recently stored sentry for the account (any name)."""
        matches = [
            e for k, e in self._entries.items() if k.startswith(f"{account}|")
        ]
        if not matches:
            return None
        return max(matches, key=lambda e: e.updated_at).sha_file

    # -- persistence ---------------------------------------------------------

    def load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("could not read sentry store %s: %s", self.path, exc)
            return
        self._entries = {
            k: SentryEntry.from_dict(v) for k, v in raw.get("entries", {}).items()
        }
        log.info("loaded %d sentry entr%s from %s", len(self._entries),
                 "y" if len(self._entries) == 1 else "ies", self.path)

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({
                "entries": {k: v.to_dict() for k, v in self._entries.items()},
            }, indent=2))
        except OSError as exc:
            log.warning("could not write sentry store %s: %s", self.path, exc)
