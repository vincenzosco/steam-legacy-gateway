"""EMsg constants used by the 2013-era Steam client.

Values are taken from SteamKit's public `EMsg` enum (SteamRE/SteamKit) and
SteamDatabase's tracked protocol dumps. The 2013-era client used the classic
binary messages below; protobuf messages (940+) use the VT01 framing with the
protobuf header carrying the EMsg's job info.

NOTE: these are the stable, well-known values. Exact 2013 behaviour for the
message *bodies* should be verified against packet captures before relying on
field-level parsing (see cm/framing.py and cm/translator.py comments).
"""
from __future__ import annotations

# --- Channel encryption handshake (first thing on a new connection) ----------
ChannelEncryptRequest = 130
ChannelEncryptResponse = 131
ChannelEncryptResult = 132
Multi = 133  # multiple messages batched into one frame

# --- Client logon / heartbeat (legacy binary messages) ----------------------
ClientHeartBeat = 703
ClientLogon = 704
ClientLogonResponse = 705
ClientLoggedOff = 706
ClientVACBanStatus = 707
ClientNewLoginKey = 712
ClientNewLoginKeyAccepted = 713
ClientSetHeartbeatRate = 718
ClientGamesPlayed = 720

# --- Protobuf-era equivalents (VT01 framing) ---------------------------------
# Confirmed in the Oct-2015 client binary (k_EMsgClient* strings) + SteamKit.
ClientLogOnResponse = 940
ClientSessionToken = 761
ClientCMList = 762
ClientUpdateAppInfo = 745

_NAMES: dict[int, str] = {}


def _register(name: str, value: int) -> None:
    _NAMES[value] = name


for _name in list(globals()):
    if _name.startswith("_") or _name in ("annotations", "dict", "list"):
        continue
    _value = globals()[_name]
    if isinstance(_value, int):
        _register(_name, _value)
del _name, _value


def emsg_name(emsg: int) -> str:
    return _NAMES.get(emsg, f"EMsg_{emsg}")
