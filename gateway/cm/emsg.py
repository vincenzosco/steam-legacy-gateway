"""EMsg constants used by the Oct-2015 Steam client (the last Lion-era build).

Values are the **renumbered** EMsg set, proven by two independent sources:

  1. the client's own binary name→value table (scripts/_scan_emsg.py extracts it),
  2. SteamKit's `emsg.steamd` at commit 9b4807eb (2015-10-24, ten days after
     the client's build date).

Steam renumbered its EMsg enum well before this client shipped; the "classic"
values used by steamkit-python's docs (704 logon, 940 response, 761 token,
762 CMList, 130/131/132 channel encrypt, 133 multi) do **not** match this
client. Every number below was cross-checked against the binary's own table.

Wire detail: protobuf messages carry the `0x80000000` proto flag OR'd into the
EMsg field (see cm/framing.py). The values here are the *unflagged* message ids.
"""
from __future__ import annotations

# --- Channel encryption handshake (first thing on a new connection) ----------
ChannelEncryptRequest = 1303
ChannelEncryptResponse = 1304
ChannelEncryptResult = 1305

# --- Batching -----------------------------------------------------------------
Multi = 1  # CMsgMulti — multiple messages batched into one frame

# --- Client logon / session (protobuf, VT01) ----------------------------------
ClientLogon = 5514
ClientLogOnResponse = 751
ClientSessionToken = 850
ClientLoggedOff = 757
ClientLogOff = 706
ClientSetHeartbeatRate = 755
ClientHeartBeat = 703
ClientVACBanStatus = 782
ClientAccountInfo = 768
ClientCMList = 783
ClientServerList = 880
ClientAppInfoUpdate = 866
ClientGamesPlayed = 742
ClientLogonGameServer = 5559

# --- Steam Guard machine auth -------------------------------------------------
ClientRequestMachineAuth = 5541
ClientRequestMachineAuthResponse = 5542
ClientUpdateMachineAuth = 5537
ClientUpdateMachineAuthResponse = 5538
ClientReadMachineAuth = 5539
ClientReadMachineAuthResponse = 5540

# --- Login key (passwordless re-logon) ----------------------------------------
ClientNewLoginKey = 5463
ClientNewLoginKeyAccepted = 5464

# --- Deprecated (present in the enum, never sent by this client) -------------
ClientLogOn_Deprecated = 701
ClientAnonLogOn_Deprecated = 702

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
