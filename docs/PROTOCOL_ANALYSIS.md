# Legacy Steam client protocol analysis

What the Lion-era Steam client actually does, what it expects from a CM server,
and what the gateway is missing — grounded in the real binary (downloaded from
Macintosh Garden) and the public protocol sources (SteamKit2, steamkit-python,
SteamDatabase protobufs).

## 0. The artifact we analyzed

| | |
|---|---|
| File | `Steam_MacOS_X_10.6_Snow_Leopard.zip` (Macintosh Garden, MD5 `67d2088414f94800455f845ec8a0ff78`) |
| Build date | **Oct 14, 2015** (files timestamped `14 ott 2015`) — the last build that runs on 10.6/10.7 |
| Build path leaked | `/Users/buildbot/buildslave_steam/steam_rel_client_osx/build/...` |
| Architecture | **i386 only** (32-bit; runs on Lion, dead on 10.15+) |
| HTTPS/TLS | Apple **Security.framework (SecureTransport)** + SystemConfiguration — the client speaks whatever TLS Lion's OS stack offers (TLS 1.0/1.1 era) |
| Protocol buffers | Embeds Google protobuf runtime — the `VT01` protobuf layer |
| Key dylibs | `steamclient.dylib` (59 MB, the protocol core), `steamui.dylib`, `libsteam.dylib`, `steamloader.dylib`, `steamservice.dylib`, `friendsui.dylib`, `chromehtml.dylib` (WebKit shell) |

## 1. Bootstrap & endpoints (what the client contacts)

From `strings` on `steamclient.dylib` / `osx32/steam`:

- **CM**: `cm0.steampowered.com` (DNS) **and hardcoded CM IPs** — e.g.
  `208.64.200.201:27017/27018/27019`, plus Valve-internal `172.16.3.x` leftovers.
  ⚠️ **Hardcoded IPs bypass /etc/hosts.** A hosts-file redirect will not capture
  those connections; you need a router redirect or a PF rule on the Lion machine
  for port 27017-27020. (The client caches the CM list from `ClientCMList` too.)
- **Web API**: `api.steampowered.com`, `api.beta.steampowered.com`
- **Store/login**: `store.steampowered.com`, `login.steampowered.com` (login UI),
  `steamcommunity.com`
- **Content**: `cs.steampowered.com` (content server host), `steamcdn-a.akamaihd.net`,
  `cdn.akamai.steamstatic.com` — **not** `steampipe`/`cacheN` for this era.
- Cell-ID based content server selection (`CellID (HTTP): (…) pinging...`).

## 2. The CM protocol — what the client actually speaks

### 2.1 EMsg numbering: the client uses the RENUMBERED set

**Critical finding (from the binary's own name→value table, extracted by
`scripts/_scan_emsg.py`, cross-checked against SteamKit's `emsg.steamd` at
commit 9b4807eb, 2015-10-24):** Steam renumbered its EMsg enum before this
client shipped, so the "classic" values (704 logon / 940 response / 761 token /
762 CMList / 130/131/132 channel encrypt / 133 multi) are **wrong for this
client**. The correct values the gateway uses:

| Message | EMsg | Notes |
|---|---|---|
| `Multi` | 1 | protobuf batching frame |
| `ClientHeartBeat` | 703 | protobuf (`CMsgClientHeartBeat`), sent by client |
| `ClientGamesPlayed` | 742 | protobuf |
| `ClientLogOnResponse` | 751 | protobuf — logon reply |
| `ClientSetHeartbeatRate` | 755 | protobuf |
| `ClientLoggedOff` | 757 | protobuf |
| `ClientAccountInfo` | 768 | protobuf — persona/account data |
| `ClientVACBanStatus` | 782 | protobuf |
| `ClientCMList` | 783 | protobuf — CM rotation list |
| `ClientSessionToken` | 850 | protobuf — AM session token |
| `ClientAppInfoUpdate` | 866 | protobuf |
| `ClientServerList` | 880 | protobuf |
| `ChannelEncryptRequest` | 1303 | struct — server-initiated |
| `ChannelEncryptResponse` | 1304 | struct |
| `ChannelEncryptResult` | 1305 | struct |
| `ClientNewLoginKey` | 5463 | protobuf — server offers a login key |
| `ClientNewLoginKeyAccepted` | 5464 | protobuf — client accepts |
| `ClientLogon` | 5514 | protobuf — the logon itself |
| `ClientUpdateMachineAuth` | 5537 | protobuf — Steam Guard sentry push |
| `ClientUpdateMachineAuthResponse` | 5538 | protobuf — client wrote sentry |
| `ClientReadMachineAuth` | 5539 | protobuf — client reads sentry |
| `ClientReadMachineAuthResponse` | 5540 | protobuf |
| `ClientRequestMachineAuth` | 5541 | protobuf — client uploads sentry |
| `ClientRequestMachineAuthResponse` | 5542 | protobuf |
| `ClientLogonGameServer` | 5559 | protobuf |
| `ClientLogOn_Deprecated` | 701 | present in enum, never sent |
| `ClientAnonLogOn_Deprecated` | 702 | present in enum, never sent |

### 2.2 Framing (verified against SteamKit 2015 `TcpConnection` + `SteamLanguageInternal`)

All CM TCP traffic is length-prefixed with the VT01 magic (`0x31305456`):

    [len:4]["VT01"][emsg|proto-flag:4][...]

The EMsg field discriminates the layout, exactly as the client's
`CMClient.GetPacketMsg` does:

```
struct (MsgHdr):      [emsg:4][target_job:8][source_job:8][body]
protobuf (MsgHdrProtoBuf): [emsg|0x80000000:4][header_len:4][header][body]
```

- **The 0x80000000 proto flag IS on the wire** (`MsgUtil.MakeMsg(msg, true)`).
  Without it the client treats a protobuf message as a struct message and
  parsing fails. The gateway sets it on encode and strips it on decode.
- The channel-encrypt handshake messages (1303/1304/1305) are always struct.
- Struct job ids are read-but-ignored by the client for handshake messages.

Gateway status: implemented in `cm/framing.py` ✅ (unit + integration tested).

### 2.3 Channel encryption (server-initiated — confirmed from `CMClient.cs`)

Per the 2015 `CMClient.HandleEncryptRequest`, the handshake is:

```
server ──ChannelEncryptRequest(1303)──►  body = MsgChannelEncryptRequest struct:
                                         [protocol_version:4][universe:4]
                                         (protocol_version must be 1 — the
                                          client asserts it; universe selects
                                          the RSA key, EUniverse.Public = 1)
client ──ChannelEncryptResponse(1304)──►  [protocol_version:4][key_size:4]
                                          [session_key RSA-OAEP:keysize]
                                          [crc32(session_key):4][end_flag:4]
server ──ChannelEncryptResult(1305)──►   [eresult:4]  (1 = OK)
then: AES-256-CBC/PKCS7 with session_key; optional HMAC-SHA1 (hash_key =
session_key[:16], iv = HMAC(msg)[:13] + 3 random bytes, IV pre-encrypted AES-ECB)
```

⚠️ The earlier analysis (steamkit-python) claimed the request body was a 16-byte
challenge. The 2015-era SteamKit source shows the struct
`[protocol_version][universe]`; the binary's `MsgChannelEncryptRequest_t`
confirms it. The gateway now sends the struct body (8 bytes).

**Open question (must be capture-verified):** the client encrypts its session
key with a key from its built-in `KeyDictionary` (per universe). We scanned the
entire bundle for the EUniverse.Public DER + raw modulus from 2015-era SteamKit
(`scripts/_scan_key.py`): **NONE found.** Either this build stores the key in
an unrecognized/obfuscated form, or the 2015-era server provides it during the
handshake. If the latter, a pure MITM works with no client modification. If the
former, the only path is replacing the embedded key with the gateway's own (a
single well-defined patch). This is the single most important unknown.

✅ **Verified by the gateway's client simulator** (`gateway/cm/sim_client.py`,
`tests/test_handshake_integration.py`): the full exchange — including the
corrected request body, protobuf logon, and the MachineAuth flow — runs
end-to-end and is captured byte-for-byte.

### 2.4 Logon

- The client sends **protobuf `ClientLogon` (5514, proto-flagged)** with
  `CMsgClientLogon` field numbers **account_name = 50, password = 51**
  (RSA-encrypted), protocol_version = 1, client_os_type = 7, client_language = 6,
  machine_id = 30, should_remember_password = 8, **sha_sentryfile = 83**.
  (The earlier "fields 1/2" assumption came from a stale doc — the 2015-era
  generated SteamKit proto shows 50/51.)
- The gateway replies with protobuf **`ClientLogOnResponse` (751)** whose header
  carries `steamid` (1, fixed64) + `client_sessionid` (2); the body carries
  eresult (1), out_of_game_heartbeat_seconds (2) — this drives the client's
  heartbeat timer — plus public_ip (4), server_time (5), account_flags (6),
  cell_id (7), ip_country_code (21).
- No `ClientHello` string exists in this build — it predates it.

### 2.5 Post-logon responses the client *requires* (all implemented)

From SteamKit 2015 `CMClient`/`SteamUser` handlers and the binary's constants:

| Message | EMsg | Purpose | Gateway |
|---|---|---|---|
| `ClientLogOnResponse` (proto) | 751 | eresult; header carries `client_sessionid` + `steamid`; body heartbeat seconds | ✅ |
| `ClientSessionToken` (proto) | 850 | AM session token (u64), field `token` | ✅ |
| `ClientAccountInfo` (proto) | 768 | persona_name (1), ip_country (2), count_authed_computers (5), account_flags (7) | ✅ |
| `ClientCMList` (proto) | 783 | cm_addresses (1) / cm_ports (2) — sends the gateway's own listener so the client rotates to us | ✅ |
| `ClientLoggedOff` | 757 | eresult on kick | handler-ready |
| heartbeat | 703/755 | client heartbeats at `out_of_game_heartbeat_seconds`; server can re-rate | ✅ |

## 3. Steam Guard MachineAuth flow (implemented)

From SteamKit 2015 `SteamUser.cs` (`HandleUpdateMachineAuth` /
`SendMachineAuthResponse` / `AcceptNewLoginKey`) and the binary's message
constants:

### 3.1 The exchange

After a successful logon the gateway (acting as the CM server) completes the
"remember this computer" flow:

```
server ──ClientUpdateMachineAuth(5537)──►  header: jobid_source = <job> (10, fixed64)
                                            body: filename (1), offset (2),
                                                  cubtowrite (3), bytes (4) — the sentry
client ──ClientUpdateMachineAuthResponse(5538)──►  header: jobid_target = <job> (11, fixed64)
                                            body: filename (1), eresult (2),
                                                  filesize (3), sha_file (4),
                                                  offset (6), cubwrote (7)
```

- The client writes the sentry to disk (`ssfn...` file) and replies with the
  SHA-1 of what it actually wrote.
- The gateway stores the sentry in a persistent `SentinelStore`
  (`cm/machineauth.py`) so a re-connecting client can `ReadMachineAuth` it back
  and so the account's sentry stays stable across sessions.
- If a logon already presents `sha_sentryfile` (83) matching the stored SHA,
  the push is skipped (the client already has the sentry).

Two client-initiated variants complete the trio:

```
client ──ClientReadMachineAuth(5539)──►  filename (1), offset (2), cubtoread (3)
server ──ClientReadMachineAuthResponse(5540)──►  bytes_read (8), sha_file (4), filesize (3)
client ──ClientRequestMachineAuth(5541)──►  client uploads its sentry
server ──ClientRequestMachineAuthResponse(5542)──►  eresult (1)
```

### 3.2 Login key

The gateway also offers a passwordless re-logon token:

```
server ──ClientNewLoginKey(5463)──►  unique_id (1), login_key (2)
client ──ClientNewLoginKeyAccepted(5464)──►  unique_id (1)
```

### 3.3 Job-id targeting

`CMsgProtoBufHeader` job fields are **fixed64**: `jobid_source = 10`,
`jobid_target = 11`, defaulting to `ulong.MaxValue` (-1). The client copies the
request's source job into its response's target job; the gateway correlates on
it. (See `cm/machineauth.py:header()`.)

## 4. Remaining gaps

| Feature | Evidence in binary | Gateway status |
|---|---|---|
| Steam Guard machine auth (all 6 messages) | confirmed | ✅ implemented + tested |
| Login key (5463 / 5464) | confirmed | ✅ implemented + tested |
| Content/download (depot manifests + chunks via `cs.steampowered.com`) | confirmed | bridge exists; URL/protocol specifics TBD by capture |
| App info updates (`ClientAppInfoUpdate` 866) | confirmed constants | ignored (non-fatal) |
| Library/license data (own-app list) | `ClientAccountInfo` | minimal persona sent; full license list TBD |
| Friends/chat (`ClientChatMsg`, `ClientChatEnter`, persona…) | many constants | missing |
| Game launch → session tickets (`ClientGamesPlayed` 742, game-server tickets) | confirmed | missing |
| Store/community rendering | `chromehtml.dylib` (old WebKit) | dead end — modern storefront won't render; unchanged |

## 5. Capture tooling (what exists now)

- **`gateway/cm/sim_client.py` / `scripts/client_sim.py`** — a protocol-accurate
  stand-in for the Lion-era client. Run it against the live gateway to capture
  the full handshake + MachineAuth exchange without needing a 32-bit machine:
  ```bash
  python3 -m gateway run --cm-only          # terminal 1: gateway, no root needed
  python3 scripts/client_sim.py --out captures/handshake.txt   # terminal 2: the client
  ```
  Every frame is hexdumped with direction (`<` server→client, `>` client→server)
  and annotated with the message name. The MachineAuth frames show the sentry
  push, the SHA the client reports, and the login-key accept.
- **Gateway capture mode** — set `cm.capture_dir: captures/` in the config and
  every connection's raw bytes are written to `captures/conn-*.bin` (outbound
  prefixed `>`, inbound `<`). When you run the *real* client on the Lion Mac,
  those files are the ground truth.

### Verified so far (simulator + tests)

The complete flow runs end-to-end and matches the documented layout:
`ChannelEncryptRequest` (`[proto v1][universe 1]`) →
`ChannelEncryptResponse` (`[proto v1][key_size 128][key][crc32][end_flag]`) →
`ChannelEncryptResult` (eresult=1) → protobuf `ClientLogon` (5514, fields 50/51)
→ `ClientLogOnResponse` (751) → `ClientSessionToken` (850) → `ClientAccountInfo`
(768) → `ClientCMList` (783) → `ClientUpdateMachineAuth` (5537, job-id targeted)
→ `ClientUpdateMachineAuthResponse` (5538, SHA returned) → `ClientNewLoginKey`
(5463) → `ClientNewLoginKeyAccepted` (5464). See
`tests/test_handshake_integration.py` and the capture below.

## 6. What a capture must confirm (verification plan)

1. **The channel-encrypt session-key story** — is the key pinned to a
   client-embedded key (→ patch required) or server-provided (→ MITM ok)?
   `scripts/_scan_key.py` currently finds no embedded DER/raw key.
2. **AES mode after handshake** (CBC + optional HMAC per steamkit-python).
3. **MachineAuth against the real client** — does the real client write the
   `ssfn` sentry and reply 5538 exactly as the simulator does?
4. **Content request URLs** the client actually issues against `cs.steampowered.com`.

Method: run the client on the Lion machine with the gateway's CM listener
pointing at a packet-capture mode (`tcpdump` on the gateway host, or a debug
dump mode in `cm/server.py`), then map bytes → messages.

## 7. Sources

- Binary: Macintosh Garden `Steam_MacOS_X_10.6_Snow_Leopard.zip` (extracted client)
- SteamKit2 at commit 9b4807eb (2015-10-24): `Steam/CMClient.cs`,
  `Steam/Handlers/SteamUser/SteamUser.cs`, `Base/Generated/SteamMsg*.cs`,
  `Base/Generated/SteamLanguage.cs`, `Networking/Steam3/TcpConnection.cs`,
  `Base/MsgBase.cs`, `Util/KeyDictionary.cs`, `Resources/SteamLanguage/emsg.steamd`
- SteamDatabase/SteamTracking protobufs (message field numbers)
- steamkit-python README (AES/HMAC scheme after the handshake)
