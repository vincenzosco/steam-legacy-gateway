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
| HTTPS/TLS | Apple **Security.framework (SecureTransport)** + SystemConfiguration — the client speaks whatever TLS Lion's OS stack offers (TLS 1.0/1.1 era). Confirms the old-TLS story. |
| Protocol buffers | Embeds Google protobuf runtime (version-check strings) — the `VT01` protobuf layer |
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
  ⚠️ Gateway route table routes `cacheN`/`steampipe`/`steamcontent` to the local
  origin but **not `cs.steampowered.com`** — fixed.
- Cell-ID based content server selection (`CellID (HTTP): (…) pinging...`).

## 2. The CM handshake — what the client expects (and what the gateway had wrong)

Evidence: binary message-class names (`MsgChannelEncryptRequest_t` etc. compiled
into `osx32/steam`, struct messages — **not** protobuf), SteamKit2 2.5.0
(`GetPacketMsg`: channel-encrypt messages are "always MsgHdr"), steamkit-python
wire-format doc.

### 2.1 Framing

Both variants exist on the connection (VT01 magic = `0x31305456`):

```
legacy/struct:   [len:4][emsg:4][target_job:8][source_job:8][body]
protobuf:        [len:4]["VT01"][emsg|proto-flag:4][hlen:4][header][body]
multi:           protobuf CMsgMulti{message_body, size_unzipped} — gzip when size_unzipped > 0
```

Gateway status: both framings implemented in `cm/framing.py` ✅; **gzip'd Multi
was missing** — fixed. Struct-vs-VT01 variants for the handshake packets need
capture confirmation.

### 2.2 Channel encryption (server-initiated — gateway had it INVERTED)

Per steamkit-python (the handshake the client implements) and the binary's
handler for incoming `ChannelEncryptRequest`:

```
server ──ChannelEncryptRequest(130)──►  body = random challenge (16 bytes)
client ──ChannelEncryptResponse(131)──►  [protocol_version:4][key_size:4=128]
                                         [session_key RSA-OAEP (SHA1):128]
                                         [crc32(session_key):4][end_flag:4]
server ──ChannelEncryptResult(132)──►   [eresult:4]  (1 = OK)
then: AES-256-CBC/PKCS7 with session_key; optional HMAC-SHA1 (hash_key =
session_key[:16], iv = HMAC(msg)[:13] + 3 random bytes, IV pre-encrypted AES-ECB)
```

**Gateway bug (fixed):** the translator implemented the *reverse* direction
(client→server Request, server→client Response). The gateway must send Request
first, then parse the client's Response and send Result.

**Open question (must be capture-verified):** steamkit-python says the session
key is RSA-OAEP-encrypted with "Steam's public key". **We scanned the entire
bundle for embedded keys (2 known Valve moduli + PEM markers): NONE found.**
Either this build stores the key in an unrecognized raw form, or the 2015-era
server provides it during the handshake. If the latter, a pure MITM works with
no client modification. If the former, the only path is replacing the embedded
key with the gateway's own (a single well-defined patch — the gateway's README
honesty section should be updated accordingly). This is the single most
important unknown.

### 2.3 Logon

- The 2015 client sends **protobuf `ClientLogon`** (`EMsg 704 | 0x80000000`,
  VT01 framing, `CMsgClientLogon`: account_name, password RSA-OAEP-encrypted,
  protocol_version, client_os_type, client_language, machine_id, …) — **not** the
  pre-2013 binary `MsgClientLogon`. The gateway's `_LegacyLogon` parser targets
  the binary layout — replaced by a minimal protobuf field walk (account_name =
  field 1).
- No `ClientHello` string exists in this build — it predates it. The client goes
  straight from channel encryption to `ClientLogon`.

### 2.4 Post-logon responses the client *requires* (gateway was missing all of these)

From SteamKit2 2.5.0 `HandleLogOnResponse`/`HandleCMList`/`HandleSessionToken`
and the binary's message constants:

| Message | EMsg | Purpose | Gateway before |
|---|---|---|---|
| `ClientLogOnResponse` (protobuf) | 940 | eresult; header carries `client_sessionid` + `steamid`; body: cell_id, public_ip, ip_country_code, legacy_out_of_game_heartbeat_seconds | sent legacy 705 instead ❌ |
| `ClientSessionToken` (protobuf) | 761 | AM session token (u64), field `token` | missing ❌ |
| `ClientCMList` (protobuf) | 762 | CM address/port list for rotation | ignored ❌ |
| `ClientLoggedOff` | 706 | eresult on kick | missing ❌ |
| heartbeat | 703/718 | client heartbeats at `legacy_out_of_game_heartbeat_seconds`; server can re-rate with 718 | partial ✅ |

## 3. Post-logon features — the gap list

| Feature | Evidence in binary | Gateway status |
|---|---|---|
| Steam Guard machine auth (`CMsgClientRequest/Update/ReadMachineAuth`) | confirmed strings | **missing** — the "remember this computer" flow needs a MachineAuth handshake |
| Login key (`ClientNewLoginKey` 712 / `Accepted` 713) | confirmed (`CMsgClientNewLoginKey`) | stubbed (accepts without storing) |
| Content/download (depot manifests + chunks via `cs.steampowered.com`) | `cs.steampowered.com`, depotcache dirs in bundle | bridge exists; URL/protocol specifics TBD by capture |
| App info updates (`ClientAppInfoChanges`, `ClientUpdateAppInfo`) | confirmed constants | ignored |
| Library/license data (own-app list) | `ClientAccountInfo` | missing — without it the library UI stays empty even if logon works |
| Friends/chat (`ClientChatMsg`, `ClientChatEnter`, persona…) | many constants | missing |
| Game launch → session tickets (`ClientGamesPlayed`, game-server tickets) | confirmed | missing — multiplayer/owned-server auth won't work |
| Store/community rendering | `chromehtml.dylib` (old WebKit) | dead end — modern storefront won't render; unchanged |

## 4. What a capture must confirm (verification plan)

1. **Framing of the 3 handshake packets** (struct with job IDs vs plain).
2. **Channel-encrypt direction + session-key encryption** — is the key pinned
   to a client-embedded key (→ patch required) or server-provided (→ MITM ok)?
3. **AES mode after handshake** (CBC + optional HMAC per steamkit-python).
4. **`ClientLogon` field numbers** and `protocol_version` constant value.
5. **Logon response field numbers** (940 eresult/cell_id/…) and whether the
   client accepts 940 with a minimal body.
6. **Content request URLs** the client actually issues against `cs.steampowered.com`.

Method: run the client on the Lion machine with the gateway's CM listener
pointing at a packet-capture mode (`tcpdump` on the gateway host, or a debug
dump mode in `cm/server.py`), then map bytes → messages.

## 5. Sources

- Binary: Macintosh Garden `Steam_MacOS_X_10.6_Snow_Leopard.zip` (extracted client)
- SteamKit2: `Steam/CMClient.cs` (master + tag 2.5.0), `Steam/Messages/*`
- steamkit-python README (channel-encrypt wire layout, AES/HMAC scheme)
- SteamDatabase/SteamTracking protobufs (message field numbers)
