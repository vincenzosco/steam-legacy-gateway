# steam-legacy-gateway

A translating gateway that lets an **ancient Steam client** (2013-era, macOS Lion 10.7,
Steam 1.0.x) talk to **modern Valve servers** — by sitting between them on a second,
modern computer.

The old client is pointed at the gateway machine (hosts file), and the gateway terminates
the old conversation on one side and re-speaks the modern protocol on the other:

```
[Lion Mac — Steam 1.0.x]
   │  hosts file → *.steampowered.com, cm0-cm7, content hosts → gateway IP
   │  speaks: TLS 1.0, 2013 CM protocol, legacy content URLs
   ▼
[Gateway — modern Mac/PC, always on, runs this software]
   ├─ TLS terminator          accepts the old TLS connection, re-does TLS 1.2/1.3
   ├─ HTTPS forwarder         routes api/store/login hosts to the real Valve hosts
   ├─ CM translator           accepts the 2013 CM protocol, speaks modern via ValvePython/steam
   ├─ Auth bridge             owns the modern login (credentials + Steam Guard), emulates
   │                          a legacy session to the old client
   └─ Content bridge          serves legacy content URLs from a depot cache that it
                              fills using modern fetching (DepotDownloader)
   ▼
[Valve servers]
```

## Honest status (read this first)

This is a **research-grade reverse-engineering project**. The framing, routing, TLS and
content layers are implemented and testable. The CM protocol *translation* layer is a
working skeleton with a message-mapping registry that must be completed and verified
against packet captures from a real 2013 client:

| Layer | Status | Notes |
|---|---|---|
| Hosts generation / routing | ✅ complete | `gateway/hosts.py`, `scripts/install_hosts.sh` |
| TLS termination + HTTPS forwarding | ✅ complete | SNI routing, per-host certs, local CA; smoke-tested |
| Content bridge (legacy URLs → depot cache) | ✅ complete | minimal HTTP origin + cache + fetcher |
| Legacy CM framing + EMsg layer | ✅ complete | `VT01` protobuf + struct-in-VT01 handshake framing, unit-tested |
| Modern back-end (ValvePython/steam) | ⚠️ complete code, needs your account | install `steam`, set credentials in config |
| CM translator / message mapping | ⚠️ grounded skeleton | see [docs/PROTOCOL_ANALYSIS.md](docs/PROTOCOL_ANALYSIS.md) — server-initiated channel encrypt + protobuf logon flow implemented from binary evidence; exact wire details still need a capture |
| Auth impersonation | ⚠️ structural only | the gateway owns the modern login; legacy session emulation is partial |

**Why the translator can't be finished blind:** the 2013 logon flow involved RSA-encrypted
passwords against the CM public key and legacy key-value header fields that changed
frequently. EMsg values and struct layouts here are taken from SteamKit's public sources
and SteamDatabase's tracked protobufs; exact 2013 behavior must be confirmed with packet
captures from a real client before a real logon will complete.

## ⚠️ Legal / account-risk disclaimer

This project exists to research protocol translation. Using it violates the Steam
Subscriber Agreement: automated or modified clients can get your account flagged or
banned. **Use at your own risk, ideally with an alt account.** Valve can break any part
of this server-side at any time — that's inherent to the approach.

## Setup

### On the gateway machine (modern Mac/PC)

```bash
cd steam-legacy-gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# optional but recommended for the content bridge:
#   install DepotDownloader (https://github.com/SteamRE/DepotDownloader) and set
#   `depot_downloader_path` in config/gateway.yaml

cp config/gateway.yaml config/gateway.local.yaml   # edit credentials & IPs
python -m gateway --gen-certs                       # create local CA + per-host certs
python -m gateway                                    # start all services
```

Then **install the CA on the Lion Mac** (the old client must trust the gateway's certs):

1. Copy `certs/steam-gateway-ca.crt` to the Lion machine.
2. Open Keychain Access → drag the cert into **System** → trust it as root.
3. Run `scripts/install_hosts.sh <GATEWAY_IP>` with sudo (backs up `/etc/hosts`).

Start Steam on the Lion Mac. It should now talk only to the gateway.

## Protocol analysis

[`docs/PROTOCOL_ANALYSIS.md`](docs/PROTOCOL_ANALYSIS.md) is the deep dive into
what the Lion-era client actually does — grounded in the real binary
(`scripts/analyze_client.sh` reproduces the analysis): the server-initiated
channel-encrypt handshake, the protobuf logon flow, the post-logon messages it
requires, and the full gap list. Read it before touching the translator.

## Getting the client (the old Steam binary)

The gateway needs an actual Lion-era Steam client to talk to. Valve no longer
serves those builds, so we fetch one from the [Macintosh Garden archive](https://macintoshgarden.org/apps/steam):

```bash
./scripts/fetch_steam_client.sh             # download + verify MD5 + extract + freeze
./scripts/fetch_steam_client.sh --dry-run   # just resolve the download URL
./scripts/fetch_steam_client.sh --mirror macgdn  # use a specific static mirror
```

What it does:

1. Downloads `Steam_MacOS_X_10.6_Snow_Leopard.zip` (~208 MB) — the **last build
   that runs on OS X 10.6/10.7** (Snow Leopard / Lion).
2. Verifies the MD5 (`67d20884...`) against the value published on Macintosh Garden.
3. Extracts `Steam.app` into `client/`.
4. Writes `Steam.cfg` (`BootStrapperInhibitAll=Enable`) into
   `Steam.app/Contents/MacOS/` so the client **never auto-updates** itself.

Notes:

- This client can no longer log in to Valve's servers on its own — Macintosh
  Garden users report it hangs at "Updating Steam Information". That is
  expected, and it is the entire reason the gateway exists.
- You can run the fetch script on the gateway machine, or directly on the Lion
  Mac (it only needs `curl`, `unzip` and `md5`). Copy `client/Steam.app` over
  if you fetch remotely.
- Never let it update: if the freeze file is removed and the client upgrades
  itself, it becomes a modern client that cannot run on Lion anyway.

## Services & ports

| Port | Service |
|---|---|
| 80 | plain HTTP → forwards to 443 (and content bridge for legacy content hosts) |
| 443 | TLS-terminating HTTPS forwarder (SNI-routed) |
| 27017–27020 | legacy CM protocol listener (translator) |
| 18081 | local-only content origin (served through the TLS proxy) |

## Config (`config/gateway.yaml`)

- `gateway_ip` — the IP the Lion machine will reach you on
- `cm_ports` — which ports to listen on for CM traffic
- `account` — username/password/steam_guard (leave `steam_guard` empty to be prompted)
- `content_cache_dir`, `depot_downloader_path`

## Testing

```bash
python -m pytest tests/ -q        # unit tests (framing, routing, hosts, mini-http)
scripts/smoke_tls.sh              # end-to-end TLS forwarding check (needs network)
```

## Project layout

```
gateway/
  main.py          entrypoint (services + subcommands)
  config.py        config loading
  routes.py        hostname → upstream routing table
  hosts.py         generates /etc/hosts entries for the Lion machine
  certs.py         local CA + per-host certificate generation
  minihttp.py      minimal async HTTP/1.1 server (used by content bridge)
  tls_proxy.py     TLS-terminating forwarder with SNI routing
  cm/
    emsg.py        EMsg constants (documented subset)
    framing.py     legacy + VT01 protobuf framing
    server.py      TCP listener on CM ports
    translator.py  session state machine + legacy↔modern message registry
    modern.py      modern back-end (ValvePython/steam wrapper)
  auth/bridge.py   modern login owner + Steam Guard handling
  content/
    cache.py       on-disk depot chunk cache
    fetcher.py     DepotDownloader / ValvePython CDN fetching
    bridge.py      legacy content URL origin server
```
