# steam-legacy-gateway

[![CI](https://github.com/vincenzosco/steam-legacy-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/vincenzosco/steam-legacy-gateway/actions/workflows/ci.yml)

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
| Hosts generation / routing | complete | `gateway/hosts.py`, `scripts/install_hosts.sh` |
| TLS termination + HTTPS forwarding | complete | SNI routing, per-host certs, local CA; smoke-tested |
| Content bridge (legacy URLs → depot cache) | complete | minimal HTTP origin + cache + fetcher |
| Legacy CM framing + EMsg layer | complete | renumbered EMsg set (from the binary's own table), VT01 + proto-flag framing, unit-tested |
| Steam Guard MachineAuth flow | complete | all 6 MachineAuth messages + NewLoginKey pair, job-id targeting, persistent sentry store, integration-tested end-to-end |
| Modern back-end (ValvePython/steam) | complete; needs your account | install `steam`, set credentials in config |
| CM translator / message mapping | grounded | see [docs/PROTOCOL_ANALYSIS.md](docs/PROTOCOL_ANALYSIS.md) — channel encrypt + protobuf logon + post-logon set implemented from the binary + 2015-era SteamKit; the AES/session-key question is the remaining capture item |
| Auth impersonation | structural only | the gateway owns the modern login; legacy session emulation is partial |

**Why the translator can't be finished blind:** the 2013 logon flow involved RSA-encrypted
passwords against the CM public key and legacy key-value header fields that changed
frequently. EMsg values and struct layouts here are taken from SteamKit's public sources
and SteamDatabase's tracked protobufs; exact 2013 behavior must be confirmed with packet
captures from a real client before a real logon will complete.

## Legal / account-risk disclaimer

This project exists to research protocol translation. Using it violates the Steam
Subscriber Agreement: automated or modified clients can get your account flagged or
banned. **Use at your own risk, ideally with an alt account.** Valve can break any part
of this server-side at any time — that's inherent to the approach.

## Hosting the bridge 24/7 + hardcoding it into the client

**GitHub Actions can't host a long-running TCP server** (runners are ephemeral
and accept no inbound connections), but it makes an excellent orchestrator:

- **CI** (`.github/workflows/ci.yml`) — runs the test suite plus a **live
  gateway → simulator handshake** (channel encrypt + logon + Steam Guard
  MachineAuth) on every push/PR.
- **Deploy** (`.github/workflows/deploy.yml`) — ships the bridge to a VM you
  control, runs it under systemd (`Restart=always`, survives reboot), then
  publishes the VM's public IP to `deploy/endpoint.txt` — *the* address.
- **Client patch** (`scripts/patch_client.py`) — rewrites the Steam client's
  built-in CM server list in place so it connects straight to that IP:
  ```bash
  ./scripts/patch_client.py --endpoint-file deploy/endpoint.txt   # IP from GH Actions
  ./scripts/patch_client.py --dry-run --ip 203.0.113.7            # preview
  ./scripts/patch_client.py --verify --expect 203.0.113.7         # confirm (exit 0 only if fully patched)
  ./scripts/patch_client.py --restore                             # revert
  ```
  No `/etc/hosts` edit needed for the CM layer — the hardcoded addresses are
  what the client tries first (and they bypass DNS entirely).

Full deployment guide: [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Setup

Full, end-to-end setup is in [`docs/SETUP.md`](docs/SETUP.md) — gateway machine, Lion machine,
CA trust, hosts install, first run, and troubleshooting. The quick version:

```bash
# gateway machine
git clone https://github.com/vincenzosco/steam-legacy-gateway.git && cd steam-legacy-gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config/gateway.yaml config/gateway.local.yaml   # edit credentials & IPs
python -m gateway gen-certs                        # create local CA + per-host certs
sudo python -m gateway run                          # start all services

# lion machine: trust certs/steam-gateway-ca.crt in Keychain, then
sudo ./scripts/install_hosts.sh <GATEWAY_IP>        # pure bash, no python needed
```

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
python -m pytest tests/ -q        # unit + in-process handshake integration tests
scripts/smoke_tls.sh              # end-to-end TLS forwarding check (needs network)

# protocol-accurate client simulation (no Lion machine needed):
python3 -m gateway run --cm-only  &              # terminal 1: gateway, no root needed
python3 scripts/client_sim.py --out captures/handshake.txt   # terminal 2: the client
```

For a capture of the *real* client later, set `cm.capture_dir: captures/` in the
config — every connection's raw bytes are written to `captures/conn-*.bin`.
See [docs/PROTOCOL_ANALYSIS.md §4](docs/PROTOCOL_ANALYSIS.md#4-capture-tooling-what-exists-now).

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
