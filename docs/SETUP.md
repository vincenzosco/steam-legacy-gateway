# Setup guide

End-to-end instructions for running the gateway and pointing the Lion-era Steam
client at it. Read [PROTOCOL_ANALYSIS.md](PROTOCOL_ANALYSIS.md) for *why* the
pieces exist; this file is only *how*.

## What you need

| Machine | Role | Requirements |
|---|---|---|
| **Gateway** (modern Mac or PC, always on) | translates legacy <-> modern | Python 3.9+; `git`; root access (ports 80/443); your Steam account + Steam Guard |
| **Lion Mac** (2008–2011 Intel) | runs the old Steam client | OS X 10.7; ~1 GB free; copies of `certs/steam-gateway-ca.crt` and the client |

Both machines on the same LAN. Decide the gateway's IP now and reserve it in the
router (or use a static IP): `ipconfig getifaddr en0` shows it.

---

## Part A — gateway machine

### 1. Get the code

```bash
git clone https://github.com/vincenzosco/steam-legacy-gateway.git
cd steam-legacy-gateway
```

### 2. Python environment + dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` installs `PyYAML`, `cryptography` (certs) and `steam`
(ValvePython — the modern CM back-end the translator drives). If you skip
`steam`, the TLS/content layers still run but the CM translator can't log you in.

### 3. Configure your account

```bash
cp config/gateway.yaml config/gateway.local.yaml
```

Edit `config/gateway.local.yaml`:

```yaml
gateway_ip: 192.168.1.50      # the IP from `ipconfig getifaddr en0`
account:
  username: "your-steam-login"
  password: "your-password"
  steam_guard: ""             # leave empty to be prompted at login
content:
  depot_downloader_path: ""   # optional: absolute path to DepotDownloader if installed
```

`config/gateway.local.yaml` is gitignored — credentials never get committed.
You can also use `STEAM_USERNAME` / `STEAM_PASSWORD` / `STEAM_GUARD_CODE` env
vars instead.

### 4. Generate certificates

```bash
python3 -m gateway gen-certs
```

This creates `certs/steam-gateway-ca.crt` (+ key) and a leaf certificate
covering every routed hostname. **You will copy the `.crt` to the Lion Mac.**

Sanity checks:

```bash
python3 -m gateway routes    # prints the routing table
python3 -m pytest tests/ -q  # 26 tests should pass
./scripts/smoke_tls.sh       # forwards a real request to Valve through the proxy
```

### 5. (Optional) fetch the client here and copy it over

```bash
./scripts/fetch_steam_client.sh          # downloads + MD5-verifies + extracts client/Steam.app
./scripts/analyze_client.sh              # reproduces the protocol analysis
```

If you fetch on the gateway, copy `client/Steam.app` to the Lion Mac over USB/NAS.

### 6. Run the gateway

Ports 80/443 are privileged, so run as root:

```bash
sudo python3 -m gateway run
```

You should see: content origin on 127.0.0.1:18081, TLS forwarder on :443, plain
forwarder on :80, and — once you configure an account — the modern session
logging in (Steam Guard prompt if `steam_guard` was empty).

---

## Part B — Lion machine

### 1. Install the client

**With the repo on the Lion Mac** (needs only `curl`, `unzip`, `md5` — all
present on 10.7):

```bash
./scripts/fetch_steam_client.sh
open client/Steam.app        # or drag Steam.app to /Applications
```

**Manually:** download `Steam_MacOS_X_10.6_Snow_Leopard.zip` from
https://macintoshgarden.org/apps/steam (MD5 `67d2088414f94800455f845ec8a0ff78`),
unzip, and copy `Steam.app` into `/Applications`.

The fetch script already freezes the client against auto-updates
(`Steam.cfg` with `BootStrapperInhibitAll=Enable` in
`Steam.app/Contents/MacOS/`). If you installed manually, create that file
yourself — **never let this client update itself.**

### 2. Trust the gateway's CA

Copy `certs/steam-gateway-ca.crt` from the gateway machine, then either:

- **GUI:** open Keychain Access → drag the cert into **System** → double-click →
  Trust → *When using this certificate: Always Trust*.
- **CLI:**

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/steam-gateway-ca.crt
```

The old client must trust this CA or it will reject the gateway's TLS
certificates.

### 3. Point Steam at the gateway

**Easiest** — generate the block on the gateway, paste it on the Lion Mac:

```bash
# on the gateway:
sudo ./scripts/install_hosts.sh --print 192.168.1.50
# copy the output, then on the Lion Mac:
sudo nano /etc/hosts        # paste at the end, save
```

**Or, if the repo is on the Lion Mac** (pure bash, no python needed):

```bash
sudo ./scripts/install_hosts.sh 192.168.1.50
# undo later with:  sudo ./scripts/install_hosts.sh remove
```

### 4. (Troubleshooting) hardcoded CM IPs

The client also has **hardcoded CM IPs baked into the binary** (e.g.
`208.64.200.201:27017`) that bypass /etc/hosts. If Steam hangs with no
connection appearing in the gateway logs, add a PF redirect on the Lion Mac so
those IPs also land on the gateway:

```
# /etc/pf.conf (append; en0 = your interface, X.X.X.X = gateway IP)
rdr pass on en0 proto tcp from any to 208.64.200.201 port 27017:27020 -> X.X.X.X
```

```bash
sudo pfctl -ef /etc/pf.conf
```

(The client usually rotates to the DNS-resolved CMs after a failed candidate,
so you may not need this — but it's there if you do.)

---

## Part C — first run & verification

1. On the **gateway**, start it with logs visible: `sudo python3 -m gateway run`.
2. On the **Lion Mac**, launch Steam.
3. Watch the gateway logs. Expected sequence per connection:
   - `legacy CM connection from <lion-ip>` then `sent ChannelEncryptRequest`
   - `client channel encrypt response: ...` (channel encryption attempted)
   - `legacy logon for <account>` … (if the modern session is ready)
4. Everything else — the store, community, downloads — will **not** fully work
   yet. See the expectations below.

## Honest expectations

What works **today** (verified):

- TLS termination + HTTPS forwarding to real Valve hosts (smoke-tested live)
- Content-origin routing (legacy content hosts → local depot bridge)
- Hosts/certs tooling, client fetch + freeze, the analysis tooling

What is **implemented but unverified** (needs a real client + capture):

- The CM handshake (server-initiated channel encryption, protobuf logon flow) —
  the wire details carry `VERIFY-BY-CAPTURE` notes in the code
- Whether the channel session key can be decrypted by the gateway at all (the
  embedded-key question — the single most important unknown)

What is **missing** (see PROTOCOL_ANALYSIS.md §3): Steam Guard MachineAuth,
app-info/license data (the library stays empty), friends/chat, game-launch
session tickets, and the modern store/community pages (old WebKit can't render
them — a dead end).

So: expect the handshake to *start* on the wire, but a full
logon + playable library is not there yet. The gateway's value today is the
verified plumbing plus the analysis that tells you exactly what's left.

## Troubleshooting quick reference

| Symptom | Fix |
|---|---|
| `Permission denied` binding :80/:443 | run with `sudo` |
| `steam` not installed | `pip install steam` in the venv |
| Client hangs with no CM connection in logs | add the PF redirect (Part B §4) |
| TLS errors in the client | CA not trusted on Lion (Part B §2) |
| Client auto-updated itself | re-extract and re-freeze (`Steam.cfg`) |
| Warnings about `--no-modern` / no account | configure `account.*` (Part A §3) |
