# Setup guide

End-to-end instructions for running the gateway and pointing the Lion-era Steam
client at it. Read [PROTOCOL_ANALYSIS.md](PROTOCOL_ANALYSIS.md) for *why* the
pieces exist; this file is only *how*.

## What you need

| Machine | Role | Requirements |
|---|---|---|
| **Gateway** (any always-on computer at home — spare Mac, old PC, Raspberry Pi) | translates legacy <-> modern | Python 3.9+; `git`; root access (ports 80/443); your Steam account + Steam Guard |
| **Lion Mac** (2008–2011 Intel) | runs the old Steam client | OS X 10.7; ~1 GB free; copies of `certs/steam-gateway-ca.crt` and the client |

Both machines on the same LAN. Decide the gateway's IP now and reserve it in the
router (or use a static IP): `ipconfig getifaddr en0` (macOS) or `hostname -I`
(Linux/Pi) shows it. Keep the bridge running 24/7 with
[`docs/DEPLOY.md`](DEPLOY.md) (systemd / launchd / Docker).

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

### 3. Configure the gateway IP (and optionally credentials)

```bash
cp config/gateway.yaml config/gateway.local.yaml
```

Edit `config/gateway.local.yaml` — at minimum the IP:

```yaml
gateway_ip: 192.168.1.50      # the IP from `ipconfig getifaddr en0`
content:
  depot_downloader_path: ""   # optional: absolute path to DepotDownloader if installed
```

**Credentials: leave `account.*` empty.** The bridge reads the username and
password the client types into its *own* login screen on the Lion Mac and
forwards them to Valve's modern servers — nothing to store in the config. To
make that possible, generate the bridge's CM RSA key and swap it into the
client (one-time):

```bash
python -m gateway gen-cm-key                     # bridge keypair (once)
./scripts/patch_client.py --swap-key --key-pem certs/cm-rsa.key
./scripts/patch_client.py --verify-key --key-pem certs/cm-rsa.key
```

If you *do* set `account.username` / `account.password` (or the
`STEAM_USERNAME` / `STEAM_PASSWORD` env vars), the bridge uses those instead
— the client-supplied credentials are ignored. `config/gateway.local.yaml` is
gitignored either way.

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

### 3. Point Steam at the gateway — CM layer (binary patch, recommended)

The client has **hardcoded CM IPs baked into the binary** (e.g.
`208.64.200.201:27017`) that are tried *without DNS*, so /etc/hosts alone is
not enough for the CM layer. Rewrite them to the gateway's LAN IP instead
(74 slots, in-place, one-time backup):

```bash
# on any modern machine with the extracted client (or on the Lion Mac via USB/NAS copy)
./scripts/patch_client.py --ip 192.168.1.50            # gateway's LAN IP
./scripts/patch_client.py --verify --expect 192.168.1.50  # exit 0 only if fully patched
```

Preview with `--dry-run`; revert with `--restore`. If you patched a copy
elsewhere, copy `Steam.app` back to the Lion Mac afterwards.

### 4. Point Steam at the gateway — TLS hosts (hosts file)

The hosts block is still needed for the **TLS/HTTPS hosts** (store, api,
community — the CM layer is handled by the binary patch above).

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

**Fallback (only if you prefer not to patch the binary):** add a PF redirect
on the Lion Mac so the hardcoded CM IPs land on the gateway:

```
# /etc/pf.conf (append; en0 = your interface, X.X.X.X = gateway IP)
rdr pass on en0 proto tcp from any to 208.64.200.201 port 27017:27020 -> X.X.X.X
```

```bash
sudo pfctl -ef /etc/pf.conf
```

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

What is **implemented and integration-tested** (simulator, incl. CI):

- The CM handshake + channel crypto — the bridge RSA-decrypts the client's
  session key (after the key-swap) and AES-256 encrypts/decrypts the
  post-handshake payloads; the logon password is decrypted and forwarded to
  the modern session. The whole flow runs end-to-end in fully encrypted mode
  (`tests/test_handshake_integration.py`, `--encrypted` sim mode).
- Steam Guard MachineAuth (sentry push/read/request + NewLoginKey pair).

Still needs a **real client capture** to confirm: the exact RSA padding on the
session-key/password blobs (PKCS#1 assumed, OAEP fallback built in) and the
AES frame layout — plus the items below. Expect the encrypted handshake to
work on the wire.

What is **missing** (see PROTOCOL_ANALYSIS.md §3): app-info/license data (the
library stays empty), friends/chat, game-launch session tickets, and the
modern store/community pages (old WebKit can't render them — a dead end).

## Troubleshooting quick reference

| Symptom | Fix |
|---|---|
| `Permission denied` binding :80/:443 | run with `sudo` |
| `steam` not installed | `pip install steam` in the venv |
| Client hangs with no CM connection in logs | patch the binary: `./scripts/patch_client.py --ip <gateway-ip>` (Part B §3); PF redirect only as fallback |
| TLS errors in the client | CA not trusted on Lion (Part B §2) |
| Client auto-updated itself | re-extract and re-freeze (`Steam.cfg`) |
| Logon refused with "could not decrypt logon password" | the client still encrypts to Valve's key — run `python -m gateway gen-cm-key` + `./scripts/patch_client.py --swap-key` (Part A §3) |
| Warnings about no account configured | that is expected now — the bridge takes credentials from the client's login screen (Part A §3) |
