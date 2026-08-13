# Running the bridge at home (24/7)

The bridge is a long-running server (CM on TCP 27017-27020, TLS on 443/80,
content origin on 18081). It needs a machine that is on 24/7 — but it does
**not** need a rented VM or a public IP. The recommended setup is a second
computer in your home, on the same LAN as the Lion Mac.

## Why home works (and what the GitHub Actions path is for)

- The bridge talks to Valve **outbound** (it owns the modern login via
  ValvePython/steam), so it works from any home NAT — **no inbound ports,
  no port forwarding, no static public IP**.
- The Lion client is pointed at the bridge's **LAN IP** (e.g. `192.168.1.50`)
  with `scripts/patch_client.py`, which rewrites the client's built-in CM
  server list — no DNS involvement for the CM layer at all.
- **GitHub Actions** is used for **CI only** by default: the test suite plus a
  live gateway → simulator handshake run on every push
  (`.github/workflows/ci.yml`), so you never need a VM to develop or use the
  project.
- The **only** reason to add a VM is if the Lion Mac is *not* on the same LAN
  as the bridge (you want to reach it remotely). That optional path is
  described at the bottom.

```
[Lion Mac — Steam 1.0.x]
   │  patched CM list  -> 192.168.1.50:27017-27020   (patch_client.py, no DNS)
   │  hosts file       -> *.steampowered.com, cm*, content hosts -> 192.168.1.50
   ▼
[Home bridge — spare Mac/PC/Pi, always on]
   │  (outbound only — nothing to open in your router)
   ▼
[Valve servers]
```

## 0. Decide on the machine and its LAN IP

Any always-on computer works: a spare modern Mac, an old PC, or a Raspberry
Pi 4+. Requirements: Python 3.9+ (the docs assume 3.10+), `git`, and root
access (ports 80/443 are privileged).

Give the bridge a **fixed LAN IP** (router DHCP reservation or static):

```bash
ipconfig getifaddr en0     # macOS — the bridge's own IP
hostname -I                # Linux / Raspberry Pi
```

Note that IP — the Lion client will be patched to it.

## 1. Install on the bridge machine

```bash
git clone https://github.com/vincenzosco/steam-legacy-gateway.git
cd steam-legacy-gateway
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/gateway.yaml config/gateway.local.yaml   # edit: gateway_ip + account
python -m gateway gen-certs                        # local CA + per-host certs
```

Edit `config/gateway.local.yaml` (gitignored — credentials never get
committed):

```yaml
gateway_ip: 192.168.1.50       # the bridge's LAN IP from step 0
account:
  username: "your-steam-login"
  password: "your-password"
  steam_guard: ""              # leave empty to be prompted at first login
```

Sanity check before making it a service:

```bash
python -m pytest tests/ -q
./scripts/smoke_tls.sh         # forwards a real request to Valve through the proxy
sudo python -m gateway run     # Ctrl-C when you see all four services up
```

## 2. Keep it running 24/7

### Option A — systemd (Linux / Raspberry Pi)

```bash
sudo cp deploy/steam-gateway.service /etc/systemd/system/
# cloned somewhere other than /opt/steam-legacy-gateway? fix the paths:
sudo sed -i 's#/opt/steam-legacy-gateway#/home/pi/steam-legacy-gateway#g' \
  /etc/systemd/system/steam-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now steam-gateway.service
systemctl status steam-gateway.service     # should print "active (running)"
```

The unit sets `Restart=always` and `WantedBy=multi-user.target`, so the
bridge comes back automatically after crashes and reboots. Logs:
`sudo journalctl -u steam-gateway.service -f`.

### Option B — launchd (macOS bridge)

Save this as `/tmp/com.steamlegacygateway.bridge.plist` (fix the two
`/Users/you/...` paths), then load it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.steamlegacygateway.bridge</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/steam-legacy-gateway/.venv/bin/python</string>
    <string>-m</string>
    <string>gateway</string>
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/you/steam-legacy-gateway</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
```

```bash
sudo cp /tmp/com.steamlegacygateway.bridge.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.steamlegacygateway.bridge.plist
# logs: sudo log show --predicate 'process == "Python"' --last 1h
```

(It's a LaunchDaemon, so it runs as root and can bind 80/443. It survives
reboots via `RunAtLoad`.)

### Option C — Docker

```bash
docker build -t steam-legacy-gateway .
docker run -d --name gateway --network host \
  -e STEAM_USERNAME=you -e STEAM_PASSWORD=secret \
  -v $(pwd)/config:/app/config \
  steam-legacy-gateway
```

`--network host` exposes 27017-27020/443/80 directly, which the CM + TLS
listeners need.

### Option D — dev / foreground

```bash
sudo python -m gateway run        # or: python -m gateway run --cm-only (no root)
```

## 3. Hardcode the bridge into the Steam client

On the Lion Mac (or on any modern machine against the extracted client, then
copy `Steam.app` back), point the client's built-in CM table at the bridge:

```bash
./scripts/patch_client.py --ip 192.168.1.50              # bridge's LAN IP
./scripts/patch_client.py --verify --expect 192.168.1.50 # exit 0 only if fully patched
```

This rewrites all 74 hardcoded CM address slots in `steamclient.dylib` in
place (same-length-or-shorter only, NUL-padded, one-time backup at
`steamclient.dylib.orig`). Preview with `--dry-run`, revert with `--restore`.

- The CM layer now needs **no** `/etc/hosts` entries and no PF redirect.
- The hosts file is still used for the **TLS hosts** (store, api, community) —
  install it with `sudo ./scripts/install_hosts.sh 192.168.1.50` (Part B of
  `docs/SETUP.md`).
- macOS may warn about the invalidated code signature; silence it with
  `codesign -f -s - steamclient.dylib` (Lion does not enforce signatures for
  locally-run apps).

Then start Steam on the Lion Mac. First run: watch the bridge logs
(`journalctl -u steam-gateway.service -f` or the launchd log) — you should see
`legacy CM connection from <lion-ip>`, the channel-encrypt handshake, and the
Steam Guard prompt if `steam_guard` was left empty.

## Firewall notes

- **Home (recommended):** nothing to open. The bridge only makes outbound
  connections to Valve; the Lion client reaches it over the LAN.
- **Only if you forward ports** (e.g. to reach the bridge from outside):
  TCP 27017-27020 (CM), 443 (TLS), 80 (plain) — and a static public IP or
  dynamic-DNS hostname.

---

## Optional: expose the bridge to the internet (VM + GitHub Actions)

Only needed if the Lion Mac is not on the same LAN as the bridge. GitHub-hosted
runners are ephemeral (~6h jobs, no inbound TCP), so they cannot host the
bridge — but the **Deploy** workflow (`.github/workflows/deploy.yml`) ships it
to an always-on VM you provide and publishes that VM's public IP into the repo.

1. **Get a VM** with a public IPv4 (Oracle free tier, Hetzner, DigitalOcean,
   or a Raspberry Pi with port-forwarding). Ubuntu 22.04+ preferred.
2. **Configure secrets** (repo → Settings → Secrets and variables → Actions):
   `DEPLOY_HOST` (VM SSH host/IP), `DEPLOY_USER` (e.g. `ubuntu`),
   `DEPLOY_SSH_KEY` (private key), `DEPLOY_PORT` (default 22).
3. **Open the firewall** on the VM: `sudo ufw allow 27017:27020/tcp &&
   sudo ufw allow 443/tcp && sudo ufw allow 80/tcp` (plus the cloud provider's
   security group).
4. **Run the workflow**: Actions tab → "Deploy bridge (24/7)" → Run workflow.
   It rsyncs the code to `/opt/steam-legacy-gateway`, installs the systemd
   unit, and reads the VM's public IP (`api.ipify.org`), committing it to
   `deploy/endpoint.txt` (also uploaded as the `bridge-endpoint` artifact and
   printed in the job summary).
5. **Patch with the endpoint file instead of `--ip`:**

```bash
git pull   # gets the committed deploy/endpoint.txt
./scripts/patch_client.py --endpoint-file deploy/endpoint.txt
./scripts/patch_client.py --verify --expect "$(cat deploy/endpoint.txt)"
```

Configure the account on the VM via `config/gateway.local.yaml` or the
`STEAM_USERNAME` / `STEAM_PASSWORD` env vars in the unit file.

## Troubleshooting

- `systemctl status steam-gateway.service` on the bridge — look for
  `gateway ready` in the log.
- `sudo journalctl -u steam-gateway.service -f` — live logs (Linux).
- Client hangs with no CM connection in the logs: confirm the patch took —
  `./scripts/patch_client.py --verify --expect <bridge-IP>` (exit 0 = fully
  patched; exit 1 with WARN/FAIL = not patched or only partially patched).
- TLS errors in the client: CA not trusted on the Lion Mac (Part B of
  `docs/SETUP.md`).
- Client auto-updated itself: re-extract and re-freeze (`Steam.cfg` with
  `BootStrapperInhibitAll=Enable`) — never let this client update.
- `python scripts/client_sim.py --host <bridge-IP>` — run the protocol-accurate
  simulator against the remote bridge to confirm it answers before touching
  the client.
