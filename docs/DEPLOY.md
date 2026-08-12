# Deploying the bridge 24/7 (with GitHub Actions)

The end goal of this project is a Lion Mac running a **patched** Steam client
that connects to a **bridge** — the bridge translates the 2015 CM protocol to
modern Valve servers. The bridge is a long-running TCP server (ports
27017-27020 CM, 443/80 TLS, 18081 content origin), so it needs a machine that
is on 24/7.

## Can GitHub Actions host it? No — but it can deploy it

GitHub-hosted runners are **ephemeral**: a job runs for at most ~6 hours, then
the VM is destroyed, and runners accept **no inbound connections**. A 24/7
bridge cannot live on a GitHub runner.

What GitHub Actions *is* great at here:

1. **CI** — run the test suite + a live gateway→simulator handshake on every
   push/PR (`.github/workflows/ci.yml`).
2. **Deploy** — ship the bridge to a real VM you control and keep it running
   under systemd, then publish the VM's public IP into the repo
   (`.github/workflows/deploy.yml`).
3. **End-to-end** — the "IP from GitHub Actions": after deployment the
   workflow writes the host's public IP to `deploy/endpoint.txt`, and
   `scripts/patch_client.py` hardcodes exactly that IP into the Steam client.

```
[Lion Mac — patched Steam client]
   │  hardcoded CM list -> <deploy/endpoint.txt>:27017-27020   (no /etc/hosts needed)
   ▼
[Your VM — 24/7, deployed by GitHub Actions]
   ├─ steam-gateway.service (systemd, Restart=always)
   ├─ CM translator 27017-27020, TLS 443/80, content origin
   └─ owns the modern login (ValvePython/steam)
   ▼
[Valve servers]
```

## 1. Get a VM

Any always-on server with a public IPv4 works. Examples:

- Oracle Cloud **free tier** (2× Ampere ARM VMs, always-free)
- Hetzner CX22 (~€4/mo), DigitalOcean basic droplet (~$4-6/mo)
- A Raspberry Pi behind a router with port-forwarding (needs a static IP/DNS)

Requirements: Ubuntu 22.04+ (or any distro with python3.11+), a public IP,
and **inbound TCP on 27017-27020, 443, 80** (see firewall note below).

## 2. Configure secrets

In the repo → Settings → Secrets and variables → Actions → New repository
secret:

| Secret | Value |
|---|---|
| `DEPLOY_HOST` | the VM's SSH hostname or IP |
| `DEPLOY_USER` | SSH user (e.g. `ubuntu`) |
| `DEPLOY_SSH_KEY` | the **private** SSH key (ed25519 recommended) |
| `DEPLOY_PORT` | SSH port (default `22`; set if custom) |

## 3. Configure the account (optional but recommended)

The gateway owns the modern login. Create `config/gateway.local.yaml`
(gitignored) on the VM after first deploy, or pass credentials as env vars in
the systemd unit:

```ini
Environment=STEAM_USERNAME=you
Environment=STEAM_PASSWORD=secret
```

Without credentials the bridge still runs and completes the handshake, but
legacy logons are refused.

## 4. Firewall (VM side)

```bash
sudo ufw allow 27017:27020/tcp   # legacy CM listener
sudo ufw allow 443/tcp           # TLS forwarder
sudo ufw allow 80/tcp            # plain-HTTP forwarder (optional)
```

If the provider has a cloud security group (Oracle, AWS, GCP), open the same
ports there too.

## 5. Deploy

1. Run the **Deploy bridge (24/7)** workflow (Actions tab → Deploy bridge →
   Run workflow). This:
   - rsyncs the repo to `/opt/steam-legacy-gateway` on the VM
   - installs Python deps into a venv
   - installs + enables `steam-gateway.service` (auto-restart, survives reboot)
   - reads the VM's public IP (`api.ipify.org`) and commits it to
     `deploy/endpoint.txt`
2. Check the run summary for the IP, or read `deploy/endpoint.txt`.

## 6. Hardcode the IP into the Steam client

On the machine that has the extracted client (or fetch it with
`scripts/fetch_steam_client.sh` first):

```bash
./scripts/patch_client.py --endpoint-file deploy/endpoint.txt
# or: ./scripts/patch_client.py --ip 203.0.113.7
```

This rewrites the client's built-in CM server list (74 address slots in
`steamclient.dylib`) so it connects straight to the bridge — **no /etc/hosts
edit required for the CM layer**. Preview with `--dry-run`, revert with
`--restore`, confirm with `--verify --expect <IP>` (exits 0 only when every
CM slot points at the bridge).

### Client-side notes

- The patch only replaces strings that fit (same length or shorter); with a
  typical IPv4 like `203.0.113.7` every slot fits.
- macOS may complain about the invalidated code signature. Re-sign ad-hoc:
  `codesign -f -s - steamclient.dylib` (Lion doesn't enforce signatures for
  locally-run apps, but it silences the warning).
- TLS/HTTPS hosts (store, api, community) are still handled by the DNS layer —
  either the hosts-file block from `scripts/install_hosts.sh` or a DNS server
  pointing those names at the bridge VM.

## Manual deploy (no GitHub Actions)

```bash
rsync -az --exclude client --exclude content-cache --exclude certs --exclude .git \
  ./ user@vm:/opt/steam-legacy-gateway/
ssh user@vm 'cd /opt/steam-legacy-gateway && python3 -m venv .venv && \
  ./.venv/bin/pip install -r requirements.txt'
sudo cp deploy/steam-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now steam-gateway.service
```

## Container alternative

A Dockerfile is included for container-first setups:

```bash
docker build -t steam-legacy-gateway .
docker run -d --name gateway --network host \
  -e STEAM_USERNAME=you -e STEAM_PASSWORD=secret \
  -v $(pwd)/config:/app/config steam-legacy-gateway
```

## Troubleshooting

- `systemctl status steam-gateway.service` on the VM — check the log line
  `gateway ready`.
- `sudo journalctl -u steam-gateway.service -f` — live logs.
- If the old client still tries real Valve CMs, confirm the patch was applied:
  `./scripts/patch_client.py --verify --expect <bridge-IP>` (exit 0 = fully
  patched; exit 1 with WARN/FAIL = not patched or only partially patched).
- `python scripts/client_sim.py --host <VM_IP>` — run the simulator against the
  remote bridge from your machine to confirm it answers.
