# deploy/

Files for running the bridge 24/7 on a persistent VM, orchestrated from
GitHub Actions (see `.github/workflows/deploy.yml` and `docs/DEPLOY.md`).

| File | Purpose |
|---|---|
| `steam-gateway.service` | systemd unit: runs `python -m gateway run`, `Restart=always`, survives reboot |
| `endpoint.txt` | **the bridge's public IP** — written by the deploy workflow after deployment, consumed by `scripts/patch_client.py --endpoint-file deploy/endpoint.txt` to hardcode it into the Steam client |

`endpoint.txt` holds a placeholder (`NOT_DEPLOYED`) until the first deploy; `scripts/patch_client.py` refuses to patch with it, so you can't accidentally hardcode a bogus address.
