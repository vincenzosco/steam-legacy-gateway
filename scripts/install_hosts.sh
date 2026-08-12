#!/usr/bin/env bash
# Install or remove the steam-legacy-gateway /etc/hosts block.
#
#   sudo ./scripts/install_hosts.sh <GATEWAY_IP>        # install (backs up first)
#   sudo ./scripts/install_hosts.sh remove              # remove the block
#
# Run this ON the Lion machine. It must be able to reach the gateway project
# (copy the repo over, or run the python one-liner from the repo path).
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${1:-}" == "remove" ]]; then
  python3 -m gateway hosts --remove --file /etc/hosts
  exit 0
fi

GATEWAY_IP="${1:-}"
if [[ -z "$GATEWAY_IP" ]]; then
  echo "usage: $0 <gateway-ip>   |   $0 remove" >&2
  exit 1
fi

# One-time backup of the pristine hosts file.
if [[ ! -e /etc/hosts.steam-gateway.bak ]]; then
  cp /etc/hosts /etc/hosts.steam-gateway.bak
  echo "backed up /etc/hosts -> /etc/hosts.steam-gateway.bak"
fi

python3 -m gateway hosts --apply --ip "$GATEWAY_IP" --file /etc/hosts
echo "hosts updated. Steam on this Mac now talks to $GATEWAY_IP (the gateway)."
echo "Make sure the gateway's CA cert is trusted in Keychain Access (System)."
