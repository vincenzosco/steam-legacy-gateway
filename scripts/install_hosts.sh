#!/usr/bin/env bash
# Install or remove the steam-legacy-gateway /etc/hosts block.
#
# Pure bash — runs on macOS Lion itself (no python3 needed).
#
#   sudo ./scripts/install_hosts.sh <GATEWAY_IP>   # install (backs up first)
#   sudo ./scripts/install_hosts.sh remove         # remove the block
#
# If you don't have this script on the Lion machine, run it on the gateway and
# paste the printed block into /etc/hosts instead:
#   sudo ./scripts/install_hosts.sh --print <GATEWAY_IP>
set -euo pipefail

HEADER='# --- steam-legacy-gateway (added by install_hosts.sh) ---'
FOOTER='# --- end steam-legacy-gateway ---'

# Every Steam hostname the gateway wants to catch (mirrors gateway/hosts.py).
DOMAINS=(
  api.steampowered.com store.steampowered.com login.steampowered.com
  steamcommunity.com www.steampowered.com help.steampowered.com cdn.steampowered.com
  steamcdn-a.akamaihd.net client-update.akamaihd.net
  cs.steampowered.com steampipe.akamaized.net steamcontent.com
  edgecast.steamcontent.com xfer.steampipe.akamaized.net
  akamai.steamcontent.com mecdn.steampowered.com ltsteamcontent.com
  cache1.steampowered.com cache2.steampowered.com cache3.steampowered.com
  cache4.steampowered.com cache5.steampowered.com cache6.steampowered.com
  cache7.steampowered.com cache8.steampowered.com cache9.steampowered.com
  cache10.steampowered.com
  cm0.steampowered.com cm1.steampowered.com cm2.steampowered.com
  cm3.steampowered.com cm4.steampowered.com cm5.steampowered.com
  cm6.steampowered.com cm7.steampowered.com steam.cm
)

render_block() {
  local ip="$1"
  printf '%s\n# Maps every Steam hostname to the gateway machine, which translates the\n# legacy protocol to modern Valve servers. Remove this block to revert.\n' "$HEADER"
  local host
  for host in "${DOMAINS[@]}"; do
    printf '%s\t%s\n' "$ip" "$host"
  done
  printf '%s\n' "$FOOTER"
}

if [[ "${1:-}" == "--print" ]]; then
  render_block "${2:?usage: $0 --print <GATEWAY_IP>}"
  exit 0
fi

HOSTS=/etc/hosts
if [[ "${1:-}" == "remove" ]]; then
  sed -i '' '/^# --- steam-legacy-gateway/,/^# --- end steam-legacy-gateway/d' "$HOSTS"
  echo "gateway block removed from $HOSTS"
  exit 0
fi

GATEWAY_IP="${1:-}"
if [[ -z "$GATEWAY_IP" ]]; then
  echo "usage: $0 <gateway-ip>   |   $0 --print <gateway-ip>   |   $0 remove" >&2
  exit 1
fi

# One-time backup of the pristine hosts file.
if [[ ! -e /etc/hosts.steam-gateway.bak ]]; then
  cp /etc/hosts /etc/hosts.steam-gateway.bak
  echo "backed up /etc/hosts -> /etc/hosts.steam-gateway.bak"
fi

# Strip any previous block, then append the fresh one.
sed -i '' '/^# --- steam-legacy-gateway/,/^# --- end steam-legacy-gateway/d' "$HOSTS"
render_block "$GATEWAY_IP" >> "$HOSTS"
echo "hosts updated: Steam on this Mac now talks to $GATEWAY_IP (the gateway)."
echo "Make sure the gateway's CA cert (certs/steam-gateway-ca.crt) is trusted in Keychain Access (System)."
