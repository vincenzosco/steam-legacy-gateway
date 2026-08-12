#!/usr/bin/env bash
# Smoke-test the TLS forwarder: start it on high ports, then curl through it
# to Valve's public ISteamWebAPIUtil/GetServerInfo endpoint (no key needed).
set -euo pipefail

cd "$(dirname "$0")/.."
PORT=8443
PLAIN_PORT=8080

cleanup() { kill "${GATEWAY_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT

python3 -m gateway gen-certs >/dev/null
python3 -m gateway smoke-tls --port "$PORT" --plain-port "$PLAIN_PORT" &
GATEWAY_PID=$!

# Wait for the listener to come up (raw TCP connect, no HTTP request).
for _ in $(seq 1 50); do
  if python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1',$PORT),1); s.close()" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

echo "== TLS-terminated forward to Valve =="
curl -sk --max-time 15 \
  --resolve "api.steampowered.com:$PORT:127.0.0.1" \
  "https://api.steampowered.com:$PORT/ISteamWebAPIUtil/GetServerInfo/v1/" \
  | python3 -m json.tool

echo "== local content-origin routing (expect 404 from the bridge) =="
curl -sk --max-time 10 \
  --resolve "cache1.steampowered.com:$PORT:127.0.0.1" \
  -w "HTTP %{http_code}\n" \
  "https://cache1.steampowered.com:$PORT/depot/220/manifest/123456789" || true

echo "== plain-HTTP forward (should land on 443 via Location or fail cleanly) =="
curl -s --max-time 10 --resolve "store.steampowered.com:$PLAIN_PORT:127.0.0.1" \
  -o /dev/null -w "HTTP %{http_code}\n" "http://store.steampowered.com:$PLAIN_PORT/" || true

echo "== smoke test complete =="
