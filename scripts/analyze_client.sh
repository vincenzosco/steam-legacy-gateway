#!/usr/bin/env bash
# analyze_client.sh — reproduce the protocol analysis of the Lion-era Steam client.
#
# Runs the same checks that produced docs/PROTOCOL_ANALYSIS.md against a
# fetched client (see scripts/fetch_steam_client.sh). Requires macOS dev tools
# (strings, otool, file) and python3.
#
# Usage:
#   ./scripts/analyze_client.sh [path-to-Steam.app]   (default: client/Steam.app)

set -uo pipefail
APP="${1:-client/Steam.app}"
MACOS="$APP/Contents/MacOS"
[[ -d "$MACOS" ]] || { echo "no Steam.app at $APP — run scripts/fetch_steam_client.sh first" >&2; exit 1; }

echo "=== bundle: binaries & sizes ==="
find "$MACOS" -maxdepth 2 -name '*.dylib' -exec ls -la {} \; | awk '{printf "%10d  %s\n", $5, $9}' | sort -rn | head -12
ls -la "$MACOS/osx32/steam" 2>/dev/null || true

echo
echo "=== architecture ==="
file "$MACOS/osx32/steam" 2>/dev/null | head -3

echo
echo "=== TLS / linked frameworks (securetransport?) ==="
otool -L "$MACOS/osx32/steam" 2>/dev/null | grep -iE 'Security|SystemConfiguration|libSystem' | head -5

echo
echo "=== protocol strings: framing + channel encrypt ==="
strings -a "$MACOS/osx32/steam" | grep -aE 'VT01|ChannelEncrypt' | sort -u | head -12

echo
echo "=== EMsg constants (client*) ==="
strings -a "$MACOS/steamclient.dylib" | grep -aE 'k_EMsgClient(Log|Session|CM|Account|App|Machine|NewLogin|LoggedOff|GamesPlayed|Chat)' | sort -u | head -40

echo
echo "=== endpoints ==="
strings -a "$MACOS/steamclient.dylib" | grep -aE 'steam\\.cm|cm[0-9]\\.steampowered|\\.steampowered\\.com|akamai|steamcontent' | sort -u | head -25

echo
echo "=== Steam Guard / machine auth ==="
strings -a "$MACOS/steamclient.dylib" | grep -aE 'MachineAuth|SteamGuard|NewLoginKey' | sort -u | head -12

echo
echo "=== hardcoded CM IPs (bypass DNS!) ==="
strings -a "$MACOS/steamclient.dylib" | grep -aE '[0-9]{1,3}(\\.[0-9]{1,3}){3}:[0-9]{4,5}' | sort -u | head -10

echo
echo "=== embedded crypto keys? (whole bundle raw scan) ==="
python3 - "$MACOS" <<'EOF'
import os, sys
root = sys.argv[1]
sigs = [
    (bytes.fromhex('dfec1ad6064ead197a'), 'valve-classic-1024 modulus'),
    (b'BEGIN PUBLIC KEY', 'PEM public key'),
    (b'BEGIN RSA PUBLIC KEY', 'PEM RSA key'),
]
hits = []
for dirpath, _dirs, files in os.walk(root):
    for fn in files:
        p = os.path.join(dirpath, fn)
        try:
            if os.path.getsize(p) > 150 * 1024 * 1024:
                continue
            data = open(p, 'rb').read()
        except OSError:
            continue
        for sig, name in sigs:
            if data.find(sig) >= 0:
                hits.append((p, name))
print('\n'.join(f"{p}: {n}" for p, n in hits) if hits else "NONE — no embedded PEM/classic-Valve key found")
EOF

echo
echo "=== build path / version breadcrumbs ==="
strings -a "$MACOS/osx32/steam" | grep -aE 'steam_rel_client|buildslave|GetBootstrapperVersion' | sort -u | head -5

echo
echo "Done. Cross-reference with docs/PROTOCOL_ANALYSIS.md"
