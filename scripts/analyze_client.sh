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
echo "=== EMsg name->number table extracted from the binary ==="
# The client embeds a name->value table; scripts/_scan_emsg.py extracts it.
# NOTE: this client uses the RENUMBERED EMsg set (logon=5514, response=751,
# token=850, CMList=783, channel encrypt 1303-1305, MachineAuth 5537-5542) —
# not the classic 704/940/761/762 values older docs cite.
if python3 scripts/_scan_emsg.py 2>/dev/null | grep -aE 'k_EMsgClient(Logon|LogOnResponse|SessionToken|CMList|UpdateMachineAuth|NewLoginKey|ChannelEncrypt|Multi)' | head -20; then
  :
else
  echo "(scripts/_scan_emsg.py needs the client at client/Steam.app)"
fi

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
echo "=== embedded crypto keys? (whole-bundle multi-format scan) ==="
# scripts/_scan_key.py hunts every SteamKit universe key in every plausible
# format (DER, raw modulus BE/LE, XOR/word-swap obfuscations, base64/hex,
# CAPI blobs, XML/PEM markers). Known result: the keys are embedded as
# hex-ASCII DER strings in two tables in steamclient.dylib + single copies in
# five other binaries (see docs/PROTOCOL_ANALYSIS.md §2.3).
if python3 scripts/_scan_key.py "$APP"; then
  :
else
  echo "(scripts/_scan_key.py needs the client at client/Steam.app)"
fi

echo
echo "=== build path / version breadcrumbs ==="
strings -a "$MACOS/osx32/steam" | grep -aE 'steam_rel_client|buildslave|GetBootstrapperVersion' | sort -u | head -5

echo
echo "Done. Cross-reference with docs/PROTOCOL_ANALYSIS.md"
