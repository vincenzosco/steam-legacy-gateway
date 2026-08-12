#!/usr/bin/env bash
# fetch_steam_client.sh
#
# Download the Lion-compatible Steam client from Macintosh Garden, verify it,
# extract Steam.app, and freeze it against Valve auto-updates.
#
# Why: the gateway translates a *legacy* Steam client (2013-era protocol) to
# modern Valve servers. The client itself is long gone from Valve's servers, so
# we get it from the Macintosh Garden archive:
#   https://macintoshgarden.org/apps/steam
# The 208 MB "Steam_MacOS_X_10.6_Snow_Leopard.zip" is the last build that runs
# on OS X 10.6/10.7 (Snow Leopard / Lion). It can no longer log in to modern
# Valve servers by itself (confirmed by Macintosh Garden users) — that is
# exactly the gap this gateway closes.
#
# Usage:
#   ./scripts/fetch_steam_client.sh [--dest DIR] [--mirror auto|gardenmirror|macgdn]
#                                   [--dry-run] [--skip-verify] [--no-freeze]
#
# Runs on the gateway machine (modern macOS or Linux) or directly on the Lion
# Mac — it only needs curl, unzip and md5/md5sum, all present on 10.7.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PAGE_URL="https://macintoshgarden.org/apps/steam"
FILE_NAME="Steam_MacOS_X_10.6_Snow_Leopard.zip"
EXPECTED_MD5="67d2088414f94800455f845ec8a0ff78"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

MIRROR_GARDENMIRROR="https://gardenmirror.oldapplestuff.com/apps/$FILE_NAME"
MIRROR_MACGDN="https://old.mac.gdn/apps/$FILE_NAME"

DEST="$REPO_ROOT/client"
MIRROR="auto"
DRY_RUN=0
VERIFY=1
FREEZE=1

usage() {
  sed -n '2,20p' "$0"
  exit "${1:-1}"
}

log() { printf '\033[1;34m[fetch]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[fetch]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[fetch]\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest) DEST="$2"; shift 2 ;;
    --mirror) MIRROR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-verify) VERIFY=0; shift ;;
    --no-freeze) FREEZE=0; shift ;;
    -h|--help) usage 0 ;;
    *) usage ;;
  esac
done

md5_of() {
  if command -v md5 >/dev/null 2>&1; then
    md5 -q "$1"
  else
    md5sum "$1" | awk '{print $1}'
  fi
}

# resolve_url: print a working download URL for $FILE_NAME.
resolve_url() {
  case "$MIRROR" in
    gardenmirror) echo "$MIRROR_GARDENMIRROR"; return 0 ;;
    macgdn) echo "$MIRROR_MACGDN"; return 0 ;;
    auto|token) ;;
    *) fail "unknown --mirror '$MIRROR' (auto|gardenmirror|macgdn)" ;;
  esac

  # auto: try to scrape a fresh signed URL from the page (tokens expire, so we
  # grab one at run time). The signed link pattern is:
  #   //download.macintoshgarden.org/apps/Steam_...zip?expires=...&token=...
  local signed
  signed="$(curl -sL --max-time 30 -A "$UA" "$PAGE_URL" \
    | grep -oE 'href="//download\.macintoshgarden\.org/apps/'"$FILE_NAME"'[^"]*"' \
    | head -1 | sed 's/^href="//; s/"$//')"
  if [[ -n "$signed" ]]; then
    echo "https:$signed"
    return 0
  fi
  warn "could not scrape a fresh token URL; falling back to the static mirrors"
  echo "$MIRROR_GARDENMIRROR"
}

download_file() {
  curl -L --fail --retry 3 -C - -A "$UA" --max-time 5400 -o "$DEST/$FILE_NAME" "$1"
}

main() {
  mkdir -p "$DEST"
  local url
  url="$(resolve_url)"
  log "source: $url"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "dry-run: would download to $DEST/$FILE_NAME"
    exit 0
  fi

  # --- download (resumable, with mirror fallback) ------------------------------
  if [[ ! -s "$DEST/$FILE_NAME" ]]; then
    log "downloading $FILE_NAME ..."
    if ! download_file "$url"; then
      # Signed token URLs expire; fall back to the static mirrors.
      warn "primary URL failed; trying static mirrors"
      if ! download_file "$MIRROR_GARDENMIRROR" && ! download_file "$MIRROR_MACGDN"; then
        fail "download failed from all sources"
      fi
    fi
  else
    log "$FILE_NAME already present, skipping download"
  fi

  # --- verify -----------------------------------------------------------------
  if [[ "$VERIFY" -eq 1 ]]; then
    local got
    got="$(md5_of "$DEST/$FILE_NAME")"
    if [[ "$got" != "$EXPECTED_MD5" ]]; then
      fail "MD5 mismatch: got $got, expected $EXPECTED_MD5"
    fi
    log "MD5 OK ($got)"
  fi

  # --- extract -----------------------------------------------------------------
  local work="$DEST/extract"
  rm -rf "$work"; mkdir -p "$work"
  log "extracting ..."
  unzip -q -o "$DEST/$FILE_NAME" -d "$work"

  local app
  app="$(find "$work" -maxdepth 3 -name 'Steam.app' -type d | head -1)"
  [[ -n "$app" ]] || fail "Steam.app not found inside the archive"

  local final="$DEST/Steam.app"
  if [[ "$app" != "$final" ]]; then
    rm -rf "$final"
    mv "$app" "$final"
  fi

  # --- freeze against auto-updates ----------------------------------------------
  if [[ "$FREEZE" -eq 1 ]]; then
    mkdir -p "$final/Contents/MacOS"
    printf 'BootStrapperInhibitAll=Enable\n' > "$final/Contents/MacOS/Steam.cfg"
    log "froze updates: Steam.cfg -> $final/Contents/MacOS/Steam.cfg"
  fi

  log "client ready: $final"
  log "next: trust certs/steam-gateway-ca.crt in Keychain, then run scripts/install_hosts.sh"
}

main
