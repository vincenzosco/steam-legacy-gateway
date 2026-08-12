#!/usr/bin/env python3
"""patch_client.py — hardcode the bridge endpoint into the Lion-era Steam client.

The client binary (steamclient.dylib) embeds its CM bootstrap server list as
contiguous, NUL-terminated ASCII strings of the form `IP:PORT` (two copies in
the binary; verified by scripts/_scan_emsg.py analysis). These hardcoded
addresses are tried *without DNS*, which is exactly why a /etc/hosts redirect
alone is not enough (see docs/PROTOCOL_ANALYSIS.md §1).

This script rewrites every `A.B.C.D:2701x` string in place so the client
connects straight to the bridge — no /etc/hosts edit needed for the CM layer.

Safety rules:
  * Only same-length-or-shorter replacements are applied (a replacement longer
    than the original would overflow into the adjacent string entry). The
    unused tail of the slot is NUL-padded.
  * The original binary is backed up once to `steamclient.dylib.orig`.
  * `--dry-run` reports what *would* change without touching the file.

Usage:
  # from the GitHub Actions endpoint file (deploy/endpoint.txt holds the IP)
  ./scripts/patch_client.py --endpoint-file deploy/endpoint.txt

  # or directly:
  ./scripts/patch_client.py --dylib client/.../steamclient.dylib --ip 203.0.113.7

  # preview only / restore / verify
  ./scripts/patch_client.py --dry-run --ip 203.0.113.7
  ./scripts/patch_client.py --restore
  ./scripts/patch_client.py --verify --expect 203.0.113.7
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

DEFAULT_DYLIB = Path("client/Steam.app/Contents/MacOS/steamclient.dylib")
ENDPOINT_FILE = Path("deploy/endpoint.txt")
BACKUP_SUFFIX = ".orig"

# Match every `IP:2701x/2702x` string that looks like a CM bootstrap entry.
# The range is intentionally broad: the real Oct-2015 binary's table uses ports
# 27013 and 27017-27020 (27013 is a genuine historical CM port), and also
# carries the old LAN fallback 172.16.3.84:27017/27018 — all real CM entries
# that must be rewritten. 127.0.0.1:5734x / :8283 local-service ports are
# intentionally NOT matched (verified against the actual steamclient.dylib).
_CM_RE = re.compile(rb"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>2701[0-9]|2702[0-9])")


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _scan(data: bytes) -> list[tuple[int, int, str, int]]:
    """Return [(offset, length, ip, port)] for every CM address string."""
    found: list[tuple[int, int, str, int]] = []
    for m in _CM_RE.finditer(data):
        ip = m.group("ip").decode()
        port = int(m.group("port"))
        if not _valid_ip(ip):
            continue
        found.append((m.start(), len(m.group(0)), ip, port))
    return found


def patch(dylib: Path, target_ip: str, *, dry_run: bool) -> int:
    """Rewrite CM IP strings to target_ip. Returns the number of edits applied."""
    if not _valid_ip(target_ip):
        print(f"error: '{target_ip}' is not a valid IPv4 address", file=sys.stderr)
        return 2

    orig = dylib.with_name(dylib.name + BACKUP_SUFFIX)
    if not dylib.is_file():
        print(f"error: {dylib} not found (run scripts/fetch_steam_client.sh first)",
              file=sys.stderr)
        return 2

    data = dylib.read_bytes()
    slots = _scan(data)
    if not slots:
        print(f"no CM address strings found in {dylib} — wrong file?")
        return 1

    new_bytes = bytearray(data)
    applied, skipped = 0, 0
    for offset, length, old_ip, port in slots:
        old_str = f"{old_ip}:{port}"
        new_str = f"{target_ip}:{port}"
        if len(new_str.encode()) > length:
            skipped += 1
            print(f"  skip  @0x{offset:x} {old_str:<24} -> {new_str} "
                  f"(too long: {len(new_str)} > {length})")
            continue
        padded = new_str.encode() + b"\x00" * (length - len(new_str))
        new_bytes[offset:offset + length] = padded
        applied += 1
        print(f"  patch @0x{offset:x} {old_str:<24} -> {new_str}")

    print(f"\n{applied} slot(s) patched, {skipped} skipped (too long).")
    if skipped and applied == 0:
        print("note: no slots fit — use a shorter IP (max 13 chars, e.g. 203.0.113.7)")
    if dry_run:
        print("(dry-run — file not modified)")
        return 0

    if not orig.exists():
        shutil.copy2(dylib, orig)
        print(f"backup saved: {orig}")
    dylib.write_bytes(bytes(new_bytes))
    print(f"patched {dylib} — CM bootstrap now points at {target_ip}:27017-27020")
    print("next: re-sign ad-hoc if macOS complains (codesign -f -s - steamclient.dylib)")
    return 0


def restore(dylib: Path) -> int:
    orig = dylib.with_name(dylib.name + BACKUP_SUFFIX)
    if not orig.is_file():
        print(f"no backup found at {orig}", file=sys.stderr)
        return 1
    shutil.copy2(orig, dylib)
    print(f"restored {dylib} from {orig}")
    return 0


def verify(dylib: Path, expect: str | None = None) -> int:
    """Check the binary's CM table. Exit 0 only when every slot points at one IP.

    With `expect` set, exit 0 only when *all* slots point at that exact IP —
    the check CI uses after a patch. A pristine (unpatched) binary reports
    WARN and returns 1, so `--verify` is a reliable gate, not an echo.
    """
    if not dylib.is_file():
        print(f"{dylib} not found", file=sys.stderr)
        return 1
    data = dylib.read_bytes()
    slots = _scan(data)
    if not slots:
        print(f"FAIL: no CM address strings found in {dylib}")
        return 1
    ips = {ip for _, _, ip, _ in slots}

    if expect is not None:
        matched = sum(1 for _, _, ip, _ in slots if ip == expect)
        if matched == len(slots):
            print(f"OK — all {len(slots)} CM slots point at {expect}")
            return 0
        if matched:
            print(f"WARN — only {matched}/{len(slots)} slots point at {expect} "
                  f"(long-IP slots were skipped); not fully patched")
            return 1
        print(f"FAIL — no CM slots point at {expect} (run patch first)")
        return 1

    if len(ips) == 1:
        print(f"OK — all {len(slots)} CM entries point at {next(iter(ips))}")
        return 0
    print(f"WARN — {len(ips)} distinct CM IPs remain "
          "(unpatched, or partially patched with a long target IP)")
    return 1


def read_endpoint_file(path: Path) -> str:
    if not path.is_file():
        print(f"error: endpoint file {path} not found — deploy the bridge first "
              f"(see .github/workflows/deploy.yml)", file=sys.stderr)
        raise SystemExit(2)
    line = path.read_text(encoding="utf-8").strip().splitlines()[0].strip()
    if ":" in line and line.count(":") == 1:
        ip, port = line.rsplit(":", 1)
        if port.isdigit():
            return ip
    return line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dylib", type=Path, default=DEFAULT_DYLIB)
    parser.add_argument("--ip", help="bridge IPv4 to hardcode (e.g. 203.0.113.7)")
    parser.add_argument("--endpoint-file", type=Path, default=ENDPOINT_FILE,
                        help="read the IP from a file (deploy/endpoint.txt)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change")
    parser.add_argument("--restore", action="store_true", help="restore from backup")
    parser.add_argument("--verify", action="store_true", help="check current state")
    parser.add_argument("--expect", help="with --verify: require every slot to "
                        "point at this IP (exit 0 only if fully patched)")
    args = parser.parse_args(argv)

    if args.restore:
        return restore(args.dylib)
    if args.verify:
        return verify(args.dylib, expect=args.expect)

    ip = args.ip
    if not ip:
        ip = read_endpoint_file(args.endpoint_file)
    if not ip:
        print("error: pass --ip or --endpoint-file", file=sys.stderr)
        return 2
    if args.ip is None and not _valid_ip(ip):
        # the IP came from the GitHub Actions endpoint file: an invalid value
        # there almost certainly means the bridge isn't deployed yet
        print(f"error: '{ip}' from {args.endpoint_file} is not a valid IPv4 "
              f"address — the bridge may not be deployed yet (see docs/DEPLOY.md)",
              file=sys.stderr)
        return 2
    return patch(args.dylib, ip, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
