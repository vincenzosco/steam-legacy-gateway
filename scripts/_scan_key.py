#!/usr/bin/env python3
"""_scan_key.py — extended hunt for Valve's embedded RSA public key.

Walks the entire extracted client bundle and searches for the RSA public
keys Valve's clients embed (one per EUniverse) in every plausible on-disk
representation:

  * DER SubjectPublicKeyInfo (the exact SteamKit KeyDictionary format)
  * DER RSAPublicKey (SPKI algorithm header stripped)
  * raw 128-byte modulus: big-endian, little-endian (byte-reversed),
    split halves (first/last 64 bytes), truncated prefixes/suffixes
    (8/16/32 bytes)
  * obfuscated forms of the modulus prefix: single-byte XOR with common
    constants, 16-bit word-swap, 32-bit word byte-reversal, bit-rotation,
    bitwise complement
  * encodings: base64 (XML <RSAKeyValue>/C# blob style), hex ASCII
  * textual markers: <RSAKeyValue, Modulus>, AQAB, PEM BEGIN lines
  * Windows CAPI PUBLICKEYBLOB (06 02 00 00 00 A4 00 00 + exponent LE +
    modulus BE) and bare modulus+exponent concatenations

Key material is parsed from SteamKit's KeyDictionary.cs (2015-era commit
9b4807eb and current master) — the same source the gateway's protocol
analysis is grounded in. If the C# files are not on disk they are fetched
from GitHub (cached in /tmp).

Usage:
  python3 scripts/_scan_key.py [bundle_root]     # default: client/Steam.app
"""
from __future__ import annotations

import base64
import os
import re
import struct
import sys
import urllib.request

# --------------------------------------------------------------------------
# Ground-truth keys: SteamKit KeyDictionary.cs (2015-era + current master)
# --------------------------------------------------------------------------

KD_2015_URL = ("https://raw.githubusercontent.com/SteamRE/SteamKit/"
               "9b4807eb13471e750da36b6e34b28df64b52da24/"
               "SteamKit2/SteamKit2/Util/KeyDictionary.cs")
KD_MASTER_URL = ("https://raw.githubusercontent.com/SteamRE/SteamKit/master/"
                 "SteamKit2/SteamKit2/Util/KeyDictionary.cs")

# 2015-era style:  { EUniverse.X, new byte[] { ... } }
# master style:     [ EUniverse.X ] = [ 0x.., ... ]   (array literal)
_BLOCK_RE = re.compile(
    r"EUniverse\.(\w+)\s*\]?\s*(?:,|=)\s*(?:new\s*byte\[\]?\s*\{|\[)\s*(.*?)\s*(?:\}|\])\s*(?:,|;|=|\)|\[)?",
    re.S,
)


def _fetch(url: str, dest: str) -> None:
    """Fetch url into dest if absent; fail gracefully (analyze_client.sh calls us)."""
    if os.path.isfile(dest):
        return
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            open(dest, "wb").write(r.read())
    except Exception as e:  # network down / proxy / rate limit
        print(f"error: could not fetch key material from\n  {url}\n  ({e})",
              file=sys.stderr)
        print("hint: pre-place the SteamKit KeyDictionary.cs files at "
              "/tmp/kd2015.cs and /tmp/kdmaster.cs to run offline",
              file=sys.stderr)
        raise SystemExit(2)


def parse_keys(*paths: str) -> dict[str, bytes]:
    """Parse (universe -> DER SubjectPublicKeyInfo) from KeyDictionary.cs files.

    Precedence: the first file wins per universe (setdefault). Callers pass the
    2015-era file first — its keys are exactly what the Oct-2015 client embeds;
    current-master entries are only used for universes 2015 lacks (e.g. Dev).
    """
    keys: dict[str, bytes] = {}
    for p in paths:
        src = open(p, encoding="utf-8", errors="replace").read()
        for name, body in _BLOCK_RE.findall(src):
            hexbytes = re.findall(r"0x([0-9A-Fa-f]{2})", body)
            if len(hexbytes) >= 30:  # skip EUniverse.Invalid (null)
                der = bytes(int(h, 16) for h in hexbytes)
                keys.setdefault(name, der)
    return keys


# --------------------------------------------------------------------------
# Minimal DER walker
# --------------------------------------------------------------------------

def _read_tlv(buf: bytes, i: int = 0) -> tuple[int, bytes, int]:
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, buf[i:i + ln], i + ln


def extract_rsa(spki: bytes) -> tuple[bytes, int, bytes]:
    """Return (modulus, exponent, RSAPublicKey-DER) from SPKI DER bytes."""
    _, outer, _ = _read_tlv(spki, 0)            # SEQUENCE (SPKI)
    _, _algid, i = _read_tlv(outer, 0)          # AlgorithmIdentifier
    _, bitstr, _ = _read_tlv(outer, i)          # BIT STRING
    rsa_der = bitstr[1:]                        # drop unused-bits octet
    _, seq, _ = _read_tlv(rsa_der, 0)           # SEQUENCE (RSAPublicKey)
    _, mod_int, i = _read_tlv(seq, 0)           # INTEGER modulus
    modulus = mod_int[1:] if mod_int[:1] == b"\x00" else mod_int
    _, exp_int, _ = _read_tlv(seq, i)           # INTEGER exponent
    exponent = int.from_bytes(exp_int, "big")
    return modulus, exponent, rsa_der


# --------------------------------------------------------------------------
# Signature generation (every plausible on-disk representation)
# --------------------------------------------------------------------------

_XOR_KEYS = (0xFF, 0xAA, 0x55, 0x5A, 0xA5, 0xCC, 0x33, 0x66, 0x99, 0x0F, 0xF0)
_TEXT_MARKERS = (
    b"<RSAKeyValue", b"Modulus>", b"<Exponent>", b"AQAB",
    b"BEGIN PUBLIC KEY", b"BEGIN RSA PUBLIC KEY",
)
# The ASCII hex of the DER SPKI header that every embedded key string begins
# with — catches unidentified keys and duplicate tables (this client has two
# identical 5-key tables).
_SPKI_HEX_PREFIX = b"30819d300d06092a864886f70d010101050003818b"


def key_signatures(name: str, spki: bytes) -> dict[str, bytes]:
    modulus, exponent, rsa_der = extract_rsa(spki)
    mod_le = modulus[::-1]
    sigs: dict[str, bytes] = {}

    def add(label: str, sig: bytes) -> None:
        sigs.setdefault(label, sig)

    # --- canonical forms -------------------------------------------------
    add(f"{name} DER-SPKI", spki)
    add(f"{name} DER-RSAPublicKey", rsa_der)
    add(f"{name} modulus-BE-128", modulus)
    add(f"{name} modulus-LE-128", mod_le)
    add(f"{name} modulus-BE-half1", modulus[:64])
    add(f"{name} modulus-BE-half2", modulus[64:])
    add(f"{name} modulus-LE-half1", mod_le[:64])
    add(f"{name} modulus-LE-half2", mod_le[64:])
    for n in (8, 16, 32):
        add(f"{name} modulus-BE-prefix{n}", modulus[:n])
        add(f"{name} modulus-BE-suffix{n}", modulus[-n:])
        add(f"{name} modulus-LE-prefix{n}", mod_le[:n])
    add(f"{name} modulus+exponent-raw", modulus + bytes([exponent]))
    add(f"{name} CAPI-PUBLICKEYBLOB",
        bytes([0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00])
        + struct.pack("<I", exponent) + modulus)

    # --- obfuscated prefix variants (16 bytes) --------------------------
    pref = modulus[:16]
    for k in _XOR_KEYS:
        add(f"{name} XOR-0x{k:02X}-16", bytes(b ^ k for b in pref))
    add(f"{name} complement-16", bytes(0xFF ^ b for b in pref))
    add(f"{name} swap16-16", b"".join(pref[i:i + 2][::-1]
                                      for i in range(0, 16, 2)))
    add(f"{name} rev32-16", b"".join(pref[i:i + 4][::-1]
                                     for i in range(0, 16, 4)))
    for n in (1, 2, 4, 8):
        add(f"{name} rotl{n}-16",
            bytes(((b << n) | (b >> (8 - n))) & 0xFF for b in pref))

    # --- encodings -------------------------------------------------------
    add(f"{name} base64-DER", base64.b64encode(spki))
    add(f"{name} base64-RSAPublicKey", base64.b64encode(rsa_der))
    add(f"{name} base64-modulus-36", base64.b64encode(modulus[:36]))
    add(f"{name} hex-modulus", modulus.hex().encode())
    add(f"{name} hex-modulus-LE", mod_le.hex().encode())
    # hex-ASCII of the FULL DER SPKI — the format this client actually embeds
    # (NUL-terminated lowercase hex strings in the __cstring pool)
    add(f"{name} hex-DER-SPKI", spki.hex().encode())
    add(f"{name} hex-DER-prefix32", spki[:32].hex().encode())
    return sigs


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------

def scan(root: str, sigs: dict[str, bytes]) -> list[tuple[str, str, int]]:
    hits: list[tuple[str, str, int]] = []
    files = []
    for dirpath, _dirs, names in os.walk(root):
        for fn in names:
            files.append(os.path.join(dirpath, fn))
    for p in sorted(files):
        if p.endswith(".orig"):  # patch_client.py backups — same bytes, noise
            continue
        try:
            if os.path.getsize(p) > 400 * 1024 * 1024:
                continue
            data = open(p, "rb").read()
        except OSError:
            continue
        for label, sig in sigs.items():
            idx = data.find(sig)
            if idx >= 0:
                hits.append((p, label, idx))
    return hits


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    root = args[0] if args else "client/Steam.app"

    kd2015 = "/tmp/kd2015.cs"
    kdmaster = "/tmp/kdmaster.cs"
    _fetch(KD_2015_URL, kd2015)
    _fetch(KD_MASTER_URL, kdmaster)
    keys = parse_keys(kd2015, kdmaster)  # 2015 first: matches this client's keys
    if not keys:
        print("failed to parse any keys from SteamKit KeyDictionary", file=sys.stderr)
        return 2
    print(f"keys parsed: {', '.join(sorted(keys))}\n")

    sigs: dict[str, bytes] = {}
    for name, spki in keys.items():
        sigs.update(key_signatures(name, spki))
    # textual markers (file-wide, not key-specific)
    for m in _TEXT_MARKERS:
        sigs[f"marker {m.decode()!r}"] = m
    sigs["SPKI-hex-prefix (any key)"] = _SPKI_HEX_PREFIX

    print(f"scanning {root} with {len(sigs)} signatures ({len(keys)} keys)...")
    hits = scan(root, sigs)

    if not hits:
        print("\nNONE — no signature from any universe, in any format, found in "
              "any file of the bundle.")
        print("Conclusion: the key is not stored as DER/raw modulus/obfuscated "
              "blob in this build — it is likely fetched at runtime or embedded "
              "in an unknown transform (capture the handshake to confirm).")
        return 0

    print(f"\n{len(hits)} hit(s):")
    seen: set[str] = set()
    real = 0
    full_der_hits = 0
    for p, label, idx in hits:
        key = (p, label)
        dup = "(dup)" if key in seen else ""
        seen.add(key)
        if label.startswith("marker"):
            print(f"  {p}: {label} @ 0x{idx:x} {dup}  [textual marker — may be a"
                  f" false positive, e.g. base64 'AQAB' inside CEF resources]")
            continue
        if "hex-DER-SPKI" in label:
            full_der_hits += 1
        real += 1
        print(f"  {p}: {label} @ 0x{idx:x} {dup}")
    if real:
        if full_der_hits:
            print("\nFound full embedded keys (hex-DER-SPKI): the client stores"
                  "each universe key as a NUL-terminated lowercase hex-ASCII DER"
                  "string in the __cstring pool — patchable in place with a"
                  "same-length key swap (see PROTOCOL_ANALYSIS.md §2.3).")
        else:
            print("\nFound key-related material (SPKI-hex prefix) — inspect the"
                  "offsets above to map the full tables.")
    else:
        print("\nOnly textual-marker hits (likely false positives); no real key"
              "material found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
