"""Scan the extracted client bundle for Valve's embedded RSA public key.

The DER prefix below is taken from 2015-era SteamKit KeyDictionary.cs
(EUniverse.Public) — the exact bytes the Oct-2015 client must embed to encrypt
its channel-encrypt session key. Finding it proves a key-replacement patch is
possible (replace the embedded pubkey with the gateway's own, so the gateway
holds the matching private key and can decrypt post-handshake traffic).
"""
from __future__ import annotations

import os
import sys

# DER-encoded SubjectPublicKeyInfo of Valve's EUniverse.Public key (SteamKit).
PUB_DER = bytes.fromhex(
    "30819d300d06092a864886f70d010101050003818b0030818702818100"
    "dfec1ad62c10662c17353a14b07c59117f9dd3d82b7ae3e015cd191e46"
    "e87b8774a2184631a9031479828ee945a24912a923687389cf69a1b161"
    "46bdc1bebfd6011bd881d4dc90fbfe4f527366cb9570d7c58eba1c7a33"
    "75a1623446bb60b78068fa13a77a8a374b9ec6f45d5f3a99f99ec43ae9"
    "63a2bb881928e0e714c04289020111"
)
MODULUS_PREFIX = bytes.fromhex("dfec1ad62c10662c")
BETA_DER_PREFIX = bytes.fromhex("30819d300d06092a864886f70d010101050003818b0030818702818100aed14bc0")

root = sys.argv[1] if len(sys.argv) > 1 else "client/Steam.app/Contents/MacOS"
hits = []
for dirpath, _dirs, files in os.walk(root):
    for fn in files:
        p = os.path.join(dirpath, fn)
        try:
            if os.path.getsize(p) > 300 * 1024 * 1024:
                continue
            data = open(p, "rb").read()
        except OSError:
            continue
        for name, sig in (
            ("Valve EUniverse.Public DER (full)", PUB_DER),
            ("Valve Public modulus prefix", MODULUS_PREFIX),
            ("Valve EUniverse.Beta DER prefix", BETA_DER_PREFIX),
        ):
            idx = data.find(sig)
            if idx >= 0:
                hits.append((p, name, idx))

if hits:
    for p, name, idx in hits:
        print(f"FOUND: {p}: {name} @ 0x{idx:x}")
else:
    print("NONE — Valve public key not found as DER/raw modulus in this bundle.")
