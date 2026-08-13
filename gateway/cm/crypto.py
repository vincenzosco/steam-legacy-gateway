"""CM channel cryptography for the Oct-2015 Steam protocol.

Grounded in the 2015-era SteamKit sources (CMClient.cs, CryptoHelper.cs,
TcpConnection.cs):

  * The client generates a random 32-byte session key and RSA-encrypts it
    (PKCS#1 v1.5) with the CM server's public key for the selected universe.
    The per-universe keys are the hex-ASCII DER strings embedded in the
    client (see docs/PROTOCOL_ANALYSIS.md §2.3). To be able to read the
    session key (and the logon password, which uses the same key), the bridge
    swaps the embedded Public key for its own:
        python -m gateway gen-cm-key
        ./scripts/patch_client.py --swap-key --key-pem certs/cm-rsa.key

  * After the ChannelEncryptResult, every frame payload (the bytes after the
    plaintext "VT01" magic) is encrypted with the session key using SteamKit
    CryptoHelper.SymmetricEncrypt:
        cryptedIV = AES-256-ECB(session_key, random_iv)      # 16 bytes, no padding
        cipher    = AES-256-CBC(session_key, iv, plaintext)  # PKCS7
        wire      = cryptedIV || cipher

    SymmetricDecrypt is the inverse: ECB-decrypt the 16-byte IV, then
    CBC-decrypt the rest.

  * The embedded key slot is exactly 320 lowercase hex chars (a 160-byte DER
    SPKI, 1024-bit RSA). Valve's own CM keys use exponent 0x11 (17) which
    keeps the exponent INTEGER at 3 bytes. `cryptography` only generates
    exponents 3 or 65537, so we use 3 — also a 3-byte INTEGER — giving the
    exact same 160-byte layout for a same-length in-place swap.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger("gateway.cm.crypto")

# The client's embedded key slot: 320 lowercase hex chars + NUL.
SPKI_HEX_LEN = 320
# Session key length (CMClient.cs: CryptoHelper.GenerateRandomBlock(32)).
SESSION_KEY_LEN = 32

RSA_PKCS1 = padding.PKCS1v15()
RSA_OAEP_SHA1 = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA1()),
    algorithm=hashes.SHA1(),
    label=None,
)


def generate_cm_key() -> rsa.RSAPrivateKey:
    """Generate a 1024-bit RSA key whose SPKI DER is exactly 160 bytes.

    The embedded slot in the client holds 320 hex chars (160-byte DER). A
    1024-bit modulus always serializes to 129 bytes (leading zero for the
    sign bit), so the total is 160 only when the exponent INTEGER is 3 bytes
    — which is what Valve's own e=0x11 keys achieve, and what e=3 gives here.
    (The standard e=65537 would need 5 bytes -> 162-byte DER -> 324 hex chars,
    which overflows the slot.) The bridge's channel is local-LAN only and the
    modern login itself rides on TLS, so the legacy-compatible e=3 is fine.
    """
    key = rsa.generate_private_key(public_exponent=3, key_size=1024)
    if len(spki_der(key)) != 160:
        raise RuntimeError(f"unexpected SPKI size {len(spki_der(key))} "
                           f"(expected 160 for a 1024-bit e=3 key)")
    return key


def spki_der(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def spki_hex(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> str:
    """Lowercase hex of the SPKI DER — the exact form the client embeds."""
    hx = spki_der(key).hex()
    if len(hx) != SPKI_HEX_LEN:
        raise ValueError(
            f"SPKI hex is {len(hx)} chars, expected {SPKI_HEX_LEN} "
            f"(need a 1024-bit e=3 key, see generate_cm_key)")
    return hx


def load_or_create_cm_key(key_path: Path) -> rsa.RSAPrivateKey:
    """Load the bridge's CM RSA key from disk, generating it if absent."""
    if key_path.is_file():
        return serialization.load_pem_private_key(
            key_path.read_bytes(), password=None)
    key = generate_cm_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    log.info("generated CM RSA key at %s (SPKI hex %d chars)",
             key_path, len(spki_hex(key)))
    return key


def rsa_decrypt(blob: bytes, key: rsa.RSAPrivateKey) -> bytes | None:
    """RSA-decrypt `blob`. PKCS#1 v1.5 primary, OAEP-SHA1 fallback.

    The 2015-era client used RSACrypto (PKCS#1 v1.5, fOAEP=false). The
    fallback covers the possibility that a captured client used OAEP, so a
    real capture can disambiguate without a code change.
    """
    try:
        return key.decrypt(blob, RSA_PKCS1)
    except ValueError:
        return rsa_decrypt_oaep(blob, key)


def rsa_decrypt_oaep(blob: bytes, key: rsa.RSAPrivateKey) -> bytes | None:
    try:
        return key.decrypt(blob, RSA_OAEP_SHA1)
    except ValueError:
        return None


def decrypt_password(blob: bytes, key: rsa.RSAPrivateKey) -> str | None:
    """Decrypt a CMsgClientLogon.password blob (RSA, same CM key)."""
    plain = rsa_decrypt(blob, key)
    if plain is None:
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None


def symmetric_encrypt(plaintext: bytes, session_key: bytes) -> bytes:
    """SteamKit CryptoHelper.SymmetricEncrypt: ECB-crypted IV || CBC cipher."""
    if len(session_key) != SESSION_KEY_LEN:
        raise ValueError(f"session key must be {SESSION_KEY_LEN} bytes")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding

    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(session_key), modes.ECB()).encryptor()
    crypted_iv = enc.update(iv) + enc.finalize()
    padder = sym_padding.PKCS7(128).padder()
    enc2 = Cipher(algorithms.AES(session_key), modes.CBC(iv)).encryptor()
    cipher = enc2.update(padder.update(plaintext) + padder.finalize()) + enc2.finalize()
    return crypted_iv + cipher


def symmetric_decrypt(wire: bytes, session_key: bytes) -> bytes:
    """SteamKit CryptoHelper.SymmetricDecrypt: inverse of symmetric_encrypt."""
    if len(session_key) != SESSION_KEY_LEN:
        raise ValueError(f"session key must be {SESSION_KEY_LEN} bytes")
    if len(wire) < 17:
        raise ValueError("ciphertext too short")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding

    crypted_iv, cipher = wire[:16], wire[16:]
    dec = Cipher(algorithms.AES(session_key), modes.ECB()).decryptor()
    iv = dec.update(crypted_iv) + dec.finalize()
    dec2 = Cipher(algorithms.AES(session_key), modes.CBC(iv)).decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plain = dec2.update(cipher) + dec2.finalize()
    return unpadder.update(plain) + unpadder.finalize()


def encrypt_payload(payload: bytes, session_key: bytes) -> bytes:
    """Encrypt the post-VT01 part of a frame payload.

    On the wire the length prefix and "VT01" magic stay plaintext; only the
    data after the magic is encrypted (TcpConnection.ProcessOutgoing).
    """
    if not payload.startswith(b"VT01"):
        return payload
    return b"VT01" + symmetric_encrypt(payload[4:], session_key)


def decrypt_payload(payload: bytes, session_key: bytes) -> bytes:
    """Inverse of encrypt_payload (TcpConnection.ProcessIncoming)."""
    if not payload.startswith(b"VT01"):
        return payload
    return b"VT01" + symmetric_decrypt(payload[4:], session_key)
