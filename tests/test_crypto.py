"""Unit tests for the CM channel cryptography (gateway/cm/crypto.py).

Ground truth: SteamKit 2015 CMClient.cs (RSA-encrypted 32-byte session key)
and CryptoHelper.cs (SymmetricEncrypt: AES-256-ECB-crypted IV || AES-256-CBC
PKCS7 ciphertext with the 32-byte session key).
"""
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

from gateway.cm import crypto as cmcrypto


def _pub(key):
    return key.public_key()


def test_generated_key_fits_the_embedded_slot():
    """The client's key slot holds 320 hex chars (160-byte DER SPKI)."""
    key = cmcrypto.generate_cm_key()
    hx = cmcrypto.spki_hex(key)
    assert len(hx) == cmcrypto.SPKI_HEX_LEN == 320
    der = bytes.fromhex(hx)
    assert len(der) == 160
    # 1024-bit RSA
    assert key.key_size == 1024
    # Same DER SteamKit/Valve parse (it is a valid SPKI)
    pub = serialization.load_der_public_key(der)
    assert pub.key_size == 1024


def test_generate_cm_key_persists_and_reloads(tmp_path):
    key_path = tmp_path / "cm-rsa.key"
    key = cmcrypto.load_or_create_cm_key(key_path)
    assert key_path.is_file()
    again = cmcrypto.load_or_create_cm_key(key_path)
    assert (again.private_numbers().public_numbers.n
            == key.private_numbers().public_numbers.n)


def test_symmetric_roundtrip():
    key = os.urandom(32)
    msg = b"VT01" + b"\x08\x01\x08\x01" * 10  # anything, incl. our magic
    wire = cmcrypto.symmetric_encrypt(msg, key)
    # wire = [16-byte ECB-crypted IV] + CBC ciphertext (multiple of 16)
    assert len(wire) == 16 + ((len(msg) // 16) + 1) * 16
    assert cmcrypto.symmetric_decrypt(wire, key) == msg


def test_symmetric_iv_is_random_per_message():
    key = os.urandom(32)
    a = cmcrypto.symmetric_encrypt(b"A" * 32, key)
    b = cmcrypto.symmetric_encrypt(b"A" * 32, key)
    assert a != b


def test_payload_helpers_only_encrypt_post_vt01():
    key = os.urandom(32)
    payload = b"VT01" + b"\x08\x01\x08\x01"
    wire = cmcrypto.encrypt_payload(payload, key)
    assert wire[:4] == b"VT01"          # magic stays plaintext
    assert wire[4:] != payload[4:]      # data is encrypted
    assert cmcrypto.decrypt_payload(wire, key) == payload
    # non-VT01 payloads pass through untouched
    assert cmcrypto.encrypt_payload(b"\x00\x01", key) == b"\x00\x01"
    assert cmcrypto.decrypt_payload(b"\x00\x01", key) == b"\x00\x01"


def test_rsa_decrypt_pkcs1_session_key():
    key = cmcrypto.generate_cm_key()
    session_key = os.urandom(32)
    blob = _pub(key).encrypt(session_key, rsa_padding.PKCS1v15())
    assert cmcrypto.rsa_decrypt(blob, key) == session_key


def test_rsa_decrypt_oaep_path():
    """Some captures may show OAEP; the OAEP branch must handle it."""
    key = cmcrypto.generate_cm_key()
    session_key = os.urandom(32)
    blob = _pub(key).encrypt(
        session_key,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None))
    assert cmcrypto.rsa_decrypt_oaep(blob, key) == session_key


def test_decrypt_password():
    key = cmcrypto.generate_cm_key()
    blob = _pub(key).encrypt(b"hunter2", rsa_padding.PKCS1v15())
    assert cmcrypto.decrypt_password(blob, key) == "hunter2"


def test_decrypt_password_garbage_returns_none():
    key = cmcrypto.generate_cm_key()
    assert cmcrypto.decrypt_password(b"\x00" * 128, key) is None


def test_wrong_length_key_rejected():
    import pytest

    with pytest.raises(ValueError):
        cmcrypto.symmetric_encrypt(b"x", b"short")
