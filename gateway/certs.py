"""Local CA + host certificate generation.

The old Lion client will verify the gateway's TLS certificates against Valve's
real roots, so we generate our own CA, issue a certificate covering every routed
hostname, and the user installs the CA into the Lion keychain once.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gateway import routes

CA_CN = "steam-legacy-gateway local CA"
CA_VALID_DAYS = 3650
LEAF_VALID_DAYS = 825
RSA_BITS = 2048


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # The CA key is the trust anchor installed on the Lion machine; keep it
    # readable only by the gateway's owner.
    os.chmod(path, 0o600)


def ensure_ca(cert_dir: Path) -> tuple[Path, Path]:
    """Create (or reuse) the CA keypair. Returns (cert_path, key_path)."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = cert_dir / "steam-gateway-ca.crt", cert_dir / "steam-gateway-ca.key"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)]
    )
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    return cert_path, key_path


def ensure_bundle_cert(cert_dir: Path) -> tuple[Path, Path]:
    """Issue one leaf certificate covering every routed hostname.

    A single bundle cert is used for all connections (the old client's SNI is
    always one of the routed names), which avoids per-handshake cert swapping.
    Returns (cert_path, key_path).
    """
    ca_cert_path, ca_key_path = ensure_ca(cert_dir)
    cert_path, key_path = cert_dir / "steam-gateway-leaf.crt", cert_dir / "steam-gateway-leaf.key"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path

    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    names = (
        routes.all_forward_hostnames()
        + routes.CM_HOSTNAMES
        + routes.CONTENT_CACHE_HOSTS
    )
    sans = [x509.DNSName(n) for n in sorted(set(names))] + [x509.DNSName("localhost")]

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "steam-gateway")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    return cert_path, key_path
