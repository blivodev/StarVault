"""Self-Signed TLS Certificate and Modern Key Generation Engine for StarVault.

Generates:
- Self-Signed X.509 TLS/SSL Certificates (RSA, ECDSA, Ed25519) with Subject Alternative Names (SANs)
- WireGuard VPN Keypairs (X25519)
- Age Encryption Keypairs (X25519 Bech32)
"""

import datetime
from ipaddress import ip_address
import os
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    common_name: str = "localhost",
    san_list: Optional[List[str]] = None,
    organization: str = "StarVault Homelab",
    country: str = "US",
    validity_days: int = 365,
    key_type: str = "RSA 2048",
) -> Tuple[str, str]:
    """Generates a self-signed X.509 TLS/SSL certificate and private key in PEM format.

    Args:
        common_name: Primary domain or IP (e.g. 'localhost', '192.168.1.100', 'vault.local')
        san_list: Additional Subject Alternative Names (DNS names or IP addresses)
        organization: Organization or Company name
        country: Two-letter ISO country code (e.g. 'US')
        validity_days: Number of days until expiration
        key_type: 'RSA 2048', 'RSA 4096', 'ECDSA P-256', or 'Ed25519'

    Returns:
        (cert_pem_str, private_key_pem_str)
    """
    key_norm = key_type.upper().strip()

    if "4096" in key_norm:
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        hash_algo = hashes.SHA256()
    elif "ECDSA" in key_norm or "P-256" in key_norm:
        priv_key = ec.generate_private_key(ec.SECP256R1())
        hash_algo = hashes.SHA256()
    elif "ED25519" in key_norm:
        priv_key = ed25519.Ed25519PrivateKey.generate()
        hash_algo = None  # Ed25519 signs without separate digest
    else:
        # Default RSA 2048
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        hash_algo = hashes.SHA256()

    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper() if country else "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "StarVault"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name or "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=max(1, validity_days)))
    )

    # Basic Constraints (End Entity)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    # Subject Alternative Names (SANs)
    sans_to_add = set()
    if common_name:
        sans_to_add.add(common_name.strip())
    if san_list:
        for s in san_list:
            if s and s.strip():
                sans_to_add.add(s.strip())

    general_names: List[x509.GeneralName] = []
    for item in sans_to_add:
        try:
            ip_obj = ip_address(item)
            general_names.append(x509.IPAddress(ip_obj))
        except ValueError:
            general_names.append(x509.DNSName(item))

    if general_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )

    # Extended Key Usage (Server Auth + Client Auth)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )

    cert = builder.sign(priv_key, hash_algo)

    # Export PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    return cert_pem, key_pem


def generate_wireguard_keypair() -> Tuple[str, str]:
    """Generates a WireGuard VPN keypair (X25519 Curve25519) formatted in standard Base64.

    Returns:
        (private_key_b64, public_key_b64)
    """
    import base64
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(priv_raw).decode("ascii"),
        base64.b64encode(pub_raw).decode("ascii"),
    )


# Bech32 implementation for Age encryption keys
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_encode(hrp, data):
    combined = data + [0, 0, 0, 0, 0, 0]
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + combined) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in data + checksum])


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def generate_age_keypair() -> Tuple[str, str]:
    """Generates an Age encryption keypair conforming to age-keygen format.

    Returns:
        (secret_key, public_recipient)
        e.g. ('AGE-SECRET-KEY-1...', 'age1...')
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Convert to 5-bit arrays for Bech32
    priv_5bit = _convertbits(list(priv_raw), 8, 5, True)
    pub_5bit = _convertbits(list(pub_raw), 8, 5, True)

    secret_key = _bech32_encode("age-secret-key-", priv_5bit).upper().replace("AGE-SECRET-KEY-1", "AGE-SECRET-KEY-1")
    recipient = _bech32_encode("age", pub_5bit).lower()

    return secret_key, recipient
