"""Key Generation and Management Studio for StarVault.

Generates Ed25519, RSA-4096, and OpenPGP/GPG keypairs.
Provides format conversions to OpenSSH (.pub/.pem), PuTTY (.ppk), and Armored PGP (.asc).
"""

import base64
from dataclasses import dataclass
import hashlib
import hmac
import struct
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)


@dataclass
class GeneratedKeyResult:
    """Represents a generated keypair with metadata and multiple format exports."""
    key_type: str  # 'ed25519', 'rsa4096', 'gpg'
    algorithm_name: str  # e.g., 'Ed25519 (256-bit)', 'RSA (4096-bit)', 'OpenPGP (RSA-2048)'
    public_key: str
    private_key: str
    fingerprint: str
    comment: str = ""
    putty_ppk: str = ""
    format_notes: str = ""


def _ssh_str(data: bytes) -> bytes:
    """SSH wire-format string encoding (uint32 length + bytes)."""
    return struct.pack(">I", len(data)) + data


def _ssh_mpint(val: int) -> bytes:
    """SSH wire-format multiple precision integer encoding."""
    if val == 0:
        return struct.pack(">I", 0)
    b = val.to_bytes((val.bit_length() + 8) // 8, byteorder="big", signed=True)
    return struct.pack(">I", len(b)) + b


def _format_ppk(
    key_type_str: str,
    comment_str: str,
    pub_blob: bytes,
    priv_blob: bytes,
) -> str:
    """Formats an unencrypted PuTTY PPK v2 file."""
    comment_bytes = comment_str.encode("utf-8")
    mac_data = (
        _ssh_str(key_type_str.encode("utf-8"))
        + _ssh_str(b"none")
        + _ssh_str(comment_bytes)
        + _ssh_str(pub_blob)
        + _ssh_str(priv_blob)
    )
    mac = hmac.new(b"putty-key-file-mac-key", mac_data, hashlib.sha1).hexdigest()

    pub_b64 = base64.b64encode(pub_blob).decode("ascii")
    priv_b64 = base64.b64encode(priv_blob).decode("ascii")

    pub_lines = [pub_b64[i : i + 64] for i in range(0, len(pub_b64), 64)]
    priv_lines = [priv_b64[i : i + 64] for i in range(0, len(priv_b64), 64)]

    return (
        f"PuTTY-User-Key-File-2: {key_type_str}\n"
        f"Encryption: none\n"
        f"Comment: {comment_str}\n"
        f"Public-Lines: {len(pub_lines)}\n"
        f"{chr(10).join(pub_lines)}\n"
        f"Private-Lines: {len(priv_lines)}\n"
        f"{chr(10).join(priv_lines)}\n"
        f"Private-MAC: {mac}\n"
    )


def compute_openssh_fingerprint(public_ssh_text: str) -> str:
    """Calculates SHA256 fingerprint from an OpenSSH public key string."""
    try:
        parts = public_ssh_text.strip().split()
        if len(parts) >= 2:
            key_blob = base64.b64decode(parts[1])
            digest = hashlib.sha256(key_blob).digest()
            b64_digest = base64.b64encode(digest).decode("ascii").rstrip("=")
            return f"SHA256:{b64_digest}"
    except Exception:
        pass
    return "UNKNOWN"


def generate_ed25519_key(comment: str = "starvault-ed25519") -> GeneratedKeyResult:
    """Generates an Ed25519 SSH keypair with OpenSSH and PuTTY PPK exports."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    # OpenSSH Public Key
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    pub_text = pub_bytes.decode("ascii") + (f" {comment}" if comment else "")

    # OpenSSH Private Key PEM
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_text = priv_bytes.decode("ascii")

    # PuTTY PPK v2
    raw_pub = pub.public_bytes_raw()
    raw_priv = priv.private_bytes_raw()
    pub_blob = _ssh_str(b"ssh-ed25519") + _ssh_str(raw_pub)
    priv_blob = _ssh_str(raw_priv + raw_pub)
    ppk_text = _format_ppk("ssh-ed25519", comment or "starvault-ed25519", pub_blob, priv_blob)

    fp = compute_openssh_fingerprint(pub_text)

    return GeneratedKeyResult(
        key_type="ed25519",
        algorithm_name="Ed25519 (256-bit)",
        public_key=pub_text,
        private_key=priv_text,
        fingerprint=fp,
        comment=comment,
        putty_ppk=ppk_text,
        format_notes="Modern elliptic curve, fast, high security. Compatible with OpenSSH >= 6.5.",
    )


def generate_rsa_key(bits: int = 4096, comment: str = "starvault-rsa") -> GeneratedKeyResult:
    """Generates an RSA SSH keypair (default 4096-bit) with OpenSSH and PuTTY PPK exports."""
    if bits < 2048:
        bits = 2048

    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()

    # OpenSSH Public Key
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    pub_text = pub_bytes.decode("ascii") + (f" {comment}" if comment else "")

    # OpenSSH Private Key PEM
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_text = priv_bytes.decode("ascii")

    # PuTTY PPK v2
    pn = priv.private_numbers()
    pub_pn = pub.public_numbers()
    pub_blob = _ssh_str(b"ssh-rsa") + _ssh_mpint(pub_pn.e) + _ssh_mpint(pub_pn.n)
    priv_blob = _ssh_mpint(pn.d) + _ssh_mpint(pn.p) + _ssh_mpint(pn.q) + _ssh_mpint(pn.iqmp)
    ppk_text = _format_ppk("ssh-rsa", comment or f"starvault-rsa-{bits}", pub_blob, priv_blob)

    fp = compute_openssh_fingerprint(pub_text)

    return GeneratedKeyResult(
        key_type="rsa4096",
        algorithm_name=f"RSA ({bits}-bit)",
        public_key=pub_text,
        private_key=priv_text,
        fingerprint=fp,
        comment=comment,
        putty_ppk=ppk_text,
        format_notes=f"Standard RSA {bits}-bit keypair. Universally supported by all SSH daemons.",
    )


def generate_gpg_key(
    name: str,
    email: str,
    comment: str = "StarVault Key",
    bits: int = 2048,
) -> GeneratedKeyResult:
    """Generates an OpenPGP / GPG keypair with armored public and private outputs."""
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, bits)
    uid = pgpy.PGPUID.new(name, email=email, comment=comment)

    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[
            CompressionAlgorithm.ZLIB,
            CompressionAlgorithm.ZIP,
            CompressionAlgorithm.Uncompressed,
        ],
    )

    pub_armored = str(key.pubkey)
    priv_armored = str(key)
    fp_raw = str(key.fingerprint)

    # Format fingerprint with spacing: XXXX XXXX ...
    spaced_fp = " ".join(fp_raw[i : i + 4] for i in range(0, len(fp_raw), 4))

    return GeneratedKeyResult(
        key_type="gpg",
        algorithm_name=f"OpenPGP RSA ({bits}-bit)",
        public_key=pub_armored,
        private_key=priv_armored,
        fingerprint=spaced_fp,
        comment=f"{name} <{email}>",
        putty_ppk="",
        format_notes="Armored OpenPGP (RFC 4880) keypair for GPG email/file encryption and git commit signing.",
    )


def generate_tls_cert_key(
    common_name: str = "localhost",
    san_list: Optional[list] = None,
    organization: str = "StarVault Homelab",
    validity_days: int = 365,
    key_type: str = "RSA 2048",
) -> GeneratedKeyResult:
    """Generates a self-signed X.509 TLS/SSL certificate with SAN extensions."""
    from starvault.cert_generator import generate_self_signed_cert
    cert_pem, key_pem = generate_self_signed_cert(
        common_name=common_name,
        san_list=san_list,
        organization=organization,
        validity_days=validity_days,
        key_type=key_type,
    )
    fp = hashlib.sha256(cert_pem.encode("utf-8")).hexdigest()[:32]
    spaced_fp = " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))
    return GeneratedKeyResult(
        key_type="tls_cert",
        algorithm_name=f"X.509 TLS Certificate ({key_type})",
        public_key=cert_pem,
        private_key=key_pem,
        fingerprint=f"SHA256:{spaced_fp}",
        comment=f"CN={common_name}, Valid {validity_days} days",
        format_notes="Self-signed TLS/SSL certificate with SAN extensions for HTTPS homelab and internal services.",
    )


def generate_wireguard_key_result() -> GeneratedKeyResult:
    """Generates a WireGuard VPN Curve25519 keypair."""
    from starvault.cert_generator import generate_wireguard_keypair
    priv_b64, pub_b64 = generate_wireguard_keypair()
    fp = hashlib.sha256(pub_b64.encode("utf-8")).hexdigest()[:24]
    return GeneratedKeyResult(
        key_type="wireguard",
        algorithm_name="WireGuard VPN (Curve25519)",
        public_key=pub_b64,
        private_key=priv_b64,
        fingerprint=f"WG:{fp}",
        comment="WireGuard Interface Keypair",
        format_notes="Standard Base64 Curve25519 keypair for WireGuard peer or interface configuration.",
    )


def generate_age_key_result() -> GeneratedKeyResult:
    """Generates an Age encryption keypair."""
    from starvault.cert_generator import generate_age_keypair
    sec_key, recipient = generate_age_keypair()
    return GeneratedKeyResult(
        key_type="age",
        algorithm_name="Age Encryption Key (X25519)",
        public_key=recipient,
        private_key=sec_key,
        fingerprint=recipient[:24] + "...",
        comment="Age Recipient Key",
        format_notes="Modern age-keygen compatible X25519 keypair for encrypting files and backups.",
    )
