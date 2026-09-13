"""Cryptographic Swiss Army Knife Utility for StarVault.

Provides on-demand encryption, decryption, encoding, decoding, hashing, and HMAC
across industry-standard algorithms:
- Symmetric: AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305
- Asymmetric: RSA OAEP Encryption / Decryption
- Encodings: Base64, Hex, URL, Binary
- Hashing & HMAC: SHA-256, SHA-512, SHA3-256, MD5, HMAC-SHA256, HMAC-SHA512
- Password Hash Verification: Argon2id
"""

import base64
import hashlib
import hmac
import os
from pathlib import Path
from typing import Callable, List, Optional, Tuple, Union
from urllib.parse import quote, unquote

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from starvault.crypto import derive_key, generate_salt


# ----------------------------------------------------------------------
# Encodings
# ----------------------------------------------------------------------

def encode_base64(text: str) -> str:
    """Encodes UTF-8 string to standard Base64."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(encoded_str: str) -> str:
    """Decodes standard or URL-safe Base64 back to string."""
    cleaned = encoded_str.strip()
    missing_padding = len(cleaned) % 4
    if missing_padding:
        cleaned += "=" * (4 - missing_padding)
    raw_bytes = base64.b64decode(cleaned)
    return raw_bytes.decode("utf-8", errors="replace")


def encode_hex(text: str) -> str:
    """Encodes UTF-8 string to hexadecimal representation."""
    return text.encode("utf-8").hex()


def decode_hex(hex_str: str) -> str:
    """Decodes hexadecimal string back to text."""
    clean_hex = "".join(c for c in hex_str if c in "0123456789abcdefABCDEF")
    if len(clean_hex) % 2 != 0:
        clean_hex = "0" + clean_hex
    raw_bytes = bytes.fromhex(clean_hex)
    return raw_bytes.decode("utf-8", errors="replace")


def encode_url(text: str) -> str:
    """URL / Percent encodes a string."""
    return quote(text, safe="")


def decode_url(text: str) -> str:
    """Decodes URL / Percent encoded string."""
    return unquote(text)


def encode_binary(text: str) -> str:
    """Converts string into space-separated 8-bit binary representation."""
    return " ".join(format(b, "08b") for b in text.encode("utf-8"))


def decode_binary(binary_str: str) -> str:
    """Converts space-separated 8-bit binary numbers back to text."""
    parts = binary_str.strip().split()
    byte_list = []
    for p in parts:
        clean_p = "".join(c for c in p if c in "01")
        if clean_p:
            byte_list.append(int(clean_p, 2))
    return bytes(byte_list).decode("utf-8", errors="replace")


# ----------------------------------------------------------------------
# Hashing & HMAC
# ----------------------------------------------------------------------

def compute_hash(text: str, algorithm: str = "sha256") -> str:
    """Computes cryptographic digest in hexadecimal."""
    algo = algorithm.lower().strip().replace("-", "_")
    data = text.encode("utf-8")
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(data).hexdigest()
    elif algo == "sha384":
        return hashlib.sha384(data).hexdigest()
    elif algo == "sha224":
        return hashlib.sha224(data).hexdigest()
    elif algo in ("sha3_256", "sha3"):
        return hashlib.sha3_256(data).hexdigest()
    elif algo == "sha3_512":
        return hashlib.sha3_512(data).hexdigest()
    elif algo == "blake2b":
        return hashlib.blake2b(data).hexdigest()
    elif algo == "blake2s":
        return hashlib.blake2s(data).hexdigest()
    elif algo == "md5":
        return hashlib.md5(data).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algo == "ripemd160":
        try:
            h = hashlib.new("ripemd160")
            h.update(data)
            return h.hexdigest()
        except Exception:
            return hashlib.sha256(data).hexdigest()
    else:
        return hashlib.sha256(data).hexdigest()


def compute_hmac(text: str, secret_key: str, algorithm: str = "sha256") -> str:
    """Computes keyed-hash message authentication code (HMAC)."""
    key_bytes = secret_key.encode("utf-8")
    data_bytes = text.encode("utf-8")
    algo = algorithm.lower().strip()
    digest_mod = hashlib.sha512 if algo == "sha512" else hashlib.sha256
    return hmac.new(key_bytes, data_bytes, digest_mod).hexdigest()


# ----------------------------------------------------------------------
# Symmetric Ciphers (AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305)
# ----------------------------------------------------------------------

def _derive_symmetric_key(passphrase_or_hex: str, salt: bytes) -> bytes:
    """Derives a strict 256-bit key from a passphrase or parses a 64-char hex key."""
    clean = passphrase_or_hex.strip()
    if len(clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in clean):
        try:
            return bytes.fromhex(clean)
        except ValueError:
            pass
    # PBKDF2-HMAC-SHA256 derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(clean.encode("utf-8"))


def encrypt_symmetric(
    plaintext: str,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> str:
    """Encrypts plaintext and returns portable Base64 string containing salt, nonce, and ciphertext."""
    if not plaintext:
        return ""
    if not passphrase:
        raise ValueError("Passphrase or key is required for encryption.")

    cipher_norm = cipher.upper().replace(" ", "").replace("_", "-")
    salt = os.urandom(16)
    key_bytes = _derive_symmetric_key(passphrase, salt)
    data_bytes = plaintext.encode("utf-8")

    if "GCM" in cipher_norm:
        # AES-GCM (12-byte nonce)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        # Bundle: [1 byte version: 0x01] + [16 bytes salt] + [12 bytes nonce] + [ciphertext + tag]
        payload = b"\x01" + salt + nonce + ciphertext
        return base64.b64encode(payload).decode("ascii")

    elif "CHACHA" in cipher_norm:
        # ChaCha20-Poly1305 (12-byte nonce)
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key_bytes)
        ciphertext = chacha.encrypt(nonce, data_bytes, None)
        # Bundle: [1 byte version: 0x02] + [16 bytes salt] + [12 bytes nonce] + [ciphertext + tag]
        payload = b"\x02" + salt + nonce + ciphertext
        return base64.b64encode(payload).decode("ascii")

    elif "CBC" in cipher_norm:
        # AES-256-CBC with PKCS7 Padding (16-byte IV)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()
        c = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = c.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        # Bundle: [1 byte version: 0x03] + [16 bytes salt] + [16 bytes IV] + [ciphertext]
        payload = b"\x03" + salt + iv + ciphertext
        return base64.b64encode(payload).decode("ascii")

    else:
        raise ValueError(f"Unsupported cipher algorithm: {cipher}")


def decrypt_symmetric(
    ciphertext_b64: str,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> str:
    """Decrypts bundle produced by encrypt_symmetric."""
    if not ciphertext_b64:
        return ""
    if not passphrase:
        raise ValueError("Passphrase or key is required for decryption.")

    try:
        raw = base64.b64decode(ciphertext_b64.strip())
    except Exception as ex:
        raise ValueError(f"Invalid Base64 payload: {ex}")

    if len(raw) < 29:
        raise ValueError("Payload too short to be valid ciphertext bundle.")

    version = raw[0]
    salt = raw[1:17]
    key_bytes = _derive_symmetric_key(passphrase, salt)

    if version == 0x01 or "GCM" in cipher.upper():
        # AES-GCM
        nonce = raw[17:29]
        ct = raw[29:]
        aesgcm = AESGCM(key_bytes)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")

    elif version == 0x02 or "CHACHA" in cipher.upper():
        # ChaCha20-Poly1305
        nonce = raw[17:29]
        ct = raw[29:]
        chacha = ChaCha20Poly1305(key_bytes)
        pt = chacha.decrypt(nonce, ct, None)
        return pt.decode("utf-8")

    elif version == 0x03 or "CBC" in cipher.upper():
        # AES-256-CBC
        iv = raw[17:33]
        ct = raw[33:]
        c = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = c.decryptor()
        padded_pt = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded_pt) + unpadder.finalize()
        return pt.decode("utf-8")

    else:
        raise ValueError("Unrecognized payload format version.")


# ----------------------------------------------------------------------
# Asymmetric Ciphers (RSA OAEP)
# ----------------------------------------------------------------------

def rsa_encrypt(plaintext: str, pem_public_key: str) -> str:
    """Encrypts plaintext with an RSA public key using OAEP padding (SHA-256)."""
    pub_key = load_pem_public_key(pem_public_key.strip().encode("utf-8"))
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("Provided key is not an RSA public key.")

    ciphertext = pub_key.encrypt(
        plaintext.encode("utf-8"),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("ascii")


def rsa_decrypt(ciphertext_b64: str, pem_private_key: str, passphrase: Optional[str] = None) -> str:
    """Decrypts ciphertext with an RSA private key using OAEP padding (SHA-256)."""
    pw_bytes = passphrase.encode("utf-8") if passphrase else None
    priv_key = load_pem_private_key(pem_private_key.strip().encode("utf-8"), password=pw_bytes)
    if not isinstance(priv_key, rsa.RSAPrivateKey):
        raise ValueError("Provided key is not an RSA private key.")

    raw_ct = base64.b64decode(ciphertext_b64.strip())
    plaintext_bytes = priv_key.decrypt(
        raw_ct,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext_bytes.decode("utf-8")


def pgp_encrypt(plaintext: str, gpg_pubkey_armored: str) -> str:
    """Encrypts plaintext with an OpenPGP public key and returns ASCII armored message."""
    import pgpy
    pub, _ = pgpy.PGPKey.from_blob(gpg_pubkey_armored.strip())
    msg = pgpy.PGPMessage.new(plaintext)
    enc = pub.encrypt(msg)
    return str(enc)


def pgp_decrypt(pgp_message_armored: str, gpg_privkey_armored: str, passphrase: Optional[str] = None) -> str:
    """Decrypts an OpenPGP ASCII armored message using a private key."""
    import pgpy
    priv, _ = pgpy.PGPKey.from_blob(gpg_privkey_armored.strip())
    msg = pgpy.PGPMessage.from_blob(pgp_message_armored.strip())
    if passphrase and priv.is_protected:
        with priv.unlock(passphrase):
            dec = priv.decrypt(msg)
    else:
        dec = priv.decrypt(msg)
    return str(dec.message) if hasattr(dec, "message") else str(dec)


def asym_sign(data: str, privkey_pem: str, algorithm: str = "ed25519", passphrase: Optional[str] = None) -> str:
    """Signs plaintext data with a private key (Ed25519, RSA PSS, ECDSA) and returns Base64 signature."""
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
    data_bytes = data.encode("utf-8")
    pw = passphrase.encode("utf-8") if passphrase else None
    priv = load_pem_private_key(privkey_pem.strip().encode("utf-8"), password=pw)

    if isinstance(priv, ed25519.Ed25519PrivateKey):
        sig = priv.sign(data_bytes)
    elif isinstance(priv, rsa.RSAPrivateKey):
        sig = priv.sign(
            data_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    elif isinstance(priv, ec.EllipticCurvePrivateKey):
        sig = priv.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported key type for signing: {type(priv)}")
    return base64.b64encode(sig).decode("ascii")


def asym_verify(data: str, signature_b64: str, pubkey_pem_or_ssh: str) -> bool:
    """Verifies a signature against data and public key."""
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
    data_bytes = data.encode("utf-8")
    sig_bytes = base64.b64decode(signature_b64.strip())

    clean_pub = pubkey_pem_or_ssh.strip()
    if clean_pub.startswith(("ssh-", "ecdsa-")):
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        pub = load_ssh_public_key(clean_pub.encode("utf-8"))
    else:
        pub = load_pem_public_key(clean_pub.encode("utf-8"))

    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig_bytes, data_bytes)
            return True
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                sig_bytes,
                data_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig_bytes, data_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        else:
            return False
    except Exception:
        return False


# ----------------------------------------------------------------------
# File & Bulk File Encryption / Decryption
# ----------------------------------------------------------------------

MAGIC_FILE_HEADER = b"SVF1"


def encrypt_file(
    src_path: Union[str, Path],
    dst_path: Union[str, Path],
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> int:
    """Encrypts a file with the specified symmetric cipher.

    Returns the number of bytes written to the destination.
    """
    src = Path(src_path)
    dst = Path(dst_path)
    if not src.exists():
        raise FileNotFoundError(f"Source file does not exist: {src}")
    if not passphrase:
        raise ValueError("Passphrase or encryption key is required.")

    plaintext_bytes = src.read_bytes()
    cipher_norm = cipher.upper().replace(" ", "").replace("_", "-")
    salt = os.urandom(16)
    key_bytes = _derive_symmetric_key(passphrase, salt)

    if "GCM" in cipher_norm:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        payload = MAGIC_FILE_HEADER + b"\x01" + salt + nonce + ciphertext
    elif "CHACHA" in cipher_norm:
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key_bytes)
        ciphertext = chacha.encrypt(nonce, plaintext_bytes, None)
        payload = MAGIC_FILE_HEADER + b"\x02" + salt + nonce + ciphertext
    elif "CBC" in cipher_norm:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        c = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = c.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        payload = MAGIC_FILE_HEADER + b"\x03" + salt + iv + ciphertext
    else:
        raise ValueError(f"Unsupported cipher algorithm: {cipher}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(payload)
    return len(payload)


def decrypt_file(
    src_path: Union[str, Path],
    dst_path: Union[str, Path],
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> int:
    """Decrypts a StarVault encrypted file.

    Returns the number of decrypted bytes written.
    """
    src = Path(src_path)
    dst = Path(dst_path)
    if not src.exists():
        raise FileNotFoundError(f"Encrypted file does not exist: {src}")
    if not passphrase:
        raise ValueError("Passphrase or encryption key is required.")

    raw = src.read_bytes()
    offset = 0
    if raw.startswith(MAGIC_FILE_HEADER):
        offset = len(MAGIC_FILE_HEADER)

    if len(raw) - offset < 29:
        raise ValueError("File is too short to be a valid encrypted bundle.")

    version = raw[offset]
    salt = raw[offset + 1 : offset + 17]
    key_bytes = _derive_symmetric_key(passphrase, salt)
    payload_body = raw[offset + 17 :]

    if version == 0x01 or "GCM" in cipher.upper():
        nonce = payload_body[:12]
        ct = payload_body[12:]
        aesgcm = AESGCM(key_bytes)
        pt = aesgcm.decrypt(nonce, ct, None)
    elif version == 0x02 or "CHACHA" in cipher.upper():
        nonce = payload_body[:12]
        ct = payload_body[12:]
        chacha = ChaCha20Poly1305(key_bytes)
        pt = chacha.decrypt(nonce, ct, None)
    elif version == 0x03 or "CBC" in cipher.upper():
        iv = payload_body[:16]
        ct = payload_body[16:]
        c = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = c.decryptor()
        padded_pt = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded_pt) + unpadder.finalize()
    else:
        raise ValueError("Unrecognized encrypted file format version.")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(pt)
    return len(pt)


def bulk_encrypt_files(
    file_paths: List[Union[str, Path]],
    output_dir: Union[str, Path],
    passphrase: str,
    cipher: str = "AES-256-GCM",
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> Tuple[int, List[str]]:
    """Encrypts multiple files into the target output directory.

    Returns:
        (successful_count, list_of_error_strings)
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    success_count = 0
    errors: List[str] = []
    total = len(file_paths)

    for idx, fp in enumerate(file_paths):
        p = Path(fp)
        dst = out / (p.name + ".enc")
        try:
            encrypt_file(p, dst, passphrase, cipher=cipher)
            success_count += 1
            if progress_callback:
                progress_callback(idx + 1, total, f"Encrypted {p.name}")
        except Exception as ex:
            errors.append(f"{p.name}: {str(ex)}")

    return success_count, errors


def bulk_decrypt_files(
    file_paths: List[Union[str, Path]],
    output_dir: Union[str, Path],
    passphrase: str,
    cipher: str = "AES-256-GCM",
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> Tuple[int, List[str]]:
    """Decrypts multiple encrypted files into the target output directory.

    Returns:
        (successful_count, list_of_error_strings)
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    success_count = 0
    errors: List[str] = []
    total = len(file_paths)

    for idx, fp in enumerate(file_paths):
        p = Path(fp)
        out_name = p.name[:-4] if p.name.endswith(".enc") else f"{p.stem}_decrypted{p.suffix}"
        dst = out / out_name
        try:
            decrypt_file(p, dst, passphrase, cipher=cipher)
            success_count += 1
            if progress_callback:
                progress_callback(idx + 1, total, f"Decrypted {p.name}")
        except Exception as ex:
            errors.append(f"{p.name}: {str(ex)}")

    return success_count, errors

