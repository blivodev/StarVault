"""Cryptographic core for StarVault.

Provides Argon2id key derivation, AES-256-GCM field encryption/decryption,
canary verification, and secure in-memory key lifecycle management.
"""

import base64
import os
from typing import Optional, Tuple
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starvault.config import (
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CANARY_PLAINTEXT,
)


class CryptoError(Exception):
    """Raised when encryption or decryption fails."""
    pass


class InvalidMasterPasswordError(CryptoError):
    """Raised when master password fails canary verification."""
    pass


def generate_salt(length: int = 16) -> bytes:
    """Generates cryptographically strong random salt bytes."""
    return os.urandom(length)


def derive_key(
    password: str,
    salt: bytes,
    keyfile_secret: Optional[str] = None,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
    hash_len: int = ARGON2_HASH_LEN,
) -> bytes:
    """Derives a 256-bit AES encryption key using Argon2id.

    ==========================================================================
    ELI5 AUDIT NOTE: TRUE LOCAL 2FA COMPOSITE KEY DERIVATION
    ==========================================================================
    What is happening here?
    1. Standard password vaults only use a Master Password. If someone watches
       you type it or keylogs your keyboard, your vault is compromised.
    2. StarVault True Local 2FA combines "Something You Know" (Master Password)
       with "Something You Have" (a unique 256-bit offline QR Code Keyfile).
    3. We bind them together using a cryptographic separator:
          password_bytes + b"::STARVAULT-2FA::" + keyfile_token_bytes
       Both parts are required! Even if an attacker has your database and master
       password, they mathematically cannot derive the key without the QR image.
    4. If keyfile_secret is None, it gracefully runs in Legacy v1 mode.
    5. The combined secret is hashed through Argon2id (64MB memory, 3 passes),
       making brute-force cracking computationally impossible.
    ==========================================================================
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    # ELI5: Fusing password and 2FA keyfile token
    if keyfile_secret and keyfile_secret.strip():
        secret_bytes = (
            password.encode("utf-8")
            + b"::STARVAULT-2FA::"
            + keyfile_secret.strip().encode("utf-8")
        )
    else:
        # Legacy v1 single-factor mode
        secret_bytes = password.encode("utf-8")

    return hash_secret_raw(
        secret=secret_bytes,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )


def encrypt_field(plaintext: str, key: bytes) -> str:
    """Encrypts plaintext string with AES-256-GCM using a 12-byte random nonce.

    Returns:
        v1-prefixed base64 string containing: nonce (12 bytes) + ciphertext + tag (16 bytes).
    """
    if plaintext is None:
        plaintext = ""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = nonce + ciphertext
    return "v1:" + base64.b64encode(payload).decode("ascii")


def decrypt_field(payload: str, key: bytes) -> str:
    """Decrypts a v1 payload string with AES-256-GCM.

    Returns:
        Decrypted plaintext string.
    """
    if not payload:
        return ""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")

    if payload.startswith("v1:"):
        payload = payload[3:]

    try:
        raw = base64.b64decode(payload)
        if len(raw) < 12 + 16:  # 12-byte nonce + 16-byte tag minimum
            raise CryptoError("Payload is malformed or truncated.")

        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except InvalidTag as e:
        raise CryptoError("Decryption failed: integrity tag mismatch.") from e
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"Decryption error: {str(e)}") from e


def encrypt_blob(data: bytes, key: bytes) -> bytes:
    """Encrypts raw binary data with AES-256-GCM.

    Returns:
        bytes containing: nonce (12 bytes) + ciphertext + tag (16 bytes).
    """
    if data is None:
        data = b""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_blob(payload: bytes, key: bytes) -> bytes:
    """Decrypts raw binary payload with AES-256-GCM.

    Returns:
        Decrypted raw binary bytes.
    """
    if not payload:
        return b""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")
    if len(payload) < 12 + 16:
        raise CryptoError("Encrypted blob payload is malformed or truncated.")

    try:
        nonce = payload[:12]
        ciphertext = payload[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as e:
        raise CryptoError("Blob decryption failed: integrity tag mismatch.") from e
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"Blob decryption error: {str(e)}") from e


def create_canary(key: bytes) -> Tuple[str, str]:
    """Creates an encrypted canary token to verify master password.

    Returns:
        Tuple of (nonce_hex, ciphertext_hex).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, CANARY_PLAINTEXT, None)
    return nonce.hex(), ciphertext.hex()


def verify_canary(key: bytes, nonce_hex: str, ciphertext_hex: str) -> bool:
    """Verifies that key can decrypt the canary token successfully."""
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted == CANARY_PLAINTEXT
    except Exception:
        return False


class VaultSession:
    """Manages active vault encryption key in memory with explicit wipe."""

    def __init__(self) -> None:
        self._key: Optional[bytearray] = None

    def unlock(self, key: bytes) -> None:
        """Stores derived key in a mutable bytearray."""
        self.lock()  # Clear existing key if any
        self._key = bytearray(key)

    @property
    def key(self) -> Optional[bytes]:
        """Returns immutable bytes copy of the active key, or None if locked."""
        if self._key is None:
            return None
        return bytes(self._key)

    @property
    def is_unlocked(self) -> bool:
        """Checks if vault session is unlocked."""
        return self._key is not None and len(self._key) == 32

    def lock(self) -> None:
        """Securely zeroes in-memory key bytes and clears session."""
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._key = None

    def __del__(self) -> None:
        self.lock()
