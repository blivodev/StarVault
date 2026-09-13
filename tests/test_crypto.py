"""Unit tests for crypto module."""

import pytest
from starvault.crypto import (
    CryptoError,
    VaultSession,
    create_canary,
    decrypt_field,
    derive_key,
    encrypt_field,
    generate_salt,
    verify_canary,
)


def test_derive_key_and_salt():
    salt = generate_salt()
    assert len(salt) == 16

    key1 = derive_key("master-password-123", salt, time_cost=1, memory_cost=1024)
    assert len(key1) == 32

    # Deterministic with same password & salt
    key2 = derive_key("master-password-123", salt, time_cost=1, memory_cost=1024)
    assert key1 == key2

    # Different password produces different key
    key3 = derive_key("different-password", salt, time_cost=1, memory_cost=1024)
    assert key1 != key3


def test_encrypt_and_decrypt_field():
    salt = generate_salt()
    key = derive_key("test-key", salt, time_cost=1, memory_cost=1024)

    secret = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleRootKey root@server"
    encrypted = encrypt_field(secret, key)

    assert encrypted.startswith("v1:")
    assert encrypted != secret

    decrypted = decrypt_field(encrypted, key)
    assert decrypted == secret


def test_decrypt_invalid_key_fails():
    salt = generate_salt()
    key1 = derive_key("correct-key", salt, time_cost=1, memory_cost=1024)
    key2 = derive_key("wrong-key", salt, time_cost=1, memory_cost=1024)

    secret = "TopSecretApiToken12345"
    encrypted = encrypt_field(secret, key1)

    with pytest.raises(CryptoError):
        decrypt_field(encrypted, key2)


def test_canary_verification():
    salt = generate_salt()
    key = derive_key("vault-pass", salt, time_cost=1, memory_cost=1024)
    wrong_key = derive_key("wrong-pass", salt, time_cost=1, memory_cost=1024)

    nonce_hex, ciphertext_hex = create_canary(key)
    assert verify_canary(key, nonce_hex, ciphertext_hex) is True
    assert verify_canary(wrong_key, nonce_hex, ciphertext_hex) is False


def test_vault_session():
    session = VaultSession()
    assert not session.is_unlocked
    assert session.key is None

    fake_key = b"A" * 32
    session.unlock(fake_key)
    assert session.is_unlocked
    assert session.key == fake_key

    session.lock()
    assert not session.is_unlocked
    assert session.key is None
