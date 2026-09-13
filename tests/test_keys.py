"""Unit tests for Key Studio key generation and format export."""

import pytest
from starvault.keys import (
    compute_openssh_fingerprint,
    generate_ed25519_key,
    generate_gpg_key,
    generate_rsa_key,
)


def test_ed25519_generation_and_export():
    res = generate_ed25519_key(comment="admin@vps1")
    assert res.key_type == "ed25519"
    assert "ssh-ed25519" in res.public_key
    assert "admin@vps1" in res.public_key
    assert "BEGIN OPENSSH PRIVATE KEY" in res.private_key
    assert res.fingerprint.startswith("SHA256:")
    assert "PuTTY-User-Key-File-2: ssh-ed25519" in res.putty_ppk
    assert "Private-MAC:" in res.putty_ppk


def test_rsa_generation_and_export():
    # Use 2048 for faster test execution
    res = generate_rsa_key(bits=2048, comment="admin@rsa")
    assert res.key_type == "rsa4096"
    assert "ssh-rsa" in res.public_key
    assert "BEGIN OPENSSH PRIVATE KEY" in res.private_key
    assert res.fingerprint.startswith("SHA256:")
    assert "PuTTY-User-Key-File-2: ssh-rsa" in res.putty_ppk
    assert "Private-MAC:" in res.putty_ppk


def test_gpg_generation_and_export():
    res = generate_gpg_key(name="Homelab Root", email="root@homelab.local", bits=2048)
    assert res.key_type == "gpg"
    assert "BEGIN PGP PUBLIC KEY BLOCK" in res.public_key
    assert "BEGIN PGP PRIVATE KEY BLOCK" in res.private_key
    assert len(res.fingerprint) > 20
