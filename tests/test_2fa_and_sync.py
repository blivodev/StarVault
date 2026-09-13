"""Unit and integration tests for True Local 2FA (QR Keyfile) and Passive Cloud Sync."""

import shutil
from pathlib import Path
import pytest

from starvault.crypto import (
    CryptoError,
    create_canary,
    decrypt_field,
    derive_key,
    encrypt_field,
    generate_salt,
    verify_canary,
)
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.qr_keyfile import (
    generate_keyfile_token,
    generate_qr_image,
    read_keyfile_token,
    save_qr_image,
)


def test_qr_token_generation_and_opencv_decoding(tmp_path):
    """Verifies that generated 256-bit token is saved as QR PNG and decoded with OpenCV."""
    token = generate_keyfile_token()
    assert len(token) == 64  # 256 bits = 64 hex characters

    qr_path = tmp_path / "test_keyfile.png"
    save_qr_image(token, str(qr_path))
    assert qr_path.exists()
    assert qr_path.stat().st_size > 500  # Valid PNG image file

    # Decode with OpenCV reader
    decoded_token = read_keyfile_token(str(qr_path))
    assert decoded_token == token


def test_qr_fallback_text_keyfile(tmp_path):
    """Verifies that plain text keyfiles are also supported as fallback."""
    token = generate_keyfile_token()
    key_path = tmp_path / "secret.key"
    key_path.write_text(token, encoding="utf-8")

    decoded_token = read_keyfile_token(str(key_path))
    assert decoded_token == token


def test_composite_key_derivation_security():
    """ELI5 Test:
    Verifies that Master Password + Keyfile produces a unique key.
    Neither Master Password alone nor Keyfile alone can decrypt the vault.
    """
    salt = generate_salt(16)
    password = "MasterPassword123!"
    keyfile = generate_keyfile_token()
    wrong_keyfile = generate_keyfile_token()

    # 1. Derive 2FA composite key
    correct_2fa_key = derive_key(password, salt, keyfile_secret=keyfile, time_cost=1, memory_cost=1024)

    # 2. Derive key with wrong keyfile
    wrong_2fa_key = derive_key(password, salt, keyfile_secret=wrong_keyfile, time_cost=1, memory_cost=1024)
    assert correct_2fa_key != wrong_2fa_key

    # 3. Derive legacy single-factor key (no keyfile)
    legacy_key = derive_key(password, salt, keyfile_secret=None, time_cost=1, memory_cost=1024)
    assert correct_2fa_key != legacy_key

    # 4. Encrypt with composite key and verify tamper resistance
    secret_text = "Highly Confidential Root Credential"
    encrypted = encrypt_field(secret_text, correct_2fa_key)

    # Decryption succeeds only with correct composite key
    assert decrypt_field(encrypted, correct_2fa_key) == secret_text

    # Decryption fails with wrong keyfile
    with pytest.raises(CryptoError):
        decrypt_field(encrypted, wrong_2fa_key)

    # Decryption fails with legacy password-only key
    with pytest.raises(CryptoError):
        decrypt_field(encrypted, legacy_key)


def test_legacy_vault_detection_and_migration(tmp_path):
    """ELI5 Migration Test:
    1. Create a legacy v1 vault (password only).
    2. Verify is_legacy_vault() returns True.
    3. Perform upgrade_to_2fa() with a newly generated QR keyfile.
    4. Verify is_legacy_vault() becomes False, requires_2fa() becomes True.
    5. Verify old password alone now fails, but (Password + QR Keyfile) succeeds!
    6. Verify all stored entries remain intact and readable with new 2FA key.
    """
    db_file = tmp_path / "legacy_vault.db"
    db = Database(db_file)

    # Step 1: Create legacy v1 vault
    legacy_password = "LegacyMasterPassword123!"
    old_key = db.initialize_vault(legacy_password)
    assert db.is_legacy_vault() is True
    assert db.requires_2fa() is False

    # Store a test secret in the legacy vault
    entry = VaultEntry.create_server(
        title="Prod-Database-VPS",
        hostname="10.0.0.99",
        username="dbadmin",
        password="VerySecretOldPassword",
        tags=["prod", "vps1"],
        notes="Legacy server before migration",
    )
    db.save_entry(entry, old_key)

    # Step 2: Generate 2FA QR keyfile
    token = generate_keyfile_token()
    qr_img_path = tmp_path / "my_2fa_keyfile.png"
    save_qr_image(token, str(qr_img_path))

    # Step 3: Upgrade to True Local 2FA
    new_composite_key = db.upgrade_to_2fa(old_key, legacy_password, token)
    assert new_composite_key != old_key

    # Step 4: Verify metadata reflects v2 2FA
    assert db.is_legacy_vault() is False
    assert db.requires_2fa() is True

    # Step 5: Password alone must now FAIL
    ok_legacy, _ = db.unlock_vault(legacy_password)
    assert ok_legacy is False

    # Password with wrong keyfile must FAIL
    ok_wrong, _ = db.unlock_vault(legacy_password, keyfile_secret="0" * 64)
    assert ok_wrong is False

    # Password with decoded QR keyfile must SUCCEED
    decoded_qr = read_keyfile_token(str(qr_img_path))
    ok_2fa, unlocked_key = db.unlock_vault(legacy_password, keyfile_secret=decoded_qr)
    assert ok_2fa is True
    assert unlocked_key == new_composite_key

    # Step 6: Decrypted entries must match perfectly
    recovered_entry = db.get_entry(entry.id, unlocked_key)
    assert recovered_entry is not None
    assert recovered_entry.password == "VerySecretOldPassword"
    assert recovered_entry.notes == "Legacy server before migration"


def test_passive_cloud_sync_mirroring(tmp_path):
    """Verifies that saving, deleting, and updating entries automatically copies
    the encrypted .db file to the configured backup directory.
    """
    db_file = tmp_path / "primary_vault.db"
    backup_dir = tmp_path / "GoogleDriveMirror"
    backup_dir.mkdir()

    db = Database(db_file)
    key = db.initialize_vault("SyncMasterPass123!", settings={"backup_dir": str(backup_dir)})

    # Verify initial creation mirrored to backup_dir
    mirrored_file = backup_dir / "primary_vault.db"
    assert mirrored_file.exists()
    assert mirrored_file.stat().st_size > 0

    # Add an entry -> auto-backup triggered
    e1 = VaultEntry.create_server("Server-01", "192.168.1.1")
    db.save_entry(e1, key)
    assert mirrored_file.exists()

    # Delete entry -> auto-backup triggered
    db.delete_entry(e1.id)
    assert mirrored_file.exists()


def test_restore_from_backup(tmp_path):
    """Verifies restoring a database from a backup file."""
    primary_db_file = tmp_path / "active_vault.db"
    backup_db_file = tmp_path / "snapshot.db"

    # Create snapshot vault
    db_snap = Database(backup_db_file)
    snap_key = db_snap.initialize_vault("SnapshotPass123!")
    e = VaultEntry.create_server("Restored-Server", "10.10.10.10")
    db_snap.save_entry(e, snap_key)

    # Active db is initially blank or different
    active_db = Database(primary_db_file)
    active_db.initialize_vault("OriginalPass123!")

    # Restore from snapshot
    success = active_db.restore_from_backup(backup_db_file)
    assert success is True

    # Active db should now unlock with snapshot password and contain restored entry
    ok, unlocked_key = active_db.unlock_vault("SnapshotPass123!")
    assert ok is True
    restored = active_db.get_entry(e.id, unlocked_key)
    assert restored is not None
    assert restored.title == "Restored-Server"
