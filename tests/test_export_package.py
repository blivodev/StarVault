"""Tests for StarVault Encrypted Export & Universal Import Engine (.sve, .zip, .csv)."""

from pathlib import Path
import pytest

from starvault.crypto import derive_key, generate_salt
from starvault.database import Database
from starvault.export_package import (
    create_encrypted_vault_package,
    execute_vault_import,
    export_vault_archive_zip,
    inspect_import_file,
    read_encrypted_vault_package,
)
from starvault.models import VaultEntry, VaultFile


@pytest.fixture
def test_vault(tmp_path):
    """Creates a temporary initialized database with master password and session key."""
    db_path = tmp_path / "test_export_vault.db"
    db = Database(db_path)
    master_pwd = "VaultMasterP@ss1"
    session_key = db.initialize_vault(master_pwd)
    assert session_key is not None

    # Add credentials
    e1 = VaultEntry(
        title="Production Server",
        entry_type="server",
        hostname="10.0.0.1",
        username="root",
        password="RootSuperSecretPassword!",
        tags=["prod", "vps"],
    )
    db.save_entry(e1, session_key, change_summary="Initial server")

    # Add keypair
    kp = VaultEntry.create_keypair(
        title="Work SSH Ed25519",
        key_name="work_key",
        key_type="ed25519",
        public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneratedTestKey work@local",
        private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nFakePrivKey\n-----END OPENSSH PRIVATE KEY-----",
        fingerprint="SHA256:testfingerprint1234567890",
        tags=["ssh", "work"],
    )
    db.save_entry(kp, session_key, change_summary="Initial keypair")

    # Add file
    test_content = b"SERVER_HOST=10.0.0.1\nPORT=5432\nDB_PASS=vault_secret"
    vf = VaultFile(filename="env_prod.conf", mime_type="text/plain", file_size=len(test_content))
    db.save_file(vf, test_content, session_key)

    # Modify e1 to create a version snapshot
    e1.password = "RootUpdatedSecret2026!"
    db.save_entry(e1, session_key, change_summary="Password rotation")

    return db, session_key, master_pwd


def test_create_and_read_encrypted_vault_package(test_vault, tmp_path):
    """Verifies that .sve container creates and decrypts properly with correct passphrase."""
    db, session_key, _ = test_vault
    export_file = tmp_path / "backup.sve"
    export_passphrase = "ExportSecretPass123!"

    ok, msg, summary = create_encrypted_vault_package(
        database=db,
        session_key=session_key,
        export_passphrase=export_passphrase,
        target_path=export_file,
        include_credentials=True,
        include_keys=True,
        include_files=True,
        include_versions=True,
    )
    assert ok is True
    assert export_file.is_file()
    assert summary["credentials_count"] >= 1
    assert summary["keys_count"] >= 1
    assert summary["files_count"] >= 1
    assert summary["versions_count"] >= 1

    # Raw bytes check magic header
    raw = export_file.read_bytes()
    assert raw[:4] == b"STV1"

    # Decrypt and read container
    read_ok, read_msg, pkg = read_encrypted_vault_package(export_file, export_passphrase)
    assert read_ok is True
    assert pkg is not None
    assert pkg["format"] == "starvault_encrypted_export"
    assert len(pkg["entries"]) >= 2
    assert len(pkg["files"]) >= 1
    assert len(pkg["versions"]) >= 1


def test_read_encrypted_vault_package_wrong_passphrase(test_vault, tmp_path):
    """Verifies that wrong passphrase fails decryption gracefully with invalid tag error."""
    db, session_key, _ = test_vault
    export_file = tmp_path / "backup_wrong_pwd.sve"
    export_passphrase = "CorrectPassword123!"

    ok, _, _ = create_encrypted_vault_package(
        database=db,
        session_key=session_key,
        export_passphrase=export_passphrase,
        target_path=export_file,
    )
    assert ok is True

    # Attempt with incorrect passphrase
    bad_ok, bad_msg, pkg = read_encrypted_vault_package(export_file, "WrongPassword999!")
    assert bad_ok is False
    assert pkg is None
    assert "Incorrect export passphrase" in bad_msg


def test_inspect_import_file_sve(test_vault, tmp_path):
    """Tests preview inspection of .sve packages with and without passphrase."""
    db, session_key, _ = test_vault
    export_file = tmp_path / "inspect_test.sve"
    pwd = "InspectSecret123!"

    create_encrypted_vault_package(db, session_key, pwd, export_file)

    # Without passphrase -> NEEDS_PASSPHRASE
    ok1, msg1, meta1 = inspect_import_file(export_file, passphrase=None)
    assert ok1 is False
    assert msg1 == "NEEDS_PASSPHRASE"
    assert meta1["file_type"] == "encrypted_package"

    # With passphrase -> returns full preview counts
    ok2, msg2, meta2 = inspect_import_file(export_file, passphrase=pwd)
    assert ok2 is True
    assert meta2["credentials_count"] >= 1
    assert meta2["keys_count"] >= 1
    assert meta2["files_count"] >= 1


def test_execute_vault_import_into_fresh_vault(test_vault, tmp_path):
    """Tests importing .sve export package into a completely fresh second StarVault database."""
    source_db, source_key, _ = test_vault
    export_file = tmp_path / "full_export.sve"
    pwd = "ExportMasterKey123!"

    ok, _, _ = create_encrypted_vault_package(source_db, source_key, pwd, export_file)
    assert ok is True

    # Create destination fresh vault
    dest_db_path = tmp_path / "dest_fresh_vault.db"
    dest_db = Database(dest_db_path)
    dest_key = dest_db.initialize_vault("DestMasterPassword456!")
    assert dest_key is not None

    # Inspect export file
    insp_ok, _, meta = inspect_import_file(export_file, passphrase=pwd)
    assert insp_ok is True

    # Execute import
    imp_ok, imp_msg, summary = execute_vault_import(
        database=dest_db,
        session_key=dest_key,
        import_metadata=meta,
        conflict_strategy="skip",
    )
    assert imp_ok is True
    assert summary["imported_credentials"] >= 1
    assert summary["imported_keys"] >= 1
    assert summary["imported_files"] >= 1

    # Verify destination vault now has decrypted entries and files
    dest_entries = dest_db.get_all_entries(dest_key)
    titles = [e.title for e in dest_entries]
    assert "Production Server" in titles
    assert "Work SSH Ed25519" in titles

    # Verify files restored
    dest_files = dest_db.get_all_files(dest_key)
    assert any(f.filename == "env_prod.conf" for f in dest_files)


def test_execute_vault_import_conflict_strategies(test_vault, tmp_path):
    """Tests conflict resolution strategies: skip, overwrite, and copy."""
    source_db, source_key, _ = test_vault
    export_file = tmp_path / "conflict_export.sve"
    pwd = "ExportPassword123!"

    create_encrypted_vault_package(source_db, source_key, pwd, export_file)
    _, _, meta = inspect_import_file(export_file, passphrase=pwd)

    # 1. Test strategy="skip" on same database (entries already exist)
    ok_skip, _, sum_skip = execute_vault_import(source_db, source_key, meta, conflict_strategy="skip")
    assert ok_skip is True
    assert sum_skip["skipped_credentials"] >= 1

    # 2. Test strategy="copy"
    ok_copy, _, sum_copy = execute_vault_import(source_db, source_key, meta, conflict_strategy="copy")
    assert ok_copy is True
    assert sum_copy["imported_credentials"] >= 1
    all_entries = source_db.get_all_entries(source_key)
    titles = [e.title for e in all_entries]
    assert any("(Imported)" in t for t in titles)


def test_export_vault_archive_zip(test_vault, tmp_path):
    """Tests creating and inspecting a .zip archive export."""
    db, session_key, _ = test_vault
    zip_path = tmp_path / "archive_export.zip"

    ok, msg, summary = export_vault_archive_zip(
        database=db,
        session_key=session_key,
        target_path=zip_path,
        include_csv=True,
        include_keys=True,
        include_files=True,
    )
    assert ok is True
    assert zip_path.is_file()
    assert summary["credentials_count"] >= 1

    # Inspect zip archive
    insp_ok, _, meta = inspect_import_file(zip_path)
    assert insp_ok is True
    assert meta["file_type"] == "zip_archive"
    assert meta["credentials_count"] >= 1


def test_inspect_and_import_database_backup(test_vault, tmp_path):
    """Tests inspecting and merging records from a saved SQLite .db file into another vault."""
    source_db, source_key, pwd = test_vault

    # Source db path
    src_db_file = source_db.db_path

    # Without passphrase -> NEEDS_PASSPHRASE
    ok1, msg1, meta1 = inspect_import_file(src_db_file, passphrase=None)
    assert ok1 is False
    assert msg1 == "NEEDS_PASSPHRASE"
    assert meta1["file_type"] == "database"
    assert meta1["credentials_count"] >= 1

    # With correct passphrase
    ok2, msg2, meta2 = inspect_import_file(src_db_file, passphrase=pwd)
    assert ok2 is True
    assert meta2["file_type"] == "database"
    assert meta2["credentials_count"] >= 1
    assert "derived_key" in meta2

    # Create destination fresh vault
    dest_db_path = tmp_path / "dest_imported_vault.db"
    dest_db = Database(dest_db_path)
    dest_key = dest_db.initialize_vault("DestSecret999!")

    # Import from source db into destination vault
    imp_ok, imp_msg, summary = execute_vault_import(
        database=dest_db,
        session_key=dest_key,
        import_metadata=meta2,
        file_path=src_db_file,
    )
    assert imp_ok is True
    assert summary["imported_credentials"] >= 1
    dest_entries = dest_db.get_all_entries(dest_key)
    assert len(dest_entries) >= 1


def test_inspect_and_import_json_export(tmp_path):
    """Tests inspecting and importing a JSON vault export file."""
    import json
    json_path = tmp_path / "sample_export.json"
    sample_data = {
        "entries": [
            {
                "id": "item-1",
                "title": "JSON Imported Server",
                "entry_type": "server",
                "username": "root",
                "password": "SecureServerPassword123!",
                "hostname": "192.168.1.50",
            },
            {
                "id": "item-2",
                "title": "JSON Imported API Key",
                "entry_type": "apikey",
                "api_token": "sk-1234567890abcdef",
            },
        ]
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sample_data, f)

    ok, msg, meta = inspect_import_file(json_path)
    assert ok is True
    assert meta["file_type"] == "json"
    assert meta["credentials_count"] == 2

    # Import into target vault
    dest_db_path = tmp_path / "json_dest_vault.db"
    dest_db = Database(dest_db_path)
    dest_key = dest_db.initialize_vault("DestSecret999!")

    imp_ok, imp_msg, summary = execute_vault_import(
        database=dest_db,
        session_key=dest_key,
        import_metadata=meta,
        file_path=json_path,
    )
    assert imp_ok is True
    assert summary["imported_credentials"] == 2
    entries = dest_db.get_all_entries(dest_key)
    titles = [e.title for e in entries]
    assert "JSON Imported Server" in titles
