"""Tests for StarVault Credential Version Control and Retention Lifecycle."""

import json
from pathlib import Path
import tempfile
import time
from typing import Generator
import pytest

from starvault.config import get_default_keys_dir
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.versioning import (
    CleanVersionsResult,
    VaultEntryVersion,
    apply_version_to_entry,
    compute_secret_fingerprint,
    delete_physical_key_files,
    detect_change_summary,
    find_stale_physical_key_files,
    parse_retention_days,
    save_keypair_to_physical_files,
    snapshot_entry_data,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    db_path = tmp_path / "test_starvault.db"
    return Database(db_path)


@pytest.fixture
def unlocked_db(temp_db: Database) -> tuple[Database, bytes]:
    pwd = "MasterTestPassword123!"
    key = temp_db.initialize_vault(pwd)
    assert key is not None
    return temp_db, key


def test_parse_retention_days():
    assert parse_retention_days(30, "days") == 30
    assert parse_retention_days(1, "day") == 1
    assert parse_retention_days(3, "months") == 90
    assert parse_retention_days(1, "month") == 30
    assert parse_retention_days(1, "year") == 365
    assert parse_retention_days(2, "years") == 730


def test_fingerprint_and_change_summary():
    entry = VaultEntry.create_server(
        title="Prod Server",
        hostname="10.0.0.1",
        username="admin",
        password="InitialPassword123!",
    )
    fp1 = compute_secret_fingerprint(entry)
    summary1 = detect_change_summary(None, entry)
    assert "Initial credential version" in summary1

    # Non-sensitive change: tags only
    snap1 = snapshot_entry_data(entry)
    entry.tags = ["production", "aws"]
    fp2 = compute_secret_fingerprint(entry)
    # Tags are not part of core secret fingerprint
    assert fp1 == fp2

    # Sensitive change: rotate password
    entry.password = "NewRotatedPassword456!"
    fp3 = compute_secret_fingerprint(entry)
    assert fp1 != fp3

    summary2 = detect_change_summary(snap1, entry)
    assert "Rotated password" in summary2


def test_database_version_lifecycle(unlocked_db: tuple[Database, bytes]):
    db, key = unlocked_db

    # 1. Create new entry
    entry = VaultEntry.create_server(
        title="Database Server",
        hostname="db.internal",
        username="postgres",
        password="SecretPasswordV1",
        notes="Primary database cluster",
    )
    db.save_entry(entry, key)

    versions = db.get_entry_versions(entry.id, key=key, decrypt=True)
    assert len(versions) == 1
    assert versions[0].version_num == 1
    assert "Initial" in versions[0].change_summary
    assert versions[0].decrypted_data["password"] == "SecretPasswordV1"

    # 2. Saving identical secret does not create duplicate version
    entry.tags = ["updated-tag"]
    db.save_entry(entry, key)
    versions_after_tag = db.get_entry_versions(entry.id)
    assert len(versions_after_tag) == 1

    # 3. Rotate password -> records Version 2
    entry.password = "SecretPasswordV2"
    db.save_entry(entry, key)

    versions = db.get_entry_versions(entry.id, key=key, decrypt=True)
    assert len(versions) == 2
    assert versions[0].version_num == 2
    assert "Rotated password" in versions[0].change_summary
    assert versions[0].decrypted_data["password"] == "SecretPasswordV2"
    assert versions[1].version_num == 1
    assert versions[1].decrypted_data["password"] == "SecretPasswordV1"

    # 4. Rotate sudo password and notes -> records Version 3
    entry.sudo_password = "SudoRootPassword999!"
    entry.notes = "Upgraded to PostgreSQL 17"
    db.save_entry(entry, key)

    versions = db.get_entry_versions(entry.id, key=key, decrypt=True)
    assert len(versions) == 3
    assert versions[0].version_num == 3

    # 5. Rollback to Version 1
    v1 = [v for v in versions if v.version_num == 1][0]
    restored = db.restore_entry_version(entry.id, v1.id, key)
    assert restored is not None
    assert restored.password == "SecretPasswordV1"

    # Check that pre-rollback snapshot and restored versions exist
    all_versions = db.get_entry_versions(entry.id, key=key, decrypt=True)
    assert len(all_versions) >= 4
    # Live entry in database now has password from v1
    live = db.get_entry(entry.id, key)
    assert live.password == "SecretPasswordV1"


def test_physical_key_files_and_deletion(unlocked_db: tuple[Database, bytes], tmp_path: Path):
    db, key = unlocked_db
    target_dir = tmp_path / "keys_test"
    entry = VaultEntry.create_keypair(
        title="Deploy-SSH-Key",
        key_name="id_ed25519_deploy",
        key_type="ed25519",
        public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneratedPubKey deploy@starvault",
        private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nbXlfc2VjcmV0X2tleQ==\n-----END OPENSSH PRIVATE KEY-----",
        fingerprint="SHA256:abc123mockfingerprint",
    )

    # Generate physical files
    files = save_keypair_to_physical_files(entry, target_dir=target_dir)
    assert len(files) == 2
    for f in files:
        assert Path(f).is_file()

    # Save entry linking associated files
    db.save_entry(entry, key, associated_files=files)

    versions = db.get_entry_versions(entry.id, key=key, decrypt=True)
    assert len(versions) == 1
    assert len(versions[0].associated_files) == 2

    # Delete physical files
    del_count, deleted_paths = delete_physical_key_files(files)
    assert del_count == 2
    for f in files:
        assert not Path(f).exists()


def test_clean_old_versions_pruning(unlocked_db: tuple[Database, bytes]):
    db, key = unlocked_db

    entry = VaultEntry.create_api_key(
        title="Stripe Payment API",
        provider="Stripe",
        api_token="sk_live_initial111",
    )
    db.save_entry(entry, key)

    # Create 4 versions
    for i in range(2, 6):
        entry.api_token = f"sk_live_token_{i}"
        db.save_entry(entry, key)

    versions = db.get_entry_versions(entry.id)
    assert len(versions) == 5

    # Dry run keeping only newest 2 versions
    dry_result = db.clean_old_versions(max_versions_per_entry=2, dry_run=True)
    assert dry_result.dry_run is True
    assert dry_result.versions_deleted == 3
    assert len(db.get_entry_versions(entry.id)) == 5  # Unchanged in dry run

    # Actual prune keeping newest 2 versions
    prune_result = db.clean_old_versions(max_versions_per_entry=2, dry_run=False)
    assert prune_result.dry_run is False
    assert prune_result.versions_deleted == 3

    remaining = db.get_entry_versions(entry.id)
    assert len(remaining) == 2
    assert [v.version_num for v in remaining] == [5, 4]


def test_reencrypt_versions_on_password_change(unlocked_db: tuple[Database, bytes]):
    db, old_key = unlocked_db

    entry = VaultEntry.create_server(
        title="Web Server",
        hostname="web1.starvault.internal",
        username="ubuntu",
        password="MyOldWebPassword123!",
    )
    db.save_entry(entry, old_key)

    entry.password = "MyRotatedWebPassword456!"
    db.save_entry(entry, old_key)

    versions = db.get_entry_versions(entry.id, key=old_key, decrypt=True)
    assert len(versions) == 2
    assert versions[0].decrypted_data["password"] == "MyRotatedWebPassword456!"

    # Change master password
    new_password = "BrandNewMasterPassword999!"
    new_key = db.change_master_password(old_key, new_password)
    assert new_key != old_key

    # Retrieve and decrypt versions with new key
    versions_new = db.get_entry_versions(entry.id, key=new_key, decrypt=True)
    assert len(versions_new) == 2
    assert versions_new[0].decrypted_data["password"] == "MyRotatedWebPassword456!"
    assert versions_new[1].decrypted_data["password"] == "MyOldWebPassword123!"


def test_mcp_server_versioning_tools(unlocked_db: tuple[Database, bytes]):
    from starvault.mcp_server import StarVaultMCPServer
    db, key = unlocked_db

    entry = VaultEntry.create_service(
        title="Redis Cache",
        app_name="Redis",
        password="RedisAuthPasswordV1",
    )
    db.save_entry(entry, key)

    entry.password = "RedisAuthPasswordV2"
    db.save_entry(entry, key)

    # Initialize MCP server
    server = StarVaultMCPServer(db_path=db.db_path)
    # Unlock MCP session
    server.execute_tool("starvault_unlock", {"master_password": "MasterTestPassword123!"})

    # 1. Query versions tool
    res_str = server.execute_tool("starvault_get_entry_versions", {"identifier": "Redis Cache", "decrypt": True})
    res = json.loads(res_str)
    assert res["success"] is True
    assert res["total_versions"] == 2
    v1_id = [v["id"] for v in res["versions"] if v["version_num"] == 1][0]

    # 2. Rollback version tool
    res_roll_str = server.execute_tool("starvault_restore_entry_version", {"identifier": "Redis Cache", "version_id": v1_id})
    res_roll = json.loads(res_roll_str)
    assert res_roll["success"] is True

    # 3. Retention clean tool
    res_clean_str = server.execute_tool("starvault_clean_old_versions", {"max_versions_per_entry": 1, "dry_run": False})
    res_clean = json.loads(res_clean_str)
    assert res_clean["success"] is True
    assert res_clean["result"]["versions_deleted"] >= 1


def test_delete_entry_cleans_versions_and_keys(unlocked_db: tuple[Database, bytes], tmp_path: Path):
    db, key = unlocked_db
    target_dir = tmp_path / "keys_del"
    entry = VaultEntry.create_keypair(
        title="Orphaned Keypair",
        key_name="test_key",
        key_type="rsa",
        public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3Mock",
        private_key="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA3M==\n-----END RSA PRIVATE KEY-----",
    )
    files = save_keypair_to_physical_files(entry, target_dir=target_dir)
    db.save_entry(entry, key, associated_files=files)

    assert len(db.get_entry_versions(entry.id)) == 1
    for f in files:
        assert Path(f).is_file()

    # Delete entry and cascade physical files
    db.delete_entry(entry.id, delete_physical_files=True)
    assert db.get_entry(entry.id, key) is None
    assert len(db.get_entry_versions(entry.id)) == 0
    for f in files:
        assert not Path(f).exists()
