"""Tests for StarVault Advanced Features:

- Safe SQLite schema migration (parent_server_id & vault_files table)
- Relational Parent/Child sub-credentials
- Entry duplication
- Arbitrary custom key-value fields
- Vault Health Advisor security scanner
- Encrypted File Vault (BLOB storage & extraction)
- App Config & OS Credential Manager integration
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import pytest

from starvault.app_config import AppConfigManager
from starvault.crypto import derive_key, generate_salt
from starvault.database import Database
from starvault.health import VaultHealthAdvisor, calculate_entropy
from starvault.models import VaultEntry, VaultFile


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_advanced.db"
    db = Database(db_file)
    key = db.initialize_vault("StrongMasterPass123!")
    return db, key, tmp_path


def test_safe_schema_migration(tmp_path):
    """Verifies that an older StarVault database without parent_server_id or vault_files

    is safely migrated without data loss.
    """
    old_db_file = tmp_path / "legacy_v1.db"

    # 1. Create a raw legacy v1 database
    conn = sqlite3.connect(str(old_db_file))
    conn.executescript(
        """
        CREATE TABLE vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt_hex TEXT NOT NULL,
            canary_nonce_hex TEXT NOT NULL,
            canary_ciphertext_hex TEXT NOT NULL,
            kdf_params_json TEXT NOT NULL,
            settings_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE vault_entries (
            id TEXT PRIMARY KEY,
            entry_type TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            is_favorite INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT INTO vault_entries VALUES ('ent-1', 'server', 'Legacy Server', 'General', '[]', 0, '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', 'payload')"
    )
    conn.commit()
    conn.close()

    # 2. Open with the new Database class
    db = Database(old_db_file)

    # 3. Verify columns and tables
    with sqlite3.connect(str(old_db_file)) as c:
        cols = [r[1] for r in c.execute("PRAGMA table_info(vault_entries)").fetchall()]
        assert "parent_server_id" in cols

        # Check existing row was preserved intact
        row = c.execute("SELECT id, title, parent_server_id FROM vault_entries WHERE id = 'ent-1'").fetchone()
        assert row[0] == "ent-1"
        assert row[1] == "Legacy Server"
        assert row[2] is None

        # Check vault_files table exists
        file_table = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_files'").fetchone()
        assert file_table is not None


def test_parent_child_subcredentials(temp_db):
    """Tests strict Parent/Child relationships between Servers and hosted Services."""
    db, key, _ = temp_db

    # 1. Create parent server
    server = VaultEntry.create_server(
        title="Homelab Proxmox Node",
        hostname="192.168.1.100",
        username="root",
        password="RootPassword123!",
    )
    db.save_entry(server, key)

    # 2. Create two child services linked to this server
    svc1 = VaultEntry.create_service(
        title="Postgres Production",
        app_name="PostgreSQL",
        port=5432,
        username="postgres",
        password="PgPassword456!",
    )
    svc1.parent_server_id = server.id
    db.save_entry(svc1, key)

    svc2 = VaultEntry.create_service(
        title="Jellyfin Media",
        app_name="Jellyfin",
        port=8096,
        username="jellyfin_admin",
        password="JellyPassword789!",
    )
    svc2.parent_server_id = server.id
    db.save_entry(svc2, key)

    # 3. Create an unrelated standalone service
    unrelated = VaultEntry.create_service(
        title="Cloudflare DNS",
        app_name="Cloudflare",
        api_token="cf_token_xyz",
    )
    db.save_entry(unrelated, key)

    # 4. Query child services
    children = db.get_child_services(server.id, key)
    assert len(children) == 2
    child_titles = [c.title for c in children]
    assert "Postgres Production" in child_titles
    assert "Jellyfin Media" in child_titles
    assert "Cloudflare DNS" not in child_titles

    # Verify decrypted credentials on child
    pg_child = next(c for c in children if c.title == "Postgres Production")
    assert pg_child.username == "postgres"
    assert pg_child.password == "PgPassword456!"
    assert pg_child.parent_server_id == server.id


def test_entry_duplication(temp_db):
    """Tests cloning an entry with '- Copy' title suffix and independent attributes."""
    db, key, _ = temp_db

    original = VaultEntry.create_server(
        title="VPS-Web",
        hostname="vps.example.com",
        username="deploy",
        password="SecurePass999!",
        tags=["web", "production"],
    )
    original.custom_fields = [{"key": "Region", "value": "us-east-1"}]
    db.save_entry(original, key)

    cloned = db.duplicate_entry(original.id, key)
    assert cloned is not None
    assert cloned.id != original.id
    assert cloned.title == "VPS-Web - Copy"
    assert cloned.hostname == "vps.example.com"
    assert cloned.username == "deploy"
    assert cloned.password == "SecurePass999!"
    assert cloned.tags == ["web", "production"]
    assert cloned.custom_fields == [{"key": "Region", "value": "us-east-1"}]

    # Modifying clone must not affect original
    cloned.title = "VPS-Web-Clone"
    cloned.password = "NewPass111!"
    db.save_entry(cloned, key)

    reloaded_orig = db.get_entry(original.id, key)
    assert reloaded_orig.title == "VPS-Web"
    assert reloaded_orig.password == "SecurePass999!"


def test_custom_fields_encryption(temp_db):
    """Tests storing and retrieving arbitrary custom key-value pairs."""
    db, key, _ = temp_db

    entry = VaultEntry.create_server(
        title="Database Cluster",
        hostname="db.local",
    )
    entry.custom_fields = [
        {"key": "License Key", "value": "PRO-1234-ABCD"},
        {"key": "Expires", "value": "2027-12-31"},
        {"key": "Backup PIN", "value": "9876"},
    ]
    db.save_entry(entry, key)

    reloaded = db.get_entry(entry.id, key)
    assert len(reloaded.custom_fields) == 3
    keys_dict = {cf["key"]: cf["value"] for cf in reloaded.custom_fields}
    assert keys_dict["License Key"] == "PRO-1234-ABCD"
    assert keys_dict["Expires"] == "2027-12-31"
    assert keys_dict["Backup PIN"] == "9876"


def test_vault_health_advisor():
    """Tests the in-memory Vault Health Advisor detection rules."""
    advisor = VaultHealthAdvisor()

    # 1. Duplicate Passwords across different services
    e1 = VaultEntry.create_server(title="Server A", hostname="1.1.1.1", password="SharedPassword123!")
    e2 = VaultEntry.create_service(title="App B", app_name="AppB", password="SharedPassword123!")

    # 2. Weak Password
    e3 = VaultEntry.create_service(title="Weak Service", app_name="Weak", password="123")

    # 3. Accidental Duplicate Names
    e4 = VaultEntry.create_server(title="Production Gateway", hostname="10.0.0.1", password="UniquePass1!")
    e5 = VaultEntry.create_server(title="Production Gateway", hostname="10.0.0.2", password="UniquePass2!")

    # 4. Expired Key in custom field
    e6 = VaultEntry.create_service(title="Legacy API", app_name="API", password="UniquePass3!")
    e6.custom_fields = [{"key": "Expires", "value": "2020-01-01"}]

    # 5. Ancient Password (>365 days ago)
    past_date = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    e7 = VaultEntry.create_server(title="Stale VPS", hostname="10.0.0.5", password="OldPassword123!")
    e7.updated_at = past_date

    entries = [e1, e2, e3, e4, e5, e6, e7]
    report = advisor.analyze(entries)

    assert report.total_entries_analyzed == 7
    assert report.duplicate_passwords_count >= 2
    assert report.weak_passwords_count >= 1
    assert report.duplicate_names_count >= 1
    assert report.expiring_keys_count >= 1
    assert report.stale_passwords_count >= 1

    # Overall score should reflect penalties
    assert report.overall_score < 80
    assert report.grade in ("C", "D", "F")

    # Finding types
    issue_types = {iss.issue_type for iss in report.issues}
    assert "duplicate_password" in issue_types
    assert "weak_password" in issue_types
    assert "duplicate_name" in issue_types
    assert "expiring_key" in issue_types
    assert "stale_password" in issue_types


def test_encrypted_file_vault(temp_db):
    """Tests binary BLOB encryption, storage, metadata retrieval, and extraction."""
    db, key, _ = temp_db

    # Ingest a sample configuration file (e.g., SSH private key or docker-compose)
    sample_content = b"""version: '3.8'
services:
  vault:
    image: starvault:latest
    ports:
      - "8080:8080"
"""
    vfile = VaultFile(
        filename="docker-compose.yml",
        mime_type="application/x-yaml",
        tags=["docker", "prod"],
        notes="StarVault deployment config",
    )

    # 1. Save and Encrypt
    db.save_file(vfile, sample_content, key)

    # 2. List Files (Metadata only)
    all_files = db.get_all_files(key)
    assert len(all_files) == 1
    retrieved_meta = all_files[0]
    assert retrieved_meta.filename == "docker-compose.yml"
    assert retrieved_meta.file_size == len(sample_content)
    assert retrieved_meta.mime_type == "application/x-yaml"
    assert retrieved_meta.tags == ["docker", "prod"]
    assert retrieved_meta.notes == "StarVault deployment config"

    # 3. Read & Decrypt BLOB
    decrypted_bytes = db.read_file_bytes(retrieved_meta.id, key)
    assert decrypted_bytes == sample_content

    # 4. Verify raw DB storage is encrypted (does not contain plaintext)
    with sqlite3.connect(str(db.db_path)) as conn:
        raw_blob = conn.execute("SELECT encrypted_blob FROM vault_files WHERE id = ?", (retrieved_meta.id,)).fetchone()[0]
        assert b"services:" not in raw_blob
        assert b"starvault:latest" not in raw_blob

    # 5. Delete file
    db.delete_file(retrieved_meta.id)
    assert len(db.get_all_files(key)) == 0
    assert db.read_file_bytes(retrieved_meta.id, key) is None


def test_app_config_and_recent_vaults(tmp_path):
    """Tests local unencrypted config tracking of recent vaults and last opened path."""
    cfg_file = tmp_path / "starvault_config.json"
    cfg = AppConfigManager(config_path=cfg_file)

    p1 = tmp_path / "vault1.db"
    p2 = tmp_path / "vault2.db"
    p1.touch()
    p2.touch()

    cfg.record_opened_vault(p1)
    assert cfg.get_last_vault_path() == p1.resolve()

    cfg.record_opened_vault(p2)
    assert cfg.get_last_vault_path() == p2.resolve()

    recents = cfg.get_recent_vaults()
    assert len(recents) == 2
    assert recents[0] == p2.resolve()
    assert recents[1] == p1.resolve()
