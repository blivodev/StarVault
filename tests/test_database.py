"""Unit tests for SQLite database engine."""

import tempfile
from pathlib import Path
import pytest
from starvault.database import Database
from starvault.models import VaultEntry


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_vault.db"
    return Database(db_file)


def test_init_and_unlock(temp_db):
    assert not temp_db.is_initialized()

    key = temp_db.initialize_vault("SecretMasterPass123!")
    assert temp_db.is_initialized()
    assert len(key) == 32

    # Valid unlock
    success, unlocked_key = temp_db.unlock_vault("SecretMasterPass123!")
    assert success is True
    assert unlocked_key == key

    # Invalid unlock
    success, wrong_key = temp_db.unlock_vault("WrongPassword")
    assert success is False
    assert wrong_key is None


def test_entry_crud(temp_db):
    key = temp_db.initialize_vault("TestPassword123")

    server = VaultEntry.create_server(
        title="VPS-Prod-01",
        hostname="192.168.1.100",
        username="debian",
        password="SuperSecretPassword!",
        port=2222,
        tags=["vps1", "prod", "homelab"],
        notes="Main reverse proxy host.",
    )

    temp_db.save_entry(server, key)

    # Fetch entry
    fetched = temp_db.get_entry(server.id, key)
    assert fetched is not None
    assert fetched.title == "VPS-Prod-01"
    assert fetched.hostname == "192.168.1.100"
    assert fetched.password == "SuperSecretPassword!"
    assert fetched.port == 2222
    assert "vps1" in fetched.tags
    assert fetched.notes == "Main reverse proxy host."

    # Toggle favorite
    new_fav = temp_db.toggle_favorite(server.id)
    assert new_fav is True
    fetched = temp_db.get_entry(server.id, key)
    assert fetched.is_favorite is True

    # List entries
    all_entries = temp_db.get_all_entries(key)
    assert len(all_entries) == 1
    assert all_entries[0].id == server.id

    # Check tags
    tags = temp_db.get_all_tags()
    assert "vps1" in tags
    assert "prod" in tags

    # Delete entry
    temp_db.delete_entry(server.id)
    assert temp_db.get_entry(server.id, key) is None
    assert len(temp_db.get_all_entries(key)) == 0


def test_change_master_password(temp_db):
    old_key = temp_db.initialize_vault("OldPassword123")

    service = VaultEntry.create_service(
        title="Postgres DB",
        app_name="PostgreSQL",
        url="192.168.1.100",
        port=5432,
        username="postgres",
        password="DbPassword456!",
        tags=["database", "vps1"],
    )
    temp_db.save_entry(service, old_key)

    # Change password
    new_key = temp_db.change_master_password(old_key, "NewPassword789!")
    assert new_key != old_key

    # Old password should no longer work
    ok, _ = temp_db.unlock_vault("OldPassword123")
    assert not ok

    # New password should work
    ok, unlocked_new_key = temp_db.unlock_vault("NewPassword789!")
    assert ok
    assert unlocked_new_key == new_key

    # Decrypted entry should match
    fetched = temp_db.get_entry(service.id, new_key)
    assert fetched is not None
    assert fetched.password == "DbPassword456!"
