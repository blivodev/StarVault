"""Tests for StarVault Chrome/Brave/Edge Extension Bridge API endpoints."""

import json
import urllib.request
import pytest
from starvault.database import Database
from starvault.extension_bridge import ExtensionBridgeServer
from starvault.models import VaultEntry


@pytest.fixture
def test_bridge(tmp_path):
    db_file = tmp_path / "test_bridge.db"
    db = Database(db_file)
    master_pass = "TestMaster123!"
    key = db.initialize_vault(master_pass)

    # Seed some entries
    e1 = VaultEntry.create_server(
        title="VPS 10 - Worker",
        hostname="worker-10.internal",
        username="deploy",
        password="WeakPassword",
        category="Cloud & Infrastructure",
    )
    db.save_entry(e1, key)

    e2 = VaultEntry.create_server(
        title="VPS 2 - DB",
        hostname="10.0.0.2",
        username="postgres",
        password="SuperStrongPassword!987",
        category="Databases & Storage",
    )
    e2.is_favorite = True
    db.save_entry(e2, key)

    e3 = VaultEntry.create_service(
        title="Postgres Web",
        app_name="Postgres Web",
        url="https://db.internal",
        username="admin",
        password="AnotherWeakPass",
        category="Databases & Storage",
    )
    db.save_entry(e3, key)

    # Pick an ephemeral test port
    port = 18088
    bridge = ExtensionBridgeServer(
        database=db,
        get_session_key=lambda: key,
        port=port,
    )
    bridge.start()

    yield {
        "bridge": bridge,
        "db": db,
        "key": key,
        "port": port,
        "master_pass": master_pass,
    }

    bridge.stop()


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
    except urllib.error.HTTPError as err:
        data = json.loads(err.read().decode("utf-8"))
        return err.code, data


def test_bridge_search_sorting_and_filtering(test_bridge):
    port = test_bridge["port"]
    url = f"http://127.0.0.1:{port}/api/search"

    # 1. Natural sorting with server filter: "VPS 2 - DB" should precede "VPS 10 - Worker"
    code, data = _post_json(url, {"query": "VPS", "filter_type": "server", "sort_by": "natural"})
    assert code == 200
    titles = [m["title"] for m in data["matches"]]
    assert titles == ["VPS 2 - DB", "VPS 10 - Worker"]

    # 2. Filter by type: server
    code, data = _post_json(url, {"query": "", "filter_type": "server"})
    assert code == 200
    for m in data["matches"]:
        assert m["type"] == "server"

    # 3. Filter by weak passwords (< 12 chars)
    code, data = _post_json(url, {"query": "", "filter_status": "weak"})
    assert code == 200
    for m in data["matches"]:
        assert m["is_weak"] is True


def test_bridge_key_generation(test_bridge):
    port = test_bridge["port"]
    url = f"http://127.0.0.1:{port}/api/generate_key"

    # Generate Ed25519 SSH key
    code, data = _post_json(url, {"type": "ed25519", "comment": "test@ext", "save_to_vault": True})
    assert code == 200
    assert data["success"] is True
    assert "ssh-ed25519" in data["public_key"]
    assert data["saved_id"] is not None

    # Generate TLS certificate
    code, data = _post_json(url, {"type": "tls_cert", "common_name": "api.test.local", "save_to_vault": False})
    assert code == 200
    assert data["success"] is True
    assert "BEGIN CERTIFICATE" in data["public_key"]
    assert "PRIVATE KEY" in data["private_key"]


def test_bridge_export_csv_master_password(test_bridge):
    port = test_bridge["port"]
    url = f"http://127.0.0.1:{port}/api/export_csv"

    # Wrong password
    code, data = _post_json(url, {"master_password": "WrongPassword!"})
    assert code == 401
    assert data["success"] is False

    # Correct password
    code, data = _post_json(url, {"master_password": test_bridge["master_pass"]})
    assert code == 200
    assert data["success"] is True
    assert "Title,Type,Category" in data["csv"]
    assert data["count"] >= 3


def test_bridge_toggle_favorite(test_bridge):
    port = test_bridge["port"]
    db = test_bridge["db"]
    key = test_bridge["key"]
    entries = db.get_all_entries(key)
    target = entries[0]
    initial_fav = target.is_favorite

    url = f"http://127.0.0.1:{port}/api/toggle_favorite"
    code, data = _post_json(url, {"entry_id": target.id})
    assert code == 200
    assert data["success"] is True
    assert data["is_favorite"] is not initial_fav


def test_bridge_versioning_endpoints(test_bridge):
    port = test_bridge["port"]
    db = test_bridge["db"]
    key = test_bridge["key"]
    entries = db.get_all_entries(key)
    target = entries[0]

    orig_pwd = target.password
    target.password = "NewRotatedPasswordFromBridge!"
    db.save_entry(target, key)

    # 1. Query versions via bridge
    url_v = f"http://127.0.0.1:{port}/api/entry_versions"
    code, data = _post_json(url_v, {"entry_id": target.id, "decrypt": True})
    assert code == 200
    assert data["count"] == 2
    assert len(data["versions"]) == 2
    v1_id = [v["id"] for v in data["versions"] if v["version_num"] == 1][0]

    # 2. Restore version via bridge
    url_r = f"http://127.0.0.1:{port}/api/restore_version"
    code, data_r = _post_json(url_r, {"entry_id": target.id, "version_id": v1_id})
    assert code == 200
    assert data_r["success"] is True

    # Check live entry in db
    live = db.get_entry(target.id, key)
    assert live.password == orig_pwd

    # 3. Clean versions via bridge
    url_c = f"http://127.0.0.1:{port}/api/clean_versions"
    code, data_c = _post_json(url_c, {"max_versions_per_entry": 1, "dry_run": False})
    assert code == 200
    assert data_c["success"] is True
    assert data_c["result"]["versions_deleted"] >= 1


def test_bridge_import_vault_endpoint(test_bridge):
    port = test_bridge["port"]
    url = f"http://127.0.0.1:{port}/api/import_vault"

    # Test importing a JSON export payload via bridge
    sample_json = json.dumps({
        "entries": [
            {
                "id": "ext-imported-1",
                "title": "Imported via Extension Bridge",
                "entry_type": "service",
                "username": "bridge_user",
                "password": "BridgePassword123!",
                "url": "https://bridge.test.local",
            }
        ]
    })

    code, data = _post_json(url, {
        "filename": "bridge_export.json",
        "content_text": sample_json,
        "collision_strategy": "skip",
    })
    assert code == 200
    assert data["success"] is True
    assert data["count"] >= 1

    # Verify entry is present in database
    db = test_bridge["db"]
    key = test_bridge["key"]
    entries = db.get_all_entries(key)
    titles = [e.title for e in entries]
    assert "Imported via Extension Bridge" in titles

