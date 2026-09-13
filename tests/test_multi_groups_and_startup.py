"""Comprehensive tests for multi-group & multi-service assignment and startup configuration."""

import json
import urllib.request
import pytest
from starvault.database import Database
from starvault.export_utils import export_entries_to_csv_string
from starvault.extension_bridge import ExtensionBridgeServer
from starvault.mcp_server import StarVaultMCPServer
from starvault.models import VaultEntry
from starvault.search import search_entries
from starvault.startup import is_startup_enabled, set_startup_enabled, _get_launch_command


def test_vault_entry_multi_groups_and_services():
    # 1. Fallback initialization
    e1 = VaultEntry.create_server(
        title="Edge Router",
        hostname="router.internal",
        category="Networking",
        username="admin",
    )
    assert e1.groups == ["Networking"]
    assert e1.services == []
    assert e1.get_groups_display() == "Networking"
    assert e1.get_services_display() == ""

    # 2. Multi-group and multi-service assignment
    e1.set_groups_from_str("Core-Infra, Gateway, Production")
    e1.set_services_from_str("SSH, BGP-Daemon, WireGuard")
    assert e1.groups == ["Core-Infra", "Gateway", "Production"]
    assert e1.services == ["SSH", "BGP-Daemon", "WireGuard"]
    assert e1.get_groups_display() == "Core-Infra, Gateway, Production"
    assert e1.get_services_display() == "SSH, BGP-Daemon, WireGuard"

    # 3. Encrypted payload roundtrip
    key = b"\x01" * 32
    payload = e1.to_encrypted_payload(key)
    assert payload != ""

    e2 = VaultEntry(title="Blank", entry_type="server")
    e2.load_encrypted_payload(payload, key)
    assert e2.groups == ["Core-Infra", "Gateway", "Production"]
    assert e2.services == ["SSH", "BGP-Daemon", "WireGuard"]

    # 4. Duplicate cloning
    cloned = e1.duplicate()
    assert cloned.id != e1.id
    assert cloned.groups == ["Core-Infra", "Gateway", "Production"]
    assert cloned.services == ["SSH", "BGP-Daemon", "WireGuard"]


def test_database_multi_groups_persistence(tmp_path):
    db_file = tmp_path / "multi_groups.db"
    db = Database(db_file)
    key = db.initialize_vault("MasterPass123!")

    e = VaultEntry.create_service(
        title="Multi-Cloud Auth",
        app_name="Keycloak",
        url="https://auth.example.com",
        username="superuser",
        password="ComplexSecretPassword!99",
        category="Security & Identity",
        groups=["DevOps", "Identity", "Zero-Trust"],
        services=["Keycloak", "OIDC-Provider", "SAML-Bridge"],
    )
    db.save_entry(e, key)

    # Fetch entry and verify decrypted fields and unencrypted columns
    loaded = db.get_entry(e.id, key)
    assert loaded is not None
    assert loaded.groups == ["DevOps", "Identity", "Zero-Trust"]
    assert loaded.services == ["Keycloak", "OIDC-Provider", "SAML-Bridge"]

    # Update entry with new groups and services
    loaded.groups.append("Compliance")
    loaded.services.append("Audit-Log")
    db.save_entry(loaded, key)

    reloaded = db.get_entry(e.id, key)
    assert "Compliance" in reloaded.groups
    assert "Audit-Log" in reloaded.services


def test_search_and_csv_multi_groups(tmp_path):
    e1 = VaultEntry.create_server(
        title="Primary DB",
        hostname="db.corp",
        category="Databases",
        groups=["Cluster-Alpha", "High-Priority"],
        services=["PostgreSQL-Primary", "Prometheus-Exporter"],
    )
    e2 = VaultEntry.create_service(
        title="Replica DB",
        app_name="Postgres Replica",
        category="Databases",
        groups=["Cluster-Beta", "Read-Only"],
        services=["PostgreSQL-Replica"],
    )

    # 1. Search matching by secondary group
    matches = search_entries([e1, e2], query="High-Priority")
    assert len(matches) == 1
    assert matches[0][0].title == "Primary DB"

    # 2. Search matching by secondary service
    matches_srv = search_entries([e1, e2], query="Prometheus-Exporter")
    assert len(matches_srv) == 1
    assert matches_srv[0][0].title == "Primary DB"

    # 3. CSV export containing Groups and Services
    csv_str = export_entries_to_csv_string([e1, e2])
    assert "Groups" in csv_str
    assert "Services" in csv_str
    assert "Cluster-Alpha, High-Priority" in csv_str
    assert "PostgreSQL-Primary, Prometheus-Exporter" in csv_str


def test_mcp_server_multi_groups_and_update(tmp_path):
    db_file = tmp_path / "mcp_groups.db"
    server = StarVaultMCPServer(db_file)
    master_pass = "TestMcpPass!123"
    server.db.initialize_vault(master_pass)

    # Unlock server
    resp = server.execute_tool("starvault_unlock", {"master_password": master_pass})
    assert "Successfully unlocked" in resp

    # Add entry with multiple groups and services
    add_resp = server.execute_tool("starvault_add_entry", {
        "title": "Kube Master",
        "entry_type": "server",
        "category": "Kubernetes",
        "groups": ["Control-Plane", "Production", "US-East"],
        "services": ["Kube-API", "Etcd-Leader"],
        "hostname_or_url": "k8s.internal",
    })
    assert "Successfully created" in add_resp

    # List groups tool
    list_groups_resp = json.loads(server.execute_tool("starvault_list_groups", {}))
    assert "groups" in list_groups_resp
    assert "services" in list_groups_resp
    group_names = [g["group"] for g in list_groups_resp["groups"]]
    service_names = [s["service"] for s in list_groups_resp["services"]]
    assert "Control-Plane" in group_names
    assert "Etcd-Leader" in service_names

    # Update entry tool
    up_resp = server.execute_tool("starvault_update_entry", {
        "identifier": "Kube Master",
        "groups": ["Control-Plane", "Production", "US-East", "DR-Failover"],
        "services": ["Kube-API", "Etcd-Leader", "CoreDNS"],
    })
    assert "Successfully updated" in up_resp

    # Verify updated entry
    get_resp = json.loads(server.execute_tool("starvault_get_entry", {"identifier": "Kube Master"}))
    assert "DR-Failover" in get_resp["groups"]
    assert "CoreDNS" in get_resp["services"]


def test_extension_bridge_multi_groups(tmp_path):
    db_file = tmp_path / "bridge_groups.db"
    db = Database(db_file)
    master_pass = "ExtPass!123"
    key = db.initialize_vault(master_pass)

    port = 18099
    bridge = ExtensionBridgeServer(
        database=db,
        get_session_key=lambda: key,
        port=port,
    )
    bridge.start()

    try:
        # Save new login with multiple groups and services
        url_save = f"http://127.0.0.1:{port}/api/save_entry"
        payload_save = {
            "title": "GitLab Self-Hosted",
            "url": "https://gitlab.internal",
            "username": "developer",
            "password": "SecurePassword123!",
            "category": "Dev & Repositories",
            "groups": ["Engineering", "CI-CD"],
            "services": ["GitLab-Web", "GitLab-Registry"],
        }
        req = urllib.request.Request(
            url_save,
            data=json.dumps(payload_save).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 201
            entry_id = data["id"]

        # Search credentials - verify groups and services are present in result
        url_search = f"http://127.0.0.1:{port}/api/search"
        req_search = urllib.request.Request(
            url_search,
            data=json.dumps({"query": "GitLab"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_search) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert len(data["matches"]) >= 1
            match = data["matches"][0]
            assert "Engineering" in match["groups"]
            assert "GitLab-Registry" in match["services"]

        # Get credentials
        url_get = f"http://127.0.0.1:{port}/api/get_credentials"
        req_get = urllib.request.Request(
            url_get,
            data=json.dumps({"entry_id": entry_id}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_get) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert "Engineering" in data["groups"]
            assert "GitLab-Registry" in data["services"]
    finally:
        bridge.stop()


def test_startup_launch_command_verification():
    # Verify launch command construction includes --minimized
    cmd = _get_launch_command()
    assert "--minimized" in cmd
