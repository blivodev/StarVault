"""Comprehensive test suite for Domain & URL Management feature in StarVault."""

import json
import os
from pathlib import Path
import pytest

from starvault.database import Database
from starvault.models import VaultEntry
from starvault.quick_strings import generate_dig_command, generate_whois_command
from starvault.search import search_entries
from starvault.health import VaultHealthAdvisor
from starvault.organizer import find_ghost_and_stale, merge_entries, purge_ghost_entries
from starvault.versioning import detect_change_summary, snapshot_entry_data, apply_version_to_entry
from starvault.mcp_server import StarVaultMCPServer


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_domain_vault.db"
    return Database(db_file)


def test_domain_model_creation_and_duplication():
    domain = VaultEntry.create_domain(
        title="My Primary Tech Domain",
        domain_name="starvault-hub.io",
        registrar="Cloudflare Registrar",
        expires_at="2027-05-15",
        auto_renew=True,
        dns_provider="Cloudflare DNS",
        nameservers="ns1.cloudflare.com\nns2.cloudflare.com",
        auth_code="EPP-SEC-998877",
        tags=["prod", "tech"],
        notes="Primary production domain for StarVault APIs.",
    )

    assert domain.entry_type == "domain"
    assert domain.category == "Domains"
    assert domain.domain_name == "starvault-hub.io"
    assert domain.url == "https://starvault-hub.io"
    assert domain.registrar == "Cloudflare Registrar"
    assert domain.expires_at == "2027-05-15"
    assert domain.auto_renew is True
    assert domain.dns_provider == "Cloudflare DNS"
    assert "ns1.cloudflare.com" in domain.nameservers
    assert domain.auth_code == "EPP-SEC-998877"

    # Duplication
    dup = domain.duplicate()
    assert dup.id != domain.id
    assert dup.title == f"{domain.title} - Copy"
    assert dup.domain_name == "starvault-hub.io"
    assert dup.registrar == "Cloudflare Registrar"
    assert dup.auth_code == "EPP-SEC-998877"
    assert dup.auto_renew is True


def test_domain_encryption_payload_roundtrip():
    key = os.urandom(32)
    domain = VaultEntry.create_domain(
        title="App Domain",
        domain_name="app.example.com",
        registrar="Namecheap",
        expires_at="2026-12-31",
        auto_renew=False,
        dns_provider="AWS Route53",
        nameservers="ns-1.awsdns.com",
        auth_code="SECRET_AUTH_CODE_XYZ",
    )
    domain.parent_domain_id = "parent-root-uuid"

    # Export encrypted payload with key
    payload = domain.to_encrypted_payload(key)
    assert isinstance(payload, str)
    # Auth code must be encrypted and not present as plaintext
    assert "SECRET_AUTH_CODE_XYZ" not in payload

    # Restore into fresh entry with key
    restored = VaultEntry(title="Blank", entry_type="domain")
    restored.load_encrypted_payload(payload, key)

    assert restored.domain_name == "app.example.com"
    assert restored.registrar == "Namecheap"
    assert restored.auto_renew is False
    assert restored.dns_provider == "AWS Route53"
    assert restored.auth_code == "SECRET_AUTH_CODE_XYZ"
    assert restored.parent_domain_id == "parent-root-uuid"


def test_database_domain_crud_and_relational_hierarchy(temp_db):
    key = temp_db.initialize_vault("MasterDomainPass123!")

    # 1. Create and Save Parent Domain
    domain = VaultEntry.create_domain(
        title="Production Domain",
        domain_name="production.net",
        registrar="Porkbun",
        expires_at="2028-01-01",
        auto_renew=True,
        auth_code="TRANSFER-CODE-1234",
    )
    temp_db.save_entry(domain, key)

    fetched_domain = temp_db.get_entry(domain.id, key)
    assert fetched_domain is not None
    assert fetched_domain.entry_type == "domain"
    assert fetched_domain.domain_name == "production.net"
    assert fetched_domain.registrar == "Porkbun"
    assert fetched_domain.auth_code == "TRANSFER-CODE-1234"
    assert fetched_domain.auto_renew is True

    # 2. Attach Child Server, Service, and API Key to Domain
    server = VaultEntry.create_server(
        title="Prod Web Node 1",
        hostname="node1.production.net",
        username="admin",
        password="NodePassword123!",
    )
    server.parent_domain_id = domain.id
    temp_db.save_entry(server, key)

    service = VaultEntry.create_service(
        title="Prod API Gateway",
        app_name="Gateway",
        url="https://api.production.net",
        username="api_user",
        password="ServicePass456!",
    )
    service.parent_domain_id = domain.id
    temp_db.save_entry(service, key)

    apikey = VaultEntry.create_api_key(
        title="Stripe Webhook Key",
        provider="Stripe",
        api_token="whsec_1234567890abcdef",
    )
    apikey.parent_domain_id = domain.id
    temp_db.save_entry(apikey, key)

    # 3. Query Attached Entries via get_child_entries_by_domain
    children = temp_db.get_child_entries_by_domain(domain.id, key)
    assert len(children) == 3
    child_ids = {c.id for c in children}
    assert server.id in child_ids
    assert service.id in child_ids
    assert apikey.id in child_ids

    # Unattached item should not be in children
    other_srv = VaultEntry.create_server(title="Standalone", hostname="10.0.0.1", username="root")
    temp_db.save_entry(other_srv, key)
    assert other_srv.id not in {c.id for c in temp_db.get_child_entries_by_domain(domain.id, key)}


def test_domain_search_indexing():
    entries = [
        VaultEntry.create_domain(
            title="Nexus Portal",
            domain_name="nexusportal.io",
            registrar="Namecheap",
            dns_provider="Cloudflare",
        ),
        VaultEntry.create_domain(
            title="Alpha VPS Network",
            domain_name="alphanet.org",
            registrar="GoDaddy",
            dns_provider="Route53",
        ),
        VaultEntry.create_server(
            title="Database Host",
            hostname="db.internal.lan",
            username="postgres",
        ),
    ]

    # Search by domain name
    results = search_entries(entries, query="nexusportal")
    assert len(results) >= 1
    assert results[0][0].domain_name == "nexusportal.io"

    # Search by registrar
    results = search_entries(entries, query="GoDaddy")
    assert len(results) >= 1
    assert results[0][0].domain_name == "alphanet.org"

    # Search by DNS provider
    results = search_entries(entries, query="Route53")
    assert len(results) >= 1
    assert results[0][0].domain_name == "alphanet.org"

    # Filter by Domains category
    results = search_entries(entries, query="", selected_category="Domains")
    assert len(results) == 2
    assert all(e.entry_type == "domain" for e, score in results)


def test_domain_health_advisor_expiration():
    advisor = VaultHealthAdvisor()

    # Expired domain
    expired_domain = VaultEntry.create_domain(
        title="Old Blog",
        domain_name="oldblog.com",
        registrar="Namecheap",
        expires_at="2020-01-01",
        auto_renew=False,
    )

    # Expiring domain (within 30 days)
    from datetime import datetime, timezone, timedelta
    soon_date = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%d")
    expiring_domain = VaultEntry.create_domain(
        title="Active Store",
        domain_name="mystore.com",
        registrar="Porkbun",
        expires_at=soon_date,
        auto_renew=False,
    )

    # Future domain (> 1 year)
    future_domain = VaultEntry.create_domain(
        title="Secure App",
        domain_name="secureapp.io",
        registrar="Cloudflare",
        expires_at="2030-01-01",
        auto_renew=True,
    )

    report = advisor.analyze([expired_domain, expiring_domain, future_domain])
    issue_msgs = [f"{i.title} {i.description}" for i in report.issues]

    # Should flag expired domain
    assert any("Old Blog" in m and "expired" in m for m in issue_msgs)
    # Should flag expiring domain
    assert any("Active Store" in m and "expires" in m for m in issue_msgs)
    # Future domain should not be flagged as expiring
    assert not any("secureapp.io" in m for m in issue_msgs)


def test_domain_versioning_and_snapshotting():
    old_domain = VaultEntry.create_domain(
        title="Legacy URL",
        domain_name="legacy.com",
        registrar="OldReg",
        expires_at="2026-06-01",
        auto_renew=False,
        dns_provider="ProviderA",
        auth_code="CODE1",
    )

    new_domain = old_domain.duplicate()
    new_domain.id = old_domain.id
    new_domain.registrar = "NewReg"
    new_domain.expires_at = "2028-06-01"
    new_domain.auto_renew = True
    new_domain.dns_provider = "Cloudflare"
    new_domain.auth_code = "NEWCODE"

    old_snap = snapshot_entry_data(old_domain)
    summary = detect_change_summary(old_snap, new_domain)
    assert "Updated registrar" in summary
    assert "Updated expiry date" in summary
    assert "Toggled auto-renew" in summary
    assert "Updated DNS provider" in summary
    assert "Updated transfer auth code" in summary

    # Snapshot and apply
    snap = snapshot_entry_data(new_domain)
    assert snap["domain_name"] == "legacy.com"
    assert snap["registrar"] == "NewReg"
    assert snap["auth_code"] == "NEWCODE"

    target = VaultEntry.create_domain(title="Blank", domain_name="none")
    apply_version_to_entry(target, snap)
    assert target.domain_name == "legacy.com"
    assert target.registrar == "NewReg"
    assert target.auto_renew is True
    assert target.auth_code == "NEWCODE"


def test_organizer_orphan_and_deduplication(temp_db):
    key = temp_db.initialize_vault("OrganizerPass123!")

    # 1. Deduplication merge
    d1 = VaultEntry.create_domain(
        title="Duplicate Domain",
        domain_name="dup.com",
        registrar="Namecheap",
        expires_at="",
    )
    d2 = VaultEntry.create_domain(
        title="Duplicate Domain",
        domain_name="dup.com",
        registrar="",
        expires_at="2029-01-01",
        auto_renew=True,
    )
    merged = merge_entries(d1, d2)
    assert merged.domain_name == "dup.com"
    assert merged.registrar == "Namecheap"
    assert merged.expires_at == "2029-01-01"
    assert merged.auto_renew is True

    # 2. Orphan detection & purge
    srv = VaultEntry.create_server(
        title="Orphaned Child",
        hostname="orphan.local",
        username="admin",
        password="Pass123!",
    )
    srv.parent_domain_id = "non-existent-domain-uuid"
    temp_db.save_entry(srv, key)

    findings = find_ghost_and_stale([srv])
    assert len(findings["orphans"]) == 1
    assert findings["orphans"][0].id == srv.id

    # Purge/cleanup resets parent_domain_id in database
    res = purge_ghost_entries(temp_db, key)
    assert res["fixed_orphans"] == 1

    reloaded = temp_db.get_entry(srv.id, key)
    assert reloaded.parent_domain_id is None


def test_quick_strings_commands():
    domain_entry = VaultEntry.create_domain(
        title="My Web App",
        domain_name="app.starvault.dev",
        registrar="Cloudflare",
    )
    whois_cmd = generate_whois_command(domain_entry)
    assert whois_cmd == "whois app.starvault.dev"

    dig_cmd = generate_dig_command(domain_entry, "MX")
    assert "dig +nocmd app.starvault.dev MX" in dig_cmd


def test_mcp_server_domain_tools(tmp_path):
    db_file = tmp_path / "mcp_domain_test.db"
    server = StarVaultMCPServer(db_file)
    master_key = server.db.initialize_vault("McpSecretPass!")

    # Unlock server
    server.execute_tool("starvault_unlock", {"master_password": "McpSecretPass!"})

    # Add domain entry
    add_resp = server.execute_tool("starvault_add_entry", {
        "title": "Cloudflare Domain",
        "entry_type": "domain",
        "domain_name": "mcp-test-domain.org",
        "registrar": "Cloudflare",
        "expires_at": "2028-11-20",
        "auto_renew": True,
        "auth_code": "EPP-MCP-KEY-999",
    })
    assert "Successfully created domain entry" in add_resp

    # Get entry metadata
    get_resp = json.loads(server.execute_tool("starvault_get_entry", {"identifier": "Cloudflare Domain"}))
    assert get_resp["type"] == "domain"
    assert get_resp["domain_name"] == "mcp-test-domain.org"
    assert get_resp["registrar"] == "Cloudflare"
    assert get_resp["auto_renew"] is True

    # Retrieve sensitive auth_code secret
    sec_resp = json.loads(server.execute_tool("starvault_get_secret", {
        "identifier": "Cloudflare Domain",
        "secret_type": "auth_code",
    }))
    assert sec_resp["secret_value"] == "EPP-MCP-KEY-999"

    # Attach child service via update_entry
    dom_id = get_resp["id"]
    server.execute_tool("starvault_add_entry", {
        "title": "API Backend",
        "entry_type": "service",
        "hostname_or_url": "https://api.mcp-test-domain.org",
    })
    server.execute_tool("starvault_update_entry", {
        "identifier": "API Backend",
        "parent_domain_id": dom_id,
    })

    child_entry = json.loads(server.execute_tool("starvault_get_entry", {"identifier": "API Backend"}))
    assert child_entry["parent_domain_id"] == dom_id


def test_domain_csv_export_and_import_roundtrip(temp_db, tmp_path):
    key = temp_db.initialize_vault("CsvPass123!")

    dom = VaultEntry.create_domain(
        title="CSV Domain Test",
        domain_name="csvtest.dev",
        registrar="Porkbun",
        expires_at="2029-05-01",
        auto_renew=True,
        dns_provider="Cloudflare",
        nameservers="ns1.cloudflare.com",
        auth_code="EPP-CSV-999",
    )
    temp_db.save_entry(dom, key)

    from starvault.export_utils import export_entries_to_csv_string
    from starvault.export_package import _import_csv_text

    csv_data = export_entries_to_csv_string([dom])
    assert "csvtest.dev" in csv_data
    assert "Porkbun" in csv_data
    assert "EPP-CSV-999" in csv_data

    # Import into another database
    db2 = Database(tmp_path / "imported_csv.db")
    key2 = db2.initialize_vault("CsvPass123!")
    results = {"imported_credentials": 0, "skipped_credentials": 0}
    _import_csv_text(csv_data, db2, key2, {}, "copy", results)

    entries = db2.get_all_entries(key2)
    assert len(entries) == 1
    imported_dom = entries[0]
    assert imported_dom.domain_name == "csvtest.dev"
    assert imported_dom.registrar == "Porkbun"
    assert imported_dom.expires_at == "2029-05-01"
    assert imported_dom.auto_renew is True
    assert imported_dom.auth_code == "EPP-CSV-999"

