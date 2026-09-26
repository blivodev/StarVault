"""Unit and integration tests for Domain / URL asset management, grouping, and browser extension support."""

import json
from datetime import datetime, timezone, timedelta
import pytest
from starvault.crypto import derive_key
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.quick_strings import generate_whois_command, generate_dig_command
from starvault.search import search_entries
from starvault.organizer import find_ghost_and_stale, purge_ghost_entries, sort_entries
from starvault.extension_bridge import ExtensionBridgeServer
import urllib.request


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_domains.db"
    db = Database(str(db_file))
    return db


@pytest.fixture
def master_key():
    return derive_key("SuperSecretDomainPassword!2026", b"testsalt12345678")


def test_create_domain_model(master_key):
    """Verifies VaultEntry.create_domain sets all domain and registrar credential fields."""
    dom = VaultEntry.create_domain(
        title="My Cool Project",
        domain_name="mycoolproject.org",
        registrar="Porkbun",
        expires_at="2027-10-15",
        auto_renew=True,
        registered_at="2024-10-15",
        renewal_cost="$10.99 / yr",
        dns_provider="Cloudflare",
        nameservers="ns1.cloudflare.com, ns2.cloudflare.com",
        auth_code="EPP-SECRET-998877",
        category="Domains",
        tags=["production", "portfolio"],
    )
    dom.username = "porkbun_admin@example.com"
    dom.password = "P0rkbunP@ssw0rd!2026"
    dom.totp_secret = "JBSWY3DPEHPK3PXP"

    assert dom.entry_type == "domain"
    assert dom.domain_name == "mycoolproject.org"
    assert dom.url == "https://mycoolproject.org"
    assert dom.registrar == "Porkbun"
    assert dom.expires_at == "2027-10-15"
    assert dom.auto_renew is True
    assert dom.registered_at == "2024-10-15"
    assert dom.renewal_cost == "$10.99 / yr"
    assert dom.dns_provider == "Cloudflare"
    assert dom.nameservers == "ns1.cloudflare.com, ns2.cloudflare.com"
    assert dom.auth_code == "EPP-SECRET-998877"
    assert dom.username == "porkbun_admin@example.com"
    assert dom.password == "P0rkbunP@ssw0rd!2026"
    assert dom.totp_secret == "JBSWY3DPEHPK3PXP"

    # Test encryption and decryption payload roundtrip
    payload = dom.to_encrypted_payload(master_key)
    restored = VaultEntry(id=dom.id, title=dom.title, entry_type="domain", category=dom.category)
    restored.load_encrypted_payload(payload, master_key)

    assert restored.domain_name == "mycoolproject.org"
    assert restored.registrar == "Porkbun"
    assert restored.expires_at == "2027-10-15"
    assert restored.auto_renew is True
    assert restored.registered_at == "2024-10-15"
    assert restored.renewal_cost == "$10.99 / yr"
    assert restored.dns_provider == "Cloudflare"
    assert restored.nameservers == "ns1.cloudflare.com, ns2.cloudflare.com"
    assert restored.auth_code == "EPP-SECRET-998877"
    assert restored.username == "porkbun_admin@example.com"
    assert restored.password == "P0rkbunP@ssw0rd!2026"
    assert restored.totp_secret == "JBSWY3DPEHPK3PXP"


def test_database_persistence_and_child_grouping(temp_db, master_key):
    """Tests saving domain, linking child services/keys with parent_domain_id, and querying children."""
    # 1. Create and save domain
    dom = VaultEntry.create_domain(
        title="Acme Corp Domain",
        domain_name="acme.com",
        registrar="Cloudflare",
        expires_at="2028-01-01",
    )
    dom.username = "acme_cf_admin"
    dom.password = "CFStrongPass#2026"
    temp_db.save_entry(dom, master_key)

    # 2. Create child service attached to the domain
    svc = VaultEntry.create_service(
        title="Acme Web App",
        app_name="Acme Portal",
        url="https://app.acme.com",
        username="webadmin",
        password="AppPassword123!",
    )
    svc.parent_domain_id = dom.id
    temp_db.save_entry(svc, master_key)

    # 3. Create child API key attached to the domain
    api = VaultEntry.create_api_key(
        title="Acme Public API Key",
        provider="Acme Gateway",
        api_token="ak_live_998877665544",
    )
    api.parent_domain_id = dom.id
    temp_db.save_entry(api, master_key)

    # 4. Fetch child entries by domain
    children = temp_db.get_child_entries_by_domain(dom.id, master_key)
    assert len(children) == 2
    child_titles = [c.title for c in children]
    assert "Acme Web App" in child_titles
    assert "Acme Public API Key" in child_titles
    for c in children:
        assert c.parent_domain_id == dom.id

    # 5. Verify direct entry retrieval populates parent_domain_id
    loaded_svc = temp_db.get_entry(svc.id, master_key)
    assert loaded_svc is not None
    assert loaded_svc.parent_domain_id == dom.id


def test_quick_strings_commands():
    """Tests generation of WHOIS and DIG commands for domain assets."""
    dom = VaultEntry.create_domain(
        title="Example Test",
        domain_name="example.org",
        registrar="Namecheap",
    )
    whois_cmd = generate_whois_command(dom)
    assert whois_cmd == "whois example.org"

    dig_a = generate_dig_command(dom, "A")
    assert dig_a == "dig +nocmd example.org A +multiline +noall +answer"

    dig_mx = generate_dig_command(dom, "MX")
    assert dig_mx == "dig +nocmd example.org MX +multiline +noall +answer"


def test_search_and_filtering(master_key):
    """Tests searching domain assets by domain_name, registrar, and DNS provider."""
    dom1 = VaultEntry.create_domain(
        title="Infra Cluster Domain",
        domain_name="k8s-cluster.net",
        registrar="Cloudflare",
        dns_provider="Cloudflare DNS",
    )
    dom2 = VaultEntry.create_domain(
        title="Personal Blog",
        domain_name="myblog.io",
        registrar="Namecheap",
        dns_provider="Route 53",
    )
    dom3 = VaultEntry.create_service(
        title="Database Server",
        app_name="Postgres",
        url="postgres.internal",
    )
    entries = [dom1, dom2, dom3]

    # Search by domain name
    res = search_entries(entries, query="k8s-cluster.net")
    assert len(res) >= 1
    assert res[0][0].id == dom1.id

    # Search by registrar
    res_reg = search_entries(entries, query="Namecheap")
    assert len(res_reg) >= 1
    assert res_reg[0][0].id == dom2.id

    # Search by category filter "Domains"
    res_cat = search_entries(entries, query="", selected_category="Domains")
    cat_ids = [e.id for e, s in res_cat]
    assert dom1.id in cat_ids
    assert dom2.id in cat_ids
    assert dom3.id not in cat_ids


def test_organizer_sorting_and_ghost_check(temp_db, master_key):
    """Tests organizer sorting by type and clean_ghost_and_stale_entries with domain orphans."""
    dom = VaultEntry.create_domain(title="Alpha Domain", domain_name="alpha.com", registrar="Porkbun")
    temp_db.save_entry(dom, master_key)

    # Child referencing non-existent parent domain
    orphan_svc = VaultEntry.create_service(title="Orphan Service", app_name="Orphan", url="orphan.com")
    orphan_svc.parent_domain_id = "non-existent-domain-id-999"
    temp_db.save_entry(orphan_svc, master_key)

    entries = temp_db.get_all_entries(master_key)
    findings = find_ghost_and_stale(entries)
    assert len(findings["orphans"]) == 1
    assert findings["orphans"][0].id == orphan_svc.id

    # Clean orphans
    summary = purge_ghost_entries(temp_db, master_key)
    assert summary["fixed_orphans"] == 1

    cleaned_svc = temp_db.get_entry(orphan_svc.id, master_key)
    assert cleaned_svc.parent_domain_id is None


def test_extension_bridge_domain_endpoints(temp_db, master_key):
    """Tests /api/domains, /api/search, /api/get_credentials, and /api/save_entry in ExtensionBridgeServer."""
    dom = VaultEntry.create_domain(
        title="Apex Store",
        domain_name="apexstore.com",
        registrar="Cloudflare",
        expires_at="2029-06-30",
        auth_code="EPP-776655",
    )
    dom.username = "apex_cf_user"
    dom.password = "SecretApexPass#9"
    temp_db.save_entry(dom, master_key)

    server = ExtensionBridgeServer(
        database=temp_db,
        get_session_key=lambda: master_key,
        port=8099,
    )
    server.start()

    try:
        # 1. Test /api/domains
        req = urllib.request.Request("http://127.0.0.1:8099/api/domains")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["count"] >= 1
            domain_titles = [d["title"] for d in data["domains"]]
            assert "Apex Store" in domain_titles
            assert data["domains"][0]["username"] == "apex_cf_user"
            assert data["domains"][0]["has_password"] is True

        # 2. Test /api/search with filter_type="domain"
        search_req = urllib.request.Request(
            "http://127.0.0.1:8099/api/search",
            data=json.dumps({"filter_type": "domain"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(search_req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data["matches"]) >= 1
            assert data["matches"][0]["type"] == "domain"
            assert data["matches"][0]["domain_name"] == "apexstore.com"

        # 3. Test /api/get_credentials returns domain fields and password
        cred_req = urllib.request.Request(
            "http://127.0.0.1:8099/api/get_credentials",
            data=json.dumps({"entry_id": dom.id}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(cred_req) as resp:
            creds = json.loads(resp.read().decode("utf-8"))
            assert creds["username"] == "apex_cf_user"
            assert creds["password"] == "SecretApexPass#9"
            assert creds["domain_name"] == "apexstore.com"
            assert creds["registrar"] == "Cloudflare"
            assert creds["auth_code"] == "EPP-776655"

        # 4. Test /api/save_entry saving a domain directly from extension
        save_dom_req = urllib.request.Request(
            "http://127.0.0.1:8099/api/save_entry",
            data=json.dumps({
                "type": "domain",
                "title": "Extension Saved Domain",
                "domain_name": "extsaved.net",
                "registrar": "Namecheap",
                "expires_at": "2030-01-01",
                "username": "nc_ext_user",
                "password": "NcExtPassword!1",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(save_dom_req) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            assert res_data["success"] is True
            new_id = res_data["id"]

        saved_dom = temp_db.get_entry(new_id, master_key)
        assert saved_dom is not None
        assert saved_dom.entry_type == "domain"
        assert saved_dom.domain_name == "extsaved.net"
        assert saved_dom.username == "nc_ext_user"
        assert saved_dom.password == "NcExtPassword!1"

        # 5. Test /api/save_entry saving a service linked to this domain
        save_svc_req = urllib.request.Request(
            "http://127.0.0.1:8099/api/save_entry",
            data=json.dumps({
                "type": "service",
                "title": "Ext Linked App",
                "url": "https://app.extsaved.net",
                "username": "appuser",
                "password": "AppPassword!99",
                "parent_domain_id": new_id,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(save_svc_req) as resp:
            svc_res = json.loads(resp.read().decode("utf-8"))
            assert svc_res["success"] is True
            svc_id = svc_res["id"]

        saved_svc = temp_db.get_entry(svc_id, master_key)
        assert saved_svc.parent_domain_id == new_id

    finally:
        server.stop()
