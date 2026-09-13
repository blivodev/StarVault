"""Comprehensive test suite for StarVault new features:
- Multi-format API key generation
- RFC 6238 TOTP generation and validation
- QR and Code 128 barcode generation
- Vault health auto-fix engine
- Model Context Protocol (MCP) tool execution
"""

import json
from pathlib import Path
import tempfile
import pytest

from starvault.api_keys import (
    SUPPORTED_KEY_FORMATS,
    format_api_curl_snippet,
    generate_api_key,
)
from starvault.crypto import generate_secure_password
from starvault.database import Database
from starvault.health import VaultHealthAdvisor, fix_health_issue
from starvault.mcp_server import StarVaultMCPServer
from starvault.models import VaultEntry
from starvault.totp import (
    build_otpauth_uri,
    generate_barcode_image,
    generate_qr_image,
    generate_totp,
    get_totp_remaining_seconds,
    normalize_secret,
    parse_otpauth_uri,
    verify_totp,
)


def test_password_generation_helper():
    """Verify secure password generator with various constraints."""
    p1 = generate_secure_password(length=24, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    assert len(p1) == 24
    assert any(c.isupper() for c in p1)
    assert any(c.islower() for c in p1)
    assert any(c.isdigit() for c in p1)

    p2 = generate_secure_password(length=12, use_symbols=False)
    assert len(p2) == 12


def test_api_key_generators():
    """Verify generation of keys across all supported formats."""
    # Hex
    h32, _ = generate_api_key("hex32")
    assert len(h32) == 32
    int(h32, 16)  # Valid hex

    # Base64
    b64, _ = generate_api_key("base64_32")
    assert len(b64) == 32

    # UUID
    u, _ = generate_api_key("uuid")
    assert len(u) == 36
    assert u.count("-") == 4

    # Prefixed keys
    openai_key, _ = generate_api_key("openai")
    assert openai_key.startswith("sk-proj-")

    stripe_live, _ = generate_api_key("stripe_live")
    assert stripe_live.startswith("sk_live_")

    gh_pat, _ = generate_api_key("github")
    assert gh_pat.startswith("ghp_")

    # Custom prefix
    custom, _ = generate_api_key("custom_prefixed", prefix="mycorp")
    assert custom.startswith("mycorp_")

    # AWS keypair
    access_key, secret_key = generate_api_key("aws")
    assert access_key.startswith("AKIA")
    assert len(access_key) == 20
    assert len(secret_key) == 40

    # JWT simulation
    jwt_tok, _ = generate_api_key("jwt")
    assert jwt_tok.count(".") == 2

    # Format dispatch test across all supported formats
    for fmt_key, fmt_name in SUPPORTED_KEY_FORMATS:
        key_val, sec_val = generate_api_key(fmt_key)
        assert isinstance(key_val, str)
        assert len(key_val) > 0

    # cURL snippet
    curl_snippet = format_api_curl_snippet("https://api.starvault.io", "test-token-123")
    assert "Bearer test-token-123" in curl_snippet


def test_totp_generation_and_verification():
    """Verify RFC 6238 TOTP computation and validation."""
    # Standard test secret (RFC 6238 / Google Authenticator base32)
    secret = "JBSWY3DPEHPK3PXP"
    norm = normalize_secret("jbsw y3dp ehpk 3pxp")
    assert norm == secret

    code = generate_totp(secret)
    assert len(code) == 6
    assert code.isdigit()

    # Immediate verification
    assert verify_totp(code, secret, tolerance_steps=1) is True
    assert verify_totp("000000", secret, tolerance_steps=0) is False

    rem = get_totp_remaining_seconds()
    assert 0 <= rem <= 30

    # otpauth URI parsing & building
    uri = build_otpauth_uri(account="testuser", secret=secret, issuer="GitHub")
    assert uri.startswith("otpauth://totp/")
    parsed = parse_otpauth_uri(uri)
    assert parsed is not None
    assert parsed["secret"] == secret
    assert parsed["issuer"] == "GitHub"


def test_qr_and_barcode_generation():
    """Verify QR code and Barcode 128 image generation."""
    qr_img = generate_qr_image("https://starvault.io")
    assert qr_img is not None
    assert qr_img.size[0] > 50

    barcode_img = generate_barcode_image("STARVAULT-12345")
    assert barcode_img is not None
    assert barcode_img.size[0] > 50


def test_health_audit_and_auto_fix(tmp_path: Path):
    """Verify vault health detects issues (duplicates, weak, expired) and fixes them."""
    db_file = tmp_path / "health_test.db"
    db = Database(db_file)
    key = db.initialize_vault("TestHealthPass123!")

    # Entry 1: Weak password
    e1 = VaultEntry.create_server(
        title="Weak Server",
        hostname="192.168.1.10",
        username="admin",
        password="123",
    )
    db.save_entry(e1, key)

    # Entry 2: Duplicate password
    e2 = VaultEntry.create_service(
        title="Duplicate Service",
        app_name="TestApp",
        password="123",
    )
    db.save_entry(e2, key)

    # Entry 3: Expired API key
    e3 = VaultEntry.create_api_key(
        title="Expired Key",
        provider="OpenAI",
        api_token="sk-proj-old",
        expires_at="2020-01-01T00:00:00Z",
    )
    db.save_entry(e3, key)

    # Run audit
    advisor = VaultHealthAdvisor()
    entries = db.get_all_entries(key)
    report = advisor.analyze(entries)
    assert report.total_entries_analyzed == 3
    assert report.weak_passwords_count >= 1
    assert report.duplicate_passwords_count >= 1
    assert report.expiring_keys_count >= 1

    # Fix weak password on e1 specifically
    weak_issue = next(i for i in report.issues if i.issue_type == "weak_password" and e1.id in i.entry_ids)
    ok1, msg1 = fix_health_issue(weak_issue, db, key)
    assert ok1 is True

    # Check updated password is now strong
    loaded1 = db.get_entry(e1.id, key)
    assert loaded1 is not None
    assert len(loaded1.password) >= 16

    # Fix expiration on e3
    exp_issue = next(i for i in report.issues if i.issue_type == "expiring_key")
    ok2, msg2 = fix_health_issue(exp_issue, db, key)
    assert ok2 is True

    loaded3 = db.get_entry(e3.id, key)
    assert loaded3 is not None
    assert loaded3.expires_at > "2026-01-01"


def test_mcp_server_tools(tmp_path: Path):
    """Verify MCP Server executes stdio tool requests accurately."""
    db_file = tmp_path / "mcp_test.db"
    db = Database(db_file)
    master_pass = "MCPSecurePass123!"
    key = db.initialize_vault(master_pass)

    mcp = StarVaultMCPServer(db_path=db_file)

    # 1. Check status
    st_res = json.loads(mcp.execute_tool("starvault_status", {}))
    assert st_res["is_initialized"] is True
    assert st_res["status"] == "locked"

    # 2. Unlock
    un_res = mcp.execute_tool("starvault_unlock", {"master_password": master_pass})
    assert "Successfully unlocked" in un_res

    # 3. Add API key entry via MCP
    add_res = mcp.execute_tool(
        "starvault_add_entry",
        {
            "entry_type": "apikey",
            "title": "Anthropic Key",
            "provider": "Anthropic",
            "api_token": "sk-ant-testkey12345",
            "category": "API Keys",
            "tags": "ai, claude",
        },
    )
    assert "created" in add_res.lower()

    # 4. Search entries
    srch_res = json.loads(mcp.execute_tool("starvault_search_entries", {"query": "Anthropic"}))
    assert len(srch_res) == 1
    entry_id = srch_res[0]["id"]

    # 5. Get secret
    sec_res = json.loads(mcp.execute_tool("starvault_get_secret", {"identifier": entry_id, "secret_type": "api_token"}))
    assert sec_res["secret_value"] == "sk-ant-testkey12345"

    # 6. Generate password
    pw_res = json.loads(mcp.execute_tool("starvault_generate_password", {"length": 22}))
    assert len(pw_res["password"]) == 22

    # 7. Generate API key
    key_res = json.loads(mcp.execute_tool("starvault_generate_api_key", {"format_type": "openai"}))
    assert key_res["primary_key"].startswith("sk-proj-")

    # 8. Health audit via MCP
    audit_res = json.loads(mcp.execute_tool("starvault_health_audit", {}))
    assert "overall_score" in audit_res

    # 9. Lock
    lock_res = mcp.execute_tool("starvault_lock", {})
    assert "locked" in lock_res.lower()


def test_crypto_tools_algorithms():
    """Verify cryptographic helper functions across all supported algorithms."""
    from starvault.crypto_tools import (
        compute_hash,
        compute_hmac,
        decode_base64,
        decode_binary,
        decode_hex,
        decode_url,
        decrypt_symmetric,
        encode_base64,
        encode_binary,
        encode_hex,
        encode_url,
        encrypt_symmetric,
    )

    secret_key = "SuperSecretPassphrase1234567890!"
    plain = "Confidential StarVault Payload 12345"

    # AES-256-GCM
    ct_gcm = encrypt_symmetric(plain, secret_key, cipher="AES-256-GCM")
    assert ct_gcm != plain
    assert decrypt_symmetric(ct_gcm, secret_key, cipher="AES-256-GCM") == plain

    # ChaCha20-Poly1305
    ct_chacha = encrypt_symmetric(plain, secret_key, cipher="ChaCha20-Poly1305")
    assert ct_chacha != plain
    assert decrypt_symmetric(ct_chacha, secret_key, cipher="ChaCha20-Poly1305") == plain

    # AES-256-CBC
    ct_cbc = encrypt_symmetric(plain, secret_key, cipher="AES-256-CBC")
    assert ct_cbc != plain
    assert decrypt_symmetric(ct_cbc, secret_key, cipher="AES-256-CBC") == plain

    # Encodings
    assert decode_base64(encode_base64(plain)) == plain
    assert decode_hex(encode_hex(plain)) == plain
    assert decode_url(encode_url(plain)) == plain
    assert decode_binary(encode_binary(plain)) == plain

    # Hashing & HMAC
    h256 = compute_hash(plain, "sha256")
    assert len(h256) == 64
    hmac256 = compute_hmac(plain, secret_key, "sha256")
    assert len(hmac256) == 64


def test_file_and_bulk_file_encryption(tmp_path: Path):
    """Verify single file and bulk file encryption / decryption."""
    from starvault.crypto_tools import bulk_decrypt_files, bulk_encrypt_files, decrypt_file, encrypt_file

    f1 = tmp_path / "data1.txt"
    f2 = tmp_path / "data2.bin"
    f1.write_text("Hello StarVault Secure File 1", encoding="utf-8")
    f2.write_bytes(b"\xaa\xbb\xcc\xdd" * 50)

    passphrase = "FileCryptoKey999!"
    out_dir = tmp_path / "encrypted_files"

    # Bulk encrypt
    enc_count, enc_errs = bulk_encrypt_files([f1, f2], out_dir, passphrase, cipher="AES-256-GCM")
    assert enc_count == 2
    assert len(enc_errs) == 0
    assert (out_dir / "data1.txt.enc").exists()
    assert (out_dir / "data2.bin.enc").exists()

    # Bulk decrypt
    dec_dir = tmp_path / "decrypted_files"
    dec_count, dec_errs = bulk_decrypt_files(
        [out_dir / "data1.txt.enc", out_dir / "data2.bin.enc"],
        dec_dir,
        passphrase,
        cipher="AES-256-GCM",
    )
    assert dec_count == 2
    assert len(dec_errs) == 0
    assert (dec_dir / "data1.txt").read_text(encoding="utf-8") == "Hello StarVault Secure File 1"
    assert (dec_dir / "data2.bin").read_bytes() == b"\xaa\xbb\xcc\xdd" * 50


def test_vault_export_csv_and_archives(tmp_path: Path):
    """Verify CSV and password-protected ZIP and 7Z archive exports."""
    from starvault.export_utils import export_vault_to_archive, export_vault_to_csv

    db_path = tmp_path / "export_test.db"
    db = Database(db_path)
    key = db.initialize_vault("ExportMasterPass123!")

    # Add credentials and keypair
    srv = VaultEntry.create_server(title="Core Bastion", hostname="192.168.1.1", username="admin", password="SecretPassword!")
    db.save_entry(srv, key)
    kp = VaultEntry.create_keypair("Production SSH", "prod_ssh", "ssh", "ssh-ed25519 AAAAC3...", "priv_key_data")
    db.save_entry(kp, key)

    # 1. CSV export
    csv_file = tmp_path / "vault.csv"
    ok, msg, cnt = export_vault_to_csv(db, "ExportMasterPass123!", csv_file)
    assert ok, msg
    assert cnt == 2
    content = csv_file.read_text(encoding="utf-8")
    assert "Core Bastion" in content
    assert "Production SSH" in content

    # 2. Password-protected ZIP archive
    zip_file = tmp_path / "vault_backup.zip"
    ok, msg, summ = export_vault_to_archive(
        db,
        "ExportMasterPass123!",
        zip_file,
        archive_format="zip",
        archive_password="ArchivePassword777!",
        include_csv=True,
        include_files=True,
        include_keys=True,
    )
    assert ok, msg
    assert zip_file.exists()
    assert summ["credentials_count"] == 2
    assert summ["keys_count"] == 1

    # 3. Password-protected 7Z archive
    seven_file = tmp_path / "vault_backup.7z"
    ok, msg, summ = export_vault_to_archive(
        db,
        "ExportMasterPass123!",
        seven_file,
        archive_format="7z",
        archive_password="ArchivePassword777!",
        include_csv=True,
        include_files=True,
        include_keys=True,
    )
    assert ok, msg
    assert seven_file.exists()
    assert summ["credentials_count"] == 2


def test_theming_system(tmp_path: Path):
    """Verify theming system palette definitions, switching, and configuration persistence."""
    from starvault.app_config import AppConfigManager
    from starvault.ui.theme import (
        THEME_PALETTES,
        apply_theme,
        get_available_themes,
        get_current_theme,
        register_theme_listener,
        unregister_theme_listener,
    )

    themes = get_available_themes()
    assert "Dark" in themes
    assert "Light" in themes
    assert "Trendy" in themes
    assert "Console" in themes
    assert "Nord" in themes
    assert "Dracula" in themes

    notified = []
    def listener(name):
        notified.append(name)

    register_theme_listener(listener)
    apply_theme("Trendy", save_to_config=False)
    assert get_current_theme() == "Trendy"
    assert "Trendy" in notified

    apply_theme("Console", save_to_config=False)
    assert get_current_theme() == "Console"
    assert "Console" in notified

    unregister_theme_listener(listener)
    # Reset to Dark
    apply_theme("Dark", save_to_config=False)


def test_new_mcp_tools(tmp_path: Path):
    """Verify all new MCP tools added to the server."""
    db_file = tmp_path / "mcp_extended.db"
    db = Database(db_file)
    master_pass = "MCPExtendedPass123!"
    key = db.initialize_vault(master_pass)

    mcp = StarVaultMCPServer(db_path=db_file)
    mcp.execute_tool("starvault_unlock", {"master_password": master_pass})

    # 1. Crypto tool via MCP
    enc_out = json.loads(mcp.execute_tool("starvault_crypto_tool", {
        "operation": "encrypt",
        "algorithm": "AES-256-GCM",
        "data": "MCP Secret Message",
        "key": "TestPassphrase1234567890123456",
    }))
    assert "result" in enc_out

    dec_out = json.loads(mcp.execute_tool("starvault_crypto_tool", {
        "operation": "decrypt",
        "algorithm": "AES-256-GCM",
        "data": enc_out["result"],
        "key": "TestPassphrase1234567890123456",
    }))
    assert dec_out["result"] == "MCP Secret Message"

    # 2. TLS Certificate generation via MCP
    cert_out = json.loads(mcp.execute_tool("starvault_generate_certificate", {
        "common_name": "internal.vault.local",
        "validity_days": 90,
    }))
    assert "BEGIN CERTIFICATE" in cert_out["certificate_pem"]

    # 3. Keypair generation via MCP (WireGuard)
    wg_out = json.loads(mcp.execute_tool("starvault_generate_keypair", {"key_type": "wireguard"}))
    assert len(wg_out["public_key"]) > 0

    # 4. File encryption via MCP
    f = tmp_path / "plain.txt"
    f.write_text("Secret MCP File Data", encoding="utf-8")
    enc_f = tmp_path / "plain.txt.enc"
    f_res = json.loads(mcp.execute_tool("starvault_encrypt_file", {
        "operation": "encrypt",
        "source_path": str(f),
        "dest_path": str(enc_f),
        "passphrase": "FilePassphrase123!",
    }))
    assert f_res["success"] is True
    assert enc_f.exists()


def test_organizer_heuristics_category_and_tags():
    """Verify auto-grouping and tag inference across different services."""
    from starvault.organizer import infer_category, infer_tags, normalize_title

    # 1. Category inference
    e_aws = VaultEntry(title="AWS Production Root", hostname="ec2.us-east-1.amazonaws.com")
    assert infer_category(e_aws) == "Cloud & Infrastructure"

    e_gh = VaultEntry(title="GitHub Deploy Token", url="https://github.com/myorg/repo")
    assert infer_category(e_gh) == "Dev & Repositories"

    e_db = VaultEntry(title="Postgres Master DB", db_name="production_db", service_type="database")
    assert infer_category(e_db) == "Databases & Storage"

    e_ai = VaultEntry(title="OpenAI GPT-4o Key", provider="OpenAI", entry_type="apikey")
    assert infer_category(e_ai) == "AI & LLM Services"

    e_pay = VaultEntry(title="Stripe Webhook Secret", app_name="Stripe API")
    assert infer_category(e_pay) == "Finance & Payments"

    e_key = VaultEntry(title="Bastion Key", entry_type="keypair", key_type="ed25519")
    assert infer_category(e_key) == "Keys & Certificates"

    # 2. Tag inference
    e_tags = VaultEntry(
        title="Production Web Server",
        url="https://admin.github.com/dashboard",
        port=22,
        entry_type="server",
        totp_secret="JBSWY3DPEHPK3PXP",
    )
    inferred = infer_tags(e_tags)
    assert "env:production" in inferred
    assert "proto:ssh" in inferred
    assert "has:totp" in inferred
    assert "domain:github.com" in inferred

    # 3. Title normalization
    e_norm = VaultEntry(title="my_prod_aws_api_key")
    norm_title = normalize_title(e_norm)
    assert "AWS" in norm_title
    assert "API" in norm_title


def test_organizer_deduplication_and_merge(tmp_path: Path):
    """Verify smart deduplication, clustering, and 1-click merging."""
    from starvault.organizer import deduplicate_vault, find_duplicates, merge_entries

    db = Database(tmp_path / "dedup.db")
    key = db.initialize_vault("DedupPass123!")

    # Add two duplicate entries
    e1 = VaultEntry.create_service(
        title="Acme Portal",
        app_name="Acme",
        url="https://portal.acme.com",
        username="admin@acme.com",
        password="OriginalPassword123!",
        tags=["prod"],
    )
    e2 = VaultEntry.create_service(
        title="Acme Portal - Old",
        app_name="Acme",
        url="https://portal.acme.com",
        username="admin@acme.com",
        password="NewerPassword456!",
        tags=["legacy", "acme"],
        notes="Important customer note.",
    )
    db.save_entry(e1, key)
    db.save_entry(e2, key)

    entries = db.get_all_entries(key)
    dup_groups = find_duplicates(entries)
    assert len(dup_groups) >= 1
    assert dup_groups[0].similarity_score >= 0.9

    # Execute deduplication and merge
    res = deduplicate_vault(db, key, auto_merge=True)
    assert res["merged_count"] == 1

    remaining = db.get_all_entries(key)
    assert len(remaining) == 1
    merged = remaining[0]
    assert "legacy" in merged.tags
    assert "prod" in merged.tags
    assert "Important customer note" in merged.notes


def test_organizer_ghosts_files_and_sorting(tmp_path: Path):
    """Verify ghost purging, File Vault auto-organization, and multi-dimensional sorting."""
    from starvault.models import VaultFile
    from starvault.organizer import (
        auto_organize_files,
        auto_organize_vault,
        find_ghost_and_stale,
        purge_ghost_entries,
        sort_entries,
    )

    db = Database(tmp_path / "ghosts.db")
    key = db.initialize_vault("GhostPass123!")

    # 1. Create ghost and legitimate entries
    ghost = VaultEntry(title="")  # Completely empty ghost
    real1 = VaultEntry.create_server("Zebra VPS", "zebra.lan", username="root", password="ZebraPassword123!")
    real2 = VaultEntry.create_server("Alpha Server", "alpha.lan", username="root", password="AlphaPassword123!")
    real1.category = "General"
    real2.category = "General"

    db.save_entry(ghost, key)
    db.save_entry(real1, key)
    db.save_entry(real2, key)

    findings = find_ghost_and_stale(db.get_all_entries(key))
    assert len(findings["ghosts"]) == 1

    purge_res = purge_ghost_entries(db, key)
    assert purge_res["purged_ghosts"] == 1
    assert len(db.get_all_entries(key)) == 2

    # 2. Auto-organize vault
    org_sum = auto_organize_vault(db, key)
    assert org_sum.categories_updated >= 1

    # 3. File Vault organization
    vf = VaultFile(filename="server_cert.pem", file_size=1024)
    db.save_file(vf, b"MOCK CERTIFICATE BYTES", key)
    file_res = auto_organize_files(db, key)
    assert file_res["files_updated"] >= 1

    files = db.get_all_files(key)
    assert any("folder:Keys & Certificates" in f.tags for f in files)

    # 4. Multi-dimensional sorting
    entries = db.get_all_entries(key)
    sorted_asc = sort_entries(entries, sort_by="title_asc")
    assert sorted_asc[0].title.startswith("Alpha")

    sorted_desc = sort_entries(entries, sort_by="title_desc")
    assert sorted_desc[0].title.startswith("Zebra")


def test_organizer_mcp_tools(tmp_path: Path):
    """Verify MCP tools for auto-organize, deduplication, ghosts, and sorting."""
    db_file = tmp_path / "mcp_org.db"
    db = Database(db_file)
    master_pass = "MCPSecurePass123!"
    key = db.initialize_vault(master_pass)

    # Create unorganized and duplicate entries
    e1 = VaultEntry.create_server("aws-prod-ec2", "ec2.aws.com", username="root", password="AwsPassword123!")
    e1.category = "General"
    e2 = VaultEntry.create_server("aws-prod-ec2 - Copy", "ec2.aws.com", username="root", password="AwsPassword123!")
    e2.category = "General"
    ghost = VaultEntry(title="")

    db.save_entry(e1, key)
    db.save_entry(e2, key)
    db.save_entry(ghost, key)

    mcp = StarVaultMCPServer(db_path=db_file)
    mcp.execute_tool("starvault_unlock", {"master_password": master_pass})

    # 1. Clean stale ghosts via MCP
    clean_out = json.loads(mcp.execute_tool("starvault_clean_stale_ghosts", {"dry_run": False}))
    assert clean_out["purged_ghosts"] == 1

    # 2. Auto-organize vault via MCP
    org_out = json.loads(mcp.execute_tool("starvault_auto_organize_vault", {"override_categories": False}))
    assert org_out["success"] is True
    assert org_out["categories_updated"] >= 1

    # 3. Deduplicate entries via MCP
    dedup_out = json.loads(mcp.execute_tool("starvault_deduplicate_entries", {"auto_merge": True}))
    assert dedup_out["success"] is True
    assert dedup_out["merged_count"] >= 1

    # 4. Sort entries via MCP
    sort_out = json.loads(mcp.execute_tool("starvault_sort_entries", {"sort_by": "category"}))
    assert sort_out["success"] is True
    assert sort_out["total_entries"] >= 1


