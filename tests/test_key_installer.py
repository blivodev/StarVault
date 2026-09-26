"""Tests for the Local Key Installer, Scanner, System Verifier, and Exporter."""

import hashlib
import os
from pathlib import Path
import tempfile
import zipfile
import pytest

from starvault.key_installer import (
    DiscoveredLocalKey,
    InstallTargetConfig,
    KeyCheckItem,
    KeyInstallResult,
    append_to_authorized_keys,
    determine_default_filenames,
    export_vault_keys_to_directory,
    fix_all_ssh_permissions,
    get_system_env_info,
    install_vault_key,
    install_vault_keys,
    run_system_precheck,
    sanitize_filename,
    scan_local_keys,
    set_strict_directory_permissions,
    set_strict_file_permissions,
    update_ssh_config,
    verify_content_integrity,
    verify_file_permissions,
    verify_openssh_key_syntax,
)
from starvault.keys import (
    generate_age_key_result,
    generate_ed25519_key,
    generate_gpg_key,
    generate_rsa_key,
    generate_tls_cert_key,
    generate_wireguard_key_result,
)
from starvault.models import VaultEntry


@pytest.fixture
def temp_ssh_dir(tmp_path):
    """Provides a fresh temporary directory behaving like a local SSH/keys directory."""
    d = tmp_path / ".ssh"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_system_env_info_detection():
    """Verifies host environment detection produces valid paths and os type."""
    env = get_system_env_info()
    assert env.os_type in ("windows", "linux", "darwin")
    assert env.user_home.exists()
    assert isinstance(env.ssh_dir, Path)
    assert isinstance(env.username, str)
    assert len(env.username) > 0


def test_sanitize_filename():
    """Verifies strings are safely escaped for filenames."""
    assert sanitize_filename("My Server Key / 2026!") == "My_Server_Key_2026"
    assert sanitize_filename("   ...___   ") == "key"
    assert sanitize_filename("id_ed25519") == "id_ed25519"


def test_determine_default_filenames():
    """Verifies appropriate private and public file names for various algorithms."""
    e_ssh = VaultEntry.create_keypair("VPS Production", "vps_prod", "ed25519", "pub", "priv")
    priv, pub = determine_default_filenames(e_ssh)
    assert "ed25519" in priv
    assert pub == f"{priv}.pub"

    e_gpg = VaultEntry.create_keypair("Work GPG", "work_gpg", "gpg", "pub", "priv")
    priv_g, pub_g = determine_default_filenames(e_gpg)
    assert priv_g.endswith(".asc")
    assert pub_g.endswith(".asc")


def test_permission_hardening(temp_ssh_dir):
    """Tests directory and file permission application and verification."""
    # Directory permissions
    ok_dir, msg_dir = set_strict_directory_permissions(temp_ssh_dir)
    assert ok_dir

    # Private file permissions
    priv_file = temp_ssh_dir / "id_test_priv"
    priv_file.write_text("DUMMY_PRIVATE_KEY\n", encoding="utf-8")
    ok_f, msg_f = set_strict_file_permissions(priv_file, is_private=True)
    assert ok_f

    chk = verify_file_permissions(priv_file, is_private=True)
    assert chk.status in ("OK", "WARNING")

    # Public file permissions
    pub_file = temp_ssh_dir / "id_test_priv.pub"
    pub_file.write_text("ssh-ed25519 AAAAC3... test\n", encoding="utf-8")
    ok_pub, msg_pub = set_strict_file_permissions(pub_file, is_private=False)
    assert ok_pub
    chk_pub = verify_file_permissions(pub_file, is_private=False)
    assert chk_pub.status == "OK"


def test_content_integrity_check(temp_ssh_dir):
    """Tests SHA256 bit-for-bit integrity verification."""
    test_file = temp_ssh_dir / "test_key.txt"
    content = "SECRET_KEY_MATERIAL_12345"
    test_file.write_text(content + "\n", encoding="utf-8")

    # Matching content
    match_chk = verify_content_integrity(test_file, content)
    assert match_chk.status == "OK"

    # Mismatched content
    mismatch_chk = verify_content_integrity(test_file, "DIFFERENT_MATERIAL")
    assert mismatch_chk.status == "ERROR"


def test_install_ssh_ed25519_key(temp_ssh_dir):
    """Tests complete installation and verification of an Ed25519 keypair."""
    gen = generate_ed25519_key("deploy-key")
    entry = VaultEntry.create_keypair(
        title="Deploy Key Ed25519",
        key_name="deploy",
        key_type="ed25519",
        public_key=gen.public_key,
        private_key=gen.private_key,
        fingerprint=gen.fingerprint,
    )

    cfg = InstallTargetConfig(
        destination_dir=temp_ssh_dir,
        install_private=True,
        install_public=True,
        add_to_authorized_keys=True,
        add_to_ssh_config=True,
        ssh_config_host_alias="deploy-srv",
        ssh_config_hostname="10.0.0.50",
        ssh_config_user="deployer",
    )

    result = install_vault_key(entry, cfg)
    assert result.success
    assert len(result.installed_paths) >= 2

    # Verify files created on disk
    priv_path = temp_ssh_dir / "id_ed25519_deploy_key_ed25519"
    pub_path = temp_ssh_dir / "id_ed25519_deploy_key_ed25519.pub"
    assert priv_path.exists()
    assert pub_path.exists()

    # Verify authorized_keys
    auth_file = temp_ssh_dir / "authorized_keys"
    assert auth_file.exists()
    auth_content = auth_file.read_text(encoding="utf-8")
    assert "ssh-ed25519" in auth_content

    # Verify ssh config
    cfg_file = temp_ssh_dir / "config"
    assert cfg_file.exists()
    cfg_content = cfg_file.read_text(encoding="utf-8")
    assert "Host deploy-srv" in cfg_content
    assert "HostName 10.0.0.50" in cfg_content
    assert "User deployer" in cfg_content


def test_authorized_keys_deduplication(temp_ssh_dir):
    """Verifies that appending the same key multiple times does not create duplicates."""
    pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey123 user@host"
    chk1 = append_to_authorized_keys(temp_ssh_dir, pub_key)
    assert chk1.status == "OK"

    auth_file = temp_ssh_dir / "authorized_keys"
    lines_after_first = [l for l in auth_file.read_text().splitlines() if l.strip()]
    assert len(lines_after_first) == 1

    # Second append
    chk2 = append_to_authorized_keys(temp_ssh_dir, pub_key)
    assert chk2.status == "OK"
    assert "already present" in chk2.message.lower()

    lines_after_second = [l for l in auth_file.read_text().splitlines() if l.strip()]
    assert len(lines_after_second) == 1


def test_ssh_config_deduplication(temp_ssh_dir):
    """Verifies that Host blocks are not duplicated if already present."""
    key_path = temp_ssh_dir / "id_test"
    key_path.write_text("KEY\n")

    chk1 = update_ssh_config(temp_ssh_dir, "my-vps", key_path, hostname="1.2.3.4", user="root")
    assert chk1.status == "OK"

    chk2 = update_ssh_config(temp_ssh_dir, "my-vps", key_path, hostname="1.2.3.4", user="root")
    assert chk2.status == "OK"
    assert "already configured" in chk2.message.lower()


def test_install_gpg_key(temp_ssh_dir):
    """Tests GPG key installation."""
    gen = generate_gpg_key("Tester", "test@starvault.local", "Test GPG")
    entry = VaultEntry.create_keypair(
        title="GPG Test Key",
        key_name="test_gpg",
        key_type="gpg",
        public_key=gen.public_key,
        private_key=gen.private_key,
        fingerprint=gen.fingerprint,
    )

    cfg = InstallTargetConfig(destination_dir=temp_ssh_dir, import_to_gpg_keyring=False)
    res = install_vault_key(entry, cfg)
    assert res.success
    assert any(p.name.endswith(".asc") for p in res.installed_paths)


def test_install_age_key(temp_ssh_dir):
    """Tests Age key installation into keys.txt."""
    gen = generate_age_key_result()
    entry = VaultEntry.create_keypair(
        title="Age Vault Backup Key",
        key_name="age_key",
        key_type="age",
        public_key=gen.public_key,
        private_key=gen.private_key,
        fingerprint=gen.fingerprint,
    )

    cfg = InstallTargetConfig(destination_dir=temp_ssh_dir)
    res = install_vault_key(entry, cfg)
    assert res.success

    keys_file = temp_ssh_dir / "keys.txt"
    assert keys_file.exists()
    content = keys_file.read_text(encoding="utf-8")
    assert gen.private_key in content


def test_install_wireguard_key(temp_ssh_dir):
    """Tests WireGuard configuration installation."""
    gen = generate_wireguard_key_result()
    entry = VaultEntry.create_keypair(
        title="WG Homelab Client",
        key_name="wg0",
        key_type="wireguard",
        public_key=gen.public_key,
        private_key=gen.private_key,
        fingerprint=gen.fingerprint,
    )

    cfg = InstallTargetConfig(destination_dir=temp_ssh_dir)
    res = install_vault_key(entry, cfg)
    assert res.success

    conf_file = temp_ssh_dir / "wg_homelab_client.conf"
    assert conf_file.exists()
    content = conf_file.read_text(encoding="utf-8")
    assert "[Interface]" in content
    assert gen.private_key in content


def test_install_tls_cert(temp_ssh_dir):
    """Tests TLS Certificate and Private Key installation."""
    gen = generate_tls_cert_key("localhost", organization="Test Lab")
    entry = VaultEntry.create_keypair(
        title="Localhost SSL",
        key_name="localhost_cert",
        key_type="tls_cert",
        public_key=gen.public_key,
        private_key=gen.private_key,
        fingerprint=gen.fingerprint,
    )

    cfg = InstallTargetConfig(destination_dir=temp_ssh_dir)
    res = install_vault_key(entry, cfg)
    assert res.success

    crt_file = temp_ssh_dir / "localhost_ssl.crt"
    key_file = temp_ssh_dir / "localhost_ssl.key"
    assert crt_file.exists()
    assert key_file.exists()


def test_overwrite_protection(temp_ssh_dir):
    """Verifies overwrite protection generates unique filenames when overwrite_existing=False."""
    gen = generate_ed25519_key("key-a")
    entry = VaultEntry.create_keypair(
        title="SharedName",
        key_name="shared",
        key_type="ed25519",
        public_key=gen.public_key,
        private_key=gen.private_key,
    )

    # First installation
    cfg1 = InstallTargetConfig(destination_dir=temp_ssh_dir, overwrite_existing=False)
    res1 = install_vault_key(entry, cfg1)
    assert res1.success
    first_priv = res1.installed_paths[0]

    # Second installation without overwrite: should generate unique filename
    entry2 = VaultEntry.create_keypair(
        title="SharedName",
        key_name="shared",
        key_type="ed25519",
        public_key=gen.public_key,
        private_key=gen.private_key,
    )
    res2 = install_vault_key(entry2, cfg1)
    assert res2.success
    second_priv = res2.installed_paths[0]
    assert first_priv != second_priv
    assert first_priv.exists()
    assert second_priv.exists()


def test_batch_install_keys(temp_ssh_dir):
    """Tests installing multiple vault keys in a single batch operation."""
    k1 = generate_ed25519_key("batch-1")
    k2 = generate_rsa_key(2048, "batch-2")
    e1 = VaultEntry.create_keypair("Batch Key 1", "b1", "ed25519", k1.public_key, k1.private_key)
    e2 = VaultEntry.create_keypair("Batch Key 2", "b2", "rsa4096", k2.public_key, k2.private_key)

    cfg = InstallTargetConfig(destination_dir=temp_ssh_dir)
    results = install_vault_keys([e1, e2], default_config=cfg)
    assert len(results) == 2
    assert all(r.success for r in results)


def test_scan_local_keys(temp_ssh_dir):
    """Tests discovery scanner finding local keys and detecting duplicates."""
    k_ed = generate_ed25519_key("scan-test")
    (temp_ssh_dir / "id_ed25519_scan").write_text(k_ed.private_key + "\n", encoding="utf-8")
    (temp_ssh_dir / "id_ed25519_scan.pub").write_text(k_ed.public_key + "\n", encoding="utf-8")

    # Vault entry that already has this key
    existing_entry = VaultEntry.create_keypair(
        title="Existing Vault Key",
        key_name="scan",
        key_type="ed25519",
        public_key=k_ed.public_key,
        private_key=k_ed.private_key,
        fingerprint=k_ed.fingerprint,
    )

    discovered = scan_local_keys(
        directories=[temp_ssh_dir],
        existing_vault_entries=[existing_entry],
    )
    assert len(discovered) >= 1
    disc_key = next((k for k in discovered if "scan" in k.path.name), None)
    assert disc_key is not None
    assert disc_key.already_in_vault


def test_export_vault_keys_to_directory_and_zip(tmp_path):
    """Tests bulk export of vault keys to a folder and compressed zip."""
    out_dir = tmp_path / "export_out"
    k1 = generate_ed25519_key("exp-1")
    k2 = generate_rsa_key(2048, "exp-2")
    e1 = VaultEntry.create_keypair("Export Key 1", "exp1", "ed25519", k1.public_key, k1.private_key)
    e2 = VaultEntry.create_keypair("Export Key 2", "exp2", "rsa4096", k2.public_key, k2.private_key)

    # 1. Export as raw files + SSH config
    count, paths = export_vault_keys_to_directory([e1, e2], out_dir, generate_ssh_config=True, create_zip=False)
    assert count >= 4
    assert any(p.name == "ssh_config_template" for p in paths)

    # 2. Export as zip
    zip_dir = tmp_path / "export_zip"
    z_count, z_paths = export_vault_keys_to_directory([e1, e2], zip_dir, generate_ssh_config=True, create_zip=True)
    assert z_count == 1
    assert z_paths[0].name == "starvault_keys_export.zip"
    assert zipfile.is_zipfile(z_paths[0])

    with zipfile.ZipFile(z_paths[0], "r") as zf:
        names = zf.namelist()
        assert "config" in names
        assert any(n.endswith(".pub") for n in names)


def test_run_system_precheck():
    """Verifies system diagnostics audit runs without exceptions."""
    items = run_system_precheck()
    assert len(items) >= 3
    names = [i.name for i in items]
    assert "~/.ssh Directory" in names
    assert "OpenSSH Client Tools" in names
    assert "SSH Authentication Agent" in names


def test_fix_all_ssh_permissions(temp_ssh_dir):
    """Verifies batch fixing of directory and file permissions."""
    (temp_ssh_dir / "id_key1").write_text("PRIVATE\n")
    (temp_ssh_dir / "id_key1.pub").write_text("PUBLIC\n")
    (temp_ssh_dir / "authorized_keys").write_text("AUTH\n")

    count, logs = fix_all_ssh_permissions(temp_ssh_dir)
    assert count >= 3
    assert len(logs) >= 3
