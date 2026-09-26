"""Vault Export Utility for StarVault with Master Password verification.

Safely exports decrypted vault credentials to standard CSV format and full
portable archive packages (.zip and .7z) with optional AES-256 password protection.
Includes CSV formula injection protection (DDE attacks) and full export of:
- Decrypted credentials spreadsheet (credentials.csv)
- Extracted files (.pem, .ovpn, configs, backups)
- Extracted cryptographic keypairs (SSH, GPG, WireGuard, Age, Certificates)
- Export manifest (manifest.json)
"""

import csv
import io
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union
import zipfile

try:
    import pyzipper
except ImportError:
    pyzipper = None

try:
    import py7zr
except ImportError:
    py7zr = None

from starvault.config import APP_VERSION
from starvault.database import Database
from starvault.models import VaultEntry


CSV_HEADERS = [
    "Title",
    "Type",
    "Category",
    "Groups",
    "Services",
    "Tags",
    "Username",
    "Password",
    "Hostname",
    "Port",
    "URL",
    "Provider",
    "Environment",
    "API Key / Token",
    "API Secret",
    "API Key Format",
    "Scopes",
    "Expires At",
    "TOTP Secret",
    "Sudo Password",
    "Service Type",
    "Database Name",
    "Key Type",
    "Fingerprint",
    "Public Key",
    "Domain Name",
    "Registrar",
    "Auto Renew",
    "DNS Provider",
    "Nameservers",
    "Auth / EPP Code",
    "Parent Domain ID",
    "Parent Server ID",
    "Notes",
    "Created At",
    "Updated At",
]


def _sanitize_csv_cell(val: Any) -> str:
    """Sanitizes text cells to neutralize spreadsheet formula injection (DDE attacks)."""
    if val is None:
        return ""
    str_val = str(val)
    if str_val.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + str_val
    return str_val


def export_entries_to_csv_string(entries: List[VaultEntry]) -> str:
    """Converts a list of decrypted VaultEntry objects to a valid CSV string."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(CSV_HEADERS)

    for e in entries:
        tags_str = ", ".join(e.tags) if e.tags else ""
        groups_str = e.get_groups_display()
        services_str = e.get_services_display()
        row = [
            _sanitize_csv_cell(e.title),
            _sanitize_csv_cell(e.entry_type),
            _sanitize_csv_cell(e.category),
            _sanitize_csv_cell(groups_str),
            _sanitize_csv_cell(services_str),
            _sanitize_csv_cell(tags_str),
            _sanitize_csv_cell(e.username),
            _sanitize_csv_cell(e.password),
            _sanitize_csv_cell(e.hostname),
            _sanitize_csv_cell(str(e.port) if e.port else ""),
            _sanitize_csv_cell(e.url),
            _sanitize_csv_cell(e.provider),
            _sanitize_csv_cell(e.environment),
            _sanitize_csv_cell(e.api_token),
            _sanitize_csv_cell(e.api_key_secret),
            _sanitize_csv_cell(e.api_key_format),
            _sanitize_csv_cell(e.scopes),
            _sanitize_csv_cell(e.expires_at),
            _sanitize_csv_cell(e.totp_secret),
            _sanitize_csv_cell(e.sudo_password),
            _sanitize_csv_cell(e.service_type),
            _sanitize_csv_cell(e.db_name),
            _sanitize_csv_cell(e.key_type),
            _sanitize_csv_cell(e.fingerprint),
            _sanitize_csv_cell(e.public_key),
            _sanitize_csv_cell(getattr(e, "domain_name", "")),
            _sanitize_csv_cell(getattr(e, "registrar", "")),
            _sanitize_csv_cell(getattr(e, "auto_renew", False)),
            _sanitize_csv_cell(getattr(e, "dns_provider", "")),
            _sanitize_csv_cell(getattr(e, "nameservers", "")),
            _sanitize_csv_cell(getattr(e, "auth_code", "")),
            _sanitize_csv_cell(getattr(e, "parent_domain_id", "") or ""),
            _sanitize_csv_cell(getattr(e, "parent_server_id", "") or ""),
            _sanitize_csv_cell(e.notes),
            _sanitize_csv_cell(e.created_at),
            _sanitize_csv_cell(e.updated_at),
        ]
        writer.writerow(row)

    return output.getvalue()


def export_vault_to_csv(
    database: Database,
    master_password: str,
    target_path: Union[str, Path],
    keyfile_secret: Optional[str] = None,
) -> Tuple[bool, str, int]:
    """Authenticates master password and exports all entries to a target CSV file path.

    Returns:
        (success, message, entry_count)
    """
    success, key = database.unlock_vault(master_password, keyfile_secret=keyfile_secret)
    if not success or not key:
        return False, "Master password verification failed. Export aborted.", 0

    try:
        entries = database.get_all_entries(key)
        csv_data = export_entries_to_csv_string(entries)
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(csv_data, encoding="utf-8")
        return True, f"Successfully exported {len(entries)} credentials to '{target.name}'.", len(entries)
    except Exception as ex:
        return False, f"Failed to export CSV: {str(ex)}", 0


def export_vault_to_archive(
    database: Database,
    master_password: str,
    target_archive_path: Union[str, Path],
    archive_format: str = "zip",
    archive_password: Optional[str] = None,
    include_csv: bool = True,
    include_files: bool = True,
    include_keys: bool = True,
    keyfile_secret: Optional[str] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Exports entire vault contents into a structured archive (.zip or .7z).

    Supports AES-256 archive password protection.
    Includes:
    - credentials.csv: Decrypted credentials table
    - files/: Decrypted binary files from vault
    - keys/: Individual keypair private (.pem/.key) and public (.pub/.crt) files
    - manifest.json: Metadata & audit summary

    Returns:
        (success, message, summary_dict)
    """
    success, key = database.unlock_vault(master_password, keyfile_secret=keyfile_secret)
    if not success or not key:
        return False, "Master password verification failed. Export aborted.", {}

    target = Path(target_archive_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "credentials_count": 0,
        "files_count": 0,
        "keys_count": 0,
        "format": archive_format.lower(),
        "password_protected": bool(archive_password),
    }

    try:
        with tempfile.TemporaryDirectory() as staging_dir:
            staging_p = Path(staging_dir)

            # 1. Export CSV
            all_entries = database.get_all_entries(key)
            if include_csv:
                csv_str = export_entries_to_csv_string(all_entries)
                (staging_p / "credentials.csv").write_text(csv_str, encoding="utf-8")
                summary["credentials_count"] = len(all_entries)

            # 2. Export Files
            if include_files:
                vault_files = database.get_all_files(key)
                if vault_files:
                    files_dir = staging_p / "files"
                    files_dir.mkdir(parents=True, exist_ok=True)
                    for vf in vault_files:
                        try:
                            f_bytes = database.read_file_bytes(vf.id, key)
                            if f_bytes is not None:
                                safe_name = Path(vf.filename).name
                                out_f = files_dir / safe_name
                                if out_f.exists():
                                    out_f = files_dir / f"{out_f.stem}_{vf.id[:6]}{out_f.suffix}"
                                out_f.write_bytes(f_bytes)
                                summary["files_count"] += 1
                        except Exception:
                            pass

            # 3. Export Keys & Certificates
            if include_keys:
                keypair_entries = [e for e in all_entries if e.entry_type == "keypair"]
                if keypair_entries:
                    keys_dir = staging_p / "keys"
                    keys_dir.mkdir(parents=True, exist_ok=True)
                    for kp in keypair_entries:
                        safe_base = "".join(c for c in kp.title if c.isalnum() or c in "._- ").strip() or f"key_{kp.id[:6]}"
                        # Public Key or Certificate
                        if kp.public_key:
                            pub_ext = ".crt" if kp.key_type == "cert" else ".pub"
                            (keys_dir / f"{safe_base}{pub_ext}").write_text(kp.public_key, encoding="utf-8")
                        # Private Key
                        if kp.password:
                            priv_ext = ".pem" if kp.key_type in ("ssh", "cert", "rsa") else ".key"
                            (keys_dir / f"{safe_base}{priv_ext}").write_text(kp.password, encoding="utf-8")
                        summary["keys_count"] += 1

            # 4. Write manifest
            manifest = {
                "application": "StarVault",
                "version": APP_VERSION,
                "export_date": "now",
                "contents": summary,
            }
            (staging_p / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            # 5. Build final archive (.zip or .7z)
            is_7z = archive_format.lower() in ("7z", ".7z") or target.suffix.lower() == ".7z"

            if is_7z:
                if py7zr is None:
                    return False, "py7zr library is not installed for .7z format.", summary
                if archive_password:
                    with py7zr.SevenZipFile(target, "w", password=archive_password) as szf:
                        for root, _, files in os.walk(staging_p):
                            for fname in files:
                                fpath = Path(root) / fname
                                szf.write(fpath, fpath.relative_to(staging_p))
                else:
                    with py7zr.SevenZipFile(target, "w") as szf:
                        for root, _, files in os.walk(staging_p):
                            for fname in files:
                                fpath = Path(root) / fname
                                szf.write(fpath, fpath.relative_to(staging_p))

            else:
                # Standard or AES-256 ZIP
                if archive_password:
                    if pyzipper is not None:
                        with pyzipper.AESZipFile(
                            target,
                            "w",
                            compression=pyzipper.ZIP_DEFLATED,
                            encryption=pyzipper.WZ_AES,
                        ) as zf:
                            zf.setpassword(archive_password.encode("utf-8"))
                            zf.setencryption(pyzipper.WZ_AES, nbits=256)
                            for root, _, files in os.walk(staging_p):
                                for fname in files:
                                    fpath = Path(root) / fname
                                    zf.write(fpath, str(fpath.relative_to(staging_p)))
                    else:
                        return False, "pyzipper library is required for password-protected ZIP archives.", summary
                else:
                    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        for root, _, files in os.walk(staging_p):
                            for fname in files:
                                fpath = Path(root) / fname
                                zf.write(fpath, str(fpath.relative_to(staging_p)))

        msg = (
            f"Successfully created archive '{target.name}' with {summary['credentials_count']} credentials, "
            f"{summary['files_count']} files, and {summary['keys_count']} keys."
        )
        return True, msg, summary

    except Exception as ex:
        return False, f"Archive creation failed: {str(ex)}", summary
