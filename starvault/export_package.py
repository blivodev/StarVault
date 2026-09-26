"""StarVault Encrypted Export & Universal Import Engine.

Provides:
- Creation of zero-knowledge encrypted `.sve` / `.starvault` portable export packages
  (Argon2id + AES-256-GCM authenticated container with zlib compression).
- Reading, validation, and decryption of `.sve`, `.starvault`, `.zip` archives, and `.csv` exports.
- Intelligent conflict resolution (skip, overwrite, import-as-copy) for seamless
  restoration and synchronization between distinct StarVault instances.
"""

import base64
import csv
import io
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union
import zipfile
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starvault.config import APP_VERSION
from starvault.crypto import derive_key, generate_salt
from starvault.database import Database
from starvault.models import VaultEntry, VaultFile, utc_now_iso
from starvault.versioning import VaultEntryVersion, snapshot_entry_data


# Magic bytes for StarVault Encrypted Export Container
PACKAGE_MAGIC = b"STV1"
PACKAGE_AAD = b"STARVAULT_EXPORT_V1"


def create_encrypted_vault_package(
    database: Database,
    session_key: bytes,
    export_passphrase: str,
    target_path: Union[str, Path],
    include_credentials: bool = True,
    include_keys: bool = True,
    include_files: bool = True,
    include_versions: bool = True,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Exports full or filtered vault contents into a zero-knowledge encrypted .sve file.

    Container format:
    [4 bytes MAGIC 'STV1'] [16 bytes SALT] [12 bytes NONCE] [Ciphertext + 16 bytes GCM Tag]
    Payload is zlib-compressed JSON containing decrypted entries, files, and versions.
    """
    if not export_passphrase or len(export_passphrase.strip()) < 6:
        return False, "Export passphrase must be at least 6 characters.", {}

    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "credentials_count": 0,
        "keys_count": 0,
        "files_count": 0,
        "versions_count": 0,
        "target_file": str(target),
    }

    try:
        entries_data = []
        versions_data = []
        files_data = []

        all_entries = database.get_all_entries(session_key)

        for entry in all_entries:
            is_keypair = (entry.entry_type == "keypair")
            if is_keypair and not include_keys:
                continue
            if not is_keypair and not include_credentials:
                continue

            snap = snapshot_entry_data(entry)
            entries_data.append(snap)
            if is_keypair:
                summary["keys_count"] += 1
            else:
                summary["credentials_count"] += 1

            if include_versions:
                v_list = database.get_entry_versions(entry.id, key=session_key, decrypt=True)
                for v in v_list:
                    versions_data.append({
                        "id": v.id,
                        "entry_id": v.entry_id,
                        "version_num": v.version_num,
                        "secret_type": v.secret_type,
                        "title": v.title,
                        "change_summary": v.change_summary,
                        "associated_files": list(v.associated_files),
                        "created_at": v.created_at,
                        "data": v.decrypted_data or {},
                    })
                    summary["versions_count"] += 1

        if include_files:
            vault_files = database.get_all_files(session_key)
            for vf in vault_files:
                f_bytes = database.read_file_bytes(vf.id, session_key)
                if f_bytes is not None:
                    files_data.append({
                        "id": vf.id,
                        "filename": vf.filename,
                        "mime_type": vf.mime_type,
                        "size_bytes": getattr(vf, "file_size", getattr(vf, "size_bytes", 0)),
                        "data_b64": base64.b64encode(f_bytes).decode("ascii"),
                        "created_at": vf.created_at,
                    })
                    summary["files_count"] += 1

        settings = database.get_settings()

        package_dict = {
            "format": "starvault_encrypted_export",
            "package_version": "1.0",
            "app_version": APP_VERSION,
            "created_at": utc_now_iso(),
            "summary": summary,
            "entries": entries_data,
            "versions": versions_data,
            "files": files_data,
            "settings": settings,
        }

        # Serialize and compress payload
        json_bytes = json.dumps(package_dict, separators=(",", ":")).encode("utf-8")
        compressed_payload = zlib.compress(json_bytes, level=9)

        # Derive 32-byte Argon2id encryption key from passphrase
        salt = generate_salt(16)
        enc_key = derive_key(export_passphrase, salt)

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(enc_key)
        ciphertext = aesgcm.encrypt(nonce, compressed_payload, PACKAGE_AAD)

        # Write container
        with open(target, "wb") as f:
            f.write(PACKAGE_MAGIC)
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        msg = (
            f"Encrypted export created successfully! ({summary['credentials_count']} credentials, "
            f"{summary['keys_count']} keys, {summary['files_count']} files)"
        )
        return True, msg, summary

    except Exception as ex:
        return False, f"Export failed: {str(ex)}", summary


def read_encrypted_vault_package(
    export_file_path: Union[str, Path],
    export_passphrase: str,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Decrypts and unpacks a .sve / .starvault package using the export passphrase."""
    p = Path(export_file_path)
    if not p.is_file():
        return False, "File not found.", None

    try:
        raw = p.read_bytes()
        if len(raw) < 4 + 16 + 12 + 16:
            return False, "File is too small or corrupted.", None

        magic = raw[:4]
        if magic != PACKAGE_MAGIC:
            return False, "Not a valid StarVault encrypted export file (invalid magic bytes).", None

        salt = raw[4:20]
        nonce = raw[20:32]
        ciphertext = raw[32:]

        # Derive key and decrypt
        enc_key = derive_key(export_passphrase, salt)
        aesgcm = AESGCM(enc_key)

        try:
            compressed_payload = aesgcm.decrypt(nonce, ciphertext, PACKAGE_AAD)
        except InvalidTag:
            return False, "Incorrect export passphrase or data corrupted.", None

        # Decompress and parse
        json_bytes = zlib.decompress(compressed_payload)
        package_dict = json.loads(json_bytes.decode("utf-8"))

        if package_dict.get("format") != "starvault_encrypted_export":
            return False, "Unsupported package format signature.", None

        return True, "Package decrypted and validated successfully.", package_dict

    except Exception as ex:
        return False, f"Decryption failed: {str(ex)}", None


def inspect_import_file(
    file_path: Union[str, Path],
    passphrase: Optional[str] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Analyzes an import file (.sve, .starvault, .zip, .csv) and returns metadata preview."""
    p = Path(file_path)
    if not p.is_file():
        return False, "Target import file does not exist.", {}

    suffix = p.suffix.lower()

    # 1. StarVault Encrypted Package (.sve, .starvault)
    if suffix in (".sve", ".starvault") or p.name.endswith(".sve"):
        if not passphrase:
            return False, "NEEDS_PASSPHRASE", {"file_type": "encrypted_package", "filename": p.name, "file_path": str(p)}

        success, msg, pkg = read_encrypted_vault_package(p, passphrase)
        if not success or not pkg:
            return False, msg, {"file_type": "encrypted_package", "filename": p.name, "file_path": str(p)}

        summ = pkg.get("summary", {})
        return True, "Valid StarVault Encrypted Package", {
            "file_type": "encrypted_package",
            "filename": p.name,
            "file_path": str(p),
            "credentials_count": summ.get("credentials_count", len(pkg.get("entries", []))),
            "keys_count": summ.get("keys_count", 0),
            "files_count": summ.get("files_count", len(pkg.get("files", []))),
            "versions_count": summ.get("versions_count", len(pkg.get("versions", []))),
            "app_version": pkg.get("app_version", "Unknown"),
            "created_at": pkg.get("created_at", "Unknown"),
            "package_dict": pkg,
        }

    # 2. Archive (.zip)
    elif suffix == ".zip":
        try:
            with zipfile.ZipFile(p, "r") as zf:
                names = zf.namelist()
                has_csv = "credentials.csv" in names
                files_found = [n for n in names if n.startswith("files/") and not n.endswith("/")]
                keys_found = [n for n in names if n.startswith("keys/") and not n.endswith("/")]
                has_manifest = "manifest.json" in names

                cred_count = 0
                if has_csv:
                    try:
                        csv_text = zf.read("credentials.csv").decode("utf-8", errors="ignore")
                        reader = csv.reader(io.StringIO(csv_text))
                        rows = list(reader)
                        cred_count = max(0, len(rows) - 1)
                    except Exception:
                        pass

                return True, "Valid StarVault Archive Package (.zip)", {
                    "file_type": "zip_archive",
                    "filename": p.name,
                    "file_path": str(p),
                    "credentials_count": cred_count,
                    "keys_count": len(keys_found),
                    "files_count": len(files_found),
                    "versions_count": 0,
                    "has_manifest": has_manifest,
                }
        except RuntimeError as ex:
            if "password" in str(ex).lower():
                return False, "NEEDS_PASSPHRASE", {"file_type": "zip_archive", "filename": p.name, "file_path": str(p)}
            return False, f"Could not read zip archive: {ex}", {}
        except Exception as ex:
            return False, f"Could not inspect zip file: {ex}", {}

    # 3. CSV File (.csv)
    elif suffix == ".csv":
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                rows = list(reader)
                cred_count = max(0, len(rows) - 1)
                return True, "Valid CSV Credential Spreadsheet", {
                    "file_type": "csv",
                    "filename": p.name,
                    "file_path": str(p),
                    "credentials_count": cred_count,
                    "keys_count": 0,
                    "files_count": 0,
                    "versions_count": 0,
                }
        except Exception as ex:
            return False, f"Could not read CSV: {ex}", {}

    # 4. SQLite Database Backup (.db, .sqlite, .sqlite3)
    elif suffix in (".db", ".sqlite", ".sqlite3") or p.name.endswith((".db", ".sqlite")):
        try:
            import sqlite3
            conn = sqlite3.connect(f"file:{str(p.resolve())}?mode=ro", uri=True)
            cursor = conn.cursor()
            tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            has_meta = "vault_meta" in tables or "vault_metadata" in tables
            if not has_meta or "vault_entries" not in tables:
                conn.close()
                return False, "Selected SQLite file is missing StarVault database tables.", {}

            cred_count = cursor.execute("SELECT COUNT(*) FROM vault_entries WHERE entry_type != 'keypair'").fetchone()[0]
            keys_count = cursor.execute("SELECT COUNT(*) FROM vault_entries WHERE entry_type = 'keypair'").fetchone()[0]
            files_count = cursor.execute("SELECT COUNT(*) FROM vault_files").fetchone()[0] if "vault_files" in tables else 0
            versions_count = cursor.execute("SELECT COUNT(*) FROM vault_entry_versions").fetchone()[0] if "vault_entry_versions" in tables else 0

            created_at = "Unknown"
            app_ver = APP_VERSION
            try:
                row = cursor.execute("SELECT created_at FROM vault_meta LIMIT 1").fetchone()
                if row and row[0]:
                    created_at = row[0]
            except Exception:
                pass
            conn.close()

            if not passphrase:
                return False, "NEEDS_PASSPHRASE", {
                    "file_type": "database",
                    "filename": p.name,
                    "file_path": str(p),
                    "credentials_count": cred_count,
                    "keys_count": keys_count,
                    "files_count": files_count,
                    "versions_count": versions_count,
                    "app_version": app_ver,
                    "created_at": created_at,
                }

            temp_db = Database(p)
            success, derived_key = temp_db.unlock_vault(passphrase)
            if not success or not derived_key:
                return False, "Invalid master password for database backup.", {
                    "file_type": "database",
                    "filename": p.name,
                    "file_path": str(p),
                    "credentials_count": cred_count,
                    "keys_count": keys_count,
                    "files_count": files_count,
                    "versions_count": versions_count,
                }

            return True, "Valid StarVault Database Backup (.db)", {
                "file_type": "database",
                "filename": p.name,
                "file_path": str(p),
                "credentials_count": cred_count,
                "keys_count": keys_count,
                "files_count": files_count,
                "versions_count": versions_count,
                "app_version": app_ver,
                "derived_key": derived_key,
            }
        except Exception as ex:
            return False, f"Could not inspect database file: {ex}", {}

    # 5. JSON Vault Export (.json)
    elif suffix == ".json":
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, dict):
                entries = data.get("entries", data.get("items", []))
                return True, "Valid JSON Vault Export", {
                    "file_type": "json",
                    "filename": p.name,
                    "file_path": str(p),
                    "credentials_count": len(entries),
                    "keys_count": sum(1 for e in entries if isinstance(e, dict) and e.get("entry_type") == "keypair"),
                    "files_count": len(data.get("files", [])),
                    "versions_count": len(data.get("versions", [])),
                    "json_data": data,
                }
            elif isinstance(data, list):
                return True, "Valid JSON Entry List", {
                    "file_type": "json",
                    "filename": p.name,
                    "file_path": str(p),
                    "credentials_count": len(data),
                    "keys_count": sum(1 for e in data if isinstance(e, dict) and e.get("entry_type") == "keypair"),
                    "files_count": 0,
                    "versions_count": 0,
                    "json_data": {"entries": data},
                }
            else:
                return False, "Unrecognized JSON export structure.", {}
        except Exception as ex:
            return False, f"Could not read JSON file: {ex}", {}

    else:
        return False, f"Unsupported file type '{suffix}'. Supported: .sve, .starvault, .db, .sqlite, .zip, .csv, .json", {}


def execute_vault_import(
    database: Database,
    session_key: bytes,
    import_metadata: Dict[str, Any],
    file_path: Optional[Union[str, Path]] = None,
    passphrase: Optional[str] = None,
    conflict_strategy: str = "skip",  # 'skip', 'overwrite', 'copy'
    import_credentials: bool = True,
    import_keys: bool = True,
    import_files: bool = True,
    import_versions: bool = True,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Imports parsed items into the live database encrypted with the session_key.

    Returns:
        (success, message, result_summary)
    """
    if not file_path:
        file_path = import_metadata.get("file_path")
    ftype = import_metadata.get("file_type")
    results = {
        "imported_credentials": 0,
        "skipped_credentials": 0,
        "overwritten_credentials": 0,
        "imported_keys": 0,
        "imported_files": 0,
        "imported_versions": 0,
        "errors": [],
    }

    try:
        existing_entries = database.get_all_entries(session_key)
        existing_by_title = {e.title.strip().lower(): e for e in existing_entries}
        existing_by_id = {e.id: e for e in existing_entries}

        # Case A: Encrypted Package (.sve)
        if ftype == "encrypted_package":
            pkg = import_metadata.get("package_dict")
            if not pkg:
                if not passphrase:
                    return False, "Passphrase required to decrypt package.", results
                s, m, pkg = read_encrypted_vault_package(file_path, passphrase)
                if not s or not pkg:
                    return False, m, results

            entries_raw = pkg.get("entries", [])
            for raw in entries_raw:
                etype = raw.get("entry_type", "service")
                is_key = (etype == "keypair")
                if is_key and not import_keys:
                    continue
                if not is_key and not import_credentials:
                    continue

                title = raw.get("title", "").strip() or "Imported Item"
                norm_title = title.lower()

                target_id = raw.get("id")
                existing = existing_by_title.get(norm_title) or existing_by_id.get(target_id)

                if existing:
                    if conflict_strategy == "skip":
                        results["skipped_credentials"] += 1
                        continue
                    elif conflict_strategy == "overwrite":
                        entry = existing
                        from starvault.versioning import apply_version_to_entry
                        apply_version_to_entry(entry, raw)
                        entry.updated_at = utc_now_iso()
                        database.save_entry(entry, session_key, change_summary="Imported (Overwritten)")
                        results["overwritten_credentials"] += 1
                        continue
                    else:  # 'copy'
                        import uuid
                        entry = VaultEntry(id=str(uuid.uuid4()))
                        from starvault.versioning import apply_version_to_entry
                        apply_version_to_entry(entry, raw)
                        entry.id = str(uuid.uuid4())
                        entry.title = f"{title} (Imported)"
                        entry.created_at = utc_now_iso()
                        entry.updated_at = utc_now_iso()
                        database.save_entry(entry, session_key, change_summary="Imported as Copy")
                        if is_key:
                            results["imported_keys"] += 1
                        else:
                            results["imported_credentials"] += 1
                        continue

                # New entry
                entry = VaultEntry(id=target_id or str(uuid.uuid4()))
                from starvault.versioning import apply_version_to_entry
                apply_version_to_entry(entry, raw)
                database.save_entry(entry, session_key, change_summary="Imported into StarVault")
                existing_by_title[norm_title] = entry
                existing_by_id[entry.id] = entry
                if is_key:
                    results["imported_keys"] += 1
                else:
                    results["imported_credentials"] += 1

            # Import Files
            if import_files:
                files_raw = pkg.get("files", [])
                for f_raw in files_raw:
                    try:
                        fname = f_raw.get("filename", "file.bin")
                        b64 = f_raw.get("data_b64", "")
                        if b64:
                            content = base64.b64decode(b64)
                            vf = VaultFile(
                                filename=fname,
                                file_size=len(content),
                                mime_type=f_raw.get("mime_type", "application/octet-stream"),
                            )
                            database.save_file(vf, content, session_key)
                            results["imported_files"] += 1
                    except Exception as ex:
                        results["errors"].append(f"File import error ({fname}): {ex}")

            # Import Historical Versions if requested
            if import_versions:
                vers_raw = pkg.get("versions", [])
                for vr in vers_raw:
                    try:
                        eid = vr.get("entry_id")
                        if eid and eid in existing_by_id:
                            # Save version record
                            database.record_entry_version(
                                existing_by_id[eid],
                                session_key,
                                change_summary=vr.get("change_summary", "Imported historical version"),
                                associated_files=vr.get("associated_files", []),
                            )
                            results["imported_versions"] += 1
                    except Exception:
                        pass

        # Case B: ZIP Archive
        elif ftype == "zip_archive":
            with zipfile.ZipFile(file_path, "r") as zf:
                if import_credentials and "credentials.csv" in zf.namelist():
                    csv_text = zf.read("credentials.csv").decode("utf-8", errors="ignore")
                    _import_csv_text(csv_text, database, session_key, existing_by_title, conflict_strategy, results)

                if import_files:
                    for name in zf.namelist():
                        if name.startswith("files/") and not name.endswith("/"):
                            try:
                                fname = Path(name).name
                                f_bytes = zf.read(name)
                                vf = VaultFile(filename=fname, file_size=len(f_bytes))
                                database.save_file(vf, f_bytes, session_key)
                                results["imported_files"] += 1
                            except Exception as ex:
                                results["errors"].append(f"Zip file error: {ex}")

        # Case C: CSV Spreadsheet
        elif ftype == "csv":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                csv_text = f.read()
            _import_csv_text(csv_text, database, session_key, existing_by_title, conflict_strategy, results)

        # Case D: SQLite Database Backup (.db, .sqlite)
        elif ftype == "database":
            source_key = import_metadata.get("derived_key")
            src_db = Database(file_path)
            if not source_key:
                if not passphrase:
                    return False, "Passphrase required to unlock database backup.", results
                s, source_key = src_db.unlock_vault(passphrase)
                if not s or not source_key:
                    return False, "Invalid passphrase for database backup.", results

            import uuid
            src_entries = src_db.get_all_entries(source_key)
            for entry in src_entries:
                is_key = (entry.entry_type == "keypair")
                if is_key and not import_keys:
                    continue
                if not is_key and not import_credentials:
                    continue

                title = entry.title.strip() or "Imported Item"
                norm_title = title.lower()
                existing = existing_by_title.get(norm_title) or existing_by_id.get(entry.id)

                if existing:
                    if conflict_strategy == "skip":
                        results["skipped_credentials"] += 1
                        continue
                    elif conflict_strategy == "overwrite":
                        entry.id = existing.id
                        entry.updated_at = utc_now_iso()
                        database.save_entry(entry, session_key, change_summary="Imported from DB (Overwritten)")
                        results["overwritten_credentials"] += 1
                        continue
                    else:  # copy
                        entry.id = str(uuid.uuid4())
                        entry.title = f"{title} (Imported)"
                        entry.created_at = utc_now_iso()
                        entry.updated_at = utc_now_iso()
                        database.save_entry(entry, session_key, change_summary="Imported from DB as Copy")
                        if is_key:
                            results["imported_keys"] += 1
                        else:
                            results["imported_credentials"] += 1
                        continue

                database.save_entry(entry, session_key, change_summary="Imported from DB")
                existing_by_title[norm_title] = entry
                existing_by_id[entry.id] = entry
                if is_key:
                    results["imported_keys"] += 1
                else:
                    results["imported_credentials"] += 1

            if import_files:
                try:
                    src_files = src_db.get_all_files(source_key)
                    for sf in src_files:
                        content = src_db.read_file_bytes(sf.id, source_key)
                        if content is not None:
                            new_vf = VaultFile(
                                filename=sf.filename,
                                file_size=len(content),
                                mime_type=sf.mime_type,
                                tags=list(sf.tags),
                                notes=sf.notes,
                            )
                            database.save_file(new_vf, content, session_key)
                            results["imported_files"] += 1
                except Exception as ex:
                    results["errors"].append(f"DB file import error: {ex}")

        # Case E: JSON Vault Export (.json)
        elif ftype == "json":
            j_data = import_metadata.get("json_data", {})
            entries_list = j_data.get("entries", j_data.get("items", [])) if isinstance(j_data, dict) else []
            import uuid
            from starvault.versioning import apply_version_to_entry

            for raw in entries_list:
                if not isinstance(raw, dict):
                    continue
                etype = raw.get("entry_type", "service")
                is_key = (etype == "keypair")
                if is_key and not import_keys:
                    continue
                if not is_key and not import_credentials:
                    continue

                title = raw.get("title", "").strip() or "Imported JSON Item"
                norm_title = title.lower()
                target_id = raw.get("id")
                existing = existing_by_title.get(norm_title) or existing_by_id.get(target_id)

                if existing:
                    if conflict_strategy == "skip":
                        results["skipped_credentials"] += 1
                        continue
                    elif conflict_strategy == "overwrite":
                        entry = existing
                        apply_version_to_entry(entry, raw)
                        entry.updated_at = utc_now_iso()
                        database.save_entry(entry, session_key, change_summary="Imported from JSON (Overwritten)")
                        results["overwritten_credentials"] += 1
                        continue
                    else:  # copy
                        entry = VaultEntry(id=str(uuid.uuid4()))
                        apply_version_to_entry(entry, raw)
                        entry.id = str(uuid.uuid4())
                        entry.title = f"{title} (Imported)"
                        entry.created_at = utc_now_iso()
                        entry.updated_at = utc_now_iso()
                        database.save_entry(entry, session_key, change_summary="Imported from JSON as Copy")
                        if is_key:
                            results["imported_keys"] += 1
                        else:
                            results["imported_credentials"] += 1
                        continue

                entry = VaultEntry(id=target_id or str(uuid.uuid4()))
                apply_version_to_entry(entry, raw)
                database.save_entry(entry, session_key, change_summary="Imported from JSON")
                existing_by_title[norm_title] = entry
                existing_by_id[entry.id] = entry
                if is_key:
                    results["imported_keys"] += 1
                else:
                    results["imported_credentials"] += 1

        database.trigger_backup()
        total_items = results["imported_credentials"] + results["imported_keys"] + results["imported_files"]
        msg = (
            f"Import complete! {total_items} items imported ({results['imported_credentials']} credentials, "
            f"{results['imported_keys']} keys, {results['imported_files']} files). "
            f"Skipped: {results['skipped_credentials']}, Overwritten: {results['overwritten_credentials']}."
        )
        return True, msg, results

    except Exception as ex:
        return False, f"Import failed: {str(ex)}", results


def _import_csv_text(
    csv_text: str,
    database: Database,
    session_key: bytes,
    existing_by_title: Dict[str, VaultEntry],
    conflict_strategy: str,
    results: Dict[str, Any],
) -> None:
    """Parses credentials CSV and saves entries into database."""
    reader = csv.reader(io.StringIO(csv_text))
    header = None

    for row in reader:
        if not header:
            header = [c.strip().lower() for c in row]
            continue
        if not row or not any(row):
            continue

        row_dict = {}
        for idx, col in enumerate(header):
            if idx < len(row):
                row_dict[col] = row[idx].lstrip("'")

        title = row_dict.get("title", "").strip() or "Imported CSV Login"
        norm_title = title.lower()
        existing = existing_by_title.get(norm_title)

        if existing:
            if conflict_strategy == "skip":
                results["skipped_credentials"] += 1
                continue
            elif conflict_strategy == "overwrite":
                entry = existing
            else:
                entry = VaultEntry(title=f"{title} (Imported)")
        else:
            entry = VaultEntry(title=title)

        entry.entry_type = row_dict.get("type", "service")
        entry.category = row_dict.get("category", "General")
        entry.username = row_dict.get("username", "")
        entry.password = row_dict.get("password", "")
        entry.hostname = row_dict.get("hostname", "")
        entry.url = row_dict.get("url", "")
        entry.api_token = row_dict.get("api key / token", "")
        entry.expires_at = row_dict.get("expires at", "")
        entry.totp_secret = row_dict.get("totp secret", "")
        entry.notes = row_dict.get("notes", "")

        if "domain name" in row_dict and row_dict["domain name"]:
            entry.domain_name = row_dict["domain name"]
        if "registrar" in row_dict and row_dict["registrar"]:
            entry.registrar = row_dict["registrar"]
        if "auto renew" in row_dict and row_dict["auto renew"]:
            entry.auto_renew = row_dict["auto renew"].lower() in ("true", "1", "yes")
        if "dns provider" in row_dict and row_dict["dns provider"]:
            entry.dns_provider = row_dict["dns provider"]
        if "nameservers" in row_dict and row_dict["nameservers"]:
            entry.nameservers = row_dict["nameservers"]
        if "auth / epp code" in row_dict and row_dict["auth / epp code"]:
            entry.auth_code = row_dict["auth / epp code"]
        elif "auth code" in row_dict and row_dict["auth code"]:
            entry.auth_code = row_dict["auth code"]
        if "parent domain id" in row_dict and row_dict["parent domain id"]:
            entry.parent_domain_id = row_dict["parent domain id"]
        if "parent server id" in row_dict and row_dict["parent server id"]:
            entry.parent_server_id = row_dict["parent server id"]

        port_str = row_dict.get("port", "")
        if port_str and port_str.isdigit():
            entry.port = int(port_str)

        tags_str = row_dict.get("tags", "")
        if tags_str:
            entry.tags = [t.strip() for t in tags_str.split(",") if t.strip()]

        database.save_entry(entry, session_key, change_summary="Imported from CSV")
        existing_by_title[norm_title] = entry
        results["imported_credentials"] += 1


def export_vault_archive_zip(
    database: Database,
    session_key: bytes,
    target_path: Union[str, Path],
    include_csv: bool = True,
    include_keys: bool = True,
    include_files: bool = True,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Exports vault contents into a structured .zip archive using active session key."""
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "credentials_count": 0,
        "files_count": 0,
        "keys_count": 0,
        "target_file": str(target),
    }

    try:
        from starvault.export_utils import export_entries_to_csv_string

        all_entries = database.get_all_entries(session_key)

        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. Credentials CSV
            if include_csv:
                csv_entries = [e for e in all_entries if e.entry_type != "keypair"] if not include_keys else all_entries
                csv_str = export_entries_to_csv_string(csv_entries)
                zf.writestr("credentials.csv", csv_str.encode("utf-8"))
                summary["credentials_count"] = len(csv_entries)

            # 2. Keypair individual files
            if include_keys:
                from starvault.keys import export_key_armored
                keypairs = [e for e in all_entries if e.entry_type == "keypair"]
                for kp in keypairs:
                    base_name = "".join(c for c in kp.title if c.isalnum() or c in "-_") or f"key_{kp.id[:8]}"
                    kt = getattr(kp, "key_type", "").lower()

                    # Public key / cert
                    pub_content = getattr(kp, "public_key", "")
                    if pub_content:
                        ext = ".crt" if "tls" in kt or "cert" in kt else (".asc" if "gpg" in kt else ".pub")
                        zf.writestr(f"keys/{base_name}{ext}", pub_content.encode("utf-8"))

                    # Private key
                    priv_content = getattr(kp, "private_key", "") or getattr(kp, "password", "")
                    if priv_content:
                        ext = ".key" if "tls" in kt else (".asc" if "gpg" in kt else ".pem")
                        zf.writestr(f"keys/{base_name}{ext}", priv_content.encode("utf-8"))

                    summary["keys_count"] += 1

            # 3. Vault Files
            if include_files:
                vault_files = database.get_all_files(session_key)
                for vf in vault_files:
                    f_bytes = database.read_file_bytes(vf.id, session_key)
                    if f_bytes is not None:
                        safe_name = Path(vf.filename).name
                        zf.writestr(f"files/{safe_name}", f_bytes)
                        summary["files_count"] += 1

            # 4. Manifest
            manifest = {
                "app_version": APP_VERSION,
                "exported_at": utc_now_iso(),
                "summary": summary,
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2).encode("utf-8"))

        msg = (
            f"Archive created successfully ({summary['credentials_count']} credentials, "
            f"{summary['keys_count']} keys, {summary['files_count']} files)"
        )
        return True, msg, summary

    except Exception as ex:
        return False, f"Archive creation failed: {str(ex)}", summary

