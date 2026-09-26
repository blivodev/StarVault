"""Version control and retention management system for StarVault credentials and keys.

Provides:
- Zero-knowledge historical snapshots of vault entries (passwords, SSH/GPG keys, API tokens).
- Version comparison, rollback, and restoration utilities.
- Retention rules and automated pruning with age filters (days, months, years).
- Safe cleanup of physical key files (.pem, .pub, .ppk, .key, .crt, .asc) on disk.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid

from starvault.config import get_default_keys_dir
from starvault.crypto import decrypt_field, encrypt_field
from starvault.models import VaultEntry, utc_now_iso


# Standard extensions for cryptographic key, certificate, and armored files
VALID_KEY_EXTENSIONS = {
    ".pub",
    ".pem",
    ".ppk",
    ".key",
    ".crt",
    ".asc",
    ".cert",
    ".priv",
    ".der",
    ".gpg",
    ".pgp",
    ".age",
}


@dataclass
class VaultEntryVersion:
    """Represents an immutable, encrypted snapshot of a vault entry at a point in time."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entry_id: str = ""
    version_num: int = 1
    secret_type: str = "password"  # 'password', 'keypair', 'api_token', 'credentials'
    title: str = ""
    encrypted_data: str = ""  # AES-256-GCM encrypted JSON payload
    change_summary: str = ""
    associated_files: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    decrypted_data: Optional[Dict[str, Any]] = None

    def get_decrypted_data(self, key: bytes) -> Dict[str, Any]:
        """Decrypts and returns the snapshot payload dictionary."""
        if self.decrypted_data is not None:
            return self.decrypted_data
        if not self.encrypted_data:
            self.decrypted_data = {}
            return self.decrypted_data
        json_str = decrypt_field(self.encrypted_data, key)
        self.decrypted_data = json.loads(json_str)
        return self.decrypted_data

    def to_dict(self) -> Dict[str, Any]:
        """Returns JSON-serializable dictionary representation."""
        res = {
            "id": self.id,
            "entry_id": self.entry_id,
            "version_num": self.version_num,
            "secret_type": self.secret_type,
            "title": self.title,
            "change_summary": self.change_summary,
            "associated_files": list(self.associated_files),
            "created_at": self.created_at,
        }
        if self.decrypted_data is not None:
            res["data"] = self.decrypted_data
        return res


@dataclass
class CleanVersionsResult:
    """Summary result of a version and physical key file pruning operation."""

    versions_deleted: int = 0
    physical_files_deleted: int = 0
    entries_affected: int = 0
    deleted_version_ids: List[str] = field(default_factory=list)
    deleted_file_paths: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    dry_run: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "versions_deleted": self.versions_deleted,
            "physical_files_deleted": self.physical_files_deleted,
            "entries_affected": self.entries_affected,
            "deleted_version_ids": self.deleted_version_ids,
            "deleted_file_paths": self.deleted_file_paths,
            "details": self.details,
            "dry_run": self.dry_run,
        }


def parse_retention_days(value: int, unit: str = "days") -> int:
    """Converts a retention interval (value + unit) into days.

    Supported units: 'days', 'day', 'months', 'month', 'years', 'year'.
    """
    v = max(1, int(value))
    u = unit.lower().strip().rstrip("s")
    if u == "month":
        return v * 30
    elif u == "year":
        return v * 365
    return v  # default is days


def compute_secret_fingerprint(entry: VaultEntry) -> str:
    """Generates a SHA-256 digest of an entry's sensitive and core credential values.

    Used to detect genuine secret rotations vs superficial metadata updates.
    """
    sensitive_vals = [
        entry.entry_type,
        entry.title,
        entry.hostname,
        str(entry.port),
        entry.username,
        entry.password,
        entry.sudo_password,
        entry.ssh_private_key,
        entry.ssh_public_key,
        entry.app_name,
        entry.url,
        entry.api_token,
        entry.key_name,
        entry.key_type,
        entry.public_key,
        entry.private_key,
        entry.passphrase,
        entry.provider,
        entry.api_key_secret,
        entry.totp_secret,
        getattr(entry, "auth_code", ""),
        getattr(entry, "domain_name", ""),
        getattr(entry, "registrar", ""),
        getattr(entry, "expires_at", ""),
        getattr(entry, "registered_at", ""),
        getattr(entry, "renewal_cost", ""),
        str(getattr(entry, "auto_renew", False)),
        getattr(entry, "dns_provider", ""),
        getattr(entry, "nameservers", ""),
        getattr(entry, "parent_domain_id", "") or "",
        entry.notes,
        json.dumps(entry.custom_fields, sort_keys=True),
    ]
    raw = "|".join(sensitive_vals).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def detect_change_summary(
    old_data: Optional[Dict[str, Any]],
    current_entry: VaultEntry,
) -> str:
    """Produces a descriptive human-readable summary of what changed in this version."""
    if not old_data:
        if current_entry.entry_type == "keypair":
            return f"Initial keypair ({current_entry.key_type.upper()})"
        elif current_entry.entry_type == "apikey":
            return f"Initial API key ({current_entry.provider or 'Standard'})"
        elif current_entry.entry_type == "domain":
            return f"Initial domain ({current_entry.registrar or 'Self-managed'})"
        return "Initial credential version"

    changes = []
    if current_entry.password != old_data.get("password", ""):
        changes.append("Rotated password")
    if current_entry.private_key != old_data.get("private_key", "") or current_entry.public_key != old_data.get("public_key", ""):
        changes.append(f"Updated keypair ({current_entry.key_type.upper()})")
    if current_entry.ssh_private_key != old_data.get("ssh_private_key", "") or current_entry.ssh_public_key != old_data.get("ssh_public_key", ""):
        changes.append("Updated SSH credentials")
    if current_entry.api_token != old_data.get("api_token", "") or current_entry.api_key_secret != old_data.get("api_key_secret", ""):
        changes.append("Updated API token/secret")
    if current_entry.totp_secret != old_data.get("totp_secret", ""):
        changes.append("Updated 2FA TOTP secret")
    if current_entry.username != old_data.get("username", ""):
        changes.append("Updated username")
    if current_entry.hostname != old_data.get("hostname", "") or current_entry.url != old_data.get("url", ""):
        changes.append("Updated endpoint/host")
    if current_entry.notes != old_data.get("notes", ""):
        changes.append("Updated notes")
    if current_entry.registrar != old_data.get("registrar", ""):
        changes.append("Updated registrar")
    if current_entry.expires_at != old_data.get("expires_at", ""):
        changes.append("Updated expiry date")
    if current_entry.auto_renew != old_data.get("auto_renew", False):
        changes.append("Toggled auto-renew")
    if current_entry.dns_provider != old_data.get("dns_provider", ""):
        changes.append("Updated DNS provider")
    if current_entry.nameservers != old_data.get("nameservers", ""):
        changes.append("Updated nameservers")
    if current_entry.auth_code != old_data.get("auth_code", ""):
        changes.append("Updated transfer auth code")
    if current_entry.parent_domain_id != old_data.get("parent_domain_id", None):
        changes.append("Updated linked domain")
    if getattr(current_entry, "registered_at", "") != old_data.get("registered_at", ""):
        changes.append("Updated registration date")
    if getattr(current_entry, "renewal_cost", "") != old_data.get("renewal_cost", ""):
        changes.append("Updated renewal cost")
    if current_entry.custom_fields != old_data.get("custom_fields", []):
        changes.append("Modified custom fields")

    if not changes:
        return "General configuration update"
    return "; ".join(changes)


def snapshot_entry_data(
    entry: VaultEntry,
    associated_files: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Extracts all state and credentials from an entry into a dictionary for encryption."""
    files_list = list(associated_files) if associated_files else []
    return {
        "id": entry.id,
        "entry_type": entry.entry_type,
        "title": entry.title,
        "category": entry.category,
        "groups": list(entry.groups),
        "services": list(entry.services),
        "tags": list(entry.tags),
        "parent_server_id": entry.parent_server_id,
        "parent_domain_id": entry.parent_domain_id,
        "custom_fields": [dict(cf) for cf in entry.custom_fields],
        "hostname": entry.hostname,
        "port": entry.port,
        "username": entry.username,
        "password": entry.password,
        "ssh_key_id": entry.ssh_key_id,
        "ssh_private_key": entry.ssh_private_key,
        "ssh_public_key": entry.ssh_public_key,
        "sudo_password": entry.sudo_password,
        "os_distro": entry.os_distro,
        "app_name": entry.app_name,
        "url": entry.url,
        "api_token": entry.api_token,
        "db_name": entry.db_name,
        "service_type": entry.service_type,
        "key_name": entry.key_name,
        "key_type": entry.key_type,
        "fingerprint": entry.fingerprint,
        "public_key": entry.public_key,
        "private_key": entry.private_key,
        "passphrase": entry.passphrase,
        "provider": entry.provider,
        "api_key_format": entry.api_key_format,
        "api_key_secret": entry.api_key_secret,
        "environment": entry.environment,
        "expires_at": entry.expires_at,
        "scopes": entry.scopes,
        "totp_secret": entry.totp_secret,
        "domain_name": getattr(entry, "domain_name", ""),
        "registrar": getattr(entry, "registrar", ""),
        "auto_renew": getattr(entry, "auto_renew", False),
        "registered_at": getattr(entry, "registered_at", ""),
        "renewal_cost": getattr(entry, "renewal_cost", ""),
        "dns_provider": getattr(entry, "dns_provider", ""),
        "nameservers": getattr(entry, "nameservers", ""),
        "auth_code": getattr(entry, "auth_code", ""),
        "notes": entry.notes,
        "associated_files": files_list,
        "snapshot_created_at": utc_now_iso(),
    }


def apply_version_to_entry(entry: VaultEntry, data: Dict[str, Any]) -> None:
    """Restores attributes from snapshot data dictionary back onto the live VaultEntry."""
    entry.entry_type = data.get("entry_type", entry.entry_type)
    entry.title = data.get("title", entry.title)
    entry.category = data.get("category", entry.category)
    entry.groups = list(data.get("groups", entry.groups))
    entry.services = list(data.get("services", entry.services))
    entry.tags = list(data.get("tags", entry.tags))
    entry.parent_server_id = data.get("parent_server_id", entry.parent_server_id)
    entry.parent_domain_id = data.get("parent_domain_id", entry.parent_domain_id)
    entry.custom_fields = [dict(cf) for cf in data.get("custom_fields", entry.custom_fields)]

    entry.hostname = data.get("hostname", entry.hostname)
    entry.port = data.get("port", entry.port)
    entry.username = data.get("username", entry.username)
    entry.password = data.get("password", entry.password)
    entry.ssh_key_id = data.get("ssh_key_id", entry.ssh_key_id)
    entry.ssh_private_key = data.get("ssh_private_key", entry.ssh_private_key)
    entry.ssh_public_key = data.get("ssh_public_key", entry.ssh_public_key)
    entry.sudo_password = data.get("sudo_password", entry.sudo_password)
    entry.os_distro = data.get("os_distro", entry.os_distro)

    entry.app_name = data.get("app_name", entry.app_name)
    entry.url = data.get("url", entry.url)
    entry.api_token = data.get("api_token", entry.api_token)
    entry.db_name = data.get("db_name", entry.db_name)
    entry.service_type = data.get("service_type", entry.service_type)

    entry.key_name = data.get("key_name", entry.key_name)
    entry.key_type = data.get("key_type", entry.key_type)
    entry.fingerprint = data.get("fingerprint", entry.fingerprint)
    entry.public_key = data.get("public_key", entry.public_key)
    entry.private_key = data.get("private_key", entry.private_key)
    entry.passphrase = data.get("passphrase", entry.passphrase)

    entry.provider = data.get("provider", entry.provider)
    entry.api_key_format = data.get("api_key_format", entry.api_key_format)
    entry.api_key_secret = data.get("api_key_secret", entry.api_key_secret)
    entry.environment = data.get("environment", entry.environment)
    entry.expires_at = data.get("expires_at", entry.expires_at)
    entry.scopes = data.get("scopes", entry.scopes)
    entry.totp_secret = data.get("totp_secret", entry.totp_secret)
    entry.domain_name = data.get("domain_name", getattr(entry, "domain_name", ""))
    entry.registrar = data.get("registrar", getattr(entry, "registrar", ""))
    entry.auto_renew = bool(data.get("auto_renew", getattr(entry, "auto_renew", False)))
    entry.registered_at = data.get("registered_at", getattr(entry, "registered_at", ""))
    entry.renewal_cost = data.get("renewal_cost", getattr(entry, "renewal_cost", ""))
    entry.dns_provider = data.get("dns_provider", getattr(entry, "dns_provider", ""))
    entry.nameservers = data.get("nameservers", getattr(entry, "nameservers", ""))
    entry.auth_code = data.get("auth_code", getattr(entry, "auth_code", ""))
    entry.notes = data.get("notes", entry.notes)


def delete_physical_key_files(file_paths: Sequence[Union[str, Path]]) -> Tuple[int, List[str]]:
    """Safely and securely removes physical cryptographic key files from disk.

    Validates that:
    1. The target path exists and is a regular file.
    2. The target has an approved key extension or is located inside the StarVault keys directory.

    Returns:
        (deleted_count, list_of_deleted_paths)
    """
    deleted = []
    keys_dir = get_default_keys_dir().resolve()

    for fp in file_paths:
        if not fp:
            continue
        try:
            p = Path(fp).resolve()
            if not p.is_file():
                continue

            # Security check: must reside in keys dir OR have a valid key extension
            is_in_keys_dir = False
            try:
                p.relative_to(keys_dir)
                is_in_keys_dir = True
            except ValueError:
                is_in_keys_dir = False

            ext = p.suffix.lower()
            if not is_in_keys_dir and ext not in VALID_KEY_EXTENSIONS:
                continue

            # Secure zero-overwrite before unlinking if file size <= 10MB
            sz = p.stat().st_size
            if 0 < sz <= 10 * 1024 * 1024:
                try:
                    with open(p, "wb") as f:
                        f.write(os.urandom(sz))
                        f.flush()
                        os.fsync(f.fileno())
                except Exception:
                    pass

            p.unlink(missing_ok=True)
            deleted.append(str(p))
        except Exception:
            pass

    return len(deleted), deleted


def find_stale_physical_key_files(
    keys_dir: Optional[Path] = None,
    max_age_days: int = 90,
) -> List[Path]:
    """Finds physical key files inside the StarVault keys directory older than max_age_days."""
    target_dir = (keys_dir or get_default_keys_dir()).resolve()
    if not target_dir.is_dir():
        return []

    cutoff_time = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    cutoff_timestamp = cutoff_time.timestamp()

    stale_files = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() in VALID_KEY_EXTENSIONS:
                try:
                    mtime = p.stat().st_mtime
                    if mtime < cutoff_timestamp:
                        stale_files.append(p)
                except Exception:
                    pass
    return stale_files


def save_keypair_to_physical_files(
    entry: VaultEntry,
    target_dir: Optional[Path] = None,
    overwrite: bool = True,
) -> List[str]:
    """Writes public and private key files to physical storage and returns the generated paths.

    Stored files are placed in StarVault's dedicated keys directory unless target_dir is specified.
    """
    dest_dir = (target_dir or get_default_keys_dir()).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    safe_title = re.sub(r"[^\w\-.]", "_", entry.title.strip()) or "key"
    written_paths = []

    # Choose extensions based on key_type
    kt = (entry.key_type or "ed25519").lower()
    if "gpg" in kt or "pgp" in kt:
        pub_ext, priv_ext = ".pub.asc", ".asc"
    elif "tls" in kt or "cert" in kt:
        pub_ext, priv_ext = ".crt", ".key"
    elif "age" in kt:
        pub_ext, priv_ext = ".recipient.txt", ".key"
    elif "wireguard" in kt or "wg" in kt:
        pub_ext, priv_ext = ".wg.pub", ".wg.key"
    else:
        pub_ext, priv_ext = ".pub", ".pem"

    if entry.public_key:
        pub_path = dest_dir / f"{safe_title}_{entry.id[:8]}{pub_ext}"
        if overwrite or not pub_path.exists():
            pub_path.write_text(entry.public_key, encoding="utf-8")
            written_paths.append(str(pub_path.resolve()))

    if entry.private_key:
        priv_path = dest_dir / f"{safe_title}_{entry.id[:8]}{priv_ext}"
        if overwrite or not priv_path.exists():
            # Apply strict file permissions where supported
            try:
                priv_path.write_text(entry.private_key, encoding="utf-8")
                if os.name != "nt":
                    os.chmod(priv_path, 0o600)
                written_paths.append(str(priv_path.resolve()))
            except Exception:
                pass

    return written_paths
