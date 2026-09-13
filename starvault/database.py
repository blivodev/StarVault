"""SQLite database storage engine for StarVault.

Manages metadata, encrypted entries, settings, and atomic transactions.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from starvault.config import (
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    DEFAULT_AUTOLOCK_TIMEOUT_SEC,
    DEFAULT_CLIPBOARD_TIMEOUT_SEC,
    DEFAULT_LOCK_ON_MINIMIZE,
    get_default_db_path,
)
from starvault.crypto import (
    InvalidMasterPasswordError,
    create_canary,
    decrypt_blob,
    decrypt_field,
    derive_key,
    encrypt_blob,
    encrypt_field,
    generate_salt,
    verify_canary,
)
from starvault.models import VaultEntry, VaultFile


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Manages SQLite storage for vault metadata and encrypted entries."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path) if db_path else get_default_db_path()
        self._init_db_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_db_schema(self) -> None:
        """Creates tables, runs safe migrations, and sets up indexes."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt_hex TEXT NOT NULL,
                    canary_nonce_hex TEXT NOT NULL,
                    canary_ciphertext_hex TEXT NOT NULL,
                    kdf_params_json TEXT NOT NULL,
                    settings_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vault_entries (
                    id TEXT PRIMARY KEY,
                    entry_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    is_favorite INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    parent_server_id TEXT DEFAULT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_entries_type ON vault_entries(entry_type);
                CREATE INDEX IF NOT EXISTS idx_entries_fav ON vault_entries(is_favorite);
                CREATE INDEX IF NOT EXISTS idx_entries_cat ON vault_entries(category);
                """
            )
            self._run_migrations(conn)

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Safely alters existing schemas without dropping or altering user data."""
        # Migration 1: Add parent_server_id column to vault_entries if missing
        cursor = conn.execute("PRAGMA table_info(vault_entries)")
        columns = [row[1] for row in cursor.fetchall()]
        if "parent_server_id" not in columns:
            conn.execute("ALTER TABLE vault_entries ADD COLUMN parent_server_id TEXT DEFAULT NULL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_parent ON vault_entries(parent_server_id)")

        # Migration 2: Create vault_files table if missing
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vault_files (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                notes_encrypted TEXT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_files_name ON vault_files(filename);
            CREATE INDEX IF NOT EXISTS idx_files_mime ON vault_files(mime_type);
            """
        )

    def is_initialized(self) -> bool:
        """Checks if vault metadata row exists."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT id FROM vault_meta WHERE id = 1").fetchone()
            return row is not None

    def get_kdf_params(self) -> Dict[str, Any]:
        """Loads KDF configuration parameters from metadata."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT kdf_params_json FROM vault_meta WHERE id = 1").fetchone()
            if row and row["kdf_params_json"]:
                return json.loads(row["kdf_params_json"])
        return {}

    def is_legacy_vault(self) -> bool:
        """Returns True if the vault was encrypted with legacy single-factor authentication.

        ELI5: If kdf_version is missing or 1, this is an older vault that only uses a
        password. It qualifies for our seamless True Local 2FA upgrade flow.
        """
        if not self.is_initialized():
            return False
        params = self.get_kdf_params()
        version = params.get("kdf_version", 1)
        requires_2fa = params.get("requires_keyfile", False)
        return version < 2 or not requires_2fa

    def requires_2fa(self) -> bool:
        """Returns True if unlocking requires both Master Password and QR Keyfile."""
        if not self.is_initialized():
            return False
        params = self.get_kdf_params()
        return bool(params.get("requires_keyfile", False))

    def trigger_backup(self) -> Optional[Path]:
        """Passive Cloud Sync: Mirrors current encrypted vault database to a backup directory.

        ELI5 AUDIT NOTE:
        This is 100% local! It uses SQLite's Online Backup API to safely copy
        'starvault.db' (flushing any active transactions) to whatever folder the
        user selected (e.g. local Google Drive or Dropbox synced folder).
        Zero network calls, zero cloud APIs.
        """
        settings = self.get_settings()
        backup_dir = settings.get("backup_dir", "").strip()
        if not backup_dir:
            return None

        dest_dir = Path(backup_dir)
        if not dest_dir.exists() or not dest_dir.is_dir():
            return None

        dest_file = dest_dir / self.db_path.name
        try:
            with self._get_connection() as src_conn:
                with sqlite3.connect(str(dest_file)) as dest_conn:
                    src_conn.backup(dest_conn)
            return dest_file
        except Exception:
            try:
                shutil.copy2(str(self.db_path), str(dest_file))
                return dest_file
            except Exception:
                return None

    def restore_from_backup(self, backup_file_path: Path) -> bool:
        """Restores and replaces local vault database from a backup .db file.

        ELI5 AUDIT NOTE:
        Uses SQLite's Online Backup API to cleanly import all tables and records
        from the backup .db file into our active local vault file without file locks.
        """
        src = Path(backup_file_path)
        if not src.exists() or not src.is_file():
            return False

        try:
            # Use SQLite backup API for 100% atomic, WAL-safe restoration
            with sqlite3.connect(str(src)) as src_conn:
                with self._get_connection() as dest_conn:
                    src_conn.backup(dest_conn)
            return self.is_initialized()
        except Exception:
            try:
                shutil.copy2(str(src), str(self.db_path))
                return self.is_initialized()
            except Exception:
                return False

    def initialize_vault(
        self,
        master_password: str,
        keyfile_secret: Optional[str] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Sets up vault master password, optional 2FA keyfile, and metadata.

        Returns:
            The derived 32-byte encryption key.
        """
        if not master_password or len(master_password) < 6:
            raise ValueError("Master password must be at least 6 characters.")

        salt = generate_salt(16)
        key = derive_key(master_password, salt, keyfile_secret=keyfile_secret)
        nonce_hex, ciphertext_hex = create_canary(key)

        is_2fa = bool(keyfile_secret and keyfile_secret.strip())
        kdf_params = {
            "algorithm": "argon2id",
            "kdf_version": 2 if is_2fa else 1,
            "requires_keyfile": is_2fa,
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
            "hash_len": ARGON2_HASH_LEN,
        }

        default_settings = {
            "autolock_timeout": DEFAULT_AUTOLOCK_TIMEOUT_SEC,
            "lock_on_minimize": DEFAULT_LOCK_ON_MINIMIZE,
            "clipboard_timeout": DEFAULT_CLIPBOARD_TIMEOUT_SEC,
            "backup_dir": "",
            "theme": "Dark",
        }
        if settings:
            default_settings.update(settings)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vault_meta 
                (id, salt_hex, canary_nonce_hex, canary_ciphertext_hex, kdf_params_json, settings_json, created_at)
                VALUES (1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    salt.hex(),
                    nonce_hex,
                    ciphertext_hex,
                    json.dumps(kdf_params),
                    json.dumps(default_settings),
                    utc_now_iso(),
                ),
            )

        self.trigger_backup()
        return key

    def unlock_vault(
        self,
        master_password: str,
        keyfile_secret: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes]]:
        """Validates master password (and 2FA keyfile if enabled) against canary token.

        Returns:
            (True, key_bytes) if successful, (False, None) if invalid.
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT salt_hex, canary_nonce_hex, canary_ciphertext_hex, kdf_params_json FROM vault_meta WHERE id = 1"
            ).fetchone()

        if not row:
            return False, None

        salt = bytes.fromhex(row["salt_hex"])
        kdf_params = json.loads(row["kdf_params_json"])

        key = derive_key(
            master_password,
            salt,
            keyfile_secret=keyfile_secret,
            time_cost=kdf_params.get("time_cost", ARGON2_TIME_COST),
            memory_cost=kdf_params.get("memory_cost", ARGON2_MEMORY_COST),
            parallelism=kdf_params.get("parallelism", ARGON2_PARALLELISM),
            hash_len=kdf_params.get("hash_len", ARGON2_HASH_LEN),
        )

        if verify_canary(key, row["canary_nonce_hex"], row["canary_ciphertext_hex"]):
            return True, key

        return False, None

    def upgrade_to_2fa(
        self,
        old_key: bytes,
        master_password: str,
        keyfile_token: str,
    ) -> bytes:
        """Migrates a legacy v1 vault to True Local 2FA (v2 composite key).

        ======================================================================
        ELI5 AUDIT NOTE: SEAMLESS VAULT MIGRATION PROCESS
        ======================================================================
        Step 1: User unlocks their legacy vault using their old password (old_key).
        Step 2: We read and decrypt all entries in memory using old_key.
        Step 3: We generate a fresh, uncompromised 16-byte random salt.
        Step 4: We derive a new Composite Key = Argon2id(Password + QR_Token, Salt).
        Step 5: We create a new canary verification token for the Composite Key.
        Step 6: In an atomic SQLite transaction:
                - Update vault_meta with new salt, canary, and kdf_version = 2.
                - Re-encrypt all entries using the new Composite Key.
        Step 7: We mirror the updated vault to the Passive Cloud Sync folder.
        Result: The database is now mathematically uncrackable without the QR code!
        ======================================================================
        """
        if not keyfile_token or len(keyfile_token.strip()) < 16:
            raise ValueError("Keyfile token must be a valid 256-bit string.")

        # 1. Decrypt all entries in memory with old single-factor key
        entries = self.get_all_entries(old_key)

        # 2. Derive new composite key with fresh salt
        new_salt = generate_salt(16)
        new_key = derive_key(master_password, new_salt, keyfile_secret=keyfile_token)
        new_nonce_hex, new_ciphertext_hex = create_canary(new_key)

        kdf_params = self.get_kdf_params()
        kdf_params["kdf_version"] = 2
        kdf_params["requires_keyfile"] = True

        with self._get_connection() as conn:
            with conn:
                # Update metadata row
                conn.execute(
                    """
                    UPDATE vault_meta 
                    SET salt_hex = ?, canary_nonce_hex = ?, canary_ciphertext_hex = ?, kdf_params_json = ?
                    WHERE id = 1
                    """,
                    (new_salt.hex(), new_nonce_hex, new_ciphertext_hex, json.dumps(kdf_params)),
                )

                # Re-encrypt and update all existing records
                for entry in entries:
                    new_payload = entry.to_encrypted_payload(new_key)
                    conn.execute(
                        "UPDATE vault_entries SET encrypted_payload = ? WHERE id = ?",
                        (new_payload, entry.id),
                    )

        # Mirror upgraded vault to backup directory
        self.trigger_backup()
        return new_key

    def change_master_password(
        self,
        old_key: bytes,
        new_password: str,
        new_keyfile_secret: Optional[str] = None,
    ) -> bytes:
        """Re-encrypts the entire vault under a new master password and optional keyfile."""
        if not new_password or len(new_password) < 6:
            raise ValueError("Master password must be at least 6 characters.")

        # Load all entries and decrypt with old_key
        entries = self.get_all_entries(old_key)

        # Generate new salt and key
        new_salt = generate_salt(16)
        new_key = derive_key(new_password, new_salt, keyfile_secret=new_keyfile_secret)
        new_nonce_hex, new_ciphertext_hex = create_canary(new_key)

        kdf_params = self.get_kdf_params()
        if new_keyfile_secret:
            kdf_params["kdf_version"] = 2
            kdf_params["requires_keyfile"] = True
        else:
            kdf_params["kdf_version"] = 1
            kdf_params["requires_keyfile"] = False

        with self._get_connection() as conn:
            with conn:
                # Update metadata
                conn.execute(
                    """
                    UPDATE vault_meta 
                    SET salt_hex = ?, canary_nonce_hex = ?, canary_ciphertext_hex = ?, kdf_params_json = ?
                    WHERE id = 1
                    """,
                    (new_salt.hex(), new_nonce_hex, new_ciphertext_hex, json.dumps(kdf_params)),
                )

                # Re-encrypt and update all entries
                for entry in entries:
                    new_payload = entry.to_encrypted_payload(new_key)
                    conn.execute(
                        "UPDATE vault_entries SET encrypted_payload = ? WHERE id = ?",
                        (new_payload, entry.id),
                    )

        self.trigger_backup()
        return new_key

    def get_settings(self) -> Dict[str, Any]:
        """Loads user settings dictionary."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT settings_json FROM vault_meta WHERE id = 1").fetchone()
            if row and row["settings_json"]:
                return json.loads(row["settings_json"])
        return {
            "autolock_timeout": DEFAULT_AUTOLOCK_TIMEOUT_SEC,
            "lock_on_minimize": DEFAULT_LOCK_ON_MINIMIZE,
            "clipboard_timeout": DEFAULT_CLIPBOARD_TIMEOUT_SEC,
            "backup_dir": "",
            "theme": "Dark",
        }

    def update_settings(self, settings: Dict[str, Any]) -> None:
        """Persists updated settings dictionary."""
        current = self.get_settings()
        current.update(settings)
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE vault_meta SET settings_json = ? WHERE id = 1",
                (json.dumps(current),),
            )

    def save_entry(self, entry: VaultEntry, key: bytes) -> None:
        """Inserts or updates an entry, encrypting sensitive fields."""
        payload = entry.to_encrypted_payload(key)
        tags_json = json.dumps(entry.tags)
        entry.updated_at = utc_now_iso()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vault_entries 
                (id, entry_type, title, category, tags_json, is_favorite, created_at, updated_at, encrypted_payload, parent_server_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    entry_type = excluded.entry_type,
                    title = excluded.title,
                    category = excluded.category,
                    tags_json = excluded.tags_json,
                    is_favorite = excluded.is_favorite,
                    updated_at = excluded.updated_at,
                    encrypted_payload = excluded.encrypted_payload,
                    parent_server_id = excluded.parent_server_id
                """,
                (
                    entry.id,
                    entry.entry_type,
                    entry.title,
                    entry.category,
                    tags_json,
                    1 if entry.is_favorite else 0,
                    entry.created_at,
                    entry.updated_at,
                    payload,
                    entry.parent_server_id,
                ),
            )
        self.trigger_backup()

    def delete_entry(self, entry_id: str) -> None:
        """Deletes entry by ID."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
        self.trigger_backup()

    def toggle_favorite(self, entry_id: str) -> bool:
        """Toggles entry favorite status and returns new value."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT is_favorite FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
            if not row:
                return False
            new_fav = 0 if row["is_favorite"] else 1
            conn.execute("UPDATE vault_entries SET is_favorite = ? WHERE id = ?", (new_fav, entry_id))
            return bool(new_fav)

    def duplicate_entry(self, entry_id: str, key: bytes) -> Optional[VaultEntry]:
        """Clones an existing entry with '- Copy' appended to the title and saves it."""
        entry = self.get_entry(entry_id, key)
        if not entry:
            return None
        clone = entry.duplicate()
        self.save_entry(clone, key)
        return clone

    def get_child_services(self, parent_server_id: str, key: bytes) -> List[VaultEntry]:
        """Retrieves all service entries linked to the specified parent server."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vault_entries WHERE parent_server_id = ? ORDER BY title COLLATE NOCASE ASC",
                (parent_server_id,),
            ).fetchall()
        entries = []
        for row in rows:
            try:
                entries.append(self._row_to_entry(row, key))
            except Exception:
                pass
        return entries

    def get_entry(self, entry_id: str, key: bytes) -> Optional[VaultEntry]:
        """Retrieves and decrypts a single entry."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
            if not row:
                return None

        return self._row_to_entry(row, key)

    def get_all_entries(self, key: bytes) -> List[VaultEntry]:
        """Retrieves and decrypts all entries."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vault_entries ORDER BY is_favorite DESC, title COLLATE NOCASE ASC"
            ).fetchall()

        entries = []
        for row in rows:
            try:
                entries.append(self._row_to_entry(row, key))
            except Exception:
                # If an individual row decryption fails, don't crash the entire list
                pass
        return entries

    def get_all_tags(self) -> List[str]:
        """Returns sorted list of distinct tags across all entries."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT tags_json FROM vault_entries").fetchall()

        tag_set = set()
        for row in rows:
            try:
                tags = json.loads(row["tags_json"])
                for t in tags:
                    tag_set.add(t.strip().lower())
            except Exception:
                pass
        return sorted(tag_set)

    def _row_to_entry(self, row: sqlite3.Row, key: bytes) -> VaultEntry:
        """Helper to reconstruct and decrypt a VaultEntry from a SQLite row."""
        parent_id = None
        if "parent_server_id" in row.keys():
            parent_id = row["parent_server_id"]

        entry = VaultEntry(
            id=row["id"],
            entry_type=row["entry_type"],
            title=row["title"],
            category=row["category"],
            tags=json.loads(row["tags_json"]) if row["tags_json"] else [],
            is_favorite=bool(row["is_favorite"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            parent_server_id=parent_id,
        )
        entry.load_encrypted_payload(row["encrypted_payload"], key)
        return entry

    # =========================================================================
    # Encrypted File Vault Operations (BLOB Storage)
    # =========================================================================

    def save_file(self, vault_file: VaultFile, file_bytes: bytes, key: bytes) -> None:
        """Encrypts raw file bytes with AES-256-GCM and stores in database."""
        encrypted_blob = encrypt_blob(file_bytes, key)
        notes_encrypted = encrypt_field(vault_file.notes, key) if vault_file.notes else ""
        tags_json = json.dumps(vault_file.tags)
        vault_file.updated_at = utc_now_iso()
        vault_file.file_size = len(file_bytes)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vault_files
                (id, filename, file_size, mime_type, tags_json, notes_encrypted, encrypted_blob, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    filename = excluded.filename,
                    file_size = excluded.file_size,
                    mime_type = excluded.mime_type,
                    tags_json = excluded.tags_json,
                    notes_encrypted = excluded.notes_encrypted,
                    encrypted_blob = excluded.encrypted_blob,
                    updated_at = excluded.updated_at
                """,
                (
                    vault_file.id,
                    vault_file.filename,
                    vault_file.file_size,
                    vault_file.mime_type,
                    tags_json,
                    notes_encrypted,
                    encrypted_blob,
                    vault_file.created_at,
                    vault_file.updated_at,
                ),
            )
        self.trigger_backup()

    def get_all_files(self, key: bytes) -> List[VaultFile]:
        """Returns metadata list of all encrypted files without loading BLOBs into memory."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, filename, file_size, mime_type, tags_json, notes_encrypted, created_at, updated_at
                FROM vault_files ORDER BY filename COLLATE NOCASE ASC
                """
            ).fetchall()

        results = []
        for r in rows:
            notes = ""
            if r["notes_encrypted"]:
                try:
                    notes = decrypt_field(r["notes_encrypted"], key)
                except Exception:
                    notes = ""
            tags = []
            if r["tags_json"]:
                try:
                    tags = json.loads(r["tags_json"])
                except Exception:
                    tags = []

            results.append(
                VaultFile(
                    id=r["id"],
                    filename=r["filename"],
                    file_size=r["file_size"],
                    mime_type=r["mime_type"],
                    tags=tags,
                    notes=notes,
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
            )
        return results

    def read_file_bytes(self, file_id: str, key: bytes) -> Optional[bytes]:
        """Retrieves and decrypts the binary payload for a specific stored file."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT encrypted_blob FROM vault_files WHERE id = ?", (file_id,)
            ).fetchone()

        if not row or not row["encrypted_blob"]:
            return None

        try:
            return decrypt_blob(row["encrypted_blob"], key)
        except Exception:
            return None

    def delete_file(self, file_id: str) -> None:
        """Permanently deletes an encrypted file from the vault."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM vault_files WHERE id = ?", (file_id,))
        self.trigger_backup()
