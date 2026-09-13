"""Unencrypted local application preferences and OS Credential Manager integration."""

import json
from pathlib import Path
from typing import Dict, List, Optional
import keyring

from starvault.config import DEFAULT_DATA_DIR, LOCAL_DB_FILE


def get_config_file_path() -> Path:
    """Returns path to local starvault_config.json."""
    if LOCAL_DB_FILE.exists():
        return LOCAL_DB_FILE.parent / "starvault_config.json"
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_DATA_DIR / "starvault_config.json"


class AppConfigManager:
    """Manages local recent vault paths and optional OS Credential Manager credentials."""

    SERVICE_NAME = "StarVault_App"

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config_path = config_path or get_config_file_path()
        self.data: Dict = self._load()

    def _load(self) -> Dict:
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "last_vault_path": "",
            "recent_vaults": [],
            "remember_password": False,
        }

    def _save(self) -> None:
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception:
            pass

    def get_last_vault_path(self) -> Optional[Path]:
        """Returns the most recently opened vault path if it exists."""
        last = self.data.get("last_vault_path")
        if last:
            p = Path(last)
            if p.exists():
                return p
        return None

    def get_recent_vaults(self) -> List[Path]:
        """Returns list of existing recent vault paths (up to 5)."""
        recents = self.data.get("recent_vaults", [])
        valid_paths = []
        for r in recents:
            p = Path(r)
            if p.exists() and p not in valid_paths:
                valid_paths.append(p)
        return valid_paths[:5]

    def record_opened_vault(self, db_path: Path) -> None:
        """Adds or moves vault to the top of recent vaults list."""
        path_str = str(Path(db_path).resolve())
        self.data["last_vault_path"] = path_str

        recents = [r for r in self.data.get("recent_vaults", []) if r != path_str]
        recents.insert(0, path_str)
        self.data["recent_vaults"] = recents[:5]
        self._save()

    def remove_recent_vault(self, db_path: Path) -> None:
        """Removes a vault from recent history."""
        path_str = str(Path(db_path).resolve())
        self.data["recent_vaults"] = [r for r in self.data.get("recent_vaults", []) if r != path_str]
        if self.data.get("last_vault_path") == path_str:
            self.data["last_vault_path"] = self.data["recent_vaults"][0] if self.data["recent_vaults"] else ""
        self._save()

    def is_remember_password_enabled(self) -> bool:
        """Checks if user opted into passwordless launch."""
        return bool(self.data.get("remember_password", False))

    def set_remember_password_enabled(self, enabled: bool) -> None:
        """Sets the remember password setting flag."""
        self.data["remember_password"] = bool(enabled)
        self._save()

    def save_vault_credential(
        self,
        db_path: Path,
        master_password: str,
        keyfile_token: Optional[str] = None,
    ) -> bool:
        """Stores master password and optional keyfile in the OS Credential Manager."""
        try:
            payload = {
                "password": master_password,
                "keyfile_token": keyfile_token or "",
            }
            keyring.set_password(self.SERVICE_NAME, str(Path(db_path).resolve()), json.dumps(payload))
            self.set_remember_password_enabled(True)
            return True
        except Exception:
            return False

    def get_saved_vault_credential(self, db_path: Path) -> Optional[Dict[str, str]]:
        """Retrieves saved master password and keyfile from OS Credential Manager if enabled."""
        if not self.is_remember_password_enabled():
            return None
        try:
            raw = keyring.get_password(self.SERVICE_NAME, str(Path(db_path).resolve()))
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    def clear_saved_vault_credential(self, db_path: Path) -> None:
        """Removes stored credentials for this vault from OS Credential Manager."""
        try:
            keyring.delete_password(self.SERVICE_NAME, str(Path(db_path).resolve()))
        except Exception:
            pass
