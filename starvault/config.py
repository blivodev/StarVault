"""Configuration and application paths for StarVault."""

import os
import sys
from pathlib import Path

APP_NAME = "StarVault"
APP_VERSION = "1.0.0"
APP_SUBTITLE = "Secure Credential & Key Vault for Homelabs & VPS"

# Directory paths
# Checks for local portable database first, otherwise user's home directory
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).parent.resolve()
else:
    APP_DIR = Path(__file__).parent.parent.resolve()

LOCAL_DB_FILE = (APP_DIR / "starvault.db").resolve()

if os.name == "nt":
    DEFAULT_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
else:
    DEFAULT_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "starvault"

def get_default_db_path() -> Path:
    """Returns portable database path if starvault.db exists in cwd, otherwise default app data path."""
    if LOCAL_DB_FILE.exists():
        return LOCAL_DB_FILE
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_DATA_DIR / "starvault.db"

def get_default_keys_dir() -> Path:
    """Returns the dedicated directory where physical key files are stored and managed."""
    keys_dir = DEFAULT_DATA_DIR / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    return keys_dir

# KDF Parameters (Argon2id RFC 9106 recommended)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 256 bits

# Canary token for verifying master password without storing hashes
CANARY_PLAINTEXT = b"STARVAULT-VAULT-CANARY-v1"

# Defaults
DEFAULT_CLIPBOARD_TIMEOUT_SEC = 30
DEFAULT_AUTOLOCK_TIMEOUT_SEC = 300  # 5 minutes
DEFAULT_LOCK_ON_MINIMIZE = True
