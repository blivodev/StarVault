# StarVault ★

> **A lightweight, cross-platform (Windows & Linux) desktop credential and key vault designed for VPS instances, self-hosted homelabs, and internal infrastructure.**

Built with **Python**, **CustomTkinter**, **Argon2id**, **AES-256-GCM**, and **SQLite**.

---

## Key Features

### 🛡️ Defense-in-Depth Security & True Local 2FA
- **Argon2id Key Derivation**: Master password derived with RFC 9106 parameters (64 MB memory cost, 3 iterations, 4 threads, 32-byte key length).
- **True Local 2FA (QR Code Keyfile)**: Fuses Master Password with an offline 256-bit random QR Code Keyfile (`keyfile.png`). Unlocking requires both knowledge (Master Password) and possession (physical QR keyfile).
- **Seamless Vault Migration**: Automatically detects legacy vaults (v1), allows initial unlock, and guides the user through an in-memory re-encryption upgrade to True Local 2FA (v2).
- **AES-256-GCM Field & File Encryption**: Sensitive fields (passwords, private keys, API tokens, rich notes) and arbitrary file BLOBs encrypted with unique 12-byte random nonces and 16-byte authentication tags.
- **Canary Validation**: Verifies master password and 2FA keyfile without storing plaintext passwords or hashes on disk.
- **In-Memory Protection**: Cryptographic key bytes in memory are securely zeroed upon lock or exit.
- **100% Offline & Portable**: Single standalone SQLite database (`starvault.db`).

### 🩺 Vault Health & Remediation Advisor
- **In-Memory Security Audit**: Scans decrypted vault in memory and provides an overall health score (0-100) and letter grade (A through F).
- **Vulnerability Checks**:
  - **Duplicate Passwords**: Flags identical passwords reused across different servers and services.
  - **Weak Passwords**: Identifies passwords with low length or low Shannon entropy (< 40 bits).
  - **Accidental Duplicate Names**: Uses fuzzy string matching (`rapidfuzz`) to spot entries with identical or highly similar names.
  - **Stale Passwords**: Alerts when credentials haven't been rotated in over 180 or 365 days.
  - **Expiring Keys & Tokens**: Parses custom fields (e.g. `Expires: 2026-12-31`) to warn of expired or soon-to-expire certificates and licenses.
- **One-Click Remediation**: Each finding features a "Review" button that instantly opens the affected entry in the credentials view.

### 📁 Encrypted File Vault (BLOB Storage)
- **Arbitrary File Storage**: Ingest any file (`.pem`, `.ovpn`, `docker-compose.yml`, `.env`, backup `.zip`).
- **AES-256-GCM BLOB Encryption**: Files are encrypted at rest with the same master vault key and stored as BLOBs within SQLite.
- **In-Memory Previewer**: Text and configuration files can be previewed in-memory and copied to the clipboard with 1 click.
- **Decrypted Extraction**: Safe file dialog extraction of raw decrypted files back to disk.
- **Metadata & Notes**: Search files by filename, tag, or encrypted description.

### 👥 Relational Sub-Credentials & Hierarchy
- **Strict Parent/Child Hierarchy**: Link any number of "Services/Apps" to their parent "Server/VPS".
- **Embedded Sub-Credentials Table**: Viewing a Server entry displays an embedded table showing all hosted services, usernames, masked passwords (`••••••••`), and notes.
- **Sub-Credential Quick-Copy**: Dedicated buttons to copy username, copy password, or jump straight to the child service.
- **Duplicate / Clone Entry**: Clone any entry instantly with "📄 Clone" button or `Ctrl+D` (appends `- Copy` to title).
- **Custom Fields & Timestamps**: Add arbitrary Key-Value pairs (e.g., License Keys, Expiry Dates, PINs). Automatically tracks `Created_At` and `Modified_At` timestamps.

### 🚀 Workflow, Hotkeys & Auto-Load
- **Global Hotkeys**:
  - `Ctrl + C`: Copy selected entry's Password (with 30-second clipboard wipe).
  - `Ctrl + U`: Copy selected entry's Username.
  - `Ctrl + B`: Copy selected entry's URI, IP, or Host.
  - `Ctrl + D`: Duplicate selected entry.
- **Last Vault Auto-Load & Recent Vaults**: Automatically remembers the last successfully opened vault file path in local `starvault_config.json`. Recent Vaults dropdown allows switching vaults effortlessly.
- **Optional Passwordless Launch ("Remember Me")**: Store derived key in the OS Credential Manager (Windows Credential Manager / Linux Secret Service) to bypass master password prompts on startup (includes clear security warning).
- **System Tray Quick-Access**: Minimizes directly to the notification area (next to the Windows clock / Linux tray). Restores window on click.

### 🔄 Passive Cloud Sync (Directory Mirroring)
- **Local Directory Mirroring**: Configure any local folder (e.g. Google Drive, Dropbox, OneDrive, Nextcloud local sync folder).
- **Auto-Backup**: Automatically mirrors the updated, encrypted `.db` file whenever records are created, edited, deleted, or re-encrypted.
- **Zero Cloud APIs**: 100% local filesystem operations via SQLite Online Backup API. No network calls, tokens, or third-party cloud SDKs.
- **Instant Restore**: "🔄 Restore from Backup..." button on the login screen allows restoring/overwriting the active vault from any local backup file.

### ⚡ System Tray & Minimal Fast-Search HUD
- Minimizes directly to the OS system tray (`pystray`).
- Clicking the tray icon instantly brings up a **floating, keyboard-navigable fast-search HUD** (Raycast / Alfred style).
- Type queries, use arrow keys, and press Enter to copy primary credentials, or click quick-copy buttons directly in the search rows.

### 🔍 RapidFuzz & Relational Tagging
- **Relational Matching**: Searching for `"VPS1"` instantly reveals the VPS server **and** all Docker containers, databases (PostgreSQL, Redis), or SSH keys associated with that VPS via tags.
- Non-sensitive metadata (titles, tags, categories) are indexed for blazingly fast lookups.

### 🔑 Key Generation & Management Studio
- **Key Generators**:
  - **Ed25519**: 256-bit modern elliptic curve keypairs (instant generation).
  - **RSA-4096**: 4096-bit high-security RSA keypairs.
  - **OpenPGP / GPG**: Armored keypairs with custom User IDs (Name, Email, Comment).
- **Key Inspector**: Shows Public Key, Key Type badge, and SHA256 Fingerprint (`SHA256:...`) with masked Private Key (`••••••••••••`) and click-to-reveal toggle.
- **Multi-Format Export**:
  - OpenSSH Public (`.pub`)
  - OpenSSH Private PEM (`.pem`)
  - PuTTY Private Key (`.ppk` v2 compatible)
  - Armored PGP (`.asc`)
- **Direct Vault Storage**: Save newly generated keys straight into your encrypted database with 1 click.

### 📋 Productivity & Automation
- **30-Second Clipboard Auto-Clear**: Automatically wipes passwords, private keys, and tokens from your clipboard after 30 seconds with a real-time countdown pill in the UI.
- **Auto-Lock & Inactivity Timer**: Configurable auto-lock (1 min, 5 min, 15 min, 30 min, Never) upon idle timeout or when minimizing to the system tray.
- **Connection Quick-Strings**:
  - **SSH**: Ready-to-paste commands (e.g. `ssh -p 22 root@192.168.1.50`).
  - **Databases**: Standard URLs for PostgreSQL, MySQL, Redis, and MongoDB (`postgresql://user:pass@host:port/db`), plus CLI client commands (`psql -h host -U user`).
  - **APIs**: Authenticated `curl` snippets (`curl -H "Authorization: Bearer <token>" ...`).
- **One-Click Copy UI**: Quick-copy buttons directly on entry cards and in HUD search results.

---

## Dynamic Entry Types

1. **Infrastructure / Server**:
   - Hostname/IP, Port (default 22), Username, Password, SSH Keypair, Sudo Password, OS Distro, Tags, Multi-line Rich Notes.
2. **Service / App**:
   - App Name (e.g., PostgreSQL, Jellyfin, Docker Registry), URI/URL, Port, Username, Password, API Key/Token, Database Name, Tags, Multi-line Rich Notes.
3. **SSH / GPG Keypair**:
   - Key Name, Algorithm (`ed25519`, `rsa4096`, `gpg`), Public Key, Fingerprint, Private Key, Passphrase, Tags, Multi-line Rich Notes.

---

## Running the Standalone Executable (No Command Line)

StarVault is packaged as a standalone, windowed Windows application:

- **Double-click [`StarVault.exe`](file:///d:/Projects/StarVault/StarVault.exe)** directly in this folder or in `dist\StarVault.exe`.
- **Zero console window**: Runs cleanly with custom icon embedding without popping up a command prompt.
- **Portable ready**: If a `starvault.db` file is placed in the same folder, it runs in local portable mode automatically.
- You can pin `StarVault.exe` to your Windows Taskbar, Start Menu, or create a Desktop shortcut!

---

## Installation & Setup (Running from Source)

### Requirements
- Python 3.10+ (tested on Python 3.12)
- Windows 10/11 or Linux (with Tkinter support)

### 1. Clone & Set Up Virtual Environment
```powershell
git clone https://github.com/your-repo/StarVault.git
cd StarVault

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Launch StarVault
```powershell
python run.py
```

#### Launch Options
- **Default mode** (uses `%LOCALAPPDATA%\StarVault\starvault.db`):
  ```powershell
  python run.py
  ```
- **Portable mode** (uses `./starvault.db` in the current folder):
  ```powershell
  python run.py --portable
  ```
- **Custom database path**:
  ```powershell
  python run.py --db "D:/SecureStorage/homelab_vault.db"
  ```

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + C` | Copy Password of selected entry (30-second auto-clear) |
| `Ctrl + U` | Copy Username of selected entry |
| `Ctrl + B` | Copy Host, URI, or IP address of selected entry |
| `Ctrl + D` | Duplicate selected entry (clones with `- Copy` title) |
| `Ctrl + F` | Focus fuzzy search bar |
| `Ctrl + L` | Immediately lock vault and wipe session keys |
| `Esc` | Close HUD search window / Dismiss dialogs |
| `Up / Down` | Navigate search results in HUD |
| `Enter` | Submit password / Copy primary credential in HUD |

---

## Running Automated Tests

StarVault includes automated unit and integration tests covering cryptography, database transactions, key generation, and search ranking:

```powershell
.\.venv\Scripts\pytest tests/ -v
```

---

## Security Specifications Summary

| Feature | Specification |
|---|---|
| Key Derivation Function (KDF) | Argon2id (`t=3`, `m=64MB`, `p=4`, `len=32`) |
| Salt | Cryptographically secure random 16 bytes per database |
| Cipher | AES-256-GCM (Galois/Counter Mode) |
| Nonce / IV | 12 bytes cryptographically secure random per field |
| Integrity Tag | 16 bytes authentication tag per field |
| Master Password Verification | AES-256-GCM encrypted canary token |
| In-Memory Protection | Zeroized upon lock or logout |
| Clipboard Sanitization | Automatic 30-second wipe for all copied secrets |
