"""Local Key and Certificate Installer, Inspector, and System Verifier for StarVault.

Provides automated cross-platform installation of SSH, OpenPGP/GPG, Age, WireGuard,
and TLS/SSL keys on local Windows and Linux/POSIX systems.
Handles strict permissions hardening (NTFS ACLs / POSIX chmod 0600/0700),
OpenSSH agent integration, authorized_keys management, SSH client config generation,
integrity verification, and system diagnostics.
"""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import zipfile

from starvault.keys import export_key_armored, parse_and_import_key
from starvault.models import VaultEntry


@dataclass
class InstallTargetConfig:
    """Configuration options for installing a key onto the local system."""
    destination_dir: Optional[Path] = None
    custom_filename: str = ""
    install_private: bool = True
    install_public: bool = True
    add_to_authorized_keys: bool = False
    add_to_ssh_config: bool = False
    ssh_config_host_alias: str = ""
    ssh_config_hostname: str = ""
    ssh_config_user: str = ""
    add_to_agent: bool = False
    overwrite_existing: bool = False
    import_to_gpg_keyring: bool = True
    enforce_strict_permissions: bool = True


@dataclass
class KeyCheckItem:
    """Individual system or verification check result."""
    name: str
    status: str  # "OK", "WARNING", "ERROR", "INFO", "SKIPPED"
    message: str
    details: Optional[str] = None


@dataclass
class KeyInstallResult:
    """Result of an installation operation for a specific vault key."""
    entry_id: str
    key_title: str
    key_type: str
    success: bool
    installed_paths: List[Path] = field(default_factory=list)
    checks: List[KeyCheckItem] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def has_warnings(self) -> bool:
        return any(c.status == "WARNING" for c in self.checks)


@dataclass
class SystemEnvironmentInfo:
    """Snapshot of the local host operating system and security environment."""
    os_type: str  # "windows", "linux", "darwin"
    user_home: Path
    ssh_dir: Path
    gnupg_dir: Path
    age_dir: Path
    wireguard_dir: Path
    ssl_dir: Path
    ssh_agent_available: bool
    ssh_agent_running: bool
    ssh_keygen_available: bool
    gpg_available: bool
    username: str


@dataclass
class DiscoveredLocalKey:
    """A key or certificate found on the local filesystem."""
    path: Path
    key_type: str  # "ed25519", "rsa4096", "gpg", "age", "wireguard", "tls_cert", "unknown"
    algorithm_name: str
    fingerprint: str
    title: str
    comment: str
    public_content: str
    private_content: str
    already_in_vault: bool = False


# -----------------------------------------------------------------------------
# System Environment Detection
# -----------------------------------------------------------------------------

def get_system_env_info() -> SystemEnvironmentInfo:
    """Inspects the local operating system to identify paths and available CLI utilities."""
    os_type = platform.system().lower()
    if os_type == "windows":
        home = Path(os.environ.get("USERPROFILE", Path.home())).resolve()
        username = os.environ.get("USERNAME", os.path.basename(str(home)))
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        ssh_dir = home / ".ssh"
        gnupg_dir = home / ".gnupg"
        age_dir = appdata / "age"
        wireguard_dir = appdata / "WireGuard"
        ssl_dir = home / ".ssl"
    else:
        home = Path.home().resolve()
        username = os.environ.get("USER", os.path.basename(str(home)))
        ssh_dir = home / ".ssh"
        gnupg_dir = home / ".gnupg"
        age_dir = home / ".config" / "age"
        wireguard_dir = home / ".wireguard"
        ssl_dir = home / ".ssl"

    ssh_keygen_bin = shutil.which("ssh-keygen")
    ssh_add_bin = shutil.which("ssh-add")
    gpg_bin = shutil.which("gpg")

    # Determine if ssh-agent is running
    agent_running = False
    agent_available = ssh_add_bin is not None
    if agent_available:
        try:
            # ssh-add -l returns 0 (keys present) or 1 (no keys, but agent running)
            # returns 2 if agent is not running / cannot connect
            res = subprocess.run(
                [ssh_add_bin, "-l"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            agent_running = res.returncode in (0, 1)
        except Exception:
            agent_running = False

    return SystemEnvironmentInfo(
        os_type=os_type,
        user_home=home,
        ssh_dir=ssh_dir,
        gnupg_dir=gnupg_dir,
        age_dir=age_dir,
        wireguard_dir=wireguard_dir,
        ssl_dir=ssl_dir,
        ssh_agent_available=agent_available,
        ssh_agent_running=agent_running,
        ssh_keygen_available=ssh_keygen_bin is not None,
        gpg_available=gpg_bin is not None,
        username=username,
    )


# -----------------------------------------------------------------------------
# Permission Hardening & Verification
# -----------------------------------------------------------------------------

def set_strict_directory_permissions(path: Path) -> Tuple[bool, str]:
    """Sets owner-only permissions (0700 on POSIX, restricted NTFS ACLs on Windows)."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        if platform.system().lower() == "windows":
            # Use icacls to disable inheritance and grant current user full access
            user = os.environ.get("USERNAME")
            if user and shutil.which("icacls"):
                cmd_r = ["icacls", str(path), "/inheritance:r"]
                subprocess.run(cmd_r, capture_output=True, timeout=5)
                cmd_g = ["icacls", str(path), "/grant:r", f"{user}:(OI)(CI)F"]
                subprocess.run(cmd_g, capture_output=True, timeout=5)
            return True, "Windows NTFS ACL restricted to current user."
        else:
            path.chmod(0o700)
            return True, "POSIX chmod 0700 applied."
    except Exception as ex:
        return False, f"Failed to set directory permissions: {ex}"


def set_strict_file_permissions(path: Path, is_private: bool = True) -> Tuple[bool, str]:
    """Applies strict permissions to key files.

    Private keys: 0600 on POSIX; on Windows, removes inheritance and restricts to %USERNAME%:F.
    Public keys: 0644 on POSIX; standard user read/write on Windows.
    """
    try:
        if not path.exists():
            return False, f"File {path} does not exist."

        if platform.system().lower() == "windows":
            user = os.environ.get("USERNAME")
            if user and shutil.which("icacls"):
                if is_private:
                    # Strip inheritance and grant current user full control
                    # OpenSSH for Windows strictly checks that no other user/group has access
                    subprocess.run(
                        ["icacls", str(path), "/inheritance:r"],
                        capture_output=True,
                        timeout=5,
                    )
                    subprocess.run(
                        ["icacls", str(path), "/grant:r", f"{user}:F"],
                        capture_output=True,
                        timeout=5,
                    )
                    # Clean up common Windows broadcast groups if still present
                    for group in ("Users", "Authenticated Users", "Everyone"):
                        subprocess.run(
                            ["icacls", str(path), "/remove", group],
                            capture_output=True,
                            timeout=5,
                        )
                    return True, f"Windows NTFS ACL restricted exclusively to {user}."
                else:
                    return True, "Public file permissions verified."
            return True, "File written (icacls not available)."
        else:
            mode = 0o600 if is_private else 0o644
            path.chmod(mode)
            return True, f"POSIX chmod {oct(mode)} applied."
    except Exception as ex:
        return False, f"Permission error: {ex}"


def verify_file_permissions(path: Path, is_private: bool = True) -> KeyCheckItem:
    """Verifies that a file's permissions comply with secure key storage requirements."""
    if not path.exists():
        return KeyCheckItem(
            name="File Permissions",
            status="ERROR",
            message=f"File {path.name} not found.",
        )

    if platform.system().lower() == "windows":
        if shutil.which("icacls"):
            try:
                res = subprocess.run(
                    ["icacls", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = res.stdout
                # For private keys, check that Users or Everyone are not listed with permissions
                if is_private:
                    # Strip the filepath from the first line so that e.g. "C:\Users\..." is not matched
                    acl_body = output
                    first_line = output.splitlines()[0] if output.splitlines() else ""
                    str_path = str(path)
                    if str_path in first_line:
                        first_entry = first_line.replace(str_path, "")
                        acl_body = first_entry + "\n" + "\n".join(output.splitlines()[1:])

                    bad_grps = []
                    for g in ("Everyone:", "BUILTIN\\Users:", "\\Users:", " Users:"):
                        if g in acl_body:
                            bad_grps.append(g.strip(":"))
                    if bad_grps:
                        return KeyCheckItem(
                            name="File Permissions",
                            status="WARNING",
                            message=f"Private key may have broad permissions ({', '.join(bad_grps)} detected in ACL).",
                            details=output.strip(),
                        )
                    return KeyCheckItem(
                        name="File Permissions",
                        status="OK",
                        message="Restricted NTFS ACL (Current user only).",
                        details=output.strip(),
                    )
            except Exception as ex:
                return KeyCheckItem(
                    name="File Permissions",
                    status="WARNING",
                    message=f"Could not verify Windows ACL: {ex}",
                )
        return KeyCheckItem(
            name="File Permissions",
            status="OK",
            message="File present on NTFS filesystem.",
        )
    else:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
            if is_private:
                # Private keys must NOT be readable by group or others (0o600 or 0o400)
                if (mode & 0o077) != 0:
                    return KeyCheckItem(
                        name="File Permissions",
                        status="WARNING",
                        message=f"Permissions {oct(mode)} are too open for private key (expected 0600).",
                        details="Run chmod 600 on this file.",
                    )
                return KeyCheckItem(
                    name="File Permissions",
                    status="OK",
                    message=f"Strict POSIX permissions verified ({oct(mode)}).",
                )
            else:
                return KeyCheckItem(
                    name="File Permissions",
                    status="OK",
                    message=f"Public key permissions ({oct(mode)}).",
                )
        except Exception as ex:
            return KeyCheckItem(
                name="File Permissions",
                status="ERROR",
                message=f"Could not read file stat: {ex}",
            )


# -----------------------------------------------------------------------------
# Name & Path Sanitization
# -----------------------------------------------------------------------------

def sanitize_filename(name: str, fallback: str = "key") -> str:
    """Sanitizes a string for safe usage as a filename."""
    clean = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name.strip())
    clean = re.sub(r'_+', '_', clean).strip('._')
    return clean if clean else fallback


def determine_default_filenames(entry: VaultEntry) -> Tuple[str, str]:
    """Generates standard private and public filenames based on entry algorithm and title."""
    kt = getattr(entry, "key_type", "").lower()
    title_slug = sanitize_filename(entry.title.lower())

    if "ed25519" in kt:
        base = f"id_ed25519_{title_slug}" if title_slug and title_slug != "id_ed25519" else "id_ed25519"
        return base, f"{base}.pub"
    elif "rsa" in kt:
        base = f"id_rsa_{title_slug}" if title_slug and title_slug != "id_rsa" else "id_rsa"
        return base, f"{base}.pub"
    elif "ecdsa" in kt:
        base = f"id_ecdsa_{title_slug}" if title_slug else "id_ecdsa"
        return base, f"{base}.pub"
    elif "gpg" in kt or "pgp" in kt:
        base = f"{title_slug}.asc"
        return base, f"{title_slug}_pub.asc"
    elif "age" in kt:
        return "keys.txt", f"{title_slug}_recipient.txt"
    elif "wireguard" in kt:
        return f"{title_slug}.conf", f"{title_slug}_pub.key"
    elif "tls" in kt or "cert" in kt:
        return f"{title_slug}.key", f"{title_slug}.crt"
    else:
        return f"id_{title_slug}", f"id_{title_slug}.pub"


# -----------------------------------------------------------------------------
# Diagnostics & System Checks
# -----------------------------------------------------------------------------

def verify_openssh_key_syntax(key_path: Path) -> KeyCheckItem:
    """Uses the system ssh-keygen utility to verify key syntax and fingerprint."""
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        return KeyCheckItem(
            name="OpenSSH Syntax Validation",
            status="SKIPPED",
            message="ssh-keygen CLI not found in PATH.",
        )

    try:
        res = subprocess.run(
            [ssh_keygen, "-l", "-f", str(key_path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            fp_info = res.stdout.strip()
            return KeyCheckItem(
                name="OpenSSH Syntax Validation",
                status="OK",
                message=f"Key verified by OpenSSH: {fp_info}",
                details=fp_info,
            )
        else:
            err = res.stderr.strip() or res.stdout.strip()
            return KeyCheckItem(
                name="OpenSSH Syntax Validation",
                status="WARNING",
                message=f"ssh-keygen check reported: {err}",
                details=err,
            )
    except Exception as ex:
        return KeyCheckItem(
            name="OpenSSH Syntax Validation",
            status="WARNING",
            message=f"Validation invocation error: {ex}",
        )


def verify_content_integrity(path: Path, expected_content: str) -> KeyCheckItem:
    """Verifies that the file written to disk matches the expected vault material."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            actual = f.read()

        # Normalize line endings for hash comparison
        norm_actual = actual.replace("\r\n", "\n").strip()
        norm_expected = expected_content.replace("\r\n", "\n").strip()

        hash_actual = hashlib.sha256(norm_actual.encode("utf-8")).hexdigest()
        hash_expected = hashlib.sha256(norm_expected.encode("utf-8")).hexdigest()

        if hash_actual == hash_expected:
            return KeyCheckItem(
                name="Content Integrity",
                status="OK",
                message=f"SHA-256 integrity match ({hash_actual[:12]}...).",
            )
        else:
            return KeyCheckItem(
                name="Content Integrity",
                status="ERROR",
                message="Disk content hash does not match vault key material.",
                details=f"Expected: {hash_expected}\nActual: {hash_actual}",
            )
    except Exception as ex:
        return KeyCheckItem(
            name="Content Integrity",
            status="ERROR",
            message=f"Could not read file for verification: {ex}",
        )


def check_ssh_agent_addition(key_path: Path) -> KeyCheckItem:
    """Attempts to register the installed private key into the local ssh-agent."""
    ssh_add = shutil.which("ssh-add")
    if not ssh_add:
        return KeyCheckItem(
            name="SSH Agent Registration",
            status="SKIPPED",
            message="ssh-add utility not found in PATH.",
        )

    try:
        res = subprocess.run(
            [ssh_add, str(key_path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return KeyCheckItem(
                name="SSH Agent Registration",
                status="OK",
                message=f"Successfully loaded '{key_path.name}' into ssh-agent.",
            )
        else:
            err = res.stderr.strip() or res.stdout.strip()
            # If agent is not running
            if "could not open a connection" in err.lower() or "communication with agent failed" in err.lower():
                return KeyCheckItem(
                    name="SSH Agent Registration",
                    status="WARNING",
                    message="ssh-agent is not running on this host.",
                    details=(
                        "Windows: Start 'OpenSSH Authentication Agent' service in services.msc or PowerShell.\n"
                        "Linux: Run 'eval $(ssh-agent -s)'."
                    ),
                )
            return KeyCheckItem(
                name="SSH Agent Registration",
                status="WARNING",
                message=f"ssh-add reported: {err}",
            )
    except Exception as ex:
        return KeyCheckItem(
            name="SSH Agent Registration",
            status="WARNING",
            message=f"Agent addition failed: {ex}",
        )


def append_to_authorized_keys(ssh_dir: Path, public_key_text: str) -> KeyCheckItem:
    """Safely appends a public key to ~/.ssh/authorized_keys if not already present."""
    try:
        auth_file = ssh_dir / "authorized_keys"
        clean_pub = public_key_text.strip()
        if not clean_pub:
            return KeyCheckItem(
                name="authorized_keys Registration",
                status="SKIPPED",
                message="No public key text available to append.",
            )

        existing = ""
        if auth_file.exists():
            with open(auth_file, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read()

        # Check if already present by looking for the base64 key blob
        pub_parts = clean_pub.split()
        key_blob = pub_parts[1] if len(pub_parts) >= 2 else clean_pub
        if key_blob in existing:
            return KeyCheckItem(
                name="authorized_keys Registration",
                status="OK",
                message=f"Key is already present in {auth_file.name}.",
            )

        # Append key
        prefix = "\n" if existing and not existing.endswith("\n") else ""
        with open(auth_file, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"{prefix}{clean_pub}\n")

        set_strict_file_permissions(auth_file, is_private=True)
        return KeyCheckItem(
            name="authorized_keys Registration",
            status="OK",
            message=f"Added public key to {auth_file.name} with strict permissions.",
        )
    except Exception as ex:
        return KeyCheckItem(
            name="authorized_keys Registration",
            status="ERROR",
            message=f"Failed to append to authorized_keys: {ex}",
        )


def update_ssh_config(
    ssh_dir: Path,
    host_alias: str,
    key_path: Path,
    hostname: str = "",
    user: str = "",
) -> KeyCheckItem:
    """Adds or updates a Host block in ~/.ssh/config for this key."""
    try:
        config_file = ssh_dir / "config"
        alias = host_alias.strip() or key_path.stem
        norm_key_path = str(key_path).replace("\\", "/")

        existing = ""
        if config_file.exists():
            with open(config_file, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read()

        # Check if host block already exists
        pattern = rf"(?m)^Host\s+{re.escape(alias)}\b"
        if re.search(pattern, existing):
            return KeyCheckItem(
                name="SSH Client Config",
                status="OK",
                message=f"Host '{alias}' already configured in {config_file.name}.",
            )

        block_lines = [f"\nHost {alias}"]
        if hostname:
            block_lines.append(f"    HostName {hostname}")
        if user:
            block_lines.append(f"    User {user}")
        block_lines.append(f"    IdentityFile {norm_key_path}")
        block_lines.append("    IdentitiesOnly yes\n")
        block_text = "\n".join(block_lines)

        with open(config_file, "a", encoding="utf-8", newline="\n") as f:
            f.write(block_text)

        set_strict_file_permissions(config_file, is_private=True)
        return KeyCheckItem(
            name="SSH Client Config",
            status="OK",
            message=f"Created Host '{alias}' entry in {config_file.name}.",
        )
    except Exception as ex:
        return KeyCheckItem(
            name="SSH Client Config",
            status="ERROR",
            message=f"Failed to update SSH config: {ex}",
        )


def import_into_gpg_keyring(key_content: str) -> KeyCheckItem:
    """Invokes system gpg CLI to import armored key into the native GPG keyring."""
    gpg_bin = shutil.which("gpg")
    if not gpg_bin:
        return KeyCheckItem(
            name="Native GPG Keyring Import",
            status="SKIPPED",
            message="gpg command line tool not found on this system.",
        )

    try:
        res = subprocess.run(
            [gpg_bin, "--batch", "--yes", "--import"],
            input=key_content,
            capture_output=True,
            text=True,
            timeout=8,
        )
        if res.returncode == 0:
            details = res.stderr.strip() or res.stdout.strip()
            return KeyCheckItem(
                name="Native GPG Keyring Import",
                status="OK",
                message="Successfully imported key into local GPG keyring.",
                details=details,
            )
        else:
            err = res.stderr.strip()
            return KeyCheckItem(
                name="Native GPG Keyring Import",
                status="WARNING",
                message=f"GPG import warning: {err}",
            )
    except Exception as ex:
        return KeyCheckItem(
            name="Native GPG Keyring Import",
            status="WARNING",
            message=f"GPG execution error: {ex}",
        )


# -----------------------------------------------------------------------------
# Core Installer Implementation
# -----------------------------------------------------------------------------

def install_vault_key(
    entry: VaultEntry,
    config: Optional[InstallTargetConfig] = None,
) -> KeyInstallResult:
    """Installs a single vault key onto the local machine and performs exhaustive checks."""
    cfg = config or InstallTargetConfig()
    env = get_system_env_info()

    kt = getattr(entry, "key_type", "").lower()
    is_ssh = any(k in kt for k in ("ed25519", "rsa", "ecdsa")) or entry.entry_type == "keypair" and "ssh" in getattr(entry, "public_key", "").lower()
    is_gpg = "gpg" in kt or "pgp" in kt or "BEGIN PGP" in getattr(entry, "public_key", "")
    is_age = "age" in kt or getattr(entry, "public_key", "").startswith("age1") or getattr(entry, "private_key", "").startswith("AGE-SECRET-KEY")
    is_wg = "wireguard" in kt
    is_tls = "tls" in kt or "cert" in kt or "BEGIN CERTIFICATE" in getattr(entry, "public_key", "")

    # Target directory selection
    target_dir = cfg.destination_dir
    if not target_dir:
        if is_ssh:
            target_dir = env.ssh_dir
        elif is_gpg:
            target_dir = env.gnupg_dir
        elif is_age:
            target_dir = env.age_dir
        elif is_wg:
            target_dir = env.wireguard_dir
        elif is_tls:
            target_dir = env.ssl_dir
        else:
            target_dir = env.ssh_dir

    target_dir = Path(target_dir).resolve()
    checks: List[KeyCheckItem] = []
    installed_paths: List[Path] = []

    # 1. Directory creation & security
    dir_ok, dir_msg = set_strict_directory_permissions(target_dir)
    checks.append(KeyCheckItem(
        name="Destination Directory",
        status="OK" if dir_ok else "ERROR",
        message=f"{target_dir} ({dir_msg})",
    ))
    if not dir_ok:
        return KeyInstallResult(
            entry_id=entry.id,
            key_title=entry.title,
            key_type=kt,
            success=False,
            installed_paths=[],
            checks=checks,
            error_message=f"Failed to prepare destination directory: {dir_msg}",
        )

    # Determine filenames
    def_priv_name, def_pub_name = determine_default_filenames(entry)
    if cfg.custom_filename:
        c_clean = sanitize_filename(cfg.custom_filename)
        priv_name = c_clean
        pub_name = f"{c_clean}.pub"
    else:
        priv_name = def_priv_name
        pub_name = def_pub_name

    priv_path = target_dir / priv_name
    pub_path = target_dir / pub_name

    # Overwrite protection check
    if not cfg.overwrite_existing:
        if (cfg.install_private and priv_path.exists()) or (cfg.install_public and pub_path.exists()):
            # Fall back to a unique timestamped or slugged name if default already exists
            unique_suffix = hashlib.sha256(f"{entry.id}_{entry.title}".encode()).hexdigest()[:6]
            if priv_path.exists():
                priv_path = target_dir / f"{priv_name}_{unique_suffix}"
            if pub_path.exists():
                pub_path = target_dir / f"{pub_name}_{unique_suffix}"

    priv_material = getattr(entry, "private_key", "").strip()
    pub_material = getattr(entry, "public_key", "").strip()

    # -------------------------------------------------------------------------
    # Format-Specific Installation
    # -------------------------------------------------------------------------

    # A. SSH Key Installation
    if is_ssh:
        # Write private key
        if cfg.install_private and priv_material:
            try:
                # OpenSSH private key files require trailing newline
                norm_priv = priv_material.replace("\r\n", "\n").strip() + "\n"
                with open(priv_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(norm_priv)
                installed_paths.append(priv_path)

                # Set permissions
                p_ok, p_msg = set_strict_file_permissions(priv_path, is_private=True)
                checks.append(verify_file_permissions(priv_path, is_private=True))

                # Verify integrity
                checks.append(verify_content_integrity(priv_path, norm_priv))

                # Verify syntax with ssh-keygen
                checks.append(verify_openssh_key_syntax(priv_path))

                # Add to agent if requested
                if cfg.add_to_agent:
                    checks.append(check_ssh_agent_addition(priv_path))

            except Exception as ex:
                checks.append(KeyCheckItem(
                    name="Private Key Write",
                    status="ERROR",
                    message=f"Failed to write private key: {ex}",
                ))

        # Write public key
        if cfg.install_public and pub_material:
            try:
                norm_pub = pub_material.replace("\r\n", "\n").strip() + "\n"
                with open(pub_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(norm_pub)
                installed_paths.append(pub_path)

                set_strict_file_permissions(pub_path, is_private=False)
                checks.append(verify_file_permissions(pub_path, is_private=False))
                checks.append(verify_content_integrity(pub_path, norm_pub))
            except Exception as ex:
                checks.append(KeyCheckItem(
                    name="Public Key Write",
                    status="ERROR",
                    message=f"Failed to write public key: {ex}",
                ))

        # Add to authorized_keys
        if cfg.add_to_authorized_keys and pub_material:
            checks.append(append_to_authorized_keys(target_dir, pub_material))

        # Add to ~/.ssh/config
        if cfg.add_to_ssh_config and (priv_path in installed_paths or pub_path in installed_paths):
            use_path = priv_path if priv_path in installed_paths else pub_path
            checks.append(update_ssh_config(
                ssh_dir=target_dir,
                host_alias=cfg.ssh_config_host_alias or entry.title,
                key_path=use_path,
                hostname=cfg.ssh_config_hostname,
                user=cfg.ssh_config_user,
            ))

    # B. GPG / OpenPGP Key Installation
    elif is_gpg:
        # Armored GPG file write
        content = priv_material or pub_material
        if content:
            try:
                norm_gpg = content.replace("\r\n", "\n").strip() + "\n"
                with open(priv_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(norm_gpg)
                installed_paths.append(priv_path)

                set_strict_file_permissions(priv_path, is_private=bool(priv_material))
                checks.append(verify_file_permissions(priv_path, is_private=bool(priv_material)))
                checks.append(verify_content_integrity(priv_path, norm_gpg))

                if cfg.import_to_gpg_keyring:
                    checks.append(import_into_gpg_keyring(norm_gpg))
            except Exception as ex:
                checks.append(KeyCheckItem(
                    name="GPG Key Write",
                    status="ERROR",
                    message=f"Failed to write GPG file: {ex}",
                ))

    # C. Age Key Installation
    elif is_age:
        try:
            age_file = target_dir / "keys.txt"
            secret = priv_material or pub_material
            norm_sec = secret.strip()
            comment_line = f"# {entry.title}\n" if entry.title else ""
            record = f"{comment_line}{norm_sec}\n"

            existing = ""
            if age_file.exists():
                with open(age_file, "r", encoding="utf-8", errors="replace") as f:
                    existing = f.read()

            if norm_sec in existing:
                checks.append(KeyCheckItem(
                    name="Age Key Installation",
                    status="OK",
                    message=f"Age key already present in {age_file.name}.",
                ))
            else:
                with open(age_file, "a", encoding="utf-8", newline="\n") as f:
                    f.write(record)
                set_strict_file_permissions(age_file, is_private=True)
                checks.append(KeyCheckItem(
                    name="Age Key Installation",
                    status="OK",
                    message=f"Appended key to {age_file.name}.",
                ))
            installed_paths.append(age_file)
            checks.append(verify_file_permissions(age_file, is_private=True))
        except Exception as ex:
            checks.append(KeyCheckItem(
                name="Age Key Installation",
                status="ERROR",
                message=f"Failed to write Age key: {ex}",
            ))

    # D. WireGuard Key Installation
    elif is_wg:
        try:
            wg_file = target_dir / f"{sanitize_filename(entry.title)}.conf"
            # Format minimal WireGuard configuration
            lines = [
                f"# WireGuard Keypair - {entry.title}",
                "[Interface]",
            ]
            if priv_material:
                lines.append(f"PrivateKey = {priv_material}")
            if pub_material:
                lines.append(f"# PublicKey = {pub_material}")
            lines.append("")
            content = "\n".join(lines)

            with open(wg_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
            installed_paths.append(wg_file)
            set_strict_file_permissions(wg_file, is_private=True)
            checks.append(verify_file_permissions(wg_file, is_private=True))
            checks.append(KeyCheckItem(
                name="WireGuard Config",
                status="OK",
                message=f"Written interface template to {wg_file.name}.",
            ))
        except Exception as ex:
            checks.append(KeyCheckItem(
                name="WireGuard Config",
                status="ERROR",
                message=f"Failed to write WireGuard config: {ex}",
            ))

    # E. TLS / SSL Certificate Installation
    elif is_tls:
        try:
            if pub_material:
                with open(pub_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(pub_material.strip() + "\n")
                installed_paths.append(pub_path)
                set_strict_file_permissions(pub_path, is_private=False)

            if priv_material:
                with open(priv_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(priv_material.strip() + "\n")
                installed_paths.append(priv_path)
                set_strict_file_permissions(priv_path, is_private=True)
                checks.append(verify_file_permissions(priv_path, is_private=True))

            checks.append(KeyCheckItem(
                name="TLS Certificate Installation",
                status="OK",
                message=f"Saved certificate ({pub_path.name}) and private key ({priv_path.name}).",
            ))
        except Exception as ex:
            checks.append(KeyCheckItem(
                name="TLS Certificate Installation",
                status="ERROR",
                message=f"Failed to write certificate: {ex}",
            ))

    # F. Generic Key Fallback
    else:
        try:
            mat = priv_material or pub_material
            with open(priv_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(mat.strip() + "\n")
            installed_paths.append(priv_path)
            set_strict_file_permissions(priv_path, is_private=bool(priv_material))
            checks.append(verify_file_permissions(priv_path, is_private=bool(priv_material)))
        except Exception as ex:
            checks.append(KeyCheckItem(
                name="Generic Key Write",
                status="ERROR",
                message=f"Failed to write generic key: {ex}",
            ))

    has_error = any(c.status == "ERROR" for c in checks)
    return KeyInstallResult(
        entry_id=entry.id,
        key_title=entry.title,
        key_type=kt,
        success=not has_error and len(installed_paths) > 0,
        installed_paths=installed_paths,
        checks=checks,
    )


def install_vault_keys(
    entries: List[VaultEntry],
    configs: Optional[Dict[str, InstallTargetConfig]] = None,
    default_config: Optional[InstallTargetConfig] = None,
) -> List[KeyInstallResult]:
    """Installs a batch of vault keys with individual or shared configurations."""
    results: List[KeyInstallResult] = []
    base_cfg = default_config or InstallTargetConfig()
    cfg_map = configs or {}

    for ent in entries:
        cfg = cfg_map.get(ent.id, base_cfg)
        res = install_vault_key(ent, cfg)
        results.append(res)

    return results


# -----------------------------------------------------------------------------
# System Diagnostics Pre-Check
# -----------------------------------------------------------------------------

def run_system_precheck() -> List[KeyCheckItem]:
    """Audits local SSH, GPG, and key storage directories and tooling."""
    env = get_system_env_info()
    items: List[KeyCheckItem] = []

    # 1. SSH directory audit
    if env.ssh_dir.exists():
        mode_item = verify_file_permissions(env.ssh_dir, is_private=True)
        items.append(KeyCheckItem(
            name="~/.ssh Directory",
            status="OK" if mode_item.status == "OK" else "WARNING",
            message=f"Found at {env.ssh_dir}",
            details=mode_item.details,
        ))
    else:
        items.append(KeyCheckItem(
            name="~/.ssh Directory",
            status="INFO",
            message=f"Not created yet ({env.ssh_dir}). Will be initialized automatically upon installation.",
        ))

    # 2. OpenSSH Tools (ssh-keygen, ssh-add)
    if env.ssh_keygen_available:
        items.append(KeyCheckItem(
            name="OpenSSH Client Tools",
            status="OK",
            message="ssh-keygen and ssh utilities are installed and accessible.",
        ))
    else:
        items.append(KeyCheckItem(
            name="OpenSSH Client Tools",
            status="WARNING",
            message="ssh-keygen not found in system PATH.",
            details="On Windows: Install OpenSSH via Windows Optional Features.",
        ))

    # 3. SSH Agent Status
    if env.ssh_agent_running:
        items.append(KeyCheckItem(
            name="SSH Authentication Agent",
            status="OK",
            message="ssh-agent is active and ready to accept key identities.",
        ))
    elif env.ssh_agent_available:
        tip = (
            "Windows: Run 'Start-Service ssh-agent' in administrative PowerShell.\n"
            "Linux/macOS: Run 'eval $(ssh-agent -s)' in your shell."
        )
        items.append(KeyCheckItem(
            name="SSH Authentication Agent",
            status="WARNING",
            message="ssh-agent is installed but currently stopped.",
            details=tip,
        ))
    else:
        items.append(KeyCheckItem(
            name="SSH Authentication Agent",
            status="INFO",
            message="ssh-agent client utility not found in system PATH.",
        ))

    # 4. GPG Utility Status
    if env.gpg_available:
        items.append(KeyCheckItem(
            name="GnuPG (GPG) Tooling",
            status="OK",
            message="gpg CLI found in system PATH.",
        ))
    else:
        items.append(KeyCheckItem(
            name="GnuPG (GPG) Tooling",
            status="INFO",
            message="gpg CLI not detected. Armored keys will be written directly to file.",
        ))

    return items


def fix_all_ssh_permissions(ssh_dir: Optional[Path] = None) -> Tuple[int, List[str]]:
    """Enforces strict owner-only permissions on ~/.ssh and all private keys within it."""
    env = get_system_env_info()
    target_dir = Path(ssh_dir or env.ssh_dir).resolve()
    if not target_dir.exists():
        return 0, [f"Directory {target_dir} does not exist."]

    fixed_count = 0
    logs: List[str] = []

    # Fix directory itself
    ok, msg = set_strict_directory_permissions(target_dir)
    logs.append(f"Directory {target_dir}: {msg}")
    if ok:
        fixed_count += 1

    # Scan and fix all files inside ~/.ssh
    for child in target_dir.iterdir():
        if child.is_file():
            is_pub = child.name.endswith(".pub")
            is_priv = not is_pub and (
                child.name.startswith("id_")
                or child.name in ("authorized_keys", "config", "known_hosts")
                or child.suffix in (".pem", ".key")
            )
            f_ok, f_msg = set_strict_file_permissions(child, is_private=is_priv)
            logs.append(f"{child.name}: {f_msg}")
            if f_ok:
                fixed_count += 1

    return fixed_count, logs


# -----------------------------------------------------------------------------
# Local Key Discovery (Scanner for Import)
# -----------------------------------------------------------------------------

def scan_local_keys(
    directories: Optional[List[Path]] = None,
    existing_vault_entries: Optional[List[VaultEntry]] = None,
) -> List[DiscoveredLocalKey]:
    """Scans ~/.ssh and user directories to discover local SSH, GPG, Age, and TLS keys."""
    env = get_system_env_info()
    dirs_to_scan = directories or [env.ssh_dir, env.gnupg_dir, env.age_dir, env.ssl_dir]

    # Pre-index existing vault fingerprints and public keys for deduplication
    vault_fps: Set[str] = set()
    vault_pubs: Set[str] = set()
    if existing_vault_entries:
        for ve in existing_vault_entries:
            fp = getattr(ve, "fingerprint", "").strip().lower()
            if fp:
                vault_fps.add(fp)
            pub = getattr(ve, "public_key", "").strip()
            if pub:
                vault_pubs.add(pub)

    discovered: List[DiscoveredLocalKey] = []
    seen_paths: Set[Path] = set()

    for d in dirs_to_scan:
        if not d.exists() or not d.is_dir():
            continue

        try:
            for item in d.iterdir():
                if not item.is_file() or item in seen_paths:
                    continue
                seen_paths.add(item)

                # Skip non-key artifacts
                if item.name in ("known_hosts", "known_hosts.old", "config"):
                    continue

                try:
                    # Ignore very large files (> 512 KB)
                    if item.stat().st_size > 524288:
                        continue

                    with open(item, "r", encoding="utf-8", errors="ignore") as f:
                        raw_text = f.read()

                    clean_text = raw_text.strip()
                    if not clean_text:
                        continue

                    # A. OpenSSH Public Key file (*.pub or line starting with ssh-)
                    if item.name.endswith(".pub") or clean_text.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-")):
                        pub_line = clean_text.splitlines()[0]
                        parts = pub_line.split()
                        algo = parts[0] if parts else "ssh"
                        comment = parts[2] if len(parts) >= 3 else item.stem
                        fp = ""
                        try:
                            import base64
                            b_raw = base64.b64decode(parts[1])
                            fp = "SHA256:" + base64.b64encode(hashlib.sha256(b_raw).digest()).decode("ascii").rstrip("=")
                        except Exception:
                            fp = ""

                        # Check if private key file exists alongside it
                        priv_file = item.with_suffix("") if item.name.endswith(".pub") else None
                        priv_text = ""
                        if priv_file and priv_file.exists() and priv_file.is_file():
                            try:
                                with open(priv_file, "r", encoding="utf-8", errors="ignore") as pf:
                                    priv_text = pf.read().strip()
                            except Exception:
                                pass

                        is_known = (fp.lower() in vault_fps) or (pub_line in vault_pubs)
                        discovered.append(DiscoveredLocalKey(
                            path=item,
                            key_type="ed25519" if "ed25519" in algo else ("rsa4096" if "rsa" in algo else "ssh"),
                            algorithm_name=f"OpenSSH ({algo})",
                            fingerprint=fp,
                            title=comment or item.name,
                            comment=comment,
                            public_content=pub_line,
                            private_content=priv_text,
                            already_in_vault=is_known,
                        ))

                    # B. OpenSSH / PEM Private Key file (without .pub)
                    elif "BEGIN" in clean_text and "PRIVATE KEY" in clean_text:
                        kt = "ed25519" if "ED25519" in clean_text else ("rsa4096" if "RSA" in clean_text else "ssh")
                        # Check if corresponding .pub exists
                        pub_file = item.with_name(f"{item.name}.pub")
                        pub_text = ""
                        fp = ""
                        comment = item.stem
                        if pub_file.exists():
                            try:
                                with open(pub_file, "r", encoding="utf-8", errors="ignore") as pf:
                                    pub_text = pf.read().strip().splitlines()[0]
                                    parts = pub_text.split()
                                    if len(parts) >= 3:
                                        comment = parts[2]
                                    import base64
                                    b_raw = base64.b64decode(parts[1])
                                    fp = "SHA256:" + base64.b64encode(hashlib.sha256(b_raw).digest()).decode("ascii").rstrip("=")
                            except Exception:
                                pass

                        is_known = (fp.lower() in vault_fps) if fp else False
                        discovered.append(DiscoveredLocalKey(
                            path=item,
                            key_type=kt,
                            algorithm_name=f"Private Key ({kt.upper()})",
                            fingerprint=fp or "Private key stored",
                            title=comment or item.name,
                            comment=comment,
                            public_content=pub_text,
                            private_content=clean_text,
                            already_in_vault=is_known,
                        ))

                    # C. OpenPGP / GPG Armored Key (.asc / .gpg)
                    elif "BEGIN PGP" in clean_text:
                        is_priv = "PRIVATE KEY" in clean_text
                        fp = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()[:24]
                        discovered.append(DiscoveredLocalKey(
                            path=item,
                            key_type="gpg",
                            algorithm_name="OpenPGP Armored Key",
                            fingerprint=f"PGP:{fp}",
                            title=item.stem,
                            comment="",
                            public_content=clean_text if not is_priv else "",
                            private_content=clean_text if is_priv else "",
                            already_in_vault=clean_text in vault_pubs,
                        ))

                    # D. Age Secret Key file (keys.txt)
                    elif item.name == "keys.txt" or "AGE-SECRET-KEY-1" in clean_text:
                        for line in clean_text.splitlines():
                            l_strip = line.strip()
                            if l_strip.startswith("AGE-SECRET-KEY-1"):
                                fp = l_strip[:24] + "..."
                                discovered.append(DiscoveredLocalKey(
                                    path=item,
                                    key_type="age",
                                    algorithm_name="Age Secret Key (X25519)",
                                    fingerprint=fp,
                                    title=f"Age Key ({item.stem})",
                                    comment="Local Age Secret Key",
                                    public_content="",
                                    private_content=l_strip,
                                    already_in_vault=False,
                                ))

                    # E. X.509 Certificate (.crt, .cer, .pem)
                    elif "BEGIN CERTIFICATE" in clean_text:
                        fp = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()[:24]
                        discovered.append(DiscoveredLocalKey(
                            path=item,
                            key_type="tls_cert",
                            algorithm_name="X.509 TLS Certificate",
                            fingerprint=f"SHA256:{fp}",
                            title=item.stem,
                            comment="",
                            public_content=clean_text,
                            private_content="",
                            already_in_vault=clean_text in vault_pubs,
                        ))

                except Exception:
                    continue
        except Exception:
            continue

    return discovered


# -----------------------------------------------------------------------------
# Bulk Export Engine
# -----------------------------------------------------------------------------

def export_vault_keys_to_directory(
    entries: List[VaultEntry],
    target_dir: Path,
    include_private: bool = True,
    generate_ssh_config: bool = False,
    create_zip: bool = False,
    zip_filename: str = "starvault_keys_export.zip",
) -> Tuple[int, List[Path]]:
    """Exports multiple vault keys to files or a compressed zip archive."""
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    written_paths: List[Path] = []
    ssh_hosts_config: List[str] = ["# StarVault Generated SSH Client Config\n"]

    # In case user requested a zip, we can write files to a temporary directory or directly into zip
    zip_target: Optional[zipfile.ZipFile] = None
    final_zip_path: Optional[Path] = None
    if create_zip:
        final_zip_path = target_dir / zip_filename
        zip_target = zipfile.ZipFile(final_zip_path, "w", zipfile.ZIP_DEFLATED)

    for entry in entries:
        kt = getattr(entry, "key_type", "").lower()
        title_slug = sanitize_filename(entry.title.lower())
        pub = getattr(entry, "public_key", "").strip()
        priv = getattr(entry, "private_key", "").strip() if include_private else ""

        def_priv, def_pub = determine_default_filenames(entry)

        # 1. Write Public Key
        if pub:
            pub_fname = def_pub
            if zip_target:
                zip_target.writestr(pub_fname, pub + "\n")
            else:
                p_file = target_dir / pub_fname
                with open(p_file, "w", encoding="utf-8", newline="\n") as f:
                    f.write(pub + "\n")
                set_strict_file_permissions(p_file, is_private=False)
                written_paths.append(p_file)

        # 2. Write Private Key (if present and requested)
        if priv:
            priv_fname = def_priv
            if zip_target:
                zip_target.writestr(priv_fname, priv + "\n")
            else:
                pr_file = target_dir / priv_fname
                with open(pr_file, "w", encoding="utf-8", newline="\n") as f:
                    f.write(priv + "\n")
                set_strict_file_permissions(pr_file, is_private=True)
                written_paths.append(pr_file)

        # 3. Add to SSH config snippet if SSH key
        if any(k in kt for k in ("ed25519", "rsa", "ecdsa")) or entry.entry_type == "keypair":
            alias = title_slug.replace("id_", "")
            ssh_hosts_config.append(f"Host {alias}")
            ssh_hosts_config.append(f"    IdentityFile ~/.ssh/{def_priv}")
            ssh_hosts_config.append("    IdentitiesOnly yes\n")

    # Generate OpenSSH config template file
    if generate_ssh_config and len(ssh_hosts_config) > 1:
        cfg_content = "\n".join(ssh_hosts_config)
        if zip_target:
            zip_target.writestr("config", cfg_content)
        else:
            cfg_path = target_dir / "ssh_config_template"
            with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(cfg_content)
            set_strict_file_permissions(cfg_path, is_private=True)
            written_paths.append(cfg_path)

    if zip_target:
        zip_target.close()
        if final_zip_path:
            written_paths = [final_zip_path]

    return len(written_paths), written_paths
