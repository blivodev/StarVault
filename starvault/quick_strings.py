"""Quick connection strings and terminal command generators for StarVault."""

import urllib.parse
from typing import Optional
from starvault.models import VaultEntry


def generate_ssh_command(
    entry: VaultEntry,
    key_path: Optional[str] = None,
    include_port: bool = True,
) -> str:
    """Generates an SSH terminal command for a server entry."""
    user = entry.username.strip() or "root"
    host = entry.hostname.strip() or "localhost"
    port = entry.port or 22

    cmd = ["ssh"]
    if key_path:
        cmd.extend(["-i", key_path])

    if user:
        cmd.append(f"{user}@{host}")
    else:
        cmd.append(host)

    if include_port and port != 22:
        cmd.extend(["-p", str(port)])

    return " ".join(cmd)


def generate_db_url(
    entry: VaultEntry,
    db_type: Optional[str] = None,
    mask_password: bool = False,
) -> str:
    """Generates a standard database connection URL.

    Supported schemes: postgresql, mysql, redis, mongodb, sqlite.
    """
    dtype = (db_type or entry.service_type or "postgresql").lower()
    user = entry.username.strip()
    raw_pass = entry.password.strip()
    pwd = "••••••••" if (mask_password and raw_pass) else urllib.parse.quote(raw_pass, safe="")
    host = entry.hostname.strip() or entry.url.strip() or "localhost"
    port = entry.port or 5432
    db = entry.db_name.strip()

    # Clean host if URL was provided
    if "://" in host:
        parsed = urllib.parse.urlparse(host)
        host = parsed.hostname or host
        if parsed.port:
            port = parsed.port

    if "postgres" in dtype or "psql" in dtype:
        scheme = "postgresql"
        auth = f"{user}:{pwd}@" if user or pwd else ""
        return f"{scheme}://{auth}{host}:{port}/{db}"

    elif "mysql" in dtype or "mariadb" in dtype:
        scheme = "mysql"
        auth = f"{user}:{pwd}@" if user or pwd else ""
        return f"{scheme}://{auth}{host}:{port}/{db}"

    elif "redis" in dtype:
        scheme = "redis"
        auth = f":{pwd}@" if pwd else ""
        db_num = db if db.isdigit() else "0"
        return f"{scheme}://{auth}{host}:{port}/{db_num}"

    elif "mongo" in dtype:
        scheme = "mongodb"
        auth = f"{user}:{pwd}@" if user or pwd else ""
        return f"{scheme}://{auth}{host}:{port}/{db}"

    else:
        # Generic URI
        auth = f"{user}:{pwd}@" if user or pwd else ""
        return f"{dtype}://{auth}{host}:{port}/{db}"


def generate_db_cli_command(entry: VaultEntry) -> str:
    """Generates ready-to-paste CLI client commands (psql, mysql, redis-cli)."""
    dtype = (entry.service_type or "").lower()
    host = entry.hostname.strip() or entry.url.strip() or "localhost"
    port = entry.port
    user = entry.username.strip()
    db = entry.db_name.strip()

    if "postgres" in dtype:
        cmd = f"psql -h {host} -p {port or 5432}"
        if user:
            cmd += f" -U {user}"
        if db:
            cmd += f" -d {db}"
        return cmd

    elif "mysql" in dtype or "mariadb" in dtype:
        cmd = f"mysql -h {host} -P {port or 3306}"
        if user:
            cmd += f" -u {user}"
        if db:
            cmd += f" {db}"
        cmd += " -p"
        return cmd

    elif "redis" in dtype:
        cmd = f"redis-cli -h {host} -p {port or 6379}"
        return cmd

    return ""


def generate_curl_command(entry: VaultEntry) -> str:
    """Generates an authenticated curl command snippet for API/services."""
    url = entry.url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}" if url else "http://localhost"

    if entry.api_token:
        return f'curl -H "Authorization: Bearer {entry.api_token}" {url}'
    elif entry.username and entry.password:
        return f'curl -u "{entry.username}:{entry.password}" {url}'
    return f"curl {url}"
