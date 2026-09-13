"""Unit tests for quick-strings and relational search."""

import pytest
from starvault.models import VaultEntry
from starvault.quick_strings import (
    generate_curl_command,
    generate_db_url,
    generate_ssh_command,
)
from starvault.search import search_entries


def test_quick_strings_ssh():
    server = VaultEntry.create_server(
        title="Prod-01",
        hostname="10.0.0.5",
        username="admin",
        port=2222,
    )
    cmd = generate_ssh_command(server)
    assert cmd == "ssh admin@10.0.0.5 -p 2222"

    cmd_key = generate_ssh_command(server, key_path="~/.ssh/id_ed25519")
    assert cmd_key == "ssh -i ~/.ssh/id_ed25519 admin@10.0.0.5 -p 2222"


def test_quick_strings_db_url():
    pg = VaultEntry.create_service(
        title="Postgres",
        app_name="PostgreSQL",
        url="localhost",
        port=5432,
        username="postgres",
        password="secretpassword",
        db_name="starvault_db",
        service_type="postgresql",
    )
    url = generate_db_url(pg)
    assert url == "postgresql://postgres:secretpassword@localhost:5432/starvault_db"

    masked = generate_db_url(pg, mask_password=True)
    assert masked == "postgresql://postgres:••••••••@localhost:5432/starvault_db"


def test_quick_strings_curl():
    api = VaultEntry.create_service(
        title="Internal API",
        app_name="Auth Service",
        url="http://api.local/v1/health",
        api_token="eyJhbGciOi...",
    )
    curl = generate_curl_command(api)
    assert curl == 'curl -H "Authorization: Bearer eyJhbGciOi..." http://api.local/v1/health'


def test_relational_search_vps1():
    server = VaultEntry.create_server(
        title="VPS1",
        hostname="192.168.1.50",
        username="root",
        tags=["vps1", "homelab"],
    )

    postgres = VaultEntry.create_service(
        title="Postgres Production",
        app_name="PostgreSQL",
        url="192.168.1.50",
        port=5432,
        tags=["vps1", "database"],
    )

    docker = VaultEntry.create_service(
        title="Docker Registry",
        app_name="Docker",
        url="http://192.168.1.50:5000",
        tags=["vps1", "containers"],
    )

    unrelated = VaultEntry.create_server(
        title="RaspberryPi Backup",
        hostname="192.168.1.99",
        tags=["backup", "rpi"],
    )

    entries = [server, postgres, docker, unrelated]

    # Searching "vps1" must return VPS1 server AND both services sharing tag "vps1"
    results = search_entries(entries, "vps1")
    matched_ids = [e.id for e, score in results]

    assert server.id in matched_ids
    assert postgres.id in matched_ids
    assert docker.id in matched_ids
    assert unrelated.id not in matched_ids
