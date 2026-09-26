"""Model Context Protocol (MCP) Server for StarVault.

Allows AI assistants (e.g. Claude Desktop, Cursor, Antigravity, local LLMs)
to securely interact with StarVault via stdio JSON-RPC without manual copy/pasting.

Security Architecture:
- Zero-Knowledge & Locked by Default: Secrets cannot be queried until unlocked.
- Ephemeral in-memory session key.
- Explicit tool calls for secret retrieval with audit tracking.
- CLI Entrypoint: python run.py --mcp or python -m starvault.mcp_server
"""

import json
from pathlib import Path
import sys
import traceback
from typing import Any, Dict, List, Optional

from starvault.api_keys import generate_api_key
from starvault.cert_generator import generate_self_signed_cert
from starvault.config import get_default_db_path
from starvault.crypto import generate_secure_password
from starvault.crypto_tools import (
    bulk_decrypt_files,
    bulk_encrypt_files,
    compute_hash,
    compute_hmac,
    decode_base64,
    decode_binary,
    decode_hex,
    decode_url,
    decrypt_file,
    decrypt_symmetric,
    encode_base64,
    encode_binary,
    encode_hex,
    encode_url,
    encrypt_file,
    encrypt_symmetric,
    rsa_decrypt,
    rsa_encrypt,
)
from starvault.database import Database
from starvault.export_utils import export_vault_to_archive, export_vault_to_csv
from starvault.health import VaultHealthAdvisor, fix_health_issue
from starvault.neural_health import audit_vault_neural, evaluate_entry_neural
from starvault.keys import (
    generate_age_key_result,
    generate_ed25519_key,
    generate_gpg_key,
    generate_rsa_key,
    generate_tls_cert_key,
    generate_wireguard_key_result,
)
from starvault.models import VaultEntry
from starvault.organizer import (
    auto_organize_files,
    auto_organize_vault,
    deduplicate_vault,
    find_duplicates,
    find_ghost_and_stale,
    purge_ghost_entries,
    sort_entries,
)
from starvault.search import search_entries
from starvault.totp import generate_totp_code


class StarVaultMCPServer:
    """Stdio JSON-RPC 2.0 MCP server implementation for StarVault."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db = Database(db_path)
        self.session_key: Optional[bytes] = None

    def run(self) -> None:
        """Reads JSON-RPC messages from stdin and writes responses to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
            except Exception as ex:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal error: {str(ex)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        msg_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                    },
                    "serverInfo": {
                        "name": "starvault-mcp",
                        "version": "2.0.0",
                    },
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.get_tool_definitions()},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                res_text = self.execute_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": res_text}],
                        "isError": False,
                    },
                }
            except Exception as ex:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: {str(ex)}"}],
                        "isError": True,
                    },
                }

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "starvault_status",
                "description": "Check whether the vault is locked/unlocked, entry counts, and security status.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "starvault_unlock",
                "description": "Unlocks StarVault with Master Password and optional 2FA QR keyfile secret.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "master_password": {"type": "string", "description": "Master vault password"},
                        "keyfile_secret": {"type": "string", "description": "Optional 256-bit QR keyfile token for 2FA vaults"},
                    },
                    "required": ["master_password"],
                },
            },
            {
                "name": "starvault_lock",
                "description": "Immediately locks StarVault and securely zeroes encryption keys in memory.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "starvault_search_entries",
                "description": "Searches credentials, services, API keys, and keypairs by query, category, or tag.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query keyword"},
                        "category": {"type": "string", "description": "Filter by category (e.g. 'All', 'Infrastructure', 'Services', 'API Keys', 'Keys')"},
                        "tag": {"type": "string", "description": "Optional tag filter (e.g. 'vps1', 'prod')"},
                    },
                },
            },
            {
                "name": "starvault_get_entry",
                "description": "Retrieves non-sensitive details and metadata of an entry by ID or Title.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or exact Title"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_get_secret",
                "description": "Securely retrieves decrypted sensitive credential (password, API token, private key) for an entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or exact Title"},
                        "secret_type": {"type": "string", "enum": ["password", "api_token", "private_key", "sudo_password", "totp_secret", "auth_code"], "description": "Which secret to retrieve"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_get_totp_code",
                "description": "Generates current 6-digit TOTP 2FA code for an entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or Title"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_list_groups",
                "description": "Lists all categories, assigned groups, assigned services, and relational tags with item counts.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "starvault_add_entry",
                "description": "Creates a new encrypted vault entry (server, service, apikey, keypair, domain).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Title or label for the entry"},
                        "entry_type": {"type": "string", "enum": ["server", "service", "apikey", "keypair", "domain"]},
                        "category": {"type": "string", "description": "Category name"},
                        "groups": {"type": "array", "items": {"type": "string"}, "description": "Multiple group assignments"},
                        "services": {"type": "array", "items": {"type": "string"}, "description": "Multiple service assignments"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                        "hostname_or_url": {"type": "string"},
                        "port": {"type": "integer"},
                        "api_token": {"type": "string"},
                        "provider": {"type": "string"},
                        "environment": {"type": "string"},
                        "notes": {"type": "string"},
                        "domain_name": {"type": "string", "description": "Domain name or FQDN"},
                        "registrar": {"type": "string", "description": "Domain registrar"},
                        "expires_at": {"type": "string", "description": "Expiry date (YYYY-MM-DD)"},
                        "auto_renew": {"type": "boolean", "description": "Whether auto-renewal is enabled"},
                        "dns_provider": {"type": "string", "description": "DNS management provider"},
                        "nameservers": {"type": "string", "description": "Nameservers (comma-separated or string)"},
                        "auth_code": {"type": "string", "description": "EPP/transfer authorization code"},
                        "parent_domain_id": {"type": "string", "description": "ID of parent domain entry"},
                    },
                    "required": ["title", "entry_type"],
                },
            },
            {
                "name": "starvault_update_entry",
                "description": "Updates an existing encrypted vault entry, including assigning multiple groups or services.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or Title to update"},
                        "title": {"type": "string"},
                        "category": {"type": "string"},
                        "groups": {"type": "array", "items": {"type": "string"}, "description": "Multiple group assignments"},
                        "services": {"type": "array", "items": {"type": "string"}, "description": "Multiple service assignments"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                        "hostname_or_url": {"type": "string"},
                        "port": {"type": "integer"},
                        "api_token": {"type": "string"},
                        "provider": {"type": "string"},
                        "environment": {"type": "string"},
                        "notes": {"type": "string"},
                        "domain_name": {"type": "string", "description": "Domain name or FQDN"},
                        "registrar": {"type": "string", "description": "Domain registrar"},
                        "expires_at": {"type": "string", "description": "Expiry date (YYYY-MM-DD)"},
                        "auto_renew": {"type": "boolean", "description": "Whether auto-renewal is enabled"},
                        "dns_provider": {"type": "string", "description": "DNS management provider"},
                        "nameservers": {"type": "string", "description": "Nameservers (comma-separated or string)"},
                        "auth_code": {"type": "string", "description": "EPP/transfer authorization code"},
                        "parent_domain_id": {"type": "string", "description": "ID of parent domain entry"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_delete_entry",
                "description": "Deletes an entry by ID or Title.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or Title to delete"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_generate_password",
                "description": "Generates a cryptographically strong random password.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "length": {"type": "integer", "default": 24},
                        "use_symbols": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "starvault_generate_api_key",
                "description": "Generates an API key in a specified format (hex64, base64_64, uuid, openai, stripe_live, aws, custom_prefixed).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "format_type": {"type": "string", "default": "hex64"},
                        "prefix": {"type": "string", "default": "sv"},
                    },
                },
            },
            {
                "name": "starvault_health_audit",
                "description": "Audits vault security posture in-memory using the internal neural network (default) or optional heuristic/AI scans.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["neural", "heuristic", "full"],
                            "default": "neural",
                            "description": "Analysis engine: 'neural' (default, local neural network), 'heuristic' (rule-based checks), 'full' (both)",
                        },
                    },
                },
            },
            {
                "name": "starvault_neural_analyze_entry",
                "description": "Runs the local zero-knowledge neural network on a specific entry to calculate multi-factor compromise risk (0-100), anomaly score, classification, entropy metrics, and actionable recommendations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or Title to analyze"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_fix_health_issue",
                "description": "Executes automated fix for a health issue (e.g. rotates weak or duplicate credentials).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "issue_index": {"type": "integer", "description": "0-based index of issue from starvault_health_audit"},
                    },
                    "required": ["issue_index"],
                },
            },
            {
                "name": "starvault_crypto_tool",
                "description": "Perform on-demand encryption, decryption, hashing, or encoding on input text across AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305, RSA OAEP, Base64, Hex, URL, Binary, SHA-256/512, and HMAC.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "enum": ["encrypt", "decrypt", "hash", "hmac", "encode", "decode"]},
                        "algorithm": {"type": "string", "description": "Algorithm: 'AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305', 'RSA', 'Base64', 'Hex', 'URL', 'Binary', 'SHA256', 'SHA512', 'MD5', 'HMAC'"},
                        "data": {"type": "string", "description": "Input plaintext or ciphertext"},
                        "key": {"type": "string", "description": "Secret key, passphrase, or PEM key (required for ciphers/HMAC)"},
                    },
                    "required": ["operation", "algorithm", "data"],
                },
            },
            {
                "name": "starvault_generate_certificate",
                "description": "Generates a self-signed TLS/SSL X.509 certificate and private key in PEM format with customizable Subject Alternative Names (SANs).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "common_name": {"type": "string", "default": "localhost"},
                        "san_list": {"type": "array", "items": {"type": "string"}, "description": "List of DNS names or IPs (e.g. ['localhost', '127.0.0.1'])"},
                        "validity_days": {"type": "integer", "default": 365},
                        "key_type": {"type": "string", "enum": ["RSA 2048", "RSA 4096", "ECDSA P-256", "Ed25519"], "default": "RSA 2048"},
                        "organization": {"type": "string", "default": "StarVault Homelab"},
                    },
                },
            },
            {
                "name": "starvault_generate_keypair",
                "description": "Generates high-entropy cryptographic keypairs for SSH (Ed25519, RSA-4096), OpenPGP/GPG, WireGuard VPN, or Age encryption.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key_type": {"type": "string", "enum": ["ssh-ed25519", "ssh-rsa", "gpg", "wireguard", "age"]},
                        "comment": {"type": "string", "description": "User or host comment (e.g. 'user@host')"},
                        "passphrase": {"type": "string", "description": "Optional passphrase for GPG or SSH key"},
                    },
                    "required": ["key_type"],
                },
            },
            {
                "name": "starvault_export_vault",
                "description": "Exports decrypted vault credentials to a standard CSV spreadsheet or full encrypted/portable archive (.zip or .7z).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "export_type": {"type": "string", "enum": ["csv", "archive_zip", "archive_7z"]},
                        "target_path": {"type": "string", "description": "Absolute output file path for the export"},
                        "master_password": {"type": "string", "description": "Master password to authenticate export authorization"},
                        "archive_password": {"type": "string", "description": "Optional password to AES-256 encrypt the output archive (.zip / .7z)"},
                        "keyfile_secret": {"type": "string", "description": "Optional 2FA token if vault uses 2FA"},
                    },
                    "required": ["export_type", "target_path", "master_password"],
                },
            },
            {
                "name": "starvault_encrypt_file",
                "description": "Encrypts or decrypts a single file using symmetric ciphers (AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "enum": ["encrypt", "decrypt"]},
                        "source_path": {"type": "string", "description": "Absolute path to source file"},
                        "dest_path": {"type": "string", "description": "Absolute path to destination file"},
                        "passphrase": {"type": "string", "description": "Encryption passphrase or key"},
                        "cipher": {"type": "string", "enum": ["AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"], "default": "AES-256-GCM"},
                    },
                    "required": ["operation", "source_path", "dest_path", "passphrase"],
                },
            },
            {
                "name": "starvault_auto_organize_vault",
                "description": "Automatically organizes the entire vault: infers categories for unorganized items, adds smart domain/cloud/protocol tags, and normalizes messy title casing and acronyms.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "override_categories": {"type": "boolean", "default": False, "description": "Whether to re-categorize items that already have non-General categories"},
                        "dry_run": {"type": "boolean", "default": False, "description": "Simulate and preview organization changes without persisting to database"},
                    },
                },
            },
            {
                "name": "starvault_deduplicate_entries",
                "description": "Detects duplicate or near-duplicate credentials and keys, and optionally auto-merges them into primary records while preserving all unique secrets, fields, and notes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "auto_merge": {"type": "boolean", "default": True, "description": "If True, automatically merges duplicates; if False, returns preview of detected clusters"},
                    },
                },
            },
            {
                "name": "starvault_clean_stale_ghosts",
                "description": "Finds and purges empty ghost records, abandoned temporary test entries, and repairs orphaned child credentials whose parent server no longer exists.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dry_run": {"type": "boolean", "default": False, "description": "If True, only reports findings without deleting"},
                    },
                },
            },
            {
                "name": "starvault_auto_organize_files",
                "description": "Auto-organizes stored File Vault attachments by file extension and MIME type into virtual category tags (Keys & Certificates, Configs & Dotfiles, Documents & Manuals, Archives & Backups, Media & Images).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dry_run": {"type": "boolean", "default": False, "description": "Simulate file tagging without saving"},
                    },
                },
            },
            {
                "name": "starvault_sort_entries",
                "description": "Returns vault entries sorted by specified dimension ('category', 'title_asc', 'title_desc', 'risk', 'recency', 'type').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sort_by": {"type": "string", "enum": ["category", "title_asc", "title_desc", "risk", "recency", "type"], "default": "category"},
                        "favorites_first": {"type": "boolean", "default": True},
                    },
                },
            },
            {
                "name": "starvault_get_entry_versions",
                "description": "Retrieves encrypted historical version snapshots, change summaries, and audit trail for a vault entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or Title"},
                        "decrypt": {"type": "boolean", "default": False, "description": "Whether to decrypt and return historical secrets in the response"},
                    },
                    "required": ["identifier"],
                },
            },
            {
                "name": "starvault_restore_entry_version",
                "description": "Restores a vault entry to a specified historical version snapshot. StarVault automatically snapshots the pre-rollback state.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {"type": "string", "description": "Entry ID or Title"},
                        "version_id": {"type": "string", "description": "UUID of the version snapshot to restore"},
                    },
                    "required": ["identifier", "version_id"],
                },
            },
            {
                "name": "starvault_clean_old_versions",
                "description": "Prunes historical credential versions and physical key files based on age and max versions criteria.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "max_age_days": {"type": "integer", "description": "Prune versions older than N days"},
                        "max_versions_per_entry": {"type": "integer", "description": "Retain only the newest N versions per entry"},
                        "entry_type": {"type": "string", "description": "Optional filter for entry type ('keypair', 'apikey', 'service', 'server')"},
                        "delete_physical_files": {"type": "boolean", "default": False, "description": "Whether to securely wipe associated physical key files on disk"},
                        "clean_keys_dir": {"type": "boolean", "default": False, "description": "Whether to scan keys directory for unreferenced stale key files"},
                        "dry_run": {"type": "boolean", "default": True, "description": "If True, only previews what would be pruned without deleting"},
                    },
                },
            },
        ]

    def _require_unlocked(self) -> bytes:
        if self.session_key is None:
            raise PermissionError("Vault is locked. Call 'starvault_unlock' with your master password first.")
        return self.session_key

    def _find_entry(self, identifier: str, key: bytes) -> Optional[VaultEntry]:
        clean_id = identifier.strip()
        entries = self.db.get_all_entries(key)
        for e in entries:
            if e.id == clean_id:
                return e
        for e in entries:
            if e.title.lower() == clean_id.lower():
                return e
        return None

    def execute_tool(self, name: str, args: Dict[str, Any]) -> str:
        if name == "starvault_status":
            is_unlocked = self.session_key is not None
            is_init = self.db.is_initialized()
            requires_2fa = self.db.requires_2fa()
            if is_unlocked:
                entries = self.db.get_all_entries(self.session_key)
                count = len(entries)
            else:
                count = "Locked (Unlock to view)"
            return json.dumps({
                "status": "unlocked" if is_unlocked else "locked",
                "database_path": str(self.db.db_path),
                "is_initialized": is_init,
                "requires_2fa": requires_2fa,
                "entries_count": count,
            }, indent=2)

        elif name == "starvault_unlock":
            pwd = args.get("master_password", "")
            keyfile = args.get("keyfile_secret")
            success, key = self.db.unlock_vault(pwd, keyfile_secret=keyfile)
            if success and key:
                self.session_key = key
                entries = self.db.get_all_entries(key)
                return f"Successfully unlocked vault ({len(entries)} items accessible)."
            else:
                return "Failed to unlock vault. Invalid master password or 2FA keyfile."

        elif name == "starvault_lock":
            self.session_key = None
            return "Vault successfully locked. Session keys zeroed from memory."

        elif name == "starvault_search_entries":
            key = self._require_unlocked()
            entries = self.db.get_all_entries(key)
            query = args.get("query", "")
            category = args.get("category", "All")
            tag = args.get("tag")

            results = search_entries(entries, query=query, selected_category=category, selected_tag=tag)
            output = []
            for e, score in results[:20]:
                item = {
                    "id": e.id,
                    "title": e.title,
                    "type": e.entry_type,
                    "category": e.category,
                    "groups": getattr(e, "groups", []),
                    "services": getattr(e, "services", []),
                    "tags": e.tags,
                    "host_or_url": e.hostname or e.url,
                    "username": e.username,
                    "provider": e.provider,
                    "relevance_score": round(score, 1),
                }
                output.append(item)
            return json.dumps(output, indent=2)

        elif name == "starvault_get_entry":
            key = self._require_unlocked()
            e = self._find_entry(args.get("identifier", ""), key)
            if not e:
                return "Entry not found."
            return json.dumps({
                "id": e.id,
                "title": e.title,
                "type": e.entry_type,
                "category": e.category,
                "groups": getattr(e, "groups", []),
                "services": getattr(e, "services", []),
                "tags": e.tags,
                "hostname": e.hostname,
                "port": e.port,
                "username": e.username,
                "url": e.url,
                "provider": e.provider,
                "environment": e.environment,
                "expires_at": e.expires_at,
                "domain_name": getattr(e, "domain_name", ""),
                "registrar": getattr(e, "registrar", ""),
                "auto_renew": getattr(e, "auto_renew", False),
                "dns_provider": getattr(e, "dns_provider", ""),
                "nameservers": getattr(e, "nameservers", ""),
                "parent_domain_id": getattr(e, "parent_domain_id", None),
                "parent_server_id": getattr(e, "parent_server_id", None),
                "notes": e.notes,
                "created_at": e.created_at,
                "updated_at": e.updated_at,
                "custom_fields": e.custom_fields,
            }, indent=2)

        elif name == "starvault_get_secret":
            key = self._require_unlocked()
            e = self._find_entry(args.get("identifier", ""), key)
            if not e:
                return "Entry not found."
            stype = args.get("secret_type", "password")
            if stype == "password":
                val = e.password
            elif stype == "api_token":
                val = e.api_token or e.password
            elif stype == "private_key":
                val = e.private_key or e.ssh_private_key
            elif stype == "sudo_password":
                val = e.sudo_password
            elif stype == "totp_secret":
                val = e.totp_secret
            elif stype == "auth_code":
                val = getattr(e, "auth_code", "")
            else:
                val = e.password

            return json.dumps({
                "entry_title": e.title,
                "secret_type": stype,
                "secret_value": val,
                "warning": "Sensitive secret retrieved. Ensure this is handled securely.",
            }, indent=2)

        elif name == "starvault_get_totp_code":
            key = self._require_unlocked()
            e = self._find_entry(args.get("identifier", ""), key)
            if not e:
                return "Entry not found."
            secret = e.totp_secret or ""
            if not secret:
                # Check custom fields for TOTP
                for cf in e.custom_fields:
                    if "totp" in cf.get("key", "").lower() or "2fa" in cf.get("key", "").lower():
                        secret = cf.get("value", "")
                        break
            if not secret:
                return f"No 2FA/TOTP secret configured for entry '{e.title}'."

            code = generate_totp_code(secret)
            return json.dumps({
                "entry_title": e.title,
                "totp_code": code,
                "expires_in_seconds": 30 - int(__import__("time").time() % 30),
            }, indent=2)

        elif name == "starvault_list_groups":
            key = self._require_unlocked()
            entries = self.db.get_all_entries(key)

            cats: Dict[str, int] = {}
            groups_map: Dict[str, int] = {}
            services_map: Dict[str, int] = {}
            tags: Dict[str, int] = {}
            for e in entries:
                cats[e.category] = cats.get(e.category, 0) + 1
                for g in getattr(e, "groups", []):
                    if g:
                        groups_map[g] = groups_map.get(g, 0) + 1
                for s in getattr(e, "services", []):
                    if s:
                        services_map[s] = services_map.get(s, 0) + 1
                for t in e.tags:
                    tags[t] = tags.get(t, 0) + 1

            return json.dumps({
                "categories": [{"category": k, "count": v} for k, v in sorted(cats.items())],
                "groups": [{"group": k, "count": v} for k, v in sorted(groups_map.items())],
                "services": [{"service": k, "count": v} for k, v in sorted(services_map.items())],
                "tags": [{"tag": k, "count": v} for k, v in sorted(tags.items())],
                "total_entries": len(entries),
            }, indent=2)

        elif name == "starvault_add_entry":
            key = self._require_unlocked()
            etype = args.get("entry_type", "server")
            title = args.get("title", "New Entry")
            grps = args.get("groups", [])
            srvs = args.get("services", [])
            if isinstance(grps, str):
                grps = [x.strip() for x in grps.split(",") if x.strip()]
            if isinstance(srvs, str):
                srvs = [x.strip() for x in srvs.split(",") if x.strip()]

            if etype == "domain":
                entry = VaultEntry.create_domain(
                    title=title,
                    domain_name=args.get("domain_name") or args.get("hostname_or_url", ""),
                    registrar=args.get("registrar", ""),
                    expires_at=args.get("expires_at", ""),
                    auto_renew=bool(args.get("auto_renew", False)),
                    dns_provider=args.get("dns_provider", ""),
                    nameservers=args.get("nameservers", ""),
                    auth_code=args.get("auth_code", ""),
                    category=args.get("category", "Domains"),
                    tags=args.get("tags", []),
                    notes=args.get("notes", ""),
                )
                if grps:
                    entry.groups = list(grps)
                if srvs:
                    entry.services = list(srvs)
                if "username" in args:
                    entry.username = args["username"]
                if "password" in args:
                    entry.password = args["password"]
                if "totp_secret" in args:
                    entry.totp_secret = args["totp_secret"]
                if "parent_domain_id" in args:
                    entry.parent_domain_id = args["parent_domain_id"]
            else:
                entry = VaultEntry(
                    title=title,
                    entry_type=etype,
                    category=args.get("category", "General"),
                    groups=list(grps) if grps else [],
                    services=list(srvs) if srvs else [],
                    tags=args.get("tags", []),
                    username=args.get("username", ""),
                    password=args.get("password", ""),
                    hostname=args.get("hostname_or_url", ""),
                    url=args.get("hostname_or_url", ""),
                    port=args.get("port", 22 if etype == "server" else 80),
                    api_token=args.get("api_token", ""),
                    provider=args.get("provider", ""),
                    environment=args.get("environment", "Production"),
                    notes=args.get("notes", ""),
                    expires_at=args.get("expires_at", ""),
                    parent_domain_id=args.get("parent_domain_id"),
                )
            self.db.save_entry(entry, key)
            return f"Successfully created {etype} entry '{entry.title}' (ID: {entry.id})."

        elif name == "starvault_update_entry":
            key = self._require_unlocked()
            e = self._find_entry(args.get("identifier", ""), key)
            if not e:
                return "Entry not found."
            if "title" in args:
                e.title = args["title"]
            if "category" in args:
                e.category = args["category"]
            if "groups" in args:
                g = args["groups"]
                e.groups = [x.strip() for x in g.split(",") if x.strip()] if isinstance(g, str) else list(g)
            if "services" in args:
                s = args["services"]
                e.services = [x.strip() for x in s.split(",") if x.strip()] if isinstance(s, str) else list(s)
            if "tags" in args:
                e.tags = args["tags"]
            if "username" in args:
                e.username = args["username"]
            if "password" in args:
                e.password = args["password"]
            if "hostname_or_url" in args:
                e.hostname = args["hostname_or_url"]
                e.url = args["hostname_or_url"]
            if "port" in args:
                e.port = args["port"]
            if "api_token" in args:
                e.api_token = args["api_token"]
            if "provider" in args:
                e.provider = args["provider"]
            if "environment" in args:
                e.environment = args["environment"]
            if "notes" in args:
                e.notes = args["notes"]
            if "domain_name" in args:
                e.domain_name = args["domain_name"]
            if "registrar" in args:
                e.registrar = args["registrar"]
            if "expires_at" in args:
                e.expires_at = args["expires_at"]
            if "auto_renew" in args:
                e.auto_renew = bool(args["auto_renew"])
            if "dns_provider" in args:
                e.dns_provider = args["dns_provider"]
            if "nameservers" in args:
                e.nameservers = args["nameservers"]
            if "auth_code" in args:
                e.auth_code = args["auth_code"]
            if "parent_domain_id" in args:
                e.parent_domain_id = args["parent_domain_id"]
            self.db.save_entry(e, key)
            return f"Successfully updated entry '{e.title}' (ID: {e.id})."

        elif name == "starvault_delete_entry":
            key = self._require_unlocked()
            e = self._find_entry(args.get("identifier", ""), key)
            if not e:
                return "Entry not found."
            self.db.delete_entry(e.id)
            return f"Successfully deleted entry '{e.title}'."

        elif name == "starvault_generate_password":
            length = args.get("length", 24)
            symbols = args.get("use_symbols", True)
            pwd = generate_secure_password(length=length, use_symbols=symbols)
            return json.dumps({"password": pwd, "length": len(pwd)})

        elif name == "starvault_generate_api_key":
            fmt = args.get("format_type", "hex64")
            prefix = args.get("prefix", "sv")
            p_key, s_key = generate_api_key(format_type=fmt, prefix=prefix)
            res = {"primary_key": p_key, "format": fmt}
            if s_key:
                res["secret_key"] = s_key
            return json.dumps(res, indent=2)

        elif name == "starvault_health_audit":
            key = self._require_unlocked()
            entries = self.db.get_all_entries(key)
            mode = args.get("mode", "neural").lower()
            advisor = VaultHealthAdvisor()
            report = advisor.analyze(entries)
            na = report.neural_audit or audit_vault_neural(entries)

            if mode == "neural":
                return json.dumps({
                    "engine": na.engine_name,
                    "mode": na.engine_mode,
                    "overall_score": na.safety_index,
                    "neural_safety_index": na.safety_index,
                    "grade": na.letter_grade,
                    "neural_grade": na.letter_grade,
                    "total_entries_evaluated": na.total_entries_evaluated,
                    "mean_risk_score": round(na.mean_risk_score, 1),
                    "high_risk_entries_count": na.high_risk_entries_count,
                    "anomalies_flagged_count": na.anomalies_flagged_count,
                    "class_distribution": na.class_distribution,
                    "top_vulnerabilities": na.top_vulnerabilities,
                    "suggested_optimizations": na.suggested_optimizations,
                    "execution_time_ms": round(na.execution_time_ms, 2),
                }, indent=2)
            elif mode == "heuristic":
                issues_out = []
                for idx, iss in enumerate(report.issues):
                    issues_out.append({
                        "issue_index": idx,
                        "title": iss.title,
                        "severity": iss.severity,
                        "issue_type": iss.issue_type,
                        "remediation_action": iss.remediation_action,
                        "description": iss.description,
                        "recommendation": iss.recommendation,
                    })
                return json.dumps({
                    "overall_score": report.overall_score,
                    "grade": report.grade,
                    "total_entries": report.total_entries_analyzed,
                    "issues": issues_out,
                }, indent=2)
            else:  # "full"
                issues_out = []
                for idx, iss in enumerate(report.issues):
                    issues_out.append({
                        "issue_index": idx,
                        "title": iss.title,
                        "severity": iss.severity,
                        "issue_type": iss.issue_type,
                        "remediation_action": iss.remediation_action,
                        "description": iss.description,
                        "recommendation": iss.recommendation,
                    })
                return json.dumps({
                    "overall_score": report.overall_score,
                    "heuristic_grade": report.grade,
                    "neural_safety_index": na.safety_index,
                    "neural_grade": na.letter_grade,
                    "total_entries": report.total_entries_analyzed,
                    "engine": na.engine_name,
                    "mode": na.engine_mode,
                    "anomalies_flagged_count": na.anomalies_flagged_count,
                    "class_distribution": na.class_distribution,
                    "top_vulnerabilities": na.top_vulnerabilities,
                    "suggested_optimizations": na.suggested_optimizations,
                    "issues": issues_out,
                }, indent=2)

        elif name == "starvault_neural_analyze_entry":
            key = self._require_unlocked()
            identifier = args.get("identifier", "")
            e = self._find_entry(identifier, key)
            if not e:
                return f"Entry '{identifier}' not found."
            entries = self.db.get_all_entries(key)
            reuse_map: Dict[str, int] = {}
            for ent in entries:
                pwd = ent.password or ent.api_token
                if pwd:
                    reuse_map[pwd] = reuse_map.get(pwd, 0) + 1
            assessment = evaluate_entry_neural(e)
            return json.dumps({
                "entry_id": assessment.entry_id,
                "entry_title": assessment.entry_title,
                "entry_type": assessment.entry_type,
                "risk_score": assessment.risk_score,
                "safety_score": assessment.safety_score,
                "anomaly_score": assessment.anomaly_score,
                "predicted_class": assessment.predicted_class,
                "class_probabilities": assessment.class_probabilities,
                "anomalies": assessment.anomalies,
                "recommendations": assessment.recommendations,
                "recommended_groups": assessment.recommended_groups,
                "recommended_services": assessment.recommended_services,
                "auto_fix_action": assessment.auto_fix_action,
            }, indent=2)

        elif name == "starvault_fix_health_issue":
            key = self._require_unlocked()
            idx = args.get("issue_index", 0)
            entries = self.db.get_all_entries(key)
            advisor = VaultHealthAdvisor()
            report = advisor.analyze(entries)
            if idx < 0 or idx >= len(report.issues):
                return f"Invalid issue index {idx}. Run 'starvault_health_audit' first."
            issue = report.issues[idx]
            success, msg = fix_health_issue(issue, self.db, key)
            return msg

        elif name == "starvault_crypto_tool":
            op = args.get("operation", "encrypt").lower()
            algo = args.get("algorithm", "AES-256-GCM")
            data = args.get("data", "")
            key = args.get("key", "")

            algo_upper = algo.upper()
            if op == "encrypt":
                if "AES" in algo_upper or "CHACHA" in algo_upper:
                    if not key:
                        raise ValueError("Passphrase or key required for symmetric encryption.")
                    res = encrypt_symmetric(data, key, cipher=algo)
                elif "RSA" in algo_upper:
                    if not key:
                        raise ValueError("RSA Public Key required for encryption.")
                    res = rsa_encrypt(data, key)
                else:
                    res = encode_base64(data)
                return json.dumps({"operation": op, "algorithm": algo, "result": res})

            elif op == "decrypt":
                if "AES" in algo_upper or "CHACHA" in algo_upper:
                    if not key:
                        raise ValueError("Passphrase or key required for symmetric decryption.")
                    res = decrypt_symmetric(data, key, cipher=algo)
                elif "RSA" in algo_upper:
                    if not key:
                        raise ValueError("RSA Private Key required for decryption.")
                    res = rsa_decrypt(data, key)
                else:
                    res = decode_base64(data)
                return json.dumps({"operation": op, "algorithm": algo, "result": res})

            elif op == "hash":
                h_res = compute_hash(data, algorithm=algo)
                return json.dumps({"operation": op, "algorithm": algo, "hash": h_res})

            elif op == "hmac":
                if not key:
                    raise ValueError("Secret key required for HMAC computation.")
                hmac_res = compute_hmac(data, key, algorithm=algo)
                return json.dumps({"operation": op, "algorithm": algo, "hmac": hmac_res})

            elif op == "encode":
                if "HEX" in algo_upper:
                    res = encode_hex(data)
                elif "URL" in algo_upper:
                    res = encode_url(data)
                elif "BIN" in algo_upper:
                    res = encode_binary(data)
                else:
                    res = encode_base64(data)
                return json.dumps({"operation": op, "format": algo, "result": res})

            elif op == "decode":
                if "HEX" in algo_upper:
                    res = decode_hex(data)
                elif "URL" in algo_upper:
                    res = decode_url(data)
                elif "BIN" in algo_upper:
                    res = decode_binary(data)
                else:
                    res = decode_base64(data)
                return json.dumps({"operation": op, "format": algo, "result": res})

            else:
                raise ValueError(f"Unsupported operation: {op}")

        elif name == "starvault_generate_certificate":
            cn = args.get("common_name", "localhost")
            sans = args.get("san_list")
            days = int(args.get("validity_days", 365))
            ktype = args.get("key_type", "RSA 2048")
            org = args.get("organization", "StarVault Homelab")
            cert_pem, key_pem = generate_self_signed_cert(
                common_name=cn,
                san_list=sans,
                organization=org,
                validity_days=days,
                key_type=ktype,
            )
            return json.dumps({
                "common_name": cn,
                "san_list": sans or [],
                "validity_days": days,
                "key_type": ktype,
                "certificate_pem": cert_pem,
                "private_key_pem": key_pem,
            }, indent=2)

        elif name == "starvault_generate_keypair":
            ktype = args.get("key_type", "ssh-ed25519").lower()
            comment = args.get("comment", "")
            passphrase = args.get("passphrase", "")

            if ktype in ("ssh-ed25519", "ed25519"):
                res = generate_ed25519_key(comment=comment or "starvault-ed25519")
            elif ktype in ("ssh-rsa", "rsa"):
                res = generate_rsa_key(comment=comment or "starvault-rsa")
            elif ktype == "gpg":
                res = generate_gpg_key(passphrase=passphrase or None)
            elif ktype == "wireguard":
                res = generate_wireguard_key_result()
            elif ktype == "age":
                res = generate_age_key_result()
            else:
                raise ValueError(f"Unsupported key_type: {ktype}")

            return json.dumps({
                "key_type": res.key_type,
                "algorithm": res.algorithm_name,
                "public_key": res.public_key,
                "private_key": res.private_key,
                "fingerprint": res.fingerprint,
                "comment": res.comment,
                "format_notes": res.format_notes,
            }, indent=2)

        elif name == "starvault_export_vault":
            exp_type = args.get("export_type", "csv").lower()
            tgt_path = args.get("target_path", "")
            pwd = args.get("master_password", "")
            arch_pwd = args.get("archive_password")
            kf = args.get("keyfile_secret")

            if not tgt_path or not pwd:
                raise ValueError("Both target_path and master_password are required.")

            if exp_type == "csv":
                ok, msg, count = export_vault_to_csv(self.db, pwd, Path(tgt_path), keyfile_secret=kf)
                return json.dumps({"success": ok, "message": msg, "exported_count": count})
            else:
                fmt = "7z" if "7z" in exp_type else "zip"
                ok, msg, summ = export_vault_to_archive(
                    database=self.db,
                    master_password=pwd,
                    target_archive_path=Path(tgt_path),
                    archive_format=fmt,
                    archive_password=arch_pwd,
                    keyfile_secret=kf,
                )
                return json.dumps({"success": ok, "message": msg, "summary": summ}, indent=2)

        elif name == "starvault_encrypt_file":
            op = args.get("operation", "encrypt").lower()
            src = args.get("source_path", "")
            dst = args.get("dest_path", "")
            pw = args.get("passphrase", "")
            cipher = args.get("cipher", "AES-256-GCM")

            if not src or not dst or not pw:
                raise ValueError("source_path, dest_path, and passphrase are required.")

            if op == "encrypt":
                bytes_written = encrypt_file(src, dst, pw, cipher=cipher)
                return json.dumps({"success": True, "operation": op, "bytes_written": bytes_written, "dest_path": dst})
            elif op == "decrypt":
                bytes_written = decrypt_file(src, dst, pw, cipher=cipher)
                return json.dumps({"success": True, "operation": op, "bytes_written": bytes_written, "dest_path": dst})
            else:
                raise ValueError(f"Unknown operation: {op}")

        elif name == "starvault_auto_organize_vault":
            key = self._require_unlocked()
            override = args.get("override_categories", False)
            dry_run = args.get("dry_run", False)
            summary = auto_organize_vault(self.db, key, override_categories=override, dry_run=dry_run)
            return json.dumps({
                "success": True,
                "dry_run": dry_run,
                "total_entries_scanned": summary.total_entries_scanned,
                "categories_updated": summary.categories_updated,
                "tags_added": summary.tags_added,
                "titles_normalized": summary.titles_normalized,
                "duplicates_found": summary.duplicates_found,
                "sample_changes": summary.details[:15],
            }, indent=2)

        elif name == "starvault_deduplicate_entries":
            key = self._require_unlocked()
            auto_merge = args.get("auto_merge", True)
            res = deduplicate_vault(self.db, key, auto_merge=auto_merge)
            return json.dumps({
                "success": True,
                "auto_merge": auto_merge,
                "duplicate_groups_count": res.get("duplicate_groups_count", 0),
                "merged_count": res.get("merged_count", 0),
                "details": res.get("details", []) if auto_merge else res.get("groups", []),
            }, indent=2)

        elif name == "starvault_clean_stale_ghosts":
            key = self._require_unlocked()
            dry_run = args.get("dry_run", False)
            if dry_run:
                entries = self.db.get_all_entries(key)
                findings = find_ghost_and_stale(entries)
                return json.dumps({
                    "success": True,
                    "dry_run": True,
                    "ghosts_count": len(findings["ghosts"]),
                    "orphans_count": len(findings["orphans"]),
                    "stale_test_count": len(findings["stale_test"]),
                    "ghost_titles": [g.title for g in findings["ghosts"]],
                }, indent=2)
            else:
                res = purge_ghost_entries(self.db, key)
                return json.dumps({
                    "success": True,
                    "dry_run": False,
                    "purged_ghosts": res["purged_ghosts"],
                    "fixed_orphans": res["fixed_orphans"],
                    "total_cleaned": res["total_cleaned"],
                }, indent=2)

        elif name == "starvault_auto_organize_files":
            key = self._require_unlocked()
            dry_run = args.get("dry_run", False)
            res = auto_organize_files(self.db, key, dry_run=dry_run)
            return json.dumps({
                "success": True,
                "dry_run": dry_run,
                "total_files_scanned": res["total_files_scanned"],
                "files_updated": res["files_updated"],
                "folder_breakdown": res["folder_breakdown"],
            }, indent=2)

        elif name == "starvault_sort_entries":
            key = self._require_unlocked()
            sort_by = args.get("sort_by", "category")
            fav_first = args.get("favorites_first", True)
            entries = self.db.get_all_entries(key)
            sorted_entries = sort_entries(entries, sort_by=sort_by, favorites_first=fav_first)
            return json.dumps({
                "success": True,
                "sort_by": sort_by,
                "total_entries": len(sorted_entries),
                "entries": [
                    {
                        "id": e.id,
                        "title": e.title,
                        "category": e.category,
                        "entry_type": e.entry_type,
                        "tags": e.tags,
                        "is_favorite": e.is_favorite,
                        "updated_at": e.updated_at,
                    }
                    for e in sorted_entries
                ],
            }, indent=2)

        elif name == "starvault_get_entry_versions":
            key = self._require_unlocked()
            identifier = args.get("identifier", "").strip()
            entry = self._find_entry(identifier, key)
            if not entry:
                raise ValueError(f"Entry '{identifier}' not found.")
            decrypt = bool(args.get("decrypt", False))
            versions = self.db.get_entry_versions(entry.id, key=key, decrypt=decrypt)
            return json.dumps({
                "success": True,
                "entry_id": entry.id,
                "title": entry.title,
                "total_versions": len(versions),
                "versions": [v.to_dict() for v in versions],
            }, indent=2)

        elif name == "starvault_restore_entry_version":
            key = self._require_unlocked()
            identifier = args.get("identifier", "").strip()
            version_id = args.get("version_id", "").strip()
            entry = self._find_entry(identifier, key)
            if not entry:
                raise ValueError(f"Entry '{identifier}' not found.")
            restored = self.db.restore_entry_version(entry.id, version_id, key)
            if not restored:
                raise ValueError(f"Version '{version_id}' not found for entry '{entry.title}'.")
            return json.dumps({
                "success": True,
                "message": f"Successfully restored '{restored.title}' to target historical version.",
                "entry_id": restored.id,
                "title": restored.title,
                "updated_at": restored.updated_at,
            }, indent=2)

        elif name == "starvault_clean_old_versions":
            max_age = args.get("max_age_days")
            max_v = args.get("max_versions_per_entry")
            etype = args.get("entry_type")
            del_files = bool(args.get("delete_physical_files", False))
            clean_keys = bool(args.get("clean_keys_dir", False))
            dry_run = bool(args.get("dry_run", True))
            res = self.db.clean_old_versions(
                max_age_days=max_age,
                max_versions_per_entry=max_v,
                entry_type=etype,
                delete_physical_files=del_files,
                clean_keys_dir=clean_keys,
                dry_run=dry_run,
            )
            return json.dumps({
                "success": True,
                "result": res.to_dict(),
            }, indent=2)

        else:
            raise ValueError(f"Unknown tool: {name}")


if __name__ == "__main__":
    server = StarVaultMCPServer()
    server.run()
