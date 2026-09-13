"""Localhost HTTP Bridge Server for Chromium Browser Extension (Chrome, Brave, Edge).

Provides a secure loopback API on 127.0.0.1:8088 enabling browser extensions
to query credentials for the active tab, generate passwords, and auto-save new logins.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from starvault.config import APP_VERSION
from starvault.crypto import generate_secure_password
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.search import search_entries
from starvault.totp import generate_totp_code


DEFAULT_BRIDGE_PORT = 8088


class ExtensionBridgeHandler(BaseHTTPRequestHandler):
    """Handles JSON requests from the StarVault browser extension."""

    def log_message(self, format, *args):
        # Suppress noisy stdout logs during normal operations
        pass

    def _send_cors_headers(self, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-StarVault-Token")
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_OPTIONS(self):
        self._send_cors_headers(200)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len > 0:
                raw = self.rfile.read(content_len)
                return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
        return {}

    def _check_auth(self) -> bool:
        expected = self.server.bridge_token
        if not expected:
            return True
        auth_header = self.headers.get("Authorization", "")
        custom_header = self.headers.get("X-StarVault-Token", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token == expected:
                return True
        if custom_header.strip() == expected:
            return True
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            is_unlocked = self.server.get_session_key() is not None
            self._send_cors_headers(200)
            resp = {
                "app": "StarVault",
                "version": APP_VERSION,
                "unlocked": is_unlocked,
                "port": self.server.server_port,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if parsed.path == "/api/theme":
            from starvault.ui.theme import THEME_PALETTES, get_current_theme
            curr = get_current_theme()
            palette = THEME_PALETTES.get(curr, THEME_PALETTES["Dark"])
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({"theme": curr, "palette": palette}).encode("utf-8"))
            return

        self._send_cors_headers(404)
        self.wfile.write(json.dumps({"error": "Not found"}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/generate_password":
            data = self._read_json_body()
            length = int(data.get("length", 20))
            pwd = generate_secure_password(length=length)
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({"password": pwd}).encode("utf-8"))
            return

        if path == "/api/generate_api_key":
            from starvault.api_keys import generate_api_key
            data = self._read_json_body()
            fmt = data.get("format", "hex64")
            prefix = data.get("prefix", "sv")
            primary_key, secret_key = generate_api_key(fmt, prefix=prefix)
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({"key": primary_key, "secret": secret_key, "format": fmt}).encode("utf-8"))
            return

        if path == "/api/crypto_tool":
            from starvault.crypto_tools import (
                compute_hash,
                compute_hmac,
                decode_base64,
                decode_hex,
                decode_url,
                decrypt_symmetric,
                encode_base64,
                encode_hex,
                encode_url,
                encrypt_symmetric,
            )
            data = self._read_json_body()
            op = data.get("operation", "hash").lower()
            algo = data.get("algorithm", "SHA-256")
            text = data.get("text", "")
            key = data.get("key", "")

            try:
                algo_upper = algo.upper()
                if op == "encrypt":
                    res = encrypt_symmetric(text, key, cipher=algo)
                elif op == "decrypt":
                    res = decrypt_symmetric(text, key, cipher=algo)
                elif op == "hash":
                    res = compute_hash(text, algorithm=algo)
                elif op == "hmac":
                    res = compute_hmac(text, key, algorithm=algo)
                elif op == "encode":
                    res = encode_base64(text) if "BASE" in algo_upper else (encode_hex(text) if "HEX" in algo_upper else encode_url(text))
                elif op == "decode":
                    res = decode_base64(text) if "BASE" in algo_upper else (decode_hex(text) if "HEX" in algo_upper else decode_url(text))
                else:
                    res = compute_hash(text, "sha256")

                self._send_cors_headers(200)
                self.wfile.write(json.dumps({"success": True, "result": res}).encode("utf-8"))
            except Exception as ex:
                self._send_cors_headers(400)
                self.wfile.write(json.dumps({"success": False, "error": str(ex)}).encode("utf-8"))
            return

        session_key = self.server.get_session_key()
        if not session_key:
            self._send_cors_headers(401)
            self.wfile.write(json.dumps({"error": "Vault is locked. Please unlock StarVault first."}).encode("utf-8"))
            return

        db: Database = self.server.database

        if path == "/api/search":
            data = self._read_json_body()
            url = data.get("url", "").strip()
            query = data.get("query", "").strip()

            domain = ""
            if url:
                parsed_url = urlparse(url if "://" in url else f"https://{url}")
                domain = parsed_url.hostname or ""

            search_term = domain or query
            entries = db.get_all_entries(session_key)
            results = search_entries(entries, query=search_term) if search_term else [(e, 1.0) for e in entries]

            matched = []
            for e, score in results[:15]:
                matched.append({
                    "id": e.id,
                    "title": e.title,
                    "type": e.entry_type,
                    "username": e.username,
                    "url": e.url or e.hostname,
                    "category": e.category,
                    "has_password": bool(e.password),
                    "has_totp": bool(e.totp_secret),
                })

            self._send_cors_headers(200)
            self.wfile.write(json.dumps({"matches": matched, "query": search_term}).encode("utf-8"))
            return

        elif path == "/api/get_credentials":
            data = self._read_json_body()
            entry_id = data.get("entry_id", "").strip()
            entry = db.get_entry(entry_id, session_key)
            if not entry:
                self._send_cors_headers(404)
                self.wfile.write(json.dumps({"error": "Entry not found"}).encode("utf-8"))
                return

            totp_code = ""
            if entry.totp_secret:
                totp_code = generate_totp_code(entry.totp_secret)

            self._send_cors_headers(200)
            self.wfile.write(json.dumps({
                "id": entry.id,
                "title": entry.title,
                "username": entry.username,
                "password": entry.password,
                "api_token": entry.api_token,
                "totp_code": totp_code,
                "url": entry.url or entry.hostname,
            }).encode("utf-8"))
            return

        elif path == "/api/save_entry":
            data = self._read_json_body()
            title = data.get("title", "").strip()
            url = data.get("url", "").strip()
            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not title:
                parsed_u = urlparse(url if "://" in url else f"https://{url}")
                title = parsed_u.hostname or "New Login"

            new_entry = VaultEntry.create_service(
                title=title,
                app_name=title,
                url=url,
                username=username,
                password=password,
            )
            db.save_entry(new_entry, session_key)
            self._send_cors_headers(201)
            self.wfile.write(json.dumps({"success": True, "id": new_entry.id, "title": new_entry.title}).encode("utf-8"))
            return

        elif path == "/api/auto_organize":
            session_key = self.server.get_session_key()
            if not session_key:
                self._send_cors_headers(401)
                self.wfile.write(json.dumps({"error": "Vault is locked"}).encode("utf-8"))
                return
            from starvault.organizer import auto_organize_vault
            data = self._read_json_body()
            override = data.get("override_categories", False)
            dry_run = data.get("dry_run", False)
            summ = auto_organize_vault(self.server.database, session_key, override_categories=override, dry_run=dry_run)
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({
                "success": True,
                "categories_updated": summ.categories_updated,
                "tags_added": summ.tags_added,
                "titles_normalized": summ.titles_normalized,
            }).encode("utf-8"))
            return

        elif path == "/api/deduplicate":
            session_key = self.server.get_session_key()
            if not session_key:
                self._send_cors_headers(401)
                self.wfile.write(json.dumps({"error": "Vault is locked"}).encode("utf-8"))
                return
            from starvault.organizer import deduplicate_vault
            res = deduplicate_vault(self.server.database, session_key, auto_merge=True)
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({
                "success": True,
                "merged_count": res["merged_count"],
            }).encode("utf-8"))
            return

        elif path == "/api/lock":
            if self.server.on_lock:
                self.server.on_lock()
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({"success": True, "message": "Vault locked"}).encode("utf-8"))
            return

        self._send_cors_headers(404)
        self.wfile.write(json.dumps({"error": "Unknown API endpoint"}).encode("utf-8"))


class ExtensionBridgeServer:
    """Manages the background loopback HTTP server for browser extension communication."""

    def __init__(
        self,
        database: Database,
        get_session_key: Callable[[], Optional[bytes]],
        on_lock: Optional[Callable[[], None]] = None,
        port: int = DEFAULT_BRIDGE_PORT,
    ) -> None:
        self.database = database
        self.get_session_key = get_session_key
        self.on_lock = on_lock
        self.port = port
        self.bridge_token = secrets.token_hex(16)
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Starts the bridge server on 127.0.0.1 in a background daemon thread."""
        try:
            self._httpd = HTTPServer(("127.0.0.1", self.port), ExtensionBridgeHandler)
            self._httpd.database = self.database
            self._httpd.get_session_key = self.get_session_key
            self._httpd.on_lock = self.on_lock
            self._httpd.bridge_token = self.bridge_token

            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()
            return True
        except Exception:
            return False

    def stop(self) -> None:
        """Stops the bridge server."""
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
