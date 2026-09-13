"""Google Drive Passive & Active Cloud Sync for StarVault.

Features:
- Google OAuth 2.0 Web flow for desktop with local callback server (http://localhost:8085)
  and fallback manual code entry.
- Direct Google Drive API v3 upload / download using Python standard urllib.
- Zero-Knowledge Security: Syncs only the encrypted SQLite database file ('starvault.db').
  The database is encrypted with Argon2id + AES-256-GCM. Unencrypted secrets NEVER touch
  Google Drive or any network interface.
"""

from datetime import datetime, timezone
import http.server
import json
from pathlib import Path
import threading
import time
from typing import Callable, Dict, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

# Default OAuth Client Credentials (can be overridden in settings)
DEFAULT_CLIENT_ID = "382490518342-8c4q38v94q1142oeqdflkmvd2989r14b.apps.googleusercontent.com"
DEFAULT_CLIENT_SECRET = "GOCSPX-dummy_placeholder_secret_replace_if_needed"
AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files"
DRIVE_UPLOAD_ENDPOINT = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.email"
REDIRECT_PORT = 8085
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/"


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Handles OAuth 2.0 redirect code callback."""
    code: Optional[str] = None
    error: Optional[str] = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            OAuthCallbackHandler.code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>StarVault - Google Auth Success</title></head>
            <body style="background:#0F1117; color:#E0E6ED; font-family:sans-serif; text-align:center; padding:60px;">
                <h1 style="color:#00E5FF; font-size:32px;">★ StarVault Cloud Sync</h1>
                <p style="font-size:18px;">Authentication successful! You are now connected to Google Drive.</p>
                <p style="color:#6C757D;">You can close this browser tab and return to StarVault.</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
        else:
            OAuthCallbackHandler.error = params.get("error", ["Unknown error"])[0]
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication Failed</h1><p>Please return to StarVault and try again.</p>")

    def log_message(self, format, *args):
        # Suppress server logs
        pass


class GoogleDriveSync:
    """Handles OAuth authentication, tokens, and encrypted database syncing to Google Drive."""

    def __init__(self, config_getter: Callable[[], dict], config_saver: Callable[[dict], None]) -> None:
        self.config_getter = config_getter
        self.config_saver = config_saver
        self._auth_server: Optional[http.server.HTTPServer] = None

    def get_client_credentials(self) -> Tuple[str, str]:
        cfg = self.config_getter()
        client_id = cfg.get("gdrive_client_id", "").strip() or DEFAULT_CLIENT_ID
        client_secret = cfg.get("gdrive_client_secret", "").strip() or DEFAULT_CLIENT_SECRET
        return client_id, client_secret

    def get_auth_url(self) -> str:
        client_id, _ = self.get_client_credentials()
        params = {
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPES,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

    def start_oauth_flow(self, on_complete: Optional[Callable[[bool, str], None]] = None) -> None:
        """Launches the user's browser and listens for OAuth redirect in the background."""
        OAuthCallbackHandler.code = None
        OAuthCallbackHandler.error = None

        def run_server():
            try:
                server = http.server.HTTPServer(("127.0.0.1", REDIRECT_PORT), OAuthCallbackHandler)
                self._auth_server = server
                server.timeout = 180  # 3 minutes timeout

                # Open browser
                webbrowser.open(self.get_auth_url())

                start_time = time.time()
                while time.time() - start_time < 180 and not OAuthCallbackHandler.code and not OAuthCallbackHandler.error:
                    server.handle_request()

                server.server_close()

                if OAuthCallbackHandler.code:
                    success, msg = self.exchange_code_for_tokens(OAuthCallbackHandler.code)
                    if on_complete:
                        on_complete(success, msg)
                else:
                    err = OAuthCallbackHandler.error or "Login timed out."
                    if on_complete:
                        on_complete(False, err)
            except Exception as ex:
                if on_complete:
                    on_complete(False, str(ex))

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()

    def exchange_code_for_tokens(self, code: str) -> Tuple[bool, str]:
        """Exchanges authorization code for access and refresh tokens."""
        client_id, client_secret = self.get_client_credentials()
        data = urllib.parse.urlencode({
            "code": code.strip(),
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        }).encode("utf-8")

        try:
            req = urllib.request.Request(TOKEN_ENDPOINT, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            refresh_token = result.get("refresh_token")
            access_token = result.get("access_token")

            if not refresh_token:
                # If existing refresh token was already saved, keep it
                cfg = self.config_getter()
                refresh_token = cfg.get("gdrive_refresh_token", "")

            # Fetch user email for display
            user_email = self._fetch_user_email(access_token)

            cfg = self.config_getter()
            cfg["gdrive_connected"] = True
            cfg["gdrive_refresh_token"] = refresh_token
            cfg["gdrive_access_token"] = access_token
            cfg["gdrive_token_expiry"] = time.time() + result.get("expires_in", 3600)
            cfg["gdrive_user_email"] = user_email
            cfg["gdrive_last_sync"] = "Not yet synced"
            self.config_saver(cfg)

            return True, f"Connected as {user_email}"
        except urllib.error.HTTPError as ex:
            err_body = ex.read().decode("utf-8", errors="ignore")
            return False, f"Google OAuth failed: {err_body}"
        except Exception as ex:
            return False, f"Connection error: {str(ex)}"

    def _fetch_user_email(self, access_token: str) -> str:
        try:
            req = urllib.request.Request(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("email", "Google User")
        except Exception:
            return "Google User"

    def get_valid_access_token(self) -> Optional[str]:
        """Retrieves or refreshes Google OAuth access token."""
        cfg = self.config_getter()
        if not cfg.get("gdrive_connected"):
            return None

        refresh_token = cfg.get("gdrive_refresh_token", "")
        access_token = cfg.get("gdrive_access_token", "")
        expiry = cfg.get("gdrive_token_expiry", 0)

        if access_token and time.time() < (expiry - 120):
            return access_token

        if not refresh_token:
            return None

        # Refresh the token
        client_id, client_secret = self.get_client_credentials()
        data = urllib.parse.urlencode({
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }).encode("utf-8")

        try:
            req = urllib.request.Request(TOKEN_ENDPOINT, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            new_access_token = result.get("access_token")
            cfg["gdrive_access_token"] = new_access_token
            cfg["gdrive_token_expiry"] = time.time() + result.get("expires_in", 3600)
            self.config_saver(cfg)
            return new_access_token
        except Exception:
            return None

    def disconnect(self) -> None:
        """Clears Google Drive tokens and connection state."""
        cfg = self.config_getter()
        cfg["gdrive_connected"] = False
        cfg["gdrive_refresh_token"] = ""
        cfg["gdrive_access_token"] = ""
        cfg["gdrive_user_email"] = ""
        cfg["gdrive_last_sync"] = ""
        cfg["gdrive_file_id"] = ""
        self.config_saver(cfg)

    def upload_vault_to_drive(self, local_db_path: Path) -> Tuple[bool, str]:
        """Safely uploads the local encrypted .db file to Google Drive."""
        if not local_db_path.exists():
            return False, f"Local vault file '{local_db_path}' does not exist."

        token = self.get_valid_access_token()
        if not token:
            return False, "Not authenticated with Google Drive. Please log in first."

        try:
            # Read local encrypted database file bytes
            with open(local_db_path, "rb") as f:
                db_bytes = f.read()

            cfg = self.config_getter()
            existing_file_id = cfg.get("gdrive_file_id", "")

            # If no existing file id, search for 'starvault.db' on Drive
            if not existing_file_id:
                query = urllib.parse.urlencode({
                    "q": "name = 'starvault.db' and trashed = false",
                    "fields": "files(id, name, modifiedTime)",
                })
                req = urllib.request.Request(
                    f"{DRIVE_FILES_ENDPOINT}?{query}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    files = data.get("files", [])
                    if files:
                        existing_file_id = files[0]["id"]

            boundary = "==============StarVaultSyncBoundary=============="
            metadata = {
                "name": "starvault.db",
                "description": "Encrypted StarVault Database Backup (Argon2id + AES-256-GCM)",
            }

            body = (
                f"--{boundary}\r\n"
                f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
                f"{json.dumps(metadata)}\r\n"
                f"--{boundary}\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode("utf-8") + db_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

            if existing_file_id:
                # Update existing file
                url = f"https://www.googleapis.com/upload/drive/v3/files/{existing_file_id}?uploadType=multipart"
                method = "PATCH"
            else:
                # Create new file
                url = DRIVE_UPLOAD_ENDPOINT
                method = "POST"

            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": f"multipart/related; boundary={boundary}",
                },
                method=method,
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                new_file_id = result.get("id", existing_file_id)

            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            cfg["gdrive_file_id"] = new_file_id
            cfg["gdrive_last_sync"] = now_str
            self.config_saver(cfg)

            return True, f"Successfully uploaded encrypted vault to Google Drive ({now_str})"
        except Exception as ex:
            return False, f"Failed to upload to Google Drive: {str(ex)}"

    def download_vault_from_drive(self, target_dest_path: Path) -> Tuple[bool, str]:
        """Downloads encrypted vault database from Google Drive."""
        token = self.get_valid_access_token()
        if not token:
            return False, "Not authenticated with Google Drive."

        try:
            cfg = self.config_getter()
            file_id = cfg.get("gdrive_file_id", "")

            if not file_id:
                query = urllib.parse.urlencode({
                    "q": "name = 'starvault.db' and trashed = false",
                    "fields": "files(id, name, modifiedTime)",
                })
                req = urllib.request.Request(
                    f"{DRIVE_FILES_ENDPOINT}?{query}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    files = data.get("files", [])
                    if not files:
                        return False, "No 'starvault.db' file found in your Google Drive."
                    file_id = files[0]["id"]

            download_url = f"{DRIVE_FILES_ENDPOINT}/{file_id}?alt=media"
            req = urllib.request.Request(
                download_url,
                headers={"Authorization": f"Bearer {token}"},
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                downloaded_bytes = resp.read()

            target_dest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_dest_path, "wb") as f:
                f.write(downloaded_bytes)

            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            cfg["gdrive_file_id"] = file_id
            cfg["gdrive_last_sync"] = f"Downloaded {now_str}"
            self.config_saver(cfg)

            return True, f"Downloaded encrypted database ({len(downloaded_bytes)} bytes) from Google Drive."
        except Exception as ex:
            return False, f"Failed to download from Google Drive: {str(ex)}"
