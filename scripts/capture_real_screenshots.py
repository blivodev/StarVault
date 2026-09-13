"""Generates authentic, high-resolution screenshots of StarVault UI using Windows PrintWindow API."""

import ctypes
import ctypes.wintypes
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image

from starvault.cert_generator import generate_self_signed_cert
from starvault.crypto_tools import encode_base64
from starvault.database import Database
from starvault.keys import generate_ed25519_key, generate_wireguard_key_result
from starvault.models import VaultEntry, VaultFile
from starvault.ui.app import StarVaultApp


def capture_window_image(window) -> Image.Image:
    """Captures true window pixels using Windows user32 PrintWindow API."""
    window.update_idletasks()
    window.update()
    time.sleep(0.3)

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    hwnd = window.winfo_id()
    parent_hwnd = user32.GetParent(hwnd) or hwnd

    rect = ctypes.wintypes.RECT()
    user32.GetWindowRect(parent_hwnd, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top

    hdc_src = user32.GetWindowDC(parent_hwnd)
    hdc_mem = gdi32.CreateCompatibleDC(hdc_src)
    hbmp = gdi32.CreateCompatibleBitmap(hdc_src, w, h)
    gdi32.SelectObject(hdc_mem, hbmp)

    PW_RENDERFULLCONTENT = 0x00000002
    user32.PrintWindow(parent_hwnd, hdc_mem, PW_RENDERFULLCONTENT)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", ctypes.wintypes.DWORD),
            ("biWidth", ctypes.wintypes.LONG),
            ("biHeight", ctypes.wintypes.LONG),
            ("biPlanes", ctypes.wintypes.WORD),
            ("biBitCount", ctypes.wintypes.WORD),
            ("biCompression", ctypes.wintypes.DWORD),
            ("biSizeImage", ctypes.wintypes.DWORD),
            ("biXPelsPerMeter", ctypes.wintypes.LONG),
            ("biYPelsPerMeter", ctypes.wintypes.LONG),
            ("biClrUsed", ctypes.wintypes.DWORD),
            ("biClrImportant", ctypes.wintypes.DWORD),
        ]

    bih = BITMAPINFOHEADER()
    bih.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bih.biWidth = w
    bih.biHeight = -h  # top-down DIB
    bih.biPlanes = 1
    bih.biBitCount = 32
    bih.biCompression = 0

    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(hdc_mem, hbmp, 0, h, buf, ctypes.byref(bih), 0)

    user32.ReleaseDC(parent_hwnd, hdc_src)
    gdi32.DeleteDC(hdc_mem)
    gdi32.DeleteObject(hbmp)

    # BGRA to RGBA image
    im = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
    return im.convert("RGB")


def populate_demo_vault(db_path: Path, password: str = "DemoMasterPass123!") -> bytes:
    """Populates a realistic demonstration database with rich infrastructure credentials."""
    db = Database(db_path)
    key = db.initialize_vault(password)
    now = datetime.now(timezone.utc)

    # 1. Servers / Infrastructure
    vps1 = VaultEntry.create_server(
        title="VPS 1 - Production Gateway",
        hostname="gateway.us-east.starvault.io",
        username="admin",
        password="SecureProdPassword!987",
        port=22,
        tags=["prod", "vps", "aws", "us-east"],
        notes="Primary edge proxy and SSH jumpbox. Monitored 24/7.",
        os_distro="Ubuntu 24.04 LTS",
        category="Cloud & Infrastructure",
    )
    vps1.is_favorite = True
    vps1.totp_secret = "JBSWY3DPEHPK3PXP"
    db.save_entry(vps1, key)

    vps2 = VaultEntry.create_server(
        title="VPS 2 - DB Cluster Master",
        hostname="10.100.4.15",
        username="postgres",
        password="HighEntropyDbPassword!456",
        port=5432,
        tags=["prod", "db", "postgres", "vps"],
        notes="PostgreSQL 16 High-Availability cluster with streaming replication.",
        os_distro="Debian 12 Bookworm",
        category="Databases & Storage",
    )
    db.save_entry(vps2, key)

    vps10 = VaultEntry.create_server(
        title="VPS 10 - Staging Worker",
        hostname="worker-10.internal",
        username="deploy",
        password="StagingPassword!321",
        port=22,
        tags=["stage", "worker", "docker"],
        notes="Celery async workers running background jobs.",
        category="Cloud & Infrastructure",
    )
    db.save_entry(vps10, key)

    # 2. Services / Apps
    srv_pg = VaultEntry.create_service(
        title="PostgreSQL Production",
        app_name="PostgreSQL",
        url="postgresql://dbadmin:p@ss@10.100.4.15:5432/starvault_prod",
        username="dbadmin",
        password="HighEntropyDbPassword!456",
        db_name="starvault_prod",
        service_type="database",
        tags=["prod", "database", "postgres"],
        category="Databases & Storage",
    )
    srv_pg.parent_server_id = vps2.id
    db.save_entry(srv_pg, key)

    srv_redis = VaultEntry.create_service(
        title="Redis Cache Instance",
        app_name="Redis",
        url="redis://:cachepass@10.100.4.16:6379/0",
        username="default",
        password="CacheSecretPassword99!",
        service_type="cache",
        tags=["prod", "cache", "redis"],
        category="Databases & Storage",
    )
    srv_redis.parent_server_id = vps2.id
    db.save_entry(srv_redis, key)

    srv_jellyfin = VaultEntry.create_service(
        title="Jellyfin Homelab Media",
        app_name="Jellyfin",
        url="https://media.homelab.local:8096",
        username="admin",
        password="WeakPassword123",  # Intentionally moderate/weak for health advisor demo
        tags=["homelab", "media"],
        category="Work & Productivity",
    )
    db.save_entry(srv_jellyfin, key)

    # 3. API Keys
    api_openai = VaultEntry.create_api_key(
        title="OpenAI GPT-4o API Key",
        api_token="sk-proj-prod-live-9876543210abcdef0123456789",
        provider="OpenAI",
        environment="Production",
        tags=["ai", "openai", "prod"],
        category="AI & LLM Services",
    )
    api_openai.is_favorite = True
    db.save_entry(api_openai, key)

    api_stripe = VaultEntry.create_api_key(
        title="Stripe Live Secret Key",
        api_token="sk_live_51MzABCD1234567890wxyz",
        provider="Stripe",
        environment="Production",
        expires_at=(now + timedelta(days=12)).strftime("%Y-%m-%d"),  # Expiring soon
        tags=["finance", "stripe", "payments"],
        category="Finance & Payments",
    )
    db.save_entry(api_stripe, key)

    # 4. Keypairs & Certificates
    ed_res = generate_ed25519_key(comment="admin@starvault.io")
    key_ssh = VaultEntry.create_keypair(
        title="Bastion Ed25519 SSH Key",
        key_name="id_ed25519_bastion",
        key_type="ed25519",
        public_key=ed_res.public_key,
        private_key=ed_res.private_key,
        fingerprint=ed_res.fingerprint,
        tags=["ssh", "keys", "bastion"],
        category="Keys & Certificates",
    )
    db.save_entry(key_ssh, key)

    wg_res = generate_wireguard_key_result()
    key_wg = VaultEntry.create_keypair(
        title="Homelab WireGuard VPN",
        key_name="wg0-client",
        key_type="wireguard",
        public_key=wg_res.public_key,
        private_key=wg_res.private_key,
        tags=["vpn", "wireguard", "infra"],
        category="Security & Networking",
    )
    db.save_entry(key_wg, key)

    cert_pem, cert_key_pem = generate_self_signed_cert(
        common_name="*.vault.local",
        san_list=["localhost", "127.0.0.1", "vault.local"],
        validity_days=365,
    )
    key_cert = VaultEntry.create_keypair(
        title="Self-Signed TLS Certificate (*.vault.local)",
        key_name="tls_vault_local",
        key_type="tls_cert",
        public_key=cert_pem,
        private_key=cert_key_pem,
        tags=["tls", "cert", "ssl", "san"],
        category="Keys & Certificates",
    )
    key_cert.expires_at = (now + timedelta(days=365)).strftime("%Y-%m-%d")
    db.save_entry(key_cert, key)

    # 5. File Vault attachments
    f1 = VaultFile(filename="ssl_bundle.pem", file_size=4096, tags=["folder:Keys & Certificates", "ext:pem"])
    db.save_file(f1, cert_pem.encode("utf-8"), key)

    f2 = VaultFile(filename="docker-compose.yml", file_size=2048, tags=["folder:Configs & Dotfiles", "ext:yml"])
    db.save_file(f2, b"version: '3.8'\nservices:\n  starvault:\n    image: starvault:latest\n", key)

    f3 = VaultFile(filename="backup_database.sql.gz", file_size=65536, tags=["folder:Archives & Backups", "ext:gz"])
    db.save_file(f3, b"\x1f\x8b\x08MOCK_GZIP_ARCHIVE_DATA", key)

    return key


def run_capture():
    out_dir = Path("docs/screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)

    demo_db_path = Path("docs/demo_vault.db")
    if demo_db_path.exists():
        demo_db_path.unlink()

    demo_pass = "DemoMasterPass123!"
    key = populate_demo_vault(demo_db_path, demo_pass)

    print(f"[+] Initialized demo vault at {demo_db_path}")

    app = StarVaultApp(db_path=demo_db_path)
    app.geometry("1240x780")
    app.deiconify()
    app.update_idletasks()
    app.update()

    # Unlock the vault
    app.on_unlock_success(key)
    dashboard = app.current_view
    dashboard.reload_entries()

    # Select the first entry so inspector panel is rich
    if dashboard.entries:
        dashboard._select_entry(dashboard.entries[0])

    app.update_idletasks()
    app.update()
    time.sleep(0.5)

    # 1. Capture Dashboard Credentials Main List
    img1 = capture_window_image(app)
    path1 = out_dir / "01_dashboard_credentials.png"
    img1.save(path1, "PNG")
    print(f"[+] Captured: {path1}")

    # 2. Capture Vault Health & Auto-Organize Studio
    dashboard.tab_selector.set("🛡️ Vault Health")
    dashboard._on_nav_tab_changed("🛡️ Vault Health")
    app.update_idletasks()
    app.update()
    time.sleep(0.5)

    img2 = capture_window_image(app)
    path2 = out_dir / "02_vault_health_advisor.png"
    img2.save(path2, "PNG")
    print(f"[+] Captured: {path2}")

    # 3. Capture Crypto Tools Workbench
    dashboard.tab_selector.set("⚡ Crypto Tools")
    dashboard._on_nav_tab_changed("⚡ Crypto Tools")
    app.update_idletasks()
    app.update()
    time.sleep(0.5)

    img3 = capture_window_image(app)
    path3 = out_dir / "03_crypto_tools_workbench.png"
    img3.save(path3, "PNG")
    print(f"[+] Captured: {path3}")

    # 4. Capture Encrypted File Vault
    dashboard.tab_selector.set("📁 File Vault")
    dashboard._on_nav_tab_changed("📁 File Vault")
    app.update_idletasks()
    app.update()
    time.sleep(0.5)

    img4 = capture_window_image(app)
    path4 = out_dir / "04_encrypted_file_vault.png"
    img4.save(path4, "PNG")
    print(f"[+] Captured: {path4}")

    # 5. Capture Groups & Relational Tags
    dashboard.tab_selector.set("🗂️ Groups")
    dashboard._on_nav_tab_changed("🗂️ Groups")
    app.update_idletasks()
    app.update()
    time.sleep(0.5)

    img5 = capture_window_image(app)
    path5 = out_dir / "05_groups_and_tags.png"
    img5.save(path5, "PNG")
    print(f"[+] Captured: {path5}")

    # 6. Capture Console (Matrix Green) Theme
    from starvault.ui.theme import apply_theme
    apply_theme("Console")
    app.update_idletasks()
    app.update()
    time.sleep(0.5)

    img6 = capture_window_image(app)
    path6 = out_dir / "06_theme_console_matrix.png"
    img6.save(path6, "PNG")
    print(f"[+] Captured: {path6}")

    # Restore Dark Theme and close
    apply_theme("Dark")
    try:
        app.tray.stop()
        app.destroy()
    except Exception:
        pass

    if demo_db_path.exists():
        demo_db_path.unlink()

    print("[OK] All 6 authentic screenshots captured and saved to docs/screenshots/")


if __name__ == "__main__":
    run_capture()
