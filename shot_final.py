"""Final visual check: unlocked dashboard + a second tab, screenshot both."""
import sys, time, threading, tempfile
sys.path.insert(0, ".")
from pathlib import Path
import os

tmpdir = tempfile.mkdtemp()
os.environ["LOCALAPPDATA"] = tmpdir
db_path = Path(tmpdir) / "shot.db"

from starvault.database import Database
from starvault.models import VaultEntry

db = Database(db_path)
key = db.initialize_vault("shotpass123")

samples = [
    VaultEntry.create_server("LiteLLM Proxy", "localhost", username="admin", password="pw", port=4000, tags=["ai"], groups=["Infra"]),
    VaultEntry.create_service("BookStack admin", "BookStack", url="https://wiki.sektor9.dev", username="admin", password="pw", tags=["wiki"], groups=["Web"]),
    VaultEntry.create_domain("sektor9.dev", "sektor9.dev", registrar="Cloudflare", expires_at="2027-01-15", auto_renew=True),
    VaultEntry.create_api_key("Cloudflare API", "cf-token-xyz", provider="Cloudflare", tags=["dns"]),
    VaultEntry.create_keypair("id_ed25519", "id_ed25519", "ed25519", "ssh-ed25519 AAAA", "PRIVATE", fingerprint="ab:cd:ef"),
    VaultEntry.create_service("Authelia SSO", "Authelia", url="https://auth.sektor9.dev", username="admin", password="pw", tags=["auth"]),
]
for s in samples:
    db.save_entry(s, key, create_version=False)

from starvault.ui.app import StarVaultApp
app = StarVaultApp(db_path=db_path)


def run():
    time.sleep(2.0)
    try:
        app.session.unlock(key)
        app._show_initial_view()
        app.update_idletasks()
        time.sleep(2.0)
        from PIL import ImageGrab
        x, y = app.winfo_rootx(), app.winfo_rooty()
        w, h = app.winfo_width(), app.winfo_height()
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save("ui_dash.png")
        print("saved ui_dash.png", (w, h))

        # switch to the Crypto Tools tab (heaviest view) and shoot again
        dash = app.current_view
        if dash and hasattr(dash, "switch_to_tab"):
            dash.switch_to_tab("Crypto Tools")
            app.update_idletasks()
            time.sleep(2.5)
            ImageGrab.grab(bbox=(x, y, x + w, y + h)).save("ui_crypto.png")
            print("saved ui_crypto.png")
    except Exception:
        import traceback
        traceback.print_exc()
    app.after(0, app.quit_application)


threading.Thread(target=run, daemon=True).start()
app.mainloop()
print("done")
