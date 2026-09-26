"""Integration tests for UI views, HUD, dialogs, and app state transitions."""

import pytest
from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.ui.app import StarVaultApp
from starvault.ui.dashboard import DashboardView
from starvault.ui.hud import QuickSearchHUD
from starvault.ui.unlock_view import UnlockView


@pytest.fixture(scope="module")
def app_instance(tmp_path_factory):
    db_file = tmp_path_factory.mktemp("data") / "integration_vault.db"
    app = StarVaultApp(db_path=db_file)
    app.withdraw()
    yield app
    try:
        app.tray.stop()
        app.destroy()
    except Exception:
        pass


def test_app_initial_state_shows_unlock_view(app_instance):
    assert isinstance(app_instance.current_view, UnlockView)
    assert not app_instance.session.is_unlocked


def test_app_unlock_and_dashboard_transition(app_instance):
    db = app_instance.db
    # Initialize vault
    key = db.initialize_vault("IntegrationMasterPass123!")

    # Simulate successful unlock
    app_instance.on_unlock_success(key)

    assert app_instance.session.is_unlocked
    assert isinstance(app_instance.current_view, DashboardView)

    # Save a test entry
    server = VaultEntry.create_server(
        title="Test-VPS",
        hostname="10.0.0.1",
        username="root",
        tags=["vps1", "test"],
    )
    db.save_entry(server, key)
    app_instance.current_view.reload_entries()

    assert len(app_instance.current_view.entries) == 1
    assert app_instance.current_view.entries[0].title == "Test-VPS"


def test_hud_instantiation_and_search(app_instance):
    db = app_instance.db
    key = app_instance.session.key
    assert key is not None

    # Add 2 entries
    e1 = VaultEntry.create_server("VPS-10", "192.168.1.10", tags=["vps1"])
    e2 = VaultEntry.create_service("Postgres-10", "PostgreSQL", url="192.168.1.10", tags=["vps1", "database"])
    db.save_entry(e1, key)
    db.save_entry(e2, key)

    clip = ClipboardManager()
    hud = QuickSearchHUD(
        app_instance,
        clipboard_mgr=clip,
        get_entries_func=lambda: db.get_all_entries(key),
    )
    hud.withdraw()

    hud.search_entry.insert(0, "vps1")
    hud._refresh_results()

    assert len(hud.current_results) >= 2
    matched_titles = [e.title for e in hud.current_results]
    assert "VPS-10" in matched_titles
    assert "Postgres-10" in matched_titles

    hud.destroy()


def test_ui_tab_switching_and_duplication(app_instance):
    """Tests switching between Dashboard tabs, duplicating an entry via UI, and navigating from Health Advisor."""
    db = app_instance.db
    key = db.initialize_vault("IntegrationMasterPass123!")
    app_instance.on_unlock_success(key)

    dashboard: DashboardView = app_instance.current_view
    assert isinstance(dashboard, DashboardView)

    # Add a server entry
    server = VaultEntry.create_server(
        title="Production VPS",
        hostname="10.10.10.10",
        username="admin",
        password="WeakPassword123!",
    )
    db.save_entry(server, key)
    dashboard.reload_entries()
    assert len(dashboard.entries) == 1

    def is_packed(w):
        try:
            return bool(w.pack_info())
        except Exception:
            return False

    # 1. Test Duplication via UI method
    dashboard._select_entry(dashboard.entries[0])
    dashboard._duplicate_entry(dashboard.selected_entry)
    assert len(dashboard.entries) == 2
    titles = [e.title for e in dashboard.entries]
    assert "Production VPS - Copy" in titles

    # 2. Test Tab Switching to Vault Health
    dashboard.tab_selector.set("🛡️ Vault Health")
    dashboard._on_nav_tab_changed("🛡️ Vault Health")
    assert is_packed(dashboard.health_view)
    assert not is_packed(dashboard.body_frame)

    # 3. Test Navigation back from Health Advisor to specific entry
    dashboard.switch_to_credentials_tab(server.id)
    assert is_packed(dashboard.body_frame)
    assert dashboard.selected_entry.id == server.id

    # 4. Test Tab Switching to Encrypted Files
    dashboard.tab_selector.set("📁 File Vault")
    dashboard._on_nav_tab_changed("📁 File Vault")
    assert is_packed(dashboard.files_view)
    assert not is_packed(dashboard.body_frame)

    # Switch back and lock
    dashboard.tab_selector.set("Credentials")
    dashboard._on_nav_tab_changed("Credentials")
    app_instance.lock_vault()
    assert not app_instance.session.is_unlocked
    assert isinstance(app_instance.current_view, UnlockView)


def test_dashboard_sorting_and_filtering(app_instance):
    """Verify natural sorting, numerical sorting, and quick type/status filtering in Dashboard."""
    from datetime import datetime, timezone, timedelta

    db = app_instance.db
    # If locked, unlock with test key
    if not app_instance.session.is_unlocked:
        key = db.initialize_vault("SortPass123!")
        app_instance.on_unlock_success(key)
    key = app_instance.session.key
    assert key is not None

    # Clear entries
    for e in db.get_all_entries(key):
        db.delete_entry(e.id)

    # 1. Create realistic items with numeric variations
    e_vps1 = VaultEntry.create_server("VPS 1", "vps1.lan", username="root", port=22)
    e_vps10 = VaultEntry.create_server("VPS 10", "vps10.lan", username="root", port=8080)
    e_vps2 = VaultEntry.create_server("VPS 2", "vps2.lan", username="root", port=443)
    e_api = VaultEntry.create_api_key("Stripe API Key", "sk_live_123", provider="Stripe")
    e_api.expires_at = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%Y-%m-%d")

    db.save_entry(e_vps1, key)
    db.save_entry(e_vps10, key)
    db.save_entry(e_vps2, key)
    db.save_entry(e_api, key)

    app_instance.on_unlock_success(key)
    dashboard = app_instance.current_view
    dashboard.reload_entries()

    # 2. Test Natural Numeric Sorting (VPS 1 -> VPS 2 -> VPS 10)
    dashboard.dashboard_sort_combo.set("Natural Numeric (1, 2, 10...)")
    dashboard._apply_filters()
    titles = [e.title for e in dashboard.filtered_entries if "VPS" in e.title]
    assert titles == ["VPS 1", "VPS 2", "VPS 10"]

    # 3. Test Type Filter: Servers
    dashboard._on_type_filter_changed("🖥️ Servers")
    assert len(dashboard.filtered_entries) == 3
    assert all(e.entry_type == "server" for e in dashboard.filtered_entries)

    # 4. Test Status Filter: Expiring
    dashboard._toggle_status_chip("expiring")
    assert len(dashboard.filtered_entries) == 0  # No servers are expiring
    dashboard._on_type_filter_changed("All")      # Now Stripe API Key should match
    assert len(dashboard.filtered_entries) == 1
    assert dashboard.filtered_entries[0].title == "Stripe API Key"

    # 5. Test Direction Flip
    dashboard._clear_all_filters()
    assert len(dashboard.filtered_entries) == 4
    dashboard.dashboard_sort_combo.set("Alphabetical (A → Z)")
    dashboard._apply_filters()
    first_title = dashboard.filtered_entries[0].title
    dashboard._toggle_sort_direction()
    last_title = dashboard.filtered_entries[-1].title
    assert first_title == last_title


def test_crypto_tools_subtabs_and_file_import_export(app_instance):
    """Verify CryptoTools subtab switching renders distinct frames and File Encryption is not duplicate."""
    db = app_instance.db
    if not app_instance.session.is_unlocked:
        key = db.initialize_vault("CryptoToolsPass123!")
        app_instance.on_unlock_success(key)

    dashboard: DashboardView = app_instance.current_view
    dashboard.switch_to_tab("⚡ Crypto Tools")

    crypto_tools = dashboard._get_crypto_tools_view()
    assert crypto_tools is not None

    def is_packed(w):
        try:
            target = getattr(w, "_parent_frame", w)
            return bool(target.pack_info())
        except Exception:
            return False

    # 1. Switch to File Encryption subtab
    crypto_tools.switch_to_subtab("📁 File Encryption")
    assert is_packed(crypto_tools.file_frame)
    assert not is_packed(crypto_tools.crypt_frame)
    assert hasattr(crypto_tools, "f_encrypt_btn")
    assert hasattr(crypto_tools, "f_decrypt_btn")

    # 2. Switch to Encrypt & Decrypt text subtab
    crypto_tools.switch_to_subtab("🔐 Encrypt & Decrypt")
    assert is_packed(crypto_tools.crypt_frame)
    assert not is_packed(crypto_tools.file_frame)

    # 3. Verify File Vault has Import/Upload and Export All actions
    dashboard.switch_to_tab("📁 File Vault")
    files_view = dashboard._get_files_view()
    assert is_packed(files_view)
    assert hasattr(files_view, "_open_upload_dialog")
    assert hasattr(files_view, "_export_all_files")


def test_theme_switching_token_propagation():
    """Verify that apply_theme propagates color tokens across all starvault.ui modules."""
    from starvault.ui import theme
    import starvault.ui.dashboard as dash_mod
    import starvault.ui.crypto_tools_view as crypto_mod

    # Apply Light theme
    theme.apply_theme("Light")
    assert theme.get_current_theme() == "Light"
    assert dash_mod.BG_ROOT == theme.THEMES["Light"]["BG_ROOT"]
    assert crypto_mod.BG_ROOT == theme.THEMES["Light"]["BG_ROOT"]
    assert dash_mod.TEXT_PRIMARY == theme.THEMES["Light"]["TEXT_PRIMARY"]

    # Switch to Nord
    theme.apply_theme("Nord")
    assert theme.get_current_theme() == "Nord"
    assert dash_mod.BG_ROOT == theme.THEMES["Nord"]["BG_ROOT"]
    assert crypto_mod.BG_ROOT == theme.THEMES["Nord"]["BG_ROOT"]
    assert dash_mod.ACCENT_PRIMARY == theme.THEMES["Nord"]["ACCENT_PRIMARY"]

    # Switch back to Dark
    theme.apply_theme("Dark")
    assert theme.get_current_theme() == "Dark"



