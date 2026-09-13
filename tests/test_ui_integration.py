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

