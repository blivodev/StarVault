"""Main StarVault Application Controller and Window Manager."""

from pathlib import Path
import sys
from typing import Optional
import customtkinter as ctk
from PIL import ImageTk

from starvault.app_config import AppConfigManager
from starvault.autolock import AutoLockManager
from starvault.clipboard import ClipboardManager
from starvault.config import APP_NAME, APP_VERSION, get_default_db_path
from starvault.crypto import VaultSession
from starvault.database import Database
from starvault.extension_bridge import ExtensionBridgeServer
from starvault.tray import SystemTrayManager
from starvault.ui.dashboard import DashboardView
from starvault.ui.hud import QuickSearchHUD
from starvault.ui.icons import generate_vault_icon_image
from starvault.ui.key_studio import KeyStudioDialog
from starvault.ui.migration_dialog import MigrationDialog
from starvault.ui.theme import BG_ROOT, apply_global_theme, register_theme_listener
from starvault.ui.unlock_view import UnlockView


class StarVaultApp(ctk.CTk):
    """Root application window coordinating security sessions, dashboard, HUD, and tray."""

    def __init__(self, db_path: Optional[Path] = None, start_minimized: bool = False, **kwargs):
        super().__init__(**kwargs)
        apply_global_theme()

        self.title(f"{APP_NAME} v{APP_VERSION} - Credential & Key Vault")
        self.geometry("1240x820")
        self.minsize(980, 680)
        self.configure(fg_color=BG_ROOT)

        # Set window icon
        try:
            icon_img = generate_vault_icon_image(64)
            self._tk_icon = ImageTk.PhotoImage(icon_img)
            self.iconphoto(False, self._tk_icon)
        except Exception:
            pass

        # App Configuration (Recent Vaults, Remember Me)
        self.app_config = AppConfigManager()
        active_db = db_path or self.app_config.get_last_vault_path() or get_default_db_path()

        # Core Services
        self.db = Database(active_db)
        self.app_config.record_opened_vault(self.db.db_path)
        self.session = VaultSession()
        settings = self.db.get_settings()

        self.clipboard_mgr = ClipboardManager(
            default_timeout_sec=settings.get("clipboard_timeout", 30)
        )
        self.autolock_mgr = AutoLockManager(
            timeout_seconds=settings.get("autolock_timeout", 300),
            lock_on_minimize=settings.get("lock_on_minimize", True),
            on_lock_trigger=self.lock_vault,
        )

        # Child Views
        self.current_view: Optional[ctk.CTkFrame] = None
        self.hud_window: Optional[QuickSearchHUD] = None

        # System Tray Manager
        self.tray = SystemTrayManager(
            on_open_hud=lambda: self.after(0, self.open_hud),
            on_open_main=lambda: self.after(0, self.restore_main_window),
            on_lock=lambda: self.after(0, self.lock_vault),
            on_open_keys=lambda: self.after(0, self.open_key_studio_from_tray),
            on_exit=lambda: self.after(0, self.quit_application),
        )
        self.tray.start()

        # Chromium Extension Localhost Bridge (Chrome, Brave, Edge)
        self.extension_bridge = ExtensionBridgeServer(
            database=self.db,
            get_session_key=lambda: self.session.key if self.session.is_unlocked else None,
            on_lock=self.lock_vault,
        )
        self.extension_bridge.start()

        # Register dynamic theme listener
        register_theme_listener(self._on_theme_changed)

        # Window event bindings
        self.protocol("WM_DELETE_WINDOW", self._on_close_button_clicked)
        self.bind("<Unmap>", self._on_window_unmap)

        # Global activity tracking for auto-lock
        self.bind_all("<Any-KeyPress>", lambda e: self.autolock_mgr.record_activity(), add="+")
        self.bind_all("<ButtonPress>", lambda e: self.autolock_mgr.record_activity(), add="+")
        self.bind_all("<Motion>", lambda e: self.autolock_mgr.record_activity(), add="+")

        # Global shortcuts
        self.bind("<Control-f>", lambda e: self._focus_search())
        self.bind("<Control-l>", lambda e: self.lock_vault())

        # Initial View
        self._show_initial_view()

        if start_minimized:
            self.withdraw()

    def _show_initial_view(self):
        """Displays UnlockView if locked or DashboardView if unlocked."""
        if self.current_view:
            self.current_view.destroy()
            self.current_view = None

        # Check for Passwordless Launch / Remember Me in OS Credential Manager
        if not self.session.is_unlocked and self.db.is_initialized():
            saved = self.app_config.get_saved_vault_credential(self.db.db_path)
            if saved and saved.get("password"):
                pwd = saved["password"]
                kf = saved.get("keyfile_token") or None
                success, key = self.db.unlock_vault(pwd, kf)
                if success and key:
                    self.session.unlock(key)
                    self.autolock_mgr.record_activity()
                else:
                    self.app_config.clear_saved_vault_credential(self.db.db_path)

        if self.session.is_unlocked:
            self.current_view = DashboardView(
                self,
                database=self.db,
                session_key=self.session.key,
                clipboard_mgr=self.clipboard_mgr,
                autolock_mgr=self.autolock_mgr,
                on_lock_requested=self.lock_vault,
                on_minimize_to_tray=self.minimize_to_tray,
            )
            self.current_view.pack(fill="both", expand=True)
        else:
            self.current_view = UnlockView(
                self,
                is_initialized=self.db.is_initialized(),
                on_unlock_success=self.on_unlock_success,
                on_initialize_success=self.on_unlock_success,
                database=self.db,
                app_config=self.app_config,
                on_switch_vault=self.switch_vault,
            )
            self.current_view.pack(fill="both", expand=True)

    def switch_vault(self, new_path: Path):
        """Switches to a different local vault database."""
        if self.session.is_unlocked:
            self.lock_vault()
        self.db = Database(new_path)
        if hasattr(self, "extension_bridge") and self.extension_bridge:
            self.extension_bridge.database = self.db
        self.app_config.record_opened_vault(new_path)
        self._show_initial_view()

    def _on_theme_changed(self, theme_name: str):
        """Handles live theme switching and refreshes views with new color tokens."""
        from starvault.ui.theme import BG_ROOT
        self.configure(fg_color=BG_ROOT)
        self._show_initial_view()

    def on_unlock_success(self, key: bytes, master_password: Optional[str] = None):
        """Called when master password verification succeeds."""
        self.session.unlock(key)
        self.autolock_mgr.record_activity()
        self.app_config.record_opened_vault(self.db.db_path)
        self._show_initial_view()

        # Detect Legacy Vault and prompt for migration to True Local 2FA
        if self.db.is_legacy_vault() and master_password:
            self.after(300, lambda: self._prompt_legacy_migration(key, master_password))

    def _prompt_legacy_migration(self, old_key: bytes, master_password: str):
        MigrationDialog(
            self,
            database=self.db,
            old_key=old_key,
            master_password=master_password,
            on_migration_success=self._on_migration_success,
        )

    def _on_migration_success(self, new_key: bytes):
        self.session.unlock(new_key)
        if isinstance(self.current_view, DashboardView):
            self.current_view.update_session_key(new_key)

    def lock_vault(self):
        """Locks vault session and returns to UnlockView."""
        if not self.session.is_unlocked:
            return

        self.session.lock()
        self.clipboard_mgr.cancel_timer()

        if self.hud_window and self.hud_window.winfo_exists():
            self.hud_window.hide_hud()

        self._show_initial_view()

    def open_hud(self):
        """Opens or brings up the minimal fast-search HUD."""
        if not self.session.is_unlocked:
            # If locked, bring up main window to unlock first
            self.restore_main_window()
            return

        if self.hud_window is None or not self.hud_window.winfo_exists():
            self.hud_window = QuickSearchHUD(
                self,
                clipboard_mgr=self.clipboard_mgr,
                get_entries_func=lambda: self.db.get_all_entries(self.session.key) if self.session.is_unlocked else [],
                on_open_full_vault=self.restore_main_window,
            )

        self.hud_window.show_hud()

    def restore_main_window(self):
        """Brings the main application window to the foreground."""
        self.deiconify()
        self.lift()
        self.focus_force()

    def minimize_to_tray(self):
        """Hides the main window into the system tray and triggers auto-lock if configured."""
        self.withdraw()
        if self.hud_window and self.hud_window.winfo_exists():
            self.hud_window.hide_hud()
        self.autolock_mgr.on_minimized()

    def _on_close_button_clicked(self):
        """Window close button minimizes to tray instead of quitting."""
        self.minimize_to_tray()

    def _on_window_unmap(self, event):
        """Handles minimize button click on window titlebar."""
        if event.widget == self and self.state() == "iconic":
            self.minimize_to_tray()

    def _focus_search(self):
        if isinstance(self.current_view, DashboardView):
            self.current_view.search_entry.focus_set()
            self.current_view.search_entry.select_range(0, "end")

    def _on_theme_changed(self, theme_name: str) -> None:
        """Handles theme change broadcast from theme manager and updates views and persistence."""
        try:
            from starvault.ui.theme import BG_ROOT
            self.configure(fg_color=BG_ROOT)
            if hasattr(self, "app_config") and self.app_config:
                self.app_config.set_theme(theme_name)
            if hasattr(self, "db") and self.db and hasattr(self, "session") and self.session.is_unlocked:
                try:
                    self.db.update_settings({"theme": theme_name})
                except Exception:
                    pass
            if self.current_view:
                if hasattr(self.current_view, "on_theme_changed"):
                    self.current_view.on_theme_changed(theme_name)
                elif hasattr(self.current_view, "_build_ui"):
                    self.current_view._build_ui()
        except Exception:
            pass

    def open_key_studio_from_tray(self):
        if not self.session.is_unlocked:
            self.restore_main_window()
            return
        self.restore_main_window()
        if isinstance(self.current_view, DashboardView):
            self.current_view._open_key_studio()

    def quit_application(self):
        """Clean application shutdown."""
        self.lock_vault()
        if hasattr(self, "extension_bridge") and self.extension_bridge:
            self.extension_bridge.stop()
        self.tray.stop()
        self.destroy()
        sys.exit(0)
