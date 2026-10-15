"""Main Dashboard View for StarVault with card list and detail inspector."""

from datetime import datetime, timezone, timedelta
from tkinter import messagebox
from typing import Callable, List, Optional, Set
import uuid
import customtkinter as ctk

from starvault.autolock import AutoLockManager
from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.quick_strings import (
    generate_curl_command,
    generate_db_cli_command,
    generate_db_url,
    generate_dig_command,
    generate_ssh_command,
    generate_whois_command,
)
from starvault.search import search_entries
from starvault.ui.api_key_dialog import ApiKeyStudioDialog
from starvault.ui.crypto_tools_view import CryptoToolsView
from starvault.ui.entry_dialog import EntryDialog
from starvault.ui.files_view import FilesView
from starvault.ui.groups_view import GroupsView
from starvault.ui.health_view import HealthView
from starvault.ui.key_studio import KeyStudioDialog
from starvault.ui.local_key_installer_dialog import LocalKeyInstallerDialog
from starvault.ui.settings_dialog import SettingsDialog
from starvault.ui.totp_view import TotpView
from starvault.ui.vault_export_dialog import VaultExportDialog
from starvault.ui.vault_import_dialog import VaultImportDialog
from starvault.ui.version_history_dialog import VersionHistoryDialog
from starvault.health import parse_date_safely
from starvault.ui.theme import (
    ACCENT_EMERALD,
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_CARD_HOVER,
    BG_INPUT,
    BG_ROOT,
    BG_SIDEBAR,
    BG_SUBTLE,
    BORDER_COLOR,
    COLOR_DANGER,
    COLOR_FAVORITE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_ON_ACCENT,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    cycle_next_theme,
    get_current_theme,
    get_font,
    get_mono_font,
)
from starvault.ui.widgets import add_password_toggle


class DashboardView(ctk.CTkFrame):
    """Primary application dashboard containing sidebar, entry cards, and inspector."""

    def __init__(
        self,
        parent,
        database: Database,
        session_key: bytes,
        clipboard_mgr: ClipboardManager,
        autolock_mgr: AutoLockManager,
        on_lock_requested: Callable[[], None],
        on_minimize_to_tray: Optional[Callable[[], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.database = database
        self.session_key = session_key
        self.clipboard_mgr = clipboard_mgr
        self.autolock_mgr = autolock_mgr
        self.on_lock_requested = on_lock_requested
        self.on_minimize_to_tray = on_minimize_to_tray

        self.entries: List[VaultEntry] = []
        self.filtered_entries: List[VaultEntry] = []
        self.selected_entry: Optional[VaultEntry] = None
        self.selected_category = "All"
        self.selected_tag: Optional[str] = None
        self.selected_type_filter = "All"
        self.selected_status_filter: Optional[str] = None
        self.sort_reverse = False
        self._revealed_secrets: set = set()
        self._search_job = None
        self._card_widgets = {}
        self._card_meta = {}
        self._rendered_ids = []
        self._highlighted_selection = None
        self._rendered_limit = 35
        self.selected_entry_ids: Set[str] = set()
        self.last_clicked_id: Optional[str] = None
        self.inspector_visible: bool = True

        self._build_ui()
        self.clipboard_mgr.set_status_callback(self._on_clipboard_status)
        self.reload_entries()
        self._schedule_autolock_ui_update()
        self._setup_hotkeys()

    def update_session_key(self, new_key: bytes):
        self.session_key = new_key
        if self.health_view:
            self.health_view.encryption_key = new_key
        if self.files_view:
            self.files_view.encryption_key = new_key
        if self.groups_view:
            self.groups_view.session_key = new_key
        if self.totp_view:
            self.totp_view.session_key = new_key
        if self.crypto_tools_view:
            self.crypto_tools_view.update_session_key(new_key)
        if hasattr(self, "_dirty_views"):
            self._dirty_views.update(["groups", "totp", "health", "files", "crypto"])

    def _build_ui(self):
        # 1. Top Global Navigation & Search Bar
        self._build_top_navbar()

        # 2. Main Content Split (Left Sidebar + Center Cards + Right Inspector)
        self.body_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.body_frame.pack(fill="both", expand=True)

        # Left Sidebar
        self.sidebar = ctk.CTkFrame(self.body_frame, fg_color=BG_SIDEBAR, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self._build_sidebar()

        # Right Detail Inspector
        self.inspector_panel = ctk.CTkScrollableFrame(
            self.body_frame,
            fg_color=BG_CARD,
            width=380,
            corner_radius=0,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.inspector_panel.pack(side="right", fill="both")
        self._render_inspector_empty()

        # Center Entries Cards List
        self.center_container = ctk.CTkFrame(self.body_frame, fg_color=BG_ROOT)
        self.center_container.pack(side="left", fill="both", expand=True)

        # Filter bar header
        self.filter_header = ctk.CTkFrame(self.center_container, fg_color="transparent", height=36)
        self.filter_header.pack(fill="x", padx=16, pady=(10, 2))

        self.filter_title_lbl = ctk.CTkLabel(
            self.filter_header,
            text="All Vault Entries",
            font=get_font(14, "bold"),
            text_color=TEXT_PRIMARY,
        )
        self.filter_title_lbl.pack(side="left")

        self.count_badge = ctk.CTkLabel(
            self.filter_header,
            text="0 items",
            font=get_font(11),
            text_color=TEXT_MUTED,
        )
        self.count_badge.pack(side="left", padx=8)

        self.inspector_toggle_btn = ctk.CTkButton(
            self.filter_header,
            text="◀ Inspector",
            width=90,
            height=28,
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._toggle_inspector,
        )
        self.inspector_toggle_btn.pack(side="left", padx=8)

        # Sort Dropdown & Direction Toggle in header
        sort_frame = ctk.CTkFrame(self.filter_header, fg_color="transparent")
        sort_frame.pack(side="right")

        ctk.CTkLabel(sort_frame, text="Sort:", font=get_font(11, "bold"), text_color=TEXT_MUTED).pack(side="left", padx=(0, 6))

        self.dashboard_sort_combo = ctk.CTkComboBox(
            sort_frame,
            values=[
                "Alphabetical (A → Z)",
                "Alphabetical (Z → A)",
                "Natural Numeric (1, 2, 10...)",
                "Date Modified (Newest)",
                "Date Modified (Oldest)",
                "Date Created (Newest)",
                "Date Created (Oldest)",
                "Category (A → Z)",
                "Security Risk (Highest)",
                "Entry Type",
                "Port Number (Numeric)",
            ],
            width=190,
            height=28,
            font=get_font(11),
            command=lambda v: self._apply_filters(),
        )
        self.dashboard_sort_combo.set("Alphabetical (A → Z)")
        self.dashboard_sort_combo.pack(side="left", padx=(0, 4))

        self.sort_dir_btn = ctk.CTkButton(
            sort_frame,
            text="▲",
            width=28,
            height=28,
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._toggle_sort_direction,
        )
        self.sort_dir_btn.pack(side="left")

        # Quick Filter Row (Type Pills & Status Chips)
        self.quick_filter_bar = ctk.CTkFrame(self.center_container, fg_color="transparent")
        self.quick_filter_bar.pack(fill="x", padx=16, pady=(2, 6))

        # Type Pills Segmented Button
        self.type_filter_var = ctk.StringVar(value="All")
        self.type_selector = ctk.CTkSegmentedButton(
            self.quick_filter_bar,
            values=["All", "Domains", "Servers", "Services", "API Keys", "Keypairs", "Favorites"],
            variable=self.type_filter_var,
            font=get_font(10, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=26,
            corner_radius=6,
            command=self._on_type_filter_changed,
        )
        self.type_selector.pack(side="left", padx=(0, 8))

        # Status Chips (Expiring, Weak, TOTP)
        self.chip_expiring = ctk.CTkButton(
            self.quick_filter_bar,
            text="Expiring",
            font=get_font(10),
            height=26,
            width=70,
            corner_radius=5,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._toggle_status_chip("expiring"),
        )
        self.chip_expiring.pack(side="left", padx=2)

        self.chip_weak = ctk.CTkButton(
            self.quick_filter_bar,
            text="Weak Pass",
            font=get_font(10),
            height=26,
            width=75,
            corner_radius=5,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._toggle_status_chip("weak"),
        )
        self.chip_weak.pack(side="left", padx=2)

        self.chip_totp = ctk.CTkButton(
            self.quick_filter_bar,
            text="2FA Active",
            font=get_font(10),
            height=26,
            width=75,
            corner_radius=5,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._toggle_status_chip("totp"),
        )
        self.chip_totp.pack(side="left", padx=2)

        # Clear Filters Button
        self.clear_filters_btn = ctk.CTkButton(
            self.quick_filter_bar,
            text="Clear",
            font=get_font(10),
            height=26,
            width=50,
            corner_radius=5,
            fg_color="transparent",
            hover_color=BG_INPUT,
            text_color=COLOR_DANGER,
            command=self._clear_all_filters,
        )
        self.clear_filters_btn.pack(side="right")

        # Bulk Actions Floating/Docked Toolbar
        self._build_bulk_toolbar()

        # Scrollable Cards Area
        self.cards_scroll = ctk.CTkScrollableFrame(self.center_container, fg_color=BG_ROOT)
        self.cards_scroll.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # 3. Vault Child Views (Initialized lazily on first tab access for instant startup)
        self.health_view: Optional[HealthView] = None
        self.files_view: Optional[FilesView] = None
        self.groups_view: Optional[GroupsView] = None
        self.totp_view: Optional[TotpView] = None
        self.crypto_tools_view: Optional[CryptoToolsView] = None
        self._dirty_views: Set[str] = set()

    def _get_health_view(self) -> HealthView:
        if self.health_view is None:
            self.health_view = HealthView(
                self,
                database=self.database,
                encryption_key=self.session_key,
                on_review_entry=self.switch_to_credentials_tab,
                on_vault_updated=self.reload_entries,
            )
        return self.health_view

    def _get_files_view(self) -> FilesView:
        if self.files_view is None:
            self.files_view = FilesView(
                self,
                database=self.database,
                encryption_key=self.session_key,
            )
        return self.files_view

    def _get_groups_view(self) -> GroupsView:
        if self.groups_view is None:
            self.groups_view = GroupsView(
                self,
                database=self.database,
                session_key=self.session_key,
                clipboard_mgr=self.clipboard_mgr,
                on_select_entry=self.switch_to_credentials_tab,
            )
        return self.groups_view

    def _get_totp_view(self) -> TotpView:
        if self.totp_view is None:
            self.totp_view = TotpView(
                self,
                database=self.database,
                session_key=self.session_key,
                clipboard_mgr=self.clipboard_mgr,
            )
        return self.totp_view

    def _get_crypto_tools_view(self) -> CryptoToolsView:
        if self.crypto_tools_view is None:
            self.crypto_tools_view = CryptoToolsView(
                self,
                clipboard_mgr=self.clipboard_mgr,
                database=self.database,
                session_key=self.session_key,
                on_save_to_vault=self.reload_entries,
            )
        return self.crypto_tools_view

    def _build_top_navbar(self):
        top_bar = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0, border_width=1, border_color=BORDER_COLOR)
        top_bar.pack(fill="x")

        # Brand / Logo
        brand_frame = ctk.CTkFrame(top_bar, fg_color="transparent")
        brand_frame.pack(side="left", padx=(18, 8), pady=12)

        ctk.CTkLabel(
            brand_frame,
            text="★",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(
            brand_frame,
            text="StarVault",
            font=get_font(16, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # Navigation Tabs Segmented Button
        self.nav_var = ctk.StringVar(value="Credentials")
        self.tab_selector = ctk.CTkSegmentedButton(
            top_bar,
            values=["Credentials", "Groups", "2FA & QR", "Vault Health", "File Vault", "Crypto Tools"],
            variable=self.nav_var,
            command=self._on_nav_tab_changed,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            corner_radius=6,
        )
        self.tab_selector.pack(side="left", padx=10, pady=14)

        # Central Fuzzy Search Bar
        self.search_container = ctk.CTkFrame(top_bar, fg_color=BG_INPUT, corner_radius=6, border_width=1, border_color=BORDER_COLOR, width=340, height=38)
        self.search_container.pack(side="left", fill="x", expand=True, padx=(10, 16), pady=12)

        ctk.CTkLabel(self.search_container, text="⌕", font=get_font(14), text_color=TEXT_MUTED).pack(side="left", padx=(10, 4))

        self.search_entry = ctk.CTkEntry(
            self.search_container,
            placeholder_text="Search credentials, servers, domains, tags...",
            font=get_font(13),
            fg_color="transparent",
            border_width=0,
            text_color=TEXT_PRIMARY,
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=4)
        self.search_entry.bind("<KeyRelease>", lambda e: self._on_search_query_change())

        # Right Action & Status Area
        actions_frame = ctk.CTkFrame(top_bar, fg_color="transparent")
        actions_frame.pack(side="right", padx=16, pady=12)

        # Expiry Alert Pill (shown when items are expiring/expired)
        self.expiry_pill = ctk.CTkButton(
            actions_frame,
            text="",
            font=get_font(11, "bold"),
            fg_color=COLOR_WARNING,
            text_color="#000000",
            hover_color=COLOR_DANGER,
            height=28,
            corner_radius=6,
            command=self._on_expiry_pill_clicked,
        )

        # Clipboard Status Pill
        self.clipboard_pill = ctk.CTkLabel(
            actions_frame,
            text="",
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            text_color=COLOR_SUCCESS,
            corner_radius=6,
            padx=10,
            pady=4,
        )
        self.clipboard_pill.pack(side="left", padx=(0, 8))

        # Auto-lock indicator
        self.autolock_label = ctk.CTkLabel(
            actions_frame,
            text="5:00",
            font=get_mono_font(11),
            text_color=TEXT_MUTED,
        )
        self.autolock_label.pack(side="left", padx=(0, 10))

        # Action buttons
        ctk.CTkButton(
            actions_frame,
            text="+ New Entry",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_ON_ACCENT,
            height=34,
            corner_radius=6,
            command=self._open_new_entry_dialog,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="API Studio",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            corner_radius=6,
            command=self._open_api_key_studio,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="Key Studio",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            corner_radius=6,
            command=self._open_key_studio,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="Local Keys",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            height=34,
            corner_radius=6,
            command=self._open_local_key_installer,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="Export",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            corner_radius=6,
            command=self._open_vault_export_dialog,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="Import",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            corner_radius=6,
            command=self._open_vault_import_dialog,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="Settings",
            font=get_font(12),
            height=34,
            corner_radius=6,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self._open_settings,
        ).pack(side="left", padx=3)

        self.theme_btn = ctk.CTkButton(
            actions_frame,
            text=f"Theme: {get_current_theme()}",
            font=get_font(11, "bold"),
            height=34,
            corner_radius=6,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._on_cycle_theme_clicked,
        )
        self.theme_btn.pack(side="left", padx=3)

        ctk.CTkButton(
            actions_frame,
            text="Lock",
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            text_color=COLOR_DANGER,
            height=34,
            corner_radius=6,
            command=self.on_lock_requested,
        ).pack(side="left", padx=(3, 0))

    def _build_sidebar(self):
        # Category Filter Buttons
        ctk.CTkLabel(
            self.sidebar,
            text="CATEGORIES",
            font=get_font(10, "bold"),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=16, pady=(16, 6))

        self.cat_buttons = {}
        categories = [
            ("All", "All Entries"),
            ("Favorites", "Favorites"),
            ("Domains", "Domains & URLs"),
            ("API Keys", "API Keys"),
            ("Servers", "Servers & VPS"),
            ("Services", "Services & DBs"),
            ("Keys", "SSH & GPG Keys"),
        ]

        for cat_key, cat_label in categories:
            btn = ctk.CTkButton(
                self.sidebar,
                text=cat_label,
                font=get_font(12),
                anchor="w",
                height=34,
                corner_radius=6,
                fg_color=BG_CARD if cat_key == self.selected_category else "transparent",
                hover_color=BG_CARD_HOVER,
                text_color=ACCENT_PRIMARY if cat_key == self.selected_category else TEXT_SECONDARY,
                command=lambda k=cat_key: self._set_category_filter(k),
            )
            btn.pack(fill="x", padx=8, pady=2)
            self.cat_buttons[cat_key] = btn

        # Relational Tags Section
        ctk.CTkLabel(
            self.sidebar,
            text="RELATIONAL TAGS",
            font=get_font(10, "bold"),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=16, pady=(20, 6))

        self.tags_scroll = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        self.tags_scroll.pack(fill="both", expand=True, padx=8, pady=4)
        self._refresh_tags_sidebar()

    def _refresh_tags_sidebar(self):
        for child in self.tags_scroll.winfo_children():
            child.destroy()

        all_tags = self.database.get_all_tags()
        if not all_tags:
            ctk.CTkLabel(
                self.tags_scroll,
                text="No tags defined yet",
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(pady=8)
            return

        for tag in all_tags:
            # Count entries with this tag
            count = sum(1 for e in self.entries if tag.lower() in [t.lower() for t in e.tags])
            is_active = self.selected_tag == tag

            btn = ctk.CTkButton(
                self.tags_scroll,
                text=f"#{tag} ({count})",
                font=get_font(11),
                anchor="w",
                height=28,
                fg_color=BG_CARD if is_active else "transparent",
                hover_color=BG_CARD_HOVER,
                text_color=ACCENT_PRIMARY if is_active else TEXT_MUTED,
                command=lambda t=tag: self._toggle_tag_filter(t),
            )
            btn.pack(fill="x", pady=1)

    def _set_category_filter(self, category: str):
        self.selected_category = category
        for k, btn in self.cat_buttons.items():
            is_active = k == category
            btn.configure(
                fg_color=BG_CARD if is_active else "transparent",
                text_color=ACCENT_PRIMARY if is_active else TEXT_SECONDARY,
            )
        self.filter_title_lbl.configure(text=f"{category} Entries")
        self._apply_filters()

    def _toggle_tag_filter(self, tag: str):
        if self.selected_tag == tag:
            self.selected_tag = None
        else:
            self.selected_tag = tag
        self._refresh_tags_sidebar()
        self._apply_filters()

    def reload_entries(self):
        """Loads and decrypts entries from database."""
        try:
            self.entries = self.database.get_all_entries(self.session_key)
        except Exception:
            self.entries = []
        self._update_expiry_status()
        self._apply_filters()
        self._refresh_tags_sidebar()
        if hasattr(self, "_dirty_views"):
            self._dirty_views.update(["groups", "totp", "health", "files", "crypto"])

    def _update_expiry_status(self):
        """Checks for expiring credentials and updates the navbar alert pill."""
        if not hasattr(self, "expiry_pill"):
            return
        now_utc = datetime.now(timezone.utc)
        in_30_days = now_utc + timedelta(days=30)
        now_iso = now_utc.isoformat()
        soon_iso = in_30_days.isoformat()

        expiring_count = 0
        expired_count = 0
        for e in self.entries:
            exp = getattr(e, "expires_at", None)
            if exp:
                if exp < now_iso:
                    expired_count += 1
                elif exp <= soon_iso:
                    expiring_count += 1

        if expired_count > 0:
            self.expiry_pill.configure(
                text=f"⚠️ {expired_count} Expired",
                fg_color=COLOR_DANGER,
                hover_color=COLOR_WARNING,
            )
            self.expiry_pill.pack(side="left", padx=(0, 8))
        elif expiring_count > 0:
            self.expiry_pill.configure(
                text=f"⏳ {expiring_count} Expiring Soon",
                fg_color=COLOR_WARNING,
                hover_color=COLOR_DANGER,
            )
            self.expiry_pill.pack(side="left", padx=(0, 8))
        else:
            self.expiry_pill.pack_forget()

    def _on_expiry_pill_clicked(self):
        self.nav_var.set("Vault Health")
        self.tab_selector.set("Vault Health")
        self._on_nav_tab_changed("Vault Health")

    def _on_cycle_theme_clicked(self):
        new_theme = cycle_next_theme()
        if hasattr(self, "theme_btn"):
            self.theme_btn.configure(text=f"Theme: {new_theme}")
        self.reload_entries()

    def on_theme_changed(self, theme_name: str):
        if hasattr(self, "theme_btn"):
            self.theme_btn.configure(text=f"Theme: {theme_name}")
        self.reload_entries()

    def _on_search_query_change(self):
        self.autolock_mgr.record_activity()
        if self._search_job is not None:
            self.after_cancel(self._search_job)
        self._search_job = self.after(150, self._apply_filters)

    def _toggle_sort_direction(self):
        self.sort_reverse = not self.sort_reverse
        self.sort_dir_btn.configure(text="▼" if self.sort_reverse else "▲")
        self._apply_filters()

    def _on_type_filter_changed(self, choice: str):
        self.selected_type_filter = choice
        self._apply_filters()

    def _toggle_status_chip(self, chip: str):
        if self.selected_status_filter == chip:
            self.selected_status_filter = None
        else:
            self.selected_status_filter = chip
        self._update_chip_styles()
        self._apply_filters()

    def _update_chip_styles(self):
        self.chip_expiring.configure(
            fg_color=ACCENT_PRIMARY if self.selected_status_filter == "expiring" else BG_INPUT,
            text_color="#000000" if self.selected_status_filter == "expiring" else TEXT_PRIMARY,
        )
        self.chip_weak.configure(
            fg_color=COLOR_WARNING if self.selected_status_filter == "weak" else BG_INPUT,
            text_color="#000000" if self.selected_status_filter == "weak" else TEXT_PRIMARY,
        )
        self.chip_totp.configure(
            fg_color=ACCENT_INDIGO if self.selected_status_filter == "totp" else BG_INPUT,
            text_color="#ffffff" if self.selected_status_filter == "totp" else TEXT_PRIMARY,
        )

    def _clear_all_filters(self):
        self.search_entry.delete(0, "end")
        self.selected_type_filter = "All"
        self.type_filter_var.set("All")
        self.selected_status_filter = None
        self._update_chip_styles()
        self.selected_category = "All"
        for k, btn in self.cat_buttons.items():
            btn.configure(
                fg_color=BG_CARD if k == "All" else "transparent",
                text_color=ACCENT_PRIMARY if k == "All" else TEXT_SECONDARY,
            )
        self.selected_tag = None
        self._refresh_tags_sidebar()
        self._apply_filters()

    def _apply_filters(self):
        query = self.search_entry.get().strip()
        scored = search_entries(
            self.entries,
            query=query,
            selected_category=self.selected_category,
            selected_tag=self.selected_tag,
        )
        candidates = [e for e, score in scored]

        # 1. Filter by Selected Entry Type / Favorites
        if self.selected_type_filter in ("Domains", "🌐 Domains", "🔗 Domains"):
            candidates = [e for e in candidates if e.entry_type == "domain"]
        elif self.selected_type_filter in ("Servers", "🖥️ Servers"):
            candidates = [e for e in candidates if e.entry_type == "server"]
        elif self.selected_type_filter in ("Services", "⚙️ Services", "🌐 Services"):
            candidates = [e for e in candidates if e.entry_type == "service"]
        elif self.selected_type_filter in ("API Keys", "🔑 API Keys"):
            candidates = [e for e in candidates if e.entry_type == "apikey"]
        elif self.selected_type_filter in ("Keypairs", "Keys", "🛡️ Keys"):
            candidates = [e for e in candidates if e.entry_type == "keypair"]
        elif self.selected_type_filter in ("Favorites", "⭐ Favorites"):
            candidates = [e for e in candidates if e.is_favorite]

        # 2. Filter by Status Chip
        if self.selected_status_filter == "expiring":
            now_utc = datetime.now(timezone.utc)
            in_30_days = now_utc + timedelta(days=30)
            soon_iso = in_30_days.strftime("%Y-%m-%d")
            candidates = [e for e in candidates if getattr(e, "expires_at", "") and e.expires_at <= soon_iso]
        elif self.selected_status_filter == "weak":
            candidates = [e for e in candidates if e.password and len(e.password) < 12]
        elif self.selected_status_filter == "totp":
            candidates = [e for e in candidates if getattr(e, "totp_secret", "")]

        # 3. Apply Multi-Dimensional Sorting
        if hasattr(self, "dashboard_sort_combo"):
            from starvault.organizer import sort_entries
            choice = self.dashboard_sort_combo.get()
            mapping = {
                "Alphabetical (A → Z)": "title_asc",
                "Alphabetical (Z → A)": "title_desc",
                "Natural Numeric (1, 2, 10...)": "natural",
                "Date Modified (Newest)": "modified_desc",
                "Date Modified (Oldest)": "modified_asc",
                "Date Created (Newest)": "created_desc",
                "Date Created (Oldest)": "created_asc",
                "Category (A → Z)": "category",
                "Security Risk (Highest)": "risk",
                "Entry Type": "type",
                "Port Number (Numeric)": "port_numeric",
            }
            strat = mapping.get(choice, "title_asc")
            # Sort unless high-relevance query is being searched without explicit sort
            if not query or choice != "Alphabetical (A → Z)" or self.sort_reverse:
                candidates = sort_entries(candidates, sort_by=strat, reverse=self.sort_reverse)

        self.filtered_entries = candidates
        total_all = len(self.entries)
        if len(self.filtered_entries) == total_all:
            self.count_badge.configure(text=f"{total_all} items")
        else:
            self.count_badge.configure(text=f"Showing {len(self.filtered_entries)} of {total_all} items")

        self._render_cards()

    def _render_cards(self):
        # Incremental render: reuse existing card widgets when possible instead of
        # destroying and recreating every card on each search keystroke / filter change.
        # Recreating ~350 widgets per keystroke was the dominant UI cost (~1.5s).
        limit = self._rendered_limit

        # 1. Compute the set of entries that should be visible now
        to_show = self.filtered_entries[:limit]
        new_ids = [e.id for e in to_show]

        existing = self._card_widgets  # id -> card frame
        rendered_ids = getattr(self, "_rendered_ids", [])

        # Fast path: nothing changed -> just refresh selection highlights (cheap)
        if rendered_ids == new_ids:
            self._refresh_card_highlights()
            return

        if not to_show:
            self._card_widgets.clear()
            self._card_meta.clear()
            self._rendered_ids = []
            for child in self.cards_scroll.winfo_children():
                child.destroy()
            empty_frame = ctk.CTkFrame(self.cards_scroll, fg_color="transparent")
            empty_frame.pack(pady=60)
            ctk.CTkLabel(
                empty_frame,
                text="No matching credentials or services found.",
                font=get_font(14),
                text_color=TEXT_MUTED,
            ).pack()
            ctk.CTkButton(
                empty_frame,
                text="+ Create New Entry",
                font=get_font(12, "bold"),
                fg_color=ACCENT_PRIMARY,
                hover_color=ACCENT_HOVER,
                text_color="#000000",
                command=self._open_new_entry_dialog,
            ).pack(pady=12)
            return

        show_ids = set(new_ids)
        same_set = set(rendered_ids) == show_ids

        if not same_set:
            # 2. Destroy cards that are no longer in the result set
            for eid in [k for k in existing if k not in show_ids]:
                try:
                    existing[eid].destroy()
                except Exception:
                    pass
                del existing[eid]
                self._card_meta.pop(eid, None)

        # 3. Create / refresh cards in order. Only repack (reorder) when the
        #    actual order changed — avoid re-packing on every keystroke.
        reorder_needed = (rendered_ids != new_ids)
        for entry in to_show:
            card = existing.get(entry.id)
            meta = self._card_meta.get(entry.id)
            # Card is stale if it was created for a different version of the entry
            # (edited / re-imported / duplicate) — rebuild it in place.
            if card is not None and meta is not None and meta != (entry.updated_at, entry.is_favorite):
                try:
                    card.destroy()
                except Exception:
                    pass
                del existing[entry.id]
                card = None
            if card is None:
                card = self._render_entry_card(entry)
                existing[entry.id] = card
                self._card_meta[entry.id] = (entry.updated_at, entry.is_favorite)
            if reorder_needed:
                # Repack so ordering follows the current result order
                card.pack_forget()
                card.pack(fill="x", pady=4, padx=4)

        self._rendered_ids = new_ids
        # Reapply selection highlights once after the batch (cheap, skips unchanged)
        self._refresh_card_highlights()

        # 4. "Show remaining" button
        if len(self.filtered_entries) > limit:
            btn_more = getattr(self, "_show_more_btn", None)
            if btn_more is None or not btn_more.winfo_exists():
                btn_more = ctk.CTkButton(
                    self.cards_scroll,
                    text="",
                    font=get_font(11, "bold"),
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    text_color=ACCENT_PRIMARY,
                    height=32,
                    command=self._show_all_cards,
                )
                btn_more.pack(fill="x", padx=10, pady=8)
                self._show_more_btn = btn_more
            remaining = len(self.filtered_entries) - limit
            btn_more.configure(text=f"Show remaining {remaining} entries...")
        else:
            btn_more = getattr(self, "_show_more_btn", None)
            if btn_more is not None and btn_more.winfo_exists():
                btn_more.destroy()
                self._show_more_btn = None

    def _sync_card_state(self, card, entry: VaultEntry):
        """Updates a card's dynamic visuals without rebuilding it.

        Selection highlighting is handled centrally by _refresh_card_highlights
        (which skips unchanged state); this hook exists for future per-card state.
        """
        pass

    def _show_all_cards(self):
        self._rendered_limit = len(self.filtered_entries)
        self._render_cards()

    def _render_entry_card(self, entry: VaultEntry):
        is_selected = entry.id in self.selected_entry_ids
        card_bg = BG_CARD_HOVER if is_selected else BG_CARD

        card = ctk.CTkFrame(
            self.cards_scroll,
            fg_color=card_bg,
            corner_radius=10,
            border_width=2 if is_selected else 1,
            border_color=ACCENT_PRIMARY if is_selected else BORDER_COLOR,
        )
        card.pack(fill="x", pady=4, padx=4)
        self._card_widgets[entry.id] = card

        # Click card to select & show in inspector (supports Ctrl+Click and Shift+Click)
        card.bind("<Button-1>", lambda e, ent=entry: self._on_card_clicked(e, ent))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=10)
        inner.bind("<Button-1>", lambda e, ent=entry: self._on_card_clicked(e, ent))

        # Top row: Checkbox + Star Fav + Type Badge + Title + Tags
        top_row = ctk.CTkFrame(inner, fg_color="transparent")
        top_row.pack(fill="x")
        top_row.bind("<Button-1>", lambda e, ent=entry: self._on_card_clicked(e, ent))

        # Explicit multi-selection checkbox
        chk_var = ctk.BooleanVar(value=is_selected)
        chk = ctk.CTkCheckBox(
            top_row,
            text="",
            width=22,
            height=22,
            checkbox_width=18,
            checkbox_height=18,
            corner_radius=4,
            variable=chk_var,
            command=lambda ent=entry: self._toggle_single_card_selection(ent),
        )
        chk.pack(side="left", padx=(0, 4))

        # Favorite Star Toggle Button
        star_icon = "★" if entry.is_favorite else "☆"
        star_color = COLOR_FAVORITE if entry.is_favorite else TEXT_MUTED
        ctk.CTkButton(
            top_row,
            text=star_icon,
            width=24,
            height=24,
            fg_color="transparent",
            hover_color=BG_INPUT,
            font=get_font(14),
            text_color=star_color,
            command=lambda e=entry: self._toggle_favorite(e),
        ).pack(side="left", padx=(0, 6))

        # Type Badge
        if entry.entry_type == "server":
            badge_color = ACCENT_PRIMARY
            badge_text = "SERVER"
        elif entry.entry_type == "domain":
            badge_color = ACCENT_EMERALD
            badge_text = "DOMAIN"
        elif entry.entry_type == "service":
            badge_color = COLOR_WARNING
            badge_text = "SERVICE"
        elif entry.entry_type == "apikey":
            badge_color = ACCENT_INDIGO
            badge_text = "API KEY"
        else:
            badge_color = ACCENT_PURPLE
            badge_text = "KEY"

        ctk.CTkLabel(
            top_row,
            text=badge_text,
            font=get_font(9, "bold"),
            text_color=badge_color,
            fg_color=BG_INPUT,
            corner_radius=4,
            padx=6,
            pady=1,
        ).pack(side="left", padx=(0, 8))

        # Title
        title_lbl = ctk.CTkLabel(
            top_row,
            text=entry.title,
            font=get_font(13, "bold"),
            text_color=TEXT_PRIMARY,
        )
        title_lbl.pack(side="left")
        title_lbl.bind("<Button-1>", lambda e, ent=entry: self._on_card_clicked(e, ent))

        # Tag chips
        for tag in entry.tags[:3]:
            ctk.CTkLabel(
                top_row,
                text=f"#{tag}",
                font=get_font(10),
                text_color=TEXT_MUTED,
                fg_color=BG_INPUT,
                corner_radius=4,
                padx=5,
                pady=1,
            ).pack(side="left", padx=2)

        # Group chips
        if getattr(entry, "groups", None):
            for grp in entry.groups[:2]:
                ctk.CTkLabel(
                    top_row,
                    text=grp,
                    font=get_font(9),
                    text_color=ACCENT_INDIGO,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=4,
                    pady=1,
                ).pack(side="left", padx=2)

        # Service chips
        if getattr(entry, "services", None):
            for srv in entry.services[:2]:
                ctk.CTkLabel(
                    top_row,
                    text=srv,
                    font=get_font(9),
                    text_color=ACCENT_PRIMARY,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=4,
                    pady=1,
                ).pack(side="left", padx=2)

        # Domain link chip on child items
        if getattr(entry, "parent_domain_id", None):
            p_dom = next((e for e in self.entries if e.id == entry.parent_domain_id), None)
            if p_dom:
                ctk.CTkLabel(
                    top_row,
                    text=p_dom.title,
                    font=get_font(9, "bold"),
                    text_color=ACCENT_EMERALD,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=4,
                    pady=1,
                ).pack(side="left", padx=2)

        # Domain specific chips (attached count & host server)
        if entry.entry_type == "domain":
            attached_count = sum(1 for e in self.entries if getattr(e, "parent_domain_id", None) == entry.id)
            if attached_count > 0:
                ctk.CTkLabel(
                    top_row,
                    text=f"{attached_count} linked",
                    font=get_font(9, "bold"),
                    text_color=TEXT_PRIMARY,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=5,
                    pady=1,
                ).pack(side="left", padx=2)
            if entry.parent_server_id:
                p_svr = next((e for e in self.entries if e.id == entry.parent_server_id), None)
                if p_svr:
                    ctk.CTkLabel(
                        top_row,
                        text=p_svr.title,
                        font=get_font(9),
                        text_color=ACCENT_PRIMARY,
                        fg_color=BG_INPUT,
                        corner_radius=4,
                        padx=4,
                        pady=1,
                    ).pack(side="left", padx=2)

        # Middle row: Subtitle Info Preview
        mid_row = ctk.CTkFrame(inner, fg_color="transparent")
        mid_row.pack(fill="x", pady=(4, 6))
        mid_row.bind("<Button-1>", lambda e, ent=entry: self._on_card_clicked(e, ent))

        preview_str = ""
        if entry.entry_type == "server":
            preview_str = f"{entry.username}@{entry.hostname}:{entry.port}"
            if entry.os_distro:
                preview_str += f" ({entry.os_distro})"
        elif entry.entry_type == "domain":
            dom_display = entry.domain_name or entry.url or entry.title
            reg_display = entry.registrar or "Self-Managed"
            preview_str = f"{dom_display} • {reg_display}"
            if entry.expires_at:
                exp_date = parse_date_safely(entry.expires_at)
                if exp_date:
                    days_left = (exp_date - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        preview_str += f" • Expired ({abs(days_left)}d ago)"
                    elif days_left <= 30:
                        preview_str += f" • Exp: {days_left}d ({entry.expires_at[:10]})"
                    else:
                        preview_str += f" • Exp: {entry.expires_at[:10]}"
                else:
                    preview_str += f" • Exp: {entry.expires_at[:10]}"
            if getattr(entry, "auto_renew", False):
                preview_str += " • Auto-Renew"
            if getattr(entry, "dns_provider", ""):
                preview_str += f" • DNS: {entry.dns_provider}"
        elif entry.entry_type == "service":
            preview_str = f"{entry.app_name} • {entry.url or entry.hostname}"
            if entry.port:
                preview_str += f":{entry.port}"
        elif entry.entry_type == "apikey":
            env_str = entry.environment or "Production"
            preview_str = f"{entry.provider or 'API Key'} • Env: {env_str} • Format: {entry.api_key_format or 'Standard'}"
            if entry.expires_at:
                preview_str += f" • Exp: {entry.expires_at[:10]}"
        elif entry.entry_type == "keypair":
            preview_str = f"{entry.key_type.upper()} • Fingerprint: {entry.fingerprint[:28]}..."

        sub_lbl = ctk.CTkLabel(
            mid_row,
            text=preview_str,
            font=get_mono_font(11),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        sub_lbl.pack(fill="x")
        sub_lbl.bind("<Button-1>", lambda e, ent=entry: self._on_card_clicked(e, ent))

        # Bottom row: One-Click Quick-Copy Action Buttons right on card
        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(fill="x")

        if entry.entry_type == "server":
            if entry.hostname:
                ctk.CTkButton(
                    btn_row,
                    text="Copy IP",
                    width=65,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.hostname, "IP address copied"),
                ).pack(side="left", padx=(0, 4))

            ctk.CTkButton(
                btn_row,
                text="SSH Command",
                width=90,
                height=24,
                corner_radius=4,
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                font=get_font(11, "bold"),
                text_color=ACCENT_PRIMARY,
                command=lambda e=entry: self._copy_val(generate_ssh_command(e), "SSH command copied"),
            ).pack(side="left", padx=3)

            if entry.password:
                ctk.CTkButton(
                    btn_row,
                    text="Password",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)

        elif entry.entry_type == "domain":
            dom_val = entry.domain_name or entry.url or entry.title
            if dom_val:
                clean_url = dom_val if (dom_val.startswith("http://") or dom_val.startswith("https://")) else f"https://{dom_val}"
                ctk.CTkButton(
                    btn_row,
                    text="Domain URL",
                    width=80,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda u=clean_url: self._copy_val(u, "Domain URL copied"),
                ).pack(side="left", padx=(0, 4))
            if getattr(entry, "username", ""):
                ctk.CTkButton(
                    btn_row,
                    text="Username",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda u=entry.username: self._copy_val(u, "Account username copied"),
                ).pack(side="left", padx=3)
            if getattr(entry, "password", ""):
                ctk.CTkButton(
                    btn_row,
                    text="Password",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    text_color=COLOR_WARNING,
                    font=get_font(11),
                    command=lambda p=entry.password: self._copy_val(p, "Account password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)
            if getattr(entry, "registrar", ""):
                ctk.CTkButton(
                    btn_row,
                    text="Registrar",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda r=entry.registrar: self._copy_val(r, "Registrar name copied"),
                ).pack(side="left", padx=3)
            if getattr(entry, "auth_code", ""):
                ctk.CTkButton(
                    btn_row,
                    text="Auth Code",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    text_color=COLOR_WARNING,
                    font=get_font(11),
                    command=lambda c=entry.auth_code: self._copy_val(c, "Transfer auth code copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)
            ctk.CTkButton(
                btn_row,
                text="+ Attach",
                width=65,
                height=24,
                corner_radius=4,
                fg_color=BG_INPUT,
                hover_color=ACCENT_HOVER,
                font=get_font(11, "bold"),
                text_color=ACCENT_PRIMARY,
                command=lambda d=entry: self._create_linked_item_for_domain(d),
            ).pack(side="left", padx=3)

        elif entry.entry_type == "service":
            if entry.url or entry.hostname:
                ctk.CTkButton(
                    btn_row,
                    text="Copy URL",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.url or e.hostname, "URL copied"),
                ).pack(side="left", padx=(0, 4))

            if "postgres" in (entry.service_type or "") or "mysql" in (entry.service_type or "") or "redis" in (entry.service_type or ""):
                ctk.CTkButton(
                    btn_row,
                    text="DB URL",
                    width=70,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(generate_db_url(e), "DB URL copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)

            if entry.api_token:
                ctk.CTkButton(
                    btn_row,
                    text="API Token",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_SUCCESS,
                    command=lambda e=entry: self._copy_val(e.api_token, "API token copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)
            elif entry.password:
                ctk.CTkButton(
                    btn_row,
                    text="Password",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)

        elif entry.entry_type == "apikey":
            if entry.api_token:
                ctk.CTkButton(
                    btn_row,
                    text="Copy Key",
                    width=75,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=ACCENT_INDIGO,
                    command=lambda e=entry: self._copy_val(e.api_token, "API key copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=(0, 4))
            if entry.api_key_secret:
                ctk.CTkButton(
                    btn_row,
                    text="Secret",
                    width=65,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.api_key_secret, "API secret copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)
            if entry.totp_secret:
                from starvault.totp import generate_totp
                ctk.CTkButton(
                    btn_row,
                    text="2FA Code",
                    width=70,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_SUCCESS,
                    command=lambda e=entry: self._copy_val(generate_totp(e.totp_secret), "2FA code copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)

        elif entry.entry_type == "keypair":
            if entry.public_key:
                ctk.CTkButton(
                    btn_row,
                    text="Public Key",
                    width=80,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.public_key, "Public key copied"),
                ).pack(side="left", padx=(0, 4))

            if entry.private_key:
                ctk.CTkButton(
                    btn_row,
                    text="Private Key",
                    width=85,
                    height=24,
                    corner_radius=4,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_DANGER,
                    command=lambda e=entry: self._copy_val(e.private_key, "Private key copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=3)

        return card

    def _select_entry(self, entry: VaultEntry):
        self.selected_entry = entry
        self.autolock_mgr.record_activity()
        if not self.inspector_visible:
            self._toggle_inspector()
        self._refresh_card_highlights()
        self._render_inspector()

    def _toggle_inspector(self):
        self.inspector_visible = not self.inspector_visible
        if self.inspector_visible:
            self.inspector_panel.pack(side="right", fill="both")
            self.inspector_toggle_btn.configure(text="◀ Inspector")
        else:
            self.inspector_panel.pack_forget()
            self.inspector_toggle_btn.configure(text="▶ Inspector")

    def _build_bulk_toolbar(self):
        self.bulk_toolbar = ctk.CTkFrame(
            self.center_container,
            fg_color=BG_CARD,
            height=44,
            corner_radius=8,
            border_width=1,
            border_color=ACCENT_PRIMARY,
        )
        self.bulk_inner = ctk.CTkFrame(self.bulk_toolbar, fg_color="transparent")
        self.bulk_inner.pack(fill="x", padx=12, pady=6)

        self.bulk_count_lbl = ctk.CTkLabel(
            self.bulk_inner,
            text="Selected: 0 items",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        )
        self.bulk_count_lbl.pack(side="left", padx=(0, 10))

        # Copy Usernames
        ctk.CTkButton(
            self.bulk_inner,
            text="Copy Users",
            font=get_font(11),
            height=28,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._bulk_copy_usernames,
        ).pack(side="left", padx=3)

        # Copy Passwords
        ctk.CTkButton(
            self.bulk_inner,
            text="Copy Passwords",
            font=get_font(11),
            height=28,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_WARNING,
            command=self._bulk_copy_passwords,
        ).pack(side="left", padx=3)

        # Clone Selected
        ctk.CTkButton(
            self.bulk_inner,
            text="Duplicate All",
            font=get_font(11),
            height=28,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._bulk_clone_selected,
        ).pack(side="left", padx=3)

        # Bulk Tag
        ctk.CTkButton(
            self.bulk_inner,
            text="Add Tag",
            font=get_font(11),
            height=28,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._bulk_add_tag,
        ).pack(side="left", padx=3)

        # Bulk Delete
        ctk.CTkButton(
            self.bulk_inner,
            text="Delete All",
            font=get_font(11, "bold"),
            height=28,
            fg_color=COLOR_DANGER,
            hover_color=BORDER_COLOR,
            text_color="#ffffff",
            command=self._bulk_delete_selected,
        ).pack(side="left", padx=3)

        # Deselect All
        ctk.CTkButton(
            self.bulk_inner,
            text="Deselect",
            font=get_font(11),
            height=28,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            command=self._deselect_all,
        ).pack(side="right", padx=3)

    def _update_bulk_toolbar(self):
        cnt = len(self.selected_entry_ids)
        if cnt > 0:
            if hasattr(self, "bulk_count_lbl"):
                self.bulk_count_lbl.configure(text=f"Selected: {cnt} items")
            if hasattr(self, "bulk_toolbar") and not self.bulk_toolbar.winfo_ismapped():
                self.bulk_toolbar.pack(fill="x", padx=12, pady=(0, 6), before=self.cards_scroll)
        else:
            if hasattr(self, "bulk_toolbar") and self.bulk_toolbar.winfo_ismapped():
                self.bulk_toolbar.pack_forget()

    def _on_card_clicked(self, event, entry: VaultEntry):
        self.autolock_mgr.record_activity()
        is_ctrl = bool(event.state & 0x0004) or (hasattr(event, "keysym") and "Control" in event.keysym)
        is_shift = bool(event.state & 0x0001) or (hasattr(event, "keysym") and "Shift" in event.keysym)

        if is_shift and self.last_clicked_id:
            all_ids = [e.id for e in self.filtered_entries]
            if self.last_clicked_id in all_ids and entry.id in all_ids:
                idx1 = all_ids.index(self.last_clicked_id)
                idx2 = all_ids.index(entry.id)
                start_i, end_i = min(idx1, idx2), max(idx1, idx2)
                for i in range(start_i, end_i + 1):
                    self.selected_entry_ids.add(all_ids[i])
            else:
                self.selected_entry_ids.add(entry.id)
            self.last_clicked_id = entry.id
            self.selected_entry = entry
            self._render_inspector()
        elif is_ctrl:
            if entry.id in self.selected_entry_ids:
                self.selected_entry_ids.remove(entry.id)
            else:
                self.selected_entry_ids.add(entry.id)
            self.last_clicked_id = entry.id
            self.selected_entry = entry
            self._render_inspector()
        else:
            self.selected_entry_ids = {entry.id}
            self.last_clicked_id = entry.id
            self._select_entry(entry)

        self._update_bulk_toolbar()
        self._refresh_card_highlights()

    def _toggle_single_card_selection(self, entry: VaultEntry):
        if entry.id in self.selected_entry_ids:
            self.selected_entry_ids.remove(entry.id)
        else:
            self.selected_entry_ids.add(entry.id)
            self.selected_entry = entry
            self._render_inspector()
        self.last_clicked_id = entry.id
        self._update_bulk_toolbar()
        self._refresh_card_highlights()

    def _refresh_card_highlights(self):
        # Only reconfigure cards whose selection state changed — per-widget
        # .configure() is a Tcl round-trip and dominates re-render time.
        try:
            prev_sel = self._highlighted_selection
        except AttributeError:
            prev_sel = None
        if prev_sel == self.selected_entry_ids:
            return
        self._highlighted_selection = set(self.selected_entry_ids)
        for eid, widget in self._card_widgets.items():
            is_sel = eid in self.selected_entry_ids
            try:
                widget.configure(
                    fg_color=BG_CARD_HOVER if is_sel else BG_CARD,
                    border_color=ACCENT_PRIMARY if is_sel else BORDER_COLOR,
                    border_width=2 if is_sel else 1,
                )
            except Exception:
                pass

    def _bulk_copy_usernames(self):
        selected = [e for e in self.entries if e.id in self.selected_entry_ids]
        users = [getattr(e, "username", "") for e in selected if getattr(e, "username", "")]
        if users:
            text = "\n".join(users)
            self.clipboard_mgr.copy(text, f"Copied {len(users)} usernames")
        else:
            self.clipboard_mgr.copy("", "No usernames found in selected items")

    def _bulk_copy_passwords(self):
        selected = [e for e in self.entries if e.id in self.selected_entry_ids]
        pwds = [getattr(e, "password", "") for e in selected if getattr(e, "password", "")]
        if pwds:
            text = "\n".join(pwds)
            self.clipboard_mgr.copy(text, f"Copied {len(pwds)} passwords (30s wipe)", is_sensitive=True)
        else:
            self.clipboard_mgr.copy("", "No passwords found in selected items")

    def _bulk_clone_selected(self):
        selected = [e for e in self.entries if e.id in self.selected_entry_ids]
        if not selected:
            return
        cloned_count = 0
        now_iso = datetime.now(timezone.utc).isoformat()
        for e in selected:
            new_e = VaultEntry(
                id=str(uuid.uuid4()),
                entry_type=e.entry_type,
                title=f"{e.title} (Copy)",
                category=e.category,
                tags=list(e.tags) + ["cloned"],
                is_favorite=False,
                created_at=now_iso,
                updated_at=now_iso,
                username=e.username,
                password=e.password,
                hostname=e.hostname,
                port=e.port,
                sudo_password=e.sudo_password,
                ssh_key=e.ssh_key,
                os_distro=e.os_distro,
                url=e.url,
                app_name=e.app_name,
                database_name=e.database_name,
                api_token=e.api_token,
                provider=e.provider,
                environment=e.environment,
                api_key_format=e.api_key_format,
                secret_key=e.secret_key,
                scopes=list(e.scopes) if e.scopes else [],
                key_type=e.key_type,
                public_key=e.public_key,
                private_key=e.private_key,
                passphrase=e.passphrase,
                fingerprint=e.fingerprint,
                notes=e.notes,
                totp_secret=e.totp_secret,
                expires_at=e.expires_at,
                custom_fields=list(e.custom_fields) if e.custom_fields else [],
            )
            self.database.save_entry(new_e, self.session_key)
            cloned_count += 1
        self.reload_entries()
        messagebox.showinfo("Cloned", f"Successfully cloned {cloned_count} entries.")

    def _bulk_add_tag(self):
        selected = [e for e in self.entries if e.id in self.selected_entry_ids]
        if not selected:
            return
        tag = ctk.CTkInputDialog(text="Enter tag to add to selected entries:", title="Bulk Add Tag").get_input()
        if tag and tag.strip():
            clean_tag = tag.strip().lstrip("#").lower()
            for e in selected:
                if clean_tag not in e.tags:
                    e.tags.append(clean_tag)
                    self.database.save_entry(e, self.session_key)
            self.reload_entries()

    def _bulk_delete_selected(self):
        count = len(self.selected_entry_ids)
        if count == 0:
            return
        ans = messagebox.askyesno("Confirm Bulk Deletion", f"Permanently delete {count} selected entries?\n\nThis cannot be undone.")
        if ans:
            for eid in list(self.selected_entry_ids):
                self.database.delete_entry(eid)
            self.selected_entry_ids.clear()
            self.selected_entry = None
            self._update_bulk_toolbar()
            self.reload_entries()
            self._render_inspector()

    def _deselect_all(self):
        self.selected_entry_ids.clear()
        self.last_clicked_id = None
        self._update_bulk_toolbar()
        self._refresh_card_highlights()

    def _render_inspector_empty(self):
        for child in self.inspector_panel.winfo_children():
            child.destroy()

        ctk.CTkLabel(
            self.inspector_panel,
            text="Select an entry to view decrypted details,\nterminal quick-strings, and rich notes.",
            font=get_font(12),
            text_color=TEXT_MUTED,
            justify="center",
        ).pack(pady=120, padx=20)

    def _render_inspector(self):
        for child in self.inspector_panel.winfo_children():
            child.destroy()

        entry = self.selected_entry
        if not entry:
            self._render_inspector_empty()
            return

        # Top Header & Actions
        top_bar = ctk.CTkFrame(self.inspector_panel, fg_color="transparent")
        top_bar.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(
            top_bar,
            text=entry.title,
            font=get_font(16, "bold"),
            text_color=TEXT_PRIMARY,
            anchor="w",
            wraplength=260,
        ).pack(side="left")

        # Edit, Duplicate & Delete Buttons
        ctk.CTkButton(
            top_bar,
            text="Delete",
            width=32,
            height=30,
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            command=lambda: self._delete_entry(entry),
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            top_bar,
            text="Duplicate",
            width=65,
            height=30,
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._duplicate_entry(entry),
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            top_bar,
            text="History",
            width=70,
            height=30,
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._open_version_history(entry),
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            top_bar,
            text="Edit",
            width=65,
            height=30,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._edit_entry(entry),
        ).pack(side="right")

        # Category & Tags
        meta_row = ctk.CTkFrame(self.inspector_panel, fg_color="transparent")
        meta_row.pack(fill="x", padx=12, pady=(0, 6))

        ctk.CTkLabel(
            meta_row,
            text=f"{entry.category} • {entry.entry_type.upper()}",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(side="left")

        # Assigned groups and services chips
        entry_groups = getattr(entry, "groups", []) or []
        entry_services = getattr(entry, "services", []) or []
        if entry_groups or entry_services:
            pill_row = ctk.CTkFrame(self.inspector_panel, fg_color="transparent")
            pill_row.pack(fill="x", padx=12, pady=(0, 8))
            for grp in entry_groups:
                ctk.CTkLabel(
                    pill_row,
                    text=grp,
                    font=get_font(10),
                    text_color=ACCENT_INDIGO,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=6,
                    pady=2,
                ).pack(side="left", padx=(0, 4))
            for srv in entry_services:
                ctk.CTkLabel(
                    pill_row,
                    text=srv,
                    font=get_font(10),
                    text_color=ACCENT_PRIMARY,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=6,
                    pady=2,
                ).pack(side="left", padx=(0, 4))

        # Details Box
        self._build_inspector_details(entry)

        # Embedded Sub-Credentials Table for Servers & Domains
        if entry.entry_type == "server":
            self._build_inspector_subcredentials(entry)
        elif entry.entry_type == "domain":
            self._build_inspector_domain_items(entry)

        # Custom Key-Value Fields Box
        self._build_inspector_custom_fields(entry)

        # Terminal & Quick Strings Box
        self._build_inspector_quick_strings(entry)

        # Rich Notes Box
        self._build_inspector_notes(entry)

        # Metadata Timestamps Banner
        self._build_inspector_timestamps(entry)

    def _build_inspector_details(self, entry: VaultEntry):
        box = ctk.CTkFrame(self.inspector_panel, fg_color=BG_INPUT, corner_radius=8)
        box.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(box, text="CREDENTIALS", font=get_font(10, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=12, pady=(8, 4))

        if entry.entry_type == "server":
            self._add_inspector_field(box, "Host / IP", entry.hostname, copyable=True)
            self._add_inspector_field(box, "Port", str(entry.port), copyable=False)
            self._add_inspector_field(box, "Username", entry.username, copyable=True)
            if entry.password:
                self._add_inspector_masked_field(box, "Password", entry.password, key_id=f"pwd_{entry.id}")
            if entry.sudo_password:
                self._add_inspector_masked_field(box, "Sudo Password", entry.sudo_password, key_id=f"sudo_{entry.id}")

        elif entry.entry_type == "domain":
            dom_val = entry.domain_name or entry.url or entry.title
            clean_url = dom_val if (dom_val.startswith("http://") or dom_val.startswith("https://")) else f"https://{dom_val}" if dom_val else ""
            self._add_inspector_field(box, "Domain URL", clean_url, copyable=True)
            self._add_inspector_field(box, "Registrar", entry.registrar or "Unassigned", copyable=bool(entry.registrar))

            exp_text = entry.expires_at[:10] if entry.expires_at else ""
            if exp_text:
                exp_date = parse_date_safely(entry.expires_at)
                if exp_date:
                    days_left = (exp_date - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        exp_text += f" (EXPIRED {abs(days_left)}d ago!)"
                    elif days_left <= 30:
                        exp_text += f" (Expiring in {days_left}d)"
                    else:
                        exp_text += f" ({days_left}d remaining)"
            self._add_inspector_field(box, "Expires At", exp_text, copyable=False)
            if getattr(entry, "registered_at", ""):
                self._add_inspector_field(box, "Registered", entry.registered_at[:10], copyable=False)
            if getattr(entry, "renewal_cost", ""):
                self._add_inspector_field(box, "Renewal Cost", entry.renewal_cost, copyable=False)
            self._add_inspector_field(box, "Auto-Renew", "Enabled (Active)" if getattr(entry, "auto_renew", False) else "Disabled (Manual)", copyable=False)
            if getattr(entry, "dns_provider", ""):
                self._add_inspector_field(box, "DNS Provider", entry.dns_provider, copyable=True)
            if getattr(entry, "nameservers", ""):
                self._add_inspector_field(box, "Nameservers", entry.nameservers, copyable=True)
            if getattr(entry, "username", ""):
                self._add_inspector_field(box, "Account Username", entry.username, copyable=True)
            if getattr(entry, "password", ""):
                self._add_inspector_masked_field(box, "Account Password", entry.password, key_id=f"pwd_{entry.id}")
            if getattr(entry, "totp_secret", ""):
                from starvault.totp import generate_totp, get_totp_remaining_seconds
                code = generate_totp(entry.totp_secret)
                rem = get_totp_remaining_seconds()
                self._add_inspector_field(box, f"Registrar 2FA ({rem}s)", code, copyable=True, mono=True)
            if getattr(entry, "auth_code", ""):
                self._add_inspector_masked_field(box, "Auth Code", entry.auth_code, key_id=f"auth_{entry.id}")
            if entry.parent_server_id:
                p_svr = next((e for e in self.entries if e.id == entry.parent_server_id), None)
                if p_svr:
                    self._add_inspector_linked_entry_row(box, "Host Server", p_svr)

        elif entry.entry_type == "service":
            self._add_inspector_field(box, "App Name", entry.app_name, copyable=True)
            self._add_inspector_field(box, "URI / URL", entry.url, copyable=True)
            if entry.username:
                self._add_inspector_field(box, "Username", entry.username, copyable=True)
            if entry.password:
                self._add_inspector_masked_field(box, "Password", entry.password, key_id=f"pwd_{entry.id}")
            if entry.api_token:
                self._add_inspector_masked_field(box, "API Token", entry.api_token, key_id=f"tok_{entry.id}")
            if entry.db_name:
                self._add_inspector_field(box, "Database Name", entry.db_name, copyable=True)

        elif entry.entry_type == "apikey":
            self._add_inspector_field(box, "Provider", entry.provider, copyable=True)
            self._add_inspector_field(box, "Environment", entry.environment or "Production", copyable=False)
            self._add_inspector_field(box, "Format", entry.api_key_format or "Standard", copyable=False)
            if entry.scopes:
                self._add_inspector_field(box, "Scopes", entry.scopes, copyable=True)
            if entry.expires_at:
                self._add_inspector_field(box, "Expires At", entry.expires_at[:10], copyable=False)
            if entry.api_token:
                self._add_inspector_masked_field(box, "API Key / Token", entry.api_token, key_id=f"tok_{entry.id}")
            if entry.api_key_secret:
                self._add_inspector_masked_field(box, "API Secret", entry.api_key_secret, key_id=f"sec_{entry.id}")
            if entry.totp_secret:
                from starvault.totp import generate_totp, get_totp_remaining_seconds
                code = generate_totp(entry.totp_secret)
                rem = get_totp_remaining_seconds()
                self._add_inspector_field(box, f"2FA Code ({rem}s)", code, copyable=True, mono=True)

        elif entry.entry_type == "keypair":
            self._add_inspector_field(box, "Algorithm", entry.key_type.upper(), copyable=False)
            self._add_inspector_field(box, "Fingerprint", entry.fingerprint, copyable=True)
            if entry.public_key:
                self._add_inspector_field(box, "Public Key", entry.public_key, copyable=True, mono=True)
            if entry.private_key:
                self._add_inspector_masked_field(box, "Private Key", entry.private_key, key_id=f"priv_{entry.id}")
            if entry.passphrase:
                self._add_inspector_masked_field(box, "Passphrase", entry.passphrase, key_id=f"pass_{entry.id}")

            ctk.CTkButton(
                box,
                text="💻 Install Key to Local System (~/.ssh)...",
                font=get_font(11, "bold"),
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                text_color=ACCENT_PRIMARY,
                height=30,
                command=lambda: self._open_local_key_installer(preselected=entry),
            ).pack(fill="x", padx=12, pady=(6, 8))

        # Linked Domain indicator for ANY entry type
        if getattr(entry, "parent_domain_id", None):
            p_dom = next((e for e in self.entries if e.id == entry.parent_domain_id), None)
            if p_dom:
                self._add_inspector_linked_entry_row(box, "Attached Domain", p_dom)

        # Linked Server indicator for services / apikeys
        if getattr(entry, "parent_server_id", None) and entry.entry_type != "domain":
            p_svr = next((e for e in self.entries if e.id == entry.parent_server_id), None)
            if p_svr:
                self._add_inspector_linked_entry_row(box, "Host Server", p_svr)

    def _add_inspector_linked_entry_row(self, parent, label: str, target_entry: VaultEntry):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=3)
        ctk.CTkLabel(row, text=label, font=get_font(11), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=f"{target_entry.title}", font=get_font(12, "bold"), text_color=ACCENT_PRIMARY, anchor="w").pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkButton(
            row,
            text="↗️",
            width=28,
            height=24,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            command=lambda e=target_entry: self._select_entry(e),
        ).pack(side="right")

    def _add_inspector_field(self, parent, label: str, val: str, copyable: bool = False, mono: bool = False):
        if not val:
            return
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=3)

        ctk.CTkLabel(row, text=label, font=get_font(11), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")

        font_used = get_mono_font(11) if mono else get_font(12)
        val_lbl = ctk.CTkLabel(row, text=val, font=font_used, text_color=TEXT_PRIMARY, anchor="w")
        val_lbl.pack(side="left", fill="x", expand=True, padx=4)

        if copyable:
            ctk.CTkButton(
                row,
                text="📋",
                width=28,
                height=24,
                fg_color="transparent",
                hover_color=BORDER_COLOR,
                command=lambda v=val, l=label: self._copy_val(v, f"{l} copied"),
            ).pack(side="right")

    def _add_inspector_masked_field(self, parent, label: str, val: str, key_id: str):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=3)

        ctk.CTkLabel(row, text=label, font=get_font(11), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")

        is_revealed = key_id in self._revealed_secrets
        display_text = val if is_revealed else "••••••••••••"

        val_lbl = ctk.CTkLabel(row, text=display_text, font=get_mono_font(12), text_color=TEXT_PRIMARY, anchor="w")
        val_lbl.pack(side="left", fill="x", expand=True, padx=4)

        # Reveal toggle button
        eye_btn = ctk.CTkButton(
            row,
            text="👁" if not is_revealed else "🔒",
            width=28,
            height=24,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            command=lambda k=key_id: self._toggle_secret_reveal(k),
        )
        eye_btn.pack(side="right", padx=(2, 0))

        # Copy button (30s wipe)
        ctk.CTkButton(
            row,
            text="📋",
            width=28,
            height=24,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            text_color=COLOR_WARNING,
            command=lambda v=val, l=label: self._copy_val(v, f"{l} copied (30s wipe)", is_sensitive=True),
        ).pack(side="right")

    def _toggle_secret_reveal(self, key_id: str):
        if key_id in self._revealed_secrets:
            self._revealed_secrets.remove(key_id)
        else:
            self._revealed_secrets.add(key_id)
        self._render_inspector()

    def _build_inspector_quick_strings(self, entry: VaultEntry):
        q_card = ctk.CTkFrame(self.inspector_panel, fg_color=BG_INPUT, corner_radius=8)
        q_card.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(q_card, text="TERMINAL QUICK-STRINGS", font=get_font(10, "bold"), text_color=COLOR_WARNING).pack(anchor="w", padx=12, pady=(8, 4))

        if entry.entry_type == "server":
            # Ready-to-paste SSH string
            ssh_str = generate_ssh_command(entry)
            self._render_quick_string_row(q_card, "SSH Command", ssh_str)

        elif entry.entry_type == "service":
            # Database URI
            if "postgres" in (entry.service_type or "") or "mysql" in (entry.service_type or "") or "redis" in (entry.service_type or ""):
                db_url = generate_db_url(entry)
                self._render_quick_string_row(q_card, "Connection URL", db_url, is_sensitive=True)

                cli_cmd = generate_db_cli_command(entry)
                if cli_cmd:
                    self._render_quick_string_row(q_card, "CLI Client", cli_cmd)

            # Curl command
            curl_cmd = generate_curl_command(entry)
            self._render_quick_string_row(q_card, "cURL Request", curl_cmd, is_sensitive=bool(entry.api_token or entry.password))

        elif entry.entry_type == "apikey":
            if entry.api_token:
                curl_cmd = f"curl -H 'Authorization: Bearer {entry.api_token}' https://api.example.com"
                self._render_quick_string_row(q_card, "cURL Bearer Header", curl_cmd, is_sensitive=True)
                export_cmd = f"export API_KEY='{entry.api_token}'"
                self._render_quick_string_row(q_card, "Shell Export", export_cmd, is_sensitive=True)

        elif entry.entry_type == "domain":
            whois_str = generate_whois_command(entry)
            self._render_quick_string_row(q_card, "WHOIS Lookup", whois_str)
            dig_str = generate_dig_command(entry, record_type="A")
            self._render_quick_string_row(q_card, "DNS Query (A Record)", dig_str)
            dig_ns = generate_dig_command(entry, record_type="NS")
            self._render_quick_string_row(q_card, "Nameservers Query (NS)", dig_ns)
            dig_mx = generate_dig_command(entry, record_type="MX")
            self._render_quick_string_row(q_card, "Mail Exchange (MX)", dig_mx)
            dig_txt = generate_dig_command(entry, record_type="TXT")
            self._render_quick_string_row(q_card, "TXT / SPF / DMARC", dig_txt)

    def _render_quick_string_row(self, parent, label: str, text_val: str, is_sensitive: bool = False):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=12, pady=4)

        ctk.CTkLabel(frame, text=label, font=get_font(11, "bold"), text_color=TEXT_MUTED).pack(anchor="w")

        code_row = ctk.CTkFrame(frame, fg_color=BG_ROOT, corner_radius=6)
        code_row.pack(fill="x", pady=(2, 4))

        ctk.CTkLabel(
            code_row,
            text=text_val,
            font=get_mono_font(11),
            text_color=TEXT_PRIMARY,
            anchor="w",
            wraplength=260,
        ).pack(side="left", fill="x", expand=True, padx=8, pady=6)

        ctk.CTkButton(
            code_row,
            text="Copy",
            width=50,
            height=26,
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            font=get_font(11),
            text_color=ACCENT_PRIMARY,
            command=lambda v=text_val, l=label, s=is_sensitive: self._copy_val(v, f"{l} copied", is_sensitive=s),
        ).pack(side="right", padx=6, pady=4)

    def _build_inspector_notes(self, entry: VaultEntry):
        if not entry.notes:
            return

        notes_box = ctk.CTkFrame(self.inspector_panel, fg_color=BG_INPUT, corner_radius=8)
        notes_box.pack(fill="x", padx=12, pady=(0, 16))

        h_row = ctk.CTkFrame(notes_box, fg_color="transparent")
        h_row.pack(fill="x", padx=12, pady=(8, 4))

        ctk.CTkLabel(h_row, text="RICH NOTES", font=get_font(10, "bold"), text_color=ACCENT_PRIMARY).pack(side="left")

        ctk.CTkButton(
            h_row,
            text="Copy Notes",
            width=80,
            height=22,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            font=get_font(10),
            command=lambda n=entry.notes: self._copy_val(n, "Notes copied"),
        ).pack(side="right")

        ctk.CTkLabel(
            notes_box,
            text=entry.notes,
            font=get_mono_font(11),
            text_color=TEXT_SECONDARY,
            anchor="w",
            justify="left",
            wraplength=340,
        ).pack(fill="x", padx=12, pady=(0, 12))

    def _copy_val(self, val: str, label: str, is_sensitive: bool = False):
        self.autolock_mgr.record_activity()
        self.clipboard_mgr.copy(val, label=label, is_sensitive=is_sensitive)

    def _on_clipboard_status(self, label: str, seconds_left: int):
        self.clipboard_pill.configure(text=label)
        if seconds_left == 0 and "cleared" in label.lower():
            self.after(3000, lambda: self.clipboard_pill.configure(text=""))

    def _schedule_autolock_ui_update(self):
        """Updates auto-lock countdown timer label every 1 second and checks idle timeout."""
        if self.autolock_mgr.check_inactivity():
            # Locked!
            return

        rem = self.autolock_mgr.get_remaining_seconds()
        if rem >= 0:
            mins, secs = divmod(rem, 60)
            self.autolock_label.configure(text=f"⏱️ {mins}:{secs:02d}")
        else:
            self.autolock_label.configure(text="⏱️ Never")

        self.after(1000, self._schedule_autolock_ui_update)

    def _on_nav_tab_changed(self, tab_name: str):
        self.autolock_mgr.record_activity()
        # Hide all active content frames
        self.body_frame.pack_forget()
        if self.groups_view:
            self.groups_view.pack_forget()
        if self.totp_view:
            self.totp_view.pack_forget()
        if self.health_view:
            self.health_view.pack_forget()
        if self.files_view:
            self.files_view.pack_forget()
        if self.crypto_tools_view:
            self.crypto_tools_view.pack_forget()
        self.search_container.pack_forget()

        if tab_name == "Credentials":
            self.body_frame.pack(fill="both", expand=True)
            self.search_container.pack(side="left", fill="x", expand=True, padx=(10, 16), pady=12)
        elif tab_name in ("Groups", "🗂️ Groups"):
            gv = self._get_groups_view()
            gv.pack(fill="both", expand=True)
            if "groups" in self._dirty_views:
                gv.refresh() if hasattr(gv, "refresh") else gv.reload()
                self._dirty_views.discard("groups")
        elif tab_name in ("2FA & QR", "📱 2FA / QR", "2FA / QR"):
            tv = self._get_totp_view()
            tv.pack(fill="both", expand=True)
            if "totp" in self._dirty_views:
                tv.refresh() if hasattr(tv, "refresh") else tv.reload()
                self._dirty_views.discard("totp")
        elif tab_name in ("Vault Health", "🛡️ Vault Health"):
            hv = self._get_health_view()
            hv.pack(fill="both", expand=True)
            if "health" in self._dirty_views:
                hv.refresh() if hasattr(hv, "refresh") else hv.reload()
                self._dirty_views.discard("health")
        elif tab_name in ("File Vault", "📁 File Vault", "Files"):
            fv = self._get_files_view()
            fv.pack(fill="both", expand=True)
            if "files" in self._dirty_views:
                fv.refresh() if hasattr(fv, "refresh") else fv.reload()
                self._dirty_views.discard("files")
        elif tab_name in ("Crypto Tools", "⚡ Crypto Tools", "Crypto Studio"):
            ctv = self._get_crypto_tools_view()
            ctv.pack(fill="both", expand=True)
            if "crypto" in self._dirty_views:
                ctv.reload_keyring()
                self._dirty_views.discard("crypto")

    def switch_to_tab(self, tab_name: str):
        """Switches to the specified top-level navigation tab."""
        valid_tabs = ["Credentials", "Groups", "2FA & QR", "Vault Health", "File Vault", "Crypto Tools"]
        clean_input = "".join(c for c in tab_name.lower() if c.isalnum())

        target = None
        # 1. Exact or normalized match
        for t in valid_tabs:
            if t.lower() == tab_name.lower() or "".join(c for c in t.lower() if c.isalnum()) == clean_input:
                target = t
                break

        # 2. Normalized subtab contained
        if not target:
            for t in valid_tabs:
                clean_t = "".join(c for c in t.lower() if c.isalnum())
                if clean_t in clean_input:
                    target = t
                    break

        # 3. Keyword heuristics
        if not target:
            if "file" in clean_input:
                target = "File Vault"
            elif "health" in clean_input:
                target = "Vault Health"
            elif "2fa" in clean_input or "totp" in clean_input or "qr" in clean_input:
                target = "2FA & QR"
            elif "crypto" in clean_input:
                target = "Crypto Tools"
            elif "group" in clean_input:
                target = "Groups"
            elif "cred" in clean_input or "entry" in clean_input or "password" in clean_input:
                target = "Credentials"
            else:
                target = next((t for t in valid_tabs if t.lower() in tab_name.lower()), tab_name)

        self.nav_var.set(target)
        self.tab_selector.set(target)
        self._on_nav_tab_changed(target)

    def switch_to_credentials_tab(self, entry_id: Optional[str] = None):
        """Switches to Credentials tab and highlights/selects the given entry."""
        self.nav_var.set("Credentials")
        self.tab_selector.set("Credentials")
        self._on_nav_tab_changed("Credentials")
        if entry_id:
            for ent in self.entries:
                if ent.id == entry_id:
                    self._select_entry(ent)
                    break

    def _setup_hotkeys(self):
        """Binds UI-level keyboard shortcuts for rapid credential access."""
        root = self.winfo_toplevel()

        def can_handle_hotkey():
            widget = self.focus_get()
            # If user has text selected in an input field, allow default text copy
            if widget and hasattr(widget, "selection_present") and widget.selection_present():
                return False
            return True

        def on_ctrl_c(event):
            if not can_handle_hotkey():
                return None
            if self.selected_entry:
                pwd = self.selected_entry.password or self.selected_entry.api_token or self.selected_entry.private_key
                if pwd:
                    self._copy_val(pwd, "Password copied [Ctrl+C] (30s wipe)", is_sensitive=True)
                    return "break"

        def on_ctrl_u(event):
            if not can_handle_hotkey():
                return None
            if self.selected_entry and self.selected_entry.username:
                self._copy_val(self.selected_entry.username, "Username copied [Ctrl+U]")
                return "break"

        def on_ctrl_b(event):
            if not can_handle_hotkey():
                return None
            if self.selected_entry:
                target = self.selected_entry.hostname or self.selected_entry.url or ""
                if target:
                    self._copy_val(target, "URI/IP copied [Ctrl+B]")
                    return "break"

        def on_ctrl_d(event):
            if not can_handle_hotkey():
                return None
            if self.selected_entry:
                self._duplicate_entry(self.selected_entry)
                return "break"

        root.bind("<Control-c>", on_ctrl_c)
        root.bind("<Control-C>", on_ctrl_c)
        root.bind("<Control-u>", on_ctrl_u)
        root.bind("<Control-U>", on_ctrl_u)
        root.bind("<Control-b>", on_ctrl_b)
        root.bind("<Control-B>", on_ctrl_b)
        root.bind("<Control-d>", on_ctrl_d)
        root.bind("<Control-D>", on_ctrl_d)

    def _duplicate_entry(self, entry: VaultEntry):
        """Duplicates selected entry, persists it with '- Copy' title, and selects it."""
        self.autolock_mgr.record_activity()
        cloned = self.database.duplicate_entry(entry.id, self.session_key)
        if cloned:
            self._copy_val(cloned.title, f"Cloned '{entry.title}'")
            self.reload_entries()
            self._select_entry(cloned)

    def _build_inspector_subcredentials(self, server_entry: VaultEntry):
        """Renders relational sub-credentials embedded table of services hosted on this server."""
        child_services = self.database.get_child_services(server_entry.id, self.session_key)

        box = ctk.CTkFrame(self.inspector_panel, fg_color=BG_INPUT, corner_radius=8)
        box.pack(fill="x", padx=12, pady=(0, 10))

        header = ctk.CTkFrame(box, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(8, 4))

        ctk.CTkLabel(
            header,
            text=f"LINKED SERVICES / APPS ({len(child_services)})",
            font=get_font(10, "bold"),
            text_color=COLOR_WARNING,
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="+ Add Service",
            font=get_font(10, "bold"),
            width=85,
            height=20,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            command=lambda: self._create_linked_service_for(server_entry),
        ).pack(side="right")

        if not child_services:
            ctk.CTkLabel(
                box,
                text="No services linked to this server yet.\nClick '+ Add Service' or set Parent Server in an existing service.",
                font=get_font(11),
                text_color=TEXT_MUTED,
                justify="left",
            ).pack(anchor="w", padx=12, pady=(4, 10))
            return

        # Embedded Table
        table_container = ctk.CTkFrame(box, fg_color="transparent")
        table_container.pack(fill="x", padx=8, pady=(2, 8))

        # Column Header
        col_hdr = ctk.CTkFrame(table_container, fg_color="transparent")
        col_hdr.pack(fill="x", pady=(2, 4))
        ctk.CTkLabel(col_hdr, text="App / Note", font=get_font(10, "bold"), text_color=TEXT_MUTED, width=105, anchor="w").pack(side="left")
        ctk.CTkLabel(col_hdr, text="Username", font=get_font(10, "bold"), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
        ctk.CTkLabel(col_hdr, text="Password", font=get_font(10, "bold"), text_color=TEXT_MUTED, width=65, anchor="w").pack(side="left")
        ctk.CTkLabel(col_hdr, text="Quick Copy", font=get_font(10, "bold"), text_color=TEXT_MUTED, anchor="e").pack(side="right")

        for child in child_services:
            row = ctk.CTkFrame(table_container, fg_color=BG_CARD, corner_radius=4)
            row.pack(fill="x", pady=2)

            display_app = child.app_name or child.title
            if len(display_app) > 13:
                display_app = display_app[:11] + ".."
            ctk.CTkLabel(row, text=display_app, font=get_font(11, "bold"), text_color=TEXT_PRIMARY, width=105, anchor="w").pack(side="left", padx=(6, 2), pady=4)

            display_user = child.username or "-"
            if len(display_user) > 10:
                display_user = display_user[:8] + ".."
            ctk.CTkLabel(row, text=display_user, font=get_font(11), text_color=TEXT_SECONDARY, width=80, anchor="w").pack(side="left", padx=2)

            pwd_disp = "••••••••" if child.password else "-"
            ctk.CTkLabel(row, text=pwd_disp, font=get_mono_font(10), text_color=TEXT_MUTED, width=65, anchor="w").pack(side="left", padx=2)

            # Quick copy buttons
            act_box = ctk.CTkFrame(row, fg_color="transparent")
            act_box.pack(side="right", padx=4)

            if child.username:
                ctk.CTkButton(
                    act_box,
                    text="User",
                    width=38,
                    height=22,
                    corner_radius=4,
                    font=get_font(10),
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    command=lambda u=child.username: self._copy_val(u, "Sub-credential username copied"),
                ).pack(side="left", padx=1)

            if child.password:
                ctk.CTkButton(
                    act_box,
                    text="Pass",
                    width=38,
                    height=22,
                    corner_radius=4,
                    font=get_font(10),
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    command=lambda p=child.password: self._copy_val(p, "Sub-credential password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=1)

            ctk.CTkButton(
                act_box,
                text="Open",
                width=38,
                height=22,
                corner_radius=4,
                font=get_font(10),
                fg_color=BG_INPUT,
                hover_color=ACCENT_HOVER,
                command=lambda c=child: self._select_entry(c),
            ).pack(side="left", padx=1)

    def _create_linked_service_for(self, server_entry: VaultEntry):
        """Creates a new child service entry directly pre-linked to the parent server."""
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server"]
        domains = [e for e in self.entries if e.entry_type == "domain"]
        new_svc = VaultEntry.create_service(
            title=f"{server_entry.title} - Service",
            app_name="",
            url=server_entry.hostname,
        )
        new_svc.parent_server_id = server_entry.id
        EntryDialog(
            self,
            entry=new_svc,
            default_type="service",
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            available_domains=domains,
            on_save=self._on_entry_saved,
        )

    def _build_inspector_domain_items(self, domain_entry: VaultEntry):
        """Renders embedded table of all vault items/services/credentials attached to this domain."""
        child_entries = self.database.get_child_entries_by_domain(domain_entry.id, self.session_key)

        box = ctk.CTkFrame(self.inspector_panel, fg_color=BG_INPUT, corner_radius=8)
        box.pack(fill="x", padx=12, pady=(0, 10))

        header = ctk.CTkFrame(box, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(8, 4))

        ctk.CTkLabel(
            header,
            text=f"ATTACHED VAULT ITEMS ({len(child_entries)})",
            font=get_font(10, "bold"),
            text_color=ACCENT_EMERALD,
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="+ Attach Item",
            font=get_font(10, "bold"),
            width=90,
            height=20,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            command=lambda: self._create_linked_item_for_domain(domain_entry),
        ).pack(side="right")

        if not child_entries:
            ctk.CTkLabel(
                box,
                text="No vault items attached to this domain yet.\nClick '+ Attach Item' to link services, API keys, or servers.",
                font=get_font(11),
                text_color=TEXT_MUTED,
                justify="left",
            ).pack(anchor="w", padx=12, pady=(4, 10))
            return

        table_container = ctk.CTkFrame(box, fg_color="transparent")
        table_container.pack(fill="x", padx=8, pady=(2, 8))

        col_hdr = ctk.CTkFrame(table_container, fg_color="transparent")
        col_hdr.pack(fill="x", pady=(2, 4))
        ctk.CTkLabel(col_hdr, text="Item / Title", font=get_font(10, "bold"), text_color=TEXT_MUTED, width=115, anchor="w").pack(side="left")
        ctk.CTkLabel(col_hdr, text="Type", font=get_font(10, "bold"), text_color=TEXT_MUTED, width=65, anchor="w").pack(side="left")
        ctk.CTkLabel(col_hdr, text="Secret / Role", font=get_font(10, "bold"), text_color=TEXT_MUTED, width=70, anchor="w").pack(side="left")
        ctk.CTkLabel(col_hdr, text="Actions", font=get_font(10, "bold"), text_color=TEXT_MUTED, anchor="e").pack(side="right")

        for child in child_entries:
            row = ctk.CTkFrame(table_container, fg_color=BG_CARD, corner_radius=4)
            row.pack(fill="x", pady=2)

            display_title = child.title
            if len(display_title) > 15:
                display_title = display_title[:13] + ".."
            ctk.CTkLabel(row, text=display_title, font=get_font(11, "bold"), text_color=TEXT_PRIMARY, width=115, anchor="w").pack(side="left", padx=(6, 2), pady=4)

            t_disp = child.entry_type.upper()
            t_color = ACCENT_PRIMARY if child.entry_type == "server" else (COLOR_WARNING if child.entry_type == "service" else (ACCENT_INDIGO if child.entry_type == "apikey" else ACCENT_PURPLE))
            ctk.CTkLabel(row, text=t_disp, font=get_font(9, "bold"), text_color=t_color, width=65, anchor="w").pack(side="left", padx=2)

            sec_disp = "••••••••" if (child.password or child.api_token or child.private_key) else (child.username or "-")
            ctk.CTkLabel(row, text=sec_disp, font=get_mono_font(10), text_color=TEXT_MUTED, width=70, anchor="w").pack(side="left", padx=2)

            act_box = ctk.CTkFrame(row, fg_color="transparent")
            act_box.pack(side="right", padx=4)

            sec_val = child.password or child.api_token or child.private_key
            if sec_val:
                ctk.CTkButton(
                    act_box,
                    text="Pass",
                    width=38,
                    height=22,
                    corner_radius=4,
                    font=get_font(10),
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    command=lambda p=sec_val: self._copy_val(p, "Attached secret copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=1)
            elif child.username:
                ctk.CTkButton(
                    act_box,
                    text="User",
                    width=38,
                    height=22,
                    corner_radius=4,
                    font=get_font(10),
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    command=lambda u=child.username: self._copy_val(u, "Attached username copied"),
                ).pack(side="left", padx=1)

            ctk.CTkButton(
                act_box,
                text="Open",
                width=38,
                height=22,
                corner_radius=4,
                font=get_font(10),
                fg_color=BG_INPUT,
                hover_color=ACCENT_HOVER,
                command=lambda c=child: self._select_entry(c),
            ).pack(side="left", padx=1)

    def _create_linked_item_for_domain(self, domain_entry: VaultEntry):
        """Creates a new vault entry directly attached to this domain."""
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server"]
        domains = [e for e in self.entries if e.entry_type == "domain"]
        new_svc = VaultEntry.create_service(
            title=f"{domain_entry.title} - Service",
            app_name="",
            url=domain_entry.url or domain_entry.domain_name,
        )
        new_svc.parent_domain_id = domain_entry.id
        EntryDialog(
            self,
            entry=new_svc,
            default_type="service",
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            available_domains=domains,
            on_save=self._on_entry_saved,
        )

    def _build_inspector_custom_fields(self, entry: VaultEntry):
        """Displays arbitrary custom Key-Value fields."""
        if not getattr(entry, "custom_fields", None):
            return

        box = ctk.CTkFrame(self.inspector_panel, fg_color=BG_INPUT, corner_radius=8)
        box.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(
            box,
            text=f"CUSTOM FIELDS ({len(entry.custom_fields)})",
            font=get_font(10, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=12, pady=(8, 4))

        for cf in entry.custom_fields:
            if not isinstance(cf, dict):
                continue
            k = cf.get("key", "").strip()
            v = cf.get("value", "").strip()
            if k:
                self._add_inspector_field(box, k, v, copyable=True)

    def _build_inspector_timestamps(self, entry: VaultEntry):
        """Displays Created and Modified UTC timestamps."""
        ts_frame = ctk.CTkFrame(self.inspector_panel, fg_color="transparent")
        ts_frame.pack(fill="x", padx=12, pady=(0, 12))
        c_ts = entry.created_at[:19].replace("T", " ") if entry.created_at else "Unknown"
        m_ts = entry.updated_at[:19].replace("T", " ") if entry.updated_at else "Unknown"
        ctk.CTkLabel(
            ts_frame,
            text=f"Created: {c_ts} UTC  •  Modified: {m_ts} UTC",
            font=get_font(10),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

    def _toggle_favorite(self, entry: VaultEntry):
        new_fav = self.database.toggle_favorite(entry.id)
        entry.is_favorite = new_fav
        self._apply_filters()

    def _open_new_entry_dialog(self):
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server"]
        domains = [e for e in self.entries if e.entry_type == "domain"]
        def_type = "domain" if self.selected_category == "Domains" or self.selected_type_filter in ("🌐 Domains", "🔗 Domains") else "server"
        EntryDialog(
            self,
            default_type=def_type,
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            available_domains=domains,
            on_save=self._on_entry_saved,
        )

    def _edit_entry(self, entry: VaultEntry):
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server" and e.id != entry.id]
        domains = [e for e in self.entries if e.entry_type == "domain" and e.id != entry.id]
        EntryDialog(
            self,
            entry=entry,
            database=self.database,
            session_key=self.session_key,
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            available_domains=domains,
            on_save=self._on_entry_saved,
        )

    def _open_version_history(self, entry: VaultEntry):
        self.autolock_mgr.record_activity()
        VersionHistoryDialog(
            self,
            database=self.database,
            session_key=self.session_key,
            entry=entry,
            clipboard_mgr=self.clipboard_mgr,
            on_restored=self._on_entry_restored,
        )

    def _on_entry_restored(self, restored_entry: VaultEntry):
        self.reload_entries()
        self._select_entry(restored_entry)

    def _on_entry_saved(self, entry: VaultEntry):
        self.database.save_entry(entry, self.session_key)
        self.reload_entries()
        self._select_entry(entry)

    def _delete_entry(self, entry: VaultEntry):
        self.autolock_mgr.record_activity()
        self.database.delete_entry(entry.id)
        self.selected_entry = None
        self.reload_entries()
        self._render_inspector()

    def _open_key_studio(self):
        self.autolock_mgr.record_activity()
        self.nav_var.set("⚡ Crypto Tools")
        self.tab_selector.set("⚡ Crypto Tools")
        self._on_nav_tab_changed("⚡ Crypto Tools")
        if hasattr(self.crypto_tools_view, "switch_to_subtab"):
            self.crypto_tools_view.switch_to_subtab("⚡ Key Generator")

    def _open_local_key_installer(self, preselected: Optional[VaultEntry] = None):
        self.autolock_mgr.record_activity()
        LocalKeyInstallerDialog(
            self,
            database=self.database,
            session_key=self.session_key,
            clipboard_mgr=self.clipboard_mgr,
            preselected_entry=preselected,
            on_vault_updated=self.reload_entries,
        )

    def _open_settings(self):
        self.autolock_mgr.record_activity()
        SettingsDialog(
            self,
            database=self.database,
            current_key=self.session_key,
            on_key_updated=self.update_session_key,
            on_settings_updated=self._on_settings_updated,
        )

    def _on_settings_updated(self, settings: dict):
        if "autolock_timeout" in settings:
            self.autolock_mgr.timeout_seconds = settings["autolock_timeout"]
        if "lock_on_minimize" in settings:
            self.autolock_mgr.lock_on_minimize = settings["lock_on_minimize"]
        if "clipboard_timeout" in settings:
            self.clipboard_mgr.default_timeout_sec = settings["clipboard_timeout"]

    def _open_api_key_studio(self):
        self.autolock_mgr.record_activity()
        ApiKeyStudioDialog(
            self,
            on_use_key=self._on_use_generated_api_key,
        )

    def _on_use_generated_api_key(self, key_str: str, provider: str, key_fmt: str):
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server"]
        domains = [e for e in self.entries if e.entry_type == "domain"]
        new_entry = VaultEntry.create_api_key(
            title=f"{provider} API Key",
            provider=provider,
            api_token=key_str,
            api_key_format=key_fmt,
        )
        EntryDialog(
            self,
            entry=new_entry,
            default_type="apikey",
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            available_domains=domains,
            on_save=self._on_entry_saved,
        )

    def _open_vault_export_dialog(self):
        self.autolock_mgr.record_activity()
        VaultExportDialog(self, database=self.database, session_key=self.session_key)

    def _open_vault_import_dialog(self):
        self.autolock_mgr.record_activity()
        VaultImportDialog(
            self,
            database=self.database,
            session_key=self.session_key,
            on_import_completed=self._on_vault_imported,
        )

    def _on_vault_imported(self):
        self.reload_entries()
        if self.files_view:
            self.files_view.refresh()
        if self.health_view:
            self.health_view.refresh()
        if self.crypto_tools_view:
            self.crypto_tools_view.reload_keyring()

