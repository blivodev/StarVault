"""Main Dashboard View for StarVault with card list and detail inspector."""

from datetime import datetime, timezone, timedelta
from typing import Callable, List, Optional
import customtkinter as ctk

from starvault.autolock import AutoLockManager
from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.quick_strings import (
    generate_curl_command,
    generate_db_cli_command,
    generate_db_url,
    generate_ssh_command,
)
from starvault.search import search_entries
from starvault.ui.api_key_dialog import ApiKeyStudioDialog
from starvault.ui.crypto_tools_view import CryptoToolsView
from starvault.ui.entry_dialog import EntryDialog
from starvault.ui.files_view import FilesView
from starvault.ui.groups_view import GroupsView
from starvault.ui.health_view import HealthView
from starvault.ui.key_studio import KeyStudioDialog
from starvault.ui.settings_dialog import SettingsDialog
from starvault.ui.totp_view import TotpView
from starvault.ui.theme import (
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
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    get_font,
    get_mono_font,
)


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
        self._revealed_secrets: set = set()
        self._search_job = None
        self._card_widgets = {}
        self._rendered_limit = 35

        self._build_ui()
        self.clipboard_mgr.set_status_callback(self._on_clipboard_status)
        self.reload_entries()
        self._schedule_autolock_ui_update()
        self._setup_hotkeys()

    def update_session_key(self, new_key: bytes):
        self.session_key = new_key
        if hasattr(self, "health_view"):
            self.health_view.encryption_key = new_key
        if hasattr(self, "files_view"):
            self.files_view.encryption_key = new_key
        if hasattr(self, "groups_view"):
            self.groups_view.session_key = new_key
        if hasattr(self, "totp_view"):
            self.totp_view.session_key = new_key

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
        center_container = ctk.CTkFrame(self.body_frame, fg_color=BG_ROOT)
        center_container.pack(side="left", fill="both", expand=True)

        # Filter bar header
        self.filter_header = ctk.CTkFrame(center_container, fg_color="transparent", height=36)
        self.filter_header.pack(fill="x", padx=16, pady=(12, 4))

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

        # Sort Dropdown in header
        sort_frame = ctk.CTkFrame(self.filter_header, fg_color="transparent")
        sort_frame.pack(side="right", padx=(0, 4))
        ctk.CTkLabel(sort_frame, text="Sort:", font=get_font(11), text_color=TEXT_MUTED).pack(side="left", padx=(0, 6))
        self.dashboard_sort_combo = ctk.CTkComboBox(
            sort_frame,
            values=["Title (A-Z)", "Title (Z-A)", "Category", "Risk (Highest)", "Recently Modified", "Type"],
            width=160,
            height=28,
            font=get_font(11),
            command=lambda v: self._apply_filters(),
        )
        self.dashboard_sort_combo.set("Title (A-Z)")
        self.dashboard_sort_combo.pack(side="left")

        # Scrollable Cards Area
        self.cards_scroll = ctk.CTkScrollableFrame(center_container, fg_color=BG_ROOT)
        self.cards_scroll.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # 3. Vault Views (Health, Files, Groups, 2FA/QR - hidden by default)
        self.health_view = HealthView(
            self,
            database=self.database,
            encryption_key=self.session_key,
            on_review_entry=self.switch_to_credentials_tab,
            on_vault_updated=self.reload_entries,
        )
        self.files_view = FilesView(
            self,
            database=self.database,
            encryption_key=self.session_key,
        )
        self.groups_view = GroupsView(
            self,
            database=self.database,
            session_key=self.session_key,
            clipboard_mgr=self.clipboard_mgr,
            on_select_entry=self.switch_to_credentials_tab,
        )
        self.totp_view = TotpView(
            self,
            database=self.database,
            session_key=self.session_key,
            clipboard_mgr=self.clipboard_mgr,
        )
        self.crypto_tools_view = CryptoToolsView(
            self,
            clipboard_mgr=self.clipboard_mgr,
        )

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
            values=["Credentials", "🗂️ Groups", "📱 2FA / QR", "🛡️ Vault Health", "📁 File Vault", "⚡ Crypto Tools"],
            variable=self.nav_var,
            command=self._on_nav_tab_changed,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color="#000000",
            height=34,
        )
        self.tab_selector.pack(side="left", padx=10, pady=14)

        # Central Fuzzy Search Bar
        self.search_container = ctk.CTkFrame(top_bar, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR, width=340, height=38)
        self.search_container.pack(side="left", fill="x", expand=True, padx=(10, 16), pady=12)

        ctk.CTkLabel(self.search_container, text="🔍", font=get_font(12), text_color=TEXT_MUTED).pack(side="left", padx=(10, 4))

        self.search_entry = ctk.CTkEntry(
            self.search_container,
            placeholder_text="Fuzzy search credentials or tags (e.g. 'VPS1', 'postgres', 'docker')...",
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
            text="⏱️ 5:00",
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
            text_color="#000000",
            height=34,
            command=self._open_new_entry_dialog,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions_frame,
            text="⚡ API Keys",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            command=self._open_api_key_studio,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions_frame,
            text="🔑 Key Studio",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            command=self._open_key_studio,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions_frame,
            text="⚙️",
            width=36,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self._open_settings,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            actions_frame,
            text="🔒 Lock",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            text_color=COLOR_DANGER,
            height=34,
            command=self.on_lock_requested,
        ).pack(side="left", padx=(4, 0))

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
            ("All", "🌐 All Entries"),
            ("Favorites", "⭐ Favorites"),
            ("API Keys", "⚡ API Keys"),
            ("Servers", "🖥️ Servers & VPS"),
            ("Services", "⚙️ Services & DBs"),
            ("Keys", "🔑 SSH & GPG Keys"),
        ]

        for cat_key, cat_label in categories:
            btn = ctk.CTkButton(
                self.sidebar,
                text=cat_label,
                font=get_font(12),
                anchor="w",
                height=34,
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
        self.nav_var.set("🛡️ Vault Health")
        self.tab_selector.set("🛡️ Vault Health")
        self._on_nav_tab_changed("🛡️ Vault Health")

    def _on_search_query_change(self):
        self.autolock_mgr.record_activity()
        if self._search_job is not None:
            self.after_cancel(self._search_job)
        self._search_job = self.after(150, self._apply_filters)

    def _apply_filters(self):
        query = self.search_entry.get().strip()
        scored = search_entries(
            self.entries,
            query=query,
            selected_category=self.selected_category,
            selected_tag=self.selected_tag,
        )
        self.filtered_entries = [e for e, score in scored]

        # Apply active sort if not searching with high-relevance query
        if not query and hasattr(self, "dashboard_sort_combo"):
            from starvault.organizer import sort_entries
            choice = self.dashboard_sort_combo.get()
            mapping = {
                "Category": "category",
                "Title (A-Z)": "title_asc",
                "Title (Z-A)": "title_desc",
                "Risk (Highest)": "risk",
                "Recently Modified": "recency",
                "Type": "type",
            }
            strat = mapping.get(choice, "title_asc")
            self.filtered_entries = sort_entries(self.filtered_entries, sort_by=strat)

        self.count_badge.configure(text=f"{len(self.filtered_entries)} items")
        self._render_cards()

    def _render_cards(self):
        self._card_widgets.clear()
        for child in self.cards_scroll.winfo_children():
            child.destroy()

        if not self.filtered_entries:
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

        to_render = self.filtered_entries[:self._rendered_limit]
        for entry in to_render:
            self._render_entry_card(entry)

        if len(self.filtered_entries) > self._rendered_limit:
            remaining = len(self.filtered_entries) - self._rendered_limit
            btn_more = ctk.CTkButton(
                self.cards_scroll,
                text=f"Show remaining {remaining} entries...",
                font=get_font(11, "bold"),
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                text_color=ACCENT_PRIMARY,
                height=32,
                command=self._show_all_cards,
            )
            btn_more.pack(fill="x", padx=10, pady=8)

    def _show_all_cards(self):
        self._rendered_limit = len(self.filtered_entries)
        self._render_cards()

    def _render_entry_card(self, entry: VaultEntry):
        is_selected = self.selected_entry and self.selected_entry.id == entry.id
        card_bg = BG_CARD_HOVER if is_selected else BG_CARD

        card = ctk.CTkFrame(
            self.cards_scroll,
            fg_color=card_bg,
            corner_radius=10,
            border_width=1,
            border_color=ACCENT_PRIMARY if is_selected else BORDER_COLOR,
        )
        card.pack(fill="x", pady=4, padx=4)
        self._card_widgets[entry.id] = card

        # Click card to select & show in inspector
        card.bind("<Button-1>", lambda e, ent=entry: self._select_entry(ent))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=10)
        inner.bind("<Button-1>", lambda e, ent=entry: self._select_entry(ent))

        # Top row: Star Fav + Type Badge + Title + Tags
        top_row = ctk.CTkFrame(inner, fg_color="transparent")
        top_row.pack(fill="x")
        top_row.bind("<Button-1>", lambda e, ent=entry: self._select_entry(ent))

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
        title_lbl.bind("<Button-1>", lambda e, ent=entry: self._select_entry(ent))

        # Tag chips
        for tag in entry.tags[:4]:
            ctk.CTkLabel(
                top_row,
                text=f"#{tag}",
                font=get_font(10),
                text_color=TEXT_MUTED,
                fg_color=BG_INPUT,
                corner_radius=4,
                padx=5,
                pady=1,
            ).pack(side="left", padx=3)

        # Middle row: Subtitle Info Preview
        mid_row = ctk.CTkFrame(inner, fg_color="transparent")
        mid_row.pack(fill="x", pady=(4, 6))
        mid_row.bind("<Button-1>", lambda e, ent=entry: self._select_entry(ent))

        preview_str = ""
        if entry.entry_type == "server":
            preview_str = f"🖥️ {entry.username}@{entry.hostname}:{entry.port}"
            if entry.os_distro:
                preview_str += f" ({entry.os_distro})"
        elif entry.entry_type == "service":
            preview_str = f"⚙️ {entry.app_name} • {entry.url or entry.hostname}"
            if entry.port:
                preview_str += f":{entry.port}"
        elif entry.entry_type == "apikey":
            env_str = entry.environment or "Production"
            preview_str = f"⚡ {entry.provider or 'API Key'} • Env: {env_str} • Format: {entry.api_key_format or 'Standard'}"
            if entry.expires_at:
                preview_str += f" • Exp: {entry.expires_at[:10]}"
        elif entry.entry_type == "keypair":
            preview_str = f"🔑 {entry.key_type.upper()} • Fingerprint: {entry.fingerprint[:28]}..."

        sub_lbl = ctk.CTkLabel(
            mid_row,
            text=preview_str,
            font=get_mono_font(11),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        sub_lbl.pack(fill="x")
        sub_lbl.bind("<Button-1>", lambda e, ent=entry: self._select_entry(ent))

        # Bottom row: One-Click Quick-Copy Action Buttons right on card!
        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(fill="x")

        if entry.entry_type == "server":
            if entry.hostname:
                ctk.CTkButton(
                    btn_row,
                    text="📋 Copy IP",
                    width=75,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.hostname, "IP address copied"),
                ).pack(side="left", padx=(0, 4))

            ctk.CTkButton(
                btn_row,
                text="⚡ Copy SSH",
                width=85,
                height=26,
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                font=get_font(11, "bold"),
                text_color=ACCENT_PRIMARY,
                command=lambda e=entry: self._copy_val(generate_ssh_command(e), "SSH command copied"),
            ).pack(side="left", padx=4)

            if entry.password:
                ctk.CTkButton(
                    btn_row,
                    text="🔑 Copy Pass",
                    width=85,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)

        elif entry.entry_type == "service":
            if entry.url or entry.hostname:
                ctk.CTkButton(
                    btn_row,
                    text="🌐 Copy URL",
                    width=85,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.url or e.hostname, "URL copied"),
                ).pack(side="left", padx=(0, 4))

            if "postgres" in (entry.service_type or "") or "mysql" in (entry.service_type or "") or "redis" in (entry.service_type or ""):
                ctk.CTkButton(
                    btn_row,
                    text="🗄️ Copy DB URL",
                    width=100,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(generate_db_url(e), "DB URL copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)

            if entry.api_token:
                ctk.CTkButton(
                    btn_row,
                    text="🎟️ Copy Token",
                    width=90,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_SUCCESS,
                    command=lambda e=entry: self._copy_val(e.api_token, "API token copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)
            elif entry.password:
                ctk.CTkButton(
                    btn_row,
                    text="🔑 Copy Pass",
                    width=85,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)

        elif entry.entry_type == "apikey":
            if entry.api_token:
                ctk.CTkButton(
                    btn_row,
                    text="⚡ Copy Key",
                    width=90,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=ACCENT_INDIGO,
                    command=lambda e=entry: self._copy_val(e.api_token, "API key copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=(0, 4))
            if entry.api_key_secret:
                ctk.CTkButton(
                    btn_row,
                    text="🔐 Copy Secret",
                    width=95,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.api_key_secret, "API secret copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)
            if entry.totp_secret:
                from starvault.totp import generate_totp
                ctk.CTkButton(
                    btn_row,
                    text="📱 2FA",
                    width=65,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_SUCCESS,
                    command=lambda e=entry: self._copy_val(generate_totp(e.totp_secret), "2FA code copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)

        elif entry.entry_type == "keypair":
            if entry.public_key:
                ctk.CTkButton(
                    btn_row,
                    text="📋 Copy PubKey",
                    width=95,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.public_key, "Public key copied"),
                ).pack(side="left", padx=(0, 4))

            if entry.private_key:
                ctk.CTkButton(
                    btn_row,
                    text="🔐 Copy PrivKey",
                    width=100,
                    height=26,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_DANGER,
                    command=lambda e=entry: self._copy_val(e.private_key, "Private key copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=4)

    def _select_entry(self, entry: VaultEntry):
        prev_entry = self.selected_entry
        self.selected_entry = entry
        self.autolock_mgr.record_activity()

        if prev_entry and prev_entry.id in self._card_widgets:
            try:
                card_w = self._card_widgets[prev_entry.id]
                card_w.configure(fg_color=BG_CARD, border_color=BORDER_COLOR)
            except Exception:
                pass

        if entry.id in self._card_widgets:
            try:
                card_w = self._card_widgets[entry.id]
                card_w.configure(fg_color=BG_CARD_HOVER, border_color=ACCENT_PRIMARY)
            except Exception:
                pass

        self._render_inspector()

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
            text="🗑️",
            width=32,
            height=30,
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            command=lambda: self._delete_entry(entry),
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            top_bar,
            text="📄 Clone",
            width=65,
            height=30,
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._duplicate_entry(entry),
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            top_bar,
            text="✏️ Edit",
            width=65,
            height=30,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._edit_entry(entry),
        ).pack(side="right")

        # Category & Tags
        meta_row = ctk.CTkFrame(self.inspector_panel, fg_color="transparent")
        meta_row.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(
            meta_row,
            text=f"{entry.category} • {entry.entry_type.upper()}",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(side="left")

        # Details Box
        self._build_inspector_details(entry)

        # Embedded Sub-Credentials Table for Servers
        if entry.entry_type == "server":
            self._build_inspector_subcredentials(entry)

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
            text="📋 Copy Notes",
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
        # Hide all content frames
        self.body_frame.pack_forget()
        self.groups_view.pack_forget()
        self.totp_view.pack_forget()
        self.health_view.pack_forget()
        self.files_view.pack_forget()
        self.crypto_tools_view.pack_forget()
        self.search_container.pack_forget()

        if tab_name == "Credentials":
            self.body_frame.pack(fill="both", expand=True)
            self.search_container.pack(side="left", fill="x", expand=True, padx=(10, 16), pady=12)
        elif tab_name == "🗂️ Groups":
            self.groups_view.pack(fill="both", expand=True)
            self.groups_view.refresh()
        elif tab_name == "📱 2FA / QR":
            self.totp_view.pack(fill="both", expand=True)
            self.totp_view.refresh()
        elif tab_name == "🛡️ Vault Health":
            self.health_view.pack(fill="both", expand=True)
            self.health_view.refresh()
        elif tab_name == "📁 File Vault":
            self.files_view.pack(fill="both", expand=True)
            self.files_view.refresh()
        elif tab_name == "⚡ Crypto Tools":
            self.crypto_tools_view.pack(fill="both", expand=True)

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
                    text="👤",
                    width=24,
                    height=24,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    command=lambda u=child.username: self._copy_val(u, "Sub-credential username copied"),
                ).pack(side="left", padx=1)

            if child.password:
                ctk.CTkButton(
                    act_box,
                    text="🔑",
                    width=24,
                    height=24,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    command=lambda p=child.password: self._copy_val(p, "Sub-credential password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=1)

            ctk.CTkButton(
                act_box,
                text="↗️",
                width=24,
                height=24,
                fg_color=BG_INPUT,
                hover_color=ACCENT_HOVER,
                command=lambda c=child: self._select_entry(c),
            ).pack(side="left", padx=1)

    def _create_linked_service_for(self, server_entry: VaultEntry):
        """Creates a new child service entry directly pre-linked to the parent server."""
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server"]
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
        EntryDialog(
            self,
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            on_save=self._on_entry_saved,
        )

    def _edit_entry(self, entry: VaultEntry):
        self.autolock_mgr.record_activity()
        servers = [e for e in self.entries if e.entry_type == "server" and e.id != entry.id]
        EntryDialog(
            self,
            entry=entry,
            existing_tags=self.database.get_all_tags(),
            available_servers=servers,
            on_save=self._on_entry_saved,
        )

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
        KeyStudioDialog(
            self,
            clipboard_mgr=self.clipboard_mgr,
            on_save_to_vault=self._on_entry_saved,
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
            on_save=self._on_entry_saved,
        )
