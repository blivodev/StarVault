"""Minimalist fast-search HUD for instant credential lookup from system tray."""

from typing import Callable, List, Optional
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.models import VaultEntry
from starvault.quick_strings import generate_db_url, generate_ssh_command
from starvault.search import search_entries
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
    BORDER_COLOR,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    get_font,
    get_mono_font,
)


class QuickSearchHUD(ctk.CTkToplevel):
    """Floating spotlight-style search HUD window."""

    def __init__(
        self,
        parent,
        clipboard_mgr: ClipboardManager,
        get_entries_func: Callable[[], List[VaultEntry]],
        on_open_full_vault: Optional[Callable[[], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.clipboard_mgr = clipboard_mgr
        self.get_entries_func = get_entries_func
        self.on_open_full_vault = on_open_full_vault

        self.title("StarVault HUD - Quick Search")
        self.geometry("740x520")
        self.configure(fg_color=BG_ROOT)

        # Remove window borders for true floating HUD experience on Windows, or keep clean titlebar
        self.overrideredirect(False)
        self._center_window(740, 520)

        self.selected_index = 0
        self.current_results: List[VaultEntry] = []

        self._build_ui()
        self.bind("<Escape>", lambda e: self.hide_hud())
        self.bind("<Down>", self._on_arrow_down)
        self.bind("<Up>", self._on_arrow_up)
        self.bind("<Return>", self._on_enter_press)

    def _center_window(self, width: int, height: int):
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = (screen_w - width) // 2
        y = int((screen_h - height) * 0.3)  # Position in upper third
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        # Top search container
        search_card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12, border_width=1, border_color=BORDER_COLOR)
        search_card.pack(fill="x", padx=16, pady=(16, 8))

        search_row = ctk.CTkFrame(search_card, fg_color="transparent")
        search_row.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            search_row,
            text="🔍",
            font=get_font(18),
            text_color=ACCENT_PRIMARY,
        ).pack(side="left", padx=(0, 10))

        self.search_entry = ctk.CTkEntry(
            search_row,
            font=get_font(15),
            height=42,
            placeholder_text="Fuzzy search servers, services, or tags (e.g. 'vps1', 'db', 'root')...",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", self._on_search_change)

        # Close / Full window button
        ctk.CTkButton(
            search_row,
            text="🖥️ Full Vault",
            width=90,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self._open_full_window,
        ).pack(side="right")

        # Feedback toast pill
        self.toast_label = ctk.CTkLabel(
            self,
            text="",
            font=get_font(11, "bold"),
            text_color=COLOR_SUCCESS,
        )
        self.toast_label.pack(pady=(0, 4))

        # Results scrollable list
        self.results_scroll = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        self.results_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def show_hud(self):
        """Displays and focuses the HUD window."""
        self.deiconify()
        self.lift()
        self.focus_force()
        self.search_entry.focus_set()
        self.search_entry.select_range(0, "end")
        self._refresh_results()

    def hide_hud(self):
        """Hides HUD back to tray."""
        self.withdraw()

    def _open_full_window(self):
        self.hide_hud()
        if self.on_open_full_vault:
            self.on_open_full_vault()

    def _on_search_change(self, event=None):
        self._refresh_results()

    def _refresh_results(self):
        query = self.search_entry.get()
        entries = self.get_entries_func()

        scored = search_entries(entries, query, selected_category="All")
        self.current_results = [e for e, score in scored[:30]]  # Top 30

        # Clear scroll area
        for child in self.results_scroll.winfo_children():
            child.destroy()

        if not self.current_results:
            empty_lbl = ctk.CTkLabel(
                self.results_scroll,
                text="No matching credentials or services found.",
                font=get_font(13),
                text_color=TEXT_MUTED,
            )
            empty_lbl.pack(pady=40)
            return

        for idx, entry in enumerate(self.current_results):
            self._render_result_row(idx, entry)

    def _render_result_row(self, idx: int, entry: VaultEntry):
        is_selected = idx == self.selected_index
        card_bg = BG_CARD_HOVER if is_selected else BG_CARD

        row = ctk.CTkFrame(
            self.results_scroll,
            fg_color=card_bg,
            corner_radius=8,
            border_width=1,
            border_color=ACCENT_PRIMARY if is_selected else BORDER_COLOR,
            height=60,
        )
        row.pack(fill="x", pady=3, padx=2)

        # Left: Type badge & Info
        info_col = ctk.CTkFrame(row, fg_color="transparent")
        info_col.pack(side="left", fill="both", expand=True, padx=10, pady=8)

        top_line = ctk.CTkFrame(info_col, fg_color="transparent")
        top_line.pack(fill="x")

        # Type badge
        if entry.entry_type == "domain":
            badge_color = ACCENT_EMERALD
            badge_text = "DOMAIN"
        elif entry.entry_type == "server":
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
            top_line,
            text=badge_text,
            font=get_font(9, "bold"),
            text_color=badge_color,
            fg_color=BG_INPUT,
            corner_radius=4,
            padx=6,
            pady=1,
        ).pack(side="left", padx=(0, 8))

        # Title
        ctk.CTkLabel(
            top_line,
            text=entry.title,
            font=get_font(13, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # Tags
        if entry.tags:
            tags_text = " ".join(f"#{t}" for t in entry.tags[:3])
            ctk.CTkLabel(
                top_line,
                text=tags_text,
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(side="left", padx=10)

        # Subtitle (Host/URL/User)
        sub_text = ""
        if entry.entry_type == "domain":
            sub_text = getattr(entry, "domain_name", "") or entry.url or ""
            if getattr(entry, "registrar", ""):
                sub_text = f"{sub_text} • Registrar: {entry.registrar}" if sub_text else f"Registrar: {entry.registrar}"
            if getattr(entry, "expires_at", ""):
                sub_text = f"{sub_text} • Exp: {entry.expires_at}"
            if entry.username:
                sub_text = f"{entry.username} @ {sub_text}" if sub_text else entry.username
        elif entry.entry_type == "server":
            sub_text = f"{entry.username}@{entry.hostname}:{entry.port}"
        elif entry.entry_type == "service":
            sub_text = f"{entry.app_name} • {entry.url or entry.hostname}"
            if entry.port:
                sub_text += f":{entry.port}"
        elif entry.entry_type == "apikey":
            sub_text = f"{entry.provider or 'API Key'} • {entry.key_name or ''}"
            if entry.expires_at:
                sub_text += f" • Exp: {entry.expires_at}"
        elif entry.entry_type == "keypair":
            sub_text = f"{entry.key_type.upper()} • {entry.fingerprint[:24]}..."

        ctk.CTkLabel(
            info_col,
            text=sub_text,
            font=get_mono_font(11),
            text_color=TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        # Right: One-Click Quick-Copy Action Buttons
        btn_col = ctk.CTkFrame(row, fg_color="transparent")
        btn_col.pack(side="right", padx=10, pady=8)

        if entry.entry_type == "domain":
            dom_val = getattr(entry, "domain_name", "") or entry.url
            if dom_val:
                ctk.CTkButton(
                    btn_col,
                    text="🌐 Domain",
                    width=70,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(getattr(e, "domain_name", "") or e.url, "Domain URL copied"),
                ).pack(side="left", padx=2)

            if getattr(entry, "username", ""):
                ctk.CTkButton(
                    btn_col,
                    text="👤 User",
                    width=60,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.username, "Username copied"),
                ).pack(side="left", padx=2)

            if getattr(entry, "password", ""):
                ctk.CTkButton(
                    btn_col,
                    text="🔑 Pass",
                    width=60,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

            if getattr(entry, "registrar", ""):
                ctk.CTkButton(
                    btn_col,
                    text="🏢 Reg",
                    width=60,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.registrar, "Registrar copied"),
                ).pack(side="left", padx=2)

            if getattr(entry, "auth_code", ""):
                ctk.CTkButton(
                    btn_col,
                    text="🔐 EPP",
                    width=60,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.auth_code, "Auth / EPP code copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

        elif entry.entry_type == "server":
            if entry.hostname:
                ctk.CTkButton(
                    btn_col,
                    text="📋 IP",
                    width=60,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.hostname, "IP address copied"),
                ).pack(side="left", padx=2)

            ctk.CTkButton(
                btn_col,
                text="⚡ SSH",
                width=65,
                height=28,
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                font=get_font(11, "bold"),
                text_color=ACCENT_PRIMARY,
                command=lambda e=entry: self._copy_val(generate_ssh_command(e), "SSH command copied"),
            ).pack(side="left", padx=2)

            if entry.password:
                ctk.CTkButton(
                    btn_col,
                    text="🔑 Pass",
                    width=65,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

        elif entry.entry_type == "service":
            if entry.url or entry.hostname:
                ctk.CTkButton(
                    btn_col,
                    text="🌐 URL",
                    width=65,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.url or e.hostname, "URL copied"),
                ).pack(side="left", padx=2)

            if "postgres" in (entry.service_type or "") or "mysql" in (entry.service_type or "") or "redis" in (entry.service_type or ""):
                ctk.CTkButton(
                    btn_col,
                    text="🗄️ DB URL",
                    width=75,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11, "bold"),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(generate_db_url(e), "DB URL copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

            if entry.api_token:
                ctk.CTkButton(
                    btn_col,
                    text="🎟️ Token",
                    width=65,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_SUCCESS,
                    command=lambda e=entry: self._copy_val(e.api_token, "API token copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

            elif entry.password:
                ctk.CTkButton(
                    btn_col,
                    text="🔑 Pass",
                    width=65,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_WARNING,
                    command=lambda e=entry: self._copy_val(e.password, "Password copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

        elif entry.entry_type == "keypair":
            if entry.public_key:
                ctk.CTkButton(
                    btn_col,
                    text="📋 PubKey",
                    width=75,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    command=lambda e=entry: self._copy_val(e.public_key, "Public key copied"),
                ).pack(side="left", padx=2)

            if entry.private_key:
                ctk.CTkButton(
                    btn_col,
                    text="🔐 PrivKey",
                    width=75,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    font=get_font(11),
                    text_color=COLOR_DANGER,
                    command=lambda e=entry: self._copy_val(e.private_key, "Private key copied (30s wipe)", is_sensitive=True),
                ).pack(side="left", padx=2)

    def _copy_val(self, val: str, label: str, is_sensitive: bool = False):
        self.clipboard_mgr.copy(val, label=label, is_sensitive=is_sensitive)
        self.toast_label.configure(text=f"✓ {label}")
        # Automatically clear toast after 3s
        self.after(3000, lambda: self.toast_label.configure(text=""))

    def _on_arrow_down(self, event):
        if self.current_results:
            self.selected_index = min(len(self.current_results) - 1, self.selected_index + 1)
            self._refresh_results()

    def _on_arrow_up(self, event):
        if self.current_results:
            self.selected_index = max(0, self.selected_index - 1)
            self._refresh_results()

    def _on_enter_press(self, event):
        if self.current_results and 0 <= self.selected_index < len(self.current_results):
            entry = self.current_results[self.selected_index]
            # Copy primary item
            if entry.entry_type == "domain":
                self._copy_val(getattr(entry, "domain_name", "") or entry.url, "Domain URL copied")
            elif entry.entry_type == "server":
                self._copy_val(generate_ssh_command(entry), "SSH command copied")
            elif entry.entry_type == "service":
                if entry.password:
                    self._copy_val(entry.password, "Password copied", is_sensitive=True)
                elif entry.api_token:
                    self._copy_val(entry.api_token, "API token copied", is_sensitive=True)
                else:
                    self._copy_val(entry.url, "URL copied")
            elif entry.entry_type == "apikey":
                self._copy_val(entry.api_token or entry.password, "API Key copied", is_sensitive=True)
            elif entry.entry_type == "keypair":
                self._copy_val(entry.public_key, "Public key copied")
