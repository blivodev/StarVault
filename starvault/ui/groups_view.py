"""Groups View for StarVault.

Provides a unified, convenient listing of all vault items grouped by:
- Categories (Infrastructure, Services, API Keys, Databases, Homelab, etc.)
- Relational Tags (#vps1, #docker, #prod, etc.)
- Parent Hierarchy (VPS / Server -> Child Services)

Enables rapid 1-click copying of:
- Username / ID
- Password / API Key / Private Key (with 30-second clipboard auto-wipe)
- Host / URL
- 2FA / TOTP Live Code
"""

from typing import Callable, Dict, List, Optional
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.totp import generate_totp_code
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


class GroupsView(ctk.CTkFrame):
    """Convenient grouped credential manager with high-speed 1-click copy actions."""

    def __init__(
        self,
        parent,
        database: Database,
        session_key: bytes,
        clipboard_mgr: ClipboardManager,
        on_edit_entry: Optional[Callable[[VaultEntry], None]] = None,
        on_select_entry: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.database = database
        self.session_key = session_key
        self.clipboard_mgr = clipboard_mgr
        self.on_edit_entry = on_edit_entry
        self.on_select_entry = on_select_entry

        self.entries: List[VaultEntry] = []
        self.group_mode = "category"  # 'category', 'tag', 'hierarchy'
        self.search_query = ""
        self.expanded_groups: Dict[str, bool] = {}

        self._build_ui()
        self.reload()

    def update_session_key(self, new_key: bytes) -> None:
        self.session_key = new_key
        self.reload()

    def _build_ui(self) -> None:
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            title_box,
            text="🗂️ Group & Fast-Copy Explorer",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Organize all infrastructure, services, and API keys with instant 1-click copy buttons.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Grouping Mode Segmented Selector
        self.mode_var = ctk.StringVar(value="By Category")
        self.mode_selector = ctk.CTkSegmentedButton(
            header,
            values=["By Category", "By Tag", "By Server Hierarchy"],
            variable=self.mode_var,
            command=self._on_mode_changed,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color="#000000",
            height=34,
        )
        self.mode_selector.pack(side="right", padx=24, pady=15)

        # Filter bar
        filter_bar = ctk.CTkFrame(self, fg_color="transparent", height=42)
        filter_bar.pack(fill="x", padx=24, pady=(12, 6))

        # Search box
        search_box = ctk.CTkFrame(filter_bar, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        search_box.pack(side="left", fill="x", expand=True, padx=(0, 12))

        ctk.CTkLabel(search_box, text="🔍", font=get_font(12), text_color=TEXT_MUTED).pack(side="left", padx=(10, 4))
        self.search_entry = ctk.CTkEntry(
            search_box,
            placeholder_text="Filter items across all groups...",
            font=get_font(12),
            fg_color="transparent",
            border_width=0,
            text_color=TEXT_PRIMARY,
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=4)
        self.search_entry.bind("<KeyRelease>", lambda e: self._on_search_change())

        # Expand / Collapse all buttons
        ctk.CTkButton(
            filter_bar,
            text="▼ Expand All",
            font=get_font(11),
            width=90,
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=lambda: self._set_all_expanded(True),
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            filter_bar,
            text="▲ Collapse All",
            font=get_font(11),
            width=90,
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=lambda: self._set_all_expanded(False),
        ).pack(side="right")

        # Scrollable container for groups
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=24, pady=(4, 16))

    def reload(self) -> None:
        try:
            self.entries = self.database.get_all_entries(self.session_key)
        except Exception:
            self.entries = []
        self._render_groups()

    def _on_mode_changed(self, val: str) -> None:
        if val == "By Category":
            self.group_mode = "category"
        elif val == "By Tag":
            self.group_mode = "tag"
        else:
            self.group_mode = "hierarchy"
        self._render_groups()

    def _on_search_change(self) -> None:
        self.search_query = self.search_entry.get().strip().lower()
        self._render_groups()

    def _set_all_expanded(self, state: bool) -> None:
        for k in self.expanded_groups:
            self.expanded_groups[k] = state
        self._render_groups()

    def _toggle_group(self, group_name: str) -> None:
        self.expanded_groups[group_name] = not self.expanded_groups.get(group_name, True)
        self._render_groups()

    def _get_grouped_data(self) -> Dict[str, List[VaultEntry]]:
        # Filter entries first by search_query
        filtered = []
        for e in self.entries:
            if not self.search_query:
                filtered.append(e)
            else:
                q = self.search_query
                match = (
                    q in e.title.lower()
                    or q in e.category.lower()
                    or q in (e.hostname or "").lower()
                    or q in (e.url or "").lower()
                    or q in e.username.lower()
                    or q in (getattr(e, "provider", "") or "").lower()
                    or any(q in t.lower() for t in e.tags)
                )
                if match:
                    filtered.append(e)

        grouped: Dict[str, List[VaultEntry]] = {}

        if self.group_mode == "category":
            for e in filtered:
                cat = e.category or "General"
                grouped.setdefault(cat, []).append(e)

        elif self.group_mode == "tag":
            untagged = []
            for e in filtered:
                if not e.tags:
                    untagged.append(e)
                else:
                    for t in e.tags:
                        grouped.setdefault(f"#{t.lower()}", []).append(e)
            if untagged:
                grouped["(No Tags)"] = untagged

        elif self.group_mode == "hierarchy":
            # Parent servers
            servers_map = {e.id: e for e in self.entries if e.entry_type == "server"}
            for e in filtered:
                if e.entry_type == "server":
                    grp_name = f"🖥️ Server: {e.title}"
                    grouped.setdefault(grp_name, []).append(e)
                elif e.parent_server_id and e.parent_server_id in servers_map:
                    p = servers_map[e.parent_server_id]
                    grp_name = f"🖥️ Server: {p.title}"
                    grouped.setdefault(grp_name, []).append(e)
                else:
                    grouped.setdefault("Standalone Services & Keys", []).append(e)

        return grouped

    def _render_groups(self) -> None:
        for child in self.scroll_frame.winfo_children():
            child.destroy()

        grouped_data = self._get_grouped_data()

        if not grouped_data:
            empty_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
            empty_frame.pack(pady=60)
            ctk.CTkLabel(
                empty_frame,
                text="No matching credentials or services found.",
                font=get_font(14),
                text_color=TEXT_MUTED,
            ).pack()
            return

        for group_name, items in sorted(grouped_data.items()):
            # Initialize expanded state if not present
            if group_name not in self.expanded_groups:
                self.expanded_groups[group_name] = True

            is_expanded = self.expanded_groups[group_name]
            self._render_group_section(group_name, items, is_expanded)

    def _render_group_section(self, group_name: str, items: List[VaultEntry], is_expanded: bool) -> None:
        # Group Header Container
        header_card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            height=44,
        )
        header_card.pack(fill="x", pady=(8, 2))

        header_btn = ctk.CTkButton(
            header_card,
            text=f"{'▼' if is_expanded else '▶'}  {group_name}  ({len(items)})",
            font=get_font(13, "bold"),
            anchor="w",
            fg_color="transparent",
            hover_color=BG_CARD_HOVER,
            text_color=ACCENT_PRIMARY if is_expanded else TEXT_PRIMARY,
            command=lambda g=group_name: self._toggle_group(g),
            height=42,
        )
        header_btn.pack(fill="x", padx=6, pady=2)

        if not is_expanded:
            return

        # Items Table / Rows Frame
        items_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        items_frame.pack(fill="x", padx=4, pady=(2, 8))

        for entry in items:
            self._render_entry_row(items_frame, entry)

    def _render_entry_row(self, parent, entry: VaultEntry) -> None:
        row = ctk.CTkFrame(
            parent,
            fg_color=BG_INPUT,
            corner_radius=6,
            border_width=1,
            border_color=BORDER_COLOR,
            height=44,
        )
        row.pack(fill="x", pady=2)

        # Type badge
        badge_color = ACCENT_PRIMARY if entry.entry_type == "server" else (
            COLOR_WARNING if entry.entry_type == "service" else (
                ACCENT_INDIGO if entry.entry_type == "apikey" else ACCENT_PURPLE
            )
        )
        badge_text = entry.entry_type.upper()
        if badge_text == "APIKEY":
            badge_text = "API KEY"

        ctk.CTkLabel(
            row,
            text=badge_text,
            font=get_font(9, "bold"),
            text_color=badge_color,
            fg_color=BG_CARD,
            corner_radius=4,
            padx=6,
            pady=2,
            width=65,
        ).pack(side="left", padx=(10, 8), pady=8)

        # Title & Host info
        info_col = ctk.CTkFrame(row, fg_color="transparent")
        info_col.pack(side="left", fill="x", expand=True, padx=4)

        title_row = ctk.CTkFrame(info_col, fg_color="transparent")
        title_row.pack(fill="x")

        ctk.CTkLabel(
            title_row,
            text=entry.title,
            font=get_font(12, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # Details subtitle
        sub_text = entry.hostname or entry.url or entry.provider or (f"port {entry.port}" if entry.port else "")
        if entry.username:
            sub_text = f"{entry.username} @ {sub_text}" if sub_text else entry.username
        if sub_text:
            ctk.CTkLabel(
                info_col,
                text=sub_text,
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(anchor="w")

        # Action Copy Buttons
        btn_box = ctk.CTkFrame(row, fg_color="transparent")
        btn_box.pack(side="right", padx=10, pady=6)

        # 1. Copy Username (if exists)
        if entry.username:
            ctk.CTkButton(
                btn_box,
                text="👤 User",
                font=get_font(11),
                width=65,
                height=28,
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                command=lambda u=entry.username, t=entry.title: self._copy_text(u, f"Username for {t}", is_secret=False),
            ).pack(side="left", padx=3)

        # 2. Copy Password / API Key / Secret (if exists)
        secret_val = entry.password or entry.api_token or entry.private_key
        if secret_val:
            btn_label = "🔑 Key" if entry.entry_type == "apikey" else "🔑 Pass"
            ctk.CTkButton(
                btn_box,
                text=btn_label,
                font=get_font(11, "bold"),
                width=68,
                height=28,
                fg_color=BG_CARD,
                hover_color=ACCENT_PRIMARY,
                text_color=COLOR_SUCCESS,
                command=lambda s=secret_val, t=entry.title: self._copy_text(s, f"Secret for {t}", is_secret=True),
            ).pack(side="left", padx=3)

        # 3. Copy Host / URL (if exists)
        host_val = entry.url or entry.hostname
        if host_val:
            ctk.CTkButton(
                btn_box,
                text="🌐 Host",
                font=get_font(11),
                width=65,
                height=28,
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                command=lambda h=host_val, t=entry.title: self._copy_text(h, f"Host for {t}", is_secret=False),
            ).pack(side="left", padx=3)

        # 4. Copy 2FA TOTP (if exists)
        totp_sec = entry.totp_secret or ""
        if not totp_sec:
            for cf in entry.custom_fields:
                if "totp" in cf.get("key", "").lower() or "2fa" in cf.get("key", "").lower():
                    totp_sec = cf.get("value", "")
                    break

        if totp_sec:
            ctk.CTkButton(
                btn_box,
                text="🔢 2FA",
                font=get_font(11, "bold"),
                width=60,
                height=28,
                fg_color=BG_CARD,
                hover_color=ACCENT_PRIMARY,
                text_color=ACCENT_PRIMARY,
                command=lambda sec=totp_sec, t=entry.title: self._copy_totp(sec, t),
            ).pack(side="left", padx=3)

        # 5. Edit Button
        if self.on_edit_entry:
            ctk.CTkButton(
                btn_box,
                text="✏️",
                font=get_font(11),
                width=32,
                height=28,
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                command=lambda e=entry: self.on_edit_entry(e),
            ).pack(side="left", padx=3)

        # 6. View in Credentials Inspector
        if self.on_select_entry:
            ctk.CTkButton(
                btn_box,
                text="↗️",
                font=get_font(11),
                width=32,
                height=28,
                fg_color=BG_CARD,
                hover_color=ACCENT_HOVER,
                command=lambda eid=entry.id: self.on_select_entry(eid),
            ).pack(side="left", padx=3)

    def _copy_text(self, text: str, description: str, is_secret: bool = False) -> None:
        self.clipboard_mgr.copy(text, label=description, is_sensitive=is_secret)

    def _copy_totp(self, secret: str, title: str) -> None:
        code = generate_totp_code(secret)
        self.clipboard_mgr.copy(code, label=f"2FA Code for {title}", is_sensitive=True)
