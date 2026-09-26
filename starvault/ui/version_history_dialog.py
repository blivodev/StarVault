"""Version History and Credential Rollback Dialog for StarVault."""

from datetime import datetime
import json
import os
from pathlib import Path
from tkinter import messagebox
from typing import Any, Callable, Dict, List, Optional
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_INPUT,
    BG_ROOT,
    BG_SUBTLE,
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
from starvault.versioning import VaultEntryVersion


class VersionHistoryDialog(ctk.CTkToplevel):
    """Modal dialog displaying credential version history, comparison, and rollback."""

    def __init__(
        self,
        parent,
        database: Database,
        session_key: bytes,
        entry: VaultEntry,
        clipboard_mgr: Optional[ClipboardManager] = None,
        on_restored: Optional[Callable[[VaultEntry], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.database = database
        self.session_key = session_key
        self.entry = entry
        self.clipboard_mgr = clipboard_mgr
        self.on_restored = on_restored

        self.title(f"StarVault - Version History: {entry.title}")
        self.geometry("900x720")
        self.minsize(820, 620)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        self.versions: List[VaultEntryVersion] = []
        self.selected_version: Optional[VaultEntryVersion] = None
        self._revealed_fields = set()

        self._build_ui()
        self._load_versions()

    def _build_ui(self) -> None:
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            title_box,
            text=f"🕒 Version History — {self.entry.title}",
            font=get_font(16, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text=f"Type: {self.entry.entry_type.upper()}  •  Category: {self.entry.category}  •  ID: {self.entry.id[:8]}",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        self.version_count_lbl = ctk.CTkLabel(
            header,
            text="Loading versions...",
            font=get_font(12, "bold"),
            text_color=ACCENT_PRIMARY,
        )
        self.version_count_lbl.pack(side="right", padx=24, pady=16)

        # Main split container: Left = version list, Right = version detail & diff
        self.split_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.split_frame.pack(fill="both", expand=True, padx=16, pady=12)

        # Left Column: Versions List
        self.left_col = ctk.CTkFrame(self.split_frame, fg_color=BG_CARD, width=320, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        self.left_col.pack(side="left", fill="y", padx=(0, 8))
        self.left_col.pack_propagate(False)

        list_hdr = ctk.CTkFrame(self.left_col, fg_color="transparent", height=38)
        list_hdr.pack(fill="x", padx=12, pady=(10, 6))
        ctk.CTkLabel(
            list_hdr,
            text="SNAPSHOT TIMELINE",
            font=get_font(11, "bold"),
            text_color=TEXT_SECONDARY,
        ).pack(side="left")

        self.ver_scroll = ctk.CTkScrollableFrame(self.left_col, fg_color="transparent")
        self.ver_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Right Column: Details & Diff
        self.right_col = ctk.CTkFrame(self.split_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        self.right_col.pack(side="right", fill="both", expand=True)

        self.detail_scroll = ctk.CTkScrollableFrame(self.right_col, fg_color="transparent")
        self.detail_scroll.pack(fill="both", expand=True, padx=16, pady=12)

        # Bottom Action Bar
        bottom_bar = ctk.CTkFrame(self, fg_color=BG_CARD, height=54, corner_radius=0)
        bottom_bar.pack(fill="x", side="bottom")

        self.status_lbl = ctk.CTkLabel(
            bottom_bar,
            text="",
            font=get_font(12),
            text_color=COLOR_SUCCESS,
        )
        self.status_lbl.pack(side="left", padx=24, pady=12)

        ctk.CTkButton(
            bottom_bar,
            text="Close",
            width=100,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self.destroy,
        ).pack(side="right", padx=24, pady=10)

    def _load_versions(self) -> None:
        self.versions = self.database.get_entry_versions(self.entry.id, key=self.session_key, decrypt=True)
        self.version_count_lbl.configure(text=f"{len(self.versions)} Version(s) Recorded")
        self._render_version_list()

    def _render_version_list(self) -> None:
        for child in self.ver_scroll.winfo_children():
            child.destroy()

        if not self.versions:
            ctk.CTkLabel(
                self.ver_scroll,
                text="No historical versions recorded yet.\nEdits to secrets will automatically create snapshots.",
                font=get_font(11),
                text_color=TEXT_MUTED,
                justify="center",
            ).pack(pady=40, padx=10)
            self._render_empty_detail()
            return

        for idx, ver in enumerate(self.versions):
            is_selected = (self.selected_version and self.selected_version.id == ver.id) or (self.selected_version is None and idx == 0)
            if self.selected_version is None and idx == 0:
                self.selected_version = ver

            card_bg = BG_INPUT if is_selected else BG_SUBTLE
            b_color = ACCENT_PRIMARY if is_selected else BORDER_COLOR

            card = ctk.CTkFrame(
                self.ver_scroll,
                fg_color=card_bg,
                corner_radius=6,
                border_width=1,
                border_color=b_color,
            )
            card.pack(fill="x", pady=4, padx=4)

            # Top row: v# badge and date
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=8, pady=(8, 2))

            v_badge_color = ACCENT_PRIMARY if idx == 0 else ACCENT_INDIGO
            ctk.CTkLabel(
                top,
                text=f"v{ver.version_num}" + (" (Latest)" if idx == 0 else ""),
                font=get_font(11, "bold"),
                text_color="#000000" if idx == 0 else "#ffffff",
                fg_color=v_badge_color,
                corner_radius=4,
                padx=6,
                pady=2,
            ).pack(side="left")

            created_fmt = ver.created_at[:19].replace("T", " ") if ver.created_at else "Unknown"
            ctk.CTkLabel(
                top,
                text=created_fmt,
                font=get_font(10),
                text_color=TEXT_MUTED,
            ).pack(side="right")

            # Middle: change summary
            ctk.CTkLabel(
                card,
                text=ver.change_summary or "Configuration snapshot",
                font=get_font(11),
                text_color=TEXT_PRIMARY if is_selected else TEXT_SECONDARY,
                anchor="w",
                justify="left",
                wraplength=270,
            ).pack(fill="x", padx=8, pady=(2, 4))

            # Bottom info row (files count if any)
            if ver.associated_files:
                f_row = ctk.CTkFrame(card, fg_color="transparent")
                f_row.pack(fill="x", padx=8, pady=(0, 6))
                ctk.CTkLabel(
                    f_row,
                    text=f"📁 {len(ver.associated_files)} key file(s) linked",
                    font=get_font(10),
                    text_color=COLOR_WARNING,
                ).pack(side="left")
            else:
                card.pack_configure(pady=(2, 4))

            # Make card clickable
            self._bind_click_recursive(card, ver)

        if self.selected_version:
            self._render_version_detail(self.selected_version)

    def _bind_click_recursive(self, widget, ver: VaultEntryVersion) -> None:
        widget.bind("<Button-1>", lambda e, v=ver: self._on_select_version(v))
        for child in widget.winfo_children():
            self._bind_click_recursive(child, ver)

    def _on_select_version(self, ver: VaultEntryVersion) -> None:
        self.selected_version = ver
        self._revealed_fields.clear()
        self._render_version_list()

    def _render_empty_detail(self) -> None:
        for child in self.detail_scroll.winfo_children():
            child.destroy()
        ctk.CTkLabel(
            self.detail_scroll,
            text="Select a version from the timeline to view snapshot details and rollback options.",
            font=get_font(12),
            text_color=TEXT_MUTED,
        ).pack(pady=60)

    def _render_version_detail(self, ver: VaultEntryVersion) -> None:
        for child in self.detail_scroll.winfo_children():
            child.destroy()

        data = ver.get_decrypted_data(self.session_key)

        # Version Header Box
        hdr_box = ctk.CTkFrame(self.detail_scroll, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        hdr_box.pack(fill="x", pady=(0, 12))

        hb_top = ctk.CTkFrame(hdr_box, fg_color="transparent")
        hb_top.pack(fill="x", padx=14, pady=(12, 4))

        ctk.CTkLabel(
            hb_top,
            text=f"Version {ver.version_num} Snapshot Details",
            font=get_font(15, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkLabel(
            hb_top,
            text=ver.created_at[:19].replace("T", " ") + " UTC",
            font=get_mono_font(11),
            text_color=TEXT_MUTED,
        ).pack(side="right")

        ctk.CTkLabel(
            hdr_box,
            text=f"Summary: {ver.change_summary}",
            font=get_font(12, "bold"),
            text_color=ACCENT_PRIMARY,
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 12))

        # Actions Row: Rollback, Delete version
        act_row = ctk.CTkFrame(self.detail_scroll, fg_color="transparent")
        act_row.pack(fill="x", pady=(0, 12))

        ctk.CTkButton(
            act_row,
            text="🔄 Restore / Rollback to v" + str(ver.version_num),
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=34,
            command=lambda: self._confirm_rollback(ver),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            act_row,
            text="🗑️ Delete This Snapshot",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            text_color=COLOR_DANGER,
            height=34,
            command=lambda: self._confirm_delete_version(ver),
        ).pack(side="left")

        # 1. Visual Differences vs Live State
        diff_card = ctk.CTkFrame(self.detail_scroll, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        diff_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            diff_card,
            text="COMPARISON VS CURRENT LIVE ENTRY",
            font=get_font(10, "bold"),
            text_color=ACCENT_INDIGO,
        ).pack(anchor="w", padx=14, pady=(10, 6))

        diff_entries = self._compute_live_diff(data)
        if not diff_entries:
            ctk.CTkLabel(
                diff_card,
                text="✓ Identical to current live entry (no secret or configuration differences).",
                font=get_font(11),
                text_color=COLOR_SUCCESS,
            ).pack(anchor="w", padx=14, pady=(0, 10))
        else:
            for field_name, (old_v, live_v) in diff_entries.items():
                d_row = ctk.CTkFrame(diff_card, fg_color="transparent")
                d_row.pack(fill="x", padx=14, pady=3)

                ctk.CTkLabel(
                    d_row,
                    text=f"• {field_name}:",
                    font=get_font(11, "bold"),
                    text_color=TEXT_PRIMARY,
                    width=120,
                    anchor="w",
                ).pack(side="left")

                is_sensitive = "pass" in field_name.lower() or "secret" in field_name.lower() or "token" in field_name.lower() or "key" in field_name.lower()
                disp_old = "••••••••" if is_sensitive else (str(old_v)[:30] or "None")
                disp_live = "••••••••" if is_sensitive else (str(live_v)[:30] or "None")

                ctk.CTkLabel(
                    d_row,
                    text=f"Snapshot: {disp_old}  ➔  Live: {disp_live}",
                    font=get_mono_font(11),
                    text_color=COLOR_WARNING,
                    anchor="w",
                ).pack(side="left", fill="x", expand=True)

            diff_card.pack_configure(pady=(0, 12))

        # 2. Snapshot Credential Details
        snap_card = ctk.CTkFrame(self.detail_scroll, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        snap_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            snap_card,
            text="SNAPSHOT PAYLOAD VALUES",
            font=get_font(10, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=14, pady=(10, 6))

        # Inspect specific fields depending on type
        stype = data.get("entry_type", self.entry.entry_type)
        self._render_field_row(snap_card, "Title", data.get("title", ""))
        self._render_field_row(snap_card, "Category", data.get("category", ""))

        if data.get("username"):
            self._render_field_row(snap_card, "Username", data.get("username", ""), copyable=True)

        if data.get("password"):
            self._render_field_row(snap_card, "Password", data.get("password", ""), copyable=True, is_sensitive=True, field_id="pwd")

        if data.get("sudo_password"):
            self._render_field_row(snap_card, "Sudo Password", data.get("sudo_password", ""), copyable=True, is_sensitive=True, field_id="sudo")

        if data.get("hostname"):
            self._render_field_row(snap_card, "Host / IP", data.get("hostname", ""), copyable=True)

        if data.get("port"):
            self._render_field_row(snap_card, "Port", str(data.get("port", "")))

        if data.get("url"):
            self._render_field_row(snap_card, "URL", data.get("url", ""), copyable=True)

        if data.get("api_token"):
            self._render_field_row(snap_card, "API Token", data.get("api_token", ""), copyable=True, is_sensitive=True, field_id="token")

        if data.get("api_key_secret"):
            self._render_field_row(snap_card, "API Secret", data.get("api_key_secret", ""), copyable=True, is_sensitive=True, field_id="secret")

        if data.get("public_key"):
            self._render_field_row(snap_card, "Public Key", data.get("public_key", ""), copyable=True)

        if data.get("private_key"):
            self._render_field_row(snap_card, "Private Key", data.get("private_key", ""), copyable=True, is_sensitive=True, field_id="privkey")

        if data.get("totp_secret"):
            self._render_field_row(snap_card, "2FA TOTP Secret", data.get("totp_secret", ""), copyable=True, is_sensitive=True, field_id="totp")

        if data.get("notes"):
            self._render_field_row(snap_card, "Notes", data.get("notes", ""), copyable=True)

        # 3. Associated Physical Files Box (if any)
        files = ver.associated_files or data.get("associated_files", [])
        if files:
            files_card = ctk.CTkFrame(self.detail_scroll, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
            files_card.pack(fill="x", pady=(0, 12))

            ctk.CTkLabel(
                files_card,
                text=f"ASSOCIATED PHYSICAL KEY FILES ({len(files)})",
                font=get_font(10, "bold"),
                text_color=COLOR_WARNING,
            ).pack(anchor="w", padx=14, pady=(10, 6))

            for fp in files:
                p = Path(fp)
                exists = p.is_file()
                sz_str = f"({p.stat().st_size} bytes)" if exists else "(Missing from disk)"

                f_row = ctk.CTkFrame(files_card, fg_color="transparent")
                f_row.pack(fill="x", padx=14, pady=3)

                status_icon = "✓" if exists else "⚠️"
                status_color = COLOR_SUCCESS if exists else COLOR_DANGER

                ctk.CTkLabel(
                    f_row,
                    text=f"{status_icon} {p.name}",
                    font=get_font(11, "bold"),
                    text_color=status_color,
                    anchor="w",
                ).pack(side="left")

                ctk.CTkLabel(
                    f_row,
                    text=f" {sz_str}",
                    font=get_mono_font(10),
                    text_color=TEXT_MUTED,
                    anchor="w",
                ).pack(side="left")

                ctk.CTkButton(
                    f_row,
                    text="📋 Copy Path",
                    width=75,
                    height=24,
                    font=get_font(10),
                    fg_color=BG_CARD,
                    hover_color=BORDER_COLOR,
                    command=lambda p_str=str(p): self._copy_text(p_str, "File path copied"),
                ).pack(side="right")

            files_card.pack_configure(pady=(0, 12))

    def _render_field_row(
        self,
        parent,
        label: str,
        value: str,
        copyable: bool = False,
        is_sensitive: bool = False,
        field_id: str = "",
    ) -> None:
        if not value:
            return

        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=3)

        ctk.CTkLabel(
            row,
            text=label,
            font=get_font(11, "bold"),
            text_color=TEXT_SECONDARY,
            width=110,
            anchor="w",
        ).pack(side="left")

        is_revealed = field_id in self._revealed_fields if is_sensitive else True
        disp_val = value if is_revealed else "••••••••••••••••"

        val_lbl = ctk.CTkLabel(
            row,
            text=disp_val if "\n" not in disp_val else f"{disp_val.splitlines()[0]} ... ({len(disp_val)} chars)",
            font=get_mono_font(11),
            text_color=TEXT_PRIMARY,
            anchor="w",
        )
        val_lbl.pack(side="left", fill="x", expand=True, padx=(4, 8))

        if is_sensitive:
            ctk.CTkButton(
                row,
                text="Hide" if is_revealed else "Reveal",
                width=50,
                height=24,
                font=get_font(10),
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                command=lambda: self._toggle_reveal(field_id),
            ).pack(side="right", padx=(4, 0))

        if copyable:
            ctk.CTkButton(
                row,
                text="📋 Copy",
                width=60,
                height=24,
                font=get_font(10),
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                command=lambda: self._copy_text(value, f"{label} copied", is_sensitive=is_sensitive),
            ).pack(side="right")

    def _toggle_reveal(self, field_id: str) -> None:
        if field_id in self._revealed_fields:
            self._revealed_fields.remove(field_id)
        else:
            self._revealed_fields.add(field_id)
        if self.selected_version:
            self._render_version_detail(self.selected_version)

    def _copy_text(self, text: str, label: str, is_sensitive: bool = False) -> None:
        if self.clipboard_mgr:
            self.clipboard_mgr.copy(text, label=label, is_sensitive=is_sensitive)
        else:
            self.clipboard_clear()
            self.clipboard_append(text)
        self.status_lbl.configure(text=f"✓ {label}", text_color=COLOR_SUCCESS)
        self.after(3000, lambda: self.status_lbl.configure(text=""))

    def _compute_live_diff(self, snapshot_data: Dict[str, Any]) -> Dict[str, tuple]:
        """Compares snapshot values with the current live entry."""
        diffs = {}
        fields_to_check = [
            ("title", "Title"),
            ("category", "Category"),
            ("username", "Username"),
            ("password", "Password"),
            ("sudo_password", "Sudo Password"),
            ("hostname", "Host/IP"),
            ("port", "Port"),
            ("url", "URL"),
            ("api_token", "API Token"),
            ("api_key_secret", "API Secret"),
            ("public_key", "Public Key"),
            ("private_key", "Private Key"),
            ("totp_secret", "TOTP Secret"),
            ("notes", "Notes"),
        ]
        for attr, label in fields_to_check:
            snap_v = snapshot_data.get(attr, "")
            live_v = getattr(self.entry, attr, "")
            if str(snap_v or "") != str(live_v or ""):
                diffs[label] = (snap_v, live_v)
        return diffs

    def _confirm_rollback(self, ver: VaultEntryVersion) -> None:
        confirm = messagebox.askyesno(
            "Confirm Version Rollback",
            f"Are you sure you want to restore '{self.entry.title}' to Version {ver.version_num}?\n\n"
            f"StarVault will automatically create a pre-rollback snapshot of the current state, "
            f"allowing you to undo anytime.",
            parent=self,
        )
        if not confirm:
            return

        try:
            restored = self.database.restore_entry_version(self.entry.id, ver.id, self.session_key)
            if not restored:
                messagebox.showerror("Rollback Failed", "Could not restore version.", parent=self)
                return

            self.entry = restored
            if self.on_restored:
                self.on_restored(restored)

            self.status_lbl.configure(
                text=f"✓ Successfully restored to Version {ver.version_num}!",
                text_color=COLOR_SUCCESS,
            )
            self._load_versions()
            messagebox.showinfo(
                "Rollback Successful",
                f"Entry restored to Version {ver.version_num} state.\nA backup version of the pre-rollback state was recorded.",
                parent=self,
            )
        except Exception as ex:
            messagebox.showerror("Error", f"Rollback failed:\n{ex}", parent=self)

    def _confirm_delete_version(self, ver: VaultEntryVersion) -> None:
        has_files = bool(ver.associated_files)
        msg = f"Delete Version {ver.version_num} snapshot permanently?"
        if has_files:
            msg += f"\n\nThis snapshot has {len(ver.associated_files)} associated physical key file(s)."

        confirm = messagebox.askyesno("Confirm Deletion", msg, parent=self)
        if not confirm:
            return

        del_files = False
        if has_files:
            del_files = messagebox.askyesno(
                "Delete Physical Files?",
                f"Do you also want to permanently wipe the {len(ver.associated_files)} associated physical key file(s) on disk?",
                parent=self,
            )

        success = self.database.delete_entry_version(ver.id, delete_physical_files=del_files)
        if success:
            self.status_lbl.configure(text=f"✓ Deleted Version {ver.version_num} snapshot.", text_color=COLOR_SUCCESS)
            self.selected_version = None
            self._load_versions()
        else:
            messagebox.showerror("Error", "Could not delete version snapshot.", parent=self)
