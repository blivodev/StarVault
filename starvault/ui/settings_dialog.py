"""Settings and vault administration dialog for StarVault."""

import shutil
from tkinter import filedialog
from typing import Callable, Dict, Optional
import customtkinter as ctk

from starvault.database import Database
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_PRIMARY,
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


class SettingsDialog(ctk.CTkToplevel):
    """Modal dialog for application preferences and vault management."""

    def __init__(
        self,
        parent,
        database: Database,
        current_key: bytes,
        on_key_updated: Callable[[bytes], None],
        on_settings_updated: Callable[[Dict], None],
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.database = database
        self.current_key = current_key
        self.on_key_updated = on_key_updated
        self.on_settings_updated = on_settings_updated

        self.title("StarVault Preferences & Security")
        self.geometry("620x680")
        self.minsize(580, 600)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        self.settings = self.database.get_settings()
        self._build_ui()

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=60, corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="⚙️ StarVault Settings",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=24, pady=16)

        scroll = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True, padx=20, pady=16)

        # 1. Security & Auto-Lock Card
        sec_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        sec_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(sec_card, text="AUTOMATION & TIMEOUTS", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))

        # Auto-lock dropdown
        row_lock = ctk.CTkFrame(sec_card, fg_color="transparent")
        row_lock.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row_lock, text="Auto-Lock on Inactivity", font=get_font(12), text_color=TEXT_PRIMARY).pack(side="left")

        current_autolock = self.settings.get("autolock_timeout", 300)
        lock_map = {60: "1 Minute", 300: "5 Minutes", 900: "15 Minutes", 1800: "30 Minutes", 0: "Never"}
        current_lock_str = lock_map.get(current_autolock, "5 Minutes")

        self.lock_combo = ctk.CTkComboBox(
            row_lock,
            values=["1 Minute", "5 Minutes", "15 Minutes", "30 Minutes", "Never"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            width=140,
        )
        self.lock_combo.set(current_lock_str)
        self.lock_combo.pack(side="right")

        # Lock on minimize toggle
        row_min = ctk.CTkFrame(sec_card, fg_color="transparent")
        row_min.pack(fill="x", padx=16, pady=6)
        self.var_min_lock = ctk.BooleanVar(value=self.settings.get("lock_on_minimize", True))
        ctk.CTkCheckBox(
            row_min,
            text="Auto-lock vault when minimized to system tray",
            variable=self.var_min_lock,
            font=get_font(12),
        ).pack(side="left")

        # Clipboard auto-clear dropdown
        row_clip = ctk.CTkFrame(sec_card, fg_color="transparent")
        row_clip.pack(fill="x", padx=16, pady=(6, 14))
        ctk.CTkLabel(row_clip, text="Auto-Clear Sensitive Clipboard", font=get_font(12), text_color=TEXT_PRIMARY).pack(side="left")

        current_clip = self.settings.get("clipboard_timeout", 30)
        clip_map = {10: "10 Seconds", 30: "30 Seconds", 60: "60 Seconds", 0: "Never"}
        current_clip_str = clip_map.get(current_clip, "30 Seconds")

        self.clip_combo = ctk.CTkComboBox(
            row_clip,
            values=["10 Seconds", "30 Seconds", "60 Seconds", "Never"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            width=140,
        )
        self.clip_combo.set(current_clip_str)
        self.clip_combo.pack(side="right")

        # 2. Master Password Change Card
        pwd_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        pwd_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(pwd_card, text="CHANGE MASTER PASSWORD", font=get_font(11, "bold"), text_color=COLOR_WARNING).pack(anchor="w", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            pwd_card,
            text="Re-encrypts the entire database with a newly derived Argon2id key and salt.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=16)

        # New Password
        p_row1 = ctk.CTkFrame(pwd_card, fg_color="transparent")
        p_row1.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(p_row1, text="New Master Password", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.new_pwd_entry = ctk.CTkEntry(p_row1, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.new_pwd_entry.pack(fill="x", pady=(4, 0))

        # Confirm New Password
        p_row2 = ctk.CTkFrame(pwd_card, fg_color="transparent")
        p_row2.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(p_row2, text="Confirm New Password", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.confirm_pwd_entry = ctk.CTkEntry(p_row2, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.confirm_pwd_entry.pack(fill="x", pady=(4, 0))

        self.pwd_status_label = ctk.CTkLabel(pwd_card, text="", font=get_font(12))
        self.pwd_status_label.pack(padx=16, pady=2)

        ctk.CTkButton(
            pwd_card,
            text="Update Master Password",
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_WARNING,
            height=34,
            command=self._change_password,
        ).pack(anchor="e", padx=16, pady=(4, 14))

        # 3. Passive Cloud Sync & Directory Mirroring Card
        sync_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        sync_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(sync_card, text="PASSIVE CLOUD SYNC (DIRECTORY MIRRORING)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            sync_card,
            text="Automatically mirrors your encrypted .db file whenever modifications are saved. Select your local Google Drive, Dropbox, or Nextcloud synced folder.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=520,
            justify="left",
        ).pack(fill="x", padx=16, pady=(0, 8))

        # Current Directory display & selector
        self.backup_dir_var = ctk.StringVar(value=self.settings.get("backup_dir", ""))

        dir_row = ctk.CTkFrame(sync_card, fg_color="transparent")
        dir_row.pack(fill="x", padx=16, pady=4)

        self.backup_dir_entry = ctk.CTkEntry(
            dir_row,
            textvariable=self.backup_dir_var,
            font=get_mono_font(11),
            placeholder_text="No sync folder configured (e.g. D:/GoogleDrive/StarVault)",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.backup_dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            dir_row,
            text="📁 Browse...",
            width=90,
            height=36,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._select_backup_dir,
        ).pack(side="right")

        sync_btn_row = ctk.CTkFrame(sync_card, fg_color="transparent")
        sync_btn_row.pack(fill="x", padx=16, pady=(6, 14))

        ctk.CTkButton(
            sync_btn_row,
            text="🔄 Sync Snapshot Now",
            width=150,
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._manual_sync,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            sync_btn_row,
            text="✖ Disable Sync",
            width=110,
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            command=self._clear_backup_dir,
        ).pack(side="left")

        self.sync_status_label = ctk.CTkLabel(
            sync_btn_row,
            text="✓ Active" if self.backup_dir_var.get() else "Sync disabled",
            font=get_font(11),
            text_color=COLOR_SUCCESS if self.backup_dir_var.get() else TEXT_MUTED,
        )
        self.sync_status_label.pack(side="left", padx=12)

        # 4. Vault Storage & Manual Export Card
        backup_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        backup_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(backup_card, text="PORTABLE DATABASE & MANUAL BACKUP", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(12, 6))

        db_path_str = str(self.database.db_path)
        ctk.CTkLabel(
            backup_card,
            text=f"Database Location: {db_path_str}",
            font=get_mono_font(11),
            text_color=TEXT_SECONDARY,
            anchor="w",
            wraplength=500,
        ).pack(fill="x", padx=16, pady=2)

        b_row = ctk.CTkFrame(backup_card, fg_color="transparent")
        b_row.pack(fill="x", padx=16, pady=(8, 14))

        ctk.CTkButton(
            b_row,
            text="💾 Save Backup Copy (.db)",
            width=160,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._backup_db,
        ).pack(side="left")

        self.backup_status_label = ctk.CTkLabel(b_row, text="", font=get_font(12), text_color=COLOR_SUCCESS)
        self.backup_status_label.pack(side="left", padx=10)

        # Bottom Bar
        bottom = ctk.CTkFrame(self, fg_color=BG_CARD, height=60, corner_radius=0)
        bottom.pack(fill="x", side="bottom")

        ctk.CTkButton(
            bottom,
            text="Close & Save Preferences",
            width=180,
            height=38,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            font=get_font(12, "bold"),
            command=self._save_preferences,
        ).pack(side="right", padx=24, pady=12)

    def _change_password(self):
        new_pwd = self.new_pwd_entry.get().strip()
        confirm_pwd = self.confirm_pwd_entry.get().strip()

        if len(new_pwd) < 6:
            self.pwd_status_label.configure(text="Password must be at least 6 characters.", text_color=COLOR_DANGER)
            return

        if new_pwd != confirm_pwd:
            self.pwd_status_label.configure(text="Passwords do not match.", text_color=COLOR_DANGER)
            return

        try:
            new_key = self.database.change_master_password(self.current_key, new_pwd)
            self.current_key = new_key
            self.on_key_updated(new_key)
            self.new_pwd_entry.delete(0, "end")
            self.confirm_pwd_entry.delete(0, "end")
            self.pwd_status_label.configure(text="✓ Master password successfully updated!", text_color=COLOR_SUCCESS)
        except Exception as e:
            self.pwd_status_label.configure(text=f"Error: {str(e)}", text_color=COLOR_DANGER)

    def _backup_db(self):
        dest = filedialog.asksaveasfilename(
            title="Backup StarVault Database",
            initialfile="starvault_backup.db",
            filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")],
        )
        if dest:
            try:
                shutil.copyfile(str(self.database.db_path), dest)
                self.backup_status_label.configure(text="✓ Backup saved successfully!")
            except Exception as e:
                self.backup_status_label.configure(text=f"Backup error: {str(e)}", text_color=COLOR_DANGER)

    def _select_backup_dir(self):
        folder = filedialog.askdirectory(title="Select Passive Cloud Sync Folder (Google Drive, Dropbox, etc.)")
        if folder:
            self.backup_dir_var.set(folder)
            self.sync_status_label.configure(text="✓ Active (Mirroring enabled)", text_color=COLOR_SUCCESS)

    def _clear_backup_dir(self):
        self.backup_dir_var.set("")
        self.sync_status_label.configure(text="Sync disabled", text_color=TEXT_MUTED)

    def _manual_sync(self):
        dir_val = self.backup_dir_var.get().strip()
        if not dir_val:
            self.sync_status_label.configure(text="Select a directory first", text_color=COLOR_WARNING)
            return

        # Save setting first
        self.database.update_settings({"backup_dir": dir_val})
        dest = self.database.trigger_backup()
        if dest:
            self.sync_status_label.configure(text="✓ Synced successfully!", text_color=COLOR_SUCCESS)
        else:
            self.sync_status_label.configure(text="Sync failed: check directory permissions", text_color=COLOR_DANGER)

    def _save_preferences(self):
        # Parse timeouts
        lock_map = {"1 Minute": 60, "5 Minutes": 300, "15 Minutes": 900, "30 Minutes": 1800, "Never": 0}
        clip_map = {"10 Seconds": 10, "30 Seconds": 30, "60 Seconds": 60, "Never": 0}

        updated = {
            "autolock_timeout": lock_map.get(self.lock_combo.get(), 300),
            "lock_on_minimize": self.var_min_lock.get(),
            "clipboard_timeout": clip_map.get(self.clip_combo.get(), 30),
            "backup_dir": self.backup_dir_var.get().strip(),
        }
        self.database.update_settings(updated)
        if updated["backup_dir"]:
            self.database.trigger_backup()
        self.on_settings_updated(updated)
        self.destroy()
