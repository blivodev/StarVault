"""Settings and vault administration dialog for StarVault."""

import shutil
from pathlib import Path
from tkinter import filedialog
from typing import Callable, Dict, Optional
import customtkinter as ctk

from starvault.app_config import AppConfigManager
from starvault.database import Database
from starvault.export_utils import export_vault_to_archive, export_vault_to_csv
from starvault.gdrive_sync import GoogleDriveSync
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
    apply_theme,
    get_available_themes,
    get_current_theme,
    get_font,
    get_mono_font,
)
from starvault.ui.widgets import add_password_toggle


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

        # Launch on OS boot toggle
        from starvault.startup import is_startup_enabled, set_startup_enabled
        row_boot = ctk.CTkFrame(sec_card, fg_color="transparent")
        row_boot.pack(fill="x", padx=16, pady=6)
        self.var_boot = ctk.BooleanVar(value=is_startup_enabled())
        ctk.CTkCheckBox(
            row_boot,
            text="Launch StarVault automatically on Windows startup",
            variable=self.var_boot,
            font=get_font(12),
            command=lambda: set_startup_enabled(self.var_boot.get()),
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

        # 1.5 UI Theme Card
        theme_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        theme_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(theme_card, text="🎨 UI THEME & APPEARANCE (LIGHT / DARK / TRENDY / CONSOLE)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))

        row_theme = ctk.CTkFrame(theme_card, fg_color="transparent")
        row_theme.pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkLabel(row_theme, text="Color Theme Style", font=get_font(12), text_color=TEXT_PRIMARY).pack(side="left")

        current_theme_name = get_current_theme()
        self.theme_combo = ctk.CTkComboBox(
            row_theme,
            values=get_available_themes(),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            width=160,
            command=self._on_theme_selected,
        )
        self.theme_combo.set(current_theme_name)
        self.theme_combo.pack(side="right")

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
        p1_box = ctk.CTkFrame(p_row1, fg_color="transparent")
        p1_box.pack(fill="x", pady=(4, 0))
        self.new_pwd_entry = ctk.CTkEntry(p1_box, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.new_pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p1_box, self.new_pwd_entry)

        # Confirm New Password
        p_row2 = ctk.CTkFrame(pwd_card, fg_color="transparent")
        p_row2.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(p_row2, text="Confirm New Password", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        p2_box = ctk.CTkFrame(p_row2, fg_color="transparent")
        p2_box.pack(fill="x", pady=(4, 0))
        self.confirm_pwd_entry = ctk.CTkEntry(p2_box, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.confirm_pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p2_box, self.confirm_pwd_entry)

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

        # 4. Google Drive Cloud Sync Card
        gdrive_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        gdrive_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(gdrive_card, text="☁️ GOOGLE DRIVE CLOUD SYNC (LOG IN WITH GOOGLE)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            gdrive_card,
            text="Sync your encrypted database (.db) directly to Google Drive. The file is 100% encrypted with Argon2id + AES-256-GCM. Unencrypted credentials NEVER leave your device.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=520,
            justify="left",
        ).pack(fill="x", padx=16, pady=(0, 8))

        self.app_config = AppConfigManager()
        self.gdrive_sync = GoogleDriveSync(
            config_getter=self.app_config.get_gdrive_config,
            config_saver=self.app_config.save_gdrive_config,
        )

        gd_cfg = self.app_config.get_gdrive_config()
        is_gd_connected = gd_cfg.get("gdrive_connected", False)
        gd_user = gd_cfg.get("gdrive_user_email", "")
        gd_last = gd_cfg.get("gdrive_last_sync", "")

        status_text = f"✓ Connected as {gd_user}" if is_gd_connected else "Status: Not connected to Google Drive"
        if is_gd_connected and gd_last:
            status_text += f" (Last sync: {gd_last})"

        self.gdrive_status_lbl = ctk.CTkLabel(
            gdrive_card,
            text=status_text,
            font=get_font(11, "bold"),
            text_color=COLOR_SUCCESS if is_gd_connected else TEXT_MUTED,
        )
        self.gdrive_status_lbl.pack(anchor="w", padx=16, pady=(0, 8))

        self.gdrive_btn_row = ctk.CTkFrame(gdrive_card, fg_color="transparent")
        self.gdrive_btn_row.pack(fill="x", padx=16, pady=(0, 14))
        self._render_gdrive_buttons()

        # 5. Vault Storage & Manual Export Card
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

        # 6. CSV Export Card
        csv_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        csv_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(csv_card, text="📊 CREDENTIAL EXPORT (CSV SPREADSHEET)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            csv_card,
            text="Export all decrypted entries to a standard CSV spreadsheet. Requires master password authentication before decrypting.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=500,
            justify="left",
        ).pack(fill="x", padx=16, pady=(0, 8))

        csv_btn_row = ctk.CTkFrame(csv_card, fg_color="transparent")
        csv_btn_row.pack(fill="x", padx=16, pady=(4, 14))

        ctk.CTkButton(
            csv_btn_row,
            text="📤 Export to CSV...",
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            height=34,
            command=self._export_csv_flow,
        ).pack(side="left")

        self.csv_status_label = ctk.CTkLabel(csv_btn_row, text="", font=get_font(11))
        self.csv_status_label.pack(side="left", padx=10)

        # 7. Full Archive Export Card (.zip, .7z with optional password)
        arch_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        arch_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(arch_card, text="📦 FULL VAULT ARCHIVE EXPORT (ZIP / 7Z / EXTRACT ALL)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            arch_card,
            text="Extract all vault assets (credentials CSV, decrypted files, private/public keys, certificates) into an encrypted or portable archive package.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=500,
            justify="left",
        ).pack(fill="x", padx=16, pady=(0, 8))

        # Format & Options
        opt_row = ctk.CTkFrame(arch_card, fg_color="transparent")
        opt_row.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(opt_row, text="Archive Format:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 8))
        self.archive_fmt_var = ctk.StringVar(value=".zip (AES-256 Encrypted)")
        ctk.CTkOptionMenu(
            opt_row,
            values=[".zip (AES-256 Encrypted)", ".7z (High Compression)"],
            variable=self.archive_fmt_var,
            font=get_font(11),
            fg_color=BG_INPUT,
            button_color=BORDER_COLOR,
            width=200,
            height=30,
        ).pack(side="left", padx=(0, 16))

        # Archive Password Entry
        pwd_row = ctk.CTkFrame(arch_card, fg_color="transparent")
        pwd_row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(pwd_row, text="Archive Password (Optional):", font=get_font(11), text_color=TEXT_PRIMARY).pack(side="left", padx=(0, 8))
        self.arch_pwd_entry = ctk.CTkEntry(
            pwd_row,
            placeholder_text="Leave blank for unencrypted archive...",
            show="*",
            font=get_mono_font(11),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=32,
        )
        self.arch_pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        # Checkboxes for what to include
        chk_row = ctk.CTkFrame(arch_card, fg_color="transparent")
        chk_row.pack(fill="x", padx=16, pady=4)

        self.inc_csv_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(chk_row, text="CSV Data", variable=self.inc_csv_var, font=get_font(11)).pack(side="left", padx=(0, 12))

        self.inc_files_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(chk_row, text="Files (.pem, .ovpn, configs)", variable=self.inc_files_var, font=get_font(11)).pack(side="left", padx=(0, 12))

        self.inc_keys_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(chk_row, text="Keys & Certs", variable=self.inc_keys_var, font=get_font(11)).pack(side="left")

        # Action row
        arch_act_row = ctk.CTkFrame(arch_card, fg_color="transparent")
        arch_act_row.pack(fill="x", padx=16, pady=(6, 14))

        ctk.CTkButton(
            arch_act_row,
            text="📦 Export Full Archive...",
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            height=34,
            command=self._export_archive_flow,
        ).pack(side="left")

        self.arch_status_label = ctk.CTkLabel(arch_act_row, text="", font=get_font(11))
        self.arch_status_label.pack(side="left", padx=10)

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

    def _render_gdrive_buttons(self):
        for child in self.gdrive_btn_row.winfo_children():
            child.destroy()

        gd_cfg = self.app_config.get_gdrive_config()
        is_gd_connected = gd_cfg.get("gdrive_connected", False)

        if not is_gd_connected:
            ctk.CTkButton(
                self.gdrive_btn_row,
                text="🔑 Log In with Google",
                font=get_font(12, "bold"),
                fg_color=ACCENT_PRIMARY,
                hover_color=ACCENT_HOVER,
                text_color="#000000",
                command=self._on_google_login,
                height=34,
            ).pack(side="left", padx=(0, 8))
        else:
            ctk.CTkButton(
                self.gdrive_btn_row,
                text="🔄 Sync Now (Upload)",
                font=get_font(11, "bold"),
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                command=self._on_google_sync,
                height=34,
            ).pack(side="left", padx=(0, 6))

            ctk.CTkButton(
                self.gdrive_btn_row,
                text="⬇️ Pull from Drive",
                font=get_font(11),
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                command=self._on_google_pull,
                height=34,
            ).pack(side="left", padx=6)

            ctk.CTkButton(
                self.gdrive_btn_row,
                text="Disconnect",
                font=get_font(11),
                fg_color=BG_INPUT,
                hover_color=COLOR_DANGER,
                text_color=COLOR_DANGER,
                command=self._on_google_disconnect,
                height=34,
            ).pack(side="left", padx=6)

    def _on_google_login(self):
        self.gdrive_status_lbl.configure(text="Opening browser for Google login...", text_color=COLOR_WARNING)
        def on_done(success, msg):
            def update():
                if success:
                    self.gdrive_status_lbl.configure(text=f"✓ {msg}", text_color=COLOR_SUCCESS)
                else:
                    self.gdrive_status_lbl.configure(text=f"Login failed: {msg}", text_color=COLOR_DANGER)
                self._render_gdrive_buttons()
            self.after(0, update)

        self.gdrive_sync.start_oauth_flow(on_complete=on_done)

    def _on_google_sync(self):
        self.gdrive_status_lbl.configure(text="Uploading encrypted database to Google Drive...", text_color=COLOR_WARNING)
        def worker():
            success, msg = self.gdrive_sync.upload_vault_to_drive(self.database.db_path)
            def update():
                self.gdrive_status_lbl.configure(
                    text=msg,
                    text_color=COLOR_SUCCESS if success else COLOR_DANGER,
                )
            self.after(0, update)
        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _on_google_pull(self):
        self.gdrive_status_lbl.configure(text="Downloading encrypted database from Google Drive...", text_color=COLOR_WARNING)
        def worker():
            success, msg = self.gdrive_sync.download_vault_from_drive(self.database.db_path)
            def update():
                self.gdrive_status_lbl.configure(
                    text=msg,
                    text_color=COLOR_SUCCESS if success else COLOR_DANGER,
                )
            self.after(0, update)
        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _on_google_disconnect(self):
        self.gdrive_sync.disconnect()
        self.gdrive_status_lbl.configure(text="Status: Disconnected from Google Drive", text_color=TEXT_MUTED)
        self._render_gdrive_buttons()

    def _on_theme_selected(self, theme_name: str):
        apply_theme(theme_name)
        if hasattr(self, "database") and self.database:
            try:
                self.database.update_settings({"theme": theme_name})
            except Exception:
                pass

    def _prompt_master_password(self, on_authenticated: Callable[[str, Optional[str]], None]):
        """Prompts user for master password authentication before performing sensitive exports."""
        modal = ctk.CTkToplevel(self)
        modal.title("Authenticate Master Password")
        modal.geometry("450x270")
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(
            modal,
            text="🔐 Authentication Required",
            font=get_font(15, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(pady=(16, 4))

        ctk.CTkLabel(
            modal,
            text="Please verify your master password before exporting vault data.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(pady=(0, 14))

        p_row = ctk.CTkFrame(modal, fg_color="transparent")
        p_row.pack(fill="x", padx=30, pady=4)

        pwd_entry = ctk.CTkEntry(
            p_row,
            placeholder_text="Enter Master Password...",
            show="•",
            font=get_mono_font(12),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p_row, pwd_entry)
        pwd_entry.focus_set()

        kf_entry = None
        if self.database.requires_2fa():
            k_row = ctk.CTkFrame(modal, fg_color="transparent")
            k_row.pack(fill="x", padx=30, pady=4)
            kf_entry = ctk.CTkEntry(
                k_row,
                placeholder_text="2FA Keyfile Token / Secret...",
                show="•",
                font=get_mono_font(12),
                fg_color=BG_INPUT,
                border_color=BORDER_COLOR,
                height=36,
            )
            kf_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
            add_password_toggle(k_row, kf_entry)

        err_label = ctk.CTkLabel(modal, text="", font=get_font(11), text_color=COLOR_DANGER)
        err_label.pack(pady=4)

        btn_row = ctk.CTkFrame(modal, fg_color="transparent")
        btn_row.pack(pady=8)

        def do_auth():
            pwd = pwd_entry.get().strip()
            kf = kf_entry.get().strip() if kf_entry else None
            if not pwd:
                err_label.configure(text="Master password cannot be empty.")
                return

            success, _ = self.database.unlock_vault(pwd, keyfile_secret=kf)
            if not success:
                err_label.configure(text="Incorrect master password or 2FA token.")
                return

            modal.destroy()
            on_authenticated(pwd, kf)

        ctk.CTkButton(
            btn_row,
            text="Authenticate & Export",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=34,
            command=do_auth,
        ).pack(side="left", padx=6)

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            height=34,
            command=modal.destroy,
        ).pack(side="left", padx=6)

        modal.bind("<Return>", lambda e: do_auth())

    def _export_csv_flow(self):
        def on_auth(pwd: str, kf: Optional[str]):
            dest = filedialog.asksaveasfilename(
                title="Export Vault Credentials as CSV",
                initialfile="starvault_credentials.csv",
                filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")],
            )
            if not dest:
                return

            success, msg, count = export_vault_to_csv(self.database, pwd, Path(dest), keyfile_secret=kf)
            if success:
                self.csv_status_label.configure(text=f"✓ Exported {count} credentials to '{Path(dest).name}'", text_color=COLOR_SUCCESS)
            else:
                self.csv_status_label.configure(text=f"Export failed: {msg}", text_color=COLOR_DANGER)

        self._prompt_master_password(on_auth)

    def _export_archive_flow(self):
        def on_auth(pwd: str, kf: Optional[str]):
            is_7z = ".7z" in self.archive_fmt_var.get()
            ext = ".7z" if is_7z else ".zip"
            desc = "7-Zip Archive (*.7z)" if is_7z else "ZIP Archive (*.zip)"

            dest = filedialog.asksaveasfilename(
                title="Export Full Vault Archive Package",
                initialfile=f"starvault_vault_archive{ext}",
                filetypes=[(desc, f"*{ext}"), ("All Files", "*.*")],
            )
            if not dest:
                return

            arch_pwd = self.arch_pwd_entry.get().strip() or None
            self.arch_status_label.configure(text="Generating vault archive...", text_color=COLOR_WARNING)

            def worker():
                success, msg, summ = export_vault_to_archive(
                    database=self.database,
                    master_password=pwd,
                    target_archive_path=Path(dest),
                    archive_format="7z" if is_7z else "zip",
                    archive_password=arch_pwd,
                    include_csv=self.inc_csv_var.get(),
                    include_files=self.inc_files_var.get(),
                    include_keys=self.inc_keys_var.get(),
                    keyfile_secret=kf,
                )
                def finish():
                    if success:
                        self.arch_status_label.configure(
                            text=f"✓ Saved '{Path(dest).name}' ({summ.get('credentials_count', 0)} credentials, {summ.get('files_count', 0)} files, {summ.get('keys_count', 0)} keys)",
                            text_color=COLOR_SUCCESS,
                        )
                    else:
                        self.arch_status_label.configure(text=f"Error: {msg}", text_color=COLOR_DANGER)
                self.after(0, finish)

            import threading
            threading.Thread(target=worker, daemon=True).start()

        self._prompt_master_password(on_auth)

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
