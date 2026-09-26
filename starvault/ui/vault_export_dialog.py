"""StarVault Encrypted Export Dialog.

Allows users to export vault contents to:
1. Zero-Knowledge Encrypted Container (.sve / .starvault) protected by Argon2id + AES-256-GCM.
2. Compressed Archive (.zip) containing CSV, keys, files, and manifest.
3. Plaintext CSV (.csv) for credentials.
"""

from pathlib import Path
import threading
from tkinter import filedialog, messagebox
from typing import Optional
import customtkinter as ctk

from starvault.config import APP_NAME
from starvault.database import Database
from starvault.export_package import (
    create_encrypted_vault_package,
    export_vault_archive_zip,
)
from starvault.export_utils import export_entries_to_csv_string
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
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
from starvault.ui.widgets import add_password_toggle


class VaultExportDialog(ctk.CTkToplevel):
    """Modal dialog for exporting StarVault database to encrypted containers, archives, or CSV."""

    def __init__(
        self,
        parent,
        database: Database,
        session_key: bytes,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.database = database
        self.session_key = session_key

        self.title(f"{APP_NAME} - Export Vault")
        self.geometry("620x720")
        self.minsize(560, 640)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        # Header Banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=20, pady=12)

        ctk.CTkLabel(
            title_box,
            text="📤 Export StarVault Vault",
            font=get_font(17, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Create secure encrypted containers, full archives, or portable exports for local PC",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Scrollable Form Body
        self.scroll = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=16)

        # 1. Format Selection Card
        fmt_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        fmt_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            fmt_card,
            text="1. SELECT EXPORT PACKAGE FORMAT",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        self.format_var = ctk.StringVar(value="sve")

        # Radio 1: Encrypted Container
        r1 = ctk.CTkRadioButton(
            fmt_card,
            text="🔒 Encrypted StarVault Container (.sve) [RECOMMENDED]",
            variable=self.format_var,
            value="sve",
            font=get_font(12, "bold"),
            command=self._on_format_changed,
        )
        r1.pack(anchor="w", padx=16, pady=(4, 2))
        ctk.CTkLabel(
            fmt_card,
            text="Zero-knowledge container protected by Argon2id + AES-256-GCM. Fully portable to other StarVault instances.",
            font=get_font(10),
            text_color=TEXT_MUTED,
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=44, pady=(0, 8))

        # Radio 2: Compressed Archive
        r2 = ctk.CTkRadioButton(
            fmt_card,
            text="📦 Portable ZIP Archive (.zip)",
            variable=self.format_var,
            value="zip",
            font=get_font(12, "bold"),
            command=self._on_format_changed,
        )
        r2.pack(anchor="w", padx=16, pady=(4, 2))
        ctk.CTkLabel(
            fmt_card,
            text="Folder archive containing CSV passwords, decrypted files/, exported keys/, and manifest.",
            font=get_font(10),
            text_color=TEXT_MUTED,
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=44, pady=(0, 8))

        # Radio 3: Plain CSV
        r3 = ctk.CTkRadioButton(
            fmt_card,
            text="📄 Plaintext CSV (.csv)",
            variable=self.format_var,
            value="csv",
            font=get_font(12, "bold"),
            command=self._on_format_changed,
        )
        r3.pack(anchor="w", padx=16, pady=(4, 2))
        ctk.CTkLabel(
            fmt_card,
            text="Spreadsheet export of credentials only. Warning: Stored unencrypted on disk.",
            font=get_font(10),
            text_color=COLOR_WARNING,
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=44, pady=(0, 12))

        # 2. Scope & Content Checklist Card
        scope_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        scope_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            scope_card,
            text="2. SELECT DATA TO INCLUDE",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        self.inc_creds_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            scope_card,
            text="🔑 Passwords & Server Credentials",
            variable=self.inc_creds_var,
            font=get_font(12),
        ).pack(anchor="w", padx=16, pady=4)

        self.inc_keys_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            scope_card,
            text="⚡ Cryptographic Keys & Certificates (SSH, PGP, TLS, WireGuard, Age)",
            variable=self.inc_keys_var,
            font=get_font(12),
        ).pack(anchor="w", padx=16, pady=4)

        self.inc_files_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            scope_card,
            text="📁 Attached Files & Documents (Configs, Certificates, Keyrings)",
            variable=self.inc_files_var,
            font=get_font(12),
        ).pack(anchor="w", padx=16, pady=4)

        self.inc_versions_var = ctk.BooleanVar(value=True)
        self.versions_chk = ctk.CTkCheckBox(
            scope_card,
            text="📜 Historical Snapshot Versions & Change Logs",
            variable=self.inc_versions_var,
            font=get_font(12),
        )
        self.versions_chk.pack(anchor="w", padx=16, pady=(4, 12))

        # 3. Security Passphrase Card (For .sve containers)
        self.pass_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        self.pass_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            self.pass_card,
            text="3. EXPORT ENCRYPTION PASSPHRASE",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            self.pass_card,
            text="Set a passphrase to encrypt this package. You will need this passphrase to import the package on another StarVault instance.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 8))

        # Passphrase Row
        p1_frame = ctk.CTkFrame(self.pass_card, fg_color="transparent")
        p1_frame.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(p1_frame, text="Passphrase:", font=get_font(12), text_color=TEXT_SECONDARY, width=130, anchor="w").pack(side="left")
        self.pass_entry = ctk.CTkEntry(p1_frame, show="•", font=get_mono_font(11), fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p1_frame, self.pass_entry)

        # Confirm Passphrase Row
        p2_frame = ctk.CTkFrame(self.pass_card, fg_color="transparent")
        p2_frame.pack(fill="x", padx=16, pady=(4, 12))
        ctk.CTkLabel(p2_frame, text="Confirm Passphrase:", font=get_font(12), text_color=TEXT_SECONDARY, width=130, anchor="w").pack(side="left")
        self.pass_confirm_entry = ctk.CTkEntry(p2_frame, show="•", font=get_mono_font(11), fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
        self.pass_confirm_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p2_frame, self.pass_confirm_entry)

        # Status & Action Bar
        act_card = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        act_card.pack(fill="x", side="bottom")

        self.status_lbl = ctk.CTkLabel(act_card, text="", font=get_font(11))
        self.status_lbl.pack(side="left", padx=20)

        ctk.CTkButton(
            act_card,
            text="Cancel",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            width=90,
            height=36,
            command=self.destroy,
        ).pack(side="right", padx=(0, 16), pady=14)

        self.export_btn = ctk.CTkButton(
            act_card,
            text="📤 Export to File...",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=36,
            command=self._do_export,
        )
        self.export_btn.pack(side="right", padx=8, pady=14)

    def _on_format_changed(self):
        fmt = self.format_var.get()
        if fmt == "csv":
            self.pass_card.pack_forget()
            self.versions_chk.configure(state="disabled")
        else:
            self.pass_card.pack(fill="x", pady=(0, 14), padx=4)
            self.versions_chk.configure(state="normal")

    def _do_export(self):
        fmt = self.format_var.get()
        inc_creds = self.inc_creds_var.get()
        inc_keys = self.inc_keys_var.get()
        inc_files = self.inc_files_var.get()
        inc_versions = self.inc_versions_var.get()

        if not (inc_creds or inc_keys or inc_files):
            messagebox.showwarning("Select Data", "Please select at least one data category to include in the export.")
            return

        passphrase = self.pass_entry.get().strip()
        confirm = self.pass_confirm_entry.get().strip()

        if fmt == "sve":
            if len(passphrase) < 6:
                messagebox.showerror("Invalid Passphrase", "Export passphrase must be at least 6 characters long.")
                return
            if passphrase != confirm:
                messagebox.showerror("Passphrase Mismatch", "The passphrases you entered do not match.")
                return

            file_path = filedialog.asksaveasfilename(
                title="Save StarVault Encrypted Export",
                defaultextension=".sve",
                initialfile="starvault_backup.sve",
                filetypes=[
                    ("StarVault Encrypted Container", "*.sve;*.starvault"),
                    ("All Files", "*.*"),
                ],
            )
            if not file_path:
                return

            self._run_export_worker(
                lambda: create_encrypted_vault_package(
                    database=self.database,
                    session_key=self.session_key,
                    export_passphrase=passphrase,
                    target_path=file_path,
                    include_credentials=inc_creds,
                    include_keys=inc_keys,
                    include_files=inc_files,
                    include_versions=inc_versions,
                ),
                file_path,
            )

        elif fmt == "zip":
            file_path = filedialog.asksaveasfilename(
                title="Save StarVault Archive",
                defaultextension=".zip",
                initialfile="starvault_archive.zip",
                filetypes=[("ZIP Archive", "*.zip"), ("All Files", "*.*")],
            )
            if not file_path:
                return

            self._run_export_worker(
                lambda: export_vault_archive_zip(
                    database=self.database,
                    session_key=self.session_key,
                    target_path=file_path,
                    include_csv=inc_creds,
                    include_keys=inc_keys,
                    include_files=inc_files,
                ),
                file_path,
            )

        elif fmt == "csv":
            file_path = filedialog.asksaveasfilename(
                title="Save Credentials CSV",
                defaultextension=".csv",
                initialfile="starvault_credentials.csv",
                filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")],
            )
            if not file_path:
                return

            try:
                entries = self.database.get_all_entries(self.session_key)
                if not inc_keys:
                    entries = [e for e in entries if e.entry_type != "keypair"]
                csv_data = export_entries_to_csv_string(entries)
                Path(file_path).write_text(csv_data, encoding="utf-8")
                messagebox.showinfo("Export Successful", f"Exported {len(entries)} credentials to:\n{file_path}")
                self.destroy()
            except Exception as ex:
                messagebox.showerror("Export Failed", f"Could not export CSV:\n{ex}")

    def _run_export_worker(self, worker_func, target_path: str):
        self.export_btn.configure(state="disabled")
        self.status_lbl.configure(text="Generating export package...", text_color=ACCENT_PRIMARY)

        def worker():
            success, msg, summary = worker_func()

            def on_complete():
                self.export_btn.configure(state="normal")
                if success:
                    self.status_lbl.configure(text="✓ Export completed successfully", text_color=COLOR_SUCCESS)
                    messagebox.showinfo(
                        "Export Complete",
                        f"{msg}\n\nFile saved to:\n{target_path}",
                    )
                    self.destroy()
                else:
                    self.status_lbl.configure(text="Export failed", text_color=COLOR_DANGER)
                    messagebox.showerror("Export Failed", msg)

            self.after(0, on_complete)

        threading.Thread(target=worker, daemon=True).start()
