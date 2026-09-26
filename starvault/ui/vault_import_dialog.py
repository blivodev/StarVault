"""StarVault Encrypted Package & Archive Import Dialog.

Allows users to inspect and restore:
1. Zero-Knowledge Encrypted Containers (.sve / .starvault)
2. ZIP Archives (.zip)
3. Plaintext CSV spreadsheets (.csv)
with conflict resolution (skip, overwrite, import-as-copy).
"""

from pathlib import Path
import threading
from tkinter import filedialog, messagebox
from typing import Any, Callable, Dict, Optional
import customtkinter as ctk

from starvault.config import APP_NAME
from starvault.database import Database
from starvault.export_package import (
    execute_vault_import,
    inspect_import_file,
)
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


class VaultImportDialog(ctk.CTkToplevel):
    """Modal dialog for inspecting and importing .sve containers, archives, and CSVs into StarVault."""

    def __init__(
        self,
        parent,
        database: Database,
        session_key: bytes,
        on_import_completed: Optional[Callable[[], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.database = database
        self.session_key = session_key
        self.on_import_completed = on_import_completed

        self.title(f"{APP_NAME} - Import into Vault")
        self.geometry("640x740")
        self.minsize(580, 660)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        self.selected_file_path: Optional[Path] = None
        self.inspected_metadata: Optional[Dict[str, Any]] = None

        self._build_ui()

    def _build_ui(self):
        # Header Banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=20, pady=12)

        ctk.CTkLabel(
            title_box,
            text="📥 Import Data into StarVault",
            font=get_font(17, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Import encrypted .sve packages, .zip archives, or .csv files from another StarVault instance",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Scrollable Body
        self.scroll = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=16)

        # 1. File Selection Card
        sel_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        sel_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            sel_card,
            text="1. SELECT IMPORT FILE",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        btn_row = ctk.CTkFrame(sel_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="📂 Choose File...",
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            command=self._choose_import_file,
        ).pack(side="left", padx=(0, 10))

        self.file_lbl = ctk.CTkLabel(
            btn_row,
            text="No file chosen",
            font=get_mono_font(11),
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self.file_lbl.pack(side="left", fill="x", expand=True)

        # 2. Passphrase Card (Shown when file needs unlock)
        self.pass_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        self.pass_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            self.pass_card,
            text="2. PACKAGE ENCRYPTION PASSPHRASE",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(anchor="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            self.pass_card,
            text="This is an encrypted StarVault container. Enter the passphrase set when creating the export:",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 8))

        p_row = ctk.CTkFrame(self.pass_card, fg_color="transparent")
        p_row.pack(fill="x", padx=16, pady=(0, 12))

        self.pass_entry = ctk.CTkEntry(
            p_row,
            show="•",
            font=get_mono_font(12),
            placeholder_text="Enter export passphrase...",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=34,
        )
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p_row, self.pass_entry)

        self.unlock_btn = ctk.CTkButton(
            p_row,
            text="🔓 Unlock & Inspect",
            font=get_font(11, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=34,
            command=self._unlock_and_inspect,
        )
        self.unlock_btn.pack(side="left", padx=(6, 0))

        # 3. Preview & Metadata Card
        self.preview_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        self.preview_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            self.preview_card,
            text="3. PACKAGE INSPECTION PREVIEW",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        self.preview_container = ctk.CTkFrame(self.preview_card, fg_color="transparent")
        self.preview_container.pack(fill="x", padx=16, pady=(0, 12))

        self.preview_empty_lbl = ctk.CTkLabel(
            self.preview_container,
            text="Select a valid export file above to inspect package contents.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        )
        self.preview_empty_lbl.pack(anchor="w", pady=6)

        # 4. Conflict Resolution Card
        conflict_card = ctk.CTkFrame(self.scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        conflict_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            conflict_card,
            text="4. COLLISION & DUPLICATE RESOLUTION",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        self.strategy_var = ctk.StringVar(value="skip")

        r_skip = ctk.CTkRadioButton(
            conflict_card,
            text="Skip Existing Items (Preserve current vault entries)",
            variable=self.strategy_var,
            value="skip",
            font=get_font(12),
        )
        r_skip.pack(anchor="w", padx=16, pady=(2, 2))

        r_over = ctk.CTkRadioButton(
            conflict_card,
            text="Overwrite Existing Items (Replace current entries matching title)",
            variable=self.strategy_var,
            value="overwrite",
            font=get_font(12),
        )
        r_over.pack(anchor="w", padx=16, pady=(2, 2))

        self.r_copy = ctk.CTkRadioButton(
            conflict_card,
            text="Import as Duplicate Copies (Add '(Imported)' suffix)",
            variable=self.strategy_var,
            value="copy",
            font=get_font(12),
        )
        self.r_copy.pack(anchor="w", padx=16, pady=(2, 2))

        self.r_restore = ctk.CTkRadioButton(
            conflict_card,
            text="Full Database Restore (Atomically replace active vault with this backup)",
            variable=self.strategy_var,
            value="restore",
            font=get_font(12),
        )
        # Hidden by default until a database file is selected
        self.r_restore.pack_forget()

        # Action & Bottom Bar
        bottom_bar = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        bottom_bar.pack(fill="x", side="bottom")

        self.status_lbl = ctk.CTkLabel(bottom_bar, text="", font=get_font(11))
        self.status_lbl.pack(side="left", padx=20)

        ctk.CTkButton(
            bottom_bar,
            text="Cancel",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            width=90,
            height=36,
            command=self.destroy,
        ).pack(side="right", padx=(0, 16), pady=14)

        self.execute_btn = ctk.CTkButton(
            bottom_bar,
            text="📥 Execute Import into Vault",
            font=get_font(12, "bold"),
            fg_color=COLOR_SUCCESS,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=36,
            state="disabled",
            command=self._do_execute_import,
        )
        self.execute_btn.pack(side="right", padx=8, pady=14)

    def _choose_import_file(self):
        p = filedialog.askopenfilename(
            title="Select StarVault Export, Database Backup, or Archive",
            filetypes=[
                ("All Supported Vault Files", "*.sve;*.starvault;*.db;*.sqlite;*.sqlite3;*.zip;*.csv;*.json"),
                ("StarVault Database Files (*.db)", "*.db;*.sqlite;*.sqlite3"),
                ("Encrypted StarVault Packages (*.sve)", "*.sve;*.starvault"),
                ("ZIP Archives (*.zip)", "*.zip"),
                ("Spreadsheet & JSON (*.csv, *.json)", "*.csv;*.json"),
                ("All Files", "*.*"),
            ],
        )
        if not p:
            return

        self.selected_file_path = Path(p)
        self.file_lbl.configure(text=f"{self.selected_file_path.name} ({self.selected_file_path.stat().st_size} bytes)")
        self._inspect_file()

    def _unlock_and_inspect(self):
        self._inspect_file()

    def _inspect_file(self):
        if not self.selected_file_path or not self.selected_file_path.is_file():
            return

        pwd = self.pass_entry.get().strip() or None
        self.status_lbl.configure(text="Inspecting package...", text_color=TEXT_PRIMARY)

        success, msg, meta = inspect_import_file(self.selected_file_path, passphrase=pwd)

        if not success:
            if msg == "NEEDS_PASSPHRASE":
                self.status_lbl.configure(text="Encrypted package: Enter passphrase above", text_color=COLOR_WARNING)
                self.pass_card.pack(fill="x", pady=(0, 14), padx=4)
                self.execute_btn.configure(state="disabled")
            else:
                self.status_lbl.configure(text=f"Inspection failed: {msg}", text_color=COLOR_DANGER)
                self.execute_btn.configure(state="disabled")
                messagebox.showerror("Inspection Error", msg)
            return

        # Successfully inspected
        self.inspected_metadata = meta
        self.status_lbl.configure(text="✓ Package verified and ready to import", text_color=COLOR_SUCCESS)
        self.execute_btn.configure(state="normal")
        self._render_preview_details(meta)

    def _render_preview_details(self, meta: Dict[str, Any]):
        for w in self.preview_container.winfo_children():
            w.destroy()

        # Format Badge & Summary Row
        row1 = ctk.CTkFrame(self.preview_container, fg_color="transparent")
        row1.pack(fill="x", pady=(2, 8))

        ft = meta.get("file_type", "unknown")
        fmt_map = {
            "database": "🗄️ StarVault Database Backup (.db)",
            "encrypted_package": "🔒 Encrypted StarVault Package (.sve)",
            "zip_archive": "📦 Portable ZIP Archive (.zip)",
            "csv": "📄 CSV Spreadsheet (.csv)",
            "json": "📋 JSON Vault Export (.json)",
        }
        fmt_name = fmt_map.get(ft, "📄 Data Import Package")
        ctk.CTkLabel(row1, text=fmt_name, font=get_font(13, "bold"), text_color=ACCENT_PRIMARY).pack(side="left")

        if "created_at" in meta and meta["created_at"]:
            ctk.CTkLabel(row1, text=f"• Created: {meta['created_at'][:10]}", font=get_font(11), text_color=TEXT_MUTED).pack(side="left", padx=8)

        # Show/Hide Full Database Restore option based on file type
        if hasattr(self, "r_restore"):
            if ft == "database":
                self.r_restore.pack(anchor="w", padx=16, pady=(2, 12))
            else:
                self.r_restore.pack_forget()

        # Metric Chips Row
        grid = ctk.CTkFrame(self.preview_container, fg_color=BG_SUBTLE, corner_radius=8)
        grid.pack(fill="x", pady=4)

        metrics = [
            ("🔑 Credentials", meta.get("credentials_count", 0)),
            ("⚡ Keys & Certs", meta.get("keys_count", 0)),
            ("📁 Files", meta.get("files_count", 0)),
            ("📜 Versions", meta.get("versions_count", 0)),
        ]

        for i, (label, cnt) in enumerate(metrics):
            box = ctk.CTkFrame(grid, fg_color="transparent")
            box.pack(side="left", fill="x", expand=True, padx=8, pady=8)
            ctk.CTkLabel(box, text=label, font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack()
            ctk.CTkLabel(box, text=str(cnt), font=get_font(16, "bold"), text_color=ACCENT_PRIMARY).pack()

    def _do_execute_import(self):
        if not self.inspected_metadata:
            messagebox.showwarning("Not Inspected", "Please select and unlock a package first.")
            return

        strat = self.strategy_var.get()

        # Handle full database restore replacement
        if strat == "restore" and self.selected_file_path:
            confirm = messagebox.askyesno(
                "Confirm Full Database Restore",
                f"Are you sure you want to replace your entire current vault with the backup database:\n{self.selected_file_path.name}?\n\n"
                "WARNING: This will overwrite your active local database.",
            )
            if not confirm:
                return

            try:
                success = self.database.restore_from_backup(self.selected_file_path)
                if success:
                    messagebox.showinfo("Restore Successful", "✓ Vault successfully restored from database backup!")
                    if self.on_import_completed:
                        self.on_import_completed()
                    self.destroy()
                else:
                    messagebox.showerror("Restore Failed", "Could not restore database from selected file.")
            except Exception as e:
                messagebox.showerror("Restore Error", f"Restore error: {str(e)}")
            return

        self.execute_btn.configure(state="disabled")
        self.status_lbl.configure(text="Importing data into vault...", text_color=ACCENT_PRIMARY)

        def worker():
            success, msg, summary = execute_vault_import(
                database=self.database,
                session_key=self.session_key,
                import_metadata=self.inspected_metadata,
                conflict_strategy=strat,
            )

            def on_complete():
                self.execute_btn.configure(state="normal")
                if success:
                    self.status_lbl.configure(text="✓ Import completed!", text_color=COLOR_SUCCESS)
                    messagebox.showinfo("Import Successful", msg)
                    if self.on_import_completed:
                        self.on_import_completed()
                    self.destroy()
                else:
                    self.status_lbl.configure(text="Import failed", text_color=COLOR_DANGER)
                    messagebox.showerror("Import Error", msg)

            self.after(0, on_complete)

        threading.Thread(target=worker, daemon=True).start()
