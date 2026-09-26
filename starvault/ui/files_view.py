"""Encrypted File Vault view for StarVault.

Provides local, zero-knowledge encrypted BLOB storage for arbitrary files
such as SSH keys (.pem), OpenVPN profiles (.ovpn), docker-compose configurations,
and sensitive backups directly inside the SQLite database.
"""

import hashlib
import mimetypes
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import List, Optional
import customtkinter as ctk
import pyperclip

from starvault.database import Database
from starvault.models import VaultFile
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


def format_bytes(num_bytes: int) -> str:
    """Formats byte counts into human-readable strings."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.1f} MB"


def get_file_icon(filename: str) -> str:
    """Selects an intuitive emoji based on file extension."""
    ext = Path(filename).suffix.lower()
    if ext in (".pem", ".key", ".pub", ".crt", ".cer"):
        return "🔑"
    elif ext in (".ovpn", ".conf", ".cfg"):
        return "🌐"
    elif ext in (".yml", ".yaml", ".json", ".toml", ".env", ".xml"):
        return "⚙️"
    elif ext in (".zip", ".tar", ".gz", ".7z", ".rar"):
        return "📦"
    elif ext in (".sh", ".bash", ".ps1", ".py"):
        return "📜"
    return "📄"


class FilesView(ctk.CTkFrame):
    """File storage view managing encrypted BLOBs in SQLite."""

    def __init__(
        self,
        parent,
        database: Database,
        encryption_key: bytes,
        **kwargs,
    ):
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.database = database
        self.encryption_key = encryption_key
        self.files: List[VaultFile] = []

        self._build_ui()
        self.refresh()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            title_frame,
            text="Encrypted File Vault",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame,
            text="AES-256-GCM encrypted BLOB storage for .pem, .ovpn, configs, and keys.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Top Actions
        act_box = ctk.CTkFrame(header, fg_color="transparent")
        act_box.pack(side="right", padx=24, pady=14)

        # Search bar
        self.search_entry = ctk.CTkEntry(
            act_box,
            placeholder_text="Search files...",
            width=200,
            height=34,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
        )
        self.search_entry.pack(side="left", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", lambda e: self._filter_files())

        ctk.CTkButton(
            act_box,
            text="Import / Upload File...",
            font=get_font(12, "bold"),
            height=34,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=self._open_upload_dialog,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            act_box,
            text="Export All...",
            font=get_font(11, "bold"),
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._export_all_files,
        ).pack(side="left")

        # Scrollable files list
        self.scroll_files = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_files.pack(fill="both", expand=True, padx=24, pady=16)

    def refresh(self):
        """Loads encrypted files metadata from database and updates view."""
        self.files = self.database.get_all_files(self.encryption_key)
        self._filter_files()

    def _filter_files(self):
        query = self.search_entry.get().strip().lower()
        filtered = []
        for f in self.files:
            if not query:
                filtered.append(f)
            elif query in f.filename.lower() or any(query in t for t in f.tags) or query in f.notes.lower():
                filtered.append(f)

        self._render_files(filtered)

    def _render_files(self, file_list: List[VaultFile]):
        for child in self.scroll_files.winfo_children():
            child.destroy()

        if not file_list:
            empty_card = ctk.CTkFrame(
                self.scroll_files,
                fg_color=BG_CARD,
                corner_radius=10,
                border_width=1,
                border_color=BORDER_COLOR,
            )
            empty_card.pack(fill="x", pady=20)
            ctk.CTkLabel(
                empty_card,
                text="📂 No Encrypted Files Stored",
                font=get_font(15, "bold"),
                text_color=TEXT_PRIMARY,
            ).pack(pady=(24, 4))
            ctk.CTkLabel(
                empty_card,
                text="Click '+ Upload File' above to ingest .pem, .ovpn, .env, or backup files into encrypted SQLite storage.",
                font=get_font(12),
                text_color=TEXT_MUTED,
            ).pack(pady=(0, 24))
            return

        for f in file_list:
            self._render_file_row(f)

    def _render_file_row(self, vault_file: VaultFile):
        card = ctk.CTkFrame(
            self.scroll_files,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="x", pady=5)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=12)

        # File Icon
        icon = get_file_icon(vault_file.filename)
        ctk.CTkLabel(
            row,
            text=icon,
            font=get_font(24),
        ).pack(side="left", padx=(0, 14))

        # Main details (filename, size, tags)
        info_col = ctk.CTkFrame(row, fg_color="transparent")
        info_col.pack(side="left", fill="x", expand=True)

        name_row = ctk.CTkFrame(info_col, fg_color="transparent")
        name_row.pack(fill="x")

        ctk.CTkLabel(
            name_row,
            text=vault_file.filename,
            font=get_font(13, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            name_row,
            text=format_bytes(vault_file.file_size),
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=(0, 10))

        # Tags
        for tag in vault_file.tags[:3]:
            tag_pill = ctk.CTkFrame(name_row, fg_color=BG_INPUT, corner_radius=4)
            tag_pill.pack(side="left", padx=2)
            ctk.CTkLabel(tag_pill, text=f"#{tag}", font=get_font(10), text_color=TEXT_SECONDARY).pack(padx=6, pady=1)

        # Sub row: Notes / Date
        date_str = vault_file.updated_at[:19].replace("T", " ") if vault_file.updated_at else ""
        sub_text = f"Updated: {date_str}"
        if vault_file.notes:
            sub_text += f"  •  {vault_file.notes}"

        ctk.CTkLabel(
            info_col,
            text=sub_text,
            font=get_font(11),
            text_color=TEXT_MUTED,
            anchor="w",
        ).pack(fill="x", pady=(3, 0))

        # Actions on right
        btn_box = ctk.CTkFrame(row, fg_color="transparent")
        btn_box.pack(side="right")

        # Preview button
        ctk.CTkButton(
            btn_box,
            text="Preview",
            width=80,
            height=30,
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda f=vault_file: self._preview_file(f),
        ).pack(side="left", padx=3)

        # Extract / Save to Disk button
        ctk.CTkButton(
            btn_box,
            text="📤 Extract",
            width=80,
            height=30,
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda f=vault_file: self._extract_file(f),
        ).pack(side="left", padx=3)

        # Delete button
        ctk.CTkButton(
            btn_box,
            text="🗑️",
            width=32,
            height=30,
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            command=lambda f=vault_file: self._delete_file(f),
        ).pack(side="left", padx=3)

    def _open_upload_dialog(self):
        filepath = filedialog.askopenfilename(
            title="Select File to Ingest into Encrypted Vault",
            filetypes=[("All Files", "*.*")],
        )
        if not filepath:
            return

        file_p = Path(filepath)
        raw_size = file_p.stat().st_size

        # Modal dialog for tags and notes
        modal = ctk.CTkToplevel(self)
        modal.title("Ingest File into Encrypted Vault")
        modal.geometry("520x400")
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(
            modal,
            text="Ingest & Encrypt File",
            font=get_font(16, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            modal,
            text=f"Selected: {file_p.name} ({format_bytes(raw_size)})",
            font=get_font(12),
            text_color=TEXT_MUTED,
        ).pack(pady=(0, 16))

        content_box = ctk.CTkFrame(modal, fg_color="transparent")
        content_box.pack(fill="x", padx=24)

        # Filename in vault
        ctk.CTkLabel(content_box, text="Vault Filename", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        name_entry = ctk.CTkEntry(content_box, fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
        name_entry.insert(0, file_p.name)
        name_entry.pack(fill="x", pady=(2, 10))

        # Tags
        ctk.CTkLabel(content_box, text="Tags (comma-separated)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        tags_entry = ctk.CTkEntry(content_box, placeholder_text="vps1, certs, ssh, vpn", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
        tags_entry.pack(fill="x", pady=(2, 10))

        # Notes
        ctk.CTkLabel(content_box, text="Encrypted Note / Description", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        notes_entry = ctk.CTkEntry(content_box, placeholder_text="Client OpenVPN config with embedded certs", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
        notes_entry.pack(fill="x", pady=(2, 16))

        # Buttons
        btn_row = ctk.CTkFrame(modal, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=10)

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            width=100,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=modal.destroy,
        ).pack(side="right", padx=(8, 0))

        def do_save():
            final_name = name_entry.get().strip() or file_p.name
            raw_tags = tags_entry.get().strip()
            tags = [t.strip().lower() for t in raw_tags.split(",") if t.strip()]
            notes = notes_entry.get().strip()

            mime_type, _ = mimetypes.guess_type(final_name)
            if not mime_type:
                mime_type = "application/octet-stream"

            try:
                with open(file_p, "rb") as fp:
                    data = fp.read()

                vault_file = VaultFile(
                    filename=final_name,
                    file_size=len(data),
                    mime_type=mime_type,
                    tags=tags,
                    notes=notes,
                )
                self.database.save_file(vault_file, data, self.encryption_key)
                modal.destroy()
                self.refresh()
            except Exception as ex:
                messagebox.showerror("Ingestion Error", f"Failed to encrypt and store file: {ex}")

        ctk.CTkButton(
            btn_row,
            text="Encrypt & Save",
            width=130,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            font=get_font(12, "bold"),
            command=do_save,
        ).pack(side="right")

    def _preview_file(self, vault_file: VaultFile):
        """Decrypts the file into memory and shows a preview modal dialog."""
        raw_bytes = self.database.read_file_bytes(vault_file.id, self.encryption_key)
        if raw_bytes is None:
            messagebox.showerror("Decryption Failed", "Could not decrypt file data from vault.")
            return

        is_text = False
        text_content = ""
        try:
            text_content = raw_bytes.decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            try:
                text_content = raw_bytes.decode("latin-1")
                # Check for high proportion of printable characters
                printable = sum(1 for c in text_content if c.isprintable() or c in "\r\n\t")
                if printable / max(1, len(text_content)) > 0.85:
                    is_text = True
            except Exception:
                is_text = False

        popup = ctk.CTkToplevel(self)
        popup.title(f"Preview: {vault_file.filename}")
        popup.geometry("700x560")
        popup.transient(self)
        popup.grab_set()

        # Header
        top = ctk.CTkFrame(popup, fg_color=BG_CARD, height=50)
        top.pack(fill="x")

        ctk.CTkLabel(
            top,
            text=f"📄 {vault_file.filename}  ({format_bytes(len(raw_bytes))})",
            font=get_font(14, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=16, pady=12)

        if is_text:
            def copy_contents():
                pyperclip.copy(text_content)
                copy_btn.configure(text="✓ Copied!", fg_color=COLOR_SUCCESS)
                popup.after(1500, lambda: copy_btn.configure(text="Copy All", fg_color=ACCENT_PRIMARY))

            copy_btn = ctk.CTkButton(
                top,
                text="Copy All",
                font=get_font(11, "bold"),
                width=100,
                height=30,
                fg_color=ACCENT_PRIMARY,
                hover_color=ACCENT_HOVER,
                text_color="#000000",
                command=copy_contents,
            )
            copy_btn.pack(side="right", padx=16, pady=10)

        # Content area
        if is_text:
            txt_box = ctk.CTkTextbox(popup, font=get_mono_font(11), fg_color=BG_INPUT, border_color=BORDER_COLOR)
            txt_box.pack(fill="both", expand=True, padx=16, pady=16)
            txt_box.insert("1.0", text_content)
            txt_box.configure(state="disabled")
        else:
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
            bin_frame = ctk.CTkFrame(popup, fg_color="transparent")
            bin_frame.pack(fill="both", expand=True, padx=20, pady=20)

            ctk.CTkLabel(
                bin_frame,
                text="📦 Binary Data",
                font=get_font(18, "bold"),
                text_color=TEXT_PRIMARY,
            ).pack(pady=(40, 10))

            ctk.CTkLabel(
                bin_frame,
                text=f"File size: {format_bytes(len(raw_bytes))}\nMIME Type: {vault_file.mime_type}\nSHA-256: {sha256_hash}",
                font=get_mono_font(12),
                text_color=TEXT_SECONDARY,
                justify="center",
            ).pack(pady=(0, 20))

            ctk.CTkButton(
                bin_frame,
                text="Extract to Disk",
                font=get_font(12, "bold"),
                width=150,
                height=36,
                fg_color=ACCENT_PRIMARY,
                hover_color=ACCENT_HOVER,
                text_color="#000000",
                command=lambda: [popup.destroy(), self._extract_file(vault_file)],
            ).pack()

    def _extract_file(self, vault_file: VaultFile):
        """Decrypts file and prompts user for destination path to save to disk."""
        raw_bytes = self.database.read_file_bytes(vault_file.id, self.encryption_key)
        if raw_bytes is None:
            messagebox.showerror("Decryption Failed", "Could not decrypt file data.")
            return

        dest = filedialog.asksaveasfilename(
            title="Save Decrypted File",
            initialfile=vault_file.filename,
            filetypes=[("All Files", "*.*")],
        )
        if not dest:
            return

        try:
            with open(dest, "wb") as f:
                f.write(raw_bytes)
            messagebox.showinfo("Export Complete", f"Successfully extracted '{vault_file.filename}' to disk.")
        except Exception as ex:
            messagebox.showerror("Export Failed", f"Failed to write file to disk: {ex}")

    def _export_all_files(self):
        """Exports all decrypted files in the vault to a selected local directory."""
        if not self.files:
            messagebox.showinfo("No Files", "There are no files stored in the vault to export.")
            return

        dest_dir = filedialog.askdirectory(title="Select Folder to Export All Vault Files To")
        if not dest_dir:
            return

        dest_path = Path(dest_dir)
        exported = 0
        failed = []

        for vf in self.files:
            raw_bytes = self.database.read_file_bytes(vf.id, self.encryption_key)
            if raw_bytes is not None:
                try:
                    out_file = dest_path / vf.filename
                    if out_file.exists():
                        out_file = dest_path / f"{out_file.stem}_{vf.id[:6]}{out_file.suffix}"
                    with open(out_file, "wb") as f:
                        f.write(raw_bytes)
                    exported += 1
                except Exception as ex:
                    failed.append(f"{vf.filename}: {ex}")
            else:
                failed.append(f"{vf.filename}: Decryption failed")

        msg = f"Exported {exported} file(s) to:\n{dest_dir}"
        if failed:
            msg += f"\n\n{len(failed)} file(s) failed."
        messagebox.showinfo("Bulk Export Complete", msg)

    def _delete_file(self, vault_file: VaultFile):
        """Prompts confirmation and removes encrypted file."""
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Permanently delete '{vault_file.filename}' from encrypted storage?\nThis cannot be undone.",
        )
        if confirm:
            self.database.delete_file(vault_file.id)
            self.refresh()
