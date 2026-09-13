"""Crypto Tools Swiss Army Knife View for StarVault.

Interactive helper view for encrypting, decrypting, hashing, and encoding/decoding
across common formats, keys, and algorithms:
- AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305
- RSA OAEP Encrypt & Decrypt
- Base64, Hex, URL, Binary
- SHA-256, SHA-512, MD5, HMAC-SHA256
- Single and Bulk File Encryption / Decryption with military-grade ciphers
"""

import os
from pathlib import Path
import threading
from tkinter import filedialog
from typing import List, Optional
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.crypto import generate_secure_password
from starvault.crypto_tools import (
    bulk_decrypt_files,
    bulk_encrypt_files,
    compute_hash,
    compute_hmac,
    decode_base64,
    decode_binary,
    decode_hex,
    decode_url,
    decrypt_file,
    decrypt_symmetric,
    encode_base64,
    encode_binary,
    encode_hex,
    encode_url,
    encrypt_file,
    encrypt_symmetric,
    rsa_decrypt,
    rsa_encrypt,
)
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
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


class CryptoToolsView(ctk.CTkFrame):
    """Interactive encryption, decryption, encoding, hashing, and file encryption workbench."""

    ALGORITHMS = [
        "AES-256-GCM",
        "AES-256-CBC",
        "ChaCha20-Poly1305",
        "RSA (OAEP SHA-256)",
        "Base64",
        "Hexadecimal",
        "URL Encode",
        "Binary (0101)",
        "Hash (SHA-256 / 512 / MD5)",
        "HMAC",
    ]

    CIPHER_OPTIONS = [
        "AES-256-GCM (Authenticated)",
        "ChaCha20-Poly1305 (AEAD)",
        "AES-256-CBC (PKCS7)",
    ]

    def __init__(
        self,
        parent,
        clipboard_mgr: ClipboardManager,
        **kwargs,
    ) -> None:
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.clipboard_mgr = clipboard_mgr
        self.selected_files: List[Path] = []
        self._build_ui()

    def _build_ui(self) -> None:
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=24, pady=10)

        ctk.CTkLabel(
            title_box,
            text="🛠️ Crypto Tools & Algorithm Studio",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Interactive cipher helper, encoding, hashing, and bulk file encryption workbench",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Mode Selector (Text / Files)
        self.mode_var = ctk.StringVar(value="text")
        mode_seg = ctk.CTkSegmentedButton(
            header,
            values=["📝 Text & Keys", "📁 Files & Bulk Encryption"],
            command=self._on_mode_switched,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color="#000000",
            height=32,
        )
        mode_seg.set("📝 Text & Keys")
        mode_seg.pack(side="right", padx=24, pady=14)

        # Content Containers
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.pack(fill="both", expand=True)

        self._build_text_workbench()
        self._build_file_workbench()

        # Show text workbench by default
        self._on_mode_switched("📝 Text & Keys")

    def _on_mode_switched(self, mode_label: str) -> None:
        if "Text" in mode_label:
            self.file_scroll.pack_forget()
            self.text_scroll.pack(fill="both", expand=True, padx=20, pady=16)
        else:
            self.text_scroll.pack_forget()
            self.file_scroll.pack(fill="both", expand=True, padx=20, pady=16)

    # -------------------------------------------------------------------------
    # 1. Text & Keys Workbench
    # -------------------------------------------------------------------------

    def _build_text_workbench(self) -> None:
        self.text_scroll = ctk.CTkScrollableFrame(self.content_container, fg_color=BG_ROOT)

        # Algorithm Selection Card
        sel_card = ctk.CTkFrame(self.text_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        sel_card.pack(fill="x", pady=(0, 14))

        sel_inner = ctk.CTkFrame(sel_card, fg_color="transparent")
        sel_inner.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(sel_inner, text="SELECT ALGORITHM / FORMAT:", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(side="left", padx=(0, 12))

        self.algo_var = ctk.StringVar(value="AES-256-GCM")
        self.algo_menu = ctk.CTkOptionMenu(
            sel_inner,
            values=self.ALGORITHMS,
            variable=self.algo_var,
            command=self._on_algo_changed,
            fg_color=BG_INPUT,
            button_color=BORDER_COLOR,
            button_hover_color=ACCENT_PRIMARY,
            text_color=TEXT_PRIMARY,
            font=get_font(12, "bold"),
            width=240,
            height=32,
        )
        self.algo_menu.pack(side="left")

        # Key / Passphrase container (shown for ciphers/HMAC)
        self.key_card = ctk.CTkFrame(self.text_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        self.key_card.pack(fill="x", pady=(0, 14))

        self.key_inner = ctk.CTkFrame(self.key_card, fg_color="transparent")
        self.key_inner.pack(fill="x", padx=16, pady=10)

        self.key_lbl = ctk.CTkLabel(self.key_inner, text="KEY / PASSPHRASE:", font=get_font(11, "bold"), text_color=COLOR_WARNING, width=150, anchor="w")
        self.key_lbl.pack(side="left")

        self.key_entry = ctk.CTkEntry(
            self.key_inner,
            placeholder_text="Enter encryption passphrase or 256-bit hex key...",
            font=get_mono_font(12),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=34,
        )
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            self.key_inner,
            text="⚡ Gen Key",
            font=get_font(11, "bold"),
            width=80,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._generate_random_key,
        ).pack(side="left")

        # Two-Column Input and Output Panels
        io_row = ctk.CTkFrame(self.text_scroll, fg_color="transparent")
        io_row.pack(fill="both", expand=True)

        # Input Card
        in_card = ctk.CTkFrame(io_row, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        in_card.pack(side="left", fill="both", expand=True, padx=(0, 8))

        in_header = ctk.CTkFrame(in_card, fg_color="transparent")
        in_header.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(in_header, text="INPUT DATA", font=get_font(11, "bold"), text_color=TEXT_PRIMARY).pack(side="left")

        ctk.CTkButton(
            in_header,
            text="Clear",
            font=get_font(10),
            width=45,
            height=22,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self.in_box.delete("1.0", "end"),
        ).pack(side="right")

        self.in_box = ctk.CTkTextbox(in_card, font=get_mono_font(12), fg_color=BG_INPUT, border_color=BORDER_COLOR, height=180)
        self.in_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Output Card
        out_card = ctk.CTkFrame(io_row, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        out_card.pack(side="left", fill="both", expand=True, padx=(8, 0))

        out_header = ctk.CTkFrame(out_card, fg_color="transparent")
        out_header.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(out_header, text="OUTPUT RESULT", font=get_font(11, "bold"), text_color=COLOR_SUCCESS).pack(side="left")

        ctk.CTkButton(
            out_header,
            text="📋 Copy",
            font=get_font(10, "bold"),
            width=55,
            height=22,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._copy_output,
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            out_header,
            text="⬆ Use as Input",
            font=get_font(10),
            width=85,
            height=22,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._use_as_input,
        ).pack(side="right")

        self.out_box = ctk.CTkTextbox(out_card, font=get_mono_font(12), fg_color=BG_INPUT, border_color=BORDER_COLOR, height=180)
        self.out_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Action Buttons Row
        action_bar = ctk.CTkFrame(self.text_scroll, fg_color="transparent")
        action_bar.pack(fill="x", pady=16)

        self.btn_encrypt = ctk.CTkButton(
            action_bar,
            text="🔒 Encrypt / Encode / Hash",
            font=get_font(13, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=38,
            command=self._do_encrypt,
        )
        self.btn_encrypt.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.btn_decrypt = ctk.CTkButton(
            action_bar,
            text="🔓 Decrypt / Decode",
            font=get_font(13, "bold"),
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=38,
            command=self._do_decrypt,
        )
        self.btn_decrypt.pack(side="left", fill="x", expand=True, padx=(8, 0))

        # Status / Error Banner
        self.status_lbl = ctk.CTkLabel(self.text_scroll, text="", font=get_font(12), text_color=COLOR_SUCCESS)
        self.status_lbl.pack(pady=(4, 0))

        self._on_algo_changed(self.algo_var.get())

    def _on_algo_changed(self, algo: str) -> None:
        """Adapts UI according to selected cryptographic operation."""
        self.status_lbl.configure(text="")
        if any(c in algo for c in ["AES", "ChaCha"]):
            self.key_card.pack(fill="x", pady=(0, 14))
            self.key_lbl.configure(text="PASSPHRASE / KEY:")
            self.key_entry.configure(placeholder_text="Enter passphrase or 64-character hex key...")
            self.btn_encrypt.configure(text="🔒 Encrypt (Symmetric)")
            self.btn_decrypt.configure(text="🔓 Decrypt (Symmetric)", state="normal")
        elif "RSA" in algo:
            self.key_card.pack(fill="x", pady=(0, 14))
            self.key_lbl.configure(text="RSA PEM KEY:")
            self.key_entry.configure(placeholder_text="Paste Public Key to Encrypt, or Private Key to Decrypt...")
            self.btn_encrypt.configure(text="🔒 RSA Encrypt")
            self.btn_decrypt.configure(text="🔓 RSA Decrypt", state="normal")
        elif "HMAC" in algo:
            self.key_card.pack(fill="x", pady=(0, 14))
            self.key_lbl.configure(text="HMAC SECRET KEY:")
            self.key_entry.configure(placeholder_text="Secret key for message authentication...")
            self.btn_encrypt.configure(text="⚡ Compute HMAC")
            self.btn_decrypt.configure(text="[One-Way Digest]", state="disabled")
        elif "Hash" in algo:
            self.key_card.pack_forget()
            self.btn_encrypt.configure(text="⚡ Calculate Hashes (SHA-256, SHA-512, MD5)")
            self.btn_decrypt.configure(text="[One-Way Digest]", state="disabled")
        else:
            self.key_card.pack_forget()
            self.btn_encrypt.configure(text=f"🔄 Encode ({algo})")
            self.btn_decrypt.configure(text=f"🔄 Decode ({algo})", state="normal")

    def _generate_random_key(self) -> None:
        pwd = generate_secure_password(length=32)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, pwd)
        self.status_lbl.configure(text="✓ Generated fresh 32-character high-entropy secret", text_color=COLOR_SUCCESS)

    def _do_encrypt(self) -> None:
        algo = self.algo_var.get()
        inp = self.in_box.get("1.0", "end-1c")
        key = self.key_entry.get().strip()

        if not inp:
            self.status_lbl.configure(text="Please provide input data.", text_color=COLOR_WARNING)
            return

        try:
            if "AES-256-GCM" in algo:
                out = encrypt_symmetric(inp, key, cipher="AES-256-GCM")
            elif "AES-256-CBC" in algo:
                out = encrypt_symmetric(inp, key, cipher="AES-256-CBC")
            elif "ChaCha20" in algo:
                out = encrypt_symmetric(inp, key, cipher="ChaCha20-Poly1305")
            elif "RSA" in algo:
                out = rsa_encrypt(inp, key)
            elif "Base64" in algo:
                out = encode_base64(inp)
            elif "Hex" in algo:
                out = encode_hex(inp)
            elif "URL" in algo:
                out = encode_url(inp)
            elif "Binary" in algo:
                out = encode_binary(inp)
            elif "HMAC" in algo:
                sha256_hmac = compute_hmac(inp, key, "sha256")
                sha512_hmac = compute_hmac(inp, key, "sha512")
                out = f"HMAC-SHA256:\n{sha256_hmac}\n\nHMAC-SHA512:\n{sha512_hmac}"
            elif "Hash" in algo:
                sha256_h = compute_hash(inp, "sha256")
                sha512_h = compute_hash(inp, "sha512")
                md5_h = compute_hash(inp, "md5")
                sha3_h = compute_hash(inp, "sha3_256")
                out = (
                    f"SHA-256:\n{sha256_h}\n\n"
                    f"SHA-512:\n{sha512_h}\n\n"
                    f"SHA3-256:\n{sha3_h}\n\n"
                    f"MD5:\n{md5_h}"
                )
            else:
                out = encode_base64(inp)

            self.out_box.delete("1.0", "end")
            self.out_box.insert("1.0", out)
            self.status_lbl.configure(text=f"✓ {algo} execution successful ({len(out)} characters output)", text_color=COLOR_SUCCESS)
        except Exception as ex:
            self.status_lbl.configure(text=f"Error: {str(ex)}", text_color=COLOR_DANGER)

    def _do_decrypt(self) -> None:
        algo = self.algo_var.get()
        inp = self.in_box.get("1.0", "end-1c").strip()
        key = self.key_entry.get().strip()

        if not inp:
            self.status_lbl.configure(text="Please provide input data to decrypt or decode.", text_color=COLOR_WARNING)
            return

        try:
            if "AES-256-GCM" in algo:
                out = decrypt_symmetric(inp, key, cipher="AES-256-GCM")
            elif "AES-256-CBC" in algo:
                out = decrypt_symmetric(inp, key, cipher="AES-256-CBC")
            elif "ChaCha20" in algo:
                out = decrypt_symmetric(inp, key, cipher="ChaCha20-Poly1305")
            elif "RSA" in algo:
                out = rsa_decrypt(inp, key)
            elif "Base64" in algo:
                out = decode_base64(inp)
            elif "Hex" in algo:
                out = decode_hex(inp)
            elif "URL" in algo:
                out = decode_url(inp)
            elif "Binary" in algo:
                out = decode_binary(inp)
            else:
                out = decode_base64(inp)

            self.out_box.delete("1.0", "end")
            self.out_box.insert("1.0", out)
            self.status_lbl.configure(text="✓ Decryption / decoding successful", text_color=COLOR_SUCCESS)
        except Exception as ex:
            self.status_lbl.configure(text=f"Decryption failed: {str(ex)}", text_color=COLOR_DANGER)

    def _copy_output(self) -> None:
        val = self.out_box.get("1.0", "end-1c")
        if val:
            self.clipboard_mgr.copy(val, label="Output copied")
            self.status_lbl.configure(text="✓ Copied output to clipboard", text_color=COLOR_SUCCESS)

    def _use_as_input(self) -> None:
        val = self.out_box.get("1.0", "end-1c")
        if val:
            self.in_box.delete("1.0", "end")
            self.in_box.insert("1.0", val)
            self.out_box.delete("1.0", "end")
            self.status_lbl.configure(text="✓ Shifted output into input box", text_color=TEXT_PRIMARY)

    # -------------------------------------------------------------------------
    # 2. File & Bulk Encryption Workbench
    # -------------------------------------------------------------------------

    def _build_file_workbench(self) -> None:
        self.file_scroll = ctk.CTkScrollableFrame(self.content_container, fg_color=BG_ROOT)

        # File Selection & Listing Card
        files_card = ctk.CTkFrame(self.file_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        files_card.pack(fill="x", pady=(0, 14))

        f_header = ctk.CTkFrame(files_card, fg_color="transparent")
        f_header.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(f_header, text="TARGET FILES TO ENCRYPT / DECRYPT (SINGLE OR BULK)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(side="left")

        ctk.CTkButton(
            f_header,
            text="➕ Select File(s)...",
            font=get_font(11, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=28,
            command=self._select_files,
        ).pack(side="right", padx=(6, 0))

        ctk.CTkButton(
            f_header,
            text="Clear List",
            font=get_font(10),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            height=28,
            width=70,
            command=self._clear_selected_files,
        ).pack(side="right")

        # Scrollable list of chosen files
        self.file_list_frame = ctk.CTkScrollableFrame(files_card, fg_color=BG_INPUT, height=120, corner_radius=6)
        self.file_list_frame.pack(fill="x", padx=16, pady=(0, 12))
        self._render_file_list()

        # Output Destination Directory Card
        out_dir_card = ctk.CTkFrame(self.file_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        out_dir_card.pack(fill="x", pady=(0, 14))

        out_row = ctk.CTkFrame(out_dir_card, fg_color="transparent")
        out_row.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(out_row, text="OUTPUT FOLDER:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY, width=120, anchor="w").pack(side="left")

        self.out_dir_var = ctk.StringVar(value="")
        self.out_dir_entry = ctk.CTkEntry(
            out_row,
            textvariable=self.out_dir_var,
            placeholder_text="Output directory (defaults to source file directory if left blank)...",
            font=get_mono_font(11),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=34,
        )
        self.out_dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            out_row,
            text="📁 Browse...",
            font=get_font(11),
            width=90,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._select_out_dir,
        ).pack(side="right")

        # Encryption Key & Cipher Card
        f_key_card = ctk.CTkFrame(self.file_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        f_key_card.pack(fill="x", pady=(0, 14))

        f_key_row = ctk.CTkFrame(f_key_card, fg_color="transparent")
        f_key_row.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(f_key_row, text="CIPHER:", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(side="left", padx=(0, 8))

        self.f_cipher_var = ctk.StringVar(value=self.CIPHER_OPTIONS[0])
        ctk.CTkOptionMenu(
            f_key_row,
            values=self.CIPHER_OPTIONS,
            variable=self.f_cipher_var,
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            button_color=BORDER_COLOR,
            button_hover_color=ACCENT_PRIMARY,
            text_color=TEXT_PRIMARY,
            width=220,
            height=34,
        ).pack(side="left", padx=(0, 16))

        ctk.CTkLabel(f_key_row, text="KEY / PASSPHRASE:", font=get_font(11, "bold"), text_color=COLOR_WARNING).pack(side="left", padx=(0, 8))

        self.f_key_entry = ctk.CTkEntry(
            f_key_row,
            placeholder_text="Enter encryption key or passphrase...",
            font=get_mono_font(11),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            show="*",
            height=34,
        )
        self.f_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.f_show_key_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            f_key_row,
            text="Show",
            variable=self.f_show_key_var,
            font=get_font(11),
            width=60,
            command=self._toggle_file_key_visibility,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            f_key_row,
            text="⚡ Gen Key",
            font=get_font(11, "bold"),
            width=80,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._generate_file_random_key,
        ).pack(side="left")

        # Action Buttons Row
        f_action_bar = ctk.CTkFrame(self.file_scroll, fg_color="transparent")
        f_action_bar.pack(fill="x", pady=8)

        self.btn_encrypt_files = ctk.CTkButton(
            f_action_bar,
            text="🔒 Encrypt File(s) (.enc)",
            font=get_font(13, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=40,
            command=self._do_encrypt_files,
        )
        self.btn_encrypt_files.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.btn_decrypt_files = ctk.CTkButton(
            f_action_bar,
            text="🔓 Decrypt File(s)",
            font=get_font(13, "bold"),
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=40,
            command=self._do_decrypt_files,
        )
        self.btn_decrypt_files.pack(side="left", fill="x", expand=True, padx=(8, 0))

        # Progress bar & Operation Log
        self.f_progress = ctk.CTkProgressBar(self.file_scroll, fg_color=BG_INPUT, progress_color=ACCENT_PRIMARY, height=8)
        self.f_progress.set(0)
        self.f_progress.pack(fill="x", pady=(10, 6))

        self.f_status_lbl = ctk.CTkLabel(self.file_scroll, text="Select files and specify passphrase to begin.", font=get_font(12), text_color=TEXT_MUTED)
        self.f_status_lbl.pack(anchor="w", pady=(0, 8))

        log_card = ctk.CTkFrame(self.file_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        log_card.pack(fill="x")

        ctk.CTkLabel(log_card, text="OPERATION LOG", font=get_font(10, "bold"), text_color=TEXT_MUTED).pack(anchor="w", padx=12, pady=(8, 2))
        self.f_log_box = ctk.CTkTextbox(log_card, font=get_mono_font(11), fg_color=BG_INPUT, height=120)
        self.f_log_box.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    def _toggle_file_key_visibility(self) -> None:
        self.f_key_entry.configure(show="" if self.f_show_key_var.get() else "*")

    def _generate_file_random_key(self) -> None:
        pwd = generate_secure_password(length=32)
        self.f_key_entry.delete(0, "end")
        self.f_key_entry.insert(0, pwd)
        self.f_status_lbl.configure(text="✓ Generated fresh 32-character encryption key", text_color=COLOR_SUCCESS)

    def _select_files(self) -> None:
        selected = filedialog.askopenfilenames(title="Select File(s) to Encrypt or Decrypt")
        if selected:
            for s in selected:
                p = Path(s)
                if p not in self.selected_files:
                    self.selected_files.append(p)
            # Default output directory to first file's directory if unset
            if not self.out_dir_var.get() and self.selected_files:
                self.out_dir_var.set(str(self.selected_files[0].parent))
            self._render_file_list()

    def _clear_selected_files(self) -> None:
        self.selected_files.clear()
        self._render_file_list()

    def _select_out_dir(self) -> None:
        folder = filedialog.askdirectory(title="Select Output Directory")
        if folder:
            self.out_dir_var.set(folder)

    def _render_file_list(self) -> None:
        for c in self.file_list_frame.winfo_children():
            c.destroy()

        if not self.selected_files:
            ctk.CTkLabel(
                self.file_list_frame,
                text="No files selected. Click '➕ Select File(s)...' to add single or multiple files.",
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(pady=20)
            return

        for idx, fp in enumerate(self.selected_files):
            row = ctk.CTkFrame(self.file_list_frame, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=4)

            # File icon/name
            icon = "🔒" if fp.name.endswith(".enc") else "📄"
            try:
                sz = fp.stat().st_size
                sz_str = f"{sz / 1024:.1f} KB" if sz < 1024 * 1024 else f"{sz / (1024 * 1024):.1f} MB"
            except Exception:
                sz_str = "Unknown"

            ctk.CTkLabel(row, text=f"{icon} {fp.name}", font=get_font(11, "bold"), text_color=TEXT_PRIMARY, anchor="w").pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(row, text=sz_str, font=get_mono_font(10), text_color=TEXT_MUTED, width=80).pack(side="left", padx=6)

            ctk.CTkButton(
                row,
                text="✕",
                font=get_font(10),
                width=24,
                height=22,
                fg_color="transparent",
                hover_color=COLOR_DANGER,
                text_color=TEXT_MUTED,
                command=lambda p=fp: self._remove_file(p),
            ).pack(side="right")

    def _remove_file(self, path: Path) -> None:
        if path in self.selected_files:
            self.selected_files.remove(path)
            self._render_file_list()

    def _log(self, text: str) -> None:
        self.f_log_box.insert("end", text + "\n")
        self.f_log_box.see("end")

    def _do_encrypt_files(self) -> None:
        if not self.selected_files:
            self.f_status_lbl.configure(text="Please select at least one file to encrypt.", text_color=COLOR_WARNING)
            return

        key = self.f_key_entry.get().strip()
        if not key:
            self.f_status_lbl.configure(text="Passphrase or encryption key is required.", text_color=COLOR_DANGER)
            return

        out_dir = self.out_dir_var.get().strip() or (str(self.selected_files[0].parent) if self.selected_files else "")
        cipher_choice = self.f_cipher_var.get().split()[0]

        self.btn_encrypt_files.configure(state="disabled")
        self.btn_decrypt_files.configure(state="disabled")
        self.f_progress.set(0)
        self.f_status_lbl.configure(text=f"Encrypting {len(self.selected_files)} file(s)...", text_color=COLOR_WARNING)
        self._log(f"--- Starting Bulk Encryption ({cipher_choice}) ---")

        def worker():
            total = len(self.selected_files)
            def progress(current, tot, msg):
                self.after(0, lambda: self.f_progress.set(current / tot))
                self.after(0, lambda: self._log(f"[{current}/{tot}] {msg}"))

            success_cnt, errors = bulk_encrypt_files(
                self.selected_files,
                out_dir,
                key,
                cipher=cipher_choice,
                progress_callback=progress,
            )

            def finish():
                self.f_progress.set(1.0)
                self.btn_encrypt_files.configure(state="normal")
                self.btn_decrypt_files.configure(state="normal")
                if errors:
                    self.f_status_lbl.configure(text=f"Completed with errors: {success_cnt}/{total} files encrypted.", text_color=COLOR_DANGER)
                    for err in errors:
                        self._log(f"ERROR: {err}")
                else:
                    self.f_status_lbl.configure(text=f"✓ Successfully encrypted {success_cnt} file(s) to '{out_dir}'.", text_color=COLOR_SUCCESS)
                    self._log(f"SUCCESS: All {success_cnt} files encrypted and written.")

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _do_decrypt_files(self) -> None:
        if not self.selected_files:
            self.f_status_lbl.configure(text="Please select at least one file to decrypt.", text_color=COLOR_WARNING)
            return

        key = self.f_key_entry.get().strip()
        if not key:
            self.f_status_lbl.configure(text="Passphrase or encryption key is required.", text_color=COLOR_DANGER)
            return

        out_dir = self.out_dir_var.get().strip() or (str(self.selected_files[0].parent) if self.selected_files else "")
        cipher_choice = self.f_cipher_var.get().split()[0]

        self.btn_encrypt_files.configure(state="disabled")
        self.btn_decrypt_files.configure(state="disabled")
        self.f_progress.set(0)
        self.f_status_lbl.configure(text=f"Decrypting {len(self.selected_files)} file(s)...", text_color=COLOR_WARNING)
        self._log(f"--- Starting Bulk Decryption ({cipher_choice}) ---")

        def worker():
            total = len(self.selected_files)
            def progress(current, tot, msg):
                self.after(0, lambda: self.f_progress.set(current / tot))
                self.after(0, lambda: self._log(f"[{current}/{tot}] {msg}"))

            success_cnt, errors = bulk_decrypt_files(
                self.selected_files,
                out_dir,
                key,
                cipher=cipher_choice,
                progress_callback=progress,
            )

            def finish():
                self.f_progress.set(1.0)
                self.btn_encrypt_files.configure(state="normal")
                self.btn_decrypt_files.configure(state="normal")
                if errors:
                    self.f_status_lbl.configure(text=f"Completed with errors: {success_cnt}/{total} files decrypted.", text_color=COLOR_DANGER)
                    for err in errors:
                        self._log(f"ERROR: {err}")
                else:
                    self.f_status_lbl.configure(text=f"✓ Successfully decrypted {success_cnt} file(s) to '{out_dir}'.", text_color=COLOR_SUCCESS)
                    self._log(f"SUCCESS: All {success_cnt} files decrypted.")

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()
