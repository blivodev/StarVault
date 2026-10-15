"""Crypto Tools Swiss Army Knife & Kleopatra-Style Keyring Studio for StarVault.

Unified cryptographic workbench providing:
1. 🔑 Keyring & Certs (Kleopatra-style Key Manager: PGP, SSH, TLS Certs, WireGuard, Age)
2. ⚡ Key Generator (Key Studio integrated: Ed25519, RSA4096, PGP, TLS Certs, WireGuard, Age)
3. 🔐 Encrypt & Decrypt (Symmetric & Asymmetric: AES-256-GCM/CBC, ChaCha20, RSA OAEP, OpenPGP)
4. ✍️ Sign & Verify (Asymmetric signatures: Ed25519, RSA-PSS, OpenPGP, ECDSA, HMAC)
5. 📁 File Encryption (Single & Bulk file encryption with military-grade ciphers)
6. #️⃣ Hashes & Encoders (SHA-224/256/384/512, SHA3, BLAKE2, MD5, RIPEMD160, Base64, Hex, URL, Binary)
"""

import base64
import os
from pathlib import Path
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Callable, List, Optional
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.crypto import generate_secure_password
from starvault.crypto_tools import (
    asym_sign,
    asym_verify,
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
    pgp_decrypt,
    pgp_encrypt,
    rsa_decrypt,
    rsa_encrypt,
)
from starvault.keys import (
    GeneratedKeyResult,
    export_key_armored,
    generate_age_key_result,
    generate_ed25519_key,
    generate_gpg_key,
    generate_rsa_key,
    generate_tls_cert_key,
    generate_wireguard_key_result,
    parse_and_import_key,
)
from starvault.models import VaultEntry
from starvault.ui.local_key_installer_dialog import LocalKeyInstallerDialog
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_CARD_HOVER,
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


class CryptoToolsView(ctk.CTkFrame):
    """Interactive encryption, decryption, encoding, hashing, and Kleopatra-style keyring workbench."""

    SUBTABS = [
        "Keyring & Certs",
        "Key Generator",
        "Encrypt & Decrypt",
        "Sign & Verify",
        "File Encryption",
        "Hashes & Encoders",
    ]

    SYMMETRIC_ALGOS = [
        "AES-256-GCM (Authenticated)",
        "ChaCha20-Poly1305 (AEAD)",
        "AES-256-CBC (PKCS7)",
    ]

    ASYMMETRIC_ALGOS = [
        "RSA OAEP (SHA-256)",
        "OpenPGP (GPG Armored)",
    ]

    SIGNING_ALGOS = [
        "Ed25519 (EdDSA)",
        "RSA-PSS (SHA-256)",
        "OpenPGP Detached",
        "HMAC-SHA256",
    ]

    HASH_ALGOS = [
        "SHA-256",
        "SHA-512",
        "SHA3-256",
        "SHA3-512",
        "BLAKE2b",
        "BLAKE2s",
        "SHA-384",
        "SHA-224",
        "MD5",
        "RIPEMD160",
    ]

    def __init__(
        self,
        parent,
        clipboard_mgr: ClipboardManager,
        database=None,
        session_key: Optional[bytes] = None,
        on_save_to_vault: Optional[Callable[[], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.clipboard_mgr = clipboard_mgr
        self.database = database
        self.session_key = session_key
        self.on_save_to_vault = on_save_to_vault

        self.selected_files: List[Path] = []
        self.keyring_entries: List[VaultEntry] = []
        self.selected_keyring_entry: Optional[VaultEntry] = None
        self.current_generated_key: Optional[GeneratedKeyResult] = None
        self._keyring_cards = {}

        self._build_ui()
        if self.database and self.session_key:
            self.reload_keyring()

    def update_session_key(self, new_key: bytes) -> None:
        self.session_key = new_key
        self.reload_keyring()

    # -------------------------------------------------------------------------
    # UI Layout & Subtab Navigation
    # -------------------------------------------------------------------------

    def _build_ui(self) -> None:
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=20, pady=10)

        ctk.CTkLabel(
            title_box,
            text="🛠️ Crypto Tools & Kleopatra Keyring Studio",
            font=get_font(17, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Key management, asymmetric encrypt/decrypt/signing, ciphers, hashing, and bulk file encryption",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Mode Selector Segmented Button
        self.nav_var = ctk.StringVar(value="🔑 Keyring & Certs")
        self.mode_seg = ctk.CTkSegmentedButton(
            header,
            values=self.SUBTABS,
            variable=self.nav_var,
            command=self._on_subtab_switched,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
        )
        self.mode_seg.pack(side="right", padx=16, pady=14)

        # Content container
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)

        # Workbenches are built lazily on first subtab switch so opening the
        # Crypto Tools tab doesn't construct all 6 heavy sub-views at once
        # (was ~2s of widget churn). Each frame is created once and kept.
        self._built_subtabs = set()
        self.keyring_frame = None
        self.generator_frame = None
        self.crypt_frame = None
        self.sign_frame = None
        self.file_frame = None
        self.hash_frame = None

        # Show initial subtab (builds the active workbench)
        self._on_subtab_switched("Keyring & Certs")

    def _ensure_subtab(self, mode: str) -> None:
        """Builds a sub-workbench frame the first time it's shown."""
        if mode in self._built_subtabs:
            return
        self._built_subtabs.add(mode)
        if "Keyring" in mode and self.keyring_frame is None:
            self._build_keyring_workbench()
        elif "Generator" in mode and self.generator_frame is None:
            self._build_generator_workbench()
        elif "File" in mode and self.file_frame is None:
            self._build_file_workbench()
        elif "Encrypt" in mode and self.crypt_frame is None:
            self._build_encrypt_decrypt_workbench()
        elif "Sign" in mode and self.sign_frame is None:
            self._build_sign_verify_workbench()
        elif "Hashes" in mode and self.hash_frame is None:
            self._build_hashes_workbench()

    def switch_to_subtab(self, subtab_name: str) -> None:
        """Programmatically switches to the specified subtab."""
        target = None
        # 1. Exact match
        for t in self.SUBTABS:
            if t.lower() == subtab_name.lower():
                target = t
                break
        # 2. Normalized alphanumeric match
        if not target:
            clean_subtab = "".join(c for c in subtab_name.lower() if c.isalnum())
            for t in self.SUBTABS:
                clean_t = "".join(c for c in t.lower() if c.isalnum())
                if clean_t == clean_subtab:
                    target = t
                    break
        # 3. Subtab name contained in input or input contained in subtab
        if not target:
            clean_subtab = "".join(c for c in subtab_name.lower() if c.isalnum())
            for t in self.SUBTABS:
                clean_t = "".join(c for c in t.lower() if c.isalnum())
                if clean_t in clean_subtab or (len(clean_subtab) >= 3 and clean_subtab in clean_t):
                    target = t
                    break
        if target:
            self.nav_var.set(target)
            self.mode_seg.set(target)
            self._on_subtab_switched(target)

    def _on_subtab_switched(self, mode: str) -> None:
        # Ensure the target workbench is built (lazy on first use)
        self._ensure_subtab(mode)

        # Hide all workbench frames
        for frame in [
            self.keyring_frame,
            self.generator_frame,
            self.crypt_frame,
            self.sign_frame,
            self.file_frame,
            self.hash_frame,
        ]:
            if frame is not None:
                frame.pack_forget()

        if "Keyring" in mode:
            self.keyring_frame.pack(fill="both", expand=True, padx=20, pady=16)
            self.reload_keyring()
        elif "Generator" in mode:
            self.generator_frame.pack(fill="both", expand=True, padx=20, pady=16)
        elif "File" in mode:
            self.file_frame.pack(fill="both", expand=True, padx=20, pady=16)
        elif "Encrypt" in mode:
            self.crypt_frame.pack(fill="both", expand=True, padx=20, pady=16)
            self._refresh_vault_key_dropdown()
        elif "Sign" in mode:
            self.sign_frame.pack(fill="both", expand=True, padx=20, pady=16)
            self._refresh_sign_key_dropdown()
        elif "Hashes" in mode:
            self.hash_frame.pack(fill="both", expand=True, padx=20, pady=16)

    # -------------------------------------------------------------------------
    # 1. Kleopatra-Style Keyring & Certs Manager
    # -------------------------------------------------------------------------

    def _build_keyring_workbench(self) -> None:
        self.keyring_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        # Top Action Toolbar (Search + Import + Refresh)
        toolbar = ctk.CTkFrame(self.keyring_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        toolbar.pack(fill="x", pady=(0, 12))

        tb_inner = ctk.CTkFrame(toolbar, fg_color="transparent")
        tb_inner.pack(fill="x", padx=12, pady=10)

        ctk.CTkLabel(tb_inner, text="🔍", font=get_font(12), text_color=TEXT_MUTED).pack(side="left", padx=(4, 6))
        self.key_search_entry = ctk.CTkEntry(
            tb_inner,
            placeholder_text="Search keys by label, fingerprint, algorithm, or comment...",
            font=get_font(12),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            width=360,
        )
        self.key_search_entry.pack(side="left", padx=(0, 12))
        self.key_search_entry.bind("<KeyRelease>", lambda e: self._filter_keyring())

        ctk.CTkButton(
            tb_inner,
            text="💻 Local Key Installer...",
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            height=34,
            command=self._open_local_key_installer,
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            tb_inner,
            text="📥 Import Key / Cert...",
            font=get_font(11, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=34,
            command=self._open_import_key_dialog,
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            tb_inner,
            text="⚡ Generate New...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            command=lambda: self.switch_to_subtab("⚡ Key Generator"),
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            tb_inner,
            text="🔄 Refresh",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            height=34,
            command=self.reload_keyring,
        ).pack(side="right", padx=4)

        # Split body: Left Key List + Right Key Inspector
        split = ctk.CTkFrame(self.keyring_frame, fg_color="transparent")
        split.pack(fill="both", expand=True)

        self.key_list_scroll = ctk.CTkScrollableFrame(split, fg_color=BG_ROOT)
        self.key_list_scroll.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Right Inspector Card
        self.key_details_card = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR, width=380)
        self.key_details_card.pack(side="right", fill="both")
        self._render_key_details_empty()

    def reload_keyring(self) -> None:
        """Fetches all keypair entries from the active vault and renders them."""
        if not self.database or not self.session_key:
            return
        try:
            all_entries = self.database.get_all_entries(self.session_key)
            self.keyring_entries = [e for e in all_entries if e.entry_type in ("keypair", "identity")]
        except Exception:
            self.keyring_entries = []
        self._filter_keyring()

    def _filter_keyring(self) -> None:
        q = self.key_search_entry.get().strip().lower() if hasattr(self, "key_search_entry") else ""
        filtered = []
        for k in self.keyring_entries:
            match = (
                not q
                or q in k.title.lower()
                or q in getattr(k, "key_type", "").lower()
                or q in getattr(k, "fingerprint", "").lower()
                or any(q in t.lower() for t in k.tags)
            )
            if match:
                filtered.append(k)

        if not filtered:
            self._keyring_cards.clear()
            for child in self.key_list_scroll.winfo_children():
                child.destroy()
            box = tk.Frame(self.key_list_scroll, bg=self._key_bg())
            box.pack(pady=40)
            tk.Label(box, text="No keys or certificates found in vault keyring.", bg=self._key_bg(), fg=TEXT_MUTED,
                     font=("Segoe UI", 12)).pack()
            tk.Button(
                box,
                text="📥 Import Key from File or Clipboard",
                bg=ACCENT_PRIMARY, fg="#000000", relief="flat", bd=0, highlightthickness=0,
                activebackground=ACCENT_PRIMARY, activeforeground="#000000",
                font=("Segoe UI", 11, "bold"), cursor="hand2", padx=12, pady=4,
                command=self._open_import_key_dialog,
            ).pack(pady=10)
            return

        # Incremental: reuse cards whose entry is unchanged, destroy the rest.
        new_ids = {k.id for k in filtered}
        for eid in [k for k in self._keyring_cards if k not in new_ids]:
            try:
                self._keyring_cards[eid].destroy()
            except Exception:
                pass
            del self._keyring_cards[eid]

        for entry in filtered:
            card = self._keyring_cards.get(entry.id)
            if card is None:
                card = self._render_keyring_card(entry)
                self._keyring_cards[entry.id] = card

    def _key_bg(self) -> str:
        """Returns the background color of the keyring scroll frame."""
        try:
            return self.key_list_scroll.cget("fg_color")
        except Exception:
            return "#000000"

    def _render_keyring_card(self, entry: VaultEntry) -> tk.Frame:
        is_sel = self.selected_keyring_entry and self.selected_keyring_entry.id == entry.id
        card = tk.Frame(
            self.key_list_scroll,
            bg=BG_CARD_HOVER if is_sel else BG_CARD,
            highlightbackground=ACCENT_PRIMARY if is_sel else BORDER_COLOR,
            highlightthickness=2 if is_sel else 1,
        )
        card.pack(fill="x", pady=4, padx=4)
        card.bind("<Button-1>", lambda e, ent=entry: self._select_keyring_entry(ent))

        inner = tk.Frame(card, bg=card["bg"])
        inner.pack(fill="x", padx=12, pady=10)
        inner.bind("<Button-1>", lambda e, ent=entry: self._select_keyring_entry(ent))

        # Top row: Algorithm Badge + Title + Key Status
        top = tk.Frame(inner, bg=card["bg"])
        top.pack(fill="x")
        top.bind("<Button-1>", lambda e, ent=entry: self._select_keyring_entry(ent))

        kt = getattr(entry, "key_type", "keypair").upper()
        badge_color = ACCENT_PURPLE if kt in ("ED25519", "RSA4096") else (COLOR_WARNING if "GPG" in kt else ACCENT_PRIMARY)
        tk.Label(
            top,
            text=f"🔑 {kt}",
            bg=BG_INPUT,
            fg=badge_color,
            font=("Segoe UI", 10, "bold"),
            padx=6,
            pady=2,
        ).pack(side="left", padx=(0, 8))

        tk.Label(
            top,
            text=entry.title,
            bg=card["bg"],
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 13, "bold"),
        ).pack(side="left")

        # Has Private Key indicator
        has_priv = bool(getattr(entry, "private_key", "").strip())
        priv_badge = "🔒 Keypair (Priv+Pub)" if has_priv else "🌐 Public Key Only"
        priv_color = COLOR_SUCCESS if has_priv else TEXT_MUTED
        tk.Label(
            top,
            text=priv_badge,
            bg=BG_INPUT,
            fg=priv_color,
            font=("Segoe UI", 10),
            padx=6,
            pady=2,
        ).pack(side="right")

        # Subtitle: Fingerprint & Created
        fp = getattr(entry, "fingerprint", "") or "No fingerprint recorded"
        sub_text = f"Fingerprint: {fp[:36]}..." if len(fp) > 36 else f"Fingerprint: {fp}"
        if entry.created_at:
            sub_text += f" • Created: {entry.created_at[:10]}"

        tk.Label(
            inner,
            text=sub_text,
            bg=card["bg"],
            fg=TEXT_MUTED,
            font=("Consolas", 10),
            anchor="w",
            justify="left",
        ).pack(fill="x", pady=(4, 6))

        # Quick action buttons
        btn_row = tk.Frame(inner, bg=card["bg"])
        btn_row.pack(fill="x")

        def gbtn(text, fg, command, bold=False, width=None):
            b = tk.Button(
                btn_row,
                text=text,
                bg=BG_INPUT,
                fg=fg,
                activebackground=BG_INPUT,
                activeforeground=fg,
                relief="flat",
                bd=0,
                highlightthickness=0,
                padx=8,
                pady=2,
                font=("Segoe UI", 9, "bold" if bold else "normal"),
                cursor="hand2",
                command=command,
            )
            b.pack(side="left", padx=(0, 4))
            return b

        gbtn("🔐 Use to Encrypt/Decrypt", ACCENT_PRIMARY, lambda ent=entry: self._use_key_for_encrypt_decrypt(ent), bold=True)
        gbtn("✍️ Use to Sign/Verify", TEXT_PRIMARY, lambda ent=entry: self._use_key_for_sign_verify(ent))
        gbtn("💻 Install...", ACCENT_PRIMARY, lambda ent=entry: self._open_local_key_installer(preselected=ent))
        gbtn("📤 Export...", TEXT_SECONDARY, lambda ent=entry: self._open_export_key_dialog(ent))

        return card

    def _select_keyring_entry(self, entry: VaultEntry) -> None:
        self.selected_keyring_entry = entry
        self._filter_keyring()
        self._render_key_details(entry)

    def _render_key_details_empty(self) -> None:
        for child in self.key_details_card.winfo_children():
            child.destroy()
        ctk.CTkLabel(
            self.key_details_card,
            text="Select a key from the keyring\nto view metadata and certificates.",
            font=get_font(12),
            text_color=TEXT_MUTED,
            justify="center",
        ).pack(expand=True, pady=40)

    def _render_key_details(self, entry: VaultEntry) -> None:
        for child in self.key_details_card.winfo_children():
            child.destroy()

        scroll = ctk.CTkScrollableFrame(self.key_details_card, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(scroll, text=entry.title, font=get_font(15, "bold"), text_color=TEXT_PRIMARY, wraplength=340).pack(anchor="w")

        kt = getattr(entry, "key_type", "Key").upper()
        ctk.CTkLabel(scroll, text=f"Type: {kt}", font=get_font(12, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", pady=(2, 8))

        # Fingerprint box
        fp = getattr(entry, "fingerprint", "") or "N/A"
        ctk.CTkLabel(scroll, text="Fingerprint:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w")
        fp_box = ctk.CTkTextbox(scroll, height=50, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
        fp_box.insert("1.0", fp)
        fp_box.configure(state="disabled")
        fp_box.pack(fill="x", pady=(2, 8))

        # Public Key preview
        pub = getattr(entry, "public_key", "")
        if pub:
            ctk.CTkLabel(scroll, text="Public Key / Certificate:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w")
            pub_box = ctk.CTkTextbox(scroll, height=110, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
            pub_box.insert("1.0", pub)
            pub_box.configure(state="disabled")
            pub_box.pack(fill="x", pady=(2, 6))

            ctk.CTkButton(
                scroll,
                text="📋 Copy Public Key",
                font=get_font(11),
                fg_color=BG_INPUT,
                hover_color=BORDER_COLOR,
                text_color=TEXT_PRIMARY,
                height=28,
                command=lambda: self.clipboard_mgr.copy(pub, "Public key copied"),
            ).pack(fill="x", pady=(0, 10))

        # Private Key status
        has_priv = bool(getattr(entry, "private_key", "").strip())
        priv_text = "✓ Private Key Present (Stored Encrypted)" if has_priv else "✗ Private Key Not Stored"
        priv_color = COLOR_SUCCESS if has_priv else TEXT_MUTED
        ctk.CTkLabel(scroll, text=priv_text, font=get_font(11, "bold"), text_color=priv_color).pack(anchor="w", pady=(4, 8))

        # Keyring actions
        ctk.CTkButton(
            scroll,
            text="🔐 Encrypt / Decrypt with This Key",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=34,
            command=lambda: self._use_key_for_encrypt_decrypt(entry),
        ).pack(fill="x", pady=4)

        ctk.CTkButton(
            scroll,
            text="✍️ Sign / Verify with This Key",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            command=lambda: self._use_key_for_sign_verify(entry),
        ).pack(fill="x", pady=4)

        ctk.CTkButton(
            scroll,
            text="💻 Install to Local System (~/.ssh)...",
            font=get_font(12, "bold"),
            fg_color=ACCENT_INDIGO,
            hover_color=ACCENT_HOVER,
            text_color="#ffffff",
            height=34,
            command=lambda: self._open_local_key_installer(preselected=entry),
        ).pack(fill="x", pady=4)

        ctk.CTkButton(
            scroll,
            text="📤 Export Armored Key File...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            height=30,
            command=lambda: self._open_export_key_dialog(entry),
        ).pack(fill="x", pady=4)

        ctk.CTkButton(
            scroll,
            text="🗑️ Delete Key from Keyring",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            text_color=COLOR_DANGER,
            height=30,
            command=lambda: self._confirm_delete_key(entry),
        ).pack(fill="x", pady=(12, 0))

    def _open_import_key_dialog(self) -> None:
        """Modal dialog to import armored PGP, SSH, TLS Cert, WireGuard, or Age keys."""
        modal = ctk.CTkToplevel(self)
        modal.title("Import Key / Certificate into Keyring")
        modal.geometry("560x520")
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(modal, text="📥 Import Key or Certificate", font=get_font(16, "bold"), text_color=TEXT_PRIMARY).pack(pady=(16, 4))
        ctk.CTkLabel(
            modal,
            text="Paste armored OpenPGP, SSH public/private, X.509 TLS certificate, WireGuard, or Age key.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=480,
            justify="center",
        ).pack(pady=(0, 10))

        # Key Label entry
        lbl_frame = ctk.CTkFrame(modal, fg_color="transparent")
        lbl_frame.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(lbl_frame, text="Key Name / Label (Optional):", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        name_entry = ctk.CTkEntry(lbl_frame, placeholder_text="e.g. Work GPG Key, Prod Server SSH", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
        name_entry.pack(fill="x", pady=(4, 0))

        # Key Text Box
        txt_frame = ctk.CTkFrame(modal, fg_color="transparent")
        txt_frame.pack(fill="both", expand=True, padx=24, pady=8)
        ctk.CTkLabel(txt_frame, text="Key Material (Paste armored ASCII or OpenSSH):", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        key_textbox = ctk.CTkTextbox(txt_frame, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        key_textbox.pack(fill="both", expand=True, pady=(4, 0))

        # File load button & status
        btn_bar = ctk.CTkFrame(modal, fg_color="transparent")
        btn_bar.pack(fill="x", padx=24, pady=(4, 16))

        def load_from_file():
            p = filedialog.askopenfilename(
                title="Select Key File",
                filetypes=[
                    ("All Key Files", "*.asc;*.gpg;*.pub;*.pem;*.key;*.crt;*.cer;*.age"),
                    ("Armored PGP", "*.asc;*.gpg"),
                    ("SSH & PEM", "*.pub;*.pem;*.key"),
                    ("Certificates", "*.crt;*.cer;*.pem"),
                    ("All Files", "*.*"),
                ],
            )
            if p:
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    key_textbox.delete("1.0", "end")
                    key_textbox.insert("1.0", content)
                    if not name_entry.get().strip():
                        name_entry.insert(0, Path(p).stem)
                except Exception as ex:
                    messagebox.showerror("Read Error", f"Could not read key file:\n{ex}")

        ctk.CTkButton(
            btn_bar,
            text="📂 Load from File...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=load_from_file,
        ).pack(side="left")

        def do_import():
            raw = key_textbox.get("1.0", "end").strip()
            if not raw:
                messagebox.showwarning("Missing Key", "Please paste or load key content before importing.")
                return
            if not self.database or not self.session_key:
                messagebox.showerror("Error", "No unlocked vault session available to store key.")
                return

            try:
                k_name = name_entry.get().strip()
                entry = parse_and_import_key(raw, key_name=k_name)
                self.database.save_entry(entry, self.session_key)
                if self.on_save_to_vault:
                    self.on_save_to_vault()
                self.reload_keyring()
                modal.destroy()
                messagebox.showinfo("Key Imported", f"Successfully imported '{entry.title}' into vault keyring!")
            except Exception as ex:
                messagebox.showerror("Import Failed", f"Could not parse key:\n{ex}")

        ctk.CTkButton(
            btn_bar,
            text="✓ Save to Keyring",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=do_import,
        ).pack(side="right")

    def _open_export_key_dialog(self, entry: VaultEntry) -> None:
        """Export key in armored format (Public, Private, or Full Bundle)."""
        modal = ctk.CTkToplevel(self)
        modal.title(f"Export Key - {entry.title}")
        modal.geometry("520x460")
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(modal, text=f"📤 Export: {entry.title}", font=get_font(15, "bold"), text_color=TEXT_PRIMARY).pack(pady=(16, 4))

        has_priv = bool(getattr(entry, "private_key", "").strip())
        which_var = ctk.StringVar(value="public")

        opt_frame = ctk.CTkFrame(modal, fg_color="transparent")
        opt_frame.pack(pady=8)

        vals = ["public", "bundle"]
        if has_priv:
            vals.append("private")

        which_seg = ctk.CTkSegmentedButton(
            opt_frame,
            values=["Public Key", "Private Key" if has_priv else "No Private", "Full Bundle"],
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            text_color=TEXT_PRIMARY,
            command=lambda v: update_preview(v),
        )
        which_seg.set("Public Key")
        which_seg.pack()

        preview_box = ctk.CTkTextbox(modal, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
        preview_box.pack(fill="both", expand=True, padx=20, pady=8)

        def get_current_export(choice: str) -> str:
            target = "public"
            if "Private" in choice:
                target = "private"
            elif "Bundle" in choice:
                target = "bundle"
            return export_key_armored(entry, which=target)

        def update_preview(choice: str):
            armored = get_current_export(choice)
            preview_box.delete("1.0", "end")
            preview_box.insert("1.0", armored)

        update_preview("Public Key")

        act_bar = ctk.CTkFrame(modal, fg_color="transparent")
        act_bar.pack(fill="x", padx=20, pady=(4, 16))

        def copy_armored():
            armored = get_current_export(which_seg.get())
            is_sensitive = "Private" in which_seg.get() or "Bundle" in which_seg.get()
            self.clipboard_mgr.copy(armored, "Armored key copied to clipboard", is_sensitive=is_sensitive)

        def save_armored_file():
            armored = get_current_export(which_seg.get())
            ext = ".asc" if "GPG" in getattr(entry, "key_type", "").upper() else (".pub" if "Public" in which_seg.get() else ".pem")
            fn = f"{entry.title.replace(' ', '_').lower()}{ext}"
            p = filedialog.asksaveasfilename(initialfile=fn, defaultextension=ext)
            if p:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(armored)
                messagebox.showinfo("Export Successful", f"Key written to {p}")

        ctk.CTkButton(act_bar, text="📋 Copy to Clipboard", font=get_font(11), fg_color=BG_INPUT, text_color=TEXT_PRIMARY, command=copy_armored).pack(side="left", padx=(0, 6))
        ctk.CTkButton(act_bar, text="💾 Save to File...", font=get_font(11, "bold"), fg_color=ACCENT_PRIMARY, text_color="#000000", command=save_armored_file).pack(side="right")

    def _confirm_delete_key(self, entry: VaultEntry) -> None:
        ans = messagebox.askyesno("Confirm Deletion", f"Permanently delete key '{entry.title}' from the vault?\n\nThis cannot be undone.")
        if ans and self.database and self.session_key:
            self.database.delete_entry(entry.id)
            if self.on_save_to_vault:
                self.on_save_to_vault()
            self.selected_keyring_entry = None
            self._render_key_details_empty()
            self.reload_keyring()

    def _open_local_key_installer(self, preselected: Optional[VaultEntry] = None) -> None:
        """Opens the Local Key Installer & Manager dialog."""
        LocalKeyInstallerDialog(
            self,
            database=self.database,
            session_key=self.session_key,
            clipboard_mgr=self.clipboard_mgr,
            preselected_entry=preselected,
            on_vault_updated=self.reload_keyring,
        )

    def _install_generated_key_locally(self) -> None:
        """Opens the local installer preloaded with the freshly generated keypair."""
        if not self.current_generated_key:
            messagebox.showwarning("No Key", "Please generate a keypair first.")
            return
        res = self.current_generated_key
        temp_entry = VaultEntry.create_keypair(
            title=res.key_name or f"{res.key_type.upper()} Key",
            key_name=res.key_name or "generated_key",
            key_type=res.key_type,
            public_key=res.public_key,
            private_key=res.private_key,
            fingerprint=res.fingerprint,
        )
        self._open_local_key_installer(preselected=temp_entry)

    # -------------------------------------------------------------------------
    # 2. Integrated Key Generator Workbench
    # -------------------------------------------------------------------------

    def _build_generator_workbench(self) -> None:
        self.generator_frame = ctk.CTkScrollableFrame(self.content_frame, fg_color=BG_ROOT)

        gen_card = ctk.CTkFrame(self.generator_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        gen_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(gen_card, text="⚡ ASYMMETRIC KEYPAIR & CERTIFICATE GENERATOR", font=get_font(12, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))

        # Algorithm Selection
        row_algo = ctk.CTkFrame(gen_card, fg_color="transparent")
        row_algo.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row_algo, text="Algorithm / Format:", font=get_font(12, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w")

        self.gen_algo_var = ctk.StringVar(value="ed25519")
        algo_seg = ctk.CTkSegmentedButton(
            row_algo,
            values=["ed25519", "rsa4096", "gpg", "tls_cert", "wireguard", "age"],
            variable=self.gen_algo_var,
            command=self._on_gen_algo_changed,
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=get_font(11, "bold"),
            height=36,
        )
        algo_seg.pack(fill="x", pady=(4, 8))

        # Parameters container
        self.gen_params_container = ctk.CTkFrame(gen_card, fg_color="transparent")
        self.gen_params_container.pack(fill="x", padx=16, pady=(0, 8))
        self._render_gen_params("ed25519")

        # Generate Action Button
        act_row = ctk.CTkFrame(gen_card, fg_color="transparent")
        act_row.pack(fill="x", padx=16, pady=(4, 16))

        self.gen_submit_btn = ctk.CTkButton(
            act_row,
            text="⚡ Generate New Keypair",
            font=get_font(13, "bold"),
            height=40,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=self._start_key_generation,
        )
        self.gen_submit_btn.pack(side="left", padx=(0, 12))

        self.gen_status_lbl = ctk.CTkLabel(act_row, text="", font=get_font(12), text_color=TEXT_SECONDARY)
        self.gen_status_lbl.pack(side="left")

        # Output Card (Public / Private Key displays)
        out_card = ctk.CTkFrame(self.generator_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        out_card.pack(fill="x", padx=4)

        ctk.CTkLabel(out_card, text="GENERATED KEYPAIR OUTPUT", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))

        # Public key box
        ctk.CTkLabel(out_card, text="Public Key / Certificate:", font=get_font(12, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(4, 2))
        self.gen_pub_text = ctk.CTkTextbox(out_card, height=100, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
        self.gen_pub_text.pack(fill="x", padx=16, pady=(0, 6))

        # Private key box
        priv_hdr = ctk.CTkFrame(out_card, fg_color="transparent")
        priv_hdr.pack(fill="x", padx=16, pady=(4, 2))
        ctk.CTkLabel(priv_hdr, text="Private Key (Sensitive):", font=get_font(12, "bold"), text_color=COLOR_WARNING).pack(side="left")

        self.gen_priv_text = ctk.CTkTextbox(out_card, height=110, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
        self.gen_priv_text.pack(fill="x", padx=16, pady=(0, 12))

        # Action bar (Save to Keyring, Copy, Download)
        save_row = ctk.CTkFrame(out_card, fg_color="transparent")
        save_row.pack(fill="x", padx=16, pady=(0, 16))

        self.gen_save_vault_btn = ctk.CTkButton(
            save_row,
            text="💾 Save Directly to Vault Keyring",
            font=get_font(12, "bold"),
            fg_color=COLOR_SUCCESS,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=36,
            command=self._save_generated_key_to_vault,
        )
        self.gen_save_vault_btn.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            save_row,
            text="📋 Copy Public Key",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
            command=lambda: self.clipboard_mgr.copy(self.gen_pub_text.get("1.0", "end").strip(), "Public key copied"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            save_row,
            text="📋 Copy Private Key",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_WARNING,
            height=36,
            command=lambda: self.clipboard_mgr.copy(self.gen_priv_text.get("1.0", "end").strip(), "Private key copied (auto-wipe)", is_sensitive=True),
        ).pack(side="left", padx=4)

        # Local PC Export Bar
        exp_row = ctk.CTkFrame(out_card, fg_color="transparent")
        exp_row.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkLabel(exp_row, text="💾 Export to Local PC:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            exp_row,
            text="Save Public Key / Cert...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
            command=lambda: self._export_generated_key("public"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            exp_row,
            text="Save Private Key...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_WARNING,
            height=32,
            command=lambda: self._export_generated_key("private"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            exp_row,
            text="📦 Export Keypair Bundle to Folder...",
            font=get_font(11, "bold"),
            fg_color=ACCENT_INDIGO,
            hover_color=ACCENT_HOVER,
            text_color="#ffffff",
            height=32,
            command=self._export_generated_bundle,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            exp_row,
            text="💻 Install to System (~/.ssh)...",
            font=get_font(11, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=32,
            command=self._install_generated_key_locally,
        ).pack(side="left", padx=4)


    def _on_gen_algo_changed(self, algo: str) -> None:
        self._render_gen_params(algo)

    def _render_gen_params(self, algo: str) -> None:
        for child in self.gen_params_container.winfo_children():
            child.destroy()

        if algo in ("ed25519", "rsa4096"):
            ctk.CTkLabel(self.gen_params_container, text="Key Comment / Identification", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gen_comment_entry = ctk.CTkEntry(self.gen_params_container, placeholder_text="e.g. root@homelab, dev-deploy", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gen_comment_entry.insert(0, f"starvault-{algo}")
            self.gen_comment_entry.pack(fill="x", pady=(4, 0))

        elif algo == "gpg":
            row = ctk.CTkFrame(self.gen_params_container, fg_color="transparent")
            row.pack(fill="x")
            col_name = ctk.CTkFrame(row, fg_color="transparent")
            col_name.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkLabel(col_name, text="User Name *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gen_gpg_name = ctk.CTkEntry(col_name, placeholder_text="Admin", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gen_gpg_name.insert(0, "Homelab Admin")
            self.gen_gpg_name.pack(fill="x", pady=(4, 0))

            col_email = ctk.CTkFrame(row, fg_color="transparent")
            col_email.pack(side="right", fill="x", expand=True, padx=(6, 0))
            ctk.CTkLabel(col_email, text="Email *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gen_gpg_email = ctk.CTkEntry(col_email, placeholder_text="admin@domain.local", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gen_gpg_email.insert(0, "admin@starvault.local")
            self.gen_gpg_email.pack(fill="x", pady=(4, 0))

        elif algo == "tls_cert":
            row = ctk.CTkFrame(self.gen_params_container, fg_color="transparent")
            row.pack(fill="x")
            col_cn = ctk.CTkFrame(row, fg_color="transparent")
            col_cn.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkLabel(col_cn, text="Common Name (Domain / Host)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gen_tls_cn = ctk.CTkEntry(col_cn, placeholder_text="vault.local, *.homelab.net", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gen_tls_cn.insert(0, "starvault.local")
            self.gen_tls_cn.pack(fill="x", pady=(4, 0))

            col_days = ctk.CTkFrame(row, fg_color="transparent", width=140)
            col_days.pack(side="right")
            ctk.CTkLabel(col_days, text="Validity (Days)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gen_tls_days = ctk.CTkEntry(col_days, width=120, fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gen_tls_days.insert(0, "365")
            self.gen_tls_days.pack(fill="x", pady=(4, 0))

        elif algo in ("wireguard", "age"):
            ctk.CTkLabel(
                self.gen_params_container,
                text=f"Generates military-grade cryptographic keypair ({'Curve25519 VPN' if algo == 'wireguard' else 'X25519 Age file encryption'}).",
                font=get_font(12),
                text_color=TEXT_SECONDARY,
            ).pack(anchor="w", pady=4)

    def _start_key_generation(self) -> None:
        algo = self.gen_algo_var.get()
        self.gen_submit_btn.configure(state="disabled")
        self.gen_status_lbl.configure(text="Generating keypair...", text_color=ACCENT_PRIMARY)

        def worker():
            try:
                res: Optional[GeneratedKeyResult] = None
                if algo == "ed25519":
                    cmt = self.gen_comment_entry.get().strip() if hasattr(self, "gen_comment_entry") else "starvault"
                    res = generate_ed25519_key(comment=cmt)
                elif algo == "rsa4096":
                    cmt = self.gen_comment_entry.get().strip() if hasattr(self, "gen_comment_entry") else "starvault"
                    res = generate_rsa_key(bits=4096, comment=cmt)
                elif algo == "gpg":
                    name = self.gen_gpg_name.get().strip() or "User"
                    email = self.gen_gpg_email.get().strip() or "user@domain.local"
                    res = generate_gpg_key(name=name, email=email)
                elif algo == "tls_cert":
                    cn = self.gen_tls_cn.get().strip() or "localhost"
                    try:
                        days = int(self.gen_tls_days.get().strip())
                    except Exception:
                        days = 365
                    res = generate_tls_cert_key(common_name=cn, valid_days=days, san_domains=[cn])
                elif algo == "wireguard":
                    res = generate_wireguard_key_result()
                elif algo == "age":
                    res = generate_age_key_result()

                def update_ui():
                    self.current_generated_key = res
                    self.gen_submit_btn.configure(state="normal")
                    self.gen_status_lbl.configure(text="✓ Keypair generated successfully!", text_color=COLOR_SUCCESS)
                    self.gen_pub_text.delete("1.0", "end")
                    self.gen_pub_text.insert("1.0", res.public_key)
                    self.gen_priv_text.delete("1.0", "end")
                    self.gen_priv_text.insert("1.0", res.private_key)

                self.after(0, update_ui)
            except Exception as ex:
                def on_err():
                    self.gen_submit_btn.configure(state="normal")
                    self.gen_status_lbl.configure(text=f"Failed: {ex}", text_color=COLOR_DANGER)
                self.after(0, on_err)

        threading.Thread(target=worker, daemon=True).start()

    def _save_generated_key_to_vault(self) -> None:
        if not self.current_generated_key:
            messagebox.showwarning("No Key", "Please generate a key first.")
            return
        if not self.database or not self.session_key:
            messagebox.showerror("Error", "No unlocked vault session available to save key.")
            return

        res = self.current_generated_key
        entry = VaultEntry.create_keypair(
            title=res.key_name or f"{res.key_type.upper()} Key",
            key_name=res.key_name,
            key_type=res.key_type,
            public_key=res.public_key,
            private_key=res.private_key,
            fingerprint=res.fingerprint,
            tags=[res.key_type, "generated"],
            category="Keys",
        )
        self.database.save_entry(entry, self.session_key)
        if self.on_save_to_vault:
            self.on_save_to_vault()
        self.reload_keyring()
        messagebox.showinfo("Saved", f"'{entry.title}' saved to your vault keyring successfully!")

    def _export_generated_key(self, which: str = "public") -> None:
        if not self.current_generated_key:
            messagebox.showwarning("No Key", "Please generate a keypair first.")
            return

        res = self.current_generated_key
        raw_name = res.key_name or res.key_type
        clean_name = "".join(c for c in raw_name if c.isalnum() or c in "-_") or "id_key"
        kt = res.key_type.lower()

        if which == "public":
            content = res.public_key
            if "tls" in kt:
                ext = ".crt"
                title = "Save TLS Certificate"
                ft = [("Certificate", "*.crt;*.cer;*.pem"), ("All Files", "*.*")]
            elif "wireguard" in kt:
                ext = ".wg.pub"
                title = "Save WireGuard Public Key"
                ft = [("WireGuard Public Key", "*.wg.pub"), ("All Files", "*.*")]
            elif "age" in kt:
                ext = ".recipient.txt"
                title = "Save Age Recipient Public Key"
                ft = [("Age Recipient Key", "*.recipient.txt;*.txt"), ("All Files", "*.*")]
            elif "gpg" in kt:
                ext = ".asc"
                title = "Save OpenPGP Public Key"
                ft = [("Armored PGP Key", "*.asc"), ("All Files", "*.*")]
            else:
                ext = ".pub"
                title = "Save OpenSSH Public Key"
                ft = [("OpenSSH Public Key", "*.pub"), ("All Files", "*.*")]

            p = filedialog.asksaveasfilename(title=title, initialfile=f"{clean_name}{ext}", filetypes=ft)
            if p:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export Successful", f"Saved public key to:\n{p}")

        else:
            content = res.private_key
            if "tls" in kt:
                ext = ".key"
                title = "Save Private Key"
                ft = [("Private Key", "*.key;*.pem"), ("All Files", "*.*")]
            elif "wireguard" in kt:
                ext = ".wg.key"
                title = "Save WireGuard Private Key"
                ft = [("WireGuard Private Key", "*.wg.key"), ("All Files", "*.*")]
            elif "age" in kt:
                ext = ".key"
                title = "Save Age Private Key"
                ft = [("Age Private Key", "*.key;*.txt"), ("All Files", "*.*")]
            elif "gpg" in kt:
                ext = "_private.asc"
                title = "Save OpenPGP Private Key"
                ft = [("Armored PGP Key", "*.asc"), ("All Files", "*.*")]
            else:
                ext = ".pem"
                title = "Save Private Key"
                ft = [("PEM Private Key", "*.pem;*.key"), ("All Files", "*.*")]

            p = filedialog.asksaveasfilename(title=title, initialfile=f"{clean_name}{ext}", filetypes=ft)
            if p:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export Successful", f"Saved private key to:\n{p}")

    def _export_generated_bundle(self) -> None:
        if not self.current_generated_key:
            messagebox.showwarning("No Key", "Please generate a keypair first.")
            return

        res = self.current_generated_key
        raw_name = res.key_name or res.key_type
        clean_name = "".join(c for c in raw_name if c.isalnum() or c in "-_") or "id_key"
        kt = res.key_type.lower()

        folder = filedialog.askdirectory(title="Select Destination Folder for Keypair Bundle")
        if not folder:
            return

        folder_p = Path(folder)
        if "tls" in kt:
            pub_path = folder_p / f"{clean_name}.crt"
            priv_path = folder_p / f"{clean_name}.key"
        elif "wireguard" in kt:
            pub_path = folder_p / f"{clean_name}.wg.pub"
            priv_path = folder_p / f"{clean_name}.wg.key"
        elif "age" in kt:
            pub_path = folder_p / f"{clean_name}.recipient.txt"
            priv_path = folder_p / f"{clean_name}.key"
        elif "gpg" in kt:
            pub_path = folder_p / f"{clean_name}_public.asc"
            priv_path = folder_p / f"{clean_name}_private.asc"
        else:
            pub_path = folder_p / f"{clean_name}.pub"
            priv_path = folder_p / f"{clean_name}.pem"

        pub_path.write_text(res.public_key, encoding="utf-8")
        priv_path.write_text(res.private_key, encoding="utf-8")

        messagebox.showinfo(
            "Bundle Exported",
            f"Successfully exported keypair to:\n\n• {pub_path.name}\n• {priv_path.name}\n\nFolder: {folder}",
        )


    # -------------------------------------------------------------------------
    # 3. Encrypt & Decrypt Workbench (Symmetric & Asymmetric)
    # -------------------------------------------------------------------------

    def _build_encrypt_decrypt_workbench(self) -> None:
        self.crypt_frame = ctk.CTkScrollableFrame(self.content_frame, fg_color=BG_ROOT)

        # Algorithm Selection Card
        card_sel = ctk.CTkFrame(self.crypt_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        card_sel.pack(fill="x", pady=(0, 12))

        inner_sel = ctk.CTkFrame(card_sel, fg_color="transparent")
        inner_sel.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(inner_sel, text="SELECT ALGORITHM:", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(side="left", padx=(0, 10))

        all_crypt_algos = self.SYMMETRIC_ALGOS + self.ASYMMETRIC_ALGOS
        self.crypt_algo_var = ctk.StringVar(value=all_crypt_algos[0])
        self.crypt_algo_menu = ctk.CTkOptionMenu(
            inner_sel,
            values=all_crypt_algos,
            variable=self.crypt_algo_var,
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            button_color=BORDER_COLOR,
            button_hover_color=ACCENT_PRIMARY,
            text_color=TEXT_PRIMARY,
            width=280,
            height=34,
        )
        self.crypt_algo_menu.pack(side="left")

        # Key / Passphrase Card with Eye Toggle & Keyring Quick-Select
        key_card = ctk.CTkFrame(self.crypt_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        key_card.pack(fill="x", pady=(0, 12))

        key_inner = ctk.CTkFrame(key_card, fg_color="transparent")
        key_inner.pack(fill="x", padx=16, pady=10)

        ctk.CTkLabel(key_inner, text="KEY / PASSPHRASE / KEYRING KEY:", font=get_font(11, "bold"), text_color=COLOR_WARNING).pack(anchor="w", pady=(0, 4))

        key_row = ctk.CTkFrame(key_inner, fg_color="transparent")
        key_row.pack(fill="x")

        self.crypt_key_entry = ctk.CTkEntry(
            key_row,
            placeholder_text="Enter encryption passphrase, hex key, or armored RSA/PGP key...",
            font=get_mono_font(12),
            show="•",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.crypt_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(key_row, self.crypt_key_entry)

        # Quick Keyring selector
        self.vault_key_combo = ctk.CTkComboBox(
            key_row,
            values=["Select from Keyring..."],
            width=200,
            height=36,
            font=get_font(11),
            command=self._on_vault_key_selected_for_crypt,
        )
        self.vault_key_combo.pack(side="right", padx=(6, 0))

        # Input Text Box
        in_card = ctk.CTkFrame(self.crypt_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        in_card.pack(fill="x", pady=(0, 12))

        in_hdr = ctk.CTkFrame(in_card, fg_color="transparent")
        in_hdr.pack(fill="x", padx=16, pady=(10, 4))
        ctk.CTkLabel(in_hdr, text="INPUT (Plaintext to Encrypt OR Ciphertext to Decrypt):", font=get_font(11, "bold"), text_color=TEXT_PRIMARY).pack(side="left")

        ctk.CTkButton(
            in_hdr,
            text="📥 Import File into Input...",
            font=get_font(10, "bold"),
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._load_file_into_crypt_input,
        ).pack(side="right")

        self.crypt_in_text = ctk.CTkTextbox(in_card, height=130, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.crypt_in_text.pack(fill="x", padx=16, pady=(0, 10))

        # Action Buttons Row
        action_row = ctk.CTkFrame(self.crypt_frame, fg_color="transparent")
        action_row.pack(fill="x", pady=(0, 12))

        ctk.CTkButton(
            action_row,
            text="🔐 Encrypt",
            font=get_font(13, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            width=120,
            height=38,
            command=self._do_encrypt,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            action_row,
            text="🔓 Decrypt",
            font=get_font(13, "bold"),
            fg_color=ACCENT_INDIGO,
            hover_color=ACCENT_HOVER,
            text_color="#ffffff",
            width=120,
            height=38,
            command=self._do_decrypt,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            action_row,
            text="📁 Encrypt File Directly...",
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            height=38,
            command=self._do_encrypt_single_file_direct,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            action_row,
            text="📁 Decrypt File Directly...",
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_SUCCESS,
            height=38,
            command=self._do_decrypt_single_file_direct,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            action_row,
            text="🔄 Swap",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=38,
            command=self._swap_crypt_text,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            action_row,
            text="🧹 Clear",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            height=38,
            command=lambda: (self.crypt_in_text.delete("1.0", "end"), self.crypt_out_text.delete("1.0", "end")),
        ).pack(side="left", padx=4)

        self.crypt_status_lbl = ctk.CTkLabel(action_row, text="", font=get_font(12))
        self.crypt_status_lbl.pack(side="left", padx=10)

        # Output Text Box
        out_card = ctk.CTkFrame(self.crypt_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        out_card.pack(fill="x")

        out_hdr = ctk.CTkFrame(out_card, fg_color="transparent")
        out_hdr.pack(fill="x", padx=16, pady=(10, 4))
        ctk.CTkLabel(out_hdr, text="RESULT / OUTPUT:", font=get_font(11, "bold"), text_color=COLOR_SUCCESS).pack(side="left")

        ctk.CTkButton(
            out_hdr,
            text="📋 Copy Result",
            font=get_font(10, "bold"),
            width=100,
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_SUCCESS,
            command=lambda: self.clipboard_mgr.copy(self.crypt_out_text.get("1.0", "end").strip(), "Output copied to clipboard"),
        ).pack(side="right")

        ctk.CTkButton(
            out_hdr,
            text="📤 Export Output to File...",
            font=get_font(10, "bold"),
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._save_crypt_output_to_file,
        ).pack(side="right", padx=(0, 6))

        self.crypt_out_text = ctk.CTkTextbox(out_card, height=140, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.crypt_out_text.pack(fill="x", padx=16, pady=(0, 14))

    def _refresh_vault_key_dropdown(self) -> None:
        names = ["Select from Keyring..."] + [e.title for e in self.keyring_entries]
        if hasattr(self, "vault_key_combo"):
            self.vault_key_combo.configure(values=names)
            self.vault_key_combo.set("Select from Keyring...")

    def _on_vault_key_selected_for_crypt(self, choice: str) -> None:
        match = next((e for e in self.keyring_entries if e.title == choice), None)
        if match:
            self._use_key_for_encrypt_decrypt(match)

    def _use_key_for_encrypt_decrypt(self, entry: VaultEntry) -> None:
        self.switch_to_subtab("🔐 Encrypt & Decrypt")
        kt = getattr(entry, "key_type", "").lower()
        if "gpg" in kt or "pgp" in kt:
            self.crypt_algo_var.set("OpenPGP (GPG Armored)")
        elif "rsa" in kt:
            self.crypt_algo_var.set("RSA OAEP (SHA-256)")
        else:
            self.crypt_algo_var.set("AES-256-GCM (Authenticated)")

        key_val = entry.public_key or entry.private_key or ""
        self.crypt_key_entry.delete(0, "end")
        self.crypt_key_entry.insert(0, key_val)
        if hasattr(self, "vault_key_combo"):
            self.vault_key_combo.set(entry.title)

    def _swap_crypt_text(self) -> None:
        out = self.crypt_out_text.get("1.0", "end").strip()
        self.crypt_in_text.delete("1.0", "end")
        self.crypt_in_text.insert("1.0", out)
        self.crypt_out_text.delete("1.0", "end")

    def _do_encrypt(self) -> None:
        inp = self.crypt_in_text.get("1.0", "end").strip()
        key = self.crypt_key_entry.get().strip()
        algo = self.crypt_algo_var.get()

        if not inp:
            self.crypt_status_lbl.configure(text="Please enter text to encrypt.", text_color=COLOR_WARNING)
            return
        if not key:
            self.crypt_status_lbl.configure(text="Please enter an encryption key or passphrase.", text_color=COLOR_WARNING)
            return

        try:
            res = ""
            if "AES-256-GCM" in algo:
                res = encrypt_symmetric(inp, key, cipher="AES-256-GCM")
            elif "ChaCha20" in algo:
                res = encrypt_symmetric(inp, key, cipher="ChaCha20-Poly1305")
            elif "AES-256-CBC" in algo:
                res = encrypt_symmetric(inp, key, cipher="AES-256-CBC")
            elif "RSA" in algo:
                res = rsa_encrypt(inp, key)
            elif "OpenPGP" in algo:
                res = pgp_encrypt(inp, key)
            else:
                res = encrypt_symmetric(inp, key)

            self.crypt_out_text.delete("1.0", "end")
            self.crypt_out_text.insert("1.0", res)
            self.crypt_status_lbl.configure(text="✓ Encrypted successfully!", text_color=COLOR_SUCCESS)
        except Exception as ex:
            self.crypt_status_lbl.configure(text=f"Encryption failed: {ex}", text_color=COLOR_DANGER)

    def _do_decrypt(self) -> None:
        inp = self.crypt_in_text.get("1.0", "end").strip()
        key = self.crypt_key_entry.get().strip()
        algo = self.crypt_algo_var.get()

        if not inp or not key:
            self.crypt_status_lbl.configure(text="Ciphertext and key required for decryption.", text_color=COLOR_WARNING)
            return

        try:
            res = ""
            if "AES-256-GCM" in algo:
                res = decrypt_symmetric(inp, key, cipher="AES-256-GCM")
            elif "ChaCha20" in algo:
                res = decrypt_symmetric(inp, key, cipher="ChaCha20-Poly1305")
            elif "AES-256-CBC" in algo:
                res = decrypt_symmetric(inp, key, cipher="AES-256-CBC")
            elif "RSA" in algo:
                res = rsa_decrypt(inp, key)
            elif "OpenPGP" in algo:
                res = pgp_decrypt(inp, key)
            else:
                res = decrypt_symmetric(inp, key)

            self.crypt_out_text.delete("1.0", "end")
            self.crypt_out_text.insert("1.0", res)
            self.crypt_status_lbl.configure(text="✓ Decrypted successfully!", text_color=COLOR_SUCCESS)
        except Exception as ex:
            self.crypt_status_lbl.configure(text=f"Decryption failed: {ex}", text_color=COLOR_DANGER)

    def _load_file_into_crypt_input(self) -> None:
        p = filedialog.askopenfilename(
            title="Load File into Encrypt / Decrypt Input",
            filetypes=[
                ("All Supported Files", "*.txt;*.asc;*.b64;*.enc;*.json;*.yaml;*.env;*.*"),
                ("Text & Armored Files", "*.txt;*.asc;*.b64;*.json;*.yaml;*.env"),
                ("Encrypted Files", "*.enc;*.bin;*.dat"),
                ("All Files", "*.*"),
            ],
        )
        if not p:
            return

        file_p = Path(p)
        try:
            raw_bytes = file_p.read_bytes()
            # If valid utf-8 text, insert text directly
            try:
                text_content = raw_bytes.decode("utf-8")
                self.crypt_in_text.delete("1.0", "end")
                self.crypt_in_text.insert("1.0", text_content)
                self.crypt_status_lbl.configure(
                    text=f"✓ Loaded text from '{file_p.name}' ({len(text_content)} chars)",
                    text_color=COLOR_SUCCESS,
                )
            except UnicodeDecodeError:
                # Binary file: encode as base64 so it can be encrypted or decrypted
                b64_content = base64.b64encode(raw_bytes).decode("ascii")
                self.crypt_in_text.delete("1.0", "end")
                self.crypt_in_text.insert("1.0", b64_content)
                self.crypt_status_lbl.configure(
                    text=f"✓ Loaded binary as Base64 from '{file_p.name}' ({len(raw_bytes)} bytes)",
                    text_color=ACCENT_PRIMARY,
                )
        except Exception as ex:
            messagebox.showerror("Read Error", f"Could not load file:\n{ex}")

    def _save_crypt_output_to_file(self) -> None:
        content = self.crypt_out_text.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("No Output", "There is no output result to save.")
            return

        p = filedialog.asksaveasfilename(
            title="Save Output to Local File",
            initialfile="decrypted_output.txt",
            filetypes=[
                ("All Files", "*.*"),
                ("Text Files", "*.txt"),
                ("Encrypted / Armored Files", "*.enc;*.asc"),
                ("JSON / Config", "*.json;*.env;*.yaml"),
            ],
        )
        if not p:
            return

        try:
            is_b64 = False
            decoded_bytes = None
            if len(content) > 16 and not any(c in content for c in " \t\r\n"):
                try:
                    decoded_bytes = base64.b64decode(content, validate=True)
                    is_b64 = True
                except Exception:
                    is_b64 = False

            if is_b64 and decoded_bytes and (Path(p).suffix.lower() in (".bin", ".dat", ".enc", ".iso", ".zip", ".tar") or messagebox.askyesno("Binary Detected", "The output looks like Base64 encoded binary data. Would you like to save it as raw decoded binary?")):
                Path(p).write_bytes(decoded_bytes)
            else:
                Path(p).write_text(content, encoding="utf-8")

            messagebox.showinfo("Saved", f"Output written to:\n{p}")
        except Exception as ex:
            messagebox.showerror("Save Error", f"Failed to save file:\n{ex}")

    def _do_encrypt_single_file_direct(self) -> None:
        src = filedialog.askopenfilename(title="Select File to Encrypt Directly")
        if not src:
            return
        pwd = self.crypt_key_entry.get().strip()
        if not pwd:
            messagebox.showwarning("Missing Key", "Please provide an encryption passphrase or key.")
            return

        src_p = Path(src)
        dst = filedialog.asksaveasfilename(
            title="Save Encrypted File As",
            initialfile=f"{src_p.name}.enc",
            filetypes=[("Encrypted File", "*.enc"), ("All Files", "*.*")],
        )
        if not dst:
            return

        algo = self.crypt_algo_var.get()
        cipher = "AES-256-GCM"
        if "ChaCha20" in algo:
            cipher = "ChaCha20-Poly1305"
        elif "CBC" in algo:
            cipher = "AES-256-CBC"

        try:
            written = encrypt_file(src_p, Path(dst), pwd, cipher=cipher)
            self.crypt_status_lbl.configure(text=f"✓ Encrypted {src_p.name} ({written} bytes)", text_color=COLOR_SUCCESS)
            messagebox.showinfo("Encrypted Successfully", f"File encrypted:\n{dst}\n({written} bytes)")
        except Exception as ex:
            messagebox.showerror("Encryption Error", f"Failed to encrypt file:\n{ex}")

    def _do_decrypt_single_file_direct(self) -> None:
        src = filedialog.askopenfilename(
            title="Select Encrypted File to Decrypt",
            filetypes=[("Encrypted Files", "*.enc;*.svf;*.bin"), ("All Files", "*.*")],
        )
        if not src:
            return
        pwd = self.crypt_key_entry.get().strip()
        if not pwd:
            messagebox.showwarning("Missing Key", "Please provide the decryption passphrase or key.")
            return

        src_p = Path(src)
        default_name = src_p.stem if src_p.suffix == ".enc" else f"decrypted_{src_p.name}"
        dst = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=default_name,
            filetypes=[("All Files", "*.*")],
        )
        if not dst:
            return

        try:
            written = decrypt_file(src_p, Path(dst), pwd)
            self.crypt_status_lbl.configure(text=f"✓ Decrypted {src_p.name} ({written} bytes)", text_color=COLOR_SUCCESS)
            messagebox.showinfo("Decrypted Successfully", f"File decrypted:\n{dst}\n({written} bytes)")
        except Exception as ex:
            messagebox.showerror("Decryption Error", f"Failed to decrypt file:\n{ex}")


    # -------------------------------------------------------------------------
    # 4. Sign & Verify Workbench
    # -------------------------------------------------------------------------

    def _build_sign_verify_workbench(self) -> None:
        self.sign_frame = ctk.CTkScrollableFrame(self.content_frame, fg_color=BG_ROOT)

        top_card = ctk.CTkFrame(self.sign_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        top_card.pack(fill="x", pady=(0, 12))

        inner = ctk.CTkFrame(top_card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(inner, text="SIGNING ALGORITHM:", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(side="left", padx=(0, 10))
        self.sign_algo_var = ctk.StringVar(value=self.SIGNING_ALGOS[0])
        self.sign_algo_menu = ctk.CTkOptionMenu(
            inner,
            values=self.SIGNING_ALGOS,
            variable=self.sign_algo_var,
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            button_color=BORDER_COLOR,
            button_hover_color=ACCENT_PRIMARY,
            text_color=TEXT_PRIMARY,
            width=240,
            height=34,
        )
        self.sign_algo_menu.pack(side="left")

        # Key Input Card with Eye Toggle & Keyring Selector
        key_card = ctk.CTkFrame(self.sign_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        key_card.pack(fill="x", pady=(0, 12))

        k_inner = ctk.CTkFrame(key_card, fg_color="transparent")
        k_inner.pack(fill="x", padx=16, pady=10)

        ctk.CTkLabel(k_inner, text="KEY (Private Key for Signing • Public Key for Verification):", font=get_font(11, "bold"), text_color=COLOR_WARNING).pack(anchor="w", pady=(0, 4))
        k_row = ctk.CTkFrame(k_inner, fg_color="transparent")
        k_row.pack(fill="x")

        self.sign_key_entry = ctk.CTkEntry(
            k_row,
            placeholder_text="Paste PEM/OpenSSH private/public key or HMAC secret...",
            font=get_mono_font(11),
            show="•",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.sign_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(k_row, self.sign_key_entry)

        self.sign_keyring_combo = ctk.CTkComboBox(
            k_row,
            values=["Pick Key from Keyring..."],
            width=200,
            height=36,
            font=get_font(11),
            command=self._on_sign_vault_key_selected,
        )
        self.sign_keyring_combo.pack(side="right", padx=(6, 0))

        # Message Input Box
        msg_card = ctk.CTkFrame(self.sign_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        msg_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(msg_card, text="MESSAGE / PAYLOAD TO SIGN OR VERIFY:", font=get_font(11, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(10, 4))
        self.sign_msg_text = ctk.CTkTextbox(msg_card, height=120, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.sign_msg_text.pack(fill="x", padx=16, pady=(0, 10))

        # Signature Box
        sig_card = ctk.CTkFrame(self.sign_frame, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        sig_card.pack(fill="x", pady=(0, 12))

        sig_hdr = ctk.CTkFrame(sig_card, fg_color="transparent")
        sig_hdr.pack(fill="x", padx=16, pady=(10, 4))
        ctk.CTkLabel(sig_hdr, text="DIGITAL SIGNATURE (Base64 / Armored):", font=get_font(11, "bold"), text_color=ACCENT_INDIGO).pack(side="left")

        ctk.CTkButton(
            sig_hdr,
            text="📋 Copy Signature",
            font=get_font(10),
            width=120,
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self.clipboard_mgr.copy(self.sign_sig_text.get("1.0", "end").strip(), "Signature copied to clipboard"),
        ).pack(side="right")

        self.sign_sig_text = ctk.CTkTextbox(sig_card, height=90, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
        self.sign_sig_text.pack(fill="x", padx=16, pady=(0, 10))

        # Action Buttons & Verification Badge
        act_row = ctk.CTkFrame(self.sign_frame, fg_color="transparent")
        act_row.pack(fill="x", pady=(0, 10))

        ctk.CTkButton(
            act_row,
            text="✍️ Sign Message",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            width=140,
            height=38,
            command=self._do_sign,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            act_row,
            text="✅ Verify Signature",
            font=get_font(12, "bold"),
            fg_color=COLOR_SUCCESS,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            width=150,
            height=38,
            command=self._do_verify,
        ).pack(side="left", padx=4)

        self.sign_result_badge = ctk.CTkLabel(
            act_row,
            text="",
            font=get_font(12, "bold"),
            corner_radius=6,
            padx=12,
            pady=4,
        )
        self.sign_result_badge.pack(side="left", padx=12)

    def _refresh_sign_key_dropdown(self) -> None:
        names = ["Pick Key from Keyring..."] + [e.title for e in self.keyring_entries]
        if hasattr(self, "sign_keyring_combo"):
            self.sign_keyring_combo.configure(values=names)
            self.sign_keyring_combo.set("Pick Key from Keyring...")

    def _on_sign_vault_key_selected(self, choice: str) -> None:
        match = next((e for e in self.keyring_entries if e.title == choice), None)
        if match:
            self._use_key_for_sign_verify(match)

    def _use_key_for_sign_verify(self, entry: VaultEntry) -> None:
        self.switch_to_subtab("✍️ Sign & Verify")
        kt = getattr(entry, "key_type", "").lower()
        if "ed25519" in kt:
            self.sign_algo_var.set("Ed25519 (EdDSA)")
        elif "rsa" in kt:
            self.sign_algo_var.set("RSA-PSS (SHA-256)")
        elif "gpg" in kt or "pgp" in kt:
            self.sign_algo_var.set("OpenPGP Detached")

        key_val = entry.private_key or entry.public_key or ""
        self.sign_key_entry.delete(0, "end")
        self.sign_key_entry.insert(0, key_val)
        if hasattr(self, "sign_keyring_combo"):
            self.sign_keyring_combo.set(entry.title)

    def _do_sign(self) -> None:
        msg = self.sign_msg_text.get("1.0", "end").strip()
        key = self.sign_key_entry.get().strip()
        algo = self.sign_algo_var.get()

        if not msg:
            self.sign_result_badge.configure(text="Message cannot be empty", text_color=COLOR_WARNING, fg_color=BG_INPUT)
            return
        if not key:
            self.sign_result_badge.configure(text="Private key required to sign", text_color=COLOR_WARNING, fg_color=BG_INPUT)
            return

        try:
            sig = ""
            if "HMAC" in algo:
                sig = compute_hmac(key, msg)
            else:
                sig = asym_sign(msg, key)
            self.sign_sig_text.delete("1.0", "end")
            self.sign_sig_text.insert("1.0", sig)
            self.sign_result_badge.configure(text="✓ Message Signed Successfully", text_color=COLOR_SUCCESS, fg_color=BG_INPUT)
        except Exception as ex:
            self.sign_result_badge.configure(text=f"Signing Error: {ex}", text_color=COLOR_DANGER, fg_color=BG_INPUT)

    def _do_verify(self) -> None:
        msg = self.sign_msg_text.get("1.0", "end").strip()
        sig = self.sign_sig_text.get("1.0", "end").strip()
        key = self.sign_key_entry.get().strip()
        algo = self.sign_algo_var.get()

        if not msg or not sig or not key:
            self.sign_result_badge.configure(text="Message, signature, and public key required", text_color=COLOR_WARNING, fg_color=BG_INPUT)
            return

        try:
            if "HMAC" in algo:
                expected = compute_hmac(key, msg)
                is_valid = (expected.strip().lower() == sig.strip().lower())
            else:
                is_valid = asym_verify(msg, sig, key)

            if is_valid:
                self.sign_result_badge.configure(text="✓ VALID SIGNATURE (Authentic & Untampered)", text_color="#000000", fg_color=COLOR_SUCCESS)
            else:
                self.sign_result_badge.configure(text="✗ INVALID SIGNATURE (Verification Failed)", text_color="#ffffff", fg_color=COLOR_DANGER)
        except Exception as ex:
            self.sign_result_badge.configure(text=f"✗ Invalid: {ex}", text_color="#ffffff", fg_color=COLOR_DANGER)

    # -------------------------------------------------------------------------
    # 5. File & Bulk File Encryption Workbench
    # -------------------------------------------------------------------------

    def _build_file_workbench(self) -> None:
        self.file_frame = ctk.CTkScrollableFrame(self.content_frame, fg_color=BG_ROOT)

        # File Selection & Interactive Queue Card
        f_card = ctk.CTkFrame(self.file_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        f_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(f_card, text="📁 FILE SELECTION & QUEUE (SINGLE OR BULK)", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))

        row_sel = ctk.CTkFrame(f_card, fg_color="transparent")
        row_sel.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkButton(
            row_sel,
            text="📥 Add / Import File(s)...",
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
            command=self._choose_files_for_encryption,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            row_sel,
            text="📁 Add / Import Folder...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
            command=self._add_folder_for_encryption,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            row_sel,
            text="🧹 Clear Queue",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            height=32,
            command=self._clear_files_queue,
        ).pack(side="left", padx=4)

        self.f_count_lbl = ctk.CTkLabel(row_sel, text="0 files queued", font=get_font(12), text_color=TEXT_MUTED)
        self.f_count_lbl.pack(side="left", padx=10)

        # Scrollable file list container
        self.f_queue_scroll = ctk.CTkScrollableFrame(f_card, height=130, fg_color=BG_INPUT, corner_radius=6)
        self.f_queue_scroll.pack(fill="x", padx=16, pady=(0, 14))
        self._render_file_queue()

        # Passphrase & Cipher Card
        p_card = ctk.CTkFrame(self.file_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        p_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(p_card, text="ENCRYPTION PASSPHRASE, CIPHER & OUTPUT", font=get_font(11, "bold"), text_color=COLOR_WARNING).pack(anchor="w", padx=16, pady=(12, 6))

        p_row = ctk.CTkFrame(p_card, fg_color="transparent")
        p_row.pack(fill="x", padx=16, pady=(0, 8))

        self.f_key_entry = ctk.CTkEntry(
            p_row,
            placeholder_text="Enter passphrase for file encryption/decryption...",
            show="•",
            font=get_mono_font(12),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.f_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(p_row, self.f_key_entry)

        self.f_cipher_combo = ctk.CTkComboBox(
            p_row,
            values=["AES-256-GCM (Authenticated)", "ChaCha20-Poly1305 (AEAD)", "AES-256-CBC (PKCS7)"],
            width=240,
            height=36,
            font=get_font(11),
        )
        self.f_cipher_combo.pack(side="right", padx=(6, 0))

        # Destination choice
        dest_row = ctk.CTkFrame(p_card, fg_color="transparent")
        dest_row.pack(fill="x", padx=16, pady=(0, 12))

        self.f_dest_mode_var = ctk.StringVar(value="prompt")
        ctk.CTkRadioButton(
            dest_row,
            text="Prompt for output directory on start",
            variable=self.f_dest_mode_var,
            value="prompt",
            font=get_font(11),
        ).pack(side="left", padx=(0, 16))

        ctk.CTkRadioButton(
            dest_row,
            text="Save in same folder as original files",
            variable=self.f_dest_mode_var,
            value="same_folder",
            font=get_font(11),
        ).pack(side="left")

        # Action Buttons
        act_row = ctk.CTkFrame(self.file_frame, fg_color="transparent")
        act_row.pack(fill="x", padx=4, pady=(0, 14))

        self.f_encrypt_btn = ctk.CTkButton(
            act_row,
            text="🔐 Encrypt Queued Files",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=40,
            command=self._do_encrypt_files,
        )
        self.f_encrypt_btn.pack(side="left", padx=(0, 10))

        self.f_decrypt_btn = ctk.CTkButton(
            act_row,
            text="🔓 Decrypt Queued Files",
            font=get_font(12, "bold"),
            fg_color=ACCENT_INDIGO,
            hover_color=ACCENT_HOVER,
            text_color="#ffffff",
            height=40,
            command=self._do_decrypt_files,
        )
        self.f_decrypt_btn.pack(side="left", padx=4)

        # Log Output Box
        log_card = ctk.CTkFrame(self.file_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        log_card.pack(fill="x", padx=4)

        ctk.CTkLabel(log_card, text="OPERATION LOG:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(12, 4))
        self.f_log_text = ctk.CTkTextbox(log_card, height=130, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.f_log_text.pack(fill="x", padx=16, pady=(0, 14))

    def _render_file_queue(self) -> None:
        if not hasattr(self, "f_queue_scroll"):
            return
        for w in self.f_queue_scroll.winfo_children():
            w.destroy()

        if not self.selected_files:
            ctk.CTkLabel(
                self.f_queue_scroll,
                text="No files queued. Use 'Add File(s)...' or 'Add Folder...' to queue files.",
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(anchor="w", padx=8, pady=8)
            self.f_count_lbl.configure(text="0 files queued")
            return

        total_size = 0
        for fp in self.selected_files:
            try:
                sz = fp.stat().st_size
                total_size += sz
            except Exception:
                sz = 0

            row = ctk.CTkFrame(self.f_queue_scroll, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=4)

            icon = "🔒" if fp.name.endswith(".enc") or fp.name.endswith(".svf") else "📄"
            ctk.CTkLabel(row, text=icon, font=get_font(12)).pack(side="left", padx=(0, 6))

            name_box = ctk.CTkLabel(row, text=fp.name, font=get_font(11, "bold"), text_color=TEXT_PRIMARY)
            name_box.pack(side="left", padx=(0, 8))

            parent_box = ctk.CTkLabel(row, text=f"({str(fp.parent)})", font=get_font(10), text_color=TEXT_MUTED)
            parent_box.pack(side="left", fill="x", expand=True)

            sz_str = f"{sz / 1024:.1f} KB" if sz < 1024 * 1024 else f"{sz / (1024*1024):.2f} MB"
            ctk.CTkLabel(row, text=sz_str, font=get_mono_font(10), text_color=TEXT_SECONDARY).pack(side="left", padx=8)

            ctk.CTkButton(
                row,
                text="✕",
                width=24,
                height=22,
                font=get_font(10, "bold"),
                fg_color="transparent",
                hover_color=COLOR_DANGER,
                text_color=COLOR_DANGER,
                command=lambda p=fp: self._remove_file_from_queue(p),
            ).pack(side="right")

        total_mb = total_size / (1024 * 1024)
        self.f_count_lbl.configure(text=f"{len(self.selected_files)} files queued ({total_mb:.2f} MB total)")

    def _choose_files_for_encryption(self) -> None:
        paths = filedialog.askopenfilenames(title="Select Files to Encrypt or Decrypt")
        if paths:
            for p in paths:
                file_p = Path(p)
                if file_p not in self.selected_files:
                    self.selected_files.append(file_p)
            self._render_file_queue()

    def _add_folder_for_encryption(self) -> None:
        folder = filedialog.askdirectory(title="Select Folder to Add Files From")
        if folder:
            f_p = Path(folder)
            added = 0
            for item in f_p.rglob("*"):
                if item.is_file() and item not in self.selected_files:
                    self.selected_files.append(item)
                    added += 1
            self._render_file_queue()
            if added:
                self.f_log_text.insert("end", f"✓ Added {added} files from folder: {folder}\n")

    def _remove_file_from_queue(self, fp: Path) -> None:
        if fp in self.selected_files:
            self.selected_files.remove(fp)
            self._render_file_queue()

    def _clear_files_queue(self) -> None:
        self.selected_files.clear()
        self._render_file_queue()

    def _do_encrypt_files(self) -> None:
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select or add files to the queue first.")
            return
        pwd = self.f_key_entry.get().strip()
        if not pwd:
            messagebox.showwarning("No Passphrase", "Please provide an encryption passphrase.")
            return

        cipher = "AES-256-GCM"
        if "ChaCha20" in self.f_cipher_combo.get():
            cipher = "ChaCha20-Poly1305"
        elif "CBC" in self.f_cipher_combo.get():
            cipher = "AES-256-CBC"

        dest_mode = getattr(self, "f_dest_mode_var", None)
        mode = dest_mode.get() if dest_mode else "prompt"

        if mode == "prompt":
            dest_dir = filedialog.askdirectory(title="Select Output Directory for Encrypted Files")
            if not dest_dir:
                return
            dest_p = Path(dest_dir)
        else:
            dest_p = None

        self.f_encrypt_btn.configure(state="disabled")
        self.f_decrypt_btn.configure(state="disabled")
        self.f_log_text.insert("end", f"\n🔐 Starting bulk encryption of {len(self.selected_files)} file(s)...\n")

        def worker():
            if dest_p:
                success_count, errors = bulk_encrypt_files(self.selected_files, dest_p, pwd, cipher=cipher)
            else:
                success_count = 0
                errors = []
                for fp in self.selected_files:
                    dst = fp.parent / (fp.name + ".enc")
                    try:
                        encrypt_file(fp, dst, pwd, cipher=cipher)
                        success_count += 1
                    except Exception as ex:
                        errors.append(f"{fp.name}: {str(ex)}")

            def done():
                self.f_encrypt_btn.configure(state="normal")
                self.f_decrypt_btn.configure(state="normal")
                self.f_log_text.insert("end", f"✓ Finished encryption: {success_count} succeeded, {len(errors)} failed.\n")
                if errors:
                    for err in errors:
                        self.f_log_text.insert("end", f"  ✗ {err}\n")
                messagebox.showinfo("Encryption Complete", f"Successfully encrypted {success_count} files.")
            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _do_decrypt_files(self) -> None:
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select or add files to the queue first.")
            return
        pwd = self.f_key_entry.get().strip()
        if not pwd:
            messagebox.showwarning("No Passphrase", "Please provide a decryption passphrase.")
            return

        cipher = "AES-256-GCM"
        if "ChaCha20" in self.f_cipher_combo.get():
            cipher = "ChaCha20-Poly1305"
        elif "CBC" in self.f_cipher_combo.get():
            cipher = "AES-256-CBC"

        dest_mode = getattr(self, "f_dest_mode_var", None)
        mode = dest_mode.get() if dest_mode else "prompt"

        if mode == "prompt":
            dest_dir = filedialog.askdirectory(title="Select Output Directory for Decrypted Files")
            if not dest_dir:
                return
            dest_p = Path(dest_dir)
        else:
            dest_p = None

        self.f_encrypt_btn.configure(state="disabled")
        self.f_decrypt_btn.configure(state="disabled")
        self.f_log_text.insert("end", f"\n🔓 Starting bulk decryption of {len(self.selected_files)} file(s)...\n")

        def worker():
            if dest_p:
                success_count, errors = bulk_decrypt_files(self.selected_files, dest_p, pwd, cipher=cipher)
            else:
                success_count = 0
                errors = []
                for fp in self.selected_files:
                    out_name = fp.name[:-4] if fp.name.endswith(".enc") else f"{fp.stem}_decrypted{fp.suffix}"
                    dst = fp.parent / out_name
                    try:
                        decrypt_file(fp, dst, pwd, cipher=cipher)
                        success_count += 1
                    except Exception as ex:
                        errors.append(f"{fp.name}: {str(ex)}")

            def done():
                self.f_encrypt_btn.configure(state="normal")
                self.f_decrypt_btn.configure(state="normal")
                self.f_log_text.insert("end", f"✓ Finished decryption: {success_count} succeeded, {len(errors)} failed.\n")
                if errors:
                    for err in errors:
                        self.f_log_text.insert("end", f"  ✗ {err}\n")
                messagebox.showinfo("Decryption Complete", f"Successfully decrypted {success_count} files.")
            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()


    # -------------------------------------------------------------------------
    # 6. Hashes & Encoders Workbench
    # -------------------------------------------------------------------------

    def _build_hashes_workbench(self) -> None:
        self.hash_frame = ctk.CTkScrollableFrame(self.content_frame, fg_color=BG_ROOT)

        # Input Card
        in_card = ctk.CTkFrame(self.hash_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        in_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(in_card, text="INPUT TEXT TO HASH OR ENCODE/DECODE:", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))
        self.hash_input = ctk.CTkTextbox(in_card, height=100, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.hash_input.pack(fill="x", padx=16, pady=(0, 12))
        self.hash_input.bind("<KeyRelease>", lambda e: self._on_hash_input_change())

        # Encoders Action Card
        enc_card = ctk.CTkFrame(self.hash_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        enc_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(enc_card, text="FORMAT ENCODERS & DECODERS", font=get_font(11, "bold"), text_color=ACCENT_INDIGO).pack(anchor="w", padx=16, pady=(12, 6))

        row1 = ctk.CTkFrame(enc_card, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkButton(row1, text="Encode Base64", font=get_font(11), fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, height=32, command=lambda: self._set_hash_out(encode_base64(self.hash_input.get("1.0", "end").strip()))).pack(side="left", padx=(0, 4))
        ctk.CTkButton(row1, text="Decode Base64", font=get_font(11), fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, height=32, command=lambda: self._set_hash_out(decode_base64(self.hash_input.get("1.0", "end").strip()))).pack(side="left", padx=4)
        ctk.CTkButton(row1, text="Encode Hex", font=get_font(11), fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, height=32, command=lambda: self._set_hash_out(encode_hex(self.hash_input.get("1.0", "end").strip()))).pack(side="left", padx=4)
        ctk.CTkButton(row1, text="Decode Hex", font=get_font(11), fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, height=32, command=lambda: self._set_hash_out(decode_hex(self.hash_input.get("1.0", "end").strip()))).pack(side="left", padx=4)
        ctk.CTkButton(row1, text="URL Encode", font=get_font(11), fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, height=32, command=lambda: self._set_hash_out(encode_url(self.hash_input.get("1.0", "end").strip()))).pack(side="left", padx=4)
        ctk.CTkButton(row1, text="URL Decode", font=get_font(11), fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, height=32, command=lambda: self._set_hash_out(decode_url(self.hash_input.get("1.0", "end").strip()))).pack(side="left", padx=4)

        # Hash Results Card
        h_card = ctk.CTkFrame(self.hash_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        h_card.pack(fill="x", padx=4)

        ctk.CTkLabel(h_card, text="CRYPTOGRAPHIC HASH DIGESTS", font=get_font(11, "bold"), text_color=COLOR_SUCCESS).pack(anchor="w", padx=16, pady=(12, 6))

        self.hash_labels = {}
        for algo in ["SHA-256", "SHA-512", "SHA3-256", "BLAKE2b", "MD5"]:
            r = ctk.CTkFrame(h_card, fg_color="transparent")
            r.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(r, text=f"{algo}:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY, width=80, anchor="w").pack(side="left")
            ent = ctk.CTkEntry(r, font=get_mono_font(10), fg_color=BG_INPUT, border_color=BORDER_COLOR, height=28)
            ent.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkButton(r, text="📋", width=28, height=28, fg_color=BG_INPUT, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY, command=lambda e=ent: self.clipboard_mgr.copy(e.get(), "Hash copied")).pack(side="right")
            self.hash_labels[algo] = ent

        # Encoder Result Box
        ctk.CTkLabel(h_card, text="ENCODER / DECODER OUTPUT:", font=get_font(11, "bold"), text_color=TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 4))
        self.encoder_out = ctk.CTkTextbox(h_card, height=80, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.encoder_out.pack(fill="x", padx=16, pady=(0, 14))

    def _set_hash_out(self, val: str) -> None:
        self.encoder_out.delete("1.0", "end")
        self.encoder_out.insert("1.0", val)

    def _on_hash_input_change(self) -> None:
        txt = self.hash_input.get("1.0", "end").strip()
        if not txt:
            for ent in self.hash_labels.values():
                ent.delete(0, "end")
            return

        algo_map = {
            "SHA-256": "sha256",
            "SHA-512": "sha512",
            "SHA3-256": "sha3_256",
            "BLAKE2b": "blake2b",
            "MD5": "md5",
        }
        for label, algo in algo_map.items():
            if label in self.hash_labels:
                try:
                    h = compute_hash(txt, algo=algo)
                    self.hash_labels[label].delete(0, "end")
                    self.hash_labels[label].insert(0, h)
                except Exception:
                    pass
