"""Key Generation and Management Studio UI for StarVault."""

import threading
from tkinter import filedialog
from typing import Callable, Optional
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.keys import (
    GeneratedKeyResult,
    generate_age_key_result,
    generate_ed25519_key,
    generate_gpg_key,
    generate_rsa_key,
    generate_tls_cert_key,
    generate_wireguard_key_result,
)
from starvault.models import VaultEntry
from starvault.ui.theme import (
    ACCENT_HOVER,
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


class KeyStudioDialog(ctk.CTkToplevel):
    """Studio for generating and inspecting Ed25519, RSA, and GPG keys."""

    def __init__(
        self,
        parent,
        clipboard_mgr: ClipboardManager,
        on_save_to_vault: Optional[Callable[[VaultEntry], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.clipboard_mgr = clipboard_mgr
        self.on_save_to_vault = on_save_to_vault

        self.title("StarVault - Key Generation & Management Studio")
        self.geometry("860x860")
        self.minsize(780, 750)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        self.current_key: Optional[GeneratedKeyResult] = None
        self._private_revealed = False

        self._build_ui()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="🔑 Key Studio & Inspector",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=24, pady=16)

        ctk.CTkLabel(
            header,
            text="Generate OpenSSH & PuTTY (.ppk) keys & OpenPGP keypairs",
            font=get_font(12),
            text_color=TEXT_MUTED,
        ).pack(side="left", pady=16)

        # Scrollable body
        self.scroll = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=16)

        # 1. Generator Parameters Card
        self._build_generator_card()

        # 2. Key Inspector Card
        self._build_inspector_card()

    def _build_generator_card(self):
        gen_card = ctk.CTkFrame(
            self.scroll,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        gen_card.pack(fill="x", pady=(0, 16), padx=4)

        ctk.CTkLabel(
            gen_card,
            text="KEY GENERATOR",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Algorithm selection
        row_algo = ctk.CTkFrame(gen_card, fg_color="transparent")
        row_algo.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(row_algo, text="Algorithm / Type", font=get_font(12, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w")

        self.algo_var = ctk.StringVar(value="ed25519")
        algo_seg = ctk.CTkSegmentedButton(
            row_algo,
            values=["ed25519", "rsa4096", "gpg", "tls_cert", "wireguard", "age"],
            variable=self.algo_var,
            command=self._on_algo_change,
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=get_font(11, "bold"),
            height=36,
        )
        algo_seg.pack(fill="x", pady=(4, 8))

        # Parameters row (Comment, Name, Email, TLS SANs)
        self.param_container = ctk.CTkFrame(gen_card, fg_color="transparent")
        self.param_container.pack(fill="x", padx=16, pady=(0, 8))
        self._render_algo_params("ed25519")

        # Generate Button & Status
        action_row = ctk.CTkFrame(gen_card, fg_color="transparent")
        action_row.pack(fill="x", padx=16, pady=(4, 16))

        self.gen_btn = ctk.CTkButton(
            action_row,
            text="⚡ Generate New Keypair",
            font=get_font(13, "bold"),
            height=40,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=self._start_key_generation,
        )
        self.gen_btn.pack(side="left", padx=(0, 12))

        self.gen_status_label = ctk.CTkLabel(
            action_row,
            text="",
            font=get_font(12),
            text_color=TEXT_SECONDARY,
        )
        self.gen_status_label.pack(side="left")

    def _render_algo_params(self, algo: str):
        for child in self.param_container.winfo_children():
            child.destroy()

        if algo in ("ed25519", "rsa4096"):
            ctk.CTkLabel(self.param_container, text="Key Comment / Identification", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.ssh_comment_entry = ctk.CTkEntry(
                self.param_container,
                placeholder_text="e.g. root@homelab, admin@vps1",
                fg_color=BG_INPUT,
                border_color=BORDER_COLOR,
                height=36,
            )
            self.ssh_comment_entry.insert(0, f"starvault-{algo}")
            self.ssh_comment_entry.pack(fill="x", pady=(4, 0))

        elif algo == "gpg":
            row = ctk.CTkFrame(self.param_container, fg_color="transparent")
            row.pack(fill="x")

            col_name = ctk.CTkFrame(row, fg_color="transparent")
            col_name.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkLabel(col_name, text="User Name *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gpg_name_entry = ctk.CTkEntry(col_name, placeholder_text="Homelab Admin", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gpg_name_entry.insert(0, "Homelab Admin")
            self.gpg_name_entry.pack(fill="x", pady=(4, 0))

            col_email = ctk.CTkFrame(row, fg_color="transparent")
            col_email.pack(side="right", fill="x", expand=True, padx=(6, 0))
            ctk.CTkLabel(col_email, text="Email *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.gpg_email_entry = ctk.CTkEntry(col_email, placeholder_text="admin@homelab.local", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
            self.gpg_email_entry.insert(0, "admin@homelab.local")
            self.gpg_email_entry.pack(fill="x", pady=(4, 0))

        elif algo == "tls_cert":
            row1 = ctk.CTkFrame(self.param_container, fg_color="transparent")
            row1.pack(fill="x", pady=2)
            col1 = ctk.CTkFrame(row1, fg_color="transparent")
            col1.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkLabel(col1, text="Common Name (Domain / IP) *", font=get_font(11), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.tls_cn_entry = ctk.CTkEntry(col1, placeholder_text="localhost", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
            self.tls_cn_entry.insert(0, "localhost")
            self.tls_cn_entry.pack(fill="x", pady=(2, 0))

            col2 = ctk.CTkFrame(row1, fg_color="transparent")
            col2.pack(side="right", fill="x", expand=True, padx=(6, 0))
            ctk.CTkLabel(col2, text="SANs (Comma separated) *", font=get_font(11), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.tls_sans_entry = ctk.CTkEntry(col2, placeholder_text="127.0.0.1, *.local, homelab.lan", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
            self.tls_sans_entry.insert(0, "127.0.0.1, *.local")
            self.tls_sans_entry.pack(fill="x", pady=(2, 0))

            row2 = ctk.CTkFrame(self.param_container, fg_color="transparent")
            row2.pack(fill="x", pady=4)
            col3 = ctk.CTkFrame(row2, fg_color="transparent")
            col3.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkLabel(col3, text="Organization", font=get_font(11), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.tls_org_entry = ctk.CTkEntry(col3, placeholder_text="StarVault Homelab", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
            self.tls_org_entry.insert(0, "StarVault Homelab")
            self.tls_org_entry.pack(fill="x", pady=(2, 0))

            col4 = ctk.CTkFrame(row2, fg_color="transparent")
            col4.pack(side="right", fill="x", expand=True, padx=(6, 0))
            ctk.CTkLabel(col4, text="Key Algorithm", font=get_font(11), text_color=TEXT_SECONDARY).pack(anchor="w")
            self.tls_keytype_combo = ctk.CTkComboBox(col4, values=["RSA 2048", "RSA 4096", "ECDSA P-256", "Ed25519"], fg_color=BG_INPUT, border_color=BORDER_COLOR, height=34)
            self.tls_keytype_combo.set("RSA 2048")
            self.tls_keytype_combo.pack(fill="x", pady=(2, 0))

        elif algo == "wireguard":
            ctk.CTkLabel(
                self.param_container,
                text="Generates a high-performance WireGuard Curve25519 keypair.\nOutputs standard Base64 private and public keys ready to paste into wg0.conf.",
                font=get_font(11),
                text_color=TEXT_MUTED,
                justify="left",
            ).pack(anchor="w", pady=4)

        elif algo == "age":
            ctk.CTkLabel(
                self.param_container,
                text="Generates an age-keygen compatible X25519 keypair (Bech32 format).\nOutputs AGE-SECRET-KEY-1... private key and age1... recipient public key.",
                font=get_font(11),
                text_color=TEXT_MUTED,
                justify="left",
            ).pack(anchor="w", pady=4)

    def _on_algo_change(self, new_algo: str):
        self._render_algo_params(new_algo)

    def _start_key_generation(self):
        algo = self.algo_var.get()
        self.gen_btn.configure(state="disabled", text="Generating Keypair...")
        self.gen_status_label.configure(text="Generating cryptographically secure keys in background...", text_color=COLOR_WARNING)
        self.update_idletasks()

        def worker():
            try:
                if algo == "ed25519":
                    comment = self.ssh_comment_entry.get().strip() if hasattr(self, "ssh_comment_entry") else "starvault-ed25519"
                    res = generate_ed25519_key(comment=comment)
                elif algo == "rsa4096":
                    comment = self.ssh_comment_entry.get().strip() if hasattr(self, "ssh_comment_entry") else "starvault-rsa4096"
                    res = generate_rsa_key(bits=4096, comment=comment)
                elif algo == "gpg":
                    name = self.gpg_name_entry.get().strip() or "Homelab User"
                    email = self.gpg_email_entry.get().strip() or "user@homelab.local"
                    res = generate_gpg_key(name=name, email=email, bits=2048)
                elif algo == "tls_cert":
                    cn = self.tls_cn_entry.get().strip() or "localhost"
                    sans = [s.strip() for s in self.tls_sans_entry.get().split(",") if s.strip()]
                    org = self.tls_org_entry.get().strip() or "StarVault Homelab"
                    kt = self.tls_keytype_combo.get().strip() or "RSA 2048"
                    res = generate_tls_cert_key(common_name=cn, san_list=sans, organization=org, key_type=kt)
                elif algo == "wireguard":
                    res = generate_wireguard_key_result()
                elif algo == "age":
                    res = generate_age_key_result()
                else:
                    res = generate_ed25519_key()

                self.after(0, lambda: self._on_generation_complete(res))
            except Exception as e:
                self.after(0, lambda: self._on_generation_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_generation_complete(self, result: GeneratedKeyResult):
        self.current_key = result
        self.gen_btn.configure(state="normal", text="⚡ Generate New Keypair")
        self.gen_status_label.configure(text=f"✓ Successfully generated {result.algorithm_name}", text_color=COLOR_SUCCESS)

        self._private_revealed = False
        self._populate_inspector(result)

    def _on_generation_error(self, err_msg: str):
        self.gen_btn.configure(state="normal", text="⚡ Generate New Keypair")
        self.gen_status_label.configure(text=f"Generation failed: {err_msg}", text_color=COLOR_DANGER)

    def _build_inspector_card(self):
        insp_card = ctk.CTkFrame(
            self.scroll,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        insp_card.pack(fill="x", pady=(0, 16), padx=4)

        # Header Row with Fingerprint & Badge
        header_row = ctk.CTkFrame(insp_card, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            header_row,
            text="KEY INSPECTOR & EXPORT",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(side="left")

        self.key_type_badge = ctk.CTkLabel(
            header_row,
            text="NO KEY LOADED",
            font=get_font(10, "bold"),
            fg_color=BG_INPUT,
            text_color=TEXT_MUTED,
            corner_radius=6,
            padx=8,
            pady=2,
        )
        self.key_type_badge.pack(side="right")

        # Fingerprint row
        fp_row = ctk.CTkFrame(insp_card, fg_color=BG_INPUT, corner_radius=6)
        fp_row.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(fp_row, text="Fingerprint:", font=get_font(11, "bold"), text_color=TEXT_MUTED).pack(side="left", padx=8, pady=6)
        self.fp_val_label = ctk.CTkLabel(fp_row, text="Generate or load a key to inspect", font=get_mono_font(11), text_color=TEXT_PRIMARY)
        self.fp_val_label.pack(side="left", padx=4, pady=6)

        ctk.CTkButton(
            fp_row,
            text="📋 Copy",
            width=60,
            height=26,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._copy_fingerprint,
        ).pack(side="right", padx=6, pady=4)

        # Public Key Box
        pub_header = ctk.CTkFrame(insp_card, fg_color="transparent")
        pub_header.pack(fill="x", padx=16, pady=(10, 2))

        ctk.CTkLabel(pub_header, text="Public Key", font=get_font(12, "bold"), text_color=TEXT_SECONDARY).pack(side="left")
        ctk.CTkButton(
            pub_header,
            text="📋 Copy Public Key",
            width=120,
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=ACCENT_PRIMARY,
            command=self._copy_public_key,
        ).pack(side="right")

        self.pub_textbox = ctk.CTkTextbox(insp_card, height=85, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.pub_textbox.pack(fill="x", padx=16, pady=(0, 8))

        # Private Key Box (Masked by default)
        priv_header = ctk.CTkFrame(insp_card, fg_color="transparent")
        priv_header.pack(fill="x", padx=16, pady=(8, 2))

        ctk.CTkLabel(priv_header, text="Private Key (Sensitive)", font=get_font(12, "bold"), text_color=COLOR_WARNING).pack(side="left")

        self.reveal_btn = ctk.CTkButton(
            priv_header,
            text="👁 Click to Reveal",
            width=110,
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_WARNING,
            command=self._toggle_reveal_private,
        )
        self.reveal_btn.pack(side="right", padx=(6, 0))

        ctk.CTkButton(
            priv_header,
            text="📋 Copy (30s wipe)",
            width=130,
            height=26,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=COLOR_DANGER,
            command=self._copy_private_key,
        ).pack(side="right")

        self.priv_textbox = ctk.CTkTextbox(insp_card, height=110, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.priv_textbox.pack(fill="x", padx=16, pady=(0, 12))

        # Format Export Buttons Bar
        export_label = ctk.CTkLabel(insp_card, text="EXPORT FORMATS & FILES", font=get_font(11, "bold"), text_color=TEXT_MUTED)
        export_label.pack(anchor="w", padx=16, pady=(4, 4))

        export_row = ctk.CTkFrame(insp_card, fg_color="transparent")
        export_row.pack(fill="x", padx=16, pady=(0, 14))

        self.export_pub_btn = ctk.CTkButton(
            export_row,
            text="💾 Save .pub",
            width=110,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._export_file("pub"),
        )
        self.export_pub_btn.pack(side="left", padx=(0, 6))

        self.export_pem_btn = ctk.CTkButton(
            export_row,
            text="💾 Save .pem",
            width=110,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._export_file("pem"),
        )
        self.export_pem_btn.pack(side="left", padx=(0, 6))

        self.export_ppk_btn = ctk.CTkButton(
            export_row,
            text="💾 Save PuTTY .ppk",
            width=130,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._export_file("ppk"),
        )
        self.export_ppk_btn.pack(side="left", padx=(0, 6))

        self.export_asc_btn = ctk.CTkButton(
            export_row,
            text="💾 Save PGP .asc",
            width=120,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._export_file("asc"),
        )
        self.export_asc_btn.pack(side="left")

        # Save into StarVault vault directly
        save_vault_frame = ctk.CTkFrame(insp_card, fg_color=BG_SUBTLE, corner_radius=8)
        save_vault_frame.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkLabel(
            save_vault_frame,
            text="Store this keypair directly in your encrypted StarVault database:",
            font=get_font(12),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=14, pady=10)

        ctk.CTkButton(
            save_vault_frame,
            text="+ Save into Vault",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=32,
            command=self._save_into_vault,
        ).pack(side="right", padx=14, pady=10)

    def _populate_inspector(self, key: GeneratedKeyResult):
        self.key_type_badge.configure(
            text=key.algorithm_name.upper(),
            fg_color=ACCENT_PURPLE,
            text_color="#ffffff",
        )
        self.fp_val_label.configure(text=key.fingerprint)

        self.pub_textbox.delete("1.0", "end")
        self.pub_textbox.insert("1.0", key.public_key)

        self._render_private_key_textbox()

        # Update export buttons availability
        is_gpg = key.key_type == "gpg"
        self.export_ppk_btn.configure(state="disabled" if is_gpg else "normal")
        self.export_asc_btn.configure(state="normal" if is_gpg else "disabled")

    def _render_private_key_textbox(self):
        if not self.current_key:
            return
        self.priv_textbox.delete("1.0", "end")
        if self._private_revealed:
            self.priv_textbox.insert("1.0", self.current_key.private_key)
            self.reveal_btn.configure(text="🔒 Hide Private Key")
        else:
            masked = "••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••\n" * 4
            masked += "[Click 'Reveal Private Key' to view plain text contents]"
            self.priv_textbox.insert("1.0", masked)
            self.reveal_btn.configure(text="👁 Click to Reveal")

    def _toggle_reveal_private(self):
        self._private_revealed = not self._private_revealed
        self._render_private_key_textbox()

    def _copy_fingerprint(self):
        if self.current_key:
            self.clipboard_mgr.copy(self.current_key.fingerprint, label="Fingerprint copied")

    def _copy_public_key(self):
        if self.current_key:
            self.clipboard_mgr.copy(self.current_key.public_key, label="Public key copied")

    def _copy_private_key(self):
        if self.current_key:
            self.clipboard_mgr.copy(
                self.current_key.private_key,
                label="Private key copied",
                is_sensitive=True,
            )

    def _export_file(self, fmt: str):
        if not self.current_key:
            return

        def_name = self.current_key.comment or "key"
        def_name = "".join(c for c in def_name if c.isalnum() or c in "-_") or "id_key"

        if fmt == "pub":
            path = filedialog.asksaveasfilename(
                title="Export OpenSSH Public Key",
                initialfile=f"{def_name}.pub",
                filetypes=[("OpenSSH Public Key", "*.pub"), ("All Files", "*.*")],
            )
            content = self.current_key.public_key
        elif fmt == "pem":
            path = filedialog.asksaveasfilename(
                title="Export OpenSSH Private Key",
                initialfile=f"{def_name}.pem",
                filetypes=[("PEM Private Key", "*.pem"), ("All Files", "*.*")],
            )
            content = self.current_key.private_key
        elif fmt == "ppk":
            path = filedialog.asksaveasfilename(
                title="Export PuTTY Private Key",
                initialfile=f"{def_name}.ppk",
                filetypes=[("PuTTY Private Key", "*.ppk"), ("All Files", "*.*")],
            )
            content = self.current_key.putty_ppk
        elif fmt == "asc":
            path = filedialog.asksaveasfilename(
                title="Export PGP Armored Key",
                initialfile=f"{def_name}.asc",
                filetypes=[("Armored PGP Key", "*.asc"), ("All Files", "*.*")],
            )
            content = f"{self.current_key.public_key}\n\n{self.current_key.private_key}"
        else:
            return

        if path and content:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.gen_status_label.configure(
                text=f"✓ Exported to {path.split('/')[-1]}",
                text_color=COLOR_SUCCESS,
            )

    def _save_into_vault(self):
        if not self.current_key:
            return

        entry = VaultEntry.create_keypair(
            title=f"{self.current_key.comment or self.current_key.algorithm_name} Key",
            key_name=self.current_key.comment or self.current_key.algorithm_name,
            key_type=self.current_key.key_type,
            public_key=self.current_key.public_key,
            private_key=self.current_key.private_key,
            fingerprint=self.current_key.fingerprint,
            tags=[self.current_key.key_type, "generated", "keys"],
            notes=self.current_key.format_notes,
        )

        if self.on_save_to_vault:
            self.on_save_to_vault(entry)
            self.gen_status_label.configure(
                text="✓ Saved keypair directly to StarVault entries!",
                text_color=COLOR_SUCCESS,
            )
