"""Unlock, First-Run Setup, and Backup Restore View for StarVault with True Local 2FA."""

import math
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable, Optional
import customtkinter as ctk

from starvault.app_config import AppConfigManager
from starvault.qr_keyfile import (
    KeyfileError,
    generate_keyfile_token,
    generate_qr_image,
    read_keyfile_token,
    save_qr_image,
)
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
from starvault.ui.widgets import add_password_toggle


def calculate_password_entropy(password: str) -> float:
    """Estimates password entropy in bits."""
    if not password:
        return 0.0
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


class UnlockView(ctk.CTkFrame):
    """View presenting either master vault creation or master password + 2FA unlock."""

    def __init__(
        self,
        parent,
        is_initialized: bool,
        on_unlock_success: Callable[..., None],
        on_initialize_success: Callable[..., None],
        database,
        app_config: Optional[AppConfigManager] = None,
        on_switch_vault: Optional[Callable[[Path], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.is_initialized = is_initialized
        self.on_unlock_success = on_unlock_success
        self.on_initialize_success = on_initialize_success
        self.database = database
        self.app_config = app_config
        self.on_switch_vault = on_switch_vault

        self._show_password = False
        self.loaded_keyfile_token: Optional[str] = None
        self.loaded_keyfile_name: Optional[str] = None
        self.setup_keyfile_token: Optional[str] = None

        self._build_ui()

    def _build_ui(self):
        # Clear existing children if re-building after restore
        for child in self.winfo_children():
            child.destroy()

        # Center container
        self.card = ctk.CTkFrame(
            self,
            fg_color=BG_CARD,
            corner_radius=16,
            border_width=1,
            border_color=BORDER_COLOR,
            width=500,
        )
        self.card.place(relx=0.5, rely=0.5, anchor="center")

        pad_x, pad_y = 36, 28

        # Header Badge / Icon
        logo_label = ctk.CTkLabel(
            self.card,
            text="★",
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color=ACCENT_PRIMARY,
        )
        logo_label.pack(pady=(pad_y, 4))

        title_text = "StarVault" if self.is_initialized else "Create Your StarVault"
        title_label = ctk.CTkLabel(
            self.card,
            text=title_text,
            font=get_font(22, "bold"),
            text_color=TEXT_PRIMARY,
        )
        title_label.pack()

        req_2fa = self.is_initialized and self.database.requires_2fa()
        if self.is_initialized:
            subtitle_text = (
                "Enter Master Password & scan/select your QR Keyfile"
                if req_2fa
                else "Enter master password to unlock vault"
            )
        else:
            subtitle_text = "Set a strong master password and optional True Local 2FA keyfile."

        self.subtitle_label = ctk.CTkLabel(
            self.card,
            text=subtitle_text,
            font=get_font(12),
            text_color=TEXT_SECONDARY,
            wraplength=420,
            justify="center",
        )
        self.subtitle_label.pack(pady=(4, 12))

        # Vault Selector Bar
        vault_bar = ctk.CTkFrame(self.card, fg_color=BG_INPUT, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        vault_bar.pack(fill="x", padx=pad_x, pady=(0, 10))

        v_inner = ctk.CTkFrame(vault_bar, fg_color="transparent")
        v_inner.pack(fill="x", padx=10, pady=6)

        db_name = self.database.db_path.name
        ctk.CTkLabel(
            v_inner,
            text=f"📁 Vault: {db_name}",
            font=get_font(11, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        recents = self.app_config.get_recent_vaults() if self.app_config else []
        if len(recents) > 1:
            recent_options = [p.name for p in recents] + ["📂 Open File..."]
            self.recent_combo = ctk.CTkComboBox(
                v_inner,
                values=recent_options,
                width=140,
                height=26,
                font=get_font(10),
                command=self._on_recent_vault_selected,
            )
            self.recent_combo.set(db_name)
            self.recent_combo.pack(side="right")
        else:
            ctk.CTkButton(
                v_inner,
                text="📂 Switch...",
                width=75,
                height=24,
                font=get_font(10, "bold"),
                fg_color=BG_CARD,
                hover_color=BORDER_COLOR,
                command=self._choose_different_vault,
            ).pack(side="right")

        # 1. Password Entry Field
        pwd_container = ctk.CTkFrame(self.card, fg_color="transparent")
        pwd_container.pack(fill="x", padx=pad_x, pady=4)

        ctk.CTkLabel(
            pwd_container,
            text="Master Password *",
            font=get_font(12, "bold"),
            text_color=TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x")

        entry_row = ctk.CTkFrame(pwd_container, fg_color="transparent")
        entry_row.pack(fill="x", pady=(4, 0))

        self.pwd_entry = ctk.CTkEntry(
            entry_row,
            show="•",
            font=get_font(14),
            height=40,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            placeholder_text="Enter master password...",
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.pwd_entry.bind("<Return>", lambda e: self._handle_submit())

        self.toggle_eye_btn = ctk.CTkButton(
            entry_row,
            text="👁",
            width=40,
            height=40,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self._toggle_password_visibility,
        )
        self.toggle_eye_btn.pack(side="right")

        # 2. True Local 2FA QR Keyfile Section
        if req_2fa:
            self._build_2fa_unlock_section(pad_x)

        elif not self.is_initialized:
            self._build_first_run_setup_section(pad_x)

        # Passwordless Launch / Remember Me Option
        if self.is_initialized:
            self.var_remember_me = ctk.BooleanVar(
                value=self.app_config.is_remember_password_enabled() if self.app_config else False
            )
            chk_box = ctk.CTkFrame(self.card, fg_color="transparent")
            chk_box.pack(fill="x", padx=pad_x, pady=(6, 0))

            ctk.CTkCheckBox(
                chk_box,
                text="Remember Me (OS Credential Manager)",
                variable=self.var_remember_me,
                font=get_font(11, "bold"),
                text_color=TEXT_PRIMARY,
            ).pack(anchor="w")

            ctk.CTkLabel(
                chk_box,
                text="⚠️ Reduces local security: stores derived master credential in OS keychain.",
                font=get_font(10),
                text_color=TEXT_MUTED,
                wraplength=420,
                justify="left",
            ).pack(anchor="w", pady=(1, 4))

        # Error / Feedback label
        self.error_label = ctk.CTkLabel(
            self.card,
            text="",
            font=get_font(12),
            text_color=COLOR_DANGER,
            wraplength=420,
        )
        self.error_label.pack(pady=(4, 2))

        # Submit button
        btn_text = "Unlock Vault" if self.is_initialized else "Initialize & Create Vault"
        self.submit_btn = ctk.CTkButton(
            self.card,
            text=btn_text,
            font=get_font(14, "bold"),
            height=44,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=self._handle_submit,
        )
        self.submit_btn.pack(fill="x", padx=pad_x, pady=(6, 12))

        # Bottom Utilities (Restore from Backup)
        bottom_row = ctk.CTkFrame(self.card, fg_color="transparent")
        bottom_row.pack(fill="x", padx=pad_x, pady=(0, pad_y))

        ctk.CTkButton(
            bottom_row,
            text="🔄 Restore from Backup (.db)...",
            font=get_font(11),
            fg_color="transparent",
            hover_color=BG_INPUT,
            text_color=TEXT_MUTED,
            height=28,
            command=self._handle_restore_from_backup,
        ).pack(side="left")

        # Focus password entry
        self.pwd_entry.focus_set()

    def _build_2fa_unlock_section(self, pad_x: int):
        """Builds QR code keyfile picker for 2FA-protected vaults."""
        container = ctk.CTkFrame(self.card, fg_color=BG_SUBTLE, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        container.pack(fill="x", padx=pad_x, pady=(10, 6))

        h_row = ctk.CTkFrame(container, fg_color="transparent")
        h_row.pack(fill="x", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            h_row,
            text="🛡️ TRUE LOCAL 2FA KEYFILE",
            font=get_font(10, "bold"),
            text_color=ACCENT_PURPLE,
        ).pack(side="left")

        self.keyfile_badge = ctk.CTkLabel(
            h_row,
            text="REQUIRED",
            font=get_font(9, "bold"),
            fg_color=BG_INPUT,
            text_color=COLOR_WARNING,
            corner_radius=4,
            padx=6,
            pady=1,
        )
        self.keyfile_badge.pack(side="right")

        picker_row = ctk.CTkFrame(container, fg_color="transparent")
        picker_row.pack(fill="x", padx=12, pady=(4, 10))

        ctk.CTkButton(
            picker_row,
            text="📁 Select QR Keyfile...",
            font=get_font(12, "bold"),
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._select_keyfile_file,
        ).pack(side="left", padx=(0, 8))

        self.keyfile_name_label = ctk.CTkLabel(
            picker_row,
            text="No keyfile loaded",
            font=get_mono_font(11),
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self.keyfile_name_label.pack(side="left", fill="x", expand=True)

        self.clear_keyfile_btn = ctk.CTkButton(
            picker_row,
            text="✖",
            width=28,
            height=28,
            fg_color="transparent",
            hover_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            command=self._clear_loaded_keyfile,
        )

    def _build_first_run_setup_section(self, pad_x: int):
        """Builds password confirmation, strength meter, and optional 2FA setup for first run."""
        # Strength bar
        self.strength_bar = ctk.CTkProgressBar(
            self.card,
            height=4,
            fg_color=BG_INPUT,
            progress_color=COLOR_DANGER,
        )
        self.strength_bar.set(0.0)
        self.strength_bar.pack(fill="x", padx=pad_x, pady=(6, 2))

        self.strength_label = ctk.CTkLabel(
            self.card,
            text="Password strength: Enter at least 6 characters",
            font=get_font(11),
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self.strength_label.pack(fill="x", padx=pad_x)
        self.pwd_entry.bind("<KeyRelease>", self._on_password_typing)

        # Confirm Password Field
        confirm_container = ctk.CTkFrame(self.card, fg_color="transparent")
        confirm_container.pack(fill="x", padx=pad_x, pady=(8, 4))

        ctk.CTkLabel(
            confirm_container,
            text="Confirm Master Password *",
            font=get_font(12, "bold"),
            text_color=TEXT_SECONDARY,
            anchor="w",
        ).pack(fill="x")

        c_row = ctk.CTkFrame(confirm_container, fg_color="transparent")
        c_row.pack(fill="x", pady=(4, 0))

        self.confirm_entry = ctk.CTkEntry(
            c_row,
            show="•",
            font=get_font(14),
            height=40,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            placeholder_text="Repeat master password...",
        )
        self.confirm_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.confirm_entry.bind("<Return>", lambda e: self._handle_submit())
        add_password_toggle(c_row, self.confirm_entry, width=40, height=40)

        # 2FA Keyfile Option Checkbox
        twofa_box = ctk.CTkFrame(self.card, fg_color=BG_SUBTLE, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        twofa_box.pack(fill="x", padx=pad_x, pady=(10, 6))

        self.var_enable_2fa = ctk.BooleanVar(value=True)
        chk = ctk.CTkCheckBox(
            twofa_box,
            text="Enable True Local 2FA (QR Code Keyfile) [Recommended]",
            variable=self.var_enable_2fa,
            command=self._on_toggle_setup_2fa,
            font=get_font(12, "bold"),
            text_color=TEXT_PRIMARY,
        )
        chk.pack(anchor="w", padx=12, pady=(10, 4))

        self.setup_2fa_frame = ctk.CTkFrame(twofa_box, fg_color="transparent")
        self.setup_2fa_frame.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(
            self.setup_2fa_frame,
            text="Fuses your password with an offline 256-bit QR keyfile.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            anchor="w",
        ).pack(fill="x", pady=(0, 4))

        btn_row = ctk.CTkFrame(self.setup_2fa_frame, fg_color="transparent")
        btn_row.pack(fill="x")

        self.btn_gen_qr = ctk.CTkButton(
            btn_row,
            text="💾 Generate & Save QR Keyfile (.png)",
            font=get_font(11, "bold"),
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._generate_and_save_setup_keyfile,
        )
        self.btn_gen_qr.pack(side="left")

        self.setup_qr_status = ctk.CTkLabel(
            btn_row,
            text="Not saved yet",
            font=get_font(11),
            text_color=COLOR_WARNING,
        )
        self.setup_qr_status.pack(side="left", padx=10)

    def _on_toggle_setup_2fa(self):
        if self.var_enable_2fa.get():
            self.setup_2fa_frame.pack(fill="x", padx=12, pady=(0, 10))
        else:
            self.setup_2fa_frame.pack_forget()

    def _generate_and_save_setup_keyfile(self):
        token = generate_keyfile_token()
        dest = filedialog.asksaveasfilename(
            title="Save StarVault 2FA QR Keyfile",
            initialfile="starvault_keyfile.png",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
        )
        if dest:
            try:
                save_qr_image(token, dest)
                self.setup_keyfile_token = token
                self.setup_qr_status.configure(
                    text=f"✓ Saved: {Path(dest).name}",
                    text_color=COLOR_SUCCESS,
                )
            except Exception as e:
                self.setup_qr_status.configure(
                    text=f"Save failed: {str(e)}",
                    text_color=COLOR_DANGER,
                )

    def _select_keyfile_file(self):
        path = filedialog.askopenfilename(
            title="Select StarVault QR Keyfile",
            filetypes=[
                ("Keyfile & QR Images", "*.png;*.jpg;*.jpeg;*.bmp;*.webp;*.key;*.txt"),
                ("All Files", "*.*"),
            ],
        )
        if not path:
            return

        try:
            token = read_keyfile_token(path)
            self.loaded_keyfile_token = token
            self.loaded_keyfile_name = Path(path).name
            self.keyfile_name_label.configure(
                text=f"✓ {self.loaded_keyfile_name}",
                text_color=COLOR_SUCCESS,
            )
            self.keyfile_badge.configure(text="LOADED", text_color=COLOR_SUCCESS)
            self.clear_keyfile_btn.pack(side="right")
            self.error_label.configure(text="")
        except KeyfileError as e:
            self._show_error(str(e))
        except Exception as e:
            self._show_error(f"Failed to read keyfile: {str(e)}")

    def _clear_loaded_keyfile(self):
        self.loaded_keyfile_token = None
        self.loaded_keyfile_name = None
        self.keyfile_name_label.configure(text="No keyfile loaded", text_color=TEXT_MUTED)
        self.keyfile_badge.configure(text="REQUIRED", text_color=COLOR_WARNING)
        self.clear_keyfile_btn.pack_forget()

    def _handle_restore_from_backup(self):
        path = filedialog.askopenfilename(
            title="Select StarVault Backup Database to Restore",
            filetypes=[("StarVault Database", "*.db"), ("All Files", "*.*")],
        )
        if not path:
            return

        confirm = messagebox.askyesno(
            "Confirm Database Restore",
            f"Are you sure you want to restore the vault from:\n{path}?\n\n"
            "This will replace your current local vault with the selected backup.",
        )
        if not confirm:
            return

        try:
            success = self.database.restore_from_backup(Path(path))
            if success:
                self.is_initialized = self.database.is_initialized()
                self._build_ui()
                self.error_label.configure(
                    text="✓ Vault successfully restored from backup! Please unlock.",
                    text_color=COLOR_SUCCESS,
                )
            else:
                self._show_error("Failed to restore: Selected file is not a valid StarVault database.")
        except Exception as e:
            self._show_error(f"Restore error: {str(e)}")

    def _toggle_password_visibility(self):
        self._show_password = not self._show_password
        show_char = "" if self._show_password else "•"
        self.pwd_entry.configure(show=show_char)
        if hasattr(self, "confirm_entry"):
            self.confirm_entry.configure(show=show_char)
        self.toggle_eye_btn.configure(text="🔒" if self._show_password else "👁")

    def _on_password_typing(self, event=None):
        pwd = self.pwd_entry.get()
        if not pwd:
            self.strength_bar.set(0.0)
            self.strength_label.configure(
                text="Password strength: Enter at least 6 characters",
                text_color=TEXT_MUTED,
            )
            return

        entropy = calculate_password_entropy(pwd)
        ratio = min(1.0, entropy / 80.0)
        self.strength_bar.set(ratio)

        if len(pwd) < 6:
            self.strength_bar.configure(progress_color=COLOR_DANGER)
            self.strength_label.configure(
                text="Too short (minimum 6 characters required)",
                text_color=COLOR_DANGER,
            )
        elif entropy < 40:
            self.strength_bar.configure(progress_color=COLOR_WARNING)
            self.strength_label.configure(
                text="Moderate: Consider adding symbols and numbers",
                text_color=COLOR_WARNING,
            )
        else:
            self.strength_bar.configure(progress_color=COLOR_SUCCESS)
            self.strength_label.configure(
                text=f"Strong: ~{int(entropy)} bits entropy (Excellent)",
                text_color=COLOR_SUCCESS,
            )

    def _on_recent_vault_selected(self, choice: str):
        if choice == "📂 Open File...":
            self._choose_different_vault()
            return
        if self.app_config and self.on_switch_vault:
            for p in self.app_config.get_recent_vaults():
                if p.name == choice:
                    self.on_switch_vault(p)
                    break

    def _choose_different_vault(self):
        chosen = filedialog.askopenfilename(
            title="Select StarVault Database (.db)",
            filetypes=[("StarVault Database", "*.db"), ("All Files", "*.*")],
        )
        if chosen and self.on_switch_vault:
            self.on_switch_vault(Path(chosen))

    def _handle_submit(self):
        self.error_label.configure(text="")
        password = self.pwd_entry.get().strip()

        if not password:
            self._show_error("Please enter your master password.")
            return

        if self.is_initialized:
            # Check if 2FA keyfile is required
            req_2fa = self.database.requires_2fa()
            if req_2fa and not self.loaded_keyfile_token:
                self._show_error("True Local 2FA enabled: Please select your QR Keyfile image.")
                return

            self.submit_btn.configure(state="disabled", text="Verifying...")
            self.update_idletasks()

            success, key = self.database.unlock_vault(
                master_password=password,
                keyfile_secret=self.loaded_keyfile_token if req_2fa else None,
            )
            if success and key:
                if self.app_config:
                    if hasattr(self, "var_remember_me") and self.var_remember_me.get():
                        self.app_config.save_vault_credential(
                            self.database.db_path,
                            password,
                            self.loaded_keyfile_token if req_2fa else None,
                        )
                    else:
                        self.app_config.clear_saved_vault_credential(self.database.db_path)
                        self.app_config.set_remember_password_enabled(False)

                # Pass both key and password for migration detection
                self.on_unlock_success(key, password)
            else:
                self.submit_btn.configure(state="normal", text="Unlock Vault")
                if req_2fa:
                    self._show_error("Access denied: Incorrect master password or invalid 2FA Keyfile.")
                else:
                    self._show_error("Incorrect master password. Access denied.")
                self.pwd_entry.delete(0, "end")
                self.pwd_entry.focus_set()
        else:
            # First-run setup
            confirm = self.confirm_entry.get().strip()
            if len(password) < 6:
                self._show_error("Master password must be at least 6 characters long.")
                return
            if password != confirm:
                self._show_error("Passwords do not match. Please re-type carefully.")
                return

            use_2fa = self.var_enable_2fa.get()
            if use_2fa and not self.setup_keyfile_token:
                self._show_error("Please generate and save your QR Keyfile first.")
                return

            self.submit_btn.configure(state="disabled", text="Deriving Key (Argon2id)...")
            self.update_idletasks()

            try:
                key = self.database.initialize_vault(
                    master_password=password,
                    keyfile_secret=self.setup_keyfile_token if use_2fa else None,
                )
                self.on_initialize_success(key, password)
            except Exception as e:
                self.submit_btn.configure(state="normal", text="Initialize & Create Vault")
                self._show_error(f"Initialization error: {str(e)}")

    def _show_error(self, message: str):
        self.error_label.configure(text=message, text_color=COLOR_DANGER)
