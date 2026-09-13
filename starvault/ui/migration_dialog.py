"""Legacy Vault Migration Dialog for True Local 2FA Upgrade."""

from tkinter import filedialog
from typing import Callable, Optional
import customtkinter as ctk
from PIL import ImageTk

from starvault.database import Database
from starvault.qr_keyfile import generate_keyfile_token, generate_qr_image, save_qr_image
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


class MigrationDialog(ctk.CTkToplevel):
    """Modal dialog guiding users through upgrading legacy single-factor vaults to True Local 2FA."""

    def __init__(
        self,
        parent,
        database: Database,
        old_key: bytes,
        master_password: str,
        on_migration_success: Callable[[bytes], None],
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.database = database
        self.old_key = old_key
        self.master_password = master_password
        self.on_migration_success = on_migration_success

        self.title("StarVault - Security Upgrade to True Local 2FA")
        self.geometry("680x760")
        self.minsize(620, 680)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        # Generate 256-bit token and preview image
        self.token = generate_keyfile_token()
        self.keyfile_saved_path: Optional[str] = None
        self._qr_tk_img = None

        self._build_ui()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="🛡️ Upgrade to True Local 2FA",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=24, pady=16)

        scroll = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True, padx=20, pady=16)

        # Card 1: ELI5 Explanation
        info_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        info_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            info_card,
            text="LEGACY VAULT DETECTED",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(anchor="w", padx=16, pady=(12, 4))

        explanation_text = (
            "Your vault currently uses legacy single-factor protection (Master Password only).\n\n"
            "StarVault True Local 2FA cryptographically fuses your Master Password with a unique "
            "256-bit QR Code Keyfile using Argon2id. Even if an attacker learns your master password "
            "via keylogger or shoulder-surfing, they CANNOT decrypt your database without your "
            "physical QR code file."
        )
        ctk.CTkLabel(
            info_card,
            text=explanation_text,
            font=get_font(12),
            text_color=TEXT_SECONDARY,
            justify="left",
            wraplength=540,
        ).pack(fill="x", padx=16, pady=(0, 14))

        # Card 2: Generated QR Code Display & Save
        qr_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        qr_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            qr_card,
            text="STEP 1: SAVE YOUR UNIQUE 256-BIT QR KEYFILE",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Render QR Code in UI
        qr_pil_img = generate_qr_image(self.token, box_size=5, border=3)
        self._qr_tk_img = ImageTk.PhotoImage(qr_pil_img)

        qr_img_label = ctk.CTkLabel(qr_card, image=self._qr_tk_img, text="")
        qr_img_label.pack(pady=(4, 8))

        ctk.CTkLabel(
            qr_card,
            text="Save this image to an external USB flash drive or offline storage.\nDo not store it on the same drive as your database!",
            font=get_font(11),
            text_color=TEXT_MUTED,
            justify="center",
        ).pack(pady=(0, 8))

        btn_row = ctk.CTkFrame(qr_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))

        self.save_btn = ctk.CTkButton(
            btn_row,
            text="💾 Save QR Code Image (.png)...",
            font=get_font(12, "bold"),
            height=36,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=self._save_qr_keyfile,
        )
        self.save_btn.pack(side="left")

        self.save_status_label = ctk.CTkLabel(
            btn_row,
            text="Required before upgrading",
            font=get_font(11),
            text_color=COLOR_WARNING,
        )
        self.save_status_label.pack(side="left", padx=12)

        # Card 3: Re-encrypt & Migrate
        mig_card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        mig_card.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(
            mig_card,
            text="STEP 2: RE-ENCRYPT DATABASE WITH COMPOSITE KEY",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            mig_card,
            text="All existing records will be atomically re-encrypted in memory using the new composite key and a fresh salt.",
            font=get_font(12),
            text_color=TEXT_SECONDARY,
            justify="left",
            wraplength=540,
        ).pack(fill="x", padx=16, pady=(0, 12))

        self.upgrade_btn = ctk.CTkButton(
            mig_card,
            text="🚀 Upgrade & Re-Encrypt Vault Now",
            font=get_font(13, "bold"),
            height=42,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            state="disabled",
            command=self._perform_migration,
        )
        self.upgrade_btn.pack(fill="x", padx=16, pady=(0, 14))

        # Bottom Bar
        bottom = ctk.CTkFrame(self, fg_color=BG_CARD, height=60, corner_radius=0)
        bottom.pack(fill="x", side="bottom")

        ctk.CTkButton(
            bottom,
            text="Remind Me Later",
            width=130,
            height=36,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self.destroy,
        ).pack(side="left", padx=20, pady=12)

    def _save_qr_keyfile(self):
        dest = filedialog.asksaveasfilename(
            title="Save StarVault 2FA QR Keyfile",
            initialfile="starvault_keyfile.png",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
        )
        if dest:
            try:
                save_qr_image(self.token, dest)
                self.keyfile_saved_path = dest
                self.save_status_label.configure(
                    text="✓ QR Keyfile saved securely!",
                    text_color=COLOR_SUCCESS,
                )
                self.upgrade_btn.configure(
                    state="normal",
                    fg_color=COLOR_SUCCESS,
                    hover_color="#059669",
                    text_color="#ffffff",
                )
            except Exception as e:
                self.save_status_label.configure(
                    text=f"Save failed: {str(e)}",
                    text_color=COLOR_DANGER,
                )

    def _perform_migration(self):
        if not self.keyfile_saved_path:
            return

        self.upgrade_btn.configure(state="disabled", text="Re-encrypting Database...")
        self.update_idletasks()

        try:
            new_key = self.database.upgrade_to_2fa(
                old_key=self.old_key,
                master_password=self.master_password,
                keyfile_token=self.token,
            )
            self.on_migration_success(new_key)
            self.destroy()
        except Exception as e:
            self.upgrade_btn.configure(state="normal", text="🚀 Upgrade & Re-Encrypt Vault Now")
            self.save_status_label.configure(
                text=f"Migration error: {str(e)}",
                text_color=COLOR_DANGER,
            )
