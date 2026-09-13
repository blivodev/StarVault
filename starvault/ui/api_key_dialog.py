"""API Key Generation & Management Studio for StarVault.

Generates tokens across all major industry formats:
- Hex, URL-Safe Base64, UUIDv4
- OpenAI style (sk-proj-...)
- Stripe style (sk_live_..., sk_test_...)
- GitHub style (ghp_...)
- AWS Access Key ID + Secret Key pairs
- JWT Simulation tokens
- Custom prefixed tokens

Features a direct '⚡ Use this Key' button that immediately populates the active
vault entry or launches a New Entry dialog pre-filled with the generated key!
"""

from typing import Callable, Optional, Tuple
import customtkinter as ctk

from starvault.api_keys import SUPPORTED_KEY_FORMATS, generate_api_key
from starvault.clipboard import ClipboardManager
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_INPUT,
    BG_ROOT,
    BORDER_COLOR,
    COLOR_SUCCESS,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    get_font,
    get_mono_font,
)


class ApiKeyStudioDialog(ctk.CTkToplevel):
    """Modal dialog for generating and configuring API keys across diverse formats."""

    def __init__(
        self,
        parent,
        clipboard_mgr: ClipboardManager,
        on_use_key: Optional[Callable[[str, str, str], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.clipboard_mgr = clipboard_mgr
        self.on_use_key = on_use_key

        self.title("StarVault - API Key Generator Studio")
        self.geometry("640x680")
        self.minsize(580, 580)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        self.current_key = ""
        self.current_secret = ""

        self._build_ui()
        self._generate_current()

    def _build_ui(self) -> None:
        # Header
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="⚡ API Key Studio & Generator",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=24, pady=16)

        ctk.CTkLabel(
            header,
            text="Generate tokens in various formats with instant 'Use' integration",
            font=get_font(12),
            text_color=TEXT_MUTED,
        ).pack(side="left", pady=16)

        # Body container
        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=16)

        # 1. Format Selection Card
        fmt_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        fmt_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(fmt_card, text="KEY FORMAT & PRESET", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))

        row1 = ctk.CTkFrame(fmt_card, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(0, 12))

        self.format_labels = [label for key, label in SUPPORTED_KEY_FORMATS]
        self.format_key_map = {label: key for key, label in SUPPORTED_KEY_FORMATS}

        self.fmt_combo = ctk.CTkComboBox(
            row1,
            values=self.format_labels,
            command=self._on_format_changed,
            font=get_font(12),
            height=36,
        )
        self.fmt_combo.set(self.format_labels[0])
        self.fmt_combo.pack(fill="x", pady=4)

        # Custom prefix row
        self.prefix_frame = ctk.CTkFrame(fmt_card, fg_color="transparent")
        self.prefix_frame.pack(fill="x", padx=16, pady=(0, 12))

        col_prefix = ctk.CTkFrame(self.prefix_frame, fg_color="transparent")
        col_prefix.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_prefix, text="Custom Prefix (e.g. 'prod', 'sk_live')", font=get_font(12)).pack(anchor="w")
        self.prefix_entry = ctk.CTkEntry(col_prefix, placeholder_text="sv", height=34)
        self.prefix_entry.insert(0, "sv")
        self.prefix_entry.pack(fill="x", pady=(4, 0))

        col_len = ctk.CTkFrame(self.prefix_frame, fg_color="transparent", width=140)
        col_len.pack(side="right")
        self.len_label = ctk.CTkLabel(col_len, text="Length: 48", font=get_font(12))
        self.len_label.pack(anchor="w")
        self.len_slider = ctk.CTkSlider(
            col_len,
            from_=16,
            to=96,
            number_of_steps=80,
            command=lambda v: self.len_label.configure(text=f"Length: {int(v)}"),
            width=130,
        )
        self.len_slider.set(48)
        self.len_slider.pack(fill="x", pady=(8, 0))

        # 2. Key Preview Card
        preview_card = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        preview_card.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(preview_card, text="GENERATED API KEY", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(12, 6))

        ctk.CTkLabel(preview_card, text="Primary API Token / Key ID:", font=get_font(12)).pack(anchor="w", padx=16)
        self.preview_token = ctk.CTkTextbox(preview_card, height=54, font=get_mono_font(12), fg_color=BG_INPUT, border_color=BORDER_COLOR)
        self.preview_token.pack(fill="x", padx=16, pady=(4, 8))

        # Secondary secret frame (for AWS keypairs)
        self.secret_frame = ctk.CTkFrame(preview_card, fg_color="transparent")
        self.secret_label = ctk.CTkLabel(self.secret_frame, text="Secret Access Key / Secondary Secret:", font=get_font(12))
        self.secret_label.pack(anchor="w")
        self.preview_secret = ctk.CTkTextbox(self.secret_frame, height=54, font=get_mono_font(12), fg_color=BG_INPUT, border_color=BORDER_COLOR)
        self.preview_secret.pack(fill="x", pady=(4, 8))

        # Re-roll button
        ctk.CTkButton(
            preview_card,
            text="🔄 Re-roll / Generate New",
            font=get_font(12, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=34,
            command=self._generate_current,
        ).pack(anchor="w", padx=16, pady=(4, 16))

        # Bottom Action Bar
        bottom = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        bottom.pack(fill="x", side="bottom")

        ctk.CTkButton(
            bottom,
            text="Close",
            width=90,
            height=38,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self.destroy,
        ).pack(side="right", padx=(8, 20), pady=12)

        ctk.CTkButton(
            bottom,
            text="📋 Copy Key",
            width=110,
            height=38,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._copy_key,
        ).pack(side="right", padx=4, pady=12)

        # Prominent 'Use this Key' or 'Use' button
        ctk.CTkButton(
            bottom,
            text="⚡ Use this Key",
            width=140,
            height=38,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            font=get_font(13, "bold"),
            command=self._use_key,
        ).pack(side="right", padx=4, pady=12)

    def _on_format_changed(self, choice: str) -> None:
        self._generate_current()

    def _generate_current(self) -> None:
        fmt_label = self.fmt_combo.get()
        fmt_key = self.format_key_map.get(fmt_label, "hex64")
        prefix = self.prefix_entry.get().strip() or "sv"
        length = int(self.len_slider.get())

        p_key, s_key = generate_api_key(format_type=fmt_key, prefix=prefix, length=length)
        self.current_key = p_key
        self.current_secret = s_key

        self.preview_token.delete("1.0", "end")
        self.preview_token.insert("1.0", p_key)

        if s_key:
            self.secret_frame.pack(fill="x", padx=16, pady=(0, 8))
            self.preview_secret.delete("1.0", "end")
            self.preview_secret.insert("1.0", s_key)
        else:
            self.secret_frame.pack_forget()

    def _copy_key(self) -> None:
        if self.current_key:
            self.clipboard_mgr.copy(self.current_key, is_secret=True, description="API Key")

    def _use_key(self) -> None:
        fmt_label = self.fmt_combo.get()
        fmt_key = self.format_key_map.get(fmt_label, "hex64")

        if self.on_use_key:
            self.on_use_key(self.current_key, self.current_secret, fmt_key)
        self.destroy()
