"""QR / MFA / 2FA / Barcode Studio View for StarVault.

Provides:
1. 2FA Authenticator Hub:
   - Live RFC 6238 TOTP codes with real-time countdown progress bar.
   - Quick 1-click copy with 30s auto-clear.
   - Import via QR code scan (OpenCV), otpauth URI, or Base32 secret.
2. QR & Barcode Studio:
   - Generate custom QR codes and 1D Barcodes from any credential, URL, or note.
   - Decode QR / Barcodes from images.
   - Export to PNG or copy image to clipboard.
"""

from io import BytesIO
from tkinter import filedialog
from typing import Callable, Dict, List, Optional
import customtkinter as ctk
from PIL import Image, ImageTk

from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.models import VaultEntry
from starvault.totp import (
    build_otpauth_uri,
    decode_qr_image,
    generate_barcode_image,
    generate_qr_image,
    generate_totp_code,
    get_totp_remaining_seconds,
    parse_otpauth_uri,
)
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_CARD_HOVER,
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


class TotpView(ctk.CTkFrame):
    """MFA / 2FA Authenticator Hub and QR/Barcode Studio."""

    def __init__(
        self,
        parent,
        database: Database,
        session_key: bytes,
        clipboard_mgr: ClipboardManager,
        **kwargs,
    ) -> None:
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.database = database
        self.session_key = session_key
        self.clipboard_mgr = clipboard_mgr

        self.entries: List[VaultEntry] = []
        self._timer_running = True
        self._timer_id = None
        self._generated_img: Optional[Image.Image] = None
        self._photo_ref = None

        self._build_ui()
        self.reload()
        self._start_totp_loop()

    def update_session_key(self, new_key: bytes) -> None:
        self.session_key = new_key
        self.reload()

    def _build_ui(self) -> None:
        # Top Header Banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            title_box,
            text="📱 MFA / 2FA Authenticator & QR Studio",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="RFC 6238 TOTP authenticator tokens, QR code generator, and barcode reader.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Sub-tab Selector
        self.subtab_var = ctk.StringVar(value="2FA Authenticator")
        self.subtab_seg = ctk.CTkSegmentedButton(
            header,
            values=["2FA Authenticator", "QR & Barcode Studio"],
            variable=self.subtab_var,
            command=self._on_subtab_changed,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color="#000000",
            height=34,
        )
        self.subtab_seg.pack(side="right", padx=24, pady=15)

        # Containers for each subtab
        self.totp_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.studio_frame = ctk.CTkFrame(self, fg_color="transparent")

        self.totp_frame.pack(fill="both", expand=True)

        self._build_totp_hub()
        self._build_studio_hub()

    def _on_subtab_changed(self, tab: str) -> None:
        if tab == "2FA Authenticator":
            self.studio_frame.pack_forget()
            self.totp_frame.pack(fill="both", expand=True)
            self.reload()
        else:
            self.totp_frame.pack_forget()
            self.studio_frame.pack(fill="both", expand=True)

    # =========================================================================
    # TAB 1: 2FA AUTHENTICATOR HUB
    # =========================================================================
    def _build_totp_hub(self) -> None:
        # Top toolbar
        toolbar = ctk.CTkFrame(self.totp_frame, fg_color="transparent", height=42)
        toolbar.pack(fill="x", padx=24, pady=(12, 6))

        # Global countdown pill
        self.countdown_label = ctk.CTkLabel(
            toolbar,
            text="⏱️ Refresh in 30s",
            font=get_font(12, "bold"),
            text_color=COLOR_SUCCESS,
            fg_color=BG_INPUT,
            corner_radius=6,
            padx=12,
            pady=4,
        )
        self.countdown_label.pack(side="left")

        # Global progress bar
        self.time_progress = ctk.CTkProgressBar(toolbar, width=180, height=8, progress_color=COLOR_SUCCESS)
        self.time_progress.pack(side="left", padx=12)
        self.time_progress.set(1.0)

        # Add Token button
        ctk.CTkButton(
            toolbar,
            text="+ Add 2FA Token",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=34,
            command=self._open_add_totp_dialog,
        ).pack(side="right")

        # Scrollable container for TOTP cards
        self.totp_scroll = ctk.CTkScrollableFrame(self.totp_frame, fg_color="transparent")
        self.totp_scroll.pack(fill="both", expand=True, padx=24, pady=(6, 16))

    def reload(self) -> None:
        try:
            self.entries = self.database.get_all_entries(self.session_key)
        except Exception:
            self.entries = []
        self._render_totp_cards()

    def _get_totp_items(self) -> List[dict]:
        items = []
        for e in self.entries:
            secret = e.totp_secret
            if not secret:
                for cf in e.custom_fields:
                    if "totp" in cf.get("key", "").lower() or "2fa" in cf.get("key", "").lower():
                        secret = cf.get("value", "")
                        break
            if secret and secret.strip():
                items.append({
                    "entry_id": e.id,
                    "title": e.title,
                    "account": e.username or e.app_name or e.provider or "Account",
                    "secret": secret.strip(),
                    "category": e.category,
                })
        return items

    def _render_totp_cards(self) -> None:
        for child in self.totp_scroll.winfo_children():
            child.destroy()

        totp_items = self._get_totp_items()
        if not totp_items:
            empty = ctk.CTkFrame(self.totp_scroll, fg_color=BG_CARD, corner_radius=10)
            empty.pack(fill="x", pady=40, padx=20)
            ctk.CTkLabel(
                empty,
                text="📱 No 2FA Tokens Configured Yet",
                font=get_font(15, "bold"),
                text_color=TEXT_PRIMARY,
            ).pack(pady=(24, 6))
            ctk.CTkLabel(
                empty,
                text="Add Google Authenticator / Authy tokens to StarVault by scanning QR codes\n"
                "or entering Base32 secrets. Codes update automatically every 30 seconds.",
                font=get_font(12),
                text_color=TEXT_MUTED,
                justify="center",
            ).pack(pady=(0, 16))
            ctk.CTkButton(
                empty,
                text="+ Add First 2FA Token",
                font=get_font(12, "bold"),
                fg_color=ACCENT_PRIMARY,
                hover_color=ACCENT_HOVER,
                text_color="#000000",
                command=self._open_add_totp_dialog,
            ).pack(pady=(0, 24))
            return

        self._totp_code_labels = {}
        for item in totp_items:
            card = ctk.CTkFrame(
                self.totp_scroll,
                fg_color=BG_CARD,
                corner_radius=10,
                border_width=1,
                border_color=BORDER_COLOR,
            )
            card.pack(fill="x", pady=6)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=16, pady=12)

            # Left side: Service Title & Account
            left_col = ctk.CTkFrame(inner, fg_color="transparent")
            left_col.pack(side="left", fill="x", expand=True)

            ctk.CTkLabel(
                left_col,
                text=item["title"],
                font=get_font(14, "bold"),
                text_color=TEXT_PRIMARY,
            ).pack(anchor="w")

            ctk.CTkLabel(
                left_col,
                text=f"{item['account']}  •  {item['category']}",
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(anchor="w")

            # Right side: 6-digit Code + Copy Button
            right_col = ctk.CTkFrame(inner, fg_color="transparent")
            right_col.pack(side="right")

            code = generate_totp_code(item["secret"])
            formatted_code = f"{code[:3]} {code[3:]}" if len(code) == 6 else code

            code_lbl = ctk.CTkLabel(
                right_col,
                text=formatted_code,
                font=get_mono_font(20, "bold"),
                text_color=COLOR_SUCCESS,
                width=130,
            )
            code_lbl.pack(side="left", padx=12)
            self._totp_code_labels[item["entry_id"]] = (code_lbl, item["secret"])

            ctk.CTkButton(
                right_col,
                text="📋 Copy Code",
                font=get_font(11, "bold"),
                width=100,
                height=32,
                fg_color=BG_INPUT,
                hover_color=ACCENT_PRIMARY,
                text_color=TEXT_PRIMARY,
                command=lambda s=item["secret"], t=item["title"]: self._copy_totp(s, t),
            ).pack(side="left", padx=4)

    def _copy_totp(self, secret: str, title: str) -> None:
        code = generate_totp_code(secret)
        self.clipboard_mgr.copy(code, is_secret=True, description=f"2FA code for '{title}' ({code})")

    def _start_totp_loop(self) -> None:
        if not self._timer_running:
            return

        rem = get_totp_remaining_seconds()
        self.countdown_label.configure(text=f"⏱️ Refresh in {rem}s")
        self.time_progress.set(rem / 30.0)

        # Color changes when time is low
        if rem <= 5:
            self.countdown_label.configure(text_color=COLOR_DANGER)
            self.time_progress.configure(progress_color=COLOR_DANGER)
        elif rem <= 10:
            self.countdown_label.configure(text_color=COLOR_WARNING)
            self.time_progress.configure(progress_color=COLOR_WARNING)
        else:
            self.countdown_label.configure(text_color=COLOR_SUCCESS)
            self.time_progress.configure(progress_color=COLOR_SUCCESS)

        # Refresh code labels when near or at 30
        if hasattr(self, "_totp_code_labels"):
            for eid, (lbl, secret) in self._totp_code_labels.items():
                code = generate_totp_code(secret)
                fmt = f"{code[:3]} {code[3:]}" if len(code) == 6 else code
                lbl.configure(text=fmt)

        self._timer_id = self.after(1000, self._start_totp_loop)

    def destroy(self) -> None:
        self._timer_running = False
        if self._timer_id:
            self.after_cancel(self._timer_id)
        super().destroy()

    def _open_add_totp_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("Add 2FA Authenticator Token")
        dlg.geometry("520x480")
        dlg.transient(self)
        dlg.grab_set()

        ctk.CTkLabel(dlg, text="Add New 2FA Account", font=get_font(16, "bold")).pack(pady=(20, 4))
        ctk.CTkLabel(
            dlg,
            text="Scan QR code from an image file, paste an otpauth:// link, or enter secret key.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(pady=(0, 16))

        content = ctk.CTkFrame(dlg, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=24)

        ctk.CTkLabel(content, text="Account / Service Title *", font=get_font(12)).pack(anchor="w")
        title_entry = ctk.CTkEntry(content, placeholder_text="e.g. GitHub, AWS Console, Cloudflare", height=36)
        title_entry.pack(fill="x", pady=(4, 10))

        ctk.CTkLabel(content, text="Username / Email", font=get_font(12)).pack(anchor="w")
        user_entry = ctk.CTkEntry(content, placeholder_text="user@example.com", height=36)
        user_entry.pack(fill="x", pady=(4, 10))

        ctk.CTkLabel(content, text="Base32 Secret Key or otpauth:// URI *", font=get_font(12)).pack(anchor="w")
        secret_entry = ctk.CTkEntry(content, placeholder_text="JBSWY3DPEHPK3PXP...", height=36)
        secret_entry.pack(fill="x", pady=(4, 10))

        def scan_qr_file():
            path = filedialog.askopenfilename(
                title="Select 2FA QR Code Image",
                filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All Files", "*.*")],
            )
            if path:
                val = decode_qr_image(path)
                if val:
                    if val.startswith("otpauth://"):
                        try:
                            parsed = parse_otpauth_uri(val)
                            title_entry.delete(0, "end")
                            title_entry.insert(0, parsed.get("issuer") or parsed.get("account"))
                            user_entry.delete(0, "end")
                            user_entry.insert(0, parsed.get("account"))
                            secret_entry.delete(0, "end")
                            secret_entry.insert(0, parsed.get("secret"))
                        except Exception:
                            secret_entry.delete(0, "end")
                            secret_entry.insert(0, val)
                    else:
                        secret_entry.delete(0, "end")
                        secret_entry.insert(0, val)

        ctk.CTkButton(
            content,
            text="📷 Scan QR Code Image File...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=scan_qr_file,
            height=32,
        ).pack(anchor="w", pady=(0, 16))

        status_lbl = ctk.CTkLabel(content, text="", font=get_font(11), text_color=COLOR_DANGER)
        status_lbl.pack()

        def save_token():
            t = title_entry.get().strip()
            s = secret_entry.get().strip()
            u = user_entry.get().strip()

            if not t or not s:
                status_lbl.configure(text="Please provide a title and secret key.")
                return

            if s.startswith("otpauth://"):
                try:
                    p = parse_otpauth_uri(s)
                    s = p.get("secret", s)
                    if not u:
                        u = p.get("account", "")
                except Exception:
                    pass

            entry = VaultEntry(
                title=t,
                entry_type="service",
                category="Services",
                username=u,
                totp_secret=s,
                notes="2FA Authenticator Token",
            )
            self.database.save_entry(entry, self.session_key)
            self.reload()
            dlg.destroy()

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=16)

        ctk.CTkButton(btn_row, text="Cancel", fg_color=BG_INPUT, command=dlg.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btn_row, text="Save Token", fg_color=ACCENT_PRIMARY, text_color="#000000", command=save_token).pack(side="right")

    # =========================================================================
    # TAB 2: QR & BARCODE STUDIO
    # =========================================================================
    def _build_studio_hub(self) -> None:
        scroll = ctk.CTkScrollableFrame(self.studio_frame, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=24, pady=16)

        split = ctk.CTkFrame(scroll, fg_color="transparent")
        split.pack(fill="both", expand=True)

        # Left Column: Input Form
        left = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))

        ctk.CTkLabel(left, text="GENERATE CODE", font=get_font(12, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 8))

        # Code type selector
        self.code_type_var = ctk.StringVar(value="QR Code (2D)")
        ctk.CTkSegmentedButton(
            left,
            values=["QR Code (2D)", "Barcode (1D)"],
            variable=self.code_type_var,
            font=get_font(11, "bold"),
            selected_color=ACCENT_PRIMARY,
            text_color="#000000",
            height=34,
        ).pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(left, text="Content / Text / Secret / URL *", font=get_font(12)).pack(anchor="w", padx=16)
        self.studio_text = ctk.CTkTextbox(left, height=120, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(12))
        self.studio_text.pack(fill="x", padx=16, pady=(4, 12))
        self.studio_text.insert("1.0", "https://github.com/YOUR_USERNAME/StarVault")

        gen_btn_row = ctk.CTkFrame(left, fg_color="transparent")
        gen_btn_row.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(
            gen_btn_row,
            text="⚡ Render Code",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=38,
            command=self._render_studio_code,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            gen_btn_row,
            text="📷 Scan File...",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            height=38,
            command=self._scan_file_studio,
        ).pack(side="left")

        # Right Column: Visual Preview & Export
        right = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR)
        right.pack(side="right", fill="both", expand=True, padx=(12, 0))

        ctk.CTkLabel(right, text="PREVIEW & EXPORT", font=get_font(12, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 8))

        self.preview_canvas = ctk.CTkLabel(right, text="", width=260, height=260, fg_color=BG_INPUT, corner_radius=8)
        self.preview_canvas.pack(padx=16, pady=12)

        export_row = ctk.CTkFrame(right, fg_color="transparent")
        export_row.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(
            export_row,
            text="💾 Save PNG...",
            font=get_font(12),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._save_image_png,
        ).pack(side="left", padx=(0, 8))

        self._render_studio_code()

    def _render_studio_code(self) -> None:
        raw_text = self.studio_text.get("1.0", "end").strip()
        if not raw_text:
            return

        code_type = self.code_type_var.get()
        if "QR" in code_type:
            pil_img = generate_qr_image(raw_text, box_size=7)
        else:
            pil_img = generate_barcode_image(raw_text, height=100)

        self._generated_img = pil_img
        # Resize for preview
        display_img = pil_img.copy()
        display_img.thumbnail((240, 240))
        ctk_img = ctk.CTkImage(light_image=display_img, dark_image=display_img, size=display_img.size)
        self.preview_canvas.configure(image=ctk_img, text="")

    def _save_image_png(self) -> None:
        if not self._generated_img:
            return
        dest = filedialog.asksaveasfilename(
            title="Save Rendered Code",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
        )
        if dest:
            self._generated_img.save(dest)

    def _scan_file_studio(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Code Image",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All Files", "*.*")],
        )
        if path:
            val = decode_qr_image(path)
            if val:
                self.studio_text.delete("1.0", "end")
                self.studio_text.insert("1.0", val)
                self._render_studio_code()
