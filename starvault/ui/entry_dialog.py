"""Entry creation and editing modal dialog for StarVault."""

import random
import string
from typing import Callable, List, Optional
import customtkinter as ctk

from starvault.models import VaultEntry
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


def generate_secure_password(
    length: int = 24,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generates a cryptographically strong random password."""
    chars = ""
    reqs = []
    if use_upper:
        chars += string.ascii_uppercase
        reqs.append(random.choice(string.ascii_uppercase))
    if use_lower:
        chars += string.ascii_lowercase
        reqs.append(random.choice(string.ascii_lowercase))
    if use_digits:
        chars += string.digits
        reqs.append(random.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        chars += symbols
        reqs.append(random.choice(symbols))

    if not chars:
        chars = string.ascii_letters + string.digits

    remaining_len = max(0, length - len(reqs))
    import secrets

    random_chars = [secrets.choice(chars) for _ in range(remaining_len)]
    full_list = reqs + random_chars
    random.shuffle(full_list)
    return "".join(full_list)


class EntryDialog(ctk.CTkToplevel):
    """Modal dialog for creating or editing vault entries."""

    def __init__(
        self,
        parent,
        entry: Optional[VaultEntry] = None,
        default_type: str = "server",
        existing_tags: Optional[List[str]] = None,
        available_servers: Optional[List[VaultEntry]] = None,
        on_save: Optional[Callable[[VaultEntry], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.entry = entry
        self.default_type = entry.entry_type if entry else default_type
        self.existing_tags = existing_tags or []
        self.available_servers = available_servers or []
        self.on_save = on_save
        self.custom_field_rows: List[dict] = []
        self.server_id_map: dict = {}

        self.title("Edit Entry" if entry else "New Vault Entry")
        self.geometry("740x840")
        self.minsize(680, 700)
        self.configure(fg_color=BG_ROOT)

        # Make modal
        self.transient(parent)
        self.grab_set()

        self._show_passwords = False
        self._build_ui()
        if self.entry:
            self._populate_fields(self.entry)

    def _build_ui(self):
        # Header banner
        header_frame = ctk.CTkFrame(self, fg_color=BG_CARD, height=60, corner_radius=0)
        header_frame.pack(fill="x")

        title_text = "Edit Vault Entry" if self.entry else "Create Vault Entry"
        ctk.CTkLabel(
            header_frame,
            text=title_text,
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=24, pady=16)

        # Type selector segmented button
        self.type_var = ctk.StringVar(value=self.default_type)
        self.type_segmented = ctk.CTkSegmentedButton(
            header_frame,
            values=["server", "service", "keypair"],
            variable=self.type_var,
            command=self._on_type_changed,
            font=get_font(12, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color="#000000",
        )
        self.type_segmented.pack(side="right", padx=24, pady=12)

        # Scrollable container for dynamic form fields
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color=BG_ROOT)
        self.scroll_frame.pack(fill="both", expand=True, padx=20, pady=16)

        # 1. Common Basics Section (Title, Category, Tags)
        self._build_basics_section()

        # 2. Dynamic Type-Specific Container
        self.dynamic_container = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        self.dynamic_container.pack(fill="x", pady=(12, 0))
        self._render_type_fields(self.type_var.get())

        # 3. Custom Key-Value Fields
        self._build_custom_fields_section()

        # 4. Rich Notes Area
        self._build_notes_section()

        # Bottom Action Bar
        bottom_bar = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        bottom_bar.pack(fill="x", side="bottom")

        # Metadata Timestamps
        if self.entry:
            c_date = self.entry.created_at[:19].replace("T", " ") if self.entry.created_at else "Unknown"
            m_date = self.entry.updated_at[:19].replace("T", " ") if self.entry.updated_at else "Unknown"
            ctk.CTkLabel(
                bottom_bar,
                text=f"Created: {c_date}  |  Modified: {m_date}",
                font=get_font(11),
                text_color=TEXT_MUTED,
            ).pack(side="left", padx=20, pady=12)

        ctk.CTkButton(
            bottom_bar,
            text="Cancel",
            width=100,
            height=38,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self.destroy,
        ).pack(side="right", padx=(8, 24), pady=12)

        ctk.CTkButton(
            bottom_bar,
            text="Save Entry",
            width=130,
            height=38,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            font=get_font(13, "bold"),
            command=self._save,
        ).pack(side="right", pady=12)

    def _build_basics_section(self):
        basics_card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        basics_card.pack(fill="x", pady=(0, 8), padx=4)

        ctk.CTkLabel(
            basics_card,
            text="IDENTIFICATION & TAGS",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Title & Category Row
        row1 = ctk.CTkFrame(basics_card, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(0, 8))

        # Title
        col_title = ctk.CTkFrame(row1, fg_color="transparent")
        col_title.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_title, text="Title / Label *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.title_entry = ctk.CTkEntry(
            col_title,
            placeholder_text="e.g. VPS1-Debian, Postgres-Main, Prod-Deploy-Key",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.title_entry.pack(fill="x", pady=(4, 0))

        # Category
        col_cat = ctk.CTkFrame(row1, fg_color="transparent", width=200)
        col_cat.pack(side="right", padx=(8, 0))
        ctk.CTkLabel(col_cat, text="Category", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.category_entry = ctk.CTkComboBox(
            col_cat,
            values=["Infrastructure", "Services", "Databases", "Keys", "Homelab", "Production"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.category_entry.pack(fill="x", pady=(4, 0))

        # Tags Row (comma-separated with relational note)
        row_tags = ctk.CTkFrame(basics_card, fg_color="transparent")
        row_tags.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkLabel(
            row_tags,
            text="Relational Tags (comma separated, e.g. 'vps1, homelab, prod')",
            font=get_font(12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w")
        self.tags_entry = ctk.CTkEntry(
            row_tags,
            placeholder_text="vps1, homelab, docker",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.tags_entry.pack(fill="x", pady=(4, 0))

    def _render_type_fields(self, entry_type: str):
        # Clear dynamic container
        for child in self.dynamic_container.winfo_children():
            child.destroy()

        card = ctk.CTkFrame(
            self.dynamic_container,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="x", padx=4)

        if entry_type == "server":
            self._render_server_form(card)
        elif entry_type == "service":
            self._render_service_form(card)
        elif entry_type == "keypair":
            self._render_keypair_form(card)

    def _render_server_form(self, container):
        ctk.CTkLabel(
            container,
            text="SERVER & SSH DETAILS",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Hostname & Port
        row1 = ctk.CTkFrame(container, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)

        col_host = ctk.CTkFrame(row1, fg_color="transparent")
        col_host.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_host, text="Hostname or IP Address *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_host = ctk.CTkEntry(col_host, placeholder_text="192.168.1.50 or vps.example.com", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_host.pack(fill="x", pady=(4, 0))

        col_port = ctk.CTkFrame(row1, fg_color="transparent", width=120)
        col_port.pack(side="right")
        ctk.CTkLabel(col_port, text="Port", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_port = ctk.CTkEntry(col_port, placeholder_text="22", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36, width=110)
        self.server_port.insert(0, "22")
        self.server_port.pack(fill="x", pady=(4, 0))

        # Username & Password
        row2 = ctk.CTkFrame(container, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        col_user = ctk.CTkFrame(row2, fg_color="transparent")
        col_user.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_user, text="Username", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_user = ctk.CTkEntry(col_user, placeholder_text="root or debian", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_user.insert(0, "root")
        self.server_user.pack(fill="x", pady=(4, 0))

        col_pass = ctk.CTkFrame(row2, fg_color="transparent")
        col_pass.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_pass, text="Password (Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        pass_row = ctk.CTkFrame(col_pass, fg_color="transparent")
        pass_row.pack(fill="x", pady=(4, 0))
        self.server_pass = ctk.CTkEntry(pass_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_pass.pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            pass_row,
            text="🎲",
            width=36,
            height=36,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._open_password_generator_popup(self.server_pass),
        ).pack(side="right")

        # SSH Private Key & Sudo Password
        row3 = ctk.CTkFrame(container, fg_color="transparent")
        row3.pack(fill="x", padx=16, pady=(4, 14))

        col_sudo = ctk.CTkFrame(row3, fg_color="transparent")
        col_sudo.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_sudo, text="Sudo Password (Optional)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_sudo = ctk.CTkEntry(col_sudo, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_sudo.pack(fill="x", pady=(4, 0))

        col_distro = ctk.CTkFrame(row3, fg_color="transparent")
        col_distro.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_distro, text="OS Distro / Specs", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_distro = ctk.CTkEntry(col_distro, placeholder_text="Ubuntu 24.04, 4vCPU 8GB", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_distro.pack(fill="x", pady=(4, 0))

        # SSH Key box
        ssh_box = ctk.CTkFrame(container, fg_color="transparent")
        ssh_box.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkLabel(ssh_box, text="SSH Private Key (Optional, Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_key_text = ctk.CTkTextbox(ssh_box, height=80, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.server_key_text.pack(fill="x", pady=(4, 0))

    def _render_service_form(self, container):
        ctk.CTkLabel(
            container,
            text="SERVICE / APPLICATION DETAILS",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Host / Parent Server Dropdown
        row_parent = ctk.CTkFrame(container, fg_color="transparent")
        row_parent.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row_parent, text="Parent Server / VPS (Relational Hierarchy)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        server_options = ["None (Standalone)"]
        self.server_id_map = {"None (Standalone)": None}
        for s in self.available_servers:
            label = f"{s.title} ({s.hostname or 'No IP'})"
            server_options.append(label)
            self.server_id_map[label] = s.id

        self.parent_server_combo = ctk.CTkComboBox(
            row_parent,
            values=server_options,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.parent_server_combo.set("None (Standalone)")
        self.parent_server_combo.pack(fill="x", pady=(4, 0))

        # App Name & Service Type
        row1 = ctk.CTkFrame(container, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)

        col_app = ctk.CTkFrame(row1, fg_color="transparent")
        col_app.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_app, text="App / Service Name *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_app = ctk.CTkEntry(col_app, placeholder_text="PostgreSQL, Jellyfin, Docker Registry", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_app.pack(fill="x", pady=(4, 0))

        col_type = ctk.CTkFrame(row1, fg_color="transparent", width=180)
        col_type.pack(side="right")
        ctk.CTkLabel(col_type, text="Type Preset", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_type_combo = ctk.CTkComboBox(
            col_type,
            values=["postgresql", "mysql", "redis", "mongodb", "web", "docker", "api", "generic"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.service_type_combo.pack(fill="x", pady=(4, 0))

        # URL / Host & Port
        row2 = ctk.CTkFrame(container, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        col_url = ctk.CTkFrame(row2, fg_color="transparent")
        col_url.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_url, text="URI / Host / URL", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_url = ctk.CTkEntry(col_url, placeholder_text="http://192.168.1.50:8096 or localhost", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_url.pack(fill="x", pady=(4, 0))

        col_port = ctk.CTkFrame(row2, fg_color="transparent", width=120)
        col_port.pack(side="right")
        ctk.CTkLabel(col_port, text="Port", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_port = ctk.CTkEntry(col_port, placeholder_text="5432", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36, width=110)
        self.service_port.pack(fill="x", pady=(4, 0))

        # Username & Password
        row3 = ctk.CTkFrame(container, fg_color="transparent")
        row3.pack(fill="x", padx=16, pady=4)

        col_user = ctk.CTkFrame(row3, fg_color="transparent")
        col_user.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_user, text="Username / Role", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_user = ctk.CTkEntry(col_user, placeholder_text="postgres, admin, user", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_user.pack(fill="x", pady=(4, 0))

        col_pass = ctk.CTkFrame(row3, fg_color="transparent")
        col_pass.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_pass, text="Password (Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        pass_row = ctk.CTkFrame(col_pass, fg_color="transparent")
        pass_row.pack(fill="x", pady=(4, 0))
        self.service_pass = ctk.CTkEntry(pass_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_pass.pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            pass_row,
            text="🎲",
            width=36,
            height=36,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._open_password_generator_popup(self.service_pass),
        ).pack(side="right")

        # Database Name & API Key / Token
        row4 = ctk.CTkFrame(container, fg_color="transparent")
        row4.pack(fill="x", padx=16, pady=(4, 14))

        col_db = ctk.CTkFrame(row4, fg_color="transparent")
        col_db.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_db, text="Database Name (for SQL/Redis)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_db = ctk.CTkEntry(col_db, placeholder_text="mydb, production", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_db.pack(fill="x", pady=(4, 0))

        col_token = ctk.CTkFrame(row4, fg_color="transparent")
        col_token.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_token, text="API Key / Token (Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.service_token = ctk.CTkEntry(col_token, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_token.pack(fill="x", pady=(4, 0))

    def _render_keypair_form(self, container):
        ctk.CTkLabel(
            container,
            text="KEYPAIR DETAILS",
            font=get_font(11, "bold"),
            text_color=ACCENT_PURPLE,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Key Name & Algorithm
        row1 = ctk.CTkFrame(container, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)

        col_name = ctk.CTkFrame(row1, fg_color="transparent")
        col_name.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_name, text="Key Label *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_name_entry = ctk.CTkEntry(col_name, placeholder_text="Homelab Root SSH, Backup Deploy Key", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.key_name_entry.pack(fill="x", pady=(4, 0))

        col_algo = ctk.CTkFrame(row1, fg_color="transparent", width=180)
        col_algo.pack(side="right")
        ctk.CTkLabel(col_algo, text="Key Algorithm", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_type_combo = ctk.CTkComboBox(
            col_algo,
            values=["ed25519", "rsa4096", "gpg"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.key_type_combo.pack(fill="x", pady=(4, 0))

        # Fingerprint & Passphrase
        row2 = ctk.CTkFrame(container, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        col_fp = ctk.CTkFrame(row2, fg_color="transparent")
        col_fp.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_fp, text="Key Fingerprint", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_fp_entry = ctk.CTkEntry(col_fp, placeholder_text="SHA256:...", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.key_fp_entry.pack(fill="x", pady=(4, 0))

        col_pass = ctk.CTkFrame(row2, fg_color="transparent")
        col_pass.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_pass, text="Passphrase (Encrypted, if any)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_passphrase_entry = ctk.CTkEntry(col_pass, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.key_passphrase_entry.pack(fill="x", pady=(4, 0))

        # Public Key Box
        pub_box = ctk.CTkFrame(container, fg_color="transparent")
        pub_box.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(pub_box, text="Public Key (OpenSSH or Armored PGP)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_pub_text = ctk.CTkTextbox(pub_box, height=75, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.key_pub_text.pack(fill="x", pady=(4, 0))

        # Private Key Box
        priv_box = ctk.CTkFrame(container, fg_color="transparent")
        priv_box.pack(fill="x", padx=16, pady=(4, 14))
        ctk.CTkLabel(priv_box, text="Private Key (Encrypted at rest)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_priv_text = ctk.CTkTextbox(priv_box, height=90, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.key_priv_text.pack(fill="x", pady=(4, 0))

    def _build_custom_fields_section(self):
        self.cf_card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.cf_card.pack(fill="x", pady=(12, 0), padx=4)

        header_row = ctk.CTkFrame(self.cf_card, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            header_row,
            text="CUSTOM FIELDS (Key-Value Pairs, e.g. License, Expiry)",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(side="left")

        ctk.CTkButton(
            header_row,
            text="+ Add Field",
            width=90,
            height=26,
            font=get_font(11, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._add_custom_field_row(),
        ).pack(side="right")

        self.cf_rows_container = ctk.CTkFrame(self.cf_card, fg_color="transparent")
        self.cf_rows_container.pack(fill="x", padx=16, pady=(0, 12))

    def _add_custom_field_row(self, key_text: str = "", val_text: str = ""):
        row_frame = ctk.CTkFrame(self.cf_rows_container, fg_color="transparent")
        row_frame.pack(fill="x", pady=3)

        k_entry = ctk.CTkEntry(
            row_frame,
            placeholder_text="Key (e.g. Expiry, License, PIN)",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=32,
            width=200,
        )
        k_entry.insert(0, key_text)
        k_entry.pack(side="left", padx=(0, 6))

        v_entry = ctk.CTkEntry(
            row_frame,
            placeholder_text="Value (e.g. 2026-12-31, ABCD-1234)",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=32,
        )
        v_entry.insert(0, val_text)
        v_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        item_ref = {"frame": row_frame, "key": k_entry, "val": v_entry}

        def remove_row():
            if item_ref in self.custom_field_rows:
                self.custom_field_rows.remove(item_ref)
            row_frame.destroy()

        ctk.CTkButton(
            row_frame,
            text="✕",
            width=28,
            height=32,
            fg_color=BG_INPUT,
            hover_color=COLOR_DANGER,
            command=remove_row,
        ).pack(side="right")

        self.custom_field_rows.append(item_ref)

    def _build_notes_section(self):
        notes_card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        notes_card.pack(fill="x", pady=12, padx=4)

        ctk.CTkLabel(
            notes_card,
            text="RICH NOTES & CONFIGURATION (Encrypted at rest)",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            notes_card,
            text="Use for firewall rules, docker-compose snippets, mount points, or backup instructions.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=16)

        self.notes_text = ctk.CTkTextbox(
            notes_card,
            height=120,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            font=get_mono_font(12),
        )
        self.notes_text.pack(fill="x", padx=16, pady=(8, 16))

    def _on_type_changed(self, new_type: str):
        self._render_type_fields(new_type)

    def _open_password_generator_popup(self, target_entry: ctk.CTkEntry):
        """Spawns an interactive password generator widget popover."""
        popup = ctk.CTkToplevel(self)
        popup.title("Password Generator")
        popup.geometry("380x300")
        popup.transient(self)
        popup.grab_set()

        ctk.CTkLabel(popup, text="Generate Secure Password", font=get_font(14, "bold")).pack(pady=(16, 8))

        # Length slider
        len_frame = ctk.CTkFrame(popup, fg_color="transparent")
        len_frame.pack(fill="x", padx=20, pady=4)
        len_label = ctk.CTkLabel(len_frame, text="Length: 24", font=get_font(12))
        len_label.pack(side="left")

        slider = ctk.CTkSlider(
            len_frame,
            from_=8,
            to=64,
            number_of_steps=56,
            command=lambda v: len_label.configure(text=f"Length: {int(v)}"),
        )
        slider.set(24)
        slider.pack(side="right", fill="x", expand=True, padx=(10, 0))

        # Checkboxes
        chk_frame = ctk.CTkFrame(popup, fg_color="transparent")
        chk_frame.pack(fill="x", padx=20, pady=8)

        var_upper = ctk.BooleanVar(value=True)
        var_lower = ctk.BooleanVar(value=True)
        var_digits = ctk.BooleanVar(value=True)
        var_symbols = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(chk_frame, text="A-Z", variable=var_upper).grid(row=0, column=0, padx=4, pady=2)
        ctk.CTkCheckBox(chk_frame, text="a-z", variable=var_lower).grid(row=0, column=1, padx=4, pady=2)
        ctk.CTkCheckBox(chk_frame, text="0-9", variable=var_digits).grid(row=0, column=2, padx=4, pady=2)
        ctk.CTkCheckBox(chk_frame, text="!@#$", variable=var_symbols).grid(row=0, column=3, padx=4, pady=2)

        # Preview entry
        preview_entry = ctk.CTkEntry(popup, font=get_mono_font(13), height=38)
        preview_entry.pack(fill="x", padx=20, pady=8)

        def generate_and_show():
            pwd = generate_secure_password(
                length=int(slider.get()),
                use_upper=var_upper.get(),
                use_lower=var_lower.get(),
                use_digits=var_digits.get(),
                use_symbols=var_symbols.get(),
            )
            preview_entry.delete(0, "end")
            preview_entry.insert(0, pwd)

        generate_and_show()

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(8, 16))

        ctk.CTkButton(
            btn_row,
            text="🔄 Re-roll",
            width=100,
            command=generate_and_show,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
        ).pack(side="left")

        def use_password():
            pwd = preview_entry.get()
            target_entry.delete(0, "end")
            target_entry.insert(0, pwd)
            popup.destroy()

        ctk.CTkButton(
            btn_row,
            text="Use Password",
            width=140,
            command=use_password,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            font=get_font(12, "bold"),
        ).pack(side="right")

    def _populate_fields(self, entry: VaultEntry):
        self.type_var.set(entry.entry_type)
        self.title_entry.insert(0, entry.title)
        self.category_entry.set(entry.category)
        self.tags_entry.insert(0, entry.get_tags_display())

        # Render type-specific fields
        self._render_type_fields(entry.entry_type)

        if entry.entry_type == "server":
            self.server_host.insert(0, entry.hostname)
            self.server_port.delete(0, "end")
            self.server_port.insert(0, str(entry.port))
            self.server_user.delete(0, "end")
            self.server_user.insert(0, entry.username)
            self.server_pass.insert(0, entry.password)
            self.server_sudo.insert(0, entry.sudo_password)
            self.server_distro.insert(0, entry.os_distro)
            if entry.ssh_private_key:
                self.server_key_text.insert("1.0", entry.ssh_private_key)

        elif entry.entry_type == "service":
            # Populate parent server if linked
            if hasattr(self, "parent_server_combo") and entry.parent_server_id:
                for label, s_id in self.server_id_map.items():
                    if s_id == entry.parent_server_id:
                        self.parent_server_combo.set(label)
                        break

            self.service_app.insert(0, entry.app_name)
            self.service_type_combo.set(entry.service_type or "generic")
            self.service_url.insert(0, entry.url)
            self.service_port.delete(0, "end")
            self.service_port.insert(0, str(entry.port))
            self.service_user.insert(0, entry.username)
            self.service_pass.insert(0, entry.password)
            self.service_db.insert(0, entry.db_name)
            self.service_token.insert(0, entry.api_token)

        elif entry.entry_type == "keypair":
            self.key_name_entry.insert(0, entry.key_name)
            self.key_type_combo.set(entry.key_type)
            self.key_fp_entry.insert(0, entry.fingerprint)
            self.key_passphrase_entry.insert(0, entry.passphrase)
            self.key_pub_text.insert("1.0", entry.public_key)
            self.key_priv_text.insert("1.0", entry.private_key)

        # Populate custom fields
        for cf in getattr(entry, "custom_fields", []):
            if isinstance(cf, dict):
                self._add_custom_field_row(cf.get("key", ""), cf.get("value", ""))

        if entry.notes:
            self.notes_text.insert("1.0", entry.notes)

    def _save(self):
        title = self.title_entry.get().strip()
        etype = self.type_var.get()

        if not title:
            if etype == "server" and hasattr(self, "server_host") and self.server_host.get().strip():
                title = self.server_host.get().strip()
            elif etype == "service" and hasattr(self, "service_app") and self.service_app.get().strip():
                title = self.service_app.get().strip()
            elif etype == "keypair" and hasattr(self, "key_name_entry") and self.key_name_entry.get().strip():
                title = self.key_name_entry.get().strip()
            else:
                title = "Untitled Entry"

        entry = self.entry or VaultEntry()
        entry.title = title
        entry.entry_type = etype
        entry.category = self.category_entry.get().strip() or "General"
        entry.set_tags_from_str(self.tags_entry.get())
        entry.notes = self.notes_text.get("1.0", "end-1c")

        # Gather custom fields
        collected_custom_fields = []
        for row_ref in self.custom_field_rows:
            k = row_ref["key"].get().strip()
            v = row_ref["val"].get().strip()
            if k:
                collected_custom_fields.append({"key": k, "value": v})
        entry.custom_fields = collected_custom_fields

        if etype == "server":
            entry.hostname = self.server_host.get().strip()
            try:
                entry.port = int(self.server_port.get().strip() or 22)
            except ValueError:
                entry.port = 22
            entry.username = self.server_user.get().strip()
            entry.password = self.server_pass.get()
            entry.sudo_password = self.server_sudo.get()
            entry.os_distro = self.server_distro.get().strip()
            entry.ssh_private_key = self.server_key_text.get("1.0", "end-1c").strip()
            entry.parent_server_id = None

        elif etype == "service":
            entry.app_name = self.service_app.get().strip()
            entry.service_type = self.service_type_combo.get()
            entry.url = self.service_url.get().strip()
            try:
                entry.port = int(self.service_port.get().strip() or 80)
            except ValueError:
                entry.port = 80
            entry.username = self.service_user.get().strip()
            entry.password = self.service_pass.get()
            entry.db_name = self.service_db.get().strip()
            entry.api_token = self.service_token.get().strip()

            # Link parent server
            if hasattr(self, "parent_server_combo"):
                selected_server_label = self.parent_server_combo.get()
                entry.parent_server_id = self.server_id_map.get(selected_server_label, None)

        elif etype == "keypair":
            entry.key_name = self.key_name_entry.get().strip() or title
            entry.key_type = self.key_type_combo.get()
            entry.fingerprint = self.key_fp_entry.get().strip()
            entry.passphrase = self.key_passphrase_entry.get()
            entry.public_key = self.key_pub_text.get("1.0", "end-1c").strip()
            entry.private_key = self.key_priv_text.get("1.0", "end-1c").strip()
            entry.parent_server_id = None

        if self.on_save:
            self.on_save(entry)
        self.destroy()
