"""Entry creation and editing modal dialog for StarVault."""

import random
import string
from typing import Any, Callable, List, Optional
import customtkinter as ctk

from starvault.api_keys import SUPPORTED_KEY_FORMATS, generate_api_key
from starvault.crypto import generate_secure_password
from starvault.models import VaultEntry
from starvault.ui.theme import (
    ACCENT_EMERALD,
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
    COLOR_FAVORITE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    get_font,
    get_mono_font,
)
from starvault.ui.widgets import add_password_toggle


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
        available_domains: Optional[List[VaultEntry]] = None,
        on_save: Optional[Callable[[VaultEntry], None]] = None,
        database: Optional[Any] = None,
        session_key: Optional[bytes] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.entry = entry
        self.database = database
        self.session_key = session_key
        self.default_type = entry.entry_type if entry else default_type
        self.existing_tags = existing_tags or []
        self.available_servers = available_servers or []
        self.available_domains = available_domains or []
        self.on_save = on_save
        self.custom_field_rows: List[dict] = []
        self.server_id_map: dict = {}
        self.domain_id_map: dict = {}

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
            values=["server", "service", "domain", "apikey", "keypair"],
            variable=self.type_var,
            command=self._on_type_changed,
            font=get_font(12, "bold"),
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
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

            if self.database and self.session_key:
                ctk.CTkButton(
                    bottom_bar,
                    text="🕒 History / Rollback",
                    width=135,
                    height=34,
                    font=get_font(11),
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    text_color=ACCENT_PRIMARY,
                    command=self._open_history_dialog,
                ).pack(side="left", padx=(8, 0), pady=12)

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

        # Title Row
        row_title = ctk.CTkFrame(basics_card, fg_color="transparent")
        row_title.pack(fill="x", padx=16, pady=(0, 6))
        ctk.CTkLabel(row_title, text="Title / Label *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.title_entry = ctk.CTkEntry(
            row_title,
            placeholder_text="e.g. VPS1-Debian, Postgres-Main, Prod-Deploy-Key",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.title_entry.pack(fill="x", pady=(4, 0))

        # Groups & Services Row (Allows multiple assignments!)
        row_groups_services = ctk.CTkFrame(basics_card, fg_color="transparent")
        row_groups_services.pack(fill="x", padx=16, pady=(0, 6))

        # Multiple Groups
        col_groups = ctk.CTkFrame(row_groups_services, fg_color="transparent")
        col_groups.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_groups, text="🗂️ Groups (comma-separated, e.g. 'DevOps, Infra, Prod')", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.groups_entry = ctk.CTkEntry(
            col_groups,
            placeholder_text="Infrastructure, DevOps, Production",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.groups_entry.pack(fill="x", pady=(4, 0))

        # Multiple Services
        col_services = ctk.CTkFrame(row_groups_services, fg_color="transparent")
        col_services.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_services, text="🌐 Services (comma-separated, e.g. 'Postgres, Next.js, API')", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.services_entry = ctk.CTkEntry(
            col_services,
            placeholder_text="Postgres, Next.js, Stripe",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.services_entry.pack(fill="x", pady=(4, 0))

        # Category Preset & Relational Tags Row
        row_cat_tags = ctk.CTkFrame(basics_card, fg_color="transparent")
        row_cat_tags.pack(fill="x", padx=16, pady=(0, 14))

        # Category Preset
        col_cat = ctk.CTkFrame(row_cat_tags, fg_color="transparent", width=220)
        col_cat.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(col_cat, text="Primary Category Preset", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.category_entry = ctk.CTkComboBox(
            col_cat,
            values=["Domains", "Infrastructure", "Services", "Databases", "Keys", "Homelab", "Production", "Security & Networking", "Finance & Payments"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
            command=self._on_category_preset_selected,
        )
        self.category_entry.pack(fill="x", pady=(4, 0))

        # Tags Row
        col_tags = ctk.CTkFrame(row_cat_tags, fg_color="transparent")
        col_tags.pack(side="left", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(
            col_tags,
            text="Relational Tags (comma separated, e.g. 'vps1, homelab, prod')",
            font=get_font(12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w")
        self.tags_entry = ctk.CTkEntry(
            col_tags,
            placeholder_text="vps1, homelab, docker",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=36,
        )
        self.tags_entry.pack(fill="x", pady=(4, 0))

    def _on_category_preset_selected(self, val: str):
        current_grps = [g.strip() for g in self.groups_entry.get().split(",") if g.strip()]
        if val and val not in current_grps:
            current_grps.insert(0, val)
            self.groups_entry.delete(0, "end")
            self.groups_entry.insert(0, ", ".join(current_grps))

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
        elif entry_type == "domain":
            self._render_domain_form(card)
        elif entry_type == "apikey":
            self._render_apikey_form(card)
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
        add_password_toggle(pass_row, self.server_pass)

        ctk.CTkButton(
            pass_row,
            text="⚡ Use New",
            font=get_font(11, "bold"),
            width=78,
            height=36,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=lambda: self._quick_fill_generated_password(self.server_pass),
        ).pack(side="right", padx=(4, 0))

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
        sudo_row = ctk.CTkFrame(col_sudo, fg_color="transparent")
        sudo_row.pack(fill="x", pady=(4, 0))
        self.server_sudo = ctk.CTkEntry(sudo_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_sudo.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(sudo_row, self.server_sudo)

        col_distro = ctk.CTkFrame(row3, fg_color="transparent")
        col_distro.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_distro, text="OS Distro / Specs", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_distro = ctk.CTkEntry(col_distro, placeholder_text="Ubuntu 24.04, 4vCPU 8GB", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.server_distro.pack(fill="x", pady=(4, 0))

        # SSH Key box
        ssh_box = ctk.CTkFrame(container, fg_color="transparent")
        ssh_box.pack(fill="x", padx=16, pady=(0, 6))
        ctk.CTkLabel(ssh_box, text="SSH Private Key (Optional, Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.server_key_text = ctk.CTkTextbox(ssh_box, height=80, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.server_key_text.pack(fill="x", pady=(4, 0))

        # Parent Domain Dropdown
        self._create_parent_domain_dropdown(container, "🌐 Associated Primary Domain / URL (Optional)")

    def _create_parent_domain_dropdown(self, parent_container, label_text="🌐 Attached Domain / URL (Grouping)"):
        row_domain = ctk.CTkFrame(parent_container, fg_color="transparent")
        row_domain.pack(fill="x", padx=16, pady=(4, 10))
        ctk.CTkLabel(row_domain, text=label_text, font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        domain_options = ["None (Standalone)"]
        self.domain_id_map = {"None (Standalone)": None}
        for d in self.available_domains:
            d_title = d.title or d.domain_name or "Untitled Domain"
            d_url = d.domain_name or d.url or ""
            label = f"{d_title} ({d_url})" if d_url and d_url != d_title else d_title
            if getattr(d, "registrar", ""):
                label += f" • {d.registrar}"
            domain_options.append(label)
            self.domain_id_map[label] = d.id

        self.parent_domain_combo = ctk.CTkComboBox(
            row_domain,
            values=domain_options,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.parent_domain_combo.set("None (Standalone)")
        self.parent_domain_combo.pack(fill="x", pady=(4, 0))
        return self.parent_domain_combo

    def _render_domain_form(self, container):
        ctk.CTkLabel(
            container,
            text="🌐 DOMAIN ASSET & REGISTRATION DETAILS",
            font=get_font(11, "bold"),
            text_color=ACCENT_EMERALD,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Row 1: Domain Name / URL & Registrar
        row1 = ctk.CTkFrame(container, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)

        col_dom = ctk.CTkFrame(row1, fg_color="transparent")
        col_dom.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_dom, text="Domain Name / URL *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_url_entry = ctk.CTkEntry(
            col_dom,
            placeholder_text="example.com, myproject.org",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_url_entry.pack(fill="x", pady=(4, 0))
        self.domain_url_entry.bind("<KeyRelease>", self._on_domain_url_changed)

        col_reg = ctk.CTkFrame(row1, fg_color="transparent", width=220)
        col_reg.pack(side="right")
        ctk.CTkLabel(col_reg, text="Registrar (Bought From) *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_registrar_combo = ctk.CTkComboBox(
            col_reg,
            values=[
                "Cloudflare",
                "Namecheap",
                "Porkbun",
                "GoDaddy",
                "AWS Route 53",
                "Google Domains / Squarespace",
                "NameSilo",
                "Gandi",
                "Hostinger",
                "OVHcloud",
                "Dynadot",
                "Other / Self-Managed",
            ],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
            width=210,
        )
        self.domain_registrar_combo.set("Cloudflare")
        self.domain_registrar_combo.pack(fill="x", pady=(4, 0))

        # Row 2: Expiration Date & Auto-Renew Toggle
        row2 = ctk.CTkFrame(container, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        col_exp = ctk.CTkFrame(row2, fg_color="transparent")
        col_exp.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_exp, text="Expiry Date (YYYY-MM-DD)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        exp_input_frame = ctk.CTkFrame(col_exp, fg_color="transparent")
        exp_input_frame.pack(fill="x", pady=(4, 0))

        self.domain_expires_entry = ctk.CTkEntry(
            exp_input_frame,
            placeholder_text="YYYY-MM-DD (e.g. 2027-10-15)",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_expires_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))

        ctk.CTkButton(
            exp_input_frame,
            text="+1 Yr",
            width=48,
            height=36,
            font=get_font(10, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._quick_add_years(1),
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            exp_input_frame,
            text="+2 Yrs",
            width=50,
            height=36,
            font=get_font(10, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._quick_add_years(2),
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            exp_input_frame,
            text="+5 Yrs",
            width=50,
            height=36,
            font=get_font(10, "bold"),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._quick_add_years(5),
        ).pack(side="left", padx=2)

        col_renew = ctk.CTkFrame(row2, fg_color="transparent", width=220)
        col_renew.pack(side="right", padx=(8, 0))
        ctk.CTkLabel(col_renew, text="Auto-Renewal Status", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        self.domain_autorenew_var = ctk.BooleanVar(value=True)
        self.domain_autorenew_switch = ctk.CTkSwitch(
            col_renew,
            text="Auto-Renew Enabled",
            variable=self.domain_autorenew_var,
            font=get_font(11),
            progress_color=ACCENT_EMERALD,
            height=36,
        )
        self.domain_autorenew_switch.pack(anchor="w", pady=(8, 0))

        # Row 2b: Registration Date & Renewal Cost
        row2b = ctk.CTkFrame(container, fg_color="transparent")
        row2b.pack(fill="x", padx=16, pady=4)

        col_reg_date = ctk.CTkFrame(row2b, fg_color="transparent")
        col_reg_date.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_reg_date, text="Registration / Purchase Date (YYYY-MM-DD)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_registered_entry = ctk.CTkEntry(
            col_reg_date,
            placeholder_text="2023-01-15",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_registered_entry.pack(fill="x", pady=(4, 0))

        col_cost = ctk.CTkFrame(row2b, fg_color="transparent", width=220)
        col_cost.pack(side="right", padx=(8, 0))
        ctk.CTkLabel(col_cost, text="Renewal Cost (e.g. $10.99 / yr)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_cost_entry = ctk.CTkEntry(
            col_cost,
            placeholder_text="$12.99 / yr",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
            width=210,
        )
        self.domain_cost_entry.pack(fill="x", pady=(4, 0))

        # Row 3: DNS Provider & Nameservers
        row3 = ctk.CTkFrame(container, fg_color="transparent")
        row3.pack(fill="x", padx=16, pady=4)

        col_dns = ctk.CTkFrame(row3, fg_color="transparent")
        col_dns.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_dns, text="DNS Provider (e.g. Cloudflare, Route 53)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_dns_entry = ctk.CTkEntry(
            col_dns,
            placeholder_text="Cloudflare, Route 53, Namecheap DNS",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_dns_entry.pack(fill="x", pady=(4, 0))

        col_ns = ctk.CTkFrame(row3, fg_color="transparent")
        col_ns.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_ns, text="Nameservers", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_ns_entry = ctk.CTkEntry(
            col_ns,
            placeholder_text="ns1.cloudflare.com, ns2.cloudflare.com",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_ns_entry.pack(fill="x", pady=(4, 0))

        # Registrar / Portal Credentials & Passwords
        ctk.CTkLabel(
            container,
            text="🔐 REGISTRAR / PORTAL LOGIN & PASSWORDS",
            font=get_font(11, "bold"),
            text_color=ACCENT_EMERALD,
        ).pack(anchor="w", padx=16, pady=(12, 4))

        # Row 3b: Account Username & Password
        row_creds = ctk.CTkFrame(container, fg_color="transparent")
        row_creds.pack(fill="x", padx=16, pady=4)

        col_dom_user = ctk.CTkFrame(row_creds, fg_color="transparent")
        col_dom_user.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_dom_user, text="Account Username / Email", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.domain_user_entry = ctk.CTkEntry(
            col_dom_user,
            placeholder_text="admin@domain.com, registrar_username",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_user_entry.pack(fill="x", pady=(4, 0))

        col_dom_pass = ctk.CTkFrame(row_creds, fg_color="transparent")
        col_dom_pass.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_dom_pass, text="Account Password (Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        dom_pass_row = ctk.CTkFrame(col_dom_pass, fg_color="transparent")
        dom_pass_row.pack(fill="x", pady=(4, 0))
        self.domain_pass_entry = ctk.CTkEntry(dom_pass_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.domain_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(dom_pass_row, self.domain_pass_entry)

        ctk.CTkButton(
            dom_pass_row,
            text="⚡ Use New",
            font=get_font(11, "bold"),
            width=78,
            height=36,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=lambda: self._quick_fill_generated_password(self.domain_pass_entry),
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            dom_pass_row,
            text="🎲",
            width=36,
            height=36,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=lambda: self._open_password_generator_popup(self.domain_pass_entry),
        ).pack(side="right")

        # Row 3c: 2FA TOTP Secret & Transfer / EPP Auth Code
        row_sec = ctk.CTkFrame(container, fg_color="transparent")
        row_sec.pack(fill="x", padx=16, pady=4)

        col_totp = ctk.CTkFrame(row_sec, fg_color="transparent")
        col_totp.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_totp, text="Registrar 2FA / TOTP Secret (Base32)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        totp_row = ctk.CTkFrame(col_totp, fg_color="transparent")
        totp_row.pack(fill="x", pady=(4, 0))
        self.domain_totp_entry = ctk.CTkEntry(
            totp_row,
            show="•",
            placeholder_text="JBSWY3DPEHPK3PXP",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_totp_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(totp_row, self.domain_totp_entry)

        col_auth = ctk.CTkFrame(row_sec, fg_color="transparent")
        col_auth.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_auth, text="Transfer Auth / EPP Code (Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        auth_row = ctk.CTkFrame(col_auth, fg_color="transparent")
        auth_row.pack(fill="x", pady=(4, 0))
        self.domain_auth_entry = ctk.CTkEntry(
            auth_row,
            show="•",
            placeholder_text="EPP Transfer Authorization Code",
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_auth_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(auth_row, self.domain_auth_entry)

        # Row 4: Pointing Server / VPS
        row4 = ctk.CTkFrame(container, fg_color="transparent")
        row4.pack(fill="x", padx=16, pady=4)

        col_svr = ctk.CTkFrame(row4, fg_color="transparent")
        col_svr.pack(fill="x")
        ctk.CTkLabel(col_svr, text="Pointing Server / VPS (Optional Host)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        server_options = ["None (Unassigned)"]
        self.domain_server_id_map = {"None (Unassigned)": None}
        for s in self.available_servers:
            label = f"{s.title} ({s.hostname or 'No IP'})"
            server_options.append(label)
            self.domain_server_id_map[label] = s.id

        self.domain_server_combo = ctk.CTkComboBox(
            col_svr,
            values=server_options,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.domain_server_combo.set("None (Unassigned)")
        self.domain_server_combo.pack(fill="x", pady=(4, 0))

        # Bottom space
        ctk.CTkFrame(container, fg_color="transparent", height=10).pack()

    def _quick_add_years(self, years: int):
        from datetime import datetime, timezone, timedelta
        current_txt = self.domain_expires_entry.get().strip()
        base_dt = None
        if current_txt:
            try:
                base_dt = datetime.strptime(current_txt[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except Exception:
                pass
        if not base_dt:
            base_dt = datetime.now(timezone.utc)

        try:
            new_year = base_dt.year + years
            new_dt = base_dt.replace(year=new_year)
        except ValueError:
            new_dt = base_dt + timedelta(days=365 * years)

        self.domain_expires_entry.delete(0, "end")
        self.domain_expires_entry.insert(0, new_dt.strftime("%Y-%m-%d"))

    def _on_domain_url_changed(self, event=None):
        cur_title = self.title_entry.get().strip()
        val = self.domain_url_entry.get().strip()
        if not cur_title or cur_title.startswith("Untitled"):
            self.title_entry.delete(0, "end")
            self.title_entry.insert(0, val)

    def _render_service_form(self, container):
        ctk.CTkLabel(
            container,
            text="SERVICE / APPLICATION DETAILS",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Host / Parent Server & Domain Hierarchy
        row_parent = ctk.CTkFrame(container, fg_color="transparent")
        row_parent.pack(fill="x", padx=16, pady=4)

        col_server = ctk.CTkFrame(row_parent, fg_color="transparent")
        col_server.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_server, text="🖥️ Parent Server / VPS (Hierarchy)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        server_options = ["None (Standalone)"]
        self.server_id_map = {"None (Standalone)": None}
        for s in self.available_servers:
            label = f"{s.title} ({s.hostname or 'No IP'})"
            server_options.append(label)
            self.server_id_map[label] = s.id

        self.parent_server_combo = ctk.CTkComboBox(
            col_server,
            values=server_options,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.parent_server_combo.set("None (Standalone)")
        self.parent_server_combo.pack(fill="x", pady=(4, 0))

        col_domain = ctk.CTkFrame(row_parent, fg_color="transparent")
        col_domain.pack(side="right", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(col_domain, text="🌐 Attached Domain / URL (Grouping)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")

        domain_options = ["None (Standalone)"]
        self.domain_id_map = {"None (Standalone)": None}
        for d in self.available_domains:
            d_title = d.title or d.domain_name or "Untitled Domain"
            d_url = d.domain_name or d.url or ""
            label = f"{d_title} ({d_url})" if d_url and d_url != d_title else d_title
            if getattr(d, "registrar", ""):
                label += f" • {d.registrar}"
            domain_options.append(label)
            self.domain_id_map[label] = d.id

        self.parent_domain_combo = ctk.CTkComboBox(
            col_domain,
            values=domain_options,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.parent_domain_combo.set("None (Standalone)")
        self.parent_domain_combo.pack(fill="x", pady=(4, 0))

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
        add_password_toggle(pass_row, self.service_pass)

        ctk.CTkButton(
            pass_row,
            text="⚡ Use New",
            font=get_font(11, "bold"),
            width=78,
            height=36,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=lambda: self._quick_fill_generated_password(self.service_pass),
        ).pack(side="right", padx=(4, 0))

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
        tok_row = ctk.CTkFrame(col_token, fg_color="transparent")
        tok_row.pack(fill="x", pady=(4, 0))
        self.service_token = ctk.CTkEntry(tok_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.service_token.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(tok_row, self.service_token)

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
        pass_row = ctk.CTkFrame(col_pass, fg_color="transparent")
        pass_row.pack(fill="x", pady=(4, 0))
        self.key_passphrase_entry = ctk.CTkEntry(pass_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.key_passphrase_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(pass_row, self.key_passphrase_entry)

        # Public Key Box
        pub_box = ctk.CTkFrame(container, fg_color="transparent")
        pub_box.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(pub_box, text="Public Key (OpenSSH or Armored PGP)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_pub_text = ctk.CTkTextbox(pub_box, height=75, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.key_pub_text.pack(fill="x", pady=(4, 0))

        # Private Key Box
        priv_box = ctk.CTkFrame(container, fg_color="transparent")
        priv_box.pack(fill="x", padx=16, pady=(4, 6))
        ctk.CTkLabel(priv_box, text="Private Key (Encrypted at rest)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.key_priv_text = ctk.CTkTextbox(priv_box, height=90, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(11))
        self.key_priv_text.pack(fill="x", pady=(4, 0))

        # Parent Domain Dropdown
        self._create_parent_domain_dropdown(container, "🌐 Associated Domain / Host (Optional)")

    def _quick_fill_generated_password(self, target_entry: ctk.CTkEntry):
        """Instant one-click password generation and direct placement."""
        pwd = generate_secure_password(length=24)
        target_entry.delete(0, "end")
        target_entry.insert(0, pwd)

    def _render_apikey_form(self, container):
        ctk.CTkLabel(
            container,
            text="API KEY & TOKEN DETAILS",
            font=get_font(11, "bold"),
            text_color=ACCENT_INDIGO,
        ).pack(anchor="w", padx=16, pady=(12, 6))

        # Attached Domain Dropdown
        self._create_parent_domain_dropdown(container, "🌐 Associated Domain / Project URL (Optional)")

        # Row 1: Provider / Service & Environment
        row1 = ctk.CTkFrame(container, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)

        col_prov = ctk.CTkFrame(row1, fg_color="transparent")
        col_prov.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_prov, text="Provider / Service *", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.apikey_provider = ctk.CTkEntry(col_prov, placeholder_text="OpenAI, Stripe, AWS, GitHub, Anthropic", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.apikey_provider.pack(fill="x", pady=(4, 0))

        col_env = ctk.CTkFrame(row1, fg_color="transparent", width=180)
        col_env.pack(side="right")
        ctk.CTkLabel(col_env, text="Environment", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.apikey_env_combo = ctk.CTkComboBox(
            col_env,
            values=["Production", "Staging", "Development", "Test"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.apikey_env_combo.set("Production")
        self.apikey_env_combo.pack(fill="x", pady=(4, 0))

        # Row 2: Format & Expiry
        row2 = ctk.CTkFrame(container, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        col_fmt = ctk.CTkFrame(row2, fg_color="transparent")
        col_fmt.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_fmt, text="Key Format / Type", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.apikey_fmt_combo = ctk.CTkComboBox(
            col_fmt,
            values=["hex64", "hex32", "base64_64", "base64_32", "uuid", "openai", "stripe_live", "stripe_test", "github", "aws", "jwt", "custom_prefixed", "bearer"],
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            height=36,
        )
        self.apikey_fmt_combo.set("hex64")
        self.apikey_fmt_combo.pack(fill="x", pady=(4, 0))

        col_exp = ctk.CTkFrame(row2, fg_color="transparent", width=180)
        col_exp.pack(side="right")
        ctk.CTkLabel(col_exp, text="Expires At (YYYY-MM-DD)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.apikey_expires = ctk.CTkEntry(col_exp, placeholder_text="2026-12-31", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.apikey_expires.pack(fill="x", pady=(4, 0))

        # Row 3: Primary API Key / Token with 'Generate & Use' button
        row3 = ctk.CTkFrame(container, fg_color="transparent")
        row3.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(row3, text="API Key / Token Value * (Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        token_input_row = ctk.CTkFrame(row3, fg_color="transparent")
        token_input_row.pack(fill="x", pady=(4, 0))

        self.apikey_token = ctk.CTkEntry(token_input_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.apikey_token.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(token_input_row, self.apikey_token)

        def generate_and_use_apikey():
            fmt = self.apikey_fmt_combo.get().strip() or "hex64"
            prov = self.apikey_provider.get().strip().lower() or "sv"
            pkey, skey = generate_api_key(format_type=fmt, prefix=prov)
            self.apikey_token.delete(0, "end")
            self.apikey_token.insert(0, pkey)
            if skey and hasattr(self, "apikey_secret"):
                self.apikey_secret.delete(0, "end")
                self.apikey_secret.insert(0, skey)

        ctk.CTkButton(
            token_input_row,
            text="⚡ Generate & Use",
            font=get_font(11, "bold"),
            width=130,
            height=36,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=generate_and_use_apikey,
        ).pack(side="right")

        # Row 4: Secret Key (for paired key formats like AWS or Client Secrets)
        row4 = ctk.CTkFrame(container, fg_color="transparent")
        row4.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(row4, text="Secret Key / Secondary Token (Optional, Encrypted)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        sec_row = ctk.CTkFrame(row4, fg_color="transparent")
        sec_row.pack(fill="x", pady=(4, 0))
        self.apikey_secret = ctk.CTkEntry(sec_row, show="•", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.apikey_secret.pack(side="left", fill="x", expand=True, padx=(0, 4))
        add_password_toggle(sec_row, self.apikey_secret)

        # Row 5: Scopes / Permissions & 2FA Secret
        row5 = ctk.CTkFrame(container, fg_color="transparent")
        row5.pack(fill="x", padx=16, pady=(4, 14))

        col_scope = ctk.CTkFrame(row5, fg_color="transparent")
        col_scope.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(col_scope, text="Scopes / Permissions", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.apikey_scopes = ctk.CTkEntry(col_scope, placeholder_text="read:users, write:deploy, admin", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.apikey_scopes.pack(fill="x", pady=(4, 0))

        col_totp = ctk.CTkFrame(row5, fg_color="transparent", width=180)
        col_totp.pack(side="right")
        ctk.CTkLabel(col_totp, text="2FA / TOTP Secret (Base32)", font=get_font(12), text_color=TEXT_SECONDARY).pack(anchor="w")
        self.apikey_totp = ctk.CTkEntry(col_totp, placeholder_text="JBSWY3DPEHPK3PXP", fg_color=BG_INPUT, border_color=BORDER_COLOR, height=36)
        self.apikey_totp.pack(fill="x", pady=(4, 0))

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
            text="⚡ Use this password",
            width=160,
            command=use_password,
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            font=get_font(12, "bold"),
        ).pack(side="right")

    def _populate_fields(self, entry: VaultEntry):
        self.type_var.set(entry.entry_type)
        self.title_entry.insert(0, entry.title)
        self.groups_entry.insert(0, entry.get_groups_display())
        self.services_entry.insert(0, entry.get_services_display())
        self.category_entry.set(entry.category)
        self.tags_entry.insert(0, entry.get_tags_display())

        # Render type-specific fields
        self._render_type_fields(entry.entry_type)

        # Populate parent domain if linked
        if hasattr(self, "parent_domain_combo") and getattr(entry, "parent_domain_id", None):
            for label, d_id in self.domain_id_map.items():
                if d_id == entry.parent_domain_id:
                    self.parent_domain_combo.set(label)
                    break

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

        elif entry.entry_type == "domain":
            self.domain_url_entry.insert(0, getattr(entry, "domain_name", "") or entry.url)
            if hasattr(self, "domain_registrar_combo") and getattr(entry, "registrar", ""):
                self.domain_registrar_combo.set(entry.registrar)
            if hasattr(self, "domain_expires_entry"):
                self.domain_expires_entry.insert(0, getattr(entry, "expires_at", ""))
            if hasattr(self, "domain_registered_entry"):
                self.domain_registered_entry.insert(0, getattr(entry, "registered_at", ""))
            if hasattr(self, "domain_cost_entry"):
                self.domain_cost_entry.insert(0, getattr(entry, "renewal_cost", ""))
            if hasattr(self, "domain_autorenew_var"):
                self.domain_autorenew_var.set(bool(getattr(entry, "auto_renew", True)))
            if hasattr(self, "domain_dns_entry"):
                self.domain_dns_entry.insert(0, getattr(entry, "dns_provider", ""))
            if hasattr(self, "domain_ns_entry"):
                self.domain_ns_entry.insert(0, getattr(entry, "nameservers", ""))
            if hasattr(self, "domain_user_entry"):
                self.domain_user_entry.insert(0, entry.username or "")
            if hasattr(self, "domain_pass_entry"):
                self.domain_pass_entry.insert(0, entry.password or "")
            if hasattr(self, "domain_totp_entry"):
                self.domain_totp_entry.insert(0, getattr(entry, "totp_secret", "") or "")
            if hasattr(self, "domain_auth_entry"):
                self.domain_auth_entry.insert(0, getattr(entry, "auth_code", ""))
            if hasattr(self, "domain_server_combo") and entry.parent_server_id:
                for label, s_id in self.domain_server_id_map.items():
                    if s_id == entry.parent_server_id:
                        self.domain_server_combo.set(label)
                        break

        elif entry.entry_type == "apikey":
            if hasattr(self, "apikey_provider"):
                self.apikey_provider.insert(0, getattr(entry, "provider", ""))
                self.apikey_env_combo.set(getattr(entry, "environment", "Production") or "Production")
                self.apikey_fmt_combo.set(getattr(entry, "api_key_format", "hex64") or "hex64")
                self.apikey_expires.insert(0, getattr(entry, "expires_at", ""))
                self.apikey_token.insert(0, entry.api_token or entry.password or "")
                self.apikey_secret.insert(0, getattr(entry, "api_key_secret", ""))
                self.apikey_scopes.insert(0, getattr(entry, "scopes", ""))
                self.apikey_totp.insert(0, getattr(entry, "totp_secret", ""))

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
            elif etype == "domain" and hasattr(self, "domain_url_entry") and self.domain_url_entry.get().strip():
                title = self.domain_url_entry.get().strip()
            elif etype == "apikey" and hasattr(self, "apikey_provider") and self.apikey_provider.get().strip():
                title = f"{self.apikey_provider.get().strip()} API Key"
            elif etype == "keypair" and hasattr(self, "key_name_entry") and self.key_name_entry.get().strip():
                title = self.key_name_entry.get().strip()
            else:
                title = "Untitled Entry"

        entry = self.entry or VaultEntry()
        entry.title = title
        entry.entry_type = etype
        entry.set_groups_from_str(self.groups_entry.get())
        entry.set_services_from_str(self.services_entry.get())
        cat_choice = self.category_entry.get().strip()
        if cat_choice and cat_choice not in entry.groups:
            entry.groups.insert(0, cat_choice)
        if entry.groups:
            entry.category = entry.groups[0]
        else:
            entry.category = cat_choice or "General"
            entry.groups = [entry.category]
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
            if hasattr(self, "parent_domain_combo"):
                entry.parent_domain_id = self.domain_id_map.get(self.parent_domain_combo.get(), None)

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

            # Link parent domain
            if hasattr(self, "parent_domain_combo"):
                selected_domain_label = self.parent_domain_combo.get()
                entry.parent_domain_id = self.domain_id_map.get(selected_domain_label, None)

        elif etype == "domain":
            entry.domain_name = self.domain_url_entry.get().strip()
            clean_dom = entry.domain_name
            if clean_dom and not (clean_dom.startswith("http://") or clean_dom.startswith("https://")):
                clean_dom = f"https://{clean_dom}"
            entry.url = clean_dom
            entry.registrar = self.domain_registrar_combo.get().strip()
            entry.expires_at = self.domain_expires_entry.get().strip()
            if hasattr(self, "domain_registered_entry"):
                entry.registered_at = self.domain_registered_entry.get().strip()
            if hasattr(self, "domain_cost_entry"):
                entry.renewal_cost = self.domain_cost_entry.get().strip()
            entry.auto_renew = bool(self.domain_autorenew_var.get())
            entry.dns_provider = self.domain_dns_entry.get().strip()
            entry.nameservers = self.domain_ns_entry.get().strip()
            if hasattr(self, "domain_user_entry"):
                entry.username = self.domain_user_entry.get().strip()
            if hasattr(self, "domain_pass_entry"):
                entry.password = self.domain_pass_entry.get()
            if hasattr(self, "domain_totp_entry"):
                entry.totp_secret = self.domain_totp_entry.get().strip()
            entry.auth_code = self.domain_auth_entry.get().strip()
            if hasattr(self, "domain_server_combo"):
                selected_server_label = self.domain_server_combo.get()
                entry.parent_server_id = self.domain_server_id_map.get(selected_server_label, None)
            entry.parent_domain_id = None

        elif etype == "apikey":
            entry.provider = self.apikey_provider.get().strip()
            entry.environment = self.apikey_env_combo.get().strip()
            entry.api_key_format = self.apikey_fmt_combo.get().strip()
            entry.expires_at = self.apikey_expires.get().strip()
            entry.api_token = self.apikey_token.get().strip()
            entry.password = entry.api_token  # mirror for quick-copy compatibility
            entry.api_key_secret = self.apikey_secret.get().strip()
            entry.scopes = self.apikey_scopes.get().strip()
            entry.totp_secret = self.apikey_totp.get().strip()
            entry.parent_server_id = None
            if hasattr(self, "parent_domain_combo"):
                entry.parent_domain_id = self.domain_id_map.get(self.parent_domain_combo.get(), None)

        elif etype == "keypair":
            entry.key_name = self.key_name_entry.get().strip() or title
            entry.key_type = self.key_type_combo.get()
            entry.fingerprint = self.key_fp_entry.get().strip()
            entry.passphrase = self.key_passphrase_entry.get()
            entry.public_key = self.key_pub_text.get("1.0", "end-1c").strip()
            entry.private_key = self.key_priv_text.get("1.0", "end-1c").strip()
            entry.parent_server_id = None
            if hasattr(self, "parent_domain_combo"):
                entry.parent_domain_id = self.domain_id_map.get(self.parent_domain_combo.get(), None)

        if self.on_save:
            self.on_save(entry)
        self.destroy()

    def _open_history_dialog(self) -> None:
        if not self.entry or not self.database or not self.session_key:
            return
        from starvault.ui.version_history_dialog import VersionHistoryDialog
        VersionHistoryDialog(
            self,
            database=self.database,
            session_key=self.session_key,
            entry=self.entry,
            on_restored=self._on_version_restored,
        )

    def _on_version_restored(self, restored_entry: VaultEntry) -> None:
        self.entry = restored_entry
        self._populate_fields(restored_entry)
