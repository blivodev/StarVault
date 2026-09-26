"""Local Key Installer, Inspector, and System Verifier UI for StarVault.

Allows users to:
1. Select vault keys (SSH, GPG, Age, WireGuard, TLS) and install them locally with
   automated permission hardening (Windows NTFS ACLs / POSIX 0600), authorized_keys,
   SSH config, and ssh-agent integration.
2. Scan and discover existing local keys on the PC and import them into the vault.
3. Bulk export vault keys to files or zip archives with OpenSSH config snippets.
4. Run system diagnostics and repair local ~/.ssh directory and file permissions.
"""

from pathlib import Path
import platform
import threading
from tkinter import filedialog, messagebox
from typing import Callable, Dict, List, Optional, Set
import customtkinter as ctk

from starvault.clipboard import ClipboardManager
from starvault.database import Database
from starvault.key_installer import (
    DiscoveredLocalKey,
    InstallTargetConfig,
    KeyCheckItem,
    KeyInstallResult,
    SystemEnvironmentInfo,
    export_vault_keys_to_directory,
    fix_all_ssh_permissions,
    get_system_env_info,
    install_vault_keys,
    run_system_precheck,
    scan_local_keys,
)
from starvault.keys import parse_and_import_key
from starvault.models import VaultEntry
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


class LocalKeyInstallerDialog(ctk.CTkToplevel):
    """Local Key Installer, System Verifier, and Keyring Importer/Exporter."""

    def __init__(
        self,
        parent,
        database: Optional[Database] = None,
        session_key: Optional[bytes] = None,
        clipboard_mgr: Optional[ClipboardManager] = None,
        preselected_entry: Optional[VaultEntry] = None,
        on_vault_updated: Optional[Callable[[], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.database = database
        self.session_key = session_key
        self.clipboard_mgr = clipboard_mgr or ClipboardManager()
        self.preselected_entry = preselected_entry
        self.on_vault_updated = on_vault_updated

        self.env_info: SystemEnvironmentInfo = get_system_env_info()

        self.title("StarVault - Local Key Installer & Manager")
        self.geometry("980x780")
        self.minsize(860, 680)
        self.configure(fg_color=BG_ROOT)

        self.transient(parent)
        self.grab_set()

        # Data states
        self.vault_keys: List[VaultEntry] = []
        self.selected_key_ids: Set[str] = set()
        self.discovered_local_keys: List[DiscoveredLocalKey] = []
        self.selected_discovered_indices: Set[int] = set()
        self.last_install_results: List[KeyInstallResult] = []

        # Load vault keys
        self._load_vault_keys()
        if self.preselected_entry:
            self.selected_key_ids.add(self.preselected_entry.id)

        self._build_ui()

    def _load_vault_keys(self):
        """Loads all keypair and certificate entries from the active vault session."""
        if not self.database or not self.session_key:
            self.vault_keys = []
            return
        try:
            all_entries = self.database.get_all_entries(self.session_key)
            self.vault_keys = [
                e for e in all_entries
                if e.entry_type in ("keypair", "identity")
                or (getattr(e, "public_key", None) or getattr(e, "private_key", None))
            ]
        except Exception:
            self.vault_keys = []

    # -------------------------------------------------------------------------
    # UI Layout & Tab Switching
    # -------------------------------------------------------------------------

    def _build_ui(self):
        # 1. Top Header Banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=68, corner_radius=0, border_width=1, border_color=BORDER_COLOR)
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=20, pady=12)

        title_row = ctk.CTkFrame(title_box, fg_color="transparent")
        title_row.pack(anchor="w")

        ctk.CTkLabel(
            title_row,
            text="💻 Local Key Installer & Manager",
            font=get_font(17, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # OS badge
        os_label = "🪟 Windows (NTFS ACL)" if self.env_info.os_type == "windows" else f"🐧 {self.env_info.os_type.capitalize()} (chmod 0600)"
        ctk.CTkLabel(
            title_row,
            text=os_label,
            font=get_font(10, "bold"),
            fg_color=BG_INPUT,
            text_color=ACCENT_PRIMARY,
            corner_radius=4,
            padx=8,
            pady=2,
        ).pack(side="left", padx=(10, 0))

        ctk.CTkLabel(
            title_box,
            text="Install, verify, import, and export SSH, OpenPGP, Age, WireGuard, and TLS keys with strict permissions",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(2, 0))

        # Mode Selector Buttons
        nav_frame = ctk.CTkFrame(header, fg_color="transparent")
        nav_frame.pack(side="right", padx=16, pady=12)

        self.mode_var = ctk.StringVar(value="🚀 Install to System")
        mode_seg = ctk.CTkSegmentedButton(
            nav_frame,
            values=[
                "🚀 Install to System",
                "📥 Import Local Keys",
                "📤 Bulk Export",
                "🩺 Diagnostics",
            ],
            variable=self.mode_var,
            command=self._on_mode_switched,
            selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=get_font(11, "bold"),
            height=34,
        )
        mode_seg.pack()

        # Content container
        self.body_container = ctk.CTkFrame(self, fg_color=BG_ROOT)
        self.body_container.pack(fill="both", expand=True)

        self._render_install_mode()

    def _on_mode_switched(self, mode: str):
        for child in self.body_container.winfo_children():
            child.destroy()

        if "Install" in mode:
            self._render_install_mode()
        elif "Import" in mode:
            self._render_import_mode()
        elif "Export" in mode:
            self._render_export_mode()
        elif "Diagnostics" in mode:
            self._render_diagnostics_mode()

    # -------------------------------------------------------------------------
    # Mode 1: 🚀 Install to System
    # -------------------------------------------------------------------------

    def _render_install_mode(self):
        split = ctk.CTkFrame(self.body_container, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=16, pady=14)

        # Left Column: Key Selector Checklist
        left_col = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR, width=440)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Left Header (Search & Filter)
        left_head = ctk.CTkFrame(left_col, fg_color="transparent")
        left_head.pack(fill="x", padx=14, pady=(12, 6))

        ctk.CTkLabel(
            left_head,
            text="1. SELECT KEYS TO INSTALL",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w")

        # Search Bar
        search_row = ctk.CTkFrame(left_col, fg_color="transparent")
        search_row.pack(fill="x", padx=14, pady=(4, 6))

        self.key_search_var = ctk.StringVar()
        self.key_search_entry = ctk.CTkEntry(
            search_row,
            placeholder_text="Search keys by label, type, or fingerprint...",
            font=get_font(11),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
            textvariable=self.key_search_var,
        )
        self.key_search_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.key_search_entry.bind("<KeyRelease>", lambda e: self._refresh_key_checklist())

        self.filter_format_var = ctk.StringVar(value="All Formats")
        fmt_menu = ctk.CTkOptionMenu(
            search_row,
            values=["All Formats", "SSH", "GPG / PGP", "Age", "WireGuard", "TLS / SSL"],
            variable=self.filter_format_var,
            command=lambda v: self._refresh_key_checklist(),
            font=get_font(11),
            height=32,
            width=110,
            fg_color=BG_INPUT,
            button_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        fmt_menu.pack(side="right")

        # Select All / Deselect All / Count toolbar
        select_bar = ctk.CTkFrame(left_col, fg_color="transparent")
        select_bar.pack(fill="x", padx=14, pady=(2, 8))

        ctk.CTkButton(
            select_bar,
            text="Select All",
            font=get_font(10),
            width=70,
            height=24,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self._select_all_keys,
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            select_bar,
            text="Deselect All",
            font=get_font(10),
            width=75,
            height=24,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            command=self._deselect_all_keys,
        ).pack(side="left")

        self.count_badge_label = ctk.CTkLabel(
            select_bar,
            text=f"Selected: {len(self.selected_key_ids)} / {len(self.vault_keys)}",
            font=get_font(10, "bold"),
            text_color=ACCENT_PRIMARY,
        )
        self.count_badge_label.pack(side="right")

        # Scrollable Key Cards List
        self.key_list_scroll = ctk.CTkScrollableFrame(left_col, fg_color=BG_ROOT)
        self.key_list_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._refresh_key_checklist()

        # Right Column: Installation Configuration & Verification
        right_col = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR, width=460)
        right_col.pack(side="right", fill="both", expand=True)

        self.right_scroll = ctk.CTkScrollableFrame(right_col, fg_color="transparent")
        self.right_scroll.pack(fill="both", expand=True, padx=14, pady=12)

        ctk.CTkLabel(
            self.right_scroll,
            text="2. INSTALLATION TARGET & OPTIONS",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", pady=(0, 8))

        # Target Directory
        dir_box = ctk.CTkFrame(self.right_scroll, fg_color=BG_INPUT, corner_radius=8)
        dir_box.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(dir_box, text="Destination Directory (~/.ssh default):", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w", padx=10, pady=(8, 2))
        dest_row = ctk.CTkFrame(dir_box, fg_color="transparent")
        dest_row.pack(fill="x", padx=10, pady=(0, 8))

        self.dest_dir_var = ctk.StringVar(value=str(self.env_info.ssh_dir))
        self.dest_dir_entry = ctk.CTkEntry(
            dest_row,
            textvariable=self.dest_dir_var,
            font=get_mono_font(11),
            fg_color=BG_CARD,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
        )
        self.dest_dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def browse_dest():
            p = filedialog.askdirectory(initialdir=self.dest_dir_var.get())
            if p:
                self.dest_dir_var.set(p)

        ctk.CTkButton(
            dest_row,
            text="Browse...",
            font=get_font(11),
            width=75,
            height=32,
            fg_color=BORDER_COLOR,
            hover_color=BG_CARD_HOVER,
            command=browse_dest,
        ).pack(side="right")

        # Feature Checkboxes
        opts_box = ctk.CTkFrame(self.right_scroll, fg_color=BG_INPUT, corner_radius=8)
        opts_box.pack(fill="x", pady=(0, 10), padx=0)

        ctk.CTkLabel(opts_box, text="Installation Components & Permissions:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w", padx=10, pady=(8, 4))

        self.chk_install_priv = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts_box,
            text="Install Private Key (Strict Permissions: 0600 on Linux / Current User ACL on Windows)",
            variable=self.chk_install_priv,
            font=get_font(11),
            text_color=TEXT_PRIMARY,
            checkmark_color="#000000",
            fg_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=10, pady=3)

        self.chk_install_pub = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts_box,
            text="Install Public Key (.pub) alongside private key",
            variable=self.chk_install_pub,
            font=get_font(11),
            text_color=TEXT_PRIMARY,
            checkmark_color="#000000",
            fg_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=10, pady=3)

        self.chk_auth_keys = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_box,
            text="Add Public Key to ~/.ssh/authorized_keys (Local Server Access)",
            variable=self.chk_auth_keys,
            font=get_font(11),
            text_color=TEXT_PRIMARY,
            checkmark_color="#000000",
            fg_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=10, pady=3)

        self.chk_ssh_config = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_box,
            text="Add Host block to ~/.ssh/config for SSH client",
            variable=self.chk_ssh_config,
            font=get_font(11),
            text_color=TEXT_PRIMARY,
            checkmark_color="#000000",
            fg_color=ACCENT_PRIMARY,
            command=self._toggle_ssh_config_fields,
        ).pack(anchor="w", padx=10, pady=3)

        # Host config options container
        self.ssh_cfg_container = ctk.CTkFrame(opts_box, fg_color="transparent")
        self._build_ssh_config_subfields()

        self.chk_ssh_agent = ctk.BooleanVar(value=False)
        agent_txt = "Add Private Key to running ssh-agent (ssh-add)"
        if not self.env_info.ssh_agent_running:
            agent_txt += " (Service Stopped - see Diagnostics)"
        ctk.CTkCheckBox(
            opts_box,
            text=agent_txt,
            variable=self.chk_ssh_agent,
            font=get_font(11),
            text_color=TEXT_PRIMARY if self.env_info.ssh_agent_running else TEXT_MUTED,
            checkmark_color="#000000",
            fg_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=10, pady=3)

        self.chk_gpg_import = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts_box,
            text="Import GPG/OpenPGP keys into native GPG keyring (gpg --import)",
            variable=self.chk_gpg_import,
            font=get_font(11),
            text_color=TEXT_PRIMARY,
            checkmark_color="#000000",
            fg_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=10, pady=3)

        self.chk_overwrite = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_box,
            text="Overwrite existing files (if unchecked, unique suffix is appended safely)",
            variable=self.chk_overwrite,
            font=get_font(11),
            text_color=COLOR_WARNING,
            checkmark_color="#000000",
            fg_color=COLOR_WARNING,
        ).pack(anchor="w", padx=10, pady=(3, 10))

        # Action Button & Progress
        self.install_btn = ctk.CTkButton(
            self.right_scroll,
            text=f"⚡ Install & Check Selected Keys ({len(self.selected_key_ids)})",
            font=get_font(13, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=40,
            command=self._execute_install,
        )
        self.install_btn.pack(fill="x", pady=(4, 12))

        # Results & Checks Report Container
        self.results_card = ctk.CTkFrame(self.right_scroll, fg_color=BG_INPUT, corner_radius=8)
        self.results_card.pack(fill="both", expand=True)

        ctk.CTkLabel(
            self.results_card,
            text="SYSTEM VERIFICATION & AUDIT LOG",
            font=get_font(10, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self.results_inner = ctk.CTkFrame(self.results_card, fg_color="transparent")
        self.results_inner.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        ctk.CTkLabel(
            self.results_inner,
            text="Select keys and click 'Install & Check Selected Keys'.\nStarVault will write the files, harden permissions,\nand run OpenSSH / agent syntax verification checks.",
            font=get_font(11),
            text_color=TEXT_MUTED,
            justify="center",
        ).pack(pady=20)

    def _build_ssh_config_subfields(self):
        for child in self.ssh_cfg_container.winfo_children():
            child.destroy()

        if self.chk_ssh_config.get():
            self.ssh_cfg_container.pack(fill="x", padx=24, pady=(0, 6))

            r1 = ctk.CTkFrame(self.ssh_cfg_container, fg_color="transparent")
            r1.pack(fill="x", pady=2)
            ctk.CTkLabel(r1, text="Host Alias:", font=get_font(10), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
            self.ssh_alias_entry = ctk.CTkEntry(r1, placeholder_text="e.g. prod-server", height=28, font=get_font(11))
            self.ssh_alias_entry.pack(side="left", fill="x", expand=True)

            r2 = ctk.CTkFrame(self.ssh_cfg_container, fg_color="transparent")
            r2.pack(fill="x", pady=2)
            ctk.CTkLabel(r2, text="HostName:", font=get_font(10), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
            self.ssh_hostname_entry = ctk.CTkEntry(r2, placeholder_text="e.g. 192.168.1.100 or vps.example.com", height=28, font=get_font(11))
            self.ssh_hostname_entry.pack(side="left", fill="x", expand=True)

            r3 = ctk.CTkFrame(self.ssh_cfg_container, fg_color="transparent")
            r3.pack(fill="x", pady=2)
            ctk.CTkLabel(r3, text="User:", font=get_font(10), text_color=TEXT_MUTED, width=80, anchor="w").pack(side="left")
            self.ssh_user_entry = ctk.CTkEntry(r3, placeholder_text="e.g. root or ubuntu", height=28, font=get_font(11))
            self.ssh_user_entry.pack(side="left", fill="x", expand=True)
        else:
            self.ssh_cfg_container.pack_forget()

    def _toggle_ssh_config_fields(self):
        self._build_ssh_config_subfields()

    def _refresh_key_checklist(self):
        for child in self.key_list_scroll.winfo_children():
            child.destroy()

        q = self.key_search_var.get().strip().lower()
        fmt_filter = self.filter_format_var.get()

        matching_keys = []
        for k in self.vault_keys:
            kt = getattr(k, "key_type", "").lower()
            title = k.title.lower()
            fp = getattr(k, "fingerprint", "").lower()

            # Format filtering
            if fmt_filter == "SSH" and not any(s in kt for s in ("ed25519", "rsa", "ecdsa", "ssh")):
                continue
            elif fmt_filter == "GPG / PGP" and not any(s in kt for s in ("gpg", "pgp")):
                continue
            elif fmt_filter == "Age" and "age" not in kt:
                continue
            elif fmt_filter == "WireGuard" and "wireguard" not in kt:
                continue
            elif fmt_filter == "TLS / SSL" and not any(s in kt for s in ("tls", "cert")):
                continue

            if not q or (q in title or q in kt or q in fp or any(q in t.lower() for t in k.tags)):
                matching_keys.append(k)

        if not matching_keys:
            empty_box = ctk.CTkFrame(self.key_list_scroll, fg_color="transparent")
            empty_box.pack(pady=30)
            ctk.CTkLabel(
                empty_box,
                text="No vault keys match criteria.\nImport keys or generate a new keypair first.",
                font=get_font(11),
                text_color=TEXT_MUTED,
                justify="center",
            ).pack()
            return

        for key_entry in matching_keys:
            self._render_key_card(key_entry)

    def _render_key_card(self, entry: VaultEntry):
        is_selected = entry.id in self.selected_key_ids

        card = ctk.CTkFrame(
            self.key_list_scroll,
            fg_color=BG_CARD_HOVER if is_selected else BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=ACCENT_PRIMARY if is_selected else BORDER_COLOR,
        )
        card.pack(fill="x", pady=4, padx=2)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=10, pady=8)

        # Checkbox
        chk_var = ctk.BooleanVar(value=is_selected)

        def toggle_sel():
            if chk_var.get():
                self.selected_key_ids.add(entry.id)
            else:
                self.selected_key_ids.discard(entry.id)
            self._update_selection_counters()
            self._refresh_key_checklist()

        chk = ctk.CTkCheckBox(
            inner,
            text="",
            variable=chk_var,
            width=24,
            command=toggle_sel,
            fg_color=ACCENT_PRIMARY,
            checkmark_color="#000000",
        )
        chk.pack(side="left", padx=(0, 8))

        # Key info
        info_col = ctk.CTkFrame(inner, fg_color="transparent")
        info_col.pack(side="left", fill="x", expand=True)

        top_row = ctk.CTkFrame(info_col, fg_color="transparent")
        top_row.pack(fill="x")

        kt = getattr(entry, "key_type", "Key").upper()
        badge_color = ACCENT_PURPLE if "ED25519" in kt or "RSA" in kt else (COLOR_WARNING if "GPG" in kt else ACCENT_PRIMARY)
        ctk.CTkLabel(
            top_row,
            text=kt,
            font=get_font(9, "bold"),
            text_color=badge_color,
            fg_color=BG_INPUT,
            corner_radius=4,
            padx=6,
            pady=1,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(
            top_row,
            text=entry.title,
            font=get_font(12, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # Private key indicator
        has_priv = bool(getattr(entry, "private_key", "").strip())
        priv_badge = "🔒 Priv+Pub" if has_priv else "🌐 Pub Only"
        priv_col = COLOR_SUCCESS if has_priv else TEXT_MUTED
        ctk.CTkLabel(
            top_row,
            text=priv_badge,
            font=get_font(9),
            text_color=priv_col,
            fg_color=BG_INPUT,
            corner_radius=4,
            padx=5,
            pady=1,
        ).pack(side="right")

        # Subtitle: fingerprint
        fp = getattr(entry, "fingerprint", "") or "No fingerprint recorded"
        sub_text = fp[:32] + "..." if len(fp) > 32 else fp
        ctk.CTkLabel(
            info_col,
            text=sub_text,
            font=get_mono_font(10),
            text_color=TEXT_MUTED,
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

    def _select_all_keys(self):
        for k in self.vault_keys:
            self.selected_key_ids.add(k.id)
        self._update_selection_counters()
        self._refresh_key_checklist()

    def _deselect_all_keys(self):
        self.selected_key_ids.clear()
        self._update_selection_counters()
        self._refresh_key_checklist()

    def _update_selection_counters(self):
        count = len(self.selected_key_ids)
        total = len(self.vault_keys)
        if hasattr(self, "count_badge_label"):
            self.count_badge_label.configure(text=f"Selected: {count} / {total}")
        if hasattr(self, "install_btn"):
            self.install_btn.configure(text=f"⚡ Install & Check Selected Keys ({count})")

    # -------------------------------------------------------------------------
    # Installation Execution & Live Audit
    # -------------------------------------------------------------------------

    def _execute_install(self):
        if not self.selected_key_ids:
            messagebox.showwarning("No Keys Selected", "Please select at least one key from the list to install.")
            return

        entries_to_install = [k for k in self.vault_keys if k.id in self.selected_key_ids]
        dest_dir_str = self.dest_dir_var.get().strip()
        dest_dir = Path(dest_dir_str) if dest_dir_str else self.env_info.ssh_dir

        # Build config
        cfg = InstallTargetConfig(
            destination_dir=dest_dir,
            install_private=self.chk_install_priv.get(),
            install_public=self.chk_install_pub.get(),
            add_to_authorized_keys=self.chk_auth_keys.get(),
            add_to_ssh_config=self.chk_ssh_config.get(),
            ssh_config_host_alias=getattr(self, "ssh_alias_entry", None).get().strip() if hasattr(self, "ssh_alias_entry") else "",
            ssh_config_hostname=getattr(self, "ssh_hostname_entry", None).get().strip() if hasattr(self, "ssh_hostname_entry") else "",
            ssh_config_user=getattr(self, "ssh_user_entry", None).get().strip() if hasattr(self, "ssh_user_entry") else "",
            add_to_agent=self.chk_ssh_agent.get(),
            overwrite_existing=self.chk_overwrite.get(),
            import_to_gpg_keyring=self.chk_gpg_import.get(),
        )

        self.install_btn.configure(state="disabled", text="Installing & Verifying...")

        def run_thread():
            try:
                results = install_vault_keys(entries_to_install, default_config=cfg)
                self.last_install_results = results
                self.after(0, lambda: self._render_install_results(results))
            except Exception as ex:
                self.after(0, lambda: messagebox.showerror("Installation Error", f"An error occurred during key install:\n{ex}"))
            finally:
                self.after(0, lambda: self.install_btn.configure(
                    state="normal",
                    text=f"⚡ Install & Check Selected Keys ({len(self.selected_key_ids)})"
                ))

        threading.Thread(target=run_thread, daemon=True).start()

    def _render_install_results(self, results: List[KeyInstallResult]):
        for child in self.results_inner.winfo_children():
            child.destroy()

        success_count = sum(1 for r in results if r.success)
        total = len(results)

        # Summary Header
        summary_box = ctk.CTkFrame(self.results_inner, fg_color=BG_ROOT, corner_radius=6)
        summary_box.pack(fill="x", pady=(0, 8))

        status_col = COLOR_SUCCESS if success_count == total else (COLOR_WARNING if success_count > 0 else COLOR_DANGER)
        ctk.CTkLabel(
            summary_box,
            text=f"Results: {success_count}/{total} Keys Installed & Verified Successfully",
            font=get_font(12, "bold"),
            text_color=status_col,
        ).pack(anchor="w", padx=10, pady=8)

        # Render detail card for each key
        for res in results:
            card = ctk.CTkFrame(self.results_inner, fg_color=BG_CARD, corner_radius=6, border_width=1, border_color=BORDER_COLOR)
            card.pack(fill="x", pady=4)

            head = ctk.CTkFrame(card, fg_color="transparent")
            head.pack(fill="x", padx=10, pady=(8, 4))

            status_icon = "✅" if res.success and not res.has_warnings else ("⚠️" if res.has_warnings else "❌")
            ctk.CTkLabel(head, text=f"{status_icon} {res.key_title}", font=get_font(11, "bold"), text_color=TEXT_PRIMARY).pack(side="left")
            ctk.CTkLabel(head, text=res.key_type.upper(), font=get_font(9), text_color=TEXT_MUTED).pack(side="right")

            # Files written
            if res.installed_paths:
                paths_str = ", ".join(p.name for p in res.installed_paths)
                ctk.CTkLabel(card, text=f"Written: {paths_str}", font=get_mono_font(10), text_color=TEXT_SECONDARY).pack(anchor="w", padx=10, pady=(0, 4))

            # Checks list
            chk_frame = ctk.CTkFrame(card, fg_color="transparent")
            chk_frame.pack(fill="x", padx=10, pady=(0, 8))

            for c in res.checks:
                c_icon = "🟢" if c.status == "OK" else ("🟡" if c.status == "WARNING" else ("🔴" if c.status == "ERROR" else "⚪"))
                c_row = ctk.CTkFrame(chk_frame, fg_color="transparent")
                c_row.pack(fill="x", pady=1)

                ctk.CTkLabel(c_row, text=f"{c_icon} {c.name}:", font=get_font(10, "bold"), text_color=TEXT_SECONDARY, width=160, anchor="w").pack(side="left")
                ctk.CTkLabel(c_row, text=c.message, font=get_font(10), text_color=TEXT_PRIMARY if c.status == "OK" else COLOR_WARNING, anchor="w").pack(side="left", fill="x", expand=True)

    # -------------------------------------------------------------------------
    # Mode 2: 📥 Import Local Keys (Scanner & File Loader)
    # -------------------------------------------------------------------------

    def _render_import_mode(self):
        container = ctk.CTkFrame(self.body_container, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=16)

        # Top Action Toolbar
        top_bar = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        top_bar.pack(fill="x", pady=(0, 12))

        tb_inner = ctk.CTkFrame(top_bar, fg_color="transparent")
        tb_inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            tb_inner,
            text="📥 Discover & Import Local Keys into Vault",
            font=get_font(13, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkButton(
            tb_inner,
            text="📋 Paste Raw Key...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
            command=self._open_paste_import_dialog,
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            tb_inner,
            text="📂 Load from Files...",
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=32,
            command=self._load_key_files_dialog,
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            tb_inner,
            text="🔍 Scan ~/.ssh & System Dirs",
            font=get_font(11, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=32,
            command=self._execute_local_scan,
        ).pack(side="right", padx=4)

        # Scrollable Discovered Keys Table
        self.import_scroll = ctk.CTkScrollableFrame(container, fg_color=BG_ROOT)
        self.import_scroll.pack(fill="both", expand=True, pady=(0, 12))

        if not self.discovered_local_keys:
            self._render_import_empty_state()
        else:
            self._render_discovered_keys_list()

        # Bottom Action Bar
        bottom_bar = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        bottom_bar.pack(fill="x")

        bot_inner = ctk.CTkFrame(bottom_bar, fg_color="transparent")
        bot_inner.pack(fill="x", padx=14, pady=10)

        self.import_count_label = ctk.CTkLabel(
            bot_inner,
            text=f"Selected to Import: {len(self.selected_discovered_indices)}",
            font=get_font(11, "bold"),
            text_color=ACCENT_PRIMARY,
        )
        self.import_count_label.pack(side="left")

        ctk.CTkButton(
            bot_inner,
            text="📥 Save Selected to Vault Keyring",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=36,
            command=self._save_discovered_keys_to_vault,
        ).pack(side="right")

    def _render_import_empty_state(self):
        for child in self.import_scroll.winfo_children():
            child.destroy()

        box = ctk.CTkFrame(self.import_scroll, fg_color="transparent")
        box.pack(pady=60)

        ctk.CTkLabel(
            box,
            text="No local keys scanned yet.\nClick 'Scan ~/.ssh & System Dirs' to automatically detect\nexisting SSH, GPG, Age, and TLS keys on this machine.",
            font=get_font(12),
            text_color=TEXT_MUTED,
            justify="center",
        ).pack(pady=(0, 14))

        ctk.CTkButton(
            box,
            text="🔍 Scan ~/.ssh Directory Now",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=36,
            command=self._execute_local_scan,
        ).pack()

    def _execute_local_scan(self):
        def run_scan():
            disc = scan_local_keys(existing_vault_entries=self.vault_keys)
            self.discovered_local_keys = disc
            # By default, select all keys that are NOT yet in the vault
            self.selected_discovered_indices = {i for i, k in enumerate(disc) if not k.already_in_vault}
            self.after(0, self._render_discovered_keys_list)

        threading.Thread(target=run_scan, daemon=True).start()

    def _render_discovered_keys_list(self):
        for child in self.import_scroll.winfo_children():
            child.destroy()

        if not self.discovered_local_keys:
            self._render_import_empty_state()
            return

        for idx, k in enumerate(self.discovered_local_keys):
            card = ctk.CTkFrame(self.import_scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
            card.pack(fill="x", pady=4, padx=4)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=12, pady=10)

            chk_var = ctk.BooleanVar(value=idx in self.selected_discovered_indices)

            def toggle(i=idx, v=chk_var):
                if v.get():
                    self.selected_discovered_indices.add(i)
                else:
                    self.selected_discovered_indices.discard(i)
                self.import_count_label.configure(text=f"Selected to Import: {len(self.selected_discovered_indices)}")

            chk = ctk.CTkCheckBox(
                inner,
                text="",
                variable=chk_var,
                width=24,
                command=toggle,
                fg_color=ACCENT_PRIMARY,
                checkmark_color="#000000",
            )
            chk.pack(side="left", padx=(0, 10))

            info_col = ctk.CTkFrame(inner, fg_color="transparent")
            info_col.pack(side="left", fill="x", expand=True)

            top = ctk.CTkFrame(info_col, fg_color="transparent")
            top.pack(fill="x")

            ctk.CTkLabel(
                top,
                text=k.algorithm_name,
                font=get_font(9, "bold"),
                text_color=ACCENT_PURPLE if "SSH" in k.algorithm_name else ACCENT_PRIMARY,
                fg_color=BG_INPUT,
                corner_radius=4,
                padx=6,
                pady=1,
            ).pack(side="left", padx=(0, 8))

            ctk.CTkLabel(top, text=k.path.name, font=get_font(12, "bold"), text_color=TEXT_PRIMARY).pack(side="left")

            if k.already_in_vault:
                ctk.CTkLabel(
                    top,
                    text="✓ In Vault",
                    font=get_font(9, "bold"),
                    text_color=TEXT_MUTED,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=6,
                    pady=1,
                ).pack(side="right")
            else:
                ctk.CTkLabel(
                    top,
                    text="✨ New Key",
                    font=get_font(9, "bold"),
                    text_color=COLOR_SUCCESS,
                    fg_color=BG_INPUT,
                    corner_radius=4,
                    padx=6,
                    pady=1,
                ).pack(side="right")

            # Path & fingerprint
            sub = f"Path: {k.path}"
            if k.fingerprint:
                sub += f" • Fingerprint: {k.fingerprint}"
            ctk.CTkLabel(info_col, text=sub, font=get_mono_font(10), text_color=TEXT_MUTED, anchor="w").pack(fill="x", pady=(2, 0))

        if hasattr(self, "import_count_label"):
            self.import_count_label.configure(text=f"Selected to Import: {len(self.selected_discovered_indices)}")

    def _save_discovered_keys_to_vault(self):
        if not self.selected_discovered_indices:
            messagebox.showwarning("None Selected", "Please select at least one discovered key to import.")
            return

        if not self.database or not self.session_key:
            messagebox.showerror("Vault Locked", "No unlocked vault session available to save keys.")
            return

        imported_count = 0
        try:
            for idx in self.selected_discovered_indices:
                dk = self.discovered_local_keys[idx]
                content = dk.private_content or dk.public_content
                if not content:
                    continue

                entry = parse_and_import_key(content, key_name=dk.title or dk.path.name)
                # If we have both public and private stored separately
                if dk.public_content and not entry.public_key:
                    entry.public_key = dk.public_content
                if dk.private_content and not entry.private_key:
                    entry.private_key = dk.private_content

                self.database.save_entry(entry, self.session_key)
                imported_count += 1

            self._load_vault_keys()
            if self.on_vault_updated:
                self.on_vault_updated()

            messagebox.showinfo("Import Successful", f"Successfully imported {imported_count} keys into your StarVault vault!")
            self._execute_local_scan()
        except Exception as ex:
            messagebox.showerror("Import Error", f"Error saving keys into vault:\n{ex}")

    def _load_key_files_dialog(self):
        files = filedialog.askopenfilenames(
            title="Select Key Files to Import",
            filetypes=[
                ("All Key Files", "*.pub;*.pem;*.key;*.asc;*.gpg;*.crt;*.cer;*.age"),
                ("OpenSSH Keys", "*.pub;*.pem;*.key"),
                ("GPG / PGP Armored", "*.asc;*.gpg"),
                ("All Files", "*.*"),
            ],
        )
        if not files:
            return

        added_count = 0
        for fp_str in files:
            p = Path(fp_str)
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if not content:
                    continue
                entry = parse_and_import_key(content, key_name=p.stem)
                if self.database and self.session_key:
                    self.database.save_entry(entry, self.session_key)
                    added_count += 1
            except Exception:
                continue

        if added_count > 0:
            self._load_vault_keys()
            if self.on_vault_updated:
                self.on_vault_updated()
            messagebox.showinfo("Imported", f"Successfully imported {added_count} key files into vault!")
            self._refresh_key_checklist()

    def _open_paste_import_dialog(self):
        modal = ctk.CTkToplevel(self)
        modal.title("Paste Key Material")
        modal.geometry("520x440")
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(modal, text="Paste Raw Key Material", font=get_font(15, "bold"), text_color=TEXT_PRIMARY).pack(pady=(16, 4))
        txt = ctk.CTkTextbox(modal, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
        txt.pack(fill="both", expand=True, padx=20, pady=8)

        def do_save():
            raw = txt.get("1.0", "end").strip()
            if not raw:
                return
            if not self.database or not self.session_key:
                messagebox.showerror("Error", "Vault locked.")
                return
            try:
                entry = parse_and_import_key(raw, key_name="Pasted Key")
                self.database.save_entry(entry, self.session_key)
                if self.on_vault_updated:
                    self.on_vault_updated()
                self._load_vault_keys()
                modal.destroy()
                messagebox.showinfo("Imported", f"Imported '{entry.title}' into vault!")
            except Exception as ex:
                messagebox.showerror("Failed", f"Could not parse key: {ex}")

        btn_row = ctk.CTkFrame(modal, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(4, 16))
        ctk.CTkButton(btn_row, text="Cancel", fg_color=BG_INPUT, text_color=TEXT_PRIMARY, command=modal.destroy).pack(side="left")
        ctk.CTkButton(btn_row, text="✓ Save to Vault", font=get_font(12, "bold"), fg_color=ACCENT_PRIMARY, text_color="#000000", command=do_save).pack(side="right")

    # -------------------------------------------------------------------------
    # Mode 3: 📤 Bulk Export
    # -------------------------------------------------------------------------

    def _render_export_mode(self):
        container = ctk.CTkFrame(self.body_container, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=16)

        split = ctk.CTkFrame(container, fg_color="transparent")
        split.pack(fill="both", expand=True)

        # Left: Key Picker
        left = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR, width=440)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        ctk.CTkLabel(left, text="SELECT KEYS TO EXPORT", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=14, pady=(12, 6))

        scroll = ctk.CTkScrollableFrame(left, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        export_selected_ids = set(self.selected_key_ids) or {k.id for k in self.vault_keys}

        for k in self.vault_keys:
            c = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=6, border_width=1, border_color=BORDER_COLOR)
            c.pack(fill="x", pady=3)
            cin = ctk.CTkFrame(c, fg_color="transparent")
            cin.pack(fill="x", padx=10, pady=6)

            v = ctk.BooleanVar(value=k.id in export_selected_ids)

            def tog(kid=k.id, var=v):
                if var.get():
                    export_selected_ids.add(kid)
                else:
                    export_selected_ids.discard(kid)

            ctk.CTkCheckBox(cin, text="", variable=v, width=24, command=tog, fg_color=ACCENT_PRIMARY, checkmark_color="#000000").pack(side="left", padx=(0, 6))
            ctk.CTkLabel(cin, text=f"🔑 {k.title}", font=get_font(11, "bold"), text_color=TEXT_PRIMARY).pack(side="left")
            ctk.CTkLabel(cin, text=getattr(k, "key_type", "").upper(), font=get_font(9), text_color=TEXT_MUTED).pack(side="right")

        # Right: Export Options
        right = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_COLOR, width=420)
        right.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(right, text="EXPORT CONFIGURATION", font=get_font(11, "bold"), text_color=ACCENT_PRIMARY).pack(anchor="w", padx=14, pady=(12, 10))

        # Destination Folder
        ctk.CTkLabel(right, text="Export Destination Directory:", font=get_font(11, "bold"), text_color=TEXT_SECONDARY).pack(anchor="w", padx=14, pady=(0, 4))
        exp_dir_var = ctk.StringVar(value=str(Path.home() / "Documents"))
        d_row = ctk.CTkFrame(right, fg_color="transparent")
        d_row.pack(fill="x", padx=14, pady=(0, 14))

        ctk.CTkEntry(d_row, textvariable=exp_dir_var, font=get_mono_font(10), fg_color=BG_INPUT, height=32).pack(side="left", fill="x", expand=True, padx=(0, 6))

        def browse_exp():
            p = filedialog.askdirectory(initialdir=exp_dir_var.get())
            if p:
                exp_dir_var.set(p)

        ctk.CTkButton(d_row, text="Browse...", width=75, height=32, fg_color=BG_INPUT, text_color=TEXT_PRIMARY, command=browse_exp).pack(side="right")

        chk_inc_priv = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(right, text="Include Private Keys (.pem, .key, .asc)", variable=chk_inc_priv, font=get_font(11), text_color=TEXT_PRIMARY, fg_color=ACCENT_PRIMARY, checkmark_color="#000000").pack(anchor="w", padx=14, pady=4)

        chk_zip = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(right, text="Compress into ZIP archive (starvault_keys_export.zip)", variable=chk_zip, font=get_font(11), text_color=TEXT_PRIMARY, fg_color=ACCENT_PRIMARY, checkmark_color="#000000").pack(anchor="w", padx=14, pady=4)

        chk_cfg = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(right, text="Generate OpenSSH Client Config Template (ssh_config_template)", variable=chk_cfg, font=get_font(11), text_color=TEXT_PRIMARY, fg_color=ACCENT_PRIMARY, checkmark_color="#000000").pack(anchor="w", padx=14, pady=4)

        def do_export():
            if not export_selected_ids:
                messagebox.showwarning("None Selected", "Select at least one key to export.")
                return
            t_dir = Path(exp_dir_var.get())
            keys_to_exp = [k for k in self.vault_keys if k.id in export_selected_ids]
            try:
                cnt, paths = export_vault_keys_to_directory(
                    keys_to_exp,
                    target_dir=t_dir,
                    include_private=chk_inc_priv.get(),
                    generate_ssh_config=chk_cfg.get(),
                    create_zip=chk_zip.get(),
                )
                messagebox.showinfo("Export Complete", f"Exported {cnt} file(s) to:\n{t_dir}")
            except Exception as ex:
                messagebox.showerror("Export Failed", f"Export error: {ex}")

        ctk.CTkButton(
            right,
            text="💾 Export Selected Keys",
            font=get_font(13, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            height=40,
            command=do_export,
        ).pack(fill="x", padx=14, pady=(20, 10))

    # -------------------------------------------------------------------------
    # Mode 4: 🩺 System Diagnostics & Permission Repair
    # -------------------------------------------------------------------------

    def _render_diagnostics_mode(self):
        container = ctk.CTkFrame(self.body_container, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=16)

        header_box = ctk.CTkFrame(container, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
        header_box.pack(fill="x", pady=(0, 12))

        hin = ctk.CTkFrame(header_box, fg_color="transparent")
        hin.pack(fill="x", padx=14, pady=12)

        ctk.CTkLabel(hin, text="🩺 Local System Key Security & Environment Audit", font=get_font(13, "bold"), text_color=TEXT_PRIMARY).pack(side="left")

        def run_perm_fix():
            cnt, logs = fix_all_ssh_permissions()
            messagebox.showinfo("Permissions Hardened", f"Enforced strict permissions across {cnt} files in {self.env_info.ssh_dir}!\n\n" + "\n".join(logs[:8]))
            self._render_diagnostics_mode()

        ctk.CTkButton(
            hin,
            text="🛡️ Fix ~/.ssh Permissions",
            font=get_font(11, "bold"),
            fg_color=COLOR_WARNING,
            hover_color=BORDER_COLOR,
            text_color="#000000",
            height=32,
            command=run_perm_fix,
        ).pack(side="right")

        scroll = ctk.CTkScrollableFrame(container, fg_color=BG_ROOT)
        scroll.pack(fill="both", expand=True)

        items: List[KeyCheckItem] = run_system_precheck()

        for item in items:
            card = ctk.CTkFrame(scroll, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_COLOR)
            card.pack(fill="x", pady=4, padx=2)

            cin = ctk.CTkFrame(card, fg_color="transparent")
            cin.pack(fill="x", padx=12, pady=10)

            c_icon = "🟢" if item.status == "OK" else ("🟡" if item.status == "WARNING" else ("🔴" if item.status == "ERROR" else "ℹ️"))
            top = ctk.CTkFrame(cin, fg_color="transparent")
            top.pack(fill="x")

            ctk.CTkLabel(top, text=f"{c_icon} {item.name}", font=get_font(12, "bold"), text_color=TEXT_PRIMARY).pack(side="left")
            ctk.CTkLabel(top, text=item.status, font=get_font(10, "bold"), text_color=COLOR_SUCCESS if item.status == "OK" else COLOR_WARNING).pack(side="right")

            ctk.CTkLabel(cin, text=item.message, font=get_font(11), text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", pady=(2, 0))

            if item.details:
                detail_box = ctk.CTkTextbox(cin, height=50, fg_color=BG_INPUT, border_color=BORDER_COLOR, font=get_mono_font(10))
                detail_box.insert("1.0", item.details)
                detail_box.configure(state="disabled")
                detail_box.pack(fill="x", pady=(6, 0))
