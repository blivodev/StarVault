"""Lightweight tk-based card renderer for StarVault dashboard.

Uses plain tkinter widgets instead of customtkinter for the high-volume
credential cards. customtkinter's canvas-drawn widgets cost ~1ms each
(~34 per card = ~35ms/card), which makes search-result rebuilds take
seconds. tk widgets are 25-100x cheaper to create with the same colors and
fonts, cutting card creation from ~35ms to ~5ms with no functionality loss.

Visual difference: flat corners instead of rounded (acceptable tradeoff for
speed). All theme colors and fonts are preserved.
"""

import tkinter as tk
from typing import Optional

from starvault.ui.theme import (
    ACCENT_EMERALD,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_CARD_HOVER,
    BG_INPUT,
    BORDER_COLOR,
    COLOR_DANGER,
    COLOR_FAVORITE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)


def _bg(widget) -> str:
    """Returns the background color of a widget (works for tk and ctk)."""
    try:
        return widget.cget("fg_color")
    except Exception:
        pass
    try:
        return widget.cget("bg")
    except Exception:
        return BG_CARD


def render_tk_card(parent, entry, dashboard, is_selected: bool) -> tk.Frame:
    """Renders a credential card using plain tk widgets.

    All interactions (copy buttons, favorite toggle, selection, quick-actions)
    delegate to the DashboardView methods, so functionality is identical to the
    customtkinter card — only the widget toolkit differs.
    """
    card = tk.Frame(
        parent,
        bg=BG_CARD_HOVER if is_selected else BG_CARD,
        highlightbackground=ACCENT_PRIMARY if is_selected else BORDER_COLOR,
        highlightthickness=2 if is_selected else 1,
    )
    card.pack(fill="x", pady=4, padx=4)
    card.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    inner = tk.Frame(card, bg=card["bg"])
    inner.pack(fill="x", padx=12, pady=8)
    inner.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    # --- Top row: star + type badge + title + tags ---
    top = tk.Frame(inner, bg=card["bg"])
    top.pack(fill="x")
    top.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    # Favorite star (clickable label)
    star = tk.Label(
        top,
        text="★" if entry.is_favorite else "☆",
        bg=card["bg"],
        fg=COLOR_FAVORITE if entry.is_favorite else TEXT_MUTED,
        font=("Segoe UI", 14),
        cursor="hand2",
    )
    star.pack(side="left", padx=(0, 6))
    star.bind("<Button-1>", lambda e, ent=entry: dashboard._toggle_favorite(ent))

    # Type badge
    badge_color, badge_text = _badge(entry)
    tk.Label(
        top,
        text=badge_text,
        bg=BG_INPUT,
        fg=badge_color,
        font=("Segoe UI", 9, "bold"),
        padx=6,
        pady=1,
    ).pack(side="left", padx=(0, 8))

    # Title
    title = tk.Label(
        top,
        text=entry.title,
        bg=card["bg"],
        fg=TEXT_PRIMARY,
        font=("Segoe UI", 13, "bold"),
        anchor="w",
    )
    title.pack(side="left")
    title.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    # Tag chips
    for tag in entry.tags[:3]:
        tk.Label(
            top,
            text=f"#{tag}",
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            font=("Segoe UI", 9),
            padx=4,
            pady=1,
        ).pack(side="left", padx=2)

    # Group chips
    for grp in getattr(entry, "groups", [])[:2]:
        tk.Label(
            top,
            text=grp,
            bg=BG_INPUT,
            fg=ACCENT_INDIGO,
            font=("Segoe UI", 9),
            padx=4,
            pady=1,
        ).pack(side="left", padx=2)

    # Service chips
    for srv in getattr(entry, "services", [])[:2]:
        tk.Label(
            top,
            text=srv,
            bg=BG_INPUT,
            fg=ACCENT_PRIMARY,
            font=("Segoe UI", 9),
            padx=4,
            pady=1,
        ).pack(side="left", padx=2)

    # --- Subtitle row ---
    sub = tk.Label(
        inner,
        text=_preview(entry),
        bg=card["bg"],
        fg=TEXT_SECONDARY,
        font=("Consolas", 10),
        anchor="w",
        justify="left",
    )
    sub.pack(fill="x", pady=(4, 6))
    sub.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    # --- Action buttons row ---
    actions = tk.Frame(inner, bg=card["bg"])
    actions.pack(fill="x")
    actions.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    _render_actions(actions, entry, dashboard, card["bg"])

    return card


def _badge(entry):
    """Returns (color, text) for the entry-type badge."""
    t = entry.entry_type
    if t == "server":
        return ACCENT_PRIMARY, "SERVER"
    if t == "domain":
        return ACCENT_EMERALD, "DOMAIN"
    if t == "service":
        return COLOR_WARNING, "SERVICE"
    if t == "apikey":
        return ACCENT_INDIGO, "API KEY"
    return ACCENT_PURPLE, "KEY"


def _preview(entry) -> str:
    """Builds the one-line subtitle preview for a card."""
    t = entry.entry_type
    if t == "server":
        p = f"{entry.username}@{entry.hostname}:{entry.port}"
        if entry.os_distro:
            p += f" ({entry.os_distro})"
        return p
    if t == "domain":
        dom = entry.domain_name or entry.url or entry.title
        p = f"{dom} • {entry.registrar or 'Self-Managed'}"
        if entry.expires_at:
            p += f" • Exp: {entry.expires_at[:10]}"
        if getattr(entry, "auto_renew", False):
            p += " • Auto-Renew"
        return p
    if t == "service":
        p = f"{entry.app_name} • {entry.url or entry.hostname}"
        if entry.port:
            p += f":{entry.port}"
        return p
    if t == "apikey":
        p = f"{entry.provider or 'API Key'} • Env: {entry.environment or 'Production'}"
        if entry.expires_at:
            p += f" • Exp: {entry.expires_at[:10]}"
        return p
    if t == "keypair":
        return f"{entry.key_type.upper()} • Fingerprint: {entry.fingerprint[:28]}..."
    return ""


def _btn(parent, text, fg, bg, command, bold=False, danger=False):
    """Creates a flat tk button styled like a CTk button."""
    b = tk.Button(
        parent,
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
    b.pack(side="left", padx=2)
    return b


def _render_actions(actions, entry, dashboard, bg):
    """Renders the one-click quick-copy buttons for a card."""
    t = entry.entry_type

    if t == "server":
        if entry.hostname:
            _btn(actions, "Copy IP", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.hostname, "IP address copied"))
        _btn(actions, "SSH", ACCENT_PRIMARY, bg, lambda: dashboard._copy_val(_ssh(entry), "SSH command copied"), bold=True)
        if entry.password:
            _btn(actions, "Password", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.password, "Password copied (30s wipe)", is_sensitive=True))

    elif t == "domain":
        dom_val = entry.domain_name or entry.url or entry.title
        if dom_val:
            clean = dom_val if dom_val.startswith(("http://", "https://")) else f"https://{dom_val}"
            _btn(actions, "Domain", TEXT_PRIMARY, bg, lambda u=clean: dashboard._copy_val(u, "Domain URL copied"))
        if getattr(entry, "username", ""):
            _btn(actions, "User", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.username, "Username copied"))
        if getattr(entry, "password", ""):
            _btn(actions, "Password", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.password, "Password copied (30s wipe)", is_sensitive=True))
        if getattr(entry, "registrar", ""):
            _btn(actions, "Registrar", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.registrar, "Registrar copied"))
        if getattr(entry, "auth_code", ""):
            _btn(actions, "Auth Code", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.auth_code, "Auth code copied (30s wipe)", is_sensitive=True))
        _btn(actions, "+ Attach", ACCENT_PRIMARY, bg, lambda: dashboard._create_linked_item_for_domain(entry), bold=True)

    elif t == "service":
        if entry.url or entry.hostname:
            _btn(actions, "URL", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.url or entry.hostname, "URL copied"))
        if any(x in (entry.service_type or "") for x in ("postgres", "mysql", "redis")):
            _btn(actions, "DB URL", COLOR_WARNING, bg, lambda: dashboard._copy_val(_dburl(entry), "DB URL copied (30s wipe)", is_sensitive=True), bold=True)
        if entry.api_token:
            _btn(actions, "Token", COLOR_SUCCESS, bg, lambda: dashboard._copy_val(entry.api_token, "API token copied (30s wipe)", is_sensitive=True))
        elif entry.password:
            _btn(actions, "Password", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.password, "Password copied (30s wipe)", is_sensitive=True))

    elif t == "apikey":
        if entry.api_token:
            _btn(actions, "Copy Key", ACCENT_INDIGO, bg, lambda: dashboard._copy_val(entry.api_token, "API key copied (30s wipe)", is_sensitive=True), bold=True)
        if entry.api_key_secret:
            _btn(actions, "Secret", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.api_key_secret, "API secret copied (30s wipe)", is_sensitive=True))
        if entry.totp_secret:
            from starvault.totp import generate_totp
            _btn(actions, "2FA Code", COLOR_SUCCESS, bg, lambda: dashboard._copy_val(generate_totp(entry.totp_secret), "2FA code copied (30s wipe)", is_sensitive=True))

    elif t == "keypair":
        if entry.public_key:
            _btn(actions, "Public", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.public_key, "Public key copied"))
        if entry.private_key:
            _btn(actions, "Private", COLOR_DANGER, bg, lambda: dashboard._copy_val(entry.private_key, "Private key copied (30s wipe)", is_sensitive=True))


def _ssh(entry) -> str:
    from starvault.quick_strings import generate_ssh_command
    return generate_ssh_command(entry)


def _dburl(entry) -> str:
    from starvault.quick_strings import generate_db_url
    return generate_db_url(entry)
