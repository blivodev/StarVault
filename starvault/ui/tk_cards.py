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
    tk_font,
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

    # Favorite star (clickable label) — uses the Lucide icon font so the glyph
    # renders regardless of the active UI font.
    from starvault.ui.icons_font import icon_tk_font as _icon_tk
    star = tk.Label(
        top,
        text="\ue17a" if entry.is_favorite else "\ue2b0",
        bg=card["bg"],
        fg=COLOR_FAVORITE if entry.is_favorite else TEXT_MUTED,
        font=_icon_tk(14),
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
        font=tk_font(9, "bold"),
        padx=6,
        pady=1,
    ).pack(side="left", padx=(0, 8))

    # Title
    title = tk.Label(
        top,
        text=entry.title,
        bg=card["bg"],
        fg=TEXT_PRIMARY,
        font=tk_font(13, "bold"),
        anchor="w",
    )
    title.pack(side="left")
    title.bind("<Button-1>", lambda e, ent=entry: dashboard._on_card_clicked(e, ent))

    # Tag / group / service chips. These are packed to the RIGHT of a long
    # title, so a wide tag ran past the card edge and was hard-clipped
    # mid-word. Elide each label to a sane maximum instead.
    def _chip(parent, text, fg, max_chars=18):
        if len(text) > max_chars:
            text = text[: max_chars - 1] + "\u2026"
        lbl = tk.Label(
            parent,
            text=text,
            bg=BG_INPUT,
            fg=fg,
            font=tk_font(9),
            padx=4,
            pady=1,
        )
        lbl.pack(side="left", padx=2)
        return lbl

    for tag in entry.tags[:3]:
        _chip(top, f"#{tag}", TEXT_MUTED)

    # Group chips
    for grp in getattr(entry, "groups", [])[:2]:
        _chip(top, grp, ACCENT_INDIGO, max_chars=16)

    # Service chips
    for srv in getattr(entry, "services", [])[:2]:
        _chip(top, srv, ACCENT_PRIMARY, max_chars=16)

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


def _btn(parent, text, fg, bg, command, bold=False, danger=False, icon_name=None):
    """Creates a flat clickable button with an optional Lucide icon + text.

    A single tk.Button cannot render a Lucide glyph and Latin text together
    (one font per widget), so this builds a small clickable frame holding an
    icon label and a text label. Still plain-tk, so creation stays cheap.
    """
    from starvault.ui.icons_font import ICON_FAMILY, icon as _icon

    glyph = _icon(icon_name) if icon_name else ""

    holder = tk.Frame(parent, bg=BG_INPUT, highlightthickness=0, bd=0)
    holder.pack(side="left", padx=2)

    def _hover_on(_e=None):
        try:
            holder.configure(bg=BG_CARD)
            for w in holder.winfo_children():
                w.configure(bg=BG_CARD)
        except Exception:
            pass

    def _hover_off(_e=None):
        try:
            holder.configure(bg=BG_INPUT)
            for w in holder.winfo_children():
                w.configure(bg=BG_INPUT)
        except Exception:
            pass

    def _click(_e=None):
        command()

    widgets = []
    if glyph:
        ic = tk.Label(holder, text=glyph, bg=BG_INPUT, fg=fg, font=(ICON_FAMILY, 11),
                      padx=0, pady=2, cursor="hand2")
        ic.pack(side="left", padx=(7, 2))
        widgets.append(ic)
    if text:
        tx = tk.Label(holder, text=text, bg=BG_INPUT, fg=fg,
                      font=tk_font(9, "bold" if bold else "normal"),
                      padx=0, pady=2, cursor="hand2")
        tx.pack(side="left", padx=(2 if glyph else 7, 7))
        widgets.append(tx)

    for w in [holder] + widgets:
        w.bind("<Button-1>", _click)
        w.bind("<Enter>", _hover_on)
        w.bind("<Leave>", _hover_off)
    return holder


def _render_actions(actions, entry, dashboard, bg):
    """Renders the one-click quick-copy buttons for a card."""
    t = entry.entry_type

    if t == "server":
        if entry.hostname:
            _btn(actions, "IP", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.hostname, "IP address copied"), icon_name="network")
        _btn(actions, "SSH", ACCENT_PRIMARY, bg, lambda: dashboard._copy_val(_ssh(entry), "SSH command copied"), bold=True, icon_name="terminal")
        if entry.password:
            _btn(actions, "Password", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.password, "Password copied (30s wipe)", is_sensitive=True), icon_name="key-round")

    elif t == "domain":
        dom_val = entry.domain_name or entry.url or entry.title
        if dom_val:
            clean = dom_val if dom_val.startswith(("http://", "https://")) else f"https://{dom_val}"
            _btn(actions, "Domain", TEXT_PRIMARY, bg, lambda u=clean: dashboard._copy_val(u, "Domain URL copied"), icon_name="globe")
        if getattr(entry, "username", ""):
            _btn(actions, "User", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.username, "Username copied"), icon_name="user")
        if getattr(entry, "password", ""):
            _btn(actions, "Password", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.password, "Password copied (30s wipe)", is_sensitive=True), icon_name="key-round")
        if getattr(entry, "registrar", ""):
            _btn(actions, "Registrar", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.registrar, "Registrar copied"), icon_name="building-2")
        if getattr(entry, "auth_code", ""):
            _btn(actions, "Auth Code", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.auth_code, "Auth code copied (30s wipe)", is_sensitive=True), icon_name="key-round")
        _btn(actions, "Attach", ACCENT_PRIMARY, bg, lambda: dashboard._create_linked_item_for_domain(entry), bold=True, icon_name="link-2")

    elif t == "service":
        if entry.url or entry.hostname:
            _btn(actions, "URL", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.url or entry.hostname, "URL copied"), icon_name="globe")
        if any(x in (entry.service_type or "") for x in ("postgres", "mysql", "redis")):
            _btn(actions, "DB URL", COLOR_WARNING, bg, lambda: dashboard._copy_val(_dburl(entry), "DB URL copied (30s wipe)", is_sensitive=True), bold=True, icon_name="database")
        if entry.api_token:
            _btn(actions, "Token", COLOR_SUCCESS, bg, lambda: dashboard._copy_val(entry.api_token, "API token copied (30s wipe)", is_sensitive=True), icon_name="key-round")
        elif entry.password:
            _btn(actions, "Password", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.password, "Password copied (30s wipe)", is_sensitive=True), icon_name="key-round")
        if entry.username:
            _btn(actions, "User", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.username, "Username copied"), icon_name="user")

    elif t == "apikey":
        if entry.api_token:
            _btn(actions, "Copy Key", ACCENT_INDIGO, bg, lambda: dashboard._copy_val(entry.api_token, "API key copied (30s wipe)", is_sensitive=True), bold=True, icon_name="key-round")
        if entry.api_key_secret:
            _btn(actions, "Secret", COLOR_WARNING, bg, lambda: dashboard._copy_val(entry.api_key_secret, "API secret copied (30s wipe)", is_sensitive=True), icon_name="lock")
        if entry.totp_secret:
            from starvault.totp import generate_totp
            _btn(actions, "2FA", COLOR_SUCCESS, bg, lambda: dashboard._copy_val(generate_totp(entry.totp_secret), "2FA code copied (30s wipe)", is_sensitive=True), icon_name="smartphone")

    elif t == "keypair":
        if entry.public_key:
            _btn(actions, "Public", TEXT_PRIMARY, bg, lambda: dashboard._copy_val(entry.public_key, "Public key copied"), icon_name="key")
        if entry.private_key:
            _btn(actions, "Private", COLOR_DANGER, bg, lambda: dashboard._copy_val(entry.private_key, "Private key copied (30s wipe)", is_sensitive=True), icon_name="key-round")


def _ssh(entry) -> str:
    from starvault.quick_strings import generate_ssh_command
    return generate_ssh_command(entry)


def _dburl(entry) -> str:
    from starvault.quick_strings import generate_db_url
    return generate_db_url(entry)
