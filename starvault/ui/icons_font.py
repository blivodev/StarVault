"""Lucide icon-font helper for StarVault.

Lucide (https://lucide.dev) is licensed ISC — permissive for commercial use,
modification and redistribution. The TTF lives at
`starvault/resources/fonts/Lucide.ttf` with its licence beside it, and the
name->codepoint map at `starvault/resources/brand/lucide_codepoints.json`
(built by `tools/branding/build_lucide_map.py`).

Usage:
    from starvault.ui.icons_font import icon, icon_font
    label = ctk.CTkLabel(parent, text=icon("copy"), font=icon_font(14))

`icon(name)` returns the unicode glyph for a Lucide icon name; unknown names
return "" so a typo degrades to nothing instead of drawing tofu.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

import customtkinter as ctk

# Family name as declared inside the TTF.
ICON_FAMILY = "lucide"

_CODEPOINTS: Optional[Dict[str, int]] = None


def _load() -> Dict[str, int]:
    """Loads the name->codepoint map (once)."""
    global _CODEPOINTS
    if _CODEPOINTS is not None:
        return _CODEPOINTS
    path = Path(__file__).resolve().parent.parent / "resources" / "brand" / "lucide_codepoints.json"
    try:
        _CODEPOINTS = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        _CODEPOINTS = {}
    return _CODEPOINTS


def icon(name: str) -> str:
    """Returns the Lucide glyph for `name` (empty string if unknown)."""
    cp = _load().get(name)
    return chr(cp) if cp else ""


def has_icon(name: str) -> bool:
    """True if `name` exists in the Lucide map."""
    return name in _load()


def icon_font(size: int = 14, weight: str = "normal") -> ctk.CTkFont:
    """Returns the Lucide icon font at the requested size (for CTk widgets)."""
    return ctk.CTkFont(family=ICON_FAMILY, size=size, weight=weight)


def icon_tk_font(size: int = 14, weight: str = "normal"):
    """Returns a plain tkinter font tuple for the icon font (for tk widgets)."""
    return (ICON_FAMILY, size, weight)


# Named constants for the icons the app uses most, so call sites read clearly
# and a wrong slug shows up in one place.
ACTION_COPY = "copy"
ACTION_REVEAL = "eye"
ACTION_HIDE = "eye-off"
ACTION_EDIT = "pencil"
ACTION_DELETE = "trash-2"
ACTION_ADD = "plus"
ACTION_CLOSE = "x"
ACTION_SEARCH = "search"
ACTION_REFRESH = "refresh-cw"
ACTION_STAR = "star"
ACTION_LOCK = "lock"
ACTION_UNLOCK = "lock-open"
ACTION_SETTINGS = "settings"
ACTION_DOWNLOAD = "download"
ACTION_UPLOAD = "upload"
ACTION_OPEN = "arrow-up-right"
ACTION_HISTORY = "history"
ACTION_DUPLICATE = "copy-plus"
ACTION_IMPORT = "download"
ACTION_EXPORT = "upload"
ACTION_GENERATE = "wand-sparkles"
ACTION_INSTALL = "monitor-down"
ACTION_SAVE = "save"
ACTION_MIN = "minus"
ACTION_MAX = "square"
ACTION_RESTORE = "copy"

TYPE_SERVER = "server"
TYPE_DOMAIN = "globe"
TYPE_SERVICE = "package"
TYPE_APIKEY = "key-round"
TYPE_KEYPAIR = "key"
TYPE_FILE = "file"
TYPE_TAG = "tag"
TYPE_GROUP = "folder"

NAV_CREDENTIALS = "layout-grid"
NAV_GROUPS = "folder-tree"
NAV_2FA = "smartphone"
NAV_HEALTH = "shield-check"
NAV_FILES = "folder-lock"
NAV_CRYPTO = "key-round"
