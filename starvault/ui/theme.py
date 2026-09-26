"""Color tokens, theme styling, typography, and dynamic theming system for StarVault."""

from typing import Callable, Dict, List, Optional
import customtkinter as ctk

# -----------------------------------------------------------------------------
# Theme Color Palettes
# -----------------------------------------------------------------------------

THEME_PALETTES: Dict[str, Dict[str, str]] = {
    "Dark": {
        "mode": "Dark",
        "BG_ROOT": "#090d16",
        "BG_SIDEBAR": "#0e1422",
        "BG_CARD": "#141c2e",
        "BG_CARD_HOVER": "#1a253c",
        "BG_INPUT": "#0c1322",
        "BG_SUBTLE": "#192238",
        "BORDER_COLOR": "#23304c",
        "BORDER_FOCUS": "#38bdf8",
        "ACCENT_PRIMARY": "#38bdf8",
        "ACCENT_HOVER": "#0ea5e9",
        "ACCENT_INDIGO": "#6366f1",
        "ACCENT_PURPLE": "#8b5cf6",
        "COLOR_SUCCESS": "#10b981",
        "COLOR_WARNING": "#f59e0b",
        "COLOR_DANGER": "#ef4444",
        "COLOR_DANGER_HOVER": "#dc2626",
        "COLOR_FAVORITE": "#fbbf24",
        "TEXT_PRIMARY": "#f8fafc",
        "TEXT_SECONDARY": "#cbd5e1",
        "TEXT_MUTED": "#94a3b8",
        "TEXT_ACCENT": "#38bdf8",
        "TEXT_ON_ACCENT": "#000000",
    },
    "Light": {
        "mode": "Light",
        "BG_ROOT": "#f1f5f9",
        "BG_SIDEBAR": "#e2e8f0",
        "BG_CARD": "#ffffff",
        "BG_CARD_HOVER": "#f8fafc",
        "BG_INPUT": "#f8fafc",
        "BG_SUBTLE": "#e2e8f0",
        "BORDER_COLOR": "#cbd5e1",
        "BORDER_FOCUS": "#0284c7",
        "ACCENT_PRIMARY": "#0284c7",
        "ACCENT_HOVER": "#0369a1",
        "ACCENT_INDIGO": "#4f46e5",
        "ACCENT_PURPLE": "#7c3aed",
        "COLOR_SUCCESS": "#059669",
        "COLOR_WARNING": "#d97706",
        "COLOR_DANGER": "#dc2626",
        "COLOR_DANGER_HOVER": "#b91c1c",
        "COLOR_FAVORITE": "#d97706",
        "TEXT_PRIMARY": "#0f172a",
        "TEXT_SECONDARY": "#334155",
        "TEXT_MUTED": "#64748b",
        "TEXT_ACCENT": "#0284c7",
    },
    "Trendy": {
        "mode": "Dark",
        "BG_ROOT": "#0f0c1b",
        "BG_SIDEBAR": "#17122b",
        "BG_CARD": "#1e163b",
        "BG_CARD_HOVER": "#2a1e52",
        "BG_INPUT": "#130f24",
        "BG_SUBTLE": "#261c47",
        "BORDER_COLOR": "#3c2a75",
        "BORDER_FOCUS": "#00f0ff",
        "ACCENT_PRIMARY": "#00f0ff",
        "ACCENT_HOVER": "#ff007f",
        "ACCENT_INDIGO": "#a855f7",
        "ACCENT_PURPLE": "#b026ff",
        "COLOR_SUCCESS": "#00ffaa",
        "COLOR_WARNING": "#ffd000",
        "COLOR_DANGER": "#ff2a85",
        "COLOR_DANGER_HOVER": "#e0186f",
        "COLOR_FAVORITE": "#ffb800",
        "TEXT_PRIMARY": "#f5f3ff",
        "TEXT_SECONDARY": "#c4b5fd",
        "TEXT_MUTED": "#7c6f9f",
        "TEXT_ACCENT": "#00f0ff",
    },
    "Console": {
        "mode": "Dark",
        "BG_ROOT": "#050a05",
        "BG_SIDEBAR": "#081208",
        "BG_CARD": "#0d1a0d",
        "BG_CARD_HOVER": "#132613",
        "BG_INPUT": "#060d06",
        "BG_SUBTLE": "#112211",
        "BORDER_COLOR": "#1a381a",
        "BORDER_FOCUS": "#00ff66",
        "ACCENT_PRIMARY": "#00ff66",
        "ACCENT_HOVER": "#33ff88",
        "ACCENT_INDIGO": "#22cc66",
        "ACCENT_PURPLE": "#11aa55",
        "COLOR_SUCCESS": "#00ff66",
        "COLOR_WARNING": "#ffcc00",
        "COLOR_DANGER": "#ff3333",
        "COLOR_DANGER_HOVER": "#cc2222",
        "COLOR_FAVORITE": "#00ff66",
        "TEXT_PRIMARY": "#e0ffe0",
        "TEXT_SECONDARY": "#00cc55",
        "TEXT_MUTED": "#007733",
        "TEXT_ACCENT": "#00ff66",
    },
    "Nord": {
        "mode": "Dark",
        "BG_ROOT": "#242933",
        "BG_SIDEBAR": "#2e3440",
        "BG_CARD": "#3b4252",
        "BG_CARD_HOVER": "#434c5e",
        "BG_INPUT": "#292e39",
        "BG_SUBTLE": "#353c4a",
        "BORDER_COLOR": "#4c566a",
        "BORDER_FOCUS": "#88c0d0",
        "ACCENT_PRIMARY": "#88c0d0",
        "ACCENT_HOVER": "#81a1c1",
        "ACCENT_INDIGO": "#5e81ac",
        "ACCENT_PURPLE": "#b48ead",
        "COLOR_SUCCESS": "#a3be8c",
        "COLOR_WARNING": "#ebcb8b",
        "COLOR_DANGER": "#bf616a",
        "COLOR_DANGER_HOVER": "#a64952",
        "COLOR_FAVORITE": "#ebcb8b",
        "TEXT_PRIMARY": "#eceff4",
        "TEXT_SECONDARY": "#d8dee9",
        "TEXT_MUTED": "#7b88a1",
        "TEXT_ACCENT": "#88c0d0",
    },
    "Dracula": {
        "mode": "Dark",
        "BG_ROOT": "#1e1f29",
        "BG_SIDEBAR": "#242634",
        "BG_CARD": "#282a36",
        "BG_CARD_HOVER": "#343746",
        "BG_INPUT": "#21222c",
        "BG_SUBTLE": "#383a59",
        "BORDER_COLOR": "#44475a",
        "BORDER_FOCUS": "#bd93f9",
        "ACCENT_PRIMARY": "#bd93f9",
        "ACCENT_HOVER": "#ff79c6",
        "ACCENT_INDIGO": "#6272a4",
        "ACCENT_PURPLE": "#bd93f9",
        "COLOR_SUCCESS": "#50fa7b",
        "COLOR_WARNING": "#f1fa8c",
        "COLOR_DANGER": "#ff5555",
        "COLOR_DANGER_HOVER": "#ff3333",
        "COLOR_FAVORITE": "#f1fa8c",
        "TEXT_PRIMARY": "#f8f8f2",
        "TEXT_SECONDARY": "#bfbfd0",
        "TEXT_MUTED": "#6272a4",
        "TEXT_ACCENT": "#bd93f9",
    },
}

THEMES = THEME_PALETTES

# Active theme tokens initialized to Dark
CURRENT_THEME = "Dark"
_THEME_LISTENERS: List[Callable[[str], None]] = []

BG_ROOT = THEME_PALETTES["Dark"]["BG_ROOT"]
BG_SIDEBAR = THEME_PALETTES["Dark"]["BG_SIDEBAR"]
BG_CARD = THEME_PALETTES["Dark"]["BG_CARD"]
BG_CARD_HOVER = THEME_PALETTES["Dark"]["BG_CARD_HOVER"]
BG_INPUT = THEME_PALETTES["Dark"]["BG_INPUT"]
BG_SUBTLE = THEME_PALETTES["Dark"]["BG_SUBTLE"]
BORDER_COLOR = THEME_PALETTES["Dark"]["BORDER_COLOR"]
BORDER_FOCUS = THEME_PALETTES["Dark"]["BORDER_FOCUS"]
ACCENT_PRIMARY = THEME_PALETTES["Dark"]["ACCENT_PRIMARY"]
ACCENT_HOVER = THEME_PALETTES["Dark"]["ACCENT_HOVER"]
ACCENT_INDIGO = THEME_PALETTES["Dark"]["ACCENT_INDIGO"]
ACCENT_PURPLE = THEME_PALETTES["Dark"]["ACCENT_PURPLE"]
COLOR_SUCCESS = THEME_PALETTES["Dark"]["COLOR_SUCCESS"]
COLOR_WARNING = THEME_PALETTES["Dark"]["COLOR_WARNING"]
COLOR_DANGER = THEME_PALETTES["Dark"]["COLOR_DANGER"]
COLOR_DANGER_HOVER = THEME_PALETTES["Dark"]["COLOR_DANGER_HOVER"]
COLOR_FAVORITE = THEME_PALETTES["Dark"]["COLOR_FAVORITE"]
TEXT_PRIMARY = THEME_PALETTES["Dark"]["TEXT_PRIMARY"]
TEXT_SECONDARY = THEME_PALETTES["Dark"]["TEXT_SECONDARY"]
TEXT_MUTED = THEME_PALETTES["Dark"]["TEXT_MUTED"]
TEXT_ACCENT = THEME_PALETTES["Dark"]["TEXT_ACCENT"]
TEXT_ON_ACCENT = THEME_PALETTES["Dark"].get("TEXT_ON_ACCENT", "#000000")

ACCENT_EMERALD = "#10b981"

TYPE_COLORS = {
    "server": {"bg": "#1e293b", "text": "#38bdf8", "border": "#38bdf8"},
    "service": {"bg": "#1e293b", "text": "#f59e0b", "border": "#f59e0b"},
    "domain": {"bg": "#064e3b", "text": "#34d399", "border": "#10b981"},
    "apikey": {"bg": "#1e1b4b", "text": "#818cf8", "border": "#6366f1"},
    "keypair": {"bg": "#1e293b", "text": "#a855f7", "border": "#a855f7"},
}


def get_available_themes() -> List[str]:
    """Returns list of supported theme names."""
    return list(THEME_PALETTES.keys())


def get_current_theme() -> str:
    """Returns currently active theme name."""
    return CURRENT_THEME


def register_theme_listener(callback: Callable[[str], None]) -> None:
    """Registers a callback function to be notified when the theme changes."""
    if callback not in _THEME_LISTENERS:
        _THEME_LISTENERS.append(callback)


def unregister_theme_listener(callback: Callable[[str], None]) -> None:
    """Unregisters a theme change listener."""
    if callback in _THEME_LISTENERS:
        _THEME_LISTENERS.remove(callback)


def apply_theme(theme_name: str, save_to_config: bool = True) -> None:
    """Applies a theme by name, updating global tokens, CustomTkinter mode, and alerting listeners."""
    global CURRENT_THEME, BG_ROOT, BG_SIDEBAR, BG_CARD, BG_CARD_HOVER, BG_INPUT, BG_SUBTLE
    global BORDER_COLOR, BORDER_FOCUS, ACCENT_PRIMARY, ACCENT_HOVER, ACCENT_INDIGO, ACCENT_PURPLE
    global COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER, COLOR_DANGER_HOVER, COLOR_FAVORITE
    global TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, TEXT_ACCENT, TEXT_ON_ACCENT

    if theme_name not in THEME_PALETTES:
        theme_name = "Dark"

    CURRENT_THEME = theme_name
    palette = THEME_PALETTES[theme_name]

    # Set CustomTkinter appearance mode
    ctk.set_appearance_mode(palette.get("mode", "Dark"))

    # Update global module-level tokens
    BG_ROOT = palette["BG_ROOT"]
    BG_SIDEBAR = palette["BG_SIDEBAR"]
    BG_CARD = palette["BG_CARD"]
    BG_CARD_HOVER = palette["BG_CARD_HOVER"]
    BG_INPUT = palette["BG_INPUT"]
    BG_SUBTLE = palette["BG_SUBTLE"]
    BORDER_COLOR = palette["BORDER_COLOR"]
    BORDER_FOCUS = palette["BORDER_FOCUS"]
    ACCENT_PRIMARY = palette["ACCENT_PRIMARY"]
    ACCENT_HOVER = palette["ACCENT_HOVER"]
    ACCENT_INDIGO = palette["ACCENT_INDIGO"]
    ACCENT_PURPLE = palette["ACCENT_PURPLE"]
    COLOR_SUCCESS = palette["COLOR_SUCCESS"]
    COLOR_WARNING = palette["COLOR_WARNING"]
    COLOR_DANGER = palette["COLOR_DANGER"]
    COLOR_DANGER_HOVER = palette["COLOR_DANGER_HOVER"]
    COLOR_FAVORITE = palette["COLOR_FAVORITE"]
    TEXT_PRIMARY = palette["TEXT_PRIMARY"]
    TEXT_SECONDARY = palette["TEXT_SECONDARY"]
    TEXT_MUTED = palette["TEXT_MUTED"]
    TEXT_ACCENT = palette["TEXT_ACCENT"]
    TEXT_ON_ACCENT = palette.get("TEXT_ON_ACCENT", "#000000" if palette.get("mode") == "Dark" else "#ffffff")

    # Propagate updated tokens into all loaded StarVault module namespaces
    import sys
    for mod_name, mod in list(sys.modules.items()):
        if mod and (mod_name.startswith("starvault") or mod_name.startswith("tests")):
            for token_key, token_val in palette.items():
                if hasattr(mod, token_key):
                    try:
                        setattr(mod, token_key, token_val)
                    except Exception:
                        pass

    if save_to_config:
        try:
            from starvault.app_config import AppConfigManager
            cfg = AppConfigManager()
            cfg.set_theme(theme_name)
        except Exception:
            pass

    # Notify listeners
    for listener in _THEME_LISTENERS:
        try:
            listener(theme_name)
        except Exception:
            pass


def cycle_next_theme() -> str:
    """Cycles to the next available theme and applies it."""
    themes = get_available_themes()
    curr = get_current_theme()
    idx = (themes.index(curr) + 1) % len(themes) if curr in themes else 0
    next_t = themes[idx]
    apply_theme(next_t, save_to_config=True)
    return next_t


def apply_global_theme() -> None:
    """Initializes CustomTkinter global theme settings based on saved preference."""
    saved_theme = "Dark"
    try:
        from starvault.app_config import AppConfigManager
        cfg = AppConfigManager()
        saved_theme = cfg.get_theme()
    except Exception:
        pass

    apply_theme(saved_theme, save_to_config=False)


def get_font(size: int = 13, weight: str = "normal") -> ctk.CTkFont:
    """Returns application UI font."""
    return ctk.CTkFont(family="Segoe UI", size=size, weight=weight)


def get_mono_font(size: int = 12, weight: str = "normal") -> ctk.CTkFont:
    """Returns monospace font for credentials, code, and keys."""
    return ctk.CTkFont(family="Consolas", size=size, weight=weight)
