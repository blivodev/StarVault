"""Color tokens, theme styling, typography, and dynamic theming system for StarVault."""

import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional
import customtkinter as ctk

# -----------------------------------------------------------------------------
# Font Engine & Open-Source Typography Initializer
# -----------------------------------------------------------------------------

_FONTS_INITIALIZED = False
ACTIVE_UI_FONT = "Inter"
ACTIVE_MONO_FONT = "JetBrains Mono"
_FONT_LISTENERS: List[Callable[[], None]] = []


def _init_fonts() -> None:
    """Discovers and registers bundled open-source fonts."""
    global _FONTS_INITIALIZED, ACTIVE_UI_FONT, ACTIVE_MONO_FONT
    if _FONTS_INITIALIZED:
        return

    # Look for fonts directory in starvault/resources/fonts
    base_dir = Path(__file__).resolve().parent.parent / "resources" / "fonts"
    if base_dir.exists():
        for font_file in sorted(base_dir.glob("*.ttf")):
            try:
                if sys.platform.startswith("win"):
                    # enumerable=True ensures Tkinter/GDI font enumeration discovers custom font families
                    ctk.FontManager.windows_load_font(str(font_file), private=True, enumerable=True)
                elif sys.platform.startswith("linux"):
                    ctk.FontManager.load_font(str(font_file))
            except Exception:
                pass

    # Validate active UI font with graceful fallback
    try:
        from starvault.app_config import AppConfigManager
        cfg = AppConfigManager()
        saved_ui = cfg.data.get("ui_font", "")
        saved_mono = cfg.data.get("mono_font", "")
        if saved_ui:
            ACTIVE_UI_FONT = saved_ui
        if saved_mono:
            ACTIVE_MONO_FONT = saved_mono
    except Exception:
        pass

    _FONTS_INITIALIZED = True


# Initialize font system on module import
_init_fonts()


def get_available_ui_fonts() -> List[str]:
    """Returns list of clean, open-source and system UI fonts."""
    return [
        "Inter",
        "Plus Jakarta Sans",
        "Outfit",
        "Space Grotesk",
        "Fira Sans",
        "Roboto",
        "Rajdhani",
        "Segoe UI",
        "Source Sans Pro",
        "Arial",
    ]


def get_available_mono_fonts() -> List[str]:
    """Returns list of clean, open-source and system monospace fonts."""
    return [
        "JetBrains Mono",
        "Fira Code",
        "Inconsolata",
        "Cascadia Code",
        "Consolas",
        "Courier New",
    ]


def set_ui_font_family(family: str, save_to_config: bool = True, is_user_override: bool = True) -> None:
    """Sets active application UI font family."""
    global ACTIVE_UI_FONT
    if ACTIVE_UI_FONT == family:
        return
    ACTIVE_UI_FONT = family
    clear_font_cache()
    if save_to_config:
        try:
            from starvault.app_config import AppConfigManager
            cfg = AppConfigManager()
            cfg.data["ui_font"] = family
            if is_user_override:
                cfg.data["user_has_custom_font"] = True
            cfg._save()
        except Exception:
            pass
    for listener in list(_FONT_LISTENERS):
        try:
            listener()
        except Exception:
            pass


def set_mono_font_family(family: str, save_to_config: bool = True, is_user_override: bool = True) -> None:
    """Sets active monospace font family for credentials and code."""
    global ACTIVE_MONO_FONT
    if ACTIVE_MONO_FONT == family:
        return
    ACTIVE_MONO_FONT = family
    clear_font_cache()
    if save_to_config:
        try:
            from starvault.app_config import AppConfigManager
            cfg = AppConfigManager()
            cfg.data["mono_font"] = family
            if is_user_override:
                cfg.data["user_has_custom_font"] = True
            cfg._save()
        except Exception:
            pass
    for listener in list(_FONT_LISTENERS):
        try:
            listener()
        except Exception:
            pass


def register_font_listener(callback: Callable[[], None]) -> None:
    """Registers callback for font changes."""
    if callback not in _FONT_LISTENERS:
        _FONT_LISTENERS.append(callback)


_FONT_CACHE: Dict[tuple, ctk.CTkFont] = {}


def get_font(size: int = 13, weight: str = "normal") -> ctk.CTkFont:
    """Returns application UI font using modern open-source typography.

    Fonts are cached: creating a fresh CTkFont per widget was a significant
    share of UI rebuild cost. Cached fonts are safe to share across widgets.
    """
    key = (ACTIVE_UI_FONT, size, weight)
    cached = _FONT_CACHE.get(key)
    if cached is not None:
        return cached
    font = ctk.CTkFont(family=ACTIVE_UI_FONT, size=size, weight=weight)
    _FONT_CACHE[key] = font
    return font


def get_mono_font(size: int = 12, weight: str = "normal") -> ctk.CTkFont:
    """Returns monospace font for credentials, code, tokens, and keys."""
    key = (ACTIVE_MONO_FONT, size, weight)
    cached = _FONT_CACHE.get(key)
    if cached is not None:
        return cached
    font = ctk.CTkFont(family=ACTIVE_MONO_FONT, size=size, weight=weight)
    _FONT_CACHE[key] = font
    return font


def clear_font_cache() -> None:
    """Drops cached fonts (called when the active font family changes)."""
    _FONT_CACHE.clear()


# -----------------------------------------------------------------------------
# Curated Theme Color Palettes
# -----------------------------------------------------------------------------

THEME_PALETTES: Dict[str, Dict[str, str]] = {
    # 1. Dark (Modern Zinc Dark - Linear / Raycast / VS Code clean aesthetic)
    "Dark": {
        "UI_FONT": "Inter",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Dark",
        "BG_ROOT": "#09090b",
        "BG_SIDEBAR": "#111113",
        "BG_CARD": "#18181b",
        "BG_CARD_HOVER": "#222226",
        "BG_INPUT": "#0e0e11",
        "BG_SUBTLE": "#1e1e24",
        "BORDER_COLOR": "#27272a",
        "BORDER_FOCUS": "#38bdf8",
        "ACCENT_PRIMARY": "#38bdf8",
        "ACCENT_HOVER": "#0ea5e9",
        "ACCENT_INDIGO": "#6366f1",
        "ACCENT_PURPLE": "#a855f7",
        "COLOR_SUCCESS": "#10b981",
        "COLOR_WARNING": "#f59e0b",
        "COLOR_DANGER": "#ef4444",
        "COLOR_DANGER_HOVER": "#dc2626",
        "COLOR_FAVORITE": "#fbbf24",
        "TEXT_PRIMARY": "#f4f4f5",
        "TEXT_SECONDARY": "#a1a1aa",
        "TEXT_MUTED": "#71717a",
        "TEXT_ACCENT": "#38bdf8",
        "TEXT_ON_ACCENT": "#09090b",
    },
    # 2. Midnight OLED (True Pure Black for OLED displays & maximum focus)
    "Midnight OLED": {
        "UI_FONT": "Inter",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Dark",
        "BG_ROOT": "#000000",
        "BG_SIDEBAR": "#080808",
        "BG_CARD": "#121212",
        "BG_CARD_HOVER": "#1c1c1c",
        "BG_INPUT": "#0a0a0a",
        "BG_SUBTLE": "#171717",
        "BORDER_COLOR": "#262626",
        "BORDER_FOCUS": "#e4e4e7",
        "ACCENT_PRIMARY": "#e4e4e7",
        "ACCENT_HOVER": "#ffffff",
        "ACCENT_INDIGO": "#818cf8",
        "ACCENT_PURPLE": "#c084fc",
        "COLOR_SUCCESS": "#22c55e",
        "COLOR_WARNING": "#eab308",
        "COLOR_DANGER": "#f43f5e",
        "COLOR_DANGER_HOVER": "#e11d48",
        "COLOR_FAVORITE": "#facc15",
        "TEXT_PRIMARY": "#ffffff",
        "TEXT_SECONDARY": "#a3a3a3",
        "TEXT_MUTED": "#525252",
        "TEXT_ACCENT": "#ffffff",
        "TEXT_ON_ACCENT": "#000000",
    },
    # 3. Tokyo Night (Deep storm navy developer palette)
    "Tokyo Night": {
        "UI_FONT": "Plus Jakarta Sans",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Dark",
        "BG_ROOT": "#1a1b26",
        "BG_SIDEBAR": "#16161e",
        "BG_CARD": "#24283b",
        "BG_CARD_HOVER": "#2f3549",
        "BG_INPUT": "#13141c",
        "BG_SUBTLE": "#1f2335",
        "BORDER_COLOR": "#292e42",
        "BORDER_FOCUS": "#7aa2f7",
        "ACCENT_PRIMARY": "#7aa2f7",
        "ACCENT_HOVER": "#89ddff",
        "ACCENT_INDIGO": "#7dcfff",
        "ACCENT_PURPLE": "#bb9af7",
        "COLOR_SUCCESS": "#9ece6a",
        "COLOR_WARNING": "#e0af68",
        "COLOR_DANGER": "#f7768e",
        "COLOR_DANGER_HOVER": "#db4b4b",
        "COLOR_FAVORITE": "#e0af68",
        "TEXT_PRIMARY": "#c0caf5",
        "TEXT_SECONDARY": "#9aa5ce",
        "TEXT_MUTED": "#565f89",
        "TEXT_ACCENT": "#7aa2f7",
        "TEXT_ON_ACCENT": "#16161e",
    },
    # 4. Catppuccin Mocha (Smooth pastel dark palette)
    "Catppuccin Mocha": {
        "UI_FONT": "Plus Jakarta Sans",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#11111b",
        "BG_SIDEBAR": "#181825",
        "BG_CARD": "#1e1e2e",
        "BG_CARD_HOVER": "#313244",
        "BG_INPUT": "#141420",
        "BG_SUBTLE": "#252538",
        "BORDER_COLOR": "#313244",
        "BORDER_FOCUS": "#b4befe",
        "ACCENT_PRIMARY": "#b4befe",
        "ACCENT_HOVER": "#cba6f7",
        "ACCENT_INDIGO": "#89b4fa",
        "ACCENT_PURPLE": "#cba6f7",
        "COLOR_SUCCESS": "#a6e3a1",
        "COLOR_WARNING": "#f9e2af",
        "COLOR_DANGER": "#f38ba8",
        "COLOR_DANGER_HOVER": "#eba0ac",
        "COLOR_FAVORITE": "#fab387",
        "TEXT_PRIMARY": "#cdd6f4",
        "TEXT_SECONDARY": "#a6adc8",
        "TEXT_MUTED": "#6c7086",
        "TEXT_ACCENT": "#b4befe",
        "TEXT_ON_ACCENT": "#11111b",
    },
    # 5. Gruvbox Dark (Warm artisan retro-modern dark)
    "Gruvbox Dark": {
        "UI_FONT": "Space Grotesk",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#1d2021",
        "BG_SIDEBAR": "#282828",
        "BG_CARD": "#32302f",
        "BG_CARD_HOVER": "#3c3836",
        "BG_INPUT": "#181a1b",
        "BG_SUBTLE": "#2d2b2a",
        "BORDER_COLOR": "#504945",
        "BORDER_FOCUS": "#fe8019",
        "ACCENT_PRIMARY": "#fe8019",
        "ACCENT_HOVER": "#fabd2f",
        "ACCENT_INDIGO": "#8ec07c",
        "ACCENT_PURPLE": "#d3869b",
        "COLOR_SUCCESS": "#b8bb26",
        "COLOR_WARNING": "#fabd2f",
        "COLOR_DANGER": "#fb4934",
        "COLOR_DANGER_HOVER": "#cc241d",
        "COLOR_FAVORITE": "#fabd2f",
        "TEXT_PRIMARY": "#ebdbb2",
        "TEXT_SECONDARY": "#d5c4a1",
        "TEXT_MUTED": "#928374",
        "TEXT_ACCENT": "#fe8019",
        "TEXT_ON_ACCENT": "#1d2021",
    },
    # 6. One Dark Pro (Atom / VS Code classic dark)
    "One Dark Pro": {
        "UI_FONT": "Roboto",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Dark",
        "BG_ROOT": "#1e2227",
        "BG_SIDEBAR": "#17191d",
        "BG_CARD": "#282c34",
        "BG_CARD_HOVER": "#323842",
        "BG_INPUT": "#191c20",
        "BG_SUBTLE": "#21252b",
        "BORDER_COLOR": "#3e4451",
        "BORDER_FOCUS": "#61afef",
        "ACCENT_PRIMARY": "#61afef",
        "ACCENT_HOVER": "#528bff",
        "ACCENT_INDIGO": "#528bff",
        "ACCENT_PURPLE": "#c678dd",
        "COLOR_SUCCESS": "#98c379",
        "COLOR_WARNING": "#e5c07b",
        "COLOR_DANGER": "#e06c75",
        "COLOR_DANGER_HOVER": "#be5046",
        "COLOR_FAVORITE": "#e5c07b",
        "TEXT_PRIMARY": "#abb2bf",
        "TEXT_SECONDARY": "#828997",
        "TEXT_MUTED": "#5c6370",
        "TEXT_ACCENT": "#61afef",
        "TEXT_ON_ACCENT": "#1e2227",
    },
    # 7. Solarized Dark (Classic UNIX sysadmin precision)
    "Solarized Dark": {
        "UI_FONT": "Roboto",
        "MONO_FONT": "Inconsolata",
        "mode": "Dark",
        "BG_ROOT": "#002b36",
        "BG_SIDEBAR": "#073642",
        "BG_CARD": "#094250",
        "BG_CARD_HOVER": "#0e4d5c",
        "BG_INPUT": "#002129",
        "BG_SUBTLE": "#0a3c48",
        "BORDER_COLOR": "#586e75",
        "BORDER_FOCUS": "#2aa198",
        "ACCENT_PRIMARY": "#2aa198",
        "ACCENT_HOVER": "#268bd2",
        "ACCENT_INDIGO": "#268bd2",
        "ACCENT_PURPLE": "#6c71c4",
        "COLOR_SUCCESS": "#859900",
        "COLOR_WARNING": "#b58900",
        "COLOR_DANGER": "#dc322f",
        "COLOR_DANGER_HOVER": "#cb4b16",
        "COLOR_FAVORITE": "#b58900",
        "TEXT_PRIMARY": "#93a1a1",
        "TEXT_SECONDARY": "#839496",
        "TEXT_MUTED": "#586e75",
        "TEXT_ACCENT": "#2aa198",
        "TEXT_ON_ACCENT": "#002b36",
    },
    # 8. Nord (Arctic, elegant cold blue-gray)
    "Nord": {
        "UI_FONT": "Inter",
        "MONO_FONT": "JetBrains Mono",
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
        "TEXT_ON_ACCENT": "#242933",
    },
    # 9. Dracula (Vampire high-contrast dark)
    "Dracula": {
        "UI_FONT": "Fira Sans",
        "MONO_FONT": "Fira Code",
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
        "TEXT_ON_ACCENT": "#1e1f29",
    },
    # 10. Console (Matrix phosphor terminal)
    "Console": {
        "UI_FONT": "JetBrains Mono",
        "MONO_FONT": "Inconsolata",
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
        "TEXT_ON_ACCENT": "#050a05",
    },
    # 11. Trendy (Cyber Synthwave)
    "Trendy": {
        "UI_FONT": "Outfit",
        "MONO_FONT": "Fira Code",
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
        "TEXT_ON_ACCENT": "#0f0c1b",
    },
    # 12. Light (Refined minimal daylight)
    "Light": {
        "UI_FONT": "Inter",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Light",
        "BG_ROOT": "#f8fafc",
        "BG_SIDEBAR": "#f1f5f9",
        "BG_CARD": "#ffffff",
        "BG_CARD_HOVER": "#f8fafc",
        "BG_INPUT": "#ffffff",
        "BG_SUBTLE": "#f1f5f9",
        "BORDER_COLOR": "#e2e8f0",
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
        "TEXT_SECONDARY": "#475569",
        "TEXT_MUTED": "#64748b",
        "TEXT_ACCENT": "#0284c7",
        "TEXT_ON_ACCENT": "#ffffff",
    },
    # 13. Catppuccin Latte (Warm soft cream light)
    "Catppuccin Latte": {
        "UI_FONT": "Plus Jakarta Sans",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Light",
        "BG_ROOT": "#eff1f5",
        "BG_SIDEBAR": "#e6e9ef",
        "BG_CARD": "#ffffff",
        "BG_CARD_HOVER": "#f4f5f8",
        "BG_INPUT": "#ffffff",
        "BG_SUBTLE": "#e6e9ef",
        "BORDER_COLOR": "#ccd0da",
        "BORDER_FOCUS": "#1e66f5",
        "ACCENT_PRIMARY": "#1e66f5",
        "ACCENT_HOVER": "#04a5e5",
        "ACCENT_INDIGO": "#7287fd",
        "ACCENT_PURPLE": "#8839ef",
        "COLOR_SUCCESS": "#40a02b",
        "COLOR_WARNING": "#df8e1d",
        "COLOR_DANGER": "#d20f39",
        "COLOR_DANGER_HOVER": "#e64553",
        "COLOR_FAVORITE": "#fe640b",
        "TEXT_PRIMARY": "#4c4f69",
        "TEXT_SECONDARY": "#5c5f77",
        "TEXT_MUTED": "#8c8fa1",
        "TEXT_ACCENT": "#1e66f5",
        "TEXT_ON_ACCENT": "#ffffff",
    },
    # 14. GitHub Dark (Official GitHub developer dark mode)
    "GitHub Dark": {
        "UI_FONT": "Inter",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#0d1117",
        "BG_SIDEBAR": "#010409",
        "BG_CARD": "#161b22",
        "BG_CARD_HOVER": "#21262d",
        "BG_INPUT": "#0d1117",
        "BG_SUBTLE": "#1f242c",
        "BORDER_COLOR": "#30363d",
        "BORDER_FOCUS": "#58a6ff",
        "ACCENT_PRIMARY": "#58a6ff",
        "ACCENT_HOVER": "#79c0ff",
        "ACCENT_INDIGO": "#7ee787",
        "ACCENT_PURPLE": "#d2a8ff",
        "COLOR_SUCCESS": "#3fb950",
        "COLOR_WARNING": "#d29922",
        "COLOR_DANGER": "#f85149",
        "COLOR_DANGER_HOVER": "#da3633",
        "COLOR_FAVORITE": "#e3b341",
        "TEXT_PRIMARY": "#f0f6fc",
        "TEXT_SECONDARY": "#8b949e",
        "TEXT_MUTED": "#6e7681",
        "TEXT_ACCENT": "#58a6ff",
        "TEXT_ON_ACCENT": "#0d1117",
    },
    # 15. Monokai Pro (Sublime Text / Monokai classic perfection)
    "Monokai Pro": {
        "UI_FONT": "Fira Sans",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#222426",
        "BG_SIDEBAR": "#1b1d1e",
        "BG_CARD": "#2d3134",
        "BG_CARD_HOVER": "#373c40",
        "BG_INPUT": "#191a1b",
        "BG_SUBTLE": "#272a2c",
        "BORDER_COLOR": "#40464b",
        "BORDER_FOCUS": "#ffd866",
        "ACCENT_PRIMARY": "#ffd866",
        "ACCENT_HOVER": "#ff6188",
        "ACCENT_INDIGO": "#78dce8",
        "ACCENT_PURPLE": "#ab9df2",
        "COLOR_SUCCESS": "#a9dc76",
        "COLOR_WARNING": "#fc9867",
        "COLOR_DANGER": "#ff6188",
        "COLOR_DANGER_HOVER": "#e0436b",
        "COLOR_FAVORITE": "#ffd866",
        "TEXT_PRIMARY": "#fcfcfa",
        "TEXT_SECONDARY": "#c1c0c0",
        "TEXT_MUTED": "#727072",
        "TEXT_ACCENT": "#ffd866",
        "TEXT_ON_ACCENT": "#222426",
    },
    # 16. Rosé Pine (Minimalist Soho aesthetic pastel theme)
    "Rosé Pine": {
        "UI_FONT": "Plus Jakarta Sans",
        "MONO_FONT": "Inconsolata",
        "mode": "Dark",
        "BG_ROOT": "#191724",
        "BG_SIDEBAR": "#1f1d2e",
        "BG_CARD": "#26233a",
        "BG_CARD_HOVER": "#312f44",
        "BG_INPUT": "#161420",
        "BG_SUBTLE": "#211f30",
        "BORDER_COLOR": "#393552",
        "BORDER_FOCUS": "#ebbcba",
        "ACCENT_PRIMARY": "#ebbcba",
        "ACCENT_HOVER": "#f6c177",
        "ACCENT_INDIGO": "#9ccfd8",
        "ACCENT_PURPLE": "#c4a7e7",
        "COLOR_SUCCESS": "#31748f",
        "COLOR_WARNING": "#f6c177",
        "COLOR_DANGER": "#eb6f92",
        "COLOR_DANGER_HOVER": "#d45075",
        "COLOR_FAVORITE": "#f6c177",
        "TEXT_PRIMARY": "#e0def4",
        "TEXT_SECONDARY": "#908caa",
        "TEXT_MUTED": "#6e6a86",
        "TEXT_ACCENT": "#ebbcba",
        "TEXT_ON_ACCENT": "#191724",
    },
    # 17. Ayu Dark (Deep modern abyss with radiant gold & cyan)
    "Ayu Dark": {
        "UI_FONT": "Outfit",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Dark",
        "BG_ROOT": "#0b0e14",
        "BG_SIDEBAR": "#0f131a",
        "BG_CARD": "#131721",
        "BG_CARD_HOVER": "#1a202c",
        "BG_INPUT": "#080a0f",
        "BG_SUBTLE": "#181d28",
        "BORDER_COLOR": "#242936",
        "BORDER_FOCUS": "#e6b450",
        "ACCENT_PRIMARY": "#e6b450",
        "ACCENT_HOVER": "#ffb454",
        "ACCENT_INDIGO": "#39bae6",
        "ACCENT_PURPLE": "#d2a6ff",
        "COLOR_SUCCESS": "#7fd962",
        "COLOR_WARNING": "#ffb454",
        "COLOR_DANGER": "#f07178",
        "COLOR_DANGER_HOVER": "#d9575e",
        "COLOR_FAVORITE": "#e6b450",
        "TEXT_PRIMARY": "#bfbdb6",
        "TEXT_SECONDARY": "#898e98",
        "TEXT_MUTED": "#565b66",
        "TEXT_ACCENT": "#e6b450",
        "TEXT_ON_ACCENT": "#0b0e14",
    },
    # 18. Kanagawa (Traditional Japanese watercolor & sumi ink)
    "Kanagawa": {
        "UI_FONT": "Plus Jakarta Sans",
        "MONO_FONT": "Inconsolata",
        "mode": "Dark",
        "BG_ROOT": "#1f1f28",
        "BG_SIDEBAR": "#16161d",
        "BG_CARD": "#2a2a37",
        "BG_CARD_HOVER": "#363646",
        "BG_INPUT": "#181820",
        "BG_SUBTLE": "#22222f",
        "BORDER_COLOR": "#49475c",
        "BORDER_FOCUS": "#7e9cd8",
        "ACCENT_PRIMARY": "#7e9cd8",
        "ACCENT_HOVER": "#7fb4ca",
        "ACCENT_INDIGO": "#957fb8",
        "ACCENT_PURPLE": "#bfa3e6",
        "COLOR_SUCCESS": "#76946a",
        "COLOR_WARNING": "#e6c384",
        "COLOR_DANGER": "#c34043",
        "COLOR_DANGER_HOVER": "#e46876",
        "COLOR_FAVORITE": "#e6c384",
        "TEXT_PRIMARY": "#dcd7ba",
        "TEXT_SECONDARY": "#a3a19b",
        "TEXT_MUTED": "#727169",
        "TEXT_ACCENT": "#7e9cd8",
        "TEXT_ON_ACCENT": "#1f1f28",
    },
    # 19. Everforest Dark (Comforting natural sage & forest green)
    "Everforest Dark": {
        "UI_FONT": "Plus Jakarta Sans",
        "MONO_FONT": "JetBrains Mono",
        "mode": "Dark",
        "BG_ROOT": "#2d353b",
        "BG_SIDEBAR": "#272e33",
        "BG_CARD": "#343f44",
        "BG_CARD_HOVER": "#3d484d",
        "BG_INPUT": "#232a2e",
        "BG_SUBTLE": "#2f383e",
        "BORDER_COLOR": "#475258",
        "BORDER_FOCUS": "#a7c080",
        "ACCENT_PRIMARY": "#a7c080",
        "ACCENT_HOVER": "#83c092",
        "ACCENT_INDIGO": "#7fbbb3",
        "ACCENT_PURPLE": "#d699b6",
        "COLOR_SUCCESS": "#a7c080",
        "COLOR_WARNING": "#dbbc7f",
        "COLOR_DANGER": "#e67e80",
        "COLOR_DANGER_HOVER": "#c85f61",
        "COLOR_FAVORITE": "#dbbc7f",
        "TEXT_PRIMARY": "#d3c6aa",
        "TEXT_SECONDARY": "#9da9a0",
        "TEXT_MUTED": "#7a8478",
        "TEXT_ACCENT": "#a7c080",
        "TEXT_ON_ACCENT": "#272e33",
    },
    # 20. Cyberpunk 2077 (High-voltage cyber yellow & laser cyan)
    "Cyberpunk 2077": {
        "UI_FONT": "Rajdhani",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#0b0c10",
        "BG_SIDEBAR": "#12131a",
        "BG_CARD": "#191a24",
        "BG_CARD_HOVER": "#252636",
        "BG_INPUT": "#0d0e14",
        "BG_SUBTLE": "#1d1f2b",
        "BORDER_COLOR": "#2e3146",
        "BORDER_FOCUS": "#fee715",
        "ACCENT_PRIMARY": "#fee715",
        "ACCENT_HOVER": "#00f0ff",
        "ACCENT_INDIGO": "#00e5ff",
        "ACCENT_PURPLE": "#ff007f",
        "COLOR_SUCCESS": "#00ff9f",
        "COLOR_WARNING": "#fee715",
        "COLOR_DANGER": "#ff0055",
        "COLOR_DANGER_HOVER": "#d90048",
        "COLOR_FAVORITE": "#fee715",
        "TEXT_PRIMARY": "#f3f4f6",
        "TEXT_SECONDARY": "#b8bcc9",
        "TEXT_MUTED": "#686c82",
        "TEXT_ACCENT": "#fee715",
        "TEXT_ON_ACCENT": "#0b0c10",
    },
    # 21. Horizon Dark (Warm twilight space dark with sunset peach)
    "Horizon Dark": {
        "UI_FONT": "Outfit",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#1c1e26",
        "BG_SIDEBAR": "#16171d",
        "BG_CARD": "#232530",
        "BG_CARD_HOVER": "#2e303e",
        "BG_INPUT": "#17181f",
        "BG_SUBTLE": "#272a38",
        "BORDER_COLOR": "#3c3e4f",
        "BORDER_FOCUS": "#e95678",
        "ACCENT_PRIMARY": "#e95678",
        "ACCENT_HOVER": "#fab795",
        "ACCENT_INDIGO": "#26bbd9",
        "ACCENT_PURPLE": "#b877db",
        "COLOR_SUCCESS": "#29d398",
        "COLOR_WARNING": "#fab795",
        "COLOR_DANGER": "#e95678",
        "COLOR_DANGER_HOVER": "#cf3a5d",
        "COLOR_FAVORITE": "#fac29a",
        "TEXT_PRIMARY": "#d5d8da",
        "TEXT_SECONDARY": "#9da1a8",
        "TEXT_MUTED": "#6c6f93",
        "TEXT_ACCENT": "#e95678",
        "TEXT_ON_ACCENT": "#1c1e26",
    },
    # 22. Cobalt2 (Royal navy blue with electric yellow)
    "Cobalt2": {
        "UI_FONT": "Space Grotesk",
        "MONO_FONT": "Fira Code",
        "mode": "Dark",
        "BG_ROOT": "#15232d",
        "BG_SIDEBAR": "#121b24",
        "BG_CARD": "#193549",
        "BG_CARD_HOVER": "#1f425c",
        "BG_INPUT": "#0e1a24",
        "BG_SUBTLE": "#173042",
        "BORDER_COLOR": "#264f6d",
        "BORDER_FOCUS": "#ffc600",
        "ACCENT_PRIMARY": "#ffc600",
        "ACCENT_HOVER": "#0088ff",
        "ACCENT_INDIGO": "#0088ff",
        "ACCENT_PURPLE": "#ff9d00",
        "COLOR_SUCCESS": "#3ad900",
        "COLOR_WARNING": "#ffc600",
        "COLOR_DANGER": "#ff0033",
        "COLOR_DANGER_HOVER": "#cc0029",
        "COLOR_FAVORITE": "#ffc600",
        "TEXT_PRIMARY": "#ffffff",
        "TEXT_SECONDARY": "#9eb3c2",
        "TEXT_MUTED": "#5b778c",
        "TEXT_ACCENT": "#ffc600",
        "TEXT_ON_ACCENT": "#15232d",
    },
    # 23. Solarized Light (Precision daytime sysadmin palette)
    "Solarized Light": {
        "UI_FONT": "Roboto",
        "MONO_FONT": "Inconsolata",
        "mode": "Light",
        "BG_ROOT": "#fdf6e3",
        "BG_SIDEBAR": "#eee8d5",
        "BG_CARD": "#ffffff",
        "BG_CARD_HOVER": "#f5efdc",
        "BG_INPUT": "#fcf5e0",
        "BG_SUBTLE": "#eee8d5",
        "BORDER_COLOR": "#d3cbb7",
        "BORDER_FOCUS": "#268bd2",
        "ACCENT_PRIMARY": "#268bd2",
        "ACCENT_HOVER": "#2aa198",
        "ACCENT_INDIGO": "#6c71c4",
        "ACCENT_PURPLE": "#d33682",
        "COLOR_SUCCESS": "#859900",
        "COLOR_WARNING": "#b58900",
        "COLOR_DANGER": "#dc322f",
        "COLOR_DANGER_HOVER": "#cb4b16",
        "COLOR_FAVORITE": "#b58900",
        "TEXT_PRIMARY": "#073642",
        "TEXT_SECONDARY": "#586e75",
        "TEXT_MUTED": "#93a1a1",
        "TEXT_ACCENT": "#268bd2",
        "TEXT_ON_ACCENT": "#ffffff",
    },
    # 24. GitHub Light (Clean, crisp official GitHub daylight)
    "GitHub Light": {
        "UI_FONT": "Inter",
        "MONO_FONT": "Fira Code",
        "mode": "Light",
        "BG_ROOT": "#f6f8fa",
        "BG_SIDEBAR": "#eaeef2",
        "BG_CARD": "#ffffff",
        "BG_CARD_HOVER": "#f3f4f6",
        "BG_INPUT": "#ffffff",
        "BG_SUBTLE": "#eaeef2",
        "BORDER_COLOR": "#d0d7de",
        "BORDER_FOCUS": "#0969da",
        "ACCENT_PRIMARY": "#0969da",
        "ACCENT_HOVER": "#218bff",
        "ACCENT_INDIGO": "#6639ba",
        "ACCENT_PURPLE": "#8250df",
        "COLOR_SUCCESS": "#1a7f37",
        "COLOR_WARNING": "#9a6700",
        "COLOR_DANGER": "#cf222e",
        "COLOR_DANGER_HOVER": "#a40e26",
        "COLOR_FAVORITE": "#9a6700",
        "TEXT_PRIMARY": "#1f2328",
        "TEXT_SECONDARY": "#57606a",
        "TEXT_MUTED": "#8c959f",
        "TEXT_ACCENT": "#0969da",
        "TEXT_ON_ACCENT": "#ffffff",
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
TEXT_ON_ACCENT = THEME_PALETTES["Dark"].get("TEXT_ON_ACCENT", "#09090b")

ACCENT_EMERALD = "#10b981"

TYPE_COLORS = {
    "server": {"bg": "#18181b", "text": "#38bdf8", "border": "#27272a"},
    "service": {"bg": "#18181b", "text": "#f59e0b", "border": "#27272a"},
    "domain": {"bg": "#18181b", "text": "#10b981", "border": "#27272a"},
    "apikey": {"bg": "#18181b", "text": "#818cf8", "border": "#27272a"},
    "keypair": {"bg": "#18181b", "text": "#c084fc", "border": "#27272a"},
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
    TEXT_ON_ACCENT = palette.get("TEXT_ON_ACCENT", "#09090b" if palette.get("mode") == "Dark" else "#ffffff")

    # Propagate updated tokens into all loaded StarVault module namespaces
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

    # Apply signature font pair for the theme unless user has locked a custom font override
    user_override = False
    try:
        from starvault.app_config import AppConfigManager
        cfg = AppConfigManager()
        user_override = bool(cfg.data.get("user_has_custom_font", False))
    except Exception:
        pass

    if not user_override:
        sig_ui = palette.get("UI_FONT", "Inter")
        sig_mono = palette.get("MONO_FONT", "JetBrains Mono")
        set_ui_font_family(sig_ui, save_to_config=False, is_user_override=False)
        set_mono_font_family(sig_mono, save_to_config=False, is_user_override=False)

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
