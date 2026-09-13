"""Color tokens, theme styling, and typography for StarVault."""

import customtkinter as ctk

# Application Color Palette (Obsidian & Deep Slate with Electric Cyan & Indigo accents)
BG_ROOT = "#090d16"         # Deepest background
BG_SIDEBAR = "#0e1422"      # Sidebar container
BG_CARD = "#141c2e"         # Card background
BG_CARD_HOVER = "#1a253c"   # Card hover state
BG_INPUT = "#0c1322"        # Form input fields
BG_SUBTLE = "#192238"       # Subtle containers & borders

BORDER_COLOR = "#23304c"    # Card & container borders
BORDER_FOCUS = "#38bdf8"    # Focus state border

# Accent colors
ACCENT_PRIMARY = "#38bdf8"  # Electric Cyan
ACCENT_HOVER = "#0ea5e9"    # Hover cyan
ACCENT_INDIGO = "#6366f1"   # Indigo
ACCENT_PURPLE = "#8b5cf6"   # Purple for Keys

# Functional / Status colors
COLOR_SUCCESS = "#10b981"   # Emerald
COLOR_WARNING = "#f59e0b"   # Amber
COLOR_DANGER = "#ef4444"    # Rose / Red
COLOR_DANGER_HOVER = "#dc2626"
COLOR_FAVORITE = "#fbbf24"  # Star Gold

# Typography colors
TEXT_PRIMARY = "#f8fafc"    # Bright text
TEXT_SECONDARY = "#94a3b8"  # Slate 400
TEXT_MUTED = "#64748b"      # Slate 500
TEXT_ACCENT = "#38bdf8"

# Badge colors per entry type
TYPE_COLORS = {
    "server": {"bg": "#1e293b", "text": "#38bdf8", "border": "#38bdf8"},
    "service": {"bg": "#1e293b", "text": "#f59e0b", "border": "#f59e0b"},
    "keypair": {"bg": "#1e293b", "text": "#a855f7", "border": "#a855f7"},
}


def apply_global_theme():
    """Initializes CustomTkinter global theme settings."""
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")


def get_font(size: int = 13, weight: str = "normal") -> ctk.CTkFont:
    """Returns application UI font."""
    return ctk.CTkFont(family="Segoe UI", size=size, weight=weight)


def get_mono_font(size: int = 12, weight: str = "normal") -> ctk.CTkFont:
    """Returns monospace font for credentials, code, and keys."""
    return ctk.CTkFont(family="Consolas", size=size, weight=weight)
