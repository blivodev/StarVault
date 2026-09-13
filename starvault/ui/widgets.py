"""Reusable custom widgets and UI helpers for StarVault."""

from typing import Callable, Optional
import customtkinter as ctk

from starvault.ui.theme import (
    ACCENT_PRIMARY,
    BG_INPUT,
    BORDER_COLOR,
    TEXT_SECONDARY,
    get_font,
)


def add_password_toggle(
    parent_frame: ctk.CTkFrame,
    entry_widget: ctk.CTkEntry,
    width: int = 36,
    height: int = 36,
    mask_char: str = "•",
    side: str = "right",
    padx: tuple = (4, 0),
) -> ctk.CTkButton:
    """Attaches an interactive Show/Hide password toggle button (👁 / 🔒) to an entry widget."""
    is_revealed = [False]

    def _toggle():
        is_revealed[0] = not is_revealed[0]
        if is_revealed[0]:
            entry_widget.configure(show="")
            btn.configure(text="🔒", text_color=ACCENT_PRIMARY)
        else:
            entry_widget.configure(show=mask_char)
            btn.configure(text="👁", text_color=TEXT_SECONDARY)

    btn = ctk.CTkButton(
        parent_frame,
        text="👁",
        width=width,
        height=height,
        fg_color=BG_INPUT,
        hover_color=BORDER_COLOR,
        text_color=TEXT_SECONDARY,
        font=get_font(12),
        command=_toggle,
    )
    btn.pack(side=side, padx=padx)
    return btn
