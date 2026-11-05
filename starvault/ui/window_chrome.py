"""Frameless window chrome for StarVault.

Removes the native Windows title bar and provides an in-app title strip with
drag-to-move, edge/corner resize, and icon window controls (minimise to tray,
maximise/restore, close to tray). The native bar is replaced, not just hidden,
so the app reads as one coherent surface.

Windows specifics handled here:
- `overrideredirect(True)` removes the native title bar AND the taskbar entry,
  so minimising routes to the system tray (which StarVault already has).
- `iconify()` is unreliable under overrideredirect, hence withdraw-to-tray.
- A 6px invisible resize border is re-created with `<Configure>` because Tk
  does not provide native resize grips on a borderless window.
"""

from __future__ import annotations

import sys
import tkinter as tk
from typing import Callable, Optional

import customtkinter as ctk

from starvault.ui.icons_font import icon, icon_font
from starvault.ui.theme import (
    ACCENT_PRIMARY,
    BG_CARD,
    BG_INPUT,
    BG_ROOT,
    BORDER_COLOR,
    COLOR_DANGER,
    TEXT_MUTED,
    TEXT_PRIMARY,
    get_font,
)

RESIZE_BORDER = 5


class WindowChrome:
    """Attaches frameless behaviour to a CTk root window."""

    def __init__(
        self,
        root: ctk.CTk,
        *,
        on_minimize: Optional[Callable[[], None]] = None,
        on_close: Optional[Callable[[], None]] = None,
    ) -> None:
        self.root = root
        self.on_minimize = on_minimize
        self.on_close = on_close
        self._drag_x = 0
        self._drag_y = 0
        self._resize_edge = ""
        self._resize_start = (0, 0, 0, 0)
        self._maximized = False
        self._restore_geometry = ""

    # -- public API --------------------------------------------------------
    def enable(self) -> None:
        """Makes the window borderless (best-effort; safe if unsupported)."""
        try:
            self.root.overrideredirect(True)
            self._enabled = True
        except Exception:
            self._enabled = False
        # Keep the window above the taskbar-less layer and focused.
        try:
            self.root.lift()
        except Exception:
            pass

    def bind_drag_region(self, widget: tk.Misc) -> None:
        """Makes `widget` a drag handle for the whole window."""
        widget.bind("<Button-1>", self._start_drag, add="+")
        widget.bind("<B1-Motion>", self._do_drag, add="+")
        widget.bind("<Double-Button-1>", lambda e: self.toggle_maximize(), add="+")

    def bind_resize_region(self, widget: tk.Misc) -> None:
        """Adds edge/corner resize handling over `widget`."""
        widget.bind("<Motion>", self._on_motion, add="+")
        widget.bind("<Button-1>", self._on_press, add="+")
        widget.bind("<B1-Motion>", self._on_resize_motion, add="+")

    # -- window controls ---------------------------------------------------
    def minimize(self) -> None:
        if self.on_minimize:
            self.on_minimize()
        else:
            self.root.withdraw()

    def toggle_maximize(self) -> None:
        try:
            if self._maximized:
                if self._restore_geometry:
                    self.root.geometry(self._restore_geometry)
                self._maximized = False
            else:
                self._restore_geometry = self.root.geometry()
                sw = self.root.winfo_screenwidth()
                sh = self.root.winfo_screenheight()
                self.root.geometry(f"{sw}x{sh}+0+0")
                self._maximized = True
        except Exception:
            pass

    def close(self) -> None:
        if self.on_close:
            self.on_close()
        else:
            self.root.destroy()

    # -- drag --------------------------------------------------------------
    def _start_drag(self, event) -> None:
        self._drag_x = event.x_root - self.root.winfo_x()
        self._drag_y = event.y_root - self.root.winfo_y()

    def _do_drag(self, event) -> None:
        if self._maximized:
            return
        try:
            x = event.x_root - self._drag_x
            y = event.y_root - self._drag_y
            self.root.geometry(f"+{x}+{y}")
        except Exception:
            pass

    # -- resize ------------------------------------------------------------
    def _edge_at(self, x: int, y: int) -> str:
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        edge = ""
        if x <= RESIZE_BORDER:
            edge += "w"
        elif x >= w - RESIZE_BORDER:
            edge += "e"
        if y <= RESIZE_BORDER:
            edge += "n"
        elif y >= h - RESIZE_BORDER:
            edge += "s"
        return edge

    def _on_motion(self, event) -> None:
        edge = self._edge_at(event.x, event.y)
        cursors = {
            "n": "sb_v_double_arrow", "s": "sb_v_double_arrow",
            "e": "sb_h_double_arrow", "w": "sb_h_double_arrow",
            "ne": "size_ne_sw", "sw": "size_ne_sw",
            "nw": "size_nw_se", "se": "size_nw_se",
        }
        try:
            self.root.configure(cursor=cursors.get(edge, ""))
        except Exception:
            pass

    def _on_press(self, event) -> None:
        self._resize_edge = self._edge_at(event.x, event.y)
        if self._resize_edge:
            self._resize_start = (
                event.x_root, event.y_root,
                self.root.winfo_width(), self.root.winfo_height(),
                self.root.winfo_x(), self.root.winfo_y(),
            )

    def _on_resize_motion(self, event) -> None:
        if not self._resize_edge or self._maximized:
            return
        sx, sy, sw, sh, wx, wy = self._resize_start
        dx = event.x_root - sx
        dy = event.y_root - sy
        min_w, min_h = 980, 680
        x, y, w, h = wx, wy, sw, sh
        if "e" in self._resize_edge:
            w = max(min_w, sw + dx)
        if "s" in self._resize_edge:
            h = max(min_h, sh + dy)
        if "w" in self._resize_edge:
            w = max(min_w, sw - dx)
            x = wx + (sw - w)
        if "n" in self._resize_edge:
            h = max(min_h, sh - dy)
            y = wy + (sh - h)
        try:
            self.root.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass


def build_title_bar(
    parent,
    *,
    title_text: str,
    chrome: WindowChrome,
    mark_image=None,
) -> ctk.CTkFrame:
    """Builds the in-app title strip with brand mark and window controls."""
    bar = ctk.CTkFrame(parent, fg_color=BG_CARD, height=44, corner_radius=0,
                       border_width=1, border_color=BORDER_COLOR)
    bar.pack(fill="x")

    # Brand mark (image if supplied, else the icon glyph)
    left = ctk.CTkFrame(bar, fg_color="transparent")
    left.pack(side="left", padx=(12, 0), pady=6)
    if mark_image is not None:
        lbl = ctk.CTkLabel(left, text="", image=mark_image)
        lbl.pack(side="left")
    else:
        ctk.CTkLabel(left, text=icon("shield-check"), font=icon_font(18),
                     text_color=ACCENT_PRIMARY).pack(side="left")

    ctk.CTkLabel(left, text=title_text, font=get_font(13, "bold"),
                 text_color=TEXT_PRIMARY).pack(side="left", padx=(8, 0))

    # Window controls (icons)
    controls = ctk.CTkFrame(bar, fg_color="transparent")
    controls.pack(side="right", padx=(0, 8), pady=6)

    def cbtn(glyph, command, hover=BORDER_COLOR, fg=TEXT_MUTED):
        b = ctk.CTkButton(
            controls, text=glyph, width=32, height=28, corner_radius=6,
            font=icon_font(14), fg_color="transparent", hover_color=hover,
            text_color=fg, command=command,
        )
        b.pack(side="left", padx=2)
        return b

    cbtn(icon("minus"), chrome.minimize)
    cbtn(icon("square"), chrome.toggle_maximize)
    cbtn(icon("x"), chrome.close, hover=COLOR_DANGER, fg=COLOR_DANGER)

    chrome.bind_drag_region(bar)
    return bar
