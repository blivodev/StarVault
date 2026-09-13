"""Clipboard manager with automatic wipe for sensitive credentials."""

import threading
import time
from typing import Callable, Optional
import pyperclip


class ClipboardManager:
    """Handles secure copying with countdown and automatic wipe for sensitive credentials."""

    def __init__(self, default_timeout_sec: int = 30) -> None:
        self.default_timeout_sec = default_timeout_sec
        self._last_copied_text: Optional[str] = None
        self._wipe_timer: Optional[threading.Timer] = None
        self._countdown_thread: Optional[threading.Thread] = None
        self._stop_countdown = threading.Event()
        self._on_status_change: Optional[Callable[[str, int], None]] = None

    def set_status_callback(self, callback: Optional[Callable[[str, int], None]]) -> None:
        """Sets a callback function (label: str, seconds_left: int) for UI updates."""
        self._on_status_change = callback

    def copy(
        self,
        text: str,
        label: str = "Copied",
        is_sensitive: bool = False,
        timeout_sec: Optional[int] = None,
    ) -> None:
        """Copies text to clipboard and starts auto-wipe timer if sensitive."""
        if not text:
            return

        # Cancel any active countdown
        self.cancel_timer()

        try:
            pyperclip.copy(text)
        except Exception:
            pass

        self._last_copied_text = text
        effective_timeout = timeout_sec if timeout_sec is not None else self.default_timeout_sec

        if is_sensitive and effective_timeout > 0:
            self._start_countdown(text, label, effective_timeout)
        else:
            if self._on_status_change:
                self._on_status_change(f"✓ {label}", 0)

    def _start_countdown(self, copied_text: str, label: str, duration: int) -> None:
        """Spawns background thread to update countdown and wipe clipboard upon expiry."""
        self._stop_countdown.clear()

        def countdown_worker():
            remaining = duration
            while remaining > 0 and not self._stop_countdown.is_set():
                if self._on_status_change:
                    self._on_status_change(f"✓ {label} (clears in {remaining}s)", remaining)
                time.sleep(1)
                remaining -= 1

            if not self._stop_countdown.is_set():
                # Verify clipboard still contains the exact secret before clearing
                try:
                    current_clip = pyperclip.paste()
                    if current_clip == copied_text:
                        pyperclip.copy("")
                        if self._on_status_change:
                            self._on_status_change("🔒 Clipboard auto-cleared", 0)
                except Exception:
                    pass

        self._countdown_thread = threading.Thread(target=countdown_worker, daemon=True)
        self._countdown_thread.start()

    def cancel_timer(self) -> None:
        """Stops active countdown without clearing clipboard."""
        self._stop_countdown.set()
        if self._countdown_thread and self._countdown_thread.is_alive():
            self._countdown_thread.join(timeout=0.2)

    def clear_now(self) -> None:
        """Immediately wipes clipboard and cancels timer."""
        self.cancel_timer()
        try:
            pyperclip.copy("")
        except Exception:
            pass
        if self._on_status_change:
            self._on_status_change("Clipboard cleared", 0)
