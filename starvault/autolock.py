"""Inactivity tracker and auto-lock manager for StarVault."""

import time
from typing import Callable, Optional


class AutoLockManager:
    """Monitors inactivity and triggers vault lock on idle timeout or minimize."""

    def __init__(
        self,
        timeout_seconds: int = 300,  # 5 minutes
        lock_on_minimize: bool = True,
        on_lock_trigger: Optional[Callable[[], None]] = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.lock_on_minimize = lock_on_minimize
        self.on_lock_trigger = on_lock_trigger
        self.last_activity = time.time()
        self.is_enabled = True

    def record_activity(self) -> None:
        """Resets the inactivity timer to current timestamp."""
        self.last_activity = time.time()

    def get_remaining_seconds(self) -> int:
        """Returns remaining seconds before auto-lock fires (or -1 if disabled)."""
        if self.timeout_seconds <= 0 or not self.is_enabled:
            return -1
        elapsed = time.time() - self.last_activity
        remaining = int(self.timeout_seconds - elapsed)
        return max(0, remaining)

    def check_inactivity(self) -> bool:
        """Checks if idle timeout exceeded. If so, triggers lock callback.

        Returns:
            True if locked, False otherwise.
        """
        if self.timeout_seconds <= 0 or not self.is_enabled:
            return False

        if time.time() - self.last_activity >= self.timeout_seconds:
            self.trigger_lock(reason="idle_timeout")
            return True
        return False

    def on_minimized(self) -> None:
        """Called when window is minimized to system tray."""
        if self.lock_on_minimize and self.is_enabled:
            self.trigger_lock(reason="minimized")

    def trigger_lock(self, reason: str = "manual") -> None:
        """Executes the lock callback if registered."""
        if self.on_lock_trigger:
            self.on_lock_trigger()
