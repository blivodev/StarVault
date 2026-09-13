"""System tray integration using pystray for StarVault."""

import threading
from typing import Callable, Optional
from PIL import Image
import pystray
from pystray import Menu, MenuItem

from starvault.ui.icons import generate_vault_icon_image


class SystemTrayManager:
    """Manages the OS system tray icon and background event loop."""

    def __init__(
        self,
        on_open_hud: Callable[[], None],
        on_open_main: Callable[[], None],
        on_lock: Callable[[], None],
        on_open_keys: Callable[[], None],
        on_exit: Callable[[], None],
    ) -> None:
        self.on_open_hud = on_open_hud
        self.on_open_main = on_open_main
        self.on_lock = on_lock
        self.on_open_keys = on_open_keys
        self.on_exit = on_exit

        self._icon: Optional[pystray.Icon] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Starts system tray icon in a daemon thread."""
        image = generate_vault_icon_image(64)

        menu = Menu(
            MenuItem("🖥️ Open StarVault", lambda: self.on_open_main(), default=True),
            MenuItem("⚡ Quick HUD (Search)", lambda: self.on_open_hud()),
            MenuItem("🔑 Key Studio...", lambda: self.on_open_keys()),
            Menu.SEPARATOR,
            MenuItem("🔒 Lock Vault", lambda: self.on_lock()),
            Menu.SEPARATOR,
            MenuItem("✖️ Exit", lambda: self.on_exit()),
        )

        self._icon = pystray.Icon(
            name="StarVault",
            icon=image,
            title="StarVault - Credential & Key Vault",
            menu=menu,
        )

        self._thread = threading.Thread(target=self._icon.run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stops the system tray icon."""
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
