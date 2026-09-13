"""Windows OS Startup registration utility for StarVault.

Enables or disables launching StarVault automatically upon Windows user logon
via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.
"""

from pathlib import Path
import sys
from typing import Optional


REG_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "StarVault"


def _get_launch_command() -> str:
    """Returns the executable command line string for launching StarVault minimized to tray."""
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        local_db = (exe_path.parent / "starvault.db").resolve()
        if local_db.exists():
            return f'"{exe_path}" --portable --minimized'
        return f'"{exe_path}" --minimized'
    else:
        python_exe = Path(sys.executable).resolve()
        run_py = Path(__file__).resolve().parent.parent / "run.py"
        return f'"{python_exe}" "{run_py}" --minimized'


def is_startup_enabled() -> bool:
    """Checks whether StarVault is registered in Windows Startup registry."""
    if sys.platform != "win32":
        return False

    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY_PATH, 0, winreg.KEY_READ) as key:
            try:
                val, _ = winreg.QueryValueEx(key, APP_REG_NAME)
                return bool(val)
            except FileNotFoundError:
                return False
    except Exception:
        return False


def set_startup_enabled(enabled: bool) -> bool:
    """Registers or unregisters StarVault from Windows Startup.

    Returns:
        True if the operation succeeded, False otherwise.
    """
    if sys.platform != "win32":
        return False

    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                cmd = _get_launch_command()
                winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, APP_REG_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False
