# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all

datas = [('starvault/resources', 'starvault/resources')]
binaries = []
hiddenimports = [
    "PIL",
    "PIL._tkinter_finder",
    "pystray",
    "cv2",
    "qrcode",
    "pyperclip",
    "cryptography",
    "argon2",
    "pgpy",
    "paramiko",
    "rapidfuzz",
    "keyring",
    "keyring.backends",
    "keyring.backends.Windows",
    "pyzipper",
    "py7zr",
    "starvault.neural_health",
    "starvault.versioning",
    "starvault.ui.version_history_dialog",
    "starvault.export_package",
    "starvault.ui.vault_export_dialog",
    "starvault.ui.vault_import_dialog",
]

for pkg in ["customtkinter", "pystray", "pgpy", "keyring", "pyzipper", "py7zr"]:
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="StarVault",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No command line window pops up
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="starvault.ico",
)
