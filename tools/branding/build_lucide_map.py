"""Builds `starvault/resources/brand/lucide_codepoints.json` from the Lucide CSS.

Lucide is licensed ISC (https://lucide.dev/license) — permissive for commercial
use, modification and redistribution. The upstream `lucide.css` (which declares
the `lucide` @font-face and one `.icon-<slug>:before` rule per glyph) lives
beside this script; the shipped font is `starvault/resources/fonts/Lucide.ttf`.

Run from the repo root (or anywhere — paths resolve from __file__):
    .venv/Scripts/python.exe tools/branding/build_lucide_map.py

The generated JSON is the single source of truth for `ui/icons_font.py`, so a
Lucide version bump is: replace the CSS + TTF, re-run this script.
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CSS = Path(__file__).resolve().parent / "lucide.css"
OUT = REPO / "starvault" / "resources" / "brand" / "lucide_codepoints.json"
FONT = REPO / "starvault" / "resources" / "fonts" / "Lucide.ttf"

# Slugs the app relies on. Listed so a Lucide bump that renames one fails loudly
# here instead of silently rendering nothing at runtime.
REQUIRED = [
    "copy", "eye", "eye-off", "pencil", "trash-2", "plus", "x", "check",
    "search", "refresh-cw", "star", "star-off", "lock", "lock-open",
    "lock-keyhole", "settings", "server", "database", "globe", "key",
    "key-round", "shield", "shield-check", "fingerprint", "user", "users",
    "tags", "file-key", "activity", "zap", "terminal", "chevron-down",
    "chevron-up", "chevron-left", "chevron-right", "filter", "download",
    "upload", "minus", "square", "layout-grid", "folder-tree", "folder-lock",
    "smartphone", "package", "wand-sparkles", "monitor-down", "palette",
    "clipboard", "save", "folder", "folder-open", "link", "arrow-up-right",
    "circle-check", "circle-x", "triangle-alert", "laptop", "wrench",
]


def main() -> int:
    if not CSS.exists():
        print(f"!! missing upstream CSS: {CSS}")
        return 1

    css = CSS.read_text(encoding="utf-8")
    pat = re.compile(r'\.icon-([a-z0-9-]+):before\s*\{\s*content:\s*"\\([0-9a-f]+)"')
    cp = {m.group(1): int(m.group(2), 16) for m in pat.finditer(css)}
    print("total lucide icons:", len(cp))

    if not cp:
        print("!! parsed zero icons — the CSS format changed; not writing output")
        return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(cp, indent=0, sort_keys=True), encoding="utf-8")
    print("written:", OUT.relative_to(REPO), OUT.stat().st_size, "bytes")

    if FONT.exists():
        print("font:", FONT.relative_to(REPO), FONT.stat().st_size, "bytes")
    else:
        print(f"!! font missing: {FONT}")

    missing = [n for n in REQUIRED if n not in cp]
    for name in REQUIRED:
        print(f"  {name}: {'OK U+%04X' % cp[name] if name in cp else 'MISSING'}")
    if missing:
        print(f"\n!! {len(missing)} required slugs missing: {missing}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
