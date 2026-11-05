"""Builds the emoji -> Lucide icon-name mapping and applies it across the UI.

Emoji render from vendor fonts (Segoe UI Emoji / Noto Color Emoji), which are
not openly licensed for redistribution. Lucide is ISC. This replaces every
pictographic emoji with a Lucide glyph (font-linked inside Inter labels).

Run from the repo root:
    .venv/Scripts/python.exe tools/branding/replace_emoji.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CODES = REPO / "starvault" / "resources" / "brand" / "lucide_codepoints.json"

# emoji -> Lucide slug
EMOJI_MAP = {
    "⚡": "zap",
    "💾": "save",
    "📋": "clipboard",
    "📁": "folder",
    "📂": "folder-open",
    "📥": "download",
    "📤": "upload",
    "🔑": "key",
    "🗝": "key-round",
    "🔐": "lock-keyhole",
    "🔒": "lock",
    "🔓": "lock-open",
    "🔄": "refresh-cw",
    "💻": "laptop",
    "🖥": "monitor",
    "📄": "file-text",
    "📜": "scroll-text",
    "👁": "eye",
    "✍": "pen-line",
    "⚠": "triangle-alert",
    "🛡": "shield",
    "🚀": "rocket",
    "🗑": "trash-2",
    "🧹": "eraser",
    "🗂": "folder-tree",
    "🩺": "stethoscope",
    "✅": "circle-check",
    "❌": "circle-x",
    "🔗": "link",
    "📱": "smartphone",
    "🕒": "clock",
    "🧠": "brain",
    "🟢": "circle",
    "🟡": "circle",
    "🔴": "circle",
    "⏳": "hourglass",
    "⭐": "star",
    "🎉": "party-popper",
    "💡": "lightbulb",
    "🪟": "app-window",
    "🐧": "terminal",
    "⚪": "circle",
    "✨": "sparkles",
    "☁": "cloud",
    "📊": "chart-column",
    "⬇": "arrow-down",
    "📷": "camera",
    "🗄": "database",
    "🛠": "wrench",
    "⚙": "settings",
    "⏱": "timer",
    "🔍": "search",
    "🌐": "globe",
    "📦": "package",
    # Typographic dingbats that are UI affordances rather than text
    "✓": "check",
    "✔": "check",
    "✗": "x",
    "✘": "x",
    "✕": "x",
    "✖": "x",
    "★": "star",
    "☆": "star",
    "▲": "chevron-up",
    "▼": "chevron-down",
    "◀": "chevron-left",
    "▶": "chevron-right",
    "◈": "shield",
    "➔": "arrow-right",
    "⬆": "arrow-up",
    "⬅": "arrow-left",
    "➡": "arrow-right",
    "🔖": "bookmark",
    "📌": "pin",
    "🏷": "tag",
    "📝": "notebook-pen",
    "🔧": "wrench",
    "ℹ": "info",
    "❓": "circle-help",
    "❗": "circle-alert",
    "☑": "square-check",
    "☁": "cloud",
}

# Glyphs that are plain typography (present in Inter/DejaVu, openly licensed)
# and should be left alone. Arrows inside sort labels ("A -> Z") are text, not
# affordances, and are used as dictionary keys — replacing them adds risk for
# no visual gain.
KEEP = set("•—–→←↔…·▲▼")


def build_replacements(codes: dict) -> dict:
    out = {}
    missing = []
    for emoji, slug in EMOJI_MAP.items():
        cp = codes.get(slug)
        if cp:
            out[emoji] = chr(cp)
        else:
            missing.append((emoji, slug))
    return out, missing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    codes = json.loads(CODES.read_text(encoding="utf-8"))
    repl, missing = build_replacements(codes)
    if missing:
        print("!! missing Lucide slugs:", missing, file=sys.stderr)

    # Python UI only: the desktop app registers the Lucide font, so PUA glyphs
    # render inline. The browser extension has no such font — it uses inline
    # SVG instead (see extension/popup.html), so it is deliberately excluded.
    targets = sorted((REPO / "starvault" / "ui").rglob("*.py"))
    targets += [REPO / "starvault" / "ui" / "tk_cards.py"]

    emoji_re = re.compile(
        "[\U0001F000-\U0001FAFF"
        "\u2190-\u21FF"     # arrows
        "\u2300-\u23FF"     # technical (hourglass, timer)
        "\u25A0-\u25FF"     # geometric shapes (chevrons, squares)
        "\u2600-\u27BF"     # misc symbols + dingbats
        "\u2B00-\u2BFF"     # extra arrows/stars
        "\uFE0F\u20E3"      # variation selectors
        "]"
    )
    total = 0
    changed_files = []
    for p in targets:
        txt = p.read_text(encoding="utf-8")
        orig = txt
        # Strip variation selectors / keycap combiners first.
        txt = txt.replace("\ufe0f", "").replace("\u20e3", "")

        def sub(m):
            ch = m.group(0)
            if ch in KEEP:
                return ch
            if ch in repl:
                g = repl[ch]
                # Emit a \uXXXX escape rather than a raw Private-Use-Area byte:
                # the source stays plain ASCII-safe and readable in diffs, and
                # the character is identical at runtime.
                return f"\\u{ord(g):04x}"
            return ch

        txt = emoji_re.sub(sub, txt)
        if txt != orig:
            n = sum(1 for a, b in zip(orig, txt) if a != b)
            total += 1
            changed_files.append((str(p.relative_to(REPO)), n))
            if not args.dry_run:
                p.write_text(txt, encoding="utf-8")

    verb = "would change" if args.dry_run else "changed"
    print(f"{verb} {len(changed_files)} files")
    for f, n in changed_files:
        print(f"  {f}")

    # Report leftovers
    leftovers = {}
    for p in targets:
        txt = p.read_text(encoding="utf-8")
        found = emoji_re.findall(txt)
        found = [c for c in found if c not in KEEP]
        if found:
            leftovers[str(p.relative_to(REPO))] = found
    if leftovers:
        print("\nRemaining (unmapped) pictographs:")
        for f, chars in leftovers.items():
            print(f"  {f}: {''.join(sorted(set(chars)))}")
    else:
        print("\nNo unmapped pictographs remain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
