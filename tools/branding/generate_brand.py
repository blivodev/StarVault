"""StarVault brand-mark generator.

ONE geometry -> every shipped asset, so the app icon, the title-bar icon, the
in-app logo and the browser-extension icons can never drift apart.

Run:  python tools/branding/generate_brand.py
Outputs:
  starvault.ico                          (multi-size Windows app icon)
  starvault.png                          (512px master, repo root)
  starvault/resources/brand/mark.png     (256px transparent-bg mark)
  extension/icons/icon16.png             (browser toolbar)
  extension/icons/icon48.png
  extension/icons/icon128.png

Licence: all geometry is generated here from primitives; no third-party art.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

# ---------------------------------------------------------------------------
# Palette (matches the app's default "Dark" theme)
# ---------------------------------------------------------------------------
TILE_BG = (15, 23, 42, 255)       # #0f172a  deep navy
TILE_BG2 = (30, 41, 59, 255)      # #1e293b  slightly lighter (shield fill)
ACCENT = (56, 189, 248, 255)      # #38bdf8  sky blue
ACCENT_DIM = (14, 165, 233, 255)  # #0ea5e9
TRANSPARENT = (0, 0, 0, 0)

# Grid is 1024x1024; every shape is expressed as a fraction of `s` so the same
# code renders the .ico, the PNGs and the 16px favicon.
GRID = 1024.0


def _shield_points(s: float) -> list[tuple[float, float]]:
    """Classic crest/shield outline, centred, as a polygon on the grid."""
    u = s / GRID
    return [
        (300 * u, 300 * u),
        (724 * u, 300 * u),
        (724 * u, 540 * u),
        (512 * u, 792 * u),
        (300 * u, 540 * u),
    ]


def _star_points(s: float, cx: float, cy: float, r_out: float, r_in: float, points: int = 4) -> list[tuple[float, float]]:
    """A `points`-pointed sparkle star (4 = the classic 'star' sparkle)."""
    pts: list[tuple[float, float]] = []
    n = points * 2
    for i in range(n):
        angle = (math.pi / points) * i - math.pi / 2
        r = r_out if i % 2 == 0 else r_in
        pts.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    return pts


def render_mark(size: int, *, tile: bool = True, transparent_bg: bool = False) -> Image.Image:
    """Renders the StarVault mark at `size` px.

    tile=True draws the rounded-square app tile (used for the app icon / favicon).
    tile=False draws just the shield+star mark on a transparent background
    (used for the in-app logo and title-bar icon).

    Detail is dropped below 48px: the shield keeps a bold stroke and the star
    gets thicker arms, because fine detail (a keyhole, thin points) turns to
    mud at toolbar sizes.
    """
    # Supersample 4x then downscale for clean anti-aliased edges.
    S = size * 4
    small = size < 48
    tiny = size <= 32
    img = Image.new("RGBA", (S, S), TRANSPARENT)
    draw = ImageDraw.Draw(img)

    if tile:
        inset = S * 0.0625
        radius = S * 0.2
        draw.rounded_rectangle(
            (inset, inset, S - inset, S - inset),
            radius=radius,
            fill=TILE_BG,
            outline=ACCENT_DIM,
            width=max(2, int(S * 0.014)),
        )

    if tiny:
        # Dedicated small-size variant: a SOLID cyan shield with the star
        # knocked out. Thin outlines and concave star curves turn to mud at
        # 16-32px, so the mark becomes a filled silhouette instead.
        shield = _shield_points(S)
        draw.polygon(shield, fill=ACCENT)
        star = _star_points(S, S * 0.5, S * 0.5, S * 0.19, S * 0.075, points=4)
        draw.polygon(star, fill=TILE_BG)
        return img.resize((size, size), Image.LANCZOS)

    # Shield — bold stroke so the container reads strongly at every size.
    shield = _shield_points(S)
    draw.polygon(
        shield,
        fill=TILE_BG2,
        outline=ACCENT,
        width=max(4 if small else 3, int(S * (0.045 if small else 0.03))),
    )

    # 4-point sparkle star, bright so it contrasts against the dark shield.
    # Slightly larger arms when small so the shape survives downscaling.
    r_out = S * (0.16 if small else 0.14)
    r_in = S * (0.062 if small else 0.05)
    star = _star_points(S, S * 0.5, S * 0.475, r_out, r_in, points=4)
    draw.polygon(star, fill=(240, 249, 255, 255))

    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    produced: list[str] = []

    # 1. App icon (.ico, multi-size)
    ico_path = repo / "starvault.ico"
    render_mark(256, tile=True).save(
        ico_path,
        sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    produced.append(str(ico_path))

    # 2. Master PNG (repo root, used by the docs/site)
    png_path = repo / "starvault.png"
    render_mark(512, tile=True).save(png_path)
    produced.append(str(png_path))

    # 3. Transparent-bg mark (in-app logo / title-bar icon)
    brand_dir = repo / "starvault" / "resources" / "brand"
    brand_dir.mkdir(parents=True, exist_ok=True)
    mark_path = brand_dir / "mark.png"
    render_mark(256, tile=False, transparent_bg=True).save(mark_path)
    produced.append(str(mark_path))
    # window title-bar icon (32px transparent mark)
    (brand_dir / "mark32.png").write_bytes(b"")  # placeholder overwritten below
    render_mark(32, tile=False, transparent_bg=True).save(brand_dir / "mark32.png")
    produced.append(str(brand_dir / "mark32.png"))

    # 4. Extension icons
    ext_icons = repo / "extension" / "icons"
    ext_icons.mkdir(parents=True, exist_ok=True)
    for px in (16, 48, 128):
        p = ext_icons / f"icon{px}.png"
        render_mark(px, tile=True).save(p)
        produced.append(str(p))

    print("StarVault brand mark generated:")
    for p in produced:
        print(f"  {Path(p).relative_to(repo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
