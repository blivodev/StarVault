"""Icon generator and visual assets for StarVault."""

import io
from PIL import Image, ImageDraw


def generate_vault_icon_image(size: int = 64) -> Image.Image:
    """Generates a sleek high-res StarVault icon using PIL (Shield with glowing star)."""
    img = Image.new("RGBA", (size, size), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer Shield / Hexagon
    padding = size * 0.1
    points = [
        (size * 0.5, padding),
        (size - padding, size * 0.25),
        (size - padding, size * 0.65),
        (size * 0.5, size - padding),
        (padding, size * 0.65),
        (padding, size * 0.25),
    ]

    # Gradient-like shield background
    draw.polygon(points, fill="#0f172a", outline="#38bdf8", width=max(2, int(size * 0.05)))

    # Inner glowing star / vault lock core
    cx, cy = size * 0.5, size * 0.48
    r_outer = size * 0.22
    r_inner = size * 0.09
    star_points = []
    import math

    for i in range(8):
        angle = i * (math.pi / 4) - (math.pi / 2)
        r = r_outer if i % 2 == 0 else r_inner
        star_points.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))

    draw.polygon(star_points, fill="#38bdf8")

    # Keyhole center
    keyhole_r = size * 0.05
    draw.ellipse(
        (cx - keyhole_r, cy - keyhole_r, cx + keyhole_r, cy + keyhole_r),
        fill="#0f172a",
    )

    return img
