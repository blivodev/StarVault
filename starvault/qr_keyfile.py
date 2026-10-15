"""QR Code Keyfile Generator and Decoder for StarVault True Local 2FA.

Provides 256-bit random entropy generation, QR code image generation (PNG),
and high-speed image decoding via OpenCV QRCodeDetector.
"""

from pathlib import Path
import secrets
from typing import Optional

# cv2 / numpy are heavy (~100ms) and only needed for QR decoding — import lazily
# inside functions so application startup doesn't pay the cost.
from PIL import Image
import qrcode
from qrcode.constants import ERROR_CORRECT_H


class KeyfileError(Exception):
    """Raised when keyfile generation, saving, or decoding fails."""
    pass


def generate_keyfile_token() -> str:
    """Generates a 256-bit (32 bytes = 64 hex characters) cryptographically secure token.

    ELI5: Think of this like generating a secret physical master key with billions of
    billions of possible grooves. No computer on earth can guess this random 256-bit sequence.
    """
    return secrets.token_hex(32)


def generate_qr_image(token: str, box_size: int = 10, border: int = 4) -> Image.Image:
    """Encodes the 256-bit token string into a high-contrast standard QR code PIL Image.

    Uses Error Correction Level H (up to 30% damage/distortion recovery).
    """
    if not token or len(token.strip()) < 16:
        raise KeyfileError("Keyfile token must be at least 16 characters.")

    qr = qrcode.QRCode(
        version=None,  # Auto-fit version
        error_correction=ERROR_CORRECT_H,
        box_size=box_size,
        border=border,
    )
    qr.add_data(token.strip())
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    return img.convert("RGBA")


def save_qr_image(token: str, file_path: str) -> None:
    """Saves the generated QR code image to a local file path."""
    dest = Path(file_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    img = generate_qr_image(token)
    img.save(str(dest), format="PNG")


def read_keyfile_token(file_path: str) -> str:
    """Extracts and decodes the secret keyfile token from an image or key file.

    Supports:
    - Image files (.png, .jpg, .jpeg, .bmp, .webp) decoded via OpenCV QR detector.
    - Plain text keyfiles (.key, .txt) read directly.
    """
    p = Path(file_path)
    if not p.exists():
        raise KeyfileError(f"Keyfile does not exist: {file_path}")

    # 1. Try decoding as an image with OpenCV
    try:
        import cv2
        import numpy as np
        # Read file bytes first to avoid path encoding issues on Windows
        with open(p, "rb") as f:
            file_bytes = f.read()

        np_arr = np.frombuffer(file_bytes, np.uint8)
        cv_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if cv_img is not None:
            detector = cv2.QRCodeDetector()
            decoded_text, points, _ = detector.detectAndDecode(cv_img)
            if decoded_text and len(decoded_text.strip()) >= 16:
                return decoded_text.strip()
    except Exception:
        # If image processing fails, proceed to try text fallback
        pass

    # 2. Fallback: Try reading as a plain text / raw keyfile
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            text_content = f.read().strip()
            if text_content and len(text_content) >= 16:
                return text_content
    except Exception as e:
        raise KeyfileError(f"Failed to read keyfile: {str(e)}")

    raise KeyfileError("Could not detect or decode a valid QR code keyfile from the selected file.")
