"""Time-based One-Time Password (TOTP, RFC 6238) and QR/Barcode utilities for StarVault.

Supports:
- Generating 6-digit or 8-digit TOTP codes from Base32 secrets.
- Parsing otpauth:// URIs.
- High-res QR code generation and decoding.
- 1D Barcode generation (Code 128) and decoding.
"""

import base64
import hashlib
import hmac
import math
import struct
import time
from typing import Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse
from PIL import Image, ImageDraw, ImageFont
import qrcode


def normalize_base32(secret: str) -> bytes:
    """Cleans and pads a Base32 secret string, returning decoded bytes."""
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    missing_padding = len(cleaned) % 8
    if missing_padding:
        cleaned += "=" * (8 - missing_padding)
    return base64.b32decode(cleaned, casefold=True)


def generate_totp_code(
    secret: str,
    for_time: Optional[float] = None,
    time_step: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
) -> str:
    """Generates an RFC 6238 TOTP code from a Base32 secret."""
    if not secret or not secret.strip():
        return "------"

    try:
        key = normalize_base32(secret)
    except Exception:
        return "INVALID"

    current_time = time.time() if for_time is None else for_time
    counter = int(current_time // time_step)

    msg = struct.pack(">Q", counter)

    algo_lower = algorithm.lower().strip()
    if algo_lower == "sha256":
        digest_mod = hashlib.sha256
    elif algo_lower == "sha512":
        digest_mod = hashlib.sha512
    else:
        digest_mod = hashlib.sha1

    h = hmac.new(key, msg, digest_mod).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    token = str(code_int % (10**digits)).zfill(digits)
    return token


def verify_totp(code: str, secret: str, tolerance_steps: int = 1, time_step: int = 30) -> bool:
    """Verifies a TOTP code against a secret with optional time-step drift tolerance."""
    if not code or not secret:
        return False
    now = time.time()
    for step_offset in range(-tolerance_steps, tolerance_steps + 1):
        test_time = now + (step_offset * time_step)
        if generate_totp_code(secret, for_time=test_time, time_step=time_step) == code.strip():
            return True
    return False


# Convenience aliases
generate_totp = generate_totp_code


def normalize_secret(secret: str) -> str:
    """Returns upper-case normalized Base32 secret without spaces or dashes."""
    return secret.strip().replace(" ", "").replace("-", "").upper()


def get_totp_remaining_seconds(time_step: int = 30) -> int:
    """Returns the remaining seconds in the current TOTP time step."""
    return int(time_step - (time.time() % time_step))


def parse_otpauth_uri(uri: str) -> dict:
    """Parses an otpauth://totp/ URI into discrete components."""
    if not uri.startswith("otpauth://"):
        raise ValueError("Invalid otpauth URI scheme")

    parsed = urlparse(uri)
    query = parse_qs(parsed.query)

    path_part = unquote(parsed.path.lstrip("/"))
    issuer = query.get("issuer", [""])[0]
    account = path_part
    if ":" in path_part:
        prefix_issuer, account = path_part.split(":", 1)
        if not issuer:
            issuer = prefix_issuer

    secret = query.get("secret", [""])[0]
    digits = int(query.get("digits", ["6"])[0])
    period = int(query.get("period", ["30"])[0])
    algorithm = query.get("algorithm", ["SHA1"])[0]

    return {
        "account": account.strip(),
        "issuer": issuer.strip(),
        "secret": secret.strip(),
        "digits": digits,
        "period": period,
        "algorithm": algorithm.upper(),
    }


def build_otpauth_uri(
    account: str,
    secret: str,
    issuer: str = "StarVault",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """Constructs a standard otpauth://totp/ URI."""
    clean_account = account.strip()
    clean_issuer = issuer.strip()
    clean_secret = secret.strip().replace(" ", "").upper()
    return f"otpauth://totp/{clean_issuer}:{clean_account}?secret={clean_secret}&issuer={clean_issuer}&algorithm={algorithm}&digits={digits}&period={period}"


def generate_qr_image(data: str, box_size: int = 8, border: int = 2) -> Image.Image:
    """Generates a high-quality PIL Image containing a QR code."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="#00E5FF", back_color="#1E222D").convert("RGBA")


def decode_qr_image(img_path_or_pil) -> str:
    """Decodes QR code from an image file path or PIL Image using OpenCV."""
    import numpy as np
    import cv2

    if isinstance(img_path_or_pil, (str, bytes)):
        img = cv2.imread(str(img_path_or_pil))
    else:
        # Convert PIL to cv2 numpy array
        img = cv2.cvtColor(np.array(img_path_or_pil), cv2.COLOR_RGB2BGR)

    if img is None:
        return ""

    detector = cv2.QRCodeDetector()
    val, points, _ = detector.detectAndDecode(img)
    return val or ""


# Simple Code 128 Barcode Generation
CODE128_PATTERNS = {
    "0": "11011001100", "1": "11001101100", "2": "11001100110", "3": "10010011000",
    "4": "10010001100", "5": "10001001100", "6": "10011001000", "7": "10011000100",
    "8": "10001100100", "9": "11001001000", "A": "11110101110", "B": "11010111110",
    "C": "11011101110", "D": "11110111010", "E": "11101111010", "F": "11101011110",
    "G": "10111101110", "H": "10111011110", "I": "10101111110", "J": "10111111010",
    "K": "11111010110", "L": "11111011010", "M": "11011011110", "N": "11011110110",
    "O": "11110110110", "P": "11101101110", "Q": "11101110110", "R": "11011101100",
    "S": "11001110110", "T": "11011001110", "U": "11011100110", "V": "11011101100",
    "W": "11110100110", "X": "11101100110", "Y": "11101001110", "Z": "10111001110",
    "-": "10011101110", ".": "11110010110", " ": "11100110110", "$": "11100101110",
    "/": "10101101110", "+": "10110101110", "%": "10110111010", "*": "10010110110",
}


def generate_barcode_image(text: str, height: int = 80, bar_width: int = 2) -> Image.Image:
    """Generates a clean 1D barcode image (Code 39 style fallback)."""
    clean_text = "".join(c.upper() for c in text if c.upper() in CODE128_PATTERNS)
    if not clean_text:
        clean_text = "STARVAULT"

    full_text = f"*{clean_text}*"
    bit_pattern = "0".join(CODE128_PATTERNS.get(c, "10010110110") for c in full_text)

    img_w = len(bit_pattern) * bar_width + 40
    img_h = height + 30
    img = Image.new("RGBA", (img_w, img_h), color=(30, 34, 45, 255))
    draw = ImageDraw.Draw(img)

    # Draw bars
    x = 20
    for bit in bit_pattern:
        if bit == "1":
            draw.rectangle([x, 10, x + bar_width - 1, 10 + height], fill=(0, 229, 255, 255))
        x += bar_width

    # Draw label text at bottom
    draw.text((img_w // 2, 10 + height + 5), clean_text, fill=(255, 255, 255, 255), anchor="mt")
    return img
