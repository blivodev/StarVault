"""API Key Generator and Format Utility for StarVault.

Supports generating and validating API tokens across diverse formats:
- Hex (32-char, 64-char)
- URL-Safe Base64 (32-char, 64-char)
- UUIDv4
- Prefixed tokens (OpenAI, Stripe, GitHub, custom prefix)
- Cloud/AWS Keypairs (Access Key ID + Secret Key)
- JWT mock / simulation token
"""

import base64
import json
import secrets
import string
import time
from typing import Dict, Optional, Tuple
import uuid


SUPPORTED_KEY_FORMATS = [
    ("hex32", "Hex (32-char / 128-bit)"),
    ("hex64", "Hex (64-char / 256-bit)"),
    ("base64_32", "Base64 URL-Safe (32-char)"),
    ("base64_64", "Base64 URL-Safe (64-char)"),
    ("uuid", "UUIDv4"),
    ("openai", "OpenAI Style (sk-proj-...)"),
    ("stripe_live", "Stripe Live (sk_live_...)"),
    ("stripe_test", "Stripe Test (sk_test_...)"),
    ("github", "GitHub Personal Token (ghp_...)"),
    ("aws", "AWS Access Key Pair (AKIA... + Secret)"),
    ("jwt", "JWT Simulation Token"),
    ("custom_prefixed", "Custom Prefixed Token"),
]


def generate_api_key(
    format_type: str = "hex64",
    prefix: str = "sv",
    length: int = 48,
    custom_charset: Optional[str] = None,
) -> Tuple[str, str]:
    """Generates an API key based on format type.

    Returns:
        (primary_key, secret_or_secondary_key)
        For single tokens, secondary_key is empty string.
        For paired credentials (e.g. AWS), secondary_key contains the secret key.
    """
    format_type = (format_type or "hex64").lower().strip()

    if format_type == "hex32":
        return secrets.token_hex(16), ""

    elif format_type == "hex64":
        return secrets.token_hex(32), ""

    elif format_type == "base64_32":
        token = secrets.token_urlsafe(24)[:32]
        return token, ""

    elif format_type == "base64_64":
        token = secrets.token_urlsafe(48)[:64]
        return token, ""

    elif format_type == "uuid":
        return str(uuid.uuid4()), ""

    elif format_type == "openai":
        # sk-proj- followed by 48 url-safe random chars
        rand_part = secrets.token_urlsafe(48).replace("-", "").replace("_", "")[:48]
        return f"sk-proj-{rand_part}", ""

    elif format_type == "stripe_live":
        rand_part = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        return f"sk_live_{rand_part}", ""

    elif format_type == "stripe_test":
        rand_part = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        return f"sk_test_{rand_part}", ""

    elif format_type == "github":
        rand_part = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        return f"ghp_{rand_part}", ""

    elif format_type == "aws":
        # Access Key ID: AKIA + 16 uppercase alphanumeric chars
        id_part = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        # Secret Access Key: 40 url-safe chars
        secret_part = secrets.token_urlsafe(30)[:40]
        return id_part, secret_part

    elif format_type == "jwt":
        # Build mock JWT token: header.payload.signature
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_data = {
            "sub": f"user_{secrets.token_hex(4)}",
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400 * 365,
            "scope": "api:read api:write",
        }
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        signature = secrets.token_urlsafe(32).rstrip("=")
        return f"{header}.{payload}.{signature}", ""

    elif format_type == "custom_prefixed":
        clean_prefix = (prefix or "key").strip().rstrip("-_")
        charset = custom_charset or (string.ascii_letters + string.digits)
        rand_part = "".join(secrets.choice(charset) for _ in range(max(8, length)))
        return f"{clean_prefix}_{rand_part}", ""

    else:
        # Default alphanumeric bearer token
        charset = string.ascii_letters + string.digits
        token = "".join(secrets.choice(charset) for _ in range(max(16, length)))
        return token, ""


def format_api_curl_snippet(
    provider_or_url: str,
    api_token: str,
    header_name: str = "Authorization",
    is_bearer: bool = True,
) -> str:
    """Generates an authenticated curl command snippet."""
    url = provider_or_url.strip() if provider_or_url else "https://api.example.com/v1/resource"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    if is_bearer:
        header_val = f"Bearer {api_token}"
    else:
        header_val = api_token

    return f'curl -X GET "{url}" \\\n  -H "{header_name}: {header_val}" \\\n  -H "Content-Type: application/json"'
