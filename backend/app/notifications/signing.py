"""HMAC-SHA256 signatures for generic webhooks (replay-protected).

Headers sent with every webhook delivery:

    X-CNAPP-Timestamp: <unix seconds>
    X-CNAPP-Signature: v1=<hex(HMAC-SHA256(secret, "<timestamp>.<raw body>"))>
    X-CNAPP-Delivery:  <delivery id>   (same across retries: use it to de-duplicate)
    X-CNAPP-Event:     <source>.<event type>

Receivers recompute the HMAC over the exact raw body, compare in constant time
and reject timestamps outside a tolerance window (default 5 minutes). See
docs/NOTIFICATIONS.md for Python and Node.js verification examples.
"""
from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_HEADER = "X-CNAPP-Signature"
TIMESTAMP_HEADER = "X-CNAPP-Timestamp"
DELIVERY_HEADER = "X-CNAPP-Delivery"
EVENT_HEADER = "X-CNAPP-Event"
SCHEME = "v1"
DEFAULT_TOLERANCE = 300
MIN_SECRET_LENGTH = 32


def compute(secret: str, timestamp: int | str, body: bytes) -> str:
    msg = str(timestamp).encode() + b"." + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def sign(secret: str, body: bytes, *, timestamp: int | None = None) -> dict[str, str]:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    return {TIMESTAMP_HEADER: str(ts), SIGNATURE_HEADER: f"{SCHEME}={compute(secret, ts, body)}"}


def verify(secret: str, body: bytes, timestamp: str | None, signature: str | None, *,
           tolerance: int = DEFAULT_TOLERANCE, now: float | None = None) -> bool:
    """Reference verifier (mirrors the documented receiver code)."""
    if not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    now = time.time() if now is None else now
    if abs(now - ts) > tolerance:
        return False
    expected = compute(secret, ts, body)
    # Several signatures may be sent during secret rotation: "v1=abc,v1=def".
    for part in signature.split(","):
        scheme, _, value = part.strip().partition("=")
        if scheme == SCHEME and hmac.compare_digest(value.encode(), expected.encode()):
            return True
    return False
