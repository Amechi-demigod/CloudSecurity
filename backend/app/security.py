"""Request hardening: body-size limit middleware and sensor-ingest authentication."""
from __future__ import annotations

import hmac
import logging

from fastapi import Header, HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import config

log = logging.getLogger(__name__)


class BodySizeLimitMiddleware:
    """Reject request bodies larger than `max_bytes` with 413.

    Checks `Content-Length` up front and also counts streamed bytes, so chunked
    uploads without a length header cannot bypass the limit.
    """

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await _reject(send, self.max_bytes)
                    return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return msg

        async def tracking_send(msg: Message) -> None:
            nonlocal response_started
            if msg["type"] == "http.response.start":
                response_started = True
            await send(msg)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                await _reject(send, self.max_bytes)


class _BodyTooLarge(Exception):
    pass


async def _reject(send: Send, limit: int) -> None:
    body = f'{{"detail":"request body exceeds {limit} bytes"}}'.encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def require_ingest_token(authorization: str | None = Header(None)) -> None:
    """FastAPI dependency guarding POST /api/runtime/events.

    Fail-closed: if INGEST_API_TOKEN is not configured the endpoint is disabled
    (503) unless INGEST_ALLOW_UNAUTHENTICATED=true is set for local development.
    The runtime sensor sends `Authorization: Bearer <SENSOR_API_TOKEN>`.
    """
    s = config.settings
    token = s.ingest_api_token
    if not token:
        if s.ingest_allow_unauthenticated:
            return
        raise HTTPException(503, "sensor ingest disabled: set INGEST_API_TOKEN on the backend")
    scheme, _, supplied = (authorization or "").strip().partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), token.encode()):
        raise HTTPException(401, "invalid or missing sensor token", headers={"WWW-Authenticate": "Bearer"})


class SecurityHeadersMiddleware:
    """Add defensive response headers to every API response.

    HSTS is only sent when `hsts_max_age` > 0 (production): the browser only
    honours it over https, and the deployed app is https-only.
    """

    def __init__(self, app: ASGIApp, hsts_max_age: int = 0):
        self.app = app
        headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            # API responses carry user data: never cache them in shared caches.
            (b"cache-control", b"no-store"),
        ]
        if hsts_max_age > 0:
            headers.append((b"strict-transport-security", f"max-age={hsts_max_age}; includeSubDomains".encode()))
        self.headers = headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(msg: Message) -> None:
            if msg["type"] == "http.response.start":
                present = {k.lower() for k, _ in msg.get("headers", [])}
                msg["headers"] = list(msg.get("headers", [])) + [(k, v) for k, v in self.headers if k not in present]
            await send(msg)

        await self.app(scope, receive, send_with_headers)
