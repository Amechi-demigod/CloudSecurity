"""Request hardening: body-size limit middleware and sensor-ingest authentication."""
from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import config, tenancy
from .db import get_db

log = logging.getLogger(__name__)


class BodySizeLimitMiddleware:
    """Reject request bodies larger than `max_bytes` with 413.

    Checks `Content-Length` up front and also counts streamed bytes, so chunked
    uploads without a length header cannot bypass the limit. `path_limits`
    maps path prefixes to a different limit (e.g. agent check-ins and log
    bundles under /api/agent/).
    """

    def __init__(self, app: ASGIApp, max_bytes: int, path_limits: dict[str, int] | None = None):
        self.app = app
        self.default_max_bytes = max_bytes
        self.path_limits = sorted((path_limits or {}).items(), key=lambda kv: -len(kv[0]))

    def _limit_for(self, path: str) -> int:
        for prefix, limit in self.path_limits:
            if path.startswith(prefix):
                return limit
        return self.default_max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_bytes = self._limit_for(scope.get("path", ""))
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await _reject(send, max_bytes)
                    return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > max_bytes:
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
                await _reject(send, max_bytes)


class _BodyTooLarge(Exception):
    pass


async def _reject(send: Send, limit: int) -> None:
    body = f'{{"detail":"request body exceeds {limit} bytes"}}'.encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


INGEST_TOKEN_PREFIX = "cni_"  # noqa: S105 (token prefix, not a secret)


def hash_ingest_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_ingest_token(authorization: str | None = Header(None), db: Session = Depends(get_db)) -> str:
    """FastAPI dependency guarding the runtime-sensor ingest (POST /api/runtime/*).

    The bearer token decides the organisation the data belongs to, and the
    request's database session is scoped to it:

    * a per-organisation ingest token (`cni_...`, created by an organisation
      admin; only its SHA-256 is stored), or
    * the legacy INGEST_API_TOKEN environment variable: the default organisation.

    Fail-closed: with neither configured the endpoint is disabled (503) unless
    INGEST_ALLOW_UNAUTHENTICATED=true is set for local development (default
    organisation). The runtime sensor sends `Authorization: Bearer <SENSOR_API_TOKEN>`.
    """
    from .models import IngestToken, utcnow

    s = config.settings
    scheme, _, supplied = (authorization or "").strip().partition(" ")
    supplied = supplied.strip()
    bearer = scheme.lower() == "bearer" and bool(supplied) and len(supplied) <= 256
    if bearer and supplied.startswith(INGEST_TOKEN_PREFIX):
        with tenancy.unscoped(db):
            tok = db.scalar(select(IngestToken).where(IngestToken.token_hash == hash_ingest_token(supplied),
                                                      IngestToken.revoked_at.is_(None)))
        if tok is not None:
            org = tenancy.get_org(db, tok.organization_id)
            if org is None or org.status != "active":
                raise HTTPException(403, "organisation suspended")
            tenancy.set_org(db, tok.organization_id)
            tok.last_used_at = utcnow()  # committed with the ingest
            return tok.organization_id
    token = s.ingest_api_token
    if bearer and token and hmac.compare_digest(supplied.encode(), token.encode()):
        tenancy.set_org(db, tenancy.DEFAULT_ORG_ID)
        return tenancy.DEFAULT_ORG_ID
    if not token:
        if s.ingest_allow_unauthenticated:
            tenancy.set_org(db, tenancy.DEFAULT_ORG_ID)
            return tenancy.DEFAULT_ORG_ID
        with tenancy.unscoped(db):
            any_tokens = db.scalar(select(IngestToken.id).where(IngestToken.revoked_at.is_(None)).limit(1))
        if not any_tokens:
            raise HTTPException(503, "sensor ingest disabled: set INGEST_API_TOKEN on the backend or create an "
                                     "ingest token (Settings > Organisation)")
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
