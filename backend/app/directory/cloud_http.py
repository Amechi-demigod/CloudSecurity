"""HTTP for server-side directory collection (Microsoft Graph, Google Admin SDK
/ Cloud Identity): read-only GETs and OAuth token requests only.

* Only the provider endpoints below are ever contacted (`ALLOWED_HOSTS`, HTTPS);
  a paging link that points anywhere else is refused.
* Throttling: 429 and 503 / 504 are retried with the server's Retry-After
  (capped) or exponential backoff; transport errors likewise. A run that keeps
  being throttled fails after MAX_ATTEMPTS per request.
* Nothing secret is logged: request bodies (which carry the client secret or
  the signed assertion) are never logged, and error messages keep only the
  provider's error code and message.

Tests swap in an `httpx.MockTransport` with `set_transport()` (no test ever
talks to Microsoft or Google) and a no-op sleep with `set_sleep()`.
"""
from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset({"login.microsoftonline.com", "graph.microsoft.com", "oauth2.googleapis.com",
                           "admin.googleapis.com", "cloudidentity.googleapis.com"})
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_ATTEMPTS = 6
MAX_RETRY_AFTER = 120.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

# A bearer token, or a function returning a current one (long syncs refresh it).
Token = str | Callable[[], str]

_transport: httpx.BaseTransport | None = None
_sleep: Callable[[float], None] = time.sleep


def set_transport(transport: httpx.BaseTransport | None) -> None:
    """Tests: route every request through this transport (None = real network)."""
    global _transport
    _transport = transport


def set_sleep(fn: Callable[[float], None] | None) -> None:
    """Tests: replace the backoff sleep."""
    global _sleep
    _sleep = fn or time.sleep


class CloudApiError(Exception):
    """A provider call failed. `status` is the HTTP status (0: no response),
    `code` the provider's error code (e.g. Authorization_RequestDenied)."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}" if status else message)
        self.status, self.code, self.message = status, code, message


def _check_url(url: str) -> None:
    u = urlsplit(url)
    if u.scheme != "https" or (u.hostname or "") not in ALLOWED_HOSTS:
        raise CloudApiError(0, "invalid_url", f"refusing to call {u.scheme}://{u.hostname}: not a provider endpoint")


def _error(resp: httpx.Response) -> CloudApiError:
    """Provider error code and message (Graph / Google / OAuth shapes)."""
    code, msg = "", ""
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):  # Graph {"error": {"code", "message"}}, Google {"error": {"status", "message"}}
            code = str(err.get("code") or err.get("status") or "")
            msg = str(err.get("message") or "")
            for e in err.get("errors") or []:
                if isinstance(e, dict) and e.get("reason"):  # Google: accessNotConfigured, forbidden, ...
                    code = f"{code}/{e['reason']}" if code else str(e["reason"])
                    break
        elif isinstance(err, str):  # OAuth {"error", "error_description"}
            code, msg = err, str(body.get("error_description") or "")
    if not msg:
        msg = resp.reason_phrase or "request failed"
    return CloudApiError(resp.status_code, code[:100], msg.splitlines()[0][:500] if msg else "")


def _retry_after(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        raw = resp.headers.get("Retry-After", "")
        try:
            return min(max(float(raw), 0.0), MAX_RETRY_AFTER)
        except ValueError:
            pass
    return min(2.0 ** attempt + random.random(), 60.0)


class CloudHttp:
    """One client per sync / test (connection reuse, closed at the end)."""

    def __init__(self) -> None:
        self._client = httpx.Client(timeout=TIMEOUT, transport=_transport, follow_redirects=False,
                                    headers={"User-Agent": "cnapp-directory-discovery"})
        self.requests = 0
        self.throttled = 0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> CloudHttp:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        """Send with retries on throttling / transient errors. Returns the final
        response (any status); raises CloudApiError(0) when no response came."""
        _check_url(url)
        last: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            self.requests += 1
            try:
                resp = self._client.request(method, url, **kw)
            except httpx.TransportError as e:
                last = e
                resp = None
            if resp is not None and resp.status_code not in RETRY_STATUSES:
                return resp
            if attempt == MAX_ATTEMPTS - 1:
                if resp is not None:
                    return resp
                break
            if resp is not None and resp.status_code == 429:
                self.throttled += 1
            delay = _retry_after(resp, attempt)
            log.info("directory API %s %s: %s, retrying in %.1fs", method, urlsplit(url).path,
                     resp.status_code if resp is not None else type(last).__name__, delay)
            _sleep(delay)
        raise CloudApiError(0, "unreachable", f"{urlsplit(url).hostname} did not answer ({type(last).__name__})")

    def get_json(self, url: str, token: Token, params: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None) -> dict[str, Any]:
        bearer = token() if callable(token) else token
        resp = self.request("GET", url, params=params, headers={"Authorization": f"Bearer {bearer}",
                                                               "Accept": "application/json", **(headers or {})})
        if resp.status_code != 200:
            raise _error(resp)
        try:
            body = resp.json()
        except ValueError:
            raise CloudApiError(resp.status_code, "invalid_json", "the response was not JSON") from None
        if not isinstance(body, dict):
            raise CloudApiError(resp.status_code, "invalid_json", "unexpected response shape")
        return body

    def post_form(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        """OAuth token request. The body (secret / assertion) is never logged."""
        resp = self.request("POST", url, data=data, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise _error(resp)
        try:
            body = resp.json()
        except ValueError:
            raise CloudApiError(resp.status_code, "invalid_json", "the token response was not JSON") from None
        return body if isinstance(body, dict) else {}

    def pages(self, url: str, token: Token, params: dict[str, Any] | None = None, *, items_key: str = "value",
              next_key: str = "@odata.nextLink", headers: dict[str, str] | None = None) -> Iterator[list[dict]]:
        """Graph-style paging: follow the absolute next link (same host only)."""
        host = urlsplit(url).hostname
        nxt: str | None = url
        first = True
        while nxt:
            if urlsplit(nxt).hostname != host:
                raise CloudApiError(0, "invalid_url", "the paging link points to another host")
            body = self.get_json(nxt, token, params if first else None, headers)
            first = False
            items = body.get(items_key) or []
            yield [i for i in items if isinstance(i, dict)]
            nxt = body.get(next_key) or None

    def token_pages(self, url: str, token: Token, params: dict[str, Any], *, items_key: str,
                    max_pages: int = 1_000_000) -> Iterator[list[dict]]:
        """Google-style paging: repeat the request with pageToken."""
        page_token = ""
        for _ in range(max_pages):
            p = dict(params)
            if page_token:
                p["pageToken"] = page_token
            body = self.get_json(url, token, p)
            items = body.get(items_key) or []
            yield [i for i in items if isinstance(i, dict)]
            page_token = body.get("nextPageToken") or ""
            if not page_token:
                return
