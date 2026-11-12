"""Public website "Request a demo" form: POST /api/contact (website/index.html).

Public (no session, no CSRF cookie: there is nothing to ride on) and reachable
from the internet on the website names (on-prem nginx: SITE_HOSTNAMES serve the
static site plus this one path). One email per request goes to CONTACT_TO
through the platform mailer (app/mailer.py), with Reply-To set to the requester.

Abuse protections:
* Origin (else Referer) must be one of https://SITE_HOSTNAMES or the console
  (PUBLIC_BASE_URL): other sites cannot post into it from a visitor's browser.
* Per client IP (the trusted-proxy aware auth.client_ip): 3 per 10 minutes and
  10 per day; globally at most 50 emails per hour. In-memory per worker, like the
  login limiter; nginx adds a per-IP request limit in front (cnapp-access.sh).
* Honeypot field `website`: when filled, the answer is "sent" and nothing happens.
* Strict validation; CR / LF never reach a mail header; nothing a client sent is
  ever echoed back in a response or written to the log (no personal data there:
  only "contact request accepted" / "rejected (<reason>)").

JSON requests (assets/site.js) get JSON answers; a plain form post (no
JavaScript) gets a 303 redirect to /#contact-sent or /#contact-error.
"""
from __future__ import annotations

import html
import json
import logging
import re
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from .. import config, mailer
from ..auth import RateLimiter, client_ip

log = logging.getLogger("cnapp.contact")
router = APIRouter(tags=["website"])

# The <select> options of website/index.html (no value attribute: the text is sent).
INTERESTS = ("The whole platform", "Cloud security", "Endpoints & servers", "Vulnerabilities",
             "Assets & identity",
             # Earlier website options, still accepted from pages cached before the menu change.
             "Vulnerability management", "Endpoint management", "IT asset lifecycle")
LIMITS = {"name": 120, "email": 200, "company": 160, "message": 2000}
MAX_BODY_BYTES = 32 * 1024
PER_IP_LIMITS = ((3, 600.0), (10, 86400.0))  # (requests, window seconds)
GLOBAL_LIMIT = (50, 3600.0)  # emails per hour, all clients together

ip_limiter = RateLimiter()
global_limiter = RateLimiter()

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
# Control characters (C0, DEL, C1) and the Unicode line / paragraph separators.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_CONTROL_BUT_NEWLINE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f  ]")

# Fixed answers: never built from the request.
_ANSWERS = {
    "forbidden": (403, "Requests are only accepted from the website."),
    "unavailable": (503, "The contact form is temporarily unavailable. Please try again later."),
    "limited": (429, "Too many requests. Please try again later."),
    "invalid": (400, "Please check the form and try again."),
}


def reset_limits() -> None:
    ip_limiter.reset()
    global_limiter.reset()


def _origin(value: str) -> str | None:
    try:
        u = urlsplit(value.strip())
    except ValueError:
        return None
    if u.scheme not in ("https", "http") or not u.hostname:
        return None
    port = f":{u.port}" if u.port and u.port != (443 if u.scheme == "https" else 80) else ""
    return f"{u.scheme}://{u.hostname.lower()}{port}"


def allowed_origins() -> set[str]:
    s = config.settings
    out = {f"https://{h}" for h in s.site_hostnames}
    if s.public_base_url and (o := _origin(s.public_base_url)):
        out.add(o)
    return out


def _request_origin(request: Request) -> str | None:
    origin = request.headers.get("origin")
    if origin and origin != "null":
        return _origin(origin)
    referer = request.headers.get("referer")
    return _origin(referer) if referer else None


def _single_line(value: str) -> str:
    return " ".join(_CONTROL.sub(" ", value).split())


def _multi_line(value: str) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_BUT_NEWLINE.sub(" ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _parse(raw: bytes, json_mode: bool) -> dict[str, str] | None:
    """-> the submitted string fields, or None when the body is malformed."""
    if len(raw) > MAX_BODY_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
        if json_mode:
            data = json.loads(text) if text else {}
            if not isinstance(data, dict):
                return None
        else:
            data = {k: v[0] for k, v in parse_qs(text, keep_blank_values=True, max_num_fields=20).items()}
    except (UnicodeDecodeError, ValueError):
        return None
    out: dict[str, str] = {}
    for key in ("name", "email", "company", "interest", "message", "website"):
        value = data.get(key, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            return None
        out[key] = value
    return out


def validate(fields: dict[str, str]) -> dict[str, str] | None:
    """Cleaned values, or None if anything is invalid (the reason is never reported)."""
    name = _single_line(fields["name"])
    email = fields["email"].strip()
    company = _single_line(fields["company"])
    interest = _single_line(fields["interest"])
    message = _multi_line(fields["message"])
    if not (1 <= len(name) <= LIMITS["name"] and 1 <= len(company) <= LIMITS["company"]):
        return None
    if len(email) > LIMITS["email"] or not EMAIL_RE.match(email):
        return None
    if interest not in INTERESTS or len(message) > LIMITS["message"]:
        return None
    return {"name": name, "email": email, "company": company, "interest": interest, "message": message}


def render(v: dict[str, str]) -> tuple[str, str, str]:
    """(subject, plain text, html) of the notification; every value escaped in the HTML."""
    subject = f"Demo request: {v['company']}"[:200]
    message = v["message"] or "(no message)"
    text = (
        "New demo request from the website.\n\n"
        f"Name:      {v['name']}\n"
        f"Email:     {v['email']}\n"
        f"Company:   {v['company']}\n"
        f"Interest:  {v['interest']}\n\n"
        f"Message:\n{message}\n\n"
        "Reply to this email to answer the requester directly.\n"
    )
    e = html.escape
    rows = "".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#64748b">{label}</td><td style="padding:4px 0">{e(v[key])}</td></tr>'
        for label, key in (("Name", "name"), ("Email", "email"), ("Company", "company"), ("Interest", "interest")))
    body_html = (
        '<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:15px;color:#0f172a">'
        "<p>New demo request from the website.</p>"
        f'<table style="border-collapse:collapse">{rows}</table>'
        '<p style="margin:16px 0 4px;color:#64748b">Message</p>'
        f'<p style="margin:0">{e(message).replace(chr(10), "<br>")}</p>'
        '<p style="margin-top:20px;color:#64748b;font-size:13px">Reply to this email to answer the requester directly.</p>'
        "</div>"
    )
    return subject, text, body_html


@router.post("/api/contact", include_in_schema=False)
async def contact(request: Request) -> Response:
    json_mode = request.headers.get("content-type", "").split(";")[0].strip().lower() == "application/json"

    def accept(honeypot: bool = False) -> Response:
        # A filled honeypot looks exactly like success to the client.
        log.info("contact request rejected (honeypot)" if honeypot else "contact request accepted")
        if json_mode:
            return JSONResponse({"ok": True})
        return RedirectResponse("/#contact-sent", status_code=303)

    def reject(kind: str, why: str) -> Response:
        log.warning("contact request rejected (%s)", why)  # `why` is always a fixed string
        if json_mode:
            status, detail = _ANSWERS[kind]
            return JSONResponse({"detail": detail}, status_code=status)
        return RedirectResponse("/#contact-error", status_code=303)

    s = config.settings
    origin = _request_origin(request)
    if not origin or origin not in allowed_origins():
        return reject("forbidden", "origin not allowed")
    if not s.contact_to or not EMAIL_RE.match(s.contact_to):
        return reject("unavailable", "CONTACT_TO not configured")
    if not mailer.configured():
        return reject("unavailable", "no platform mail server")
    ip = client_ip(request)
    if any(ip_limiter.blocked(f"{ip}:{w}", n, w) for n, w in PER_IP_LIMITS):
        return reject("limited", "per-IP limit")
    for n, w in PER_IP_LIMITS:
        ip_limiter.hit(f"{ip}:{w}", n, w)
    fields = _parse(await request.body(), json_mode)
    if fields is None:
        return reject("invalid", "malformed body")
    if fields["website"].strip():
        return accept(honeypot=True)
    values = validate(fields)
    if values is None:
        return reject("invalid", "validation failed")
    if global_limiter.blocked("all", *GLOBAL_LIMIT):
        return reject("limited", "global limit")
    global_limiter.hit("all", *GLOBAL_LIMIT)
    subject, text, body_html = render(values)
    result = await run_in_threadpool(mailer.send, s.contact_to, subject, text, body_html,
                                     reply_to=values["email"])
    if not result.sent:
        return reject("unavailable", "mail delivery failed")
    return accept()
