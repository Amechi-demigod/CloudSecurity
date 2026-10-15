"""Channel types: configuration schema, validation, payload rendering and sending.

* teams   - Microsoft Teams incoming webhook or Workflows (Power Automate) webhook; Adaptive Card.
* slack   - Slack incoming webhook; Block Kit.
* email   - SMTP (STARTTLS or implicit TLS) or Azure Communication Services Email (REST, HMAC auth).
* webhook - generic JSON POST, signed with HMAC-SHA256 + timestamp (see signing.py).

All text that can come from monitored workloads (alert titles, command lines,
resource names) is escaped for the target format so it cannot inject mentions
(<!channel>), links or HTML into messages.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import smtplib
import socket
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from typing import Any
from urllib.parse import urlsplit

from . import settings as nsettings
from . import signing, ssrf

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
TEAMS_COLOR = {"critical": "attention", "high": "attention", "medium": "warning", "low": "accent", "info": "default"}
EMAIL_COLOR = {"critical": "#d13438", "high": "#e3730b", "medium": "#c19c00", "low": "#2f7bd9", "info": "#6b7280"}
SMTP_PORTS = {25, 465, 587, 2525}
EMAIL_RE = re.compile(r"^[^@\s<>,;\"']+@[^@\s<>,;\"']+\.[^@\s<>,;\"']+$")
MAX_RECIPIENTS = 20


class ChannelConfigError(ValueError):
    """Invalid channel configuration (HTTP 422 on save; permanent on send)."""


class PermanentError(Exception):
    """Delivery failed and retrying will not help (dead-lettered immediately)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class TransientError(Exception):
    """Delivery failed but may succeed later (retried with backoff)."""

    def __init__(self, message: str, status: int | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


@dataclass
class SendResult:
    status: int | None
    detail: str = ""


@dataclass
class FieldSpec:
    name: str
    label: str
    kind: str = "text"  # text | url | int | list | select | email
    secret: bool = False
    required: bool = False
    help: str = ""
    options: list[str] = field(default_factory=list)
    default: Any = None
    # For email: which provider the field belongs to ("" = both).
    provider: str = ""
    mask: str = "secret"  # how secret_hints are rendered: secret | url | connection_string


CHANNEL_TYPES: dict[str, dict[str, Any]] = {
    "teams": {
        "label": "Microsoft Teams",
        "description": "Incoming webhook or Teams Workflows webhook (Adaptive Card).",
        "fields": [FieldSpec("webhook_url", "Webhook URL", "url", secret=True, required=True, mask="url",
                             help="Teams channel -> Workflows -> 'Post to a channel when a webhook request is "
                                  "received' (or a legacy Incoming Webhook connector).")],
    },
    "slack": {
        "label": "Slack",
        "description": "Slack incoming webhook (Block Kit).",
        "fields": [FieldSpec("webhook_url", "Webhook URL", "url", secret=True, required=True, mask="url",
                             help="https://hooks.slack.com/services/... from a Slack app with Incoming Webhooks.")],
    },
    "email": {
        "label": "Email",
        "description": "SMTP with STARTTLS/TLS, or Azure Communication Services Email.",
        "fields": [
            FieldSpec("provider", "Provider", "select", options=["smtp", "acs"], default="smtp", required=True),
            FieldSpec("to_addresses", "Recipients", "list", required=True, help="Comma-separated email addresses."),
            FieldSpec("from_address", "From address", "email", provider="smtp", help="Sender, e.g. cnapp@example.com"),
            FieldSpec("host", "SMTP host", "text", provider="smtp"),
            FieldSpec("port", "SMTP port", "int", provider="smtp", default=587),
            FieldSpec("security", "Transport security", "select", provider="smtp", options=["starttls", "tls"],
                      default="starttls", help="starttls (port 587) or implicit tls (port 465)."),
            FieldSpec("username", "SMTP username", "text", provider="smtp"),
            FieldSpec("password", "SMTP password", "text", secret=True, provider="smtp"),
            FieldSpec("sender_address", "Sender address", "email", provider="acs",
                      help="A MailFrom address of a domain connected to your ACS Email resource."),
            FieldSpec("connection_string", "ACS connection string", "text", secret=True, provider="acs",
                      mask="connection_string", help="endpoint=https://<name>.communication.azure.com/;accesskey=..."),
        ],
    },
    "webhook": {
        "label": "Signed webhook",
        "description": "Generic JSON POST signed with HMAC-SHA256 (X-CNAPP-Signature) and a timestamp.",
        "fields": [
            FieldSpec("url", "Endpoint URL", "url", secret=True, required=True, mask="url"),
            FieldSpec("signing_secret", "Signing secret", "text", secret=True, required=True,
                      help=f"At least {signing.MIN_SECRET_LENGTH} characters; share it with the receiver."),
        ],
    },
}


def field_specs(ctype: str) -> list[FieldSpec]:
    return CHANNEL_TYPES[ctype]["fields"]


def secret_fields(ctype: str) -> list[FieldSpec]:
    return [f for f in field_specs(ctype) if f.secret]


def hints(ctype: str, secrets: dict[str, str]) -> dict[str, str]:
    from .crypto import mask

    return {f.name: mask(secrets[f.name], kind=f.mask) for f in secret_fields(ctype) if secrets.get(f.name)}


# --- validation ---------------------------------------------------------------------

def _emails(value: Any, label: str) -> list[str]:
    items = value if isinstance(value, list) else re.split(r"[,;\s]+", str(value or ""))
    out = []
    for raw in items:
        addr = str(raw).strip()
        if not addr:
            continue
        if not EMAIL_RE.match(addr) or "\r" in addr or "\n" in addr:
            raise ChannelConfigError(f"{label}: invalid email address {addr!r}")
        out.append(addr)
    if len(out) > MAX_RECIPIENTS:
        raise ChannelConfigError(f"{label}: at most {MAX_RECIPIENTS} recipients")
    return out


def _check_url_field(url: str, kind: str, label: str) -> str:
    url = (url or "").strip()
    if len(url) > 2048:
        raise ChannelConfigError(f"{label}: URL too long")
    try:
        ssrf.check_url(url, kind, resolve_dns=False)
    except ssrf.BlockedDestination as exc:
        raise ChannelConfigError(f"{label}: {exc}") from None
    return url


def parse_connection_string(cs: str) -> tuple[str, str]:
    parts = {}
    for p in (cs or "").split(";"):
        if "=" in p:
            k, v = p.split("=", 1)
            parts[k.strip().lower()] = v.strip()
    endpoint, key = parts.get("endpoint", ""), parts.get("accesskey", "")
    if not endpoint or not key:
        raise ChannelConfigError("ACS connection string must contain endpoint=...;accesskey=...")
    try:
        base64.b64decode(key, validate=True)
    except ValueError:
        raise ChannelConfigError("ACS access key is not valid base64") from None
    return endpoint.rstrip("/"), key


def validate(ctype: str, config: dict[str, Any], secrets: dict[str, str]) -> tuple[dict[str, Any], dict[str, str]]:
    """Normalize + validate a full channel configuration. Raises ChannelConfigError."""
    if ctype not in CHANNEL_TYPES:
        raise ChannelConfigError(f"unknown channel type {ctype!r}")
    config = dict(config or {})
    secrets = {k: (v or "").strip() for k, v in (secrets or {}).items() if v is not None}
    allowed_cfg = {f.name for f in field_specs(ctype) if not f.secret}
    allowed_sec = {f.name for f in secret_fields(ctype)}
    unknown = (set(config) - allowed_cfg) | (set(secrets) - allowed_sec)
    if unknown:
        raise ChannelConfigError(f"unknown field(s) for {ctype}: {', '.join(sorted(unknown))}")
    s = nsettings.get()
    if ctype in ("teams", "slack"):
        if not secrets.get("webhook_url"):
            raise ChannelConfigError("webhook_url is required")
        secrets["webhook_url"] = _check_url_field(secrets["webhook_url"], ctype, "webhook_url")
        return {}, secrets
    if ctype == "webhook":
        if not secrets.get("url"):
            raise ChannelConfigError("url is required")
        secrets["url"] = _check_url_field(secrets["url"], "webhook", "url")
        if len(secrets.get("signing_secret", "")) < signing.MIN_SECRET_LENGTH:
            raise ChannelConfigError(f"signing_secret must be at least {signing.MIN_SECRET_LENGTH} characters")
        return {}, secrets
    # email
    provider = (config.get("provider") or "smtp").strip().lower()
    if provider not in ("smtp", "acs"):
        raise ChannelConfigError("provider must be smtp or acs")
    to = _emails(config.get("to_addresses"), "to_addresses")
    if not to:
        raise ChannelConfigError("at least one recipient is required")
    if provider == "acs":
        sender = (config.get("sender_address") or "").strip()
        if not EMAIL_RE.match(sender):
            raise ChannelConfigError("sender_address must be an email address")
        endpoint, _ = parse_connection_string(secrets.get("connection_string", ""))
        _check_url_field(endpoint + "/emails:send", "acs", "connection_string endpoint")
        return ({"provider": "acs", "to_addresses": to, "sender_address": sender},
                {"connection_string": secrets["connection_string"]})
    host = (config.get("host") or "").strip().lower().rstrip(".")
    if not host or not re.match(r"^[a-z0-9.-]+$|^\[?[0-9a-f:.]+\]?$", host):
        raise ChannelConfigError("host must be a hostname")
    try:
        port = int(config.get("port") or 587)
    except (TypeError, ValueError):
        raise ChannelConfigError("port must be a number") from None
    if port not in SMTP_PORTS and not s.insecure_dev:
        raise ChannelConfigError(f"port must be one of {sorted(SMTP_PORTS)}")
    security = (config.get("security") or "starttls").strip().lower()
    if security not in ("starttls", "tls") and not (security == "none" and s.insecure_dev):
        raise ChannelConfigError("security must be starttls or tls")
    sender = (config.get("from_address") or "").strip()
    if not EMAIL_RE.match(sender):
        raise ChannelConfigError("from_address must be an email address")
    username = (config.get("username") or "").strip()
    if username and not secrets.get("password"):
        raise ChannelConfigError("password is required when a username is set")
    out_secrets = {"password": secrets["password"]} if secrets.get("password") else {}
    return ({"provider": "smtp", "to_addresses": to, "from_address": sender, "host": host, "port": port,
             "security": security, "username": username}, out_secrets)


# --- rendering ------------------------------------------------------------------------

def _clip(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _teams_text(s: str) -> str:
    # Adaptive Card TextBlocks render a markdown subset: break link syntax that
    # could come from attacker-controlled strings.
    return (s or "").replace("](", "]​(").replace("<", "‹").replace(">", "›")


def render_teams(msg: dict[str, Any]) -> dict[str, Any]:
    sev = msg.get("severity", "info")
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": f"{SEV_EMOJI.get(sev, '')} {sev.upper()} · {_teams_text(msg.get('source_label', ''))}",
         "weight": "Bolder", "color": TEAMS_COLOR.get(sev, "default"), "spacing": "None", "wrap": True},
        {"type": "TextBlock", "text": _teams_text(_clip(msg.get("title", ""), 250)), "size": "Large",
         "weight": "Bolder", "wrap": True},
    ]
    if msg.get("summary"):
        body.append({"type": "TextBlock", "text": _teams_text(_clip(msg["summary"], 1500)), "wrap": True})
    facts = [{"title": _teams_text(k), "value": _teams_text(_clip(str(v), 300))} for k, v in msg.get("facts", [])]
    if facts:
        body.append({"type": "FactSet", "facts": facts})
    for it in (msg.get("items") or [])[:25]:  # digest
        line = f"{SEV_EMOJI.get(it['severity'], '')} **{it['severity'].upper()}** {_teams_text(_clip(it['title'], 200))}"
        body.append({"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"})
    if msg.get("items") and msg.get("total", 0) > len(msg["items"][:25]):
        body.append({"type": "TextBlock", "text": f"…and {msg['total'] - 25} more", "isSubtle": True})
    card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "body": body, "msteams": {"width": "Full"}}
    if msg.get("link"):
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in CloudSecurity", "url": msg["link"]}]
    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def _slack_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_slack(msg: dict[str, Any]) -> dict[str, Any]:
    sev = msg.get("severity", "info")
    title = _clip(msg.get("title", ""), 140)
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{SEV_EMOJI.get(sev, '')} {title}", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn",
                                          "text": f"*{sev.upper()}* · {_slack_escape(msg.get('source_label', ''))}"}]},
    ]
    if msg.get("summary"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(_clip(msg["summary"], 2900))}})
    fields = [{"type": "mrkdwn", "text": f"*{_slack_escape(k)}*\n{_slack_escape(_clip(str(v), 300))}"}
              for k, v in msg.get("facts", [])][:10]
    if fields:
        blocks.append({"type": "section", "fields": fields})
    items = (msg.get("items") or [])[:25]
    if items:
        lines = []
        for it in items:
            t = _slack_escape(_clip(it["title"], 150))
            if it.get("link"):
                t = f"<{it['link']}|{t.replace('|', '¦')}>"
            lines.append(f"{SEV_EMOJI.get(it['severity'], '')} *{it['severity'].upper()}* {t}")
        if msg.get("total", 0) > len(items):
            lines.append(f"…and {msg['total'] - len(items)} more")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _clip("\n".join(lines), 2900)}})
    if msg.get("link"):
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open in CloudSecurity"}, "url": msg["link"],
             **({"style": "danger"} if sev in ("critical", "high") else {})}]})
    # `text` is the notification / fallback text; escaped so it cannot @-mention.
    return {"text": _slack_escape(f"[{sev.upper()}] {title}"), "blocks": blocks, "unfurl_links": False}


def render_webhook(msg: dict[str, Any], delivery_id: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": delivery_id, "type": f"cnapp.notification.{msg.get('kind', 'event')}",
                               "version": "1", "title": msg.get("title"), "severity": msg.get("severity"),
                               "link": msg.get("link")}
    if msg.get("kind") == "digest":
        payload["digest"] = {"rule": msg.get("rule_name"), "total": msg.get("total"),
                             "items": [{k: it.get(k) for k in ("severity", "title", "source", "link")}
                                       for it in msg.get("items", [])]}
    else:
        payload["event"] = msg.get("event") or {}
        payload["suppressed_since_last"] = msg.get("suppressed", 0)
    return payload


def _header_safe(s: str) -> str:
    return re.sub(r"[\r\n\t]+", " ", s or "").strip()


def render_email(msg: dict[str, Any]) -> tuple[str, str, str]:
    sev = msg.get("severity", "info")
    subject = _clip(_header_safe(f"[CNAPP][{sev.upper()}] {msg.get('title', '')}"), 200)
    lines = [msg.get("title", ""), "", msg.get("summary", ""), ""]
    lines += [f"{k}: {v}" for k, v in msg.get("facts", [])]
    for it in msg.get("items") or []:
        lines.append(f"- [{it['severity'].upper()}] {it['title']}" + (f"  {it['link']}" if it.get("link") else ""))
    if msg.get("link"):
        lines += ["", f"Open in CloudSecurity: {msg['link']}"]
    text = "\n".join(lines).strip() + "\n"
    e = html.escape
    color = EMAIL_COLOR.get(sev, "#6b7280")
    facts = "".join(f"<tr><td style=\"padding:2px 12px 2px 0;color:#6b7280\">{e(str(k))}</td>"
                    f"<td style=\"padding:2px 0\">{e(str(v))}</td></tr>" for k, v in msg.get("facts", []))
    items = "".join(
        f"<li><b style=\"color:{EMAIL_COLOR.get(it['severity'], '#6b7280')}\">{e(it['severity'].upper())}</b> "
        + (f"<a href=\"{e(it['link'], quote=True)}\">{e(it['title'])}</a>" if it.get("link") else e(it["title"]))
        + "</li>" for it in msg.get("items") or [])
    button = (f"<p><a href=\"{e(msg['link'], quote=True)}\" style=\"display:inline-block;background:#2563eb;"
              f"color:#fff;padding:8px 14px;border-radius:4px;text-decoration:none\">Open in CloudSecurity</a></p>"
              if msg.get("link") else "")
    body_html = (
        "<!doctype html><html><body style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111\">"
        f"<div style=\"border-left:4px solid {color};padding:4px 12px\">"
        f"<div style=\"color:{color};font-weight:600\">{e(sev.upper())} · {e(msg.get('source_label', ''))}</div>"
        f"<h2 style=\"margin:4px 0 8px\">{e(msg.get('title', ''))}</h2>"
        f"<p style=\"white-space:pre-wrap\">{e(msg.get('summary', ''))}</p>"
        f"<table style=\"border-collapse:collapse;font-size:13px\">{facts}</table>"
        + (f"<ul>{items}</ul>" if items else "") + button +
        "</div><p style=\"color:#9ca3af;font-size:12px\">Sent by CloudSecurity CNAPP notifications.</p>"
        "</body></html>")
    return subject, text, body_html


def render_preview(ctype: str, msg: dict[str, Any]) -> Any:
    if ctype == "teams":
        return render_teams(msg)
    if ctype == "slack":
        return render_slack(msg)
    if ctype == "webhook":
        return render_webhook(msg, "preview")
    subject, text, _ = render_email(msg)
    return {"subject": subject, "text": text}


# --- sending -----------------------------------------------------------------------------

def _retry_after(headers: dict[str, str]) -> float | None:
    try:
        return float(headers.get("retry-after", ""))
    except ValueError:
        return None


def _classify(resp: ssrf.HttpResponse, ctype: str) -> SendResult:
    snippet = resp.body[:300].decode("utf-8", "replace").strip()
    if 300 <= resp.status < 400:
        raise PermanentError(f"HTTP {resp.status}: redirects are not followed (location hidden)", resp.status)
    if resp.status in (408, 425, 429) or resp.status >= 500:
        raise TransientError(f"HTTP {resp.status}: {snippet}", resp.status, _retry_after(resp.headers))
    if resp.status >= 400:
        raise PermanentError(f"HTTP {resp.status}: {snippet}", resp.status)
    # Legacy Teams connectors answer 200 with an error text when throttled.
    if ctype == "teams" and resp.status == 200 and snippet not in ("", "1") and "error" in snippet.lower():
        raise TransientError(f"HTTP 200 with error: {snippet}", resp.status)
    return SendResult(resp.status, snippet[:200])


def _post_json(url: str, payload: Any, ctype: str, extra_headers: dict[str, str] | None = None,
               *, body: bytes | None = None) -> SendResult:
    data = body if body is not None else json.dumps(payload, separators=(",", ":")).encode()
    try:
        resp = ssrf.post(url, data, {"Content-Type": "application/json", **(extra_headers or {})}, kind=ctype)
    except ssrf.BlockedDestination as exc:
        raise PermanentError(f"blocked: {exc}") from None
    except ssrf.DeliveryHTTPError as exc:
        raise TransientError(str(exc)) from None
    return _classify(resp, ctype)


def send_webhook(secrets: dict[str, str], msg: dict[str, Any], delivery_id: str, *, now: int | None = None) -> SendResult:
    body = json.dumps(render_webhook(msg, delivery_id), separators=(",", ":"), sort_keys=True).encode()
    headers = signing.sign(secrets["signing_secret"], body, timestamp=now)
    headers[signing.DELIVERY_HEADER] = delivery_id
    headers[signing.EVENT_HEADER] = f"{msg.get('source', 'event')}.{msg.get('event_type', 'created')}"
    return _post_json(secrets["url"], None, "webhook", headers, body=body)


def acs_headers(endpoint: str, access_key: str, path_and_query: str, body: bytes, date: str) -> dict[str, str]:
    """HMAC-SHA256 request signing for Azure Communication Services."""
    host = urlsplit(endpoint).netloc
    content_hash = base64.b64encode(hashlib.sha256(body).digest()).decode()
    to_sign = f"POST\n{path_and_query}\n{date};{host};{content_hash}"
    sig = base64.b64encode(hmac.new(base64.b64decode(access_key), to_sign.encode(), hashlib.sha256).digest()).decode()
    return {"x-ms-date": date, "x-ms-content-sha256": content_hash,
            "Authorization": f"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={sig}"}


ACS_PATH = "/emails:send?api-version=2023-03-31"


def send_acs(config: dict[str, Any], secrets: dict[str, str], msg: dict[str, Any], delivery_id: str) -> SendResult:
    endpoint, key = parse_connection_string(secrets.get("connection_string", ""))
    subject, text, body_html = render_email(msg)
    payload = {"senderAddress": config["sender_address"],
               "recipients": {"to": [{"address": a} for a in config["to_addresses"]]},
               "content": {"subject": subject, "plainText": text, "html": body_html},
               "userEngagementTrackingDisabled": True}
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = acs_headers(endpoint, key, ACS_PATH, body, formatdate(usegmt=True))
    # Idempotent retries: ACS de-duplicates on the operation id.
    headers["Operation-Id"] = delivery_id
    return _post_json(endpoint + ACS_PATH, None, "acs", headers, body=body)


class _PinnedSMTP(smtplib.SMTP):
    """SMTP to a pre-validated IP; STARTTLS verifies the certificate for the hostname."""

    def __init__(self, ip: str, **kw):
        self._pinned_ip = ip
        super().__init__(**kw)

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self._pinned_ip, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, ip: str, **kw):
        self._pinned_ip = ip
        super().__init__(**kw)

    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((self._pinned_ip, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self._host)


def _smtp_target(host: str, port: int) -> str:
    s = nsettings.get()
    try:
        addrs = ssrf.resolve(host, port)
    except ssrf.DeliveryHTTPError as exc:
        raise TransientError(str(exc)) from None
    for a in addrs:
        problem = ssrf.address_problem(a, allow_private=s.smtp_allow_private or s.insecure_dev,
                                       allow_loopback=s.insecure_dev)
        if problem:
            raise PermanentError(f"blocked: SMTP host {host} resolves to a blocked address: {problem}"
                                 + (" (set NOTIFICATIONS_SMTP_ALLOW_PRIVATE=true for an internal relay)"
                                    if "private" in problem else ""))
    return str(addrs[0])


def send_smtp(config: dict[str, Any], secrets: dict[str, str], msg: dict[str, Any], delivery_id: str) -> SendResult:
    s = nsettings.get()
    host, port, security = config["host"], int(config.get("port") or 587), config.get("security", "starttls")
    ip = _smtp_target(host, port)
    subject, text, body_html = render_email(msg)
    em = EmailMessage()
    em["Subject"] = subject
    em["From"] = config["from_address"]
    em["To"] = ", ".join(config["to_addresses"])
    em["Date"] = formatdate(localtime=False, usegmt=True)
    em["Message-ID"] = make_msgid(idstring=delivery_id[:16], domain=parseaddr(config["from_address"])[1].split("@")[-1])
    em["X-CNAPP-Delivery"] = delivery_id
    em.set_content(text)
    em.add_alternative(body_html, subtype="html")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    timeout = s.connect_timeout + s.read_timeout
    try:
        if security == "tls":
            smtp: smtplib.SMTP = _PinnedSMTPSSL(ip, timeout=timeout, context=ctx)
        else:
            smtp = _PinnedSMTP(ip, timeout=timeout)
        with smtp:
            smtp.connect(host, port)
            smtp.ehlo()
            if security == "starttls":
                if not smtp.has_extn("starttls"):
                    raise PermanentError("SMTP server does not offer STARTTLS")
                smtp.starttls(context=ctx)
                smtp.ehlo()
            if config.get("username"):
                smtp.login(config["username"], secrets.get("password", ""))
            refused = smtp.send_message(em)
    except PermanentError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise PermanentError(f"SMTP authentication failed ({exc.smtp_code})") from None
    except smtplib.SMTPRecipientsRefused as exc:
        raise PermanentError(f"all recipients refused: {sorted(exc.recipients)}") from None
    except smtplib.SMTPResponseException as exc:
        detail = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
        err = f"SMTP {exc.smtp_code}: {detail[:200]}"
        if 400 <= exc.smtp_code < 500:
            raise TransientError(err) from None
        raise PermanentError(err) from None
    except ssl.SSLCertVerificationError as exc:
        raise PermanentError(f"TLS certificate verification failed: {exc.verify_message}") from None
    except (smtplib.SMTPException, OSError) as exc:
        raise TransientError(f"{type(exc).__name__}: {exc}") from None
    if refused:
        return SendResult(250, f"accepted with refused recipients: {sorted(refused)}")
    return SendResult(250, "accepted")


def send(ctype: str, config: dict[str, Any], secrets: dict[str, str], msg: dict[str, Any],
         delivery_id: str) -> SendResult:
    """Deliver `msg`. Raises PermanentError / TransientError on failure."""
    try:
        if ctype == "teams":
            return _post_json(secrets["webhook_url"], render_teams(msg), "teams")
        if ctype == "slack":
            return _post_json(secrets["webhook_url"], render_slack(msg), "slack")
        if ctype == "webhook":
            return send_webhook(secrets, msg, delivery_id)
        if ctype == "email":
            if config.get("provider") == "acs":
                return send_acs(config, secrets, msg, delivery_id)
            return send_smtp(config, secrets, msg, delivery_id)
    except KeyError as exc:
        raise PermanentError(f"channel is missing required setting {exc}") from None
    except ChannelConfigError as exc:
        raise PermanentError(str(exc)) from None
    raise PermanentError(f"unknown channel type {ctype!r}")
