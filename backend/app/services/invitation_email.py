"""The invitation email: a plain transactional message, not the alert layout of
the notification channel (no "[CNAPP]" tags, severity or "notifications" footer,
which made invitations from a new sending domain look like phishing).

Two variants:

* platform: a platform owner invites someone into an organisation (usually a
  customer's first admin). The inviter shown is only the brand, never the
  platform owner's name or address.
* organisation: an organisation admin invites a teammate. The body names the
  inviter (display name and email address, or the address alone when the
  account has no name).

Every interpolated value is HTML-escaped in the HTML part and kept on one line
in the subject (no header injection). No images, no tracking, inline styles
only (Gmail strips <style> blocks in some clients)."""
from __future__ import annotations

import html
from dataclasses import dataclass

from .. import config
from ..notifications.channels import _clip, _header_safe

NO_REPLY = "This mailbox isn't monitored, please don't reply."
IGNORE = "If you weren't expecting this, you can ignore this email."


@dataclass(frozen=True)
class Inviter:
    """The organisation admin who sent the invitation (organisation variant)."""

    email: str
    name: str = ""

    def label(self) -> str:
        name, email = _one_line(self.name, 128), _one_line(self.email, 320)
        return f"{name} ({email})" if name and email else (name or email)


def _one_line(s: str | None, n: int) -> str:
    return _clip(_header_safe(s or ""), n)


def _hours(hours: float) -> str:
    return f"{hours:g} hour" + ("" if hours == 1 else "s")


def render(*, org_name: str, role: str, link: str, ttl_hours: float,
           inviter: Inviter | None = None) -> tuple[str, str, str]:
    """(subject, plain text, html). `inviter` None = platform variant (brand only)."""
    brand = _one_line(config.settings.brand_name, 64)
    org = _one_line(org_name, 200)
    role = _one_line(role, 32)
    expiry = f"This link works once and expires in {_hours(ttl_hours)}."
    if inviter is None:
        subject = f"You've been invited to join {org} on {brand}"
        who = brand
    else:
        subject = f"You have been invited to join {org} on {brand}"
        who = inviter.label()
    subject = _clip(_header_safe(subject), 200)
    on_brand = "" if inviter is None else f" on {brand}"  # the platform variant already names the brand
    intro = f"{who} invited you as {role} to join {org}{on_brand}."

    text = "\n".join([
        f"You're invited to join {org} on {brand}", "",
        intro, "",
        "Accept the invitation and choose your password:", link, "",
        expiry,
        IGNORE, "",
        "--",
        brand,
        NO_REPLY,
    ]) + "\n"

    e = html.escape
    href = e(link, quote=True)
    body_html = (
        "<!doctype html>"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{e(subject)}</title></head>"
        "<body style=\"margin:0;padding:0;background:#f4f5f7\">"
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
        "style=\"background:#f4f5f7\"><tr><td align=\"center\" style=\"padding:24px 12px\">"
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
        "style=\"max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px\">"
        "<tr><td style=\"padding:32px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:22px;"
        "color:#111827\">"
        f"<p style=\"margin:0 0 20px;font-size:13px;font-weight:bold;color:#374151\">{e(brand)}</p>"
        f"<h1 style=\"margin:0 0 16px;font-size:20px;line-height:28px;font-weight:bold;color:#111827\">"
        f"You're invited to join {e(org)}</h1>"
        f"<p style=\"margin:0 0 24px\">{e(who)} invited you as <strong>{e(role)}</strong> to join "
        f"<strong>{e(org)}</strong>{e(on_brand)}.</p>"
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:0 0 24px\">"
        "<tr><td align=\"center\" bgcolor=\"#2563eb\" style=\"border-radius:6px;background:#2563eb\">"
        f"<a href=\"{href}\" target=\"_blank\" style=\"display:inline-block;padding:12px 24px;"
        "font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#ffffff;"
        "text-decoration:none;border-radius:6px\">Accept invitation</a></td></tr></table>"
        f"<p style=\"margin:0 0 8px;color:#374151\">{e(expiry)}</p>"
        f"<p style=\"margin:0 0 24px;color:#374151\">{e(IGNORE)}</p>"
        "<p style=\"margin:0;font-size:12px;line-height:18px;color:#6b7280\">If the button doesn't work, copy "
        f"this link into your browser:<br><a href=\"{href}\" style=\"color:#2563eb;word-break:break-all\">"
        f"{e(link)}</a></p>"
        "</td></tr></table>"
        "<p style=\"margin:16px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;"
        f"color:#6b7280\">{e(brand)}<br>{e(NO_REPLY)}</p>"
        "</td></tr></table></body></html>")
    return subject, text, body_html
