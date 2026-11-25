"""The invitation email: a plain transactional message, not the alert layout of
the notification channel (no "[CNAPP]" tags, severity or "notifications" footer,
which made invitations from a new sending domain look like phishing).

Three variants, one look (logo on a white band under a navy stripe, white card, button,
details box):

* partner: the platform invites someone into an organisation of kind 'msp'
  (brand only, no person named).
* customer: the platform, or the customer's MSP, invites a customer admin.
  Brand only: never the platform owner's name and never the MSP (docs/MSP.md:
  clients must not see the MSP, so nothing about the MSP reaches this mail).
* teammate: an organisation admin invites a teammate; the body names the
  inviter (display name and email address, or the address alone).

Every interpolated value is HTML-escaped in the HTML part and kept on one line
in the subject (no header injection). No tracking and no remote images: the
logo is an inline `cid:` image sent with the message (LOGO_CID, `logo_image()`),
inline styles only (Gmail strips <style> blocks in some clients)."""
from __future__ import annotations

import html
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from .. import config, modules
from ..notifications.channels import _clip, _header_safe

NO_REPLY = "This mailbox isn't monitored, please don't reply."
IGNORE = "If you weren't expecting this, you can ignore this email."
LOGO_CID = "sentrigis-logo"
LOGO_FILE = Path(__file__).resolve().parent.parent / "static" / "email" / "sentrigis-logo-email.png"
LOGO_WIDTH, LOGO_HEIGHT = 178, 49  # shown size (the PNG is 356x98, for high-density screens)

NAVY, BLUE, TEXT, MUTED = "#0f1d3a", "#2563eb", "#111827", "#6b7280"
FONT = "font-family:Arial,Helvetica,sans-serif"


@dataclass(frozen=True)
class Inviter:
    """The organisation admin who sent the invitation (teammate variant)."""

    email: str
    name: str = ""

    def label(self) -> str:
        name, email = _one_line(self.name, 128), _one_line(self.email, 320)
        return f"{name} ({email})" if name and email else (name or email)


def _one_line(s: str | None, n: int) -> str:
    return _clip(_header_safe(s or ""), n)


def _hours(hours: float) -> str:
    return f"{hours:g} hour" + ("" if hours == 1 else "s")


@lru_cache(maxsize=1)
def _logo_bytes() -> bytes:
    return LOGO_FILE.read_bytes()


def logo_image() -> tuple[str, str, bytes]:
    """(content id, media type, bytes) to send with the HTML (mailer `inline_images`)."""
    return LOGO_CID, "image/png", _logo_bytes()


def _role_word(role: str) -> str:
    return "administrator" if role == "admin" else role


def _console_host() -> str:
    base = (config.settings.public_base_url or "").strip()
    return _one_line(urlsplit(base).netloc if "//" in base else "", 255)


def _next_step(mods: list[str]) -> str:
    if modules.ENDPOINTS in mods:
        return "Install the agent on your computers and servers."
    if modules.CLOUD in mods or modules.EXTERNAL in mods:
        return "Connect your first cloud account or domain."
    return "Explore your console."


def render(*, org_name: str, role: str, link: str, ttl_hours: float, inviter: Inviter | None = None,
           org_kind: str = "customer", max_clients: int | None = None,
           enabled_modules: list[str] | None = None) -> tuple[str, str, str]:
    """(subject, plain text, html).

    Variant: `inviter` set = teammate; else `org_kind == "msp"` = partner; else customer
    (brand only). `max_clients` (partner) and `enabled_modules` (customer) fill the details."""
    brand = _one_line(config.settings.brand_name, 64)
    org = _one_line(org_name, 200)
    role = _one_line(role, 32)
    keys = modules.normalize(enabled_modules or [])
    expiry = f"This link works once and expires in {_hours(ttl_hours)}."
    steps: list[str] = []
    cta = "Accept invitation"
    label = ""  # small caps label above the heading
    list_title = ""
    pills: list[str] = []
    rows: list[tuple[str, str]] = [("Organisation", org), ("Your role", _role_word(role))]
    if inviter is not None:  # teammate: same wording as before, new look
        subject = f"You have been invited to join {org} on {brand}"
        heading = f"You're invited to join {org}"
        intro = [f"{inviter.label()} invited you as **{role}** to join **{org}** on {brand}."]
        rows = [("Organisation", org), ("Your role", role)]
    elif org_kind == "msp":  # partner
        subject = f"Your {brand} partner account is ready"
        label = "PARTNER ACCOUNT"
        heading = f"Welcome to {brand}, {org}"
        intro = [f"{brand} has set up a partner account for **{org}** and invited you as its "
                 f"**{_role_word(role)}**."]
        list_title = "With your partner account you can:"
        steps = ["Add your clients and choose the security modules each one needs.",
                 "Work inside each client's console with one login.",
                 "Invite your own team as admins, analysts or viewers."]
        cta = "Set your password and sign in"
        if max_clients is not None:
            rows.append(("Client limit", f"{max_clients} clients"))
    else:  # customer
        subject = f"Your {brand} security console for {org} is ready"
        heading = f"Your security console for {org} is ready"
        intro = [f"You've been invited as **{_role_word(role)}** of **{org}** on {brand}."]
        pills = [modules.LABELS[m] for m in keys]
        list_title = "Get started in three steps"
        steps = ["Accept the invitation and choose your password.", _next_step(keys), "Invite your team."]
    host = _console_host()
    if host and inviter is None:
        rows.append(("Console", host))
    subject = _clip(_header_safe(subject), 200)

    # plain text
    t = [label] if label else []
    t += [heading, ""] + [p.replace("**", "") for p in intro] + [""]
    if pills:
        t += ["What's included: " + ", ".join(pills), ""]
    if steps:
        t += [list_title] + [f"{i}. {s}" for i, s in enumerate(steps, 1)] + [""]
    t += [f"{cta}:", link, ""] + [f"{k}: {v}" for k, v in rows] + ["", expiry, IGNORE, "", "--", brand, NO_REPLY]
    text = "\n".join(t) + "\n"

    # html
    e = html.escape
    href = e(link, quote=True)

    def bold(p: str) -> str:
        chunks = e(p).split("**")
        return "".join(f"<strong>{x}</strong>" if i % 2 else x for i, x in enumerate(chunks))

    def section_title(s: str) -> str:
        return f"<p style=\"margin:0 0 8px;font-weight:bold;color:{TEXT}\">{e(s)}</p>"

    parts: list[str] = []
    if label:
        parts.append(f"<p style=\"margin:0 0 8px;font-size:12px;line-height:16px;font-weight:bold;"
                     f"letter-spacing:1.5px;color:#2f5bea\">{e(label)}</p>")
    parts.append(f"<h1 style=\"margin:0 0 16px;font-size:22px;line-height:30px;font-weight:bold;color:{TEXT}\">"
                 f"{e(heading)}</h1>")
    parts += [f"<p style=\"margin:0 0 16px\">{bold(p)}</p>" for p in intro]
    if pills:
        parts.append(section_title("What's included"))
        parts.append("<p style=\"margin:0 0 16px;line-height:30px\">" + " ".join(
            "<span style=\"display:inline-block;padding:0 10px;margin:0 6px 4px 0;background:#eef3fd;color:#1f3b8a;"
            f"font-size:13px;line-height:24px;font-weight:bold;border-radius:12px\">{e(m)}</span>" for m in pills)
            + "</p>")
    if steps:
        parts.append(section_title(list_title))
        parts.append("<ol style=\"margin:0 0 20px;padding:0 0 0 22px\">" + "".join(
            f"<li style=\"margin:0 0 4px\">{e(s)}</li>" for s in steps) + "</ol>")
    parts.append(
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:0 0 24px\">"
        f"<tr><td align=\"center\" bgcolor=\"{BLUE}\" style=\"border-radius:6px;background:{BLUE}\">"
        f"<a href=\"{href}\" target=\"_blank\" style=\"display:inline-block;padding:12px 24px;{FONT};font-size:15px;"
        f"font-weight:bold;color:#ffffff;text-decoration:none;border-radius:6px\">{e(cta)}</a></td></tr></table>")
    parts.append(
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
        "style=\"margin:0 0 24px;background:#f7f8fa;border:1px solid #eef0f4;border-radius:6px\">"
        + "".join(f"<tr><td style=\"padding:10px 16px 0;{FONT};font-size:13px;line-height:20px;color:{MUTED};"
                  f"width:110px;vertical-align:top\">{e(k)}</td><td style=\"padding:10px 16px 0;{FONT};"
                  f"font-size:13px;line-height:20px;font-weight:bold;color:{TEXT}\">{e(v)}</td></tr>"
                  for k, v in rows)
        + "<tr><td colspan=\"2\" style=\"height:10px;font-size:0;line-height:0\">&nbsp;</td></tr></table>")
    parts.append(f"<p style=\"margin:0 0 8px;color:#374151\">{e(expiry)}</p>")
    parts.append(f"<p style=\"margin:0 0 24px;color:#374151\">{e(IGNORE)}</p>")
    parts.append(f"<p style=\"margin:0;font-size:12px;line-height:18px;color:{MUTED}\">If the button doesn't work, "
                 f"copy this link into your browser:<br><a href=\"{href}\" style=\"color:{BLUE};word-break:break-all\">"
                 f"{e(link)}</a></p>")
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
        # White band under a navy stripe: the logo PNG has a white background, so it cannot sit on navy.
        f"<tr><td bgcolor=\"#ffffff\" style=\"background:#ffffff;padding:20px 32px 16px;border-top:6px solid {NAVY};"
        "border-bottom:1px solid #eef0f4;border-radius:8px 8px 0 0\">"
        f"<img src=\"cid:{LOGO_CID}\" alt=\"{e(brand, quote=True)}\" width=\"{LOGO_WIDTH}\" height=\"{LOGO_HEIGHT}\" "
        f"style=\"display:block;border:0;width:{LOGO_WIDTH}px;height:{LOGO_HEIGHT}px\"></td></tr>"
        f"<tr><td style=\"padding:32px;{FONT};font-size:15px;line-height:22px;color:{TEXT}\">"
        + "".join(parts) +
        "</td></tr></table>"
        f"<p style=\"margin:16px 0 0;{FONT};font-size:12px;line-height:18px;color:{MUTED}\">"
        f"{e(brand)}<br>{e(NO_REPLY)}</p>"
        "</td></tr></table></body></html>")
    return subject, text, body_html
