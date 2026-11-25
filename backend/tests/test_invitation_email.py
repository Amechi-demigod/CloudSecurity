"""The invitation email (app/services/invitation_email.py) and its delivery
through the platform mailer (SMTP and ACS senders of the notification channel,
faked: no network, no real email)."""
from __future__ import annotations

import base64
import json
import re
import socket

import pytest

from app import config, mailer
from app.notifications import channels as ch
from app.notifications import ssrf
from app.services.invitation_email import LOGO_CID, Inviter, logo_image, render

LINK = "https://cnapp.example.com/invite#token=cnv_abc123"
ORG_ADMIN = Inviter("jane@example.com", "Jane Doe")


@pytest.fixture(autouse=True)
def _brand(monkeypatch):
    monkeypatch.setenv("BRAND_NAME", "Sentrigis")
    config.reload_settings()
    yield
    monkeypatch.undo()
    config.reload_settings()


ALL = ["cloud", "endpoints", "vulnerabilities", "assets", "external"]


def _srcs(body_html):
    return re.findall(r'<img[^>]*\ssrc="([^"]*)"', body_html)


def test_customer_variant_is_brand_only():
    subject, text, body_html = render(org_name="Acme Ltd", role="admin", link=LINK, ttl_hours=72,
                                      enabled_modules=ALL)
    assert subject == "Your Sentrigis security console for Acme Ltd is ready"
    assert "You've been invited as administrator of Acme Ltd on Sentrigis." in text
    assert "<strong>administrator</strong>" in body_html and "Your security console for Acme Ltd is ready" in body_html
    for part in (subject, text, body_html):
        assert "[CNAPP]" not in part and "jane" not in part.lower() and "@" not in part.replace(LINK, "")
        assert "partner" not in part.lower()
    assert LINK in text and f'href="{LINK}"' in body_html and ">Accept invitation</a>" in body_html
    assert "This link works once and expires in 72 hours." in text and "expires in 72 hours" in body_html
    for line in ("If you weren't expecting this, you can ignore this email.",
                 "This mailbox isn't monitored, please don't reply."):
        assert line in text
        assert line.replace("'", "&#x27;") in body_html
    assert ("What's included: Cloud security, Endpoints & servers, Vulnerabilities, Assets & identity, "
            "Attack surface & pre-ASV") in text
    assert "Endpoints &amp; servers</span>" in body_html and "#eef3fd" in body_html
    assert ("1. Accept the invitation and choose your password.\n2. Install the agent on your computers and servers.\n"
            "3. Invite your team.") in text
    assert "Organisation: Acme Ltd\nYour role: administrator" in text
    assert "Client limit" not in text and "Set your password" not in body_html


def test_customer_modules_section_and_second_step():
    _, text, body_html = render(org_name="Acme", role="viewer", link=LINK, ttl_hours=72, enabled_modules=[])
    assert "What's included" not in text and "What's included" not in body_html and "#eef3fd" not in body_html
    assert "2. Explore your console." in text and "as viewer of" in text
    _, text, _ = render(org_name="Acme", role="admin", link=LINK, ttl_hours=72, enabled_modules=["external"])
    assert "What's included: Attack surface & pre-ASV" in text
    assert "2. Connect your first cloud account or domain." in text
    _, text, _ = render(org_name="Acme", role="admin", link=LINK, ttl_hours=72, enabled_modules=["cloud", "endpoints"])
    assert "2. Install the agent" in text
    _, text, _ = render(org_name="Acme", role="admin", link=LINK, ttl_hours=72, enabled_modules=["assets"])
    assert "2. Explore your console." in text


def test_partner_variant(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://console.example.com")
    config.reload_settings()
    subject, text, body_html = render(org_name="Zeta MSP", role="admin", link=LINK, ttl_hours=72, org_kind="msp",
                                      max_clients=25)
    assert subject == "Your Sentrigis partner account is ready"
    assert "PARTNER ACCOUNT" in text and "Welcome to Sentrigis, Zeta MSP" in text
    assert "Sentrigis has set up a partner account for Zeta MSP and invited you as its administrator." in text
    assert ("With your partner account you can:\n1. Add your clients and choose the security modules each one needs."
            "\n2. Work inside each client's console with one login.\n3. Invite your own team as admins, analysts "
            "or viewers.") in text
    assert "Set your password and sign in:" in text and ">Set your password and sign in</a>" in body_html
    assert ("Organisation: Zeta MSP\nYour role: administrator\nClient limit: 25 clients\n"
            "Console: console.example.com") in text
    assert "<ol" in body_html and "letter-spacing" in body_html and "#2f5bea" in body_html
    for part in (subject, text, body_html):
        assert "jane" not in part.lower() and "@" not in part.replace(LINK, "")
    # No client limit / no console address: the rows are omitted.
    monkeypatch.delenv("PUBLIC_BASE_URL")
    config.reload_settings()
    _, text, body_html = render(org_name="Zeta MSP", role="analyst", link=LINK, ttl_hours=72, org_kind="msp",
                                max_clients=None)
    assert "Client limit" not in text and "Client limit" not in body_html and "Console" not in text
    assert "invited you as its analyst." in text


def test_variant_selection_inviter_wins_over_kind():
    subject, *_ = render(org_name="Zeta MSP", role="admin", link=LINK, ttl_hours=72, org_kind="msp",
                         inviter=ORG_ADMIN)
    assert subject == "You have been invited to join Zeta MSP on Sentrigis"


def test_teammate_variant_names_the_inviter():
    subject, text, body_html = render(org_name="Acme Ltd", role="analyst", link=LINK, ttl_hours=1,
                                      inviter=ORG_ADMIN)
    assert subject == "You have been invited to join Acme Ltd on Sentrigis"
    assert "Jane Doe (jane@example.com) invited you as analyst to join Acme Ltd on Sentrigis." in text
    assert "Jane Doe (jane@example.com) invited you as <strong>analyst</strong>" in body_html
    assert "Organisation: Acme Ltd\nYour role: analyst" in text and "Console" not in text
    assert "expires in 1 hour." in text
    # No display name on the account: the address alone.
    _, text, _ = render(org_name="Acme Ltd", role="viewer", link=LINK, ttl_hours=72,
                        inviter=Inviter("ops@example.com", ""))
    assert "ops@example.com invited you as viewer" in text


def test_new_look_and_inline_logo_only():
    for kw in ({}, {"org_kind": "msp"}, {"inviter": ORG_ADMIN}):
        _, _, body_html = render(org_name="Acme", role="admin", link=LINK, ttl_hours=72, **kw)
        assert _srcs(body_html) == [f"cid:{LOGO_CID}"]
        assert 'alt="Sentrigis"' in body_html and 'width="178"' in body_html and 'height="49"' in body_html
        assert "#0f1d3a" in body_html and "#f4f5f7" in body_html and "max-width:560px" in body_html
        assert "#2563eb" in body_html and "#f7f8fa" in body_html and "#eef0f4" in body_html
        assert not re.search(r"(?i)(src|background)\s*=\s*[\"']?https?:|url\(", body_html)
        assert "<style" not in body_html
    cid, mime, data = logo_image()
    assert cid == LOGO_CID and mime == "image/png" and data[:8] == b"\x89PNG\r\n\x1a\n"


def test_logo_alt_follows_brand_name(monkeypatch):
    monkeypatch.setenv("BRAND_NAME", 'Acme "Sec"')
    config.reload_settings()
    _, _, body_html = render(org_name="Acme", role="admin", link=LINK, ttl_hours=72)
    assert 'alt="Acme &quot;Sec&quot;"' in body_html


def test_interpolated_values_are_escaped_and_single_line():
    evil = 'Evil <script>alert(1)</script> "Co"\r\nBcc: victim@example.com'
    for kw in ({"inviter": Inviter("a@example.com", "<b>Mallory</b>\nX-Hdr: 1")}, {}, {"org_kind": "msp"}):
        subject, text, body_html = render(org_name=evil, role="admin", link=LINK + '"><img src=x>', ttl_hours=72, **kw)
        assert "\r" not in subject and "\n" not in subject and ("Evil" in subject or kw)
        assert "<script>" not in body_html and "&lt;script&gt;" in body_html
        assert '"><img src=x' not in body_html and "&quot;&gt;&lt;img" in body_html
        assert _srcs(body_html) == [f"cid:{LOGO_CID}"]  # only our logo, no injected image
        assert "\nBcc:" not in text
    _, text, body_html = render(org_name="x", role="admin", link=LINK, ttl_hours=72,
                                inviter=Inviter("a@example.com", "<b>Mallory</b>\nX-Hdr: 1"))
    assert "<b>Mallory</b>" not in body_html and "&lt;b&gt;Mallory&lt;/b&gt;" in body_html
    assert "Mallory</b> X-Hdr: 1 (a@example.com)" in text


def _mail_env(monkeypatch, **env):
    for k in ("PLATFORM_SMTP_HOST", "PLATFORM_SMTP_FROM", "PLATFORM_ACS_CONNECTION_STRING", "PLATFORM_ACS_SENDER"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config.reload_settings()


def test_smtp_delivery_is_multipart_alternative(monkeypatch):
    _mail_env(monkeypatch, PLATFORM_SMTP_HOST="smtp.example.com",
              PLATFORM_SMTP_FROM="Sentrigis <no-reply@example.com>")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda host, port, *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    sent = []

    class FakeSMTP:
        def __init__(self, ip, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def connect(self, host, port):
            pass

        def ehlo(self):
            pass

        def has_extn(self, name):
            return True

        def starttls(self, context):
            pass

        def send_message(self, em):
            sent.append(em)
            return {}

    monkeypatch.setattr(ch, "_PinnedSMTP", FakeSMTP)
    subject, text, body_html = render(org_name="Acme Ltd", role="admin", link=LINK, ttl_hours=72)
    assert mailer.send("boss@acme.test", subject, text, body_html).sent
    em = sent[0]
    assert em["Subject"] == subject and em["To"] == "boss@acme.test"
    assert em.get_content_type() == "multipart/alternative"
    parts = {p.get_content_type(): p.get_content() for p in em.iter_parts()}
    assert parts["text/plain"] == text and parts["text/html"].strip() == body_html


def test_smtp_delivery_embeds_the_logo_as_related_part(monkeypatch):
    _mail_env(monkeypatch, PLATFORM_SMTP_HOST="smtp.example.com",
              PLATFORM_SMTP_FROM="Sentrigis <no-reply@example.com>")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda host, port, *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    sent = []

    class FakeSMTP:
        def __init__(self, ip, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def connect(self, host, port):
            pass

        def ehlo(self):
            pass

        def has_extn(self, name):
            return True

        def starttls(self, context):
            pass

        def send_message(self, em):
            sent.append(em)
            return {}

    monkeypatch.setattr(ch, "_PinnedSMTP", FakeSMTP)
    subject, text, body_html = render(org_name="Acme Ltd", role="admin", link=LINK, ttl_hours=72)
    assert mailer.send("boss@acme.test", subject, text, body_html, inline_images=[logo_image()]).sent
    em = sent[0]
    assert em.get_content_type() == "multipart/alternative"
    plain, related = list(em.iter_parts())
    assert plain.get_content_type() == "text/plain" and plain.get_content() == text
    assert related.get_content_type() == "multipart/related"
    html_part, img = list(related.iter_parts())
    assert html_part.get_content_type() == "text/html" and html_part.get_content().strip() == body_html
    assert img.get_content_type() == "image/png" and img["Content-ID"] == f"<{LOGO_CID}>"
    assert img.get_content_disposition() == "inline" and img.get_content() == logo_image()[2]
    assert f"cid:{LOGO_CID}" in body_html


def test_acs_delivery_carries_subject_text_and_html(monkeypatch):
    key = base64.b64encode(b"k" * 32).decode()
    _mail_env(monkeypatch, PLATFORM_ACS_CONNECTION_STRING=f"endpoint=https://acs-demo.communication.azure.com/;"
                                                          f"accesskey={key}",
              PLATFORM_ACS_SENDER="DoNotReply@example.com")
    sent = {}
    monkeypatch.setattr(ssrf, "post", lambda url, body, headers, *, kind: sent.update(
        body=body) or ssrf.HttpResponse(202, b"{}", {}))
    subject, text, body_html = render(org_name="Acme Ltd", role="analyst", link=LINK, ttl_hours=72,
                                      inviter=ORG_ADMIN)
    assert mailer.send("ann@acme.test", subject, text, body_html).sent
    payload = json.loads(sent["body"])
    assert payload["content"] == {"subject": subject, "plainText": text, "html": body_html}
    assert payload["recipients"]["to"] == [{"address": "ann@acme.test"}]
    assert payload["userEngagementTrackingDisabled"] is True
    assert "attachments" not in payload  # no inline image requested: unchanged behaviour
    assert mailer.send("ann@acme.test", subject, text, body_html, inline_images=[logo_image()]).sent
    att = json.loads(sent["body"])["attachments"]
    assert len(att) == 1 and att[0]["contentId"] == LOGO_CID and att[0]["contentType"] == "image/png"
    assert base64.b64decode(att[0]["contentInBase64"]) == logo_image()[2]
