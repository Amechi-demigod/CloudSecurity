"""The invitation email (app/services/invitation_email.py) and its delivery
through the platform mailer (SMTP and ACS senders of the notification channel,
faked: no network, no real email)."""
from __future__ import annotations

import base64
import json
import socket

import pytest

from app import config, mailer
from app.notifications import channels as ch
from app.notifications import ssrf
from app.services.invitation_email import Inviter, render

LINK = "https://cnapp.example.com/invite#token=cnv_abc123"
ORG_ADMIN = Inviter("jane@example.com", "Jane Doe")


@pytest.fixture(autouse=True)
def _brand(monkeypatch):
    monkeypatch.setenv("BRAND_NAME", "Travound Security")
    config.reload_settings()
    yield
    monkeypatch.undo()
    config.reload_settings()


def test_platform_variant_names_only_the_brand():
    subject, text, body_html = render(org_name="Acme Ltd", role="admin", link=LINK, ttl_hours=72)
    assert subject == "You've been invited to join Acme Ltd on Travound Security"
    assert "Travound Security invited you as admin to join Acme Ltd." in text
    for part in (subject, text, body_html):
        assert "[CNAPP]" not in part and "jane" not in part.lower() and "@" not in part.replace(LINK, "")
    assert LINK in text and f'href="{LINK}"' in body_html and ">Accept invitation</a>" in body_html
    assert "This link works once and expires in 72 hours." in text and "expires in 72 hours" in body_html
    for line in ("If you weren't expecting this, you can ignore this email.",
                 "This mailbox isn't monitored, please don't reply."):
        assert line in text
        assert line.replace("'", "&#x27;") in body_html


def test_organisation_variant_names_the_inviter():
    subject, text, body_html = render(org_name="Acme Ltd", role="analyst", link=LINK, ttl_hours=1,
                                      inviter=ORG_ADMIN)
    assert subject == "You have been invited to join Acme Ltd on Travound Security"
    assert "Jane Doe (jane@example.com) invited you as analyst to join Acme Ltd on Travound Security." in text
    assert "Jane Doe (jane@example.com) invited you as <strong>analyst</strong>" in body_html
    assert "expires in 1 hour." in text
    # No display name on the account: the address alone.
    _, text, _ = render(org_name="Acme Ltd", role="viewer", link=LINK, ttl_hours=72,
                        inviter=Inviter("ops@example.com", ""))
    assert "ops@example.com invited you as viewer" in text


def test_interpolated_values_are_escaped_and_single_line():
    evil = 'Evil <script>alert(1)</script> "Co"\r\nBcc: victim@example.com'
    subject, text, body_html = render(org_name=evil, role="admin", link=LINK + '"><img src=x>', ttl_hours=72,
                                      inviter=Inviter("a@example.com", "<b>Mallory</b>\nX-Hdr: 1"))
    assert "\r" not in subject and "\n" not in subject and subject.startswith("You have been invited to join Evil")
    assert "<script>" not in body_html and "&lt;script&gt;" in body_html
    assert "<b>Mallory</b>" not in body_html and "&lt;b&gt;Mallory&lt;/b&gt;" in body_html
    assert '"><img' not in body_html and "&quot;&gt;&lt;img" in body_html
    assert "<img" not in body_html  # no images at all (tracking pixels or otherwise)
    # The plain-text part keeps each value on its line.
    assert "Mallory</b> X-Hdr: 1 (a@example.com)" in text and "\nBcc:" not in text


def _mail_env(monkeypatch, **env):
    for k in ("PLATFORM_SMTP_HOST", "PLATFORM_SMTP_FROM", "PLATFORM_ACS_CONNECTION_STRING", "PLATFORM_ACS_SENDER"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config.reload_settings()


def test_smtp_delivery_is_multipart_alternative(monkeypatch):
    _mail_env(monkeypatch, PLATFORM_SMTP_HOST="smtp.example.com",
              PLATFORM_SMTP_FROM="Travound Security <no-reply@example.com>")
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
