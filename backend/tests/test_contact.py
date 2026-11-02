"""Public website "Request a demo" form: POST /api/contact (app/api/contact.py).

The platform mailer is faked (no network, no real email); the Reply-To header is
also checked through the real SMTP / ACS senders with a fake transport."""
from __future__ import annotations

import base64
import json
import logging
import socket

import pytest
from fastapi.testclient import TestClient

from app import config, mailer
from app.api import contact
from app.notifications import channels as ch
from app.notifications import ssrf

from .conftest import BASE_URL, reset_database

SITE = "https://travound.example"
CONSOLE = "https://console.travound.example"
CONTACT_TO = "sales-inbox@travound.example"
GOOD = {"name": "Ada Lovelace", "email": "ada@acme.test", "company": "Acme Ltd",
        "interest": "Cloud security", "message": "Two Azure tenants,\nabout 300 laptops.", "website": ""}
JSON_HEADERS = {"Origin": SITE}
FORM_HEADERS = {"Origin": SITE, "Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture()
def sent(monkeypatch):
    """Captured mailer.send calls (never a real email)."""
    calls: list[dict] = []

    def fake_send(to, subject, text, html, *, reply_to=None):
        calls.append({"to": to, "subject": subject, "text": text, "html": html, "reply_to": reply_to})
        return mailer.MailResult(True)

    monkeypatch.setattr(mailer, "send", fake_send)
    return calls


def _client(monkeypatch, **env):
    base = {"SIMULATION_MODE": "false", "SITE_HOSTNAMES": "travound.example, www.travound.example",
            "PUBLIC_BASE_URL": CONSOLE, "CONTACT_TO": CONTACT_TO,
            "PLATFORM_SMTP_HOST": "smtp.example.com", "PLATFORM_SMTP_FROM": "Travound <no-reply@example.com>"}
    base.update(env)
    for k, v in base.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    config.reload_settings()
    reset_database()
    from app.main import create_app

    return TestClient(create_app(), base_url=BASE_URL)


@pytest.fixture()
def c(monkeypatch):
    with _client(monkeypatch) as client:
        yield client
    monkeypatch.undo()
    config.reload_settings()


def test_valid_json_request_sends_one_email(c, sent):
    r = c.post("/api/contact", json=GOOD, headers=JSON_HEADERS)
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert len(sent) == 1
    mail = sent[0]
    assert mail["to"] == CONTACT_TO and mail["reply_to"] == "ada@acme.test"
    assert mail["subject"] == "Demo request: Acme Ltd"
    for value in ("Ada Lovelace", "ada@acme.test", "Acme Ltd", "Cloud security", "Two Azure tenants,\nabout 300 laptops."):
        assert value in mail["text"]
    assert "Two Azure tenants,<br>about 300 laptops." in mail["html"]
    # CONTACT_TO is never part of a response.
    assert CONTACT_TO not in r.text


def test_form_post_without_javascript_redirects(c, sent):
    r = c.post("/api/contact", data=GOOD, headers=FORM_HEADERS, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/#contact-sent"
    assert len(sent) == 1 and sent[0]["reply_to"] == "ada@acme.test"
    bad = {**GOOD, "email": "not-an-email"}
    r = c.post("/api/contact", data=bad, headers={**FORM_HEADERS, "X-Forwarded-For": "198.51.100.7"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/#contact-error"
    assert len(sent) == 1


@pytest.mark.parametrize("change", [
    {"name": ""}, {"name": "   "}, {"name": "x" * 121}, {"email": ""}, {"email": "ada@"}, {"email": "ada@acme"},
    {"email": "a b@acme.test"}, {"email": "ada@acme.test\r\nBcc: victim@example.com"},
    {"email": "a" * 190 + "@acme.test"}, {"company": ""}, {"company": "c" * 161}, {"interest": "Something else"},
    {"interest": ""}, {"message": "m" * 2001}, {"name": 5}, {"message": ["a"]},
])
def test_validation(c, sent, change):
    contact.reset_limits()
    r = c.post("/api/contact", json={**GOOD, **change}, headers=JSON_HEADERS)
    assert r.status_code == 400 and r.json() == {"detail": "Please check the form and try again."}
    assert sent == []


def test_validation_boundaries_and_cleaning(c, sent):
    r = c.post("/api/contact", headers=JSON_HEADERS, json={
        **GOOD, "name": "n" * 120, "company": "Evil\r\nBcc: victim@example.com", "message": "m" * 2000,
        "interest": "IT asset lifecycle"})
    assert r.status_code == 200, r.text
    mail = sent[0]
    assert mail["subject"] == "Demo request: Evil Bcc: victim@example.com"
    assert "\r" not in mail["subject"] and "\n" not in mail["subject"]
    # Optional message; missing honeypot field is fine.
    contact.reset_limits()
    body = {k: v for k, v in GOOD.items() if k not in ("message", "website")}
    assert c.post("/api/contact", json=body, headers=JSON_HEADERS).status_code == 200
    assert "(no message)" in sent[1]["text"]


def test_malformed_bodies(c, sent):
    for raw, ctype in ((b"{not json", "application/json"), (b"[1, 2]", "application/json"),
                       (b"\xff\xfe", "application/json"), (b"x" * (contact.MAX_BODY_BYTES + 1), "application/json")):
        contact.reset_limits()
        r = c.post("/api/contact", content=raw, headers={**JSON_HEADERS, "Content-Type": ctype})
        assert r.status_code == 400, raw[:20]
    assert sent == []


def test_errors_never_reflect_input(c, sent):
    marker = "<script>alert('reflected')</script>"
    for change in ({"name": marker * 50}, {"email": marker}, {"interest": marker}):
        contact.reset_limits()
        r = c.post("/api/contact", json={**GOOD, **change}, headers=JSON_HEADERS)
        assert r.status_code == 400 and "script" not in r.text and "reflected" not in r.text


def test_honeypot_pretends_success(c, sent):
    r = c.post("/api/contact", json={**GOOD, "website": "http://spam.example"}, headers=JSON_HEADERS)
    assert r.status_code == 200 and r.json() == {"ok": True}
    r = c.post("/api/contact", data={**GOOD, "website": "x"}, headers=FORM_HEADERS, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/#contact-sent"
    assert sent == []


@pytest.mark.parametrize("headers, ok", [
    ({"Origin": SITE}, True),
    ({"Origin": "https://www.travound.example"}, True),
    ({"Origin": "https://TRAVOUND.example:443"}, True),
    ({"Origin": CONSOLE}, True),
    ({"Origin": "null", "Referer": SITE + "/#contact"}, True),
    ({"Referer": "https://www.travound.example/"}, True),
    ({}, False),
    ({"Origin": "null"}, False),
    ({"Origin": "https://evil.example"}, False),
    ({"Origin": "http://travound.example"}, False),
    ({"Origin": "https://travound.example.evil.example"}, False),
    ({"Origin": "https://travound.example:8443"}, False),
    ({"Referer": "https://evil.example/?https://travound.example"}, False),
    ({"Origin": "https://evil.example", "Referer": SITE + "/"}, False),
])
def test_origin_check(c, sent, headers, ok):
    r = c.post("/api/contact", json=GOOD, headers=headers)
    if ok:
        assert r.status_code == 200, r.text
        assert len(sent) == 1
    else:
        assert r.status_code == 403 and r.json() == {"detail": "Requests are only accepted from the website."}
        assert sent == []


def test_unconfigured_contact_to_is_503(monkeypatch, sent):
    with _client(monkeypatch, CONTACT_TO=None) as client:
        r = client.post("/api/contact", json=GOOD, headers=JSON_HEADERS)
        assert r.status_code == 503
        assert r.json() == {"detail": "The contact form is temporarily unavailable. Please try again later."}
    with _client(monkeypatch, CONTACT_TO="not an address\r\nBcc: x@example.com") as client:
        assert client.post("/api/contact", json=GOOD, headers=JSON_HEADERS).status_code == 503
    with _client(monkeypatch, PLATFORM_SMTP_HOST=None, PLATFORM_SMTP_FROM=None) as client:
        assert client.post("/api/contact", json=GOOD, headers=JSON_HEADERS).status_code == 503
    assert sent == []
    monkeypatch.undo()
    config.reload_settings()


def test_mail_failure_is_503_without_details(c, monkeypatch):
    monkeypatch.setattr(mailer, "send", lambda *a, **k: mailer.MailResult(False, "SMTP 550: mailbox sales-inbox unknown"))
    r = c.post("/api/contact", json=GOOD, headers=JSON_HEADERS)
    assert r.status_code == 503 and "550" not in r.text and "sales-inbox" not in r.text


def test_per_ip_rate_limit(c, sent):
    for _ in range(2):
        assert c.post("/api/contact", json=GOOD, headers=JSON_HEADERS).status_code == 200
    # Invalid submissions count as well (no free probing).
    assert c.post("/api/contact", json={**GOOD, "email": "x"}, headers=JSON_HEADERS).status_code == 400
    r = c.post("/api/contact", json=GOOD, headers=JSON_HEADERS)
    assert r.status_code == 429 and r.json() == {"detail": "Too many requests. Please try again later."}
    assert len(sent) == 2


def test_per_ip_limits_window_and_daily(c, sent, monkeypatch):
    from app import auth as auth_mod

    clock = [1000.0]

    class FakeTime:
        @staticmethod
        def monotonic():
            return clock[0]

    monkeypatch.setattr(auth_mod, "time", FakeTime)
    codes = []
    for _ in range(4):  # 4 rounds of 10 minutes: 3 each, but at most 10 a day
        for _ in range(4):
            codes.append(c.post("/api/contact", json=GOOD, headers=JSON_HEADERS).status_code)
        clock[0] += 601
    assert codes.count(200) == 10 and codes.count(429) == 6
    assert len(sent) == 10
    clock[0] += 86400
    assert c.post("/api/contact", json=GOOD, headers=JSON_HEADERS).status_code == 200


def test_per_ip_limit_uses_the_trusted_proxy_client_ip(monkeypatch, sent):
    # Behind the single on-prem nginx (TRUST_PROXY_HEADERS=true): the right-most
    # X-Forwarded-For entry, which nginx sets to the address it saw, is the client.
    with _client(monkeypatch, TRUST_PROXY_HEADERS="true") as client:
        def post(ip):
            return client.post("/api/contact", json=GOOD, headers={**JSON_HEADERS, "X-Forwarded-For": ip}).status_code

        assert [post("203.0.113.5") for _ in range(4)] == [200, 200, 200, 429]
        assert post("203.0.113.6") == 200  # another client is unaffected
        assert post("203.0.113.6, 203.0.113.5") == 429  # spoofed left-most entries are ignored
    monkeypatch.undo()
    config.reload_settings()


def test_global_cap(c, sent, monkeypatch):
    monkeypatch.setattr(contact, "PER_IP_LIMITS", ((100, 600.0),))
    monkeypatch.setattr(contact, "GLOBAL_LIMIT", (5, 3600.0))
    codes = [c.post("/api/contact", json=GOOD, headers=JSON_HEADERS).status_code for _ in range(7)]
    assert codes == [200] * 5 + [429] * 2
    assert len(sent) == 5


def test_email_rendering_escapes_everything():
    evil = {"name": "<b>Mallory</b>", "email": "m@evil.test", "company": 'Evil "Co" <script>x</script>',
            "interest": "Cloud security", "message": "<img src=x onerror=alert(1)>\nline 2"}
    subject, text, body_html = contact.render(evil)
    assert subject == 'Demo request: Evil "Co" <script>x</script>'
    assert "<script>" not in body_html and "&lt;script&gt;" in body_html
    assert "<b>Mallory</b>" not in body_html and "&lt;b&gt;Mallory&lt;/b&gt;" in body_html
    assert "<img" not in body_html and "&lt;img src=x onerror=alert(1)&gt;<br>line 2" in body_html
    assert "<b>Mallory</b>" in text  # the plain-text part is plain text


def test_logs_have_no_personal_data(c, sent, caplog):
    caplog.set_level(logging.DEBUG)
    c.post("/api/contact", json=GOOD, headers=JSON_HEADERS)
    c.post("/api/contact", json={**GOOD, "email": "bad"}, headers=JSON_HEADERS)
    c.post("/api/contact", json={**GOOD, "website": "x"}, headers=JSON_HEADERS)
    c.post("/api/contact", json=GOOD, headers={"Origin": "https://evil.example"})
    messages = [r.getMessage() for r in caplog.records if r.name == "cnapp.contact"]
    assert messages == ["contact request accepted", "contact request rejected (validation failed)",
                        "contact request rejected (honeypot)", "contact request rejected (origin not allowed)"]
    everything = "\n".join(r.getMessage() for r in caplog.records)
    for value in ("Ada", "Lovelace", "ada@acme.test", "Acme", "Azure tenants", CONTACT_TO, "evil.example"):
        assert value not in everything


def test_contact_to_is_not_exposed(c):
    assert CONTACT_TO not in c.get("/api/health").text
    assert CONTACT_TO not in repr(config.settings)


# --- Reply-To through the real senders (fake transports) ---------------------------------------

def test_smtp_reply_to_header(monkeypatch):
    for k in ("PLATFORM_ACS_CONNECTION_STRING", "PLATFORM_ACS_SENDER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PLATFORM_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("PLATFORM_SMTP_FROM", "Travound <no-reply@example.com>")
    config.reload_settings()
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda host, port, *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    out = []

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
            out.append(em)
            return {}

    monkeypatch.setattr(ch, "_PinnedSMTP", FakeSMTP)
    subject, text, body_html = contact.render({**GOOD, "message": "hi"})
    assert mailer.send(CONTACT_TO, subject, text, body_html, reply_to="ada@acme.test").sent
    assert mailer.send(CONTACT_TO, subject, text, body_html).sent
    assert out[0]["Reply-To"] == "ada@acme.test" and out[0]["To"] == CONTACT_TO
    assert out[0]["Subject"] == "Demo request: Acme Ltd"
    assert out[1]["Reply-To"] is None
    monkeypatch.undo()
    config.reload_settings()


def test_acs_reply_to(monkeypatch):
    key = base64.b64encode(b"k" * 32).decode()
    for k in ("PLATFORM_SMTP_HOST", "PLATFORM_SMTP_FROM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PLATFORM_ACS_CONNECTION_STRING", f"endpoint=https://acs-demo.communication.azure.com/;accesskey={key}")
    monkeypatch.setenv("PLATFORM_ACS_SENDER", "DoNotReply@example.com")
    config.reload_settings()
    bodies = []
    monkeypatch.setattr(ssrf, "post", lambda url, body, headers, *, kind: bodies.append(body)
                        or ssrf.HttpResponse(202, b"{}", {}))
    assert mailer.send(CONTACT_TO, "s", "t", "<p>h</p>", reply_to="ada@acme.test").sent
    assert json.loads(bodies[0])["replyTo"] == [{"address": "ada@acme.test"}]
    monkeypatch.undo()
    config.reload_settings()
