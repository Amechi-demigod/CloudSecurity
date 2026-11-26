"""Sentrigis email provider + daily limit, rules that must name an area, "Send a test alert" on a rule and the
recommended rules. Transports are mocked: nothing is ever sent."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db
from app.models import Organization, utcnow
from app.notifications import Event, crypto, dispatcher, emit, ssrf
from app.notifications import channels as ch
from app.notifications.events import sources
from app.notifications.models import NotificationChannel, NotificationDelivery, NotificationRule
from tests.conftest import BASE_URL, login, make_user

SLACK_URL = "https://hooks.slack.com/services/T000/B000/VERYSECRETTOKEN"


class FakeHttp:
    def __init__(self):
        self.requests = []

    def __call__(self, url, body, headers, *, kind):
        self.requests.append(json.loads(body))
        return ssrf.HttpResponse(200, b"ok", {})


@pytest.fixture()
def env(monkeypatch):
    """Encryption key, a configured platform sender, and recording transports (SMTP + HTTP)."""
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com")
    monkeypatch.setenv("PLATFORM_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("PLATFORM_SMTP_FROM", "Sentrigis <no-reply@sentrigis.com>")
    monkeypatch.delenv("PLATFORM_ACS_CONNECTION_STRING", raising=False)
    monkeypatch.delenv("PLATFORM_ACS_SENDER", raising=False)
    monkeypatch.delenv("NOTIFY_SENTRIGIS_DAILY_LIMIT", raising=False)
    config.reload_settings()
    http = FakeHttp()
    monkeypatch.setattr(ssrf, "post", http)
    smtp: list[dict] = []

    def fake_smtp(config_, secrets, msg, delivery_id, **kw):
        smtp.append({"config": config_, "secrets": secrets, "msg": msg, "rendered": kw.get("rendered"),
                     "inline_images": kw.get("inline_images")})
        return ch.SendResult(250, "accepted")

    monkeypatch.setattr(ch, "send_smtp", fake_smtp)
    http.smtp = smtp
    yield http
    config.reload_settings()


def sentrigis_channel(client, name="Team email", to="soc@example.com"):
    r = client.post("/api/notifications/channels", json={"name": name, "type": "email",
                                                          "config": {"provider": "sentrigis", "to_addresses": to}})
    assert r.status_code == 201, r.text
    return r.json()


def smtp_channel(client, name="Own SMTP"):
    r = client.post("/api/notifications/channels", json={
        "name": name, "type": "email",
        "config": {"provider": "smtp", "to_addresses": "a@example.com", "host": "smtp.example.com", "port": 587,
                   "from_address": "alerts@example.com", "security": "starttls"}})
    assert r.status_code == 201, r.text
    return r.json()


def slack_channel(client, name="SOC Slack"):
    r = client.post("/api/notifications/channels", json={"name": name, "type": "slack",
                                                          "secrets": {"webhook_url": SLACK_URL}})
    assert r.status_code == 201, r.text
    return r.json()


def rule_body(channel_ids, **over):
    return {"name": "R", "sources": ["device"], "min_severity": "high", "channel_ids": channel_ids, **over}


# --- the Sentrigis email provider ----------------------------------------------------------------

def test_sentrigis_channel_needs_only_recipients(client, env):
    c = sentrigis_channel(client, to="a@example.com, b@example.com")
    assert c["config"] == {"provider": "sentrigis", "to_addresses": ["a@example.com", "b@example.com"]}
    assert c["secret_hints"] == {}
    # No provider given = the default, Sentrigis.
    r = client.post("/api/notifications/channels", json={"name": "d", "type": "email",
                                                          "config": {"to_addresses": "a@example.com"}})
    assert r.status_code == 201 and r.json()["config"]["provider"] == "sentrigis"
    # Recipients are still required and checked.
    for cfg in ({"provider": "sentrigis"}, {"provider": "sentrigis", "to_addresses": "nope"}):
        assert client.post("/api/notifications/channels",
                           json={"name": "x", "type": "email", "config": cfg}).status_code == 422


def test_acs_is_no_longer_offered_for_channels(client, env):
    meta = client.get("/api/notifications/meta").json()
    email = next(t for t in meta["channel_types"] if t["type"] == "email")
    provider = next(f for f in email["fields"] if f["name"] == "provider")
    assert provider["options"] == ["sentrigis", "smtp"] and provider["default"] == "sentrigis"
    assert {f["name"] for f in email["fields"]} == {"provider", "to_addresses", "from_address", "host", "port",
                                                    "security", "username", "password"}
    r = client.post("/api/notifications/channels", json={
        "name": "x", "type": "email",
        "config": {"provider": "acs", "to_addresses": "a@example.com", "sender_address": "s@example.com"},
        "secrets": {"connection_string": "endpoint=https://x.communication.azure.com/;accesskey=a2V5"}})
    assert r.status_code == 422
    assert meta["sentrigis_email"] == {"available": True, "sender": "Sentrigis <no-reply@sentrigis.com>",
                                       "daily_limit": 30}


def test_sentrigis_unavailable_without_a_platform_sender(client, env, monkeypatch):
    monkeypatch.delenv("PLATFORM_SMTP_HOST")
    config.reload_settings()
    r = client.post("/api/notifications/channels", json={"name": "x", "type": "email",
                                                          "config": {"provider": "sentrigis",
                                                                     "to_addresses": "a@example.com"}})
    assert r.status_code == 422 and "not available" in r.json()["detail"]
    assert client.get("/api/notifications/meta").json()["sentrigis_email"]["available"] is False
    # An existing channel then fails permanently, with a clear message.
    with pytest.raises(ch.PermanentError, match="not available"):
        ch.send("email", {"provider": "sentrigis", "to_addresses": ["a@example.com"]}, {}, {"title": "t"}, "d1")


def test_sentrigis_sends_the_alert_layout_through_the_platform_sender(client, env):
    c = sentrigis_channel(client)
    r = client.post(f"/api/notifications/channels/{c['id']}/test")
    assert r.status_code == 200 and r.json()["ok"] is True
    sent = env.smtp[-1]
    assert sent["config"]["from_address"] == "Sentrigis <no-reply@sentrigis.com>"
    assert sent["config"]["host"] == "smtp.example.com" and sent["config"]["to_addresses"] == ["soc@example.com"]
    assert sent["msg"]["kind"] == "test"
    subject, text, body = sent["rendered"]  # the alert layout, with the inline logo
    assert subject.startswith("[Info] ") and 'on the "Team email" email channel in Sentrigis.' in text
    assert "cid:sentrigis-logo" in body and sent["inline_images"][0][0] == "sentrigis-logo"
    assert env.requests == []


def test_sentrigis_falls_back_to_the_platform_acs_sender(env, monkeypatch):
    monkeypatch.delenv("PLATFORM_SMTP_HOST")
    monkeypatch.setenv("PLATFORM_ACS_SENDER", "no-reply@sentrigis.com")
    monkeypatch.setenv("PLATFORM_ACS_CONNECTION_STRING", "endpoint=https://acs-demo.communication.azure.com/;accesskey=a2V5")
    config.reload_settings()
    seen = {}
    monkeypatch.setattr(ch, "send_acs", lambda cfg, sec, msg, did, **kw: seen.update(cfg=cfg) or ch.SendResult(202))
    ch.send("email", {"provider": "sentrigis", "to_addresses": ["a@example.com"]}, {}, {"title": "t"}, "d1")
    assert seen["cfg"]["sender_address"] == "no-reply@sentrigis.com"


# --- the daily limit -------------------------------------------------------------------------------

def queue_delivery(channel_id, name, ctype="email", title="x"):
    with db.get_session("default") as s:
        d = NotificationDelivery(channel_id=channel_id, channel_name=name, channel_type=ctype, kind="event",
                                 title=title, severity="high", message={"title": title, "severity": "high"},
                                 status="pending", next_attempt_at=utcnow())
        s.add(d)
        s.commit()
        return d.id


def test_daily_limit_blocks_the_31st_email(client, env):
    c = sentrigis_channel(client)
    ids = [queue_delivery(c["id"], c["name"], title=f"a{i}") for i in range(31)]
    with db.get_session("default") as s:
        stats = dispatcher.send_due(s, utcnow(), limit=100)
        rows = {d.id: d for d in s.scalars(select(NotificationDelivery))}
    assert stats["sent"] == 30 and len(env.smtp) == 30
    last = rows[ids[-1]] if rows[ids[-1]].status == "skipped" else next(d for d in rows.values()
                                                                      if d.status == "skipped")
    assert last.status == "skipped" and last.attempts == 1
    assert last.last_error == "Not sent: daily limit of 30 Sentrigis emails reached (resets at midnight UTC)"
    # Not retried, and visible in the log.
    with db.get_session("default") as s:
        assert dispatcher.send_due(s, utcnow(), limit=100)["sent"] == 0
    log = client.get("/api/notifications/deliveries", params={"status": "skipped"}).json()
    assert len(log) == 1 and "daily limit of 30" in log[0]["last_error"]
    # Test emails count too.
    t = client.post(f"/api/notifications/channels/{c['id']}/test").json()
    assert t["ok"] is False and t["delivery"]["status"] == "skipped"
    assert client.get("/api/notifications/status").json()["deliveries"]["skipped"] == 2


def test_daily_limit_is_configurable_and_resets_each_day(client, env, monkeypatch):
    monkeypatch.setenv("NOTIFY_SENTRIGIS_DAILY_LIMIT", "2")
    c = sentrigis_channel(client)
    assert client.get("/api/notifications/meta").json()["sentrigis_email"]["daily_limit"] == 2
    for i in range(3):
        queue_delivery(c["id"], c["name"], title=f"a{i}")
    now = utcnow()
    with db.get_session("default") as s:
        stats = dispatcher.send_due(s, now, limit=100)
    assert stats["sent"] == 2
    with db.get_session("default") as s:
        skipped = s.scalars(select(NotificationDelivery).where(NotificationDelivery.status == "skipped")).all()
        assert len(skipped) == 1 and "daily limit of 2" in skipped[0].last_error
        # Yesterday's sends do not count today: shift them back a day.
        for d in s.scalars(select(NotificationDelivery).where(NotificationDelivery.status == "sent")):
            d.sent_at = d.sent_at - timedelta(days=2)
        s.commit()
        n = dispatcher.sentrigis_sent_today(s, now)
    assert n == 0


def test_smtp_and_other_channels_have_no_limit(client, env, monkeypatch):
    monkeypatch.setenv("NOTIFY_SENTRIGIS_DAILY_LIMIT", "1")
    s_ch, own, slack = sentrigis_channel(client), smtp_channel(client), slack_channel(client)
    queue_delivery(s_ch["id"], s_ch["name"])
    queue_delivery(s_ch["id"], s_ch["name"])  # over the limit of 1
    for _ in range(3):
        queue_delivery(own["id"], own["name"])
        queue_delivery(slack["id"], slack["name"], ctype="slack")
    with db.get_session("default") as s:
        dispatcher.send_due(s, utcnow(), limit=100)
        by = {}
        for d in s.scalars(select(NotificationDelivery)):
            by.setdefault((d.channel_name, d.status), 0)
            by[(d.channel_name, d.status)] += 1
    assert by[("Team email", "sent")] == 1 and by[("Team email", "skipped")] == 1
    assert by[("Own SMTP", "sent")] == 3 and by[("SOC Slack", "sent")] == 3
    assert not any(k[1] == "skipped" for k in by if k[0] != "Team email")


# --- rules must name an area ----------------------------------------------------------------------

def test_rule_requires_at_least_one_area(client, env):
    c = slack_channel(client)
    for body in (rule_body([c["id"], ], sources=[]), rule_body([c["id"]], sources=["  "]),
                 {"name": "R", "channel_ids": [c["id"]]}):
        r = client.post("/api/notifications/rules", json=body)
        assert r.status_code == 422 and "Pick at least one area" in r.text, body
    rule = client.post("/api/notifications/rules", json=rule_body([c["id"]])).json()
    assert rule["needs_area"] is False
    r = client.put(f"/api/notifications/rules/{rule['id']}", json=rule_body([c["id"]], sources=[]))
    assert r.status_code == 422 and "Pick at least one area" in r.text


def test_empty_sources_match_nothing_and_legacy_rules_are_flagged(client, env):
    from app.notifications.rules import EventContext, matches

    legacy = NotificationRule(name="old", enabled=True, sources=[], min_severity="info", channel_ids=[])
    assert matches(legacy, EventContext(source="device", event_type="created", severity="critical")) is False
    named = NotificationRule(name="n", enabled=True, sources=["device"], min_severity="info", channel_ids=[])
    assert matches(named, EventContext(source="device", event_type="created", severity="low")) is True
    assert matches(named, EventContext(source="scan", event_type="created", severity="low")) is False
    c = slack_channel(client)
    with db.get_session("default") as s:
        s.add(NotificationRule(name="legacy", sources=[], channel_ids=[c["id"]], min_severity="high"))
        s.commit()
    rules = client.get("/api/notifications/rules").json()
    assert rules[0]["name"] == "legacy" and rules[0]["sources"] == [] and rules[0]["needs_area"] is True


# --- "Send a test alert" ---------------------------------------------------------------------------

def test_rule_test_alert_goes_to_every_channel_of_the_rule(client, env):
    slack, mail = slack_channel(client), sentrigis_channel(client)
    # A high-severity-only rule with quiet hours all day still sends the test.
    rule = client.post("/api/notifications/rules", json=rule_body(
        [slack["id"], mail["id"]], min_severity="critical", quiet_start="00:00", quiet_end="23:59")).json()
    r = client.post(f"/api/notifications/rules/{rule['id']}/test")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and sorted(x["channel_name"] for x in body["results"]) == ["SOC Slack", "Team email"]
    assert all(x["ok"] and x["status"] == "sent" for x in body["results"])
    assert "Test alert: R" in json.dumps(env.requests[-1])
    assert env.smtp[-1]["msg"]["title"] == "Test alert: R"
    log = client.get("/api/notifications/deliveries", params={"kind": "test"}).json()
    assert len(log) == 2 and all(d["title"] == "Test alert: R" and d["rule_name"] == "R" for d in log)
    with db.get_session("default") as s:
        from app.models import AuditLog

        assert s.scalars(select(AuditLog).where(AuditLog.action == "notification_rule_tested")).first() is not None


def test_rule_test_alert_reports_a_failed_channel(client, env):
    slack = slack_channel(client)
    rule = client.post("/api/notifications/rules", json=rule_body([slack["id"]])).json()
    env.requests.clear()
    old = ssrf.post
    ssrf_post = lambda url, body, headers, *, kind: ssrf.HttpResponse(500, b"boom", {})  # noqa: E731
    ssrf.post = ssrf_post
    try:
        r = client.post(f"/api/notifications/rules/{rule['id']}/test").json()
    finally:
        ssrf.post = old
    assert r["ok"] is False and r["results"][0]["status"] == "dead" and "SECRETTOKEN" not in json.dumps(r)


def test_rule_test_alert_permissions_and_limits(client, env):
    slack = slack_channel(client)
    rule = client.post("/api/notifications/rules", json=rule_body([slack["id"]])).json()
    make_user(client, "analyst")
    make_user(client, "viewer")
    for role in ("analyst", "viewer"):
        other = TestClient(client.app, base_url=BASE_URL)
        login(other, f"{role}@example.com", "a-long-test-password")
        assert other.post(f"/api/notifications/rules/{rule['id']}/test").status_code == 403
    assert env.requests == []
    assert client.post("/api/notifications/rules/nope/test").status_code == 404
    # Rate limit: 10 per rule per 10 minutes.
    for _ in range(10):
        assert client.post(f"/api/notifications/rules/{rule['id']}/test").status_code == 200
    assert client.post(f"/api/notifications/rules/{rule['id']}/test").status_code == 429
    # A rule without a channel has nothing to send to.
    client.delete(f"/api/notifications/channels/{slack['id']}")
    other_rule = client.post("/api/notifications/rules", json=rule_body([slack_channel(client, "S2")["id"]],
                                                                         name="R2")).json()
    client.delete(f"/api/notifications/channels/{client.get('/api/notifications/channels').json()[0]['id']}")
    assert client.post(f"/api/notifications/rules/{other_rule['id']}/test").status_code == 409


# --- recommended rules -----------------------------------------------------------------------------

def set_modules(modules: list[str] | None) -> None:
    with db.get_session("default") as s:
        s.get(Organization, "default").modules = modules
        s.commit()


def test_recommended_rules_are_created_with_every_area(client, env):
    c = slack_channel(client)
    everything = sorted(s.name for s in sources())
    r = client.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["skipped"] == [] and [x["name"] for x in body["created"]] == ["High alerts – straight away",
                                                                              "Daily summary"]
    high, daily = body["created"]
    assert (high["min_severity"], high["mode"]) == ("high", "immediate")
    assert (daily["min_severity"], daily["mode"], daily["digest_hour"], daily["timezone"]) == ("medium", "digest", 8,
                                                                                            "UTC")
    for x in body["created"]:
        assert sorted(x["sources"]) == everything and x["channel_ids"] == [c["id"]]
    assert len(client.get("/api/notifications/rules").json()) == 2


def test_recommended_rules_do_not_duplicate_and_use_the_tracking_time_zone(client, env):
    c = slack_channel(client)
    client.post("/api/notifications/rules", json=rule_body([c["id"]], name="Daily summary"))
    with db.get_session("default") as s:
        from app.tracking import service as tracking

        tracking.get_settings(s).timezone = "Africa/Lagos"
        s.commit()
    body = client.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]}).json()
    assert body["skipped"] == ["Daily summary"] and [x["name"] for x in body["created"]] == [
        "High alerts – straight away"]
    assert body["created"][0]["timezone"] == "UTC"  # only the summary uses the organisation's zone
    again = client.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]}).json()
    assert again["created"] == [] and len(again["skipped"]) == 2
    with db.get_session("default") as s:
        s.query(NotificationRule).filter_by(name="Daily summary").delete()
        s.commit()
    body = client.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]}).json()
    assert body["created"][0]["timezone"] == "Africa/Lagos"


def test_recommended_rules_only_cover_licensed_areas(client, env):
    c = slack_channel(client)
    set_modules(["assets"])
    try:
        meta_sources = {s["name"] for s in client.get("/api/notifications/meta").json()["sources"]}
        assert "runtime_alert" not in meta_sources and "device" not in meta_sources
        assert {"asset_lifecycle", "directory_source"} <= meta_sources
        body = client.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]}).json()
        for x in body["created"]:
            assert set(x["sources"]) == meta_sources
            assert "runtime_alert" not in x["sources"] and "posture_finding" not in x["sources"]
    finally:
        set_modules(None)


def test_recommended_rules_validation_and_permissions(client, env):
    c = slack_channel(client)
    assert client.post("/api/notifications/rules/recommended", json={"channel_ids": []}).status_code == 422
    assert client.post("/api/notifications/rules/recommended", json={"channel_ids": ["nope"]}).status_code == 422
    make_user(client, "analyst")
    other = TestClient(client.app, base_url=BASE_URL)
    login(other, "analyst@example.com", "a-long-test-password")
    assert other.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]}).status_code == 403
    assert client.get("/api/notifications/rules").json() == []


def test_recommended_rules_route_events_end_to_end(client, env):
    c = slack_channel(client)
    client.post("/api/notifications/rules/recommended", json={"channel_ids": [c["id"]]})
    with db.get_session("default") as s:
        row = emit(s, Event(source="device", event_type="created", severity="critical", title="Disk encryption off",
                            group_key="g"))
        s.commit()
        row.created_at = datetime(2030, 1, 1)
        s.commit()
        dispatcher.process_events(s, datetime(2030, 1, 1, 0, 1))
        rows = s.scalars(select(NotificationDelivery)).all()
        assert len(rows) == 1 and rows[0].rule_name.startswith("High alerts")  # the summary rule queues a digest item
        assert s.scalars(select(NotificationChannel)).first() is not None


# --- the alert email layout ----------------------------------------------------------------------------

def _msg(**over):
    base = {"kind": "event", "title": "FIN-LT-021 connected from outside your allowed countries", "summary": "",
            "severity": "high", "source": "device_tracking", "source_label": "Device tracking",
            "facts": [["Severity", "High"], ["Source", "Device tracking"], ["Computer", "FIN-LT-021 (Windows laptop)"],
                      ["Where", "Dubai, United Arab Emirates (approximate)"]],
            "link": "https://cnapp.example.com/devices/1"}
    base.update(over)
    return base


def test_alert_email_matches_the_approved_layout(env):
    subject, text, body = ch.render_email(_msg(), "IT security team")
    assert subject == "[High] FIN-LT-021 connected from outside your allowed countries"
    assert "High \u00b7 Device tracking" in body and "border-top:6px solid #0f1d3a" in body
    assert "cid:sentrigis-logo" in body and "Open in Sentrigis" in body and "https://cnapp.example.com/devices/1" in body
    footer = 'You get this because you are on the "IT security team" email channel in Sentrigis.'
    assert footer in text and footer.replace("\"", "&quot;") in body
    assert "Location is approximate, from the computer's internet address." in text
    assert "Computer: FIN-LT-021" in text and "Severity:" not in text
    other = ch.render_email(_msg(source="scan", source_label="Cloud scans"), "Ops")[1]
    assert "Location is approximate" not in other
    assert "Open in" not in ch.render_email(_msg(link=None), "Ops")[1]


def test_alert_email_escapes_and_is_header_safe(env):
    subject, text, body = ch.render_email(_msg(title="a\r\nBcc: x@evil.com <script>"), 'Ops "<b>"')
    assert "\n" not in subject and "\r" not in subject
    assert "<script>" not in body and "&lt;script&gt;" in body and "<b>" not in body


def test_digest_email_uses_the_same_layout(env):
    msg = {"kind": "digest", "title": "Daily digest: 2 notification(s)", "summary": "1 high, 1 low",
           "severity": "high", "source": "digest", "source_label": "Digest", "facts": [],
           "items": [{"severity": "high", "title": "A", "link": "https://x.example.com/a"},
                     {"severity": "low", "title": "B"}], "link": "https://x.example.com/"}
    subject, text, body = ch.render_email(msg, "Team")
    assert subject.startswith("[High] ") and "cid:sentrigis-logo" in body and "<li>" in body
    assert "- [HIGH] A" in text and 'on the "Team" email channel' in text


def test_smtp_channel_gets_the_same_email_with_the_logo(client, env):
    c = smtp_channel(client)
    assert client.post(f"/api/notifications/channels/{c['id']}/test").json()["ok"] is True
    sent = env.smtp[-1]
    assert sent["rendered"][0].startswith("[Info] ") and 'on the "Own SMTP" email channel' in sent["rendered"][1]
    assert sent["inline_images"][0][0] == "sentrigis-logo"


def test_daily_count_survives_a_deleted_channel(client, env, monkeypatch):
    monkeypatch.setenv("NOTIFY_SENTRIGIS_DAILY_LIMIT", "2")
    c = sentrigis_channel(client)
    for i in range(2):
        queue_delivery(c["id"], c["name"], title=f"a{i}")
    with db.get_session("default") as s:
        assert dispatcher.send_due(s, utcnow(), limit=100)["sent"] == 2
    assert client.delete(f"/api/notifications/channels/{c['id']}").status_code == 204
    c2 = sentrigis_channel(client, name="Again")
    queue_delivery(c2["id"], c2["name"])
    with db.get_session("default") as s:
        stats = dispatcher.send_due(s, utcnow(), limit=100)
        assert dispatcher.sentrigis_sent_today(s, utcnow()) == 2
    assert stats["sent"] == 0 and len(env.smtp) == 2
    own = smtp_channel(client)
    assert client.post(f"/api/notifications/channels/{own['id']}/test").json()["ok"] is True
