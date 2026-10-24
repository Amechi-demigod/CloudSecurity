"""Scheduled cloud posture scans (app/services/scan_schedule.py): timing with a
fake clock, leader election, no overlap, restarts, connector selection, failure
notifications, and the schedule API."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app import config
from app import db as dbmod
from app.connectors.base import CollectionResult, Connector
from app.connectors.simulated import SimulatedConnector
from app.locks import advisory_lock
from app.models import AuditLog, ScanRun, utcnow
from app.notifications.models import NotificationEvent
from app.services import scan_schedule as sched
from app.services.scans import MANUAL, SCHEDULED, execute_scan, start_scan

from .conftest import login, make_user

T0 = datetime(2026, 10, 23, 12, 0, 0)
H = timedelta(hours=1)


class FakeConnector(Connector):
    provider = "fake"

    def __init__(self, name: str = "fake", configured: bool = True, fail: bool = False):
        self.name = name
        self._configured = configured
        self._fail = fail

    def is_configured(self) -> bool:
        return self._configured

    def collect(self) -> CollectionResult:
        if self._fail:
            raise RuntimeError("cloud API unreachable")
        return CollectionResult()


class Clock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> datetime:
        self.now += delta
        return self.now


def make_scheduler(clock: Clock, connectors: list[Connector], delay_seconds: float = 120, finish: bool = True):
    """Scheduler whose launcher records a scheduled run at the fake time (finished
    immediately, or left running with finish=False)."""
    launched: list[str] = []

    def launcher(conn: Connector, org_id: str = "default"):
        with dbmod.get_session("default") as db:
            db.add(ScanRun(connector=conn.name, trigger=SCHEDULED, started_at=clock.now,
                           status="succeeded" if finish else "running",
                           finished_at=clock.now if finish else None))
            db.commit()
        launched.append(conn.name)

    s = sched.ScanScheduler(startup_delay_seconds=delay_seconds, clock=clock,
                            registry_factory=lambda *_: {c.name: c for c in connectors}, launcher=launcher)
    return s, launched


@pytest.fixture()
def clean(session):
    yield session
    session.rollback()


def add_run(connector: str, started: datetime, trigger: str | None = SCHEDULED, status: str = "succeeded"):
    with dbmod.get_session("default") as db:
        db.add(ScanRun(connector=connector, trigger=trigger, started_at=started, status=status,
                       finished_at=None if status == "running" else started + timedelta(minutes=5)))
        db.commit()


def test_schedule_timing_with_fake_clock(clean):
    clock = Clock(T0)
    s, launched = make_scheduler(clock, [FakeConnector()])
    try:
        # Inside the startup delay: nothing runs.
        assert s.tick(clock.now).waiting
        clock.advance(timedelta(seconds=119))
        assert s.tick(clock.now).waiting and launched == []
        # Never scanned on schedule -> due as soon as the delay is over.
        clock.advance(timedelta(seconds=1))
        assert s.tick(clock.now).started == ["fake"]
        start = clock.now
        # Not again before the interval (default 6 h) has passed since that start.
        for _ in range(5):
            clock.advance(H)
            assert s.tick(clock.now).started == []
        clock.advance(timedelta(minutes=59))
        assert s.tick(clock.now).started == []
        clock.now = start + 6 * H
        assert s.tick(clock.now).started == ["fake"]
        # Fractional interval set in the console applies on the next tick.
        with dbmod.get_session("default") as db:
            sched.update(db, actor="admin@example.com", enabled=None, interval_hours=0.5, fields={"interval_hours"})
            db.commit()
        clock.advance(timedelta(minutes=29))
        assert s.tick(clock.now).started == []
        clock.advance(timedelta(minutes=1))
        assert s.tick(clock.now).started == ["fake"]
        # Disabled: nothing runs, however overdue.
        with dbmod.get_session("default") as db:
            sched.update(db, actor="admin@example.com", enabled=False, interval_hours=None, fields={"enabled"})
            db.commit()
        clock.advance(10 * H)
        assert s.tick(clock.now).started == []
        assert launched == ["fake", "fake", "fake"]
    finally:
        s.stop()


def test_disabled_by_environment(clean, monkeypatch):
    monkeypatch.setattr(config.settings, "scan_schedule_enabled", False)
    clock = Clock(T0)
    s, launched = make_scheduler(clock, [FakeConnector()], delay_seconds=0)
    try:
        assert s.tick(clock.now).started == []
        # ... until an admin turns it on in the console.
        with dbmod.get_session("default") as db:
            sched.update(db, actor="admin@example.com", enabled=True, interval_hours=None, fields={"enabled"})
            db.commit()
        assert s.tick(clock.now).started == ["fake"]
    finally:
        s.stop()


def test_only_the_leader_schedules(clean):
    clock = Clock(T0)
    a, launched_a = make_scheduler(clock, [FakeConnector()], delay_seconds=0)
    b, launched_b = make_scheduler(clock, [FakeConnector()], delay_seconds=0)
    try:
        assert a.tick(clock.now).leader
        res = b.tick(clock.now)
        assert not res.leader and res.started == []
        assert launched_a == ["fake"] and launched_b == []
        # The leader goes away: the other process takes over, without re-running
        # the connector that was scanned moments ago.
        a.stop()
        clock.advance(timedelta(minutes=1))
        res = b.tick(clock.now)
        assert res.leader and res.started == []
        clock.now = T0 + 6 * H
        assert b.tick(clock.now).started == ["fake"]
    finally:
        a.stop()
        b.stop()


def test_no_overlap_skips_and_logs(clean, caplog):
    clock = Clock(T0)
    s, launched = make_scheduler(clock, [FakeConnector()], delay_seconds=0, finish=False)
    try:
        assert s.tick(clock.now).started == ["fake"]
        # The scan is still running (holding its scan lock) 6 h later: the slot is
        # skipped, not queued.
        clock.advance(6 * H)
        with advisory_lock("scan-fake"):
            res = s.tick(clock.now)
        assert res.started == [] and res.skipped == ["fake"]
        assert "skipped" in caplog.text
        with dbmod.get_session("default") as db:
            skipped = db.scalars(select(ScanRun).where(ScanRun.status == "skipped")).all()
            assert len(skipped) == 1 and skipped[0].trigger == SCHEDULED
        # Not retried every minute; the next attempt is one interval later.
        clock.advance(timedelta(minutes=1))
        with advisory_lock("scan-fake"):
            assert s.tick(clock.now).skipped == []
        assert launched == ["fake"]
    finally:
        s.stop()


def test_running_manual_scan_also_blocks(clean):
    add_run("fake", T0 - timedelta(minutes=2), trigger=MANUAL, status="running")
    clock = Clock(T0)
    s, launched = make_scheduler(clock, [FakeConnector()], delay_seconds=0)
    try:
        assert s.tick(clock.now).skipped == ["fake"] and launched == []
    finally:
        s.stop()


def test_manual_scan_does_not_reset_the_schedule(clean):
    add_run("fake", T0 - 5 * H)  # last scheduled scan
    add_run("fake", T0 - H, trigger=MANUAL)  # a manual scan since then
    clock = Clock(T0)
    s, launched = make_scheduler(clock, [FakeConnector()], delay_seconds=0)
    try:
        assert s.tick(clock.now).started == []
        clock.advance(H)  # 6 h after the last *scheduled* scan
        assert s.tick(clock.now).started == ["fake"]
    finally:
        s.stop()


def test_restart_overdue_runs_once_after_startup_delay(clean):
    add_run("fake", T0 - 10 * H)  # overdue: the backend was down for a while
    add_run("other", T0 - 2 * H)  # not due yet
    clock = Clock(T0)
    conns = [FakeConnector(), FakeConnector("other")]
    s, launched = make_scheduler(clock, conns, delay_seconds=120)
    try:
        assert s.tick(clock.now).waiting
        clock.advance(timedelta(seconds=120))
        assert s.tick(clock.now).started == ["fake"]
        # A second restart right after must not scan again (timing comes from the DB).
        s.stop()
        s2, launched2 = make_scheduler(clock, conns, delay_seconds=0)
        try:
            clock.advance(timedelta(minutes=5))
            assert s2.tick(clock.now).started == []
            clock.now = T0 - 2 * H + 6 * H
            assert s2.tick(clock.now).started == ["other"]
        finally:
            s2.stop()
    finally:
        s.stop()


def test_unconfigured_and_simulated_connectors_are_skipped(clean, monkeypatch):
    conns = [FakeConnector("aws"), FakeConnector("gcp", configured=False), SimulatedConnector()]
    monkeypatch.setattr(config.settings, "simulation_mode", False)
    clock = Clock(T0)
    s, launched = make_scheduler(clock, conns, delay_seconds=0)
    try:
        assert s.tick(clock.now).started == ["aws"]
    finally:
        s.stop()
    assert sched.schedule_reason(conns[1]) == "not configured"
    assert "SIMULATION_MODE" in sched.schedule_reason(conns[2])
    monkeypatch.setattr(config.settings, "simulation_mode", True)
    s, launched = make_scheduler(clock, conns, delay_seconds=0)
    try:
        assert s.tick(clock.now).started == ["simulated"]  # aws was just scanned
    finally:
        s.stop()


def test_failed_scheduled_scan_is_recorded_and_notifies(clean):
    conn = FakeConnector(fail=True)
    run = start_scan(conn, "default", background=False, trigger=SCHEDULED)
    assert run.status == "failed" and "cloud API unreachable" in run.message and run.finished_at
    with dbmod.get_session("default") as db:
        ev = db.scalars(select(NotificationEvent).where(NotificationEvent.source == "scan")).one()
        assert ev.event_type == "failed" and ev.severity == "high"
        assert ev.title == "Scheduled fake scan failed"
        assert ev.attributes["trigger"] == SCHEDULED and ev.attributes["connector"] == "fake"


def test_manual_scan_trigger_recorded(clean):
    run = start_scan(FakeConnector(), "default", background=False)
    assert run.trigger == MANUAL and run.status == "succeeded"


def test_orphaned_running_scan_is_failed_and_notifies(clean):
    add_run("fake", T0 - 20 * timedelta(minutes=1), status="running")
    clock = Clock(T0)
    s, launched = make_scheduler(clock, [FakeConnector()], delay_seconds=0)
    try:
        # The orphan is cleaned up, and it anchors the schedule (started 20 min ago).
        assert s.tick(clock.now).started == []
        with dbmod.get_session("default") as db:
            run = db.scalars(select(ScanRun)).one()
            assert run.status == "failed" and "Interrupted" in run.message
            ev = db.scalars(select(NotificationEvent)).one()
            assert ev.source == "scan" and ev.event_type == "failed"
    finally:
        s.stop()


def test_recent_running_scan_is_not_treated_as_orphan(clean):
    add_run("fake", T0 - timedelta(minutes=2), status="running")
    with dbmod.get_session("default") as db:
        assert sched.recover_orphans(db, "fake", T0) == 0


def test_scan_holding_its_lock_is_not_an_orphan(clean):
    add_run("fake", T0 - 3 * H, status="running")
    with advisory_lock("scan-fake"), dbmod.get_session("default") as db:
        assert sched.recover_orphans(db, "fake", T0) == 0


def test_execute_scan_unchanged_for_existing_run(clean):
    with dbmod.get_session("default") as db:
        run = ScanRun(connector="fake", status="running")
        db.add(run)
        db.commit()
        rid = run.id
    execute_scan(FakeConnector(), rid, "default")
    with dbmod.get_session("default") as db:
        assert db.get(ScanRun, rid).status == "succeeded"


# ----------------------------------------------------------------------------- settings / API

@pytest.mark.parametrize(("env", "ok"), [("6", True), ("0.25", True), ("168", True), ("0.1", False),
                                         ("169", False), ("abc", False), ("nan", False)])
def test_interval_validation(monkeypatch, env, ok):
    monkeypatch.setenv("SCAN_INTERVAL_HOURS", env)
    try:
        s = config.reload_settings()
        assert (s.scan_schedule_problems() == []) is ok
        assert (not any("SCAN_INTERVAL_HOURS" in p for p in s.auth_config_problems())) is ok
    finally:
        monkeypatch.delenv("SCAN_INTERVAL_HOURS")
        config.reload_settings()


def test_defaults(monkeypatch):
    s = config.reload_settings()
    assert s.scan_schedule_enabled is True and s.scan_interval_hours == 6 and s.scan_startup_delay_seconds == 120
    monkeypatch.setenv("SCAN_STARTUP_DELAY_SECONDS", "-1")
    try:
        assert config.reload_settings().scan_schedule_problems()
    finally:
        monkeypatch.delenv("SCAN_STARTUP_DELAY_SECONDS")
        config.reload_settings()


def test_schedule_api(client):
    r = client.get("/api/scan-schedule")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True and body["interval_hours"] == 6 and not body["interval_overridden"]
    by_name = {c["name"]: c for c in body["connectors"]}
    # Tests run in simulation mode without Azure credentials.
    assert by_name["simulated"]["scheduled"] is True
    assert by_name["azure"]["scheduled"] is False and by_name["azure"]["not_scheduled_reason"] == "not configured"
    assert by_name["simulated"]["next_run_at"] is None  # never scanned on schedule: due now

    r = client.put("/api/scan-schedule", json={"interval_hours": 0.1})
    assert r.status_code == 422
    r = client.put("/api/scan-schedule", json={})
    assert r.status_code == 422
    r = client.put("/api/scan-schedule", json={"interval_hours": 12, "enabled": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["interval_hours"] == 12 and body["enabled"] is False and body["interval_overridden"]
    assert body["updated_by"] == "admin@example.com"
    assert not any(c["scheduled"] for c in body["connectors"])
    # null resets to the environment default; omitted fields are unchanged.
    r = client.put("/api/scan-schedule", json={"interval_hours": None})
    body = r.json()
    assert body["interval_hours"] == 6 and not body["interval_overridden"] and body["enabled"] is False

    with dbmod.get_session("default") as db:
        entries = db.scalars(select(AuditLog).where(AuditLog.action == "scan_schedule_updated")
                             .order_by(AuditLog.id)).all()
        assert len(entries) == 2
        assert entries[0].detail["after"] == {"enabled": False, "interval_hours": 12}
        assert entries[1].detail["before"]["interval_hours"] == 12


def test_schedule_api_shows_last_and_next(client):
    start = utcnow() - 2 * H
    add_run("simulated", start)
    body = client.get("/api/scan-schedule").json()
    sim = {c["name"]: c for c in body["connectors"]}["simulated"]
    assert sim["last_scheduled_run"]["trigger"] == SCHEDULED
    assert sim["last_run"]["status"] == "succeeded"
    nxt = datetime.fromisoformat(sim["next_run_at"].replace("Z", "+00:00")).replace(tzinfo=None)
    assert abs((nxt - (start + 6 * H)).total_seconds()) < 2
    scans = client.get("/api/scans").json()
    assert any(s["trigger"] == SCHEDULED for s in scans)


def test_schedule_api_roles(client):
    make_user(client, "viewer", password="a-long-test-password")
    make_user(client, "analyst", password="a-long-test-password")
    client.post("/api/auth/logout")
    client.cookies.clear()
    login(client, "analyst@example.com", "a-long-test-password")
    assert client.get("/api/scan-schedule").status_code == 200
    assert client.put("/api/scan-schedule", json={"enabled": False}).status_code == 403
    client.post("/api/auth/logout")
    client.cookies.clear()
    login(client, "viewer@example.com", "a-long-test-password")
    assert client.get("/api/scan-schedule").status_code == 200
    assert client.put("/api/scan-schedule", json={"enabled": False}).status_code == 403
