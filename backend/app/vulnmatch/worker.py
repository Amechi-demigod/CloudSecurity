"""Leader-elected background job for vulnerability matching.

Every tick (default 30 s) the leader (one per deployment, see app/locks.py):

1. refreshes the CISA KEV catalog when it is older than VULN_KEV_REFRESH_HOURS
   (and EPSS scores of open CVEs), re-flags matching vulnerabilities and
   notifies about CVEs that just became known-exploited;
2. queues every device / asset whose last match is older than
   VULN_REMATCH_INTERVAL_HOURS (new CVEs are published daily), and devices /
   assets that have an inventory but were never matched;
3. matches the queued targets whose last inventory change is older than
   VULN_DEBOUNCE_SECONDS (a burst of check-ins is handled together), then
   sends aggregated notifications (one per CVE);
4. resolves the vulnerabilities of revoked devices and forgets state of
   deleted targets.

Feed failures are recorded (vuln_feed_status) and matching continues from the
cached data; nothing here ever runs inside an agent check-in.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, select

from .. import config
from .. import db as dbmod
from ..locks import LeaderLock
from ..models import Asset, AssetPackage, Device, DeviceSoftware, Vulnerability, VulnFeedStatus, VulnMatchState, utcnow
from . import feeds, matcher
from .notify import Item, notify
from .state import ASSET, DEVICE

log = logging.getLogger(__name__)

MAX_TARGETS_PER_TICK = 25
FEED_RETRY = timedelta(hours=1)


@dataclass
class TickResult:
    leader: bool
    matched: list[str] = field(default_factory=list)
    kev_refreshed: bool = False
    notifications: int = 0
    errors: list[str] = field(default_factory=list)


def _due(st: VulnFeedStatus | None, every: timedelta, now: datetime) -> bool:
    if st is None or st.last_attempt_at is None:
        return True
    if st.last_success_at is not None and now - st.last_success_at < every:
        return False
    return now - st.last_attempt_at >= (FEED_RETRY if st.last_error else every)


def refresh_kev(db, now: datetime, *, force: bool = False) -> tuple[bool, int]:
    """Refresh KEV (when due); re-flag open vulnerabilities. Returns (refreshed, notifications)."""
    s = config.settings
    if not force and not _due(db.get(VulnFeedStatus, "kev"), timedelta(hours=s.vuln_kev_refresh_hours), now):
        return False, 0
    try:
        cat = feeds.fetch_kev()
    except feeds.FeedError as e:
        log.warning("KEV refresh failed: %s", e)
        feeds.record_status(db, "kev", ok=False, error=str(e), now=now)
        db.commit()
        return False, 0
    feeds.cache_put(db, "kev", {"cves": cat}, timedelta(days=30), now)
    feeds.record_status(db, "kev", ok=True, items=len(cat), now=now)
    newly: list[Item] = []
    for v in db.scalars(select(Vulnerability).where(Vulnerability.source.in_((matcher.NVD, matcher.OSV)),
                                                    Vulnerability.status == "open")):
        k = cat.get(v.cve_id)
        was = bool(v.kev)
        v.kev = k is not None
        v.exploit_available = v.kev
        if k is not None:
            v.evidence = {**(v.evidence or {}), "kev": k}
        if v.kev != was:
            matcher.score(v, v.asset)
            if v.kev:
                newly.append(_item(db, v))
    sent = notify(db, newly, now, reason="kev")
    db.commit()
    return True, sent


def refresh_epss(db, now: datetime) -> None:
    s = config.settings
    if not s.epss_enabled or not _due(db.get(VulnFeedStatus, "epss"), timedelta(hours=s.vuln_kev_refresh_hours), now):
        return
    cves = sorted({c for (c,) in db.execute(select(Vulnerability.cve_id).where(
        Vulnerability.source.in_((matcher.NVD, matcher.OSV)), Vulnerability.status == "open").distinct())
        if c.startswith("CVE-")})
    if not cves:
        return
    try:
        scores = feeds.fetch_epss(cves)
    except feeds.FeedError as e:
        log.warning("EPSS refresh failed: %s", e)
        feeds.record_status(db, "epss", ok=False, error=str(e), now=now)
        db.commit()
        return
    row = feeds.cache_get(db, "epss")
    merged = {**((row.data.get("scores") or {}) if row is not None else {}), **scores}
    feeds.cache_put(db, "epss", {"scores": merged}, timedelta(days=30), now)
    feeds.record_status(db, "epss", ok=True, items=len(scores), now=now)
    for v in db.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(list(scores)),
                                                    Vulnerability.status == "open")):
        v.epss = scores.get(v.cve_id)
    db.commit()


def _item(db, v: Vulnerability) -> Item:
    if v.device_id:
        d = db.get(Device, v.device_id)
        return Item(v.cve_id, v.severity, bool(v.kev), v.cvss, v.package, v.title, v.fixed_version, DEVICE,
                    v.device_id, d.hostname if d is not None else v.device_id)
    return Item(v.cve_id, v.severity, bool(v.kev), v.cvss, v.package, v.title, v.fixed_version, ASSET,
                v.asset_id or "", v.asset.name if v.asset else (v.asset_id or ""))


def queue_targets(db, now: datetime) -> int:
    """Request matches for stale / never-matched targets. Returns how many were queued."""
    s = config.settings
    cutoff = now - timedelta(hours=s.vuln_rematch_interval_hours)
    n = 0
    states = {(st.target_type, st.target_id): st for st in db.scalars(select(VulnMatchState))}
    for st in states.values():
        if st.requested_at is None and (st.matched_at is None or st.matched_at < cutoff):
            st.requested_at = now - timedelta(seconds=s.vuln_debounce_seconds)
            n += 1
    with_software = {d for (d,) in db.execute(select(DeviceSoftware.device_id).distinct())}
    for d in db.scalars(select(Device).where(Device.status == "active")):
        # Devices enrolled before matching existed (or that never sent software) still get their OS checked.
        if (DEVICE, d.id) not in states and (d.id in with_software or d.last_checkin_at is not None):
            db.add(VulnMatchState(target_type=DEVICE, target_id=d.id, inventory_hash="", checked=[],
                                  not_checked=[], os_info={},
                                  requested_at=now - timedelta(seconds=s.vuln_debounce_seconds)))
            n += 1
    for (aid,) in db.execute(select(AssetPackage.asset_id).distinct()):
        if (ASSET, aid) not in states:
            db.add(VulnMatchState(target_type=ASSET, target_id=aid, inventory_hash="", checked=[], not_checked=[],
                                  os_info={}, requested_at=now - timedelta(seconds=s.vuln_debounce_seconds)))
            n += 1
    db.commit()
    return n


def cleanup(db, now: datetime) -> None:
    for d in db.scalars(select(Device).where(Device.status != "active")):
        if matcher.resolve_all(db, Vulnerability.device_id == d.id, now, "device revoked"):
            log.info("resolved vulnerabilities of revoked device %s", d.id)
        db.execute(delete(VulnMatchState).where(VulnMatchState.target_type == DEVICE,
                                                VulnMatchState.target_id == d.id))
    device_ids = {i for (i,) in db.execute(select(Device.id))}
    asset_ids = {i for (i,) in db.execute(select(AssetPackage.asset_id).distinct())}
    for st in list(db.scalars(select(VulnMatchState))):
        if (st.target_type == DEVICE and st.target_id not in device_ids) or (
                st.target_type == ASSET and st.target_id not in asset_ids):
            db.delete(st)
    db.commit()


def match_due(db, now: datetime, limit: int = MAX_TARGETS_PER_TICK, *, force: bool = False) -> TickResult:
    s = config.settings
    res = TickResult(True)
    cutoff = now if force else now - timedelta(seconds=s.vuln_debounce_seconds)
    due = list(db.scalars(select(VulnMatchState).where(VulnMatchState.requested_at.is_not(None),
                                                       VulnMatchState.requested_at <= cutoff)
                          .order_by(VulnMatchState.requested_at).limit(limit)))
    items: list[Item] = []
    for st in due:
        try:
            if st.target_type == DEVICE:
                d = db.get(Device, st.target_id)
                if d is None or d.status != "active":
                    st.requested_at = None
                    continue
                out = matcher.match_device(db, d, now)
            else:
                a = db.get(Asset, st.target_id)
                if a is None:
                    st.requested_at = None
                    continue
                out = matcher.match_asset(db, a, now)
            db.commit()
            res.matched.append(f"{st.target_type}:{st.target_id}")
            items.extend(Item(v.cve_id, v.severity, bool(v.kev), v.cvss, v.package, v.title, v.fixed_version,
                              out.target_type, out.target_id, out.target_name) for v in out.new)
        except Exception as e:  # one broken target must not stop the others
            db.rollback()
            log.exception("vulnerability matching of %s %s failed", st.target_type, st.target_id)
            st = db.get(VulnMatchState, st.id)
            if st is not None:
                st.error = f"{e.__class__.__name__}: {e}"[:2000]
                st.requested_at = None
                st.matched_at = now
                db.commit()
            res.errors.append(f"{st.target_type if st else '?'}: {e}")
    if items:
        res.notifications += notify(db, items, now)
        db.commit()
    return res


def run_once(now: datetime | None = None, *, force: bool = False) -> TickResult:
    """One full pass (used by the worker tick and tests). `force` matches queued
    targets without waiting for the debounce period."""
    now = now or utcnow()
    with dbmod.get_session() as db:
        refreshed, sent = refresh_kev(db, now)
        queue_targets(db, now)
        res = match_due(db, now, force=force)
        refresh_epss(db, now)
        cleanup(db, now)
        res.kev_refreshed = refreshed
        res.notifications += sent
        return res


class VulnWorker:
    LOCK_NAME = "vuln-matching"

    def __init__(self, interval: float = 30.0, clock: Callable[[], datetime] = utcnow):
        self.interval = interval
        self.clock = clock
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="vuln-matching", daemon=True)
        self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> TickResult:
        if not config.settings.vuln_matching_enabled:
            return TickResult(False)
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return TickResult(False)
        return run_once(now or self.clock())

    def _run(self) -> None:
        if self._stop.wait(20):  # let the app settle after start-up
            return
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("vulnerability matching tick failed")
            self._wake.wait(self.interval)
            self._wake.clear()


_worker: VulnWorker | None = None


def set_worker(w: VulnWorker | None) -> None:
    global _worker
    _worker = w


def get_worker() -> VulnWorker | None:
    return _worker
