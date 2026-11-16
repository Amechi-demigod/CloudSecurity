"""Lifecycle of cloud assets (Azure, AWS, GCP): removal detection, restore and permanent deletion
(docs/CLOUD_INVENTORY.md).

* A scan reports the scopes (subscriptions / accounts / projects) it read completely
  (`CollectionResult.scopes_read`). For each of those, an asset of the connector in that scope that was not
  returned gets `missed_scans` + 1, one that was returned gets 0 (app/services/ingest.py). A scan that fails,
  or fails for one scope, never counts for that scope.
* At `CLOUD_REMOVE_AFTER_MISSES` misses in a row the asset is marked removed (`removed_at`): its open findings
  and vulnerabilities close ("resource removed") and it leaves the active inventory, risk, exposure,
  attack paths, posture and compliance. Returned by a later scan it is active again.
* `purge_expired` (leader-elected job, `CloudPurgeWorker`) deletes assets removed more than
  `CLOUD_REMOVED_RETENTION_DAYS` days ago, with everything that references them.
* `remove_scope` is the console's "Remove subscription / account / project": it deletes a scope's assets now.

Only assets of the cloud connectors (`CLOUD_SOURCES`) take part; devices, directory objects, sensor hosts, the
simulated connector and external attack-surface hosts have their own lifecycles.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta

from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..locks import LeaderLock
from ..models import (
    Alert,
    AlertEvent,
    Asset,
    AssetPackage,
    ExternalHost,
    Finding,
    Relationship,
    RuntimeEvent,
    ScanRun,
    Vulnerability,
    VulnMatchState,
    utcnow,
)
from ..network.models import NetworkDevice

log = logging.getLogger(__name__)

CLOUD_SOURCES = ("azure", "aws", "gcp")
RESOURCE_REMOVED = "resource_removed"
_CHUNK = 500


def _chunks(items: Sequence[str]) -> Iterable[list[str]]:
    for i in range(0, len(items), _CHUNK):
        yield list(items[i:i + _CHUNK])


# ----------------------------------------------------------------------------- scan time
def apply_scan(db: Session, source: str, scopes_read: Iterable[str], seen_ids: set[str], now: datetime) -> dict:
    """After ingesting a scan: count misses for the assets of the scopes it read completely and mark the ones
    that reached the limit removed. Returned assets were already reset by the ingest. Caller commits."""
    if source not in CLOUD_SOURCES:
        return {}
    limit = config.settings.cloud_remove_after_misses
    # A scope only counts when the scan also returned something for it (its own subscription / account / project
    # asset at least): an empty answer is not evidence that everything is gone.
    returned = {sid for (sid,) in db.execute(select(Asset.subscription_id).where(
        Asset.id.in_(list(seen_ids)))) if sid} if seen_ids else set()
    removed: list[Asset] = []
    missed = 0
    for scope in sorted(set(scopes_read) & returned):
        stmt = select(Asset).where(Asset.source == source, Asset.subscription_id == scope,
                                   Asset.removed_at.is_(None))
        for a in db.scalars(stmt):
            if a.id in seen_ids:
                continue
            a.missed_scans = (a.missed_scans or 0) + 1
            missed += 1
            if a.missed_scans >= limit:
                a.removed_at = now
                removed.append(a)
    db.flush()
    closed = _close_for_removed(db, [a.id for a in removed], now) if removed else (0, 0)
    return {"assets_missed": missed, "assets_removed": len(removed), "findings_closed": closed[0],
            "vulnerabilities_closed": closed[1]}


def _close_for_removed(db: Session, asset_ids: list[str], now: datetime) -> tuple[int, int]:
    """Close the open findings (reason "resource removed") and vulnerabilities of removed assets."""
    findings = vulns = 0
    for chunk in _chunks(asset_ids):
        for f in db.scalars(select(Finding).where(Finding.asset_id.in_(chunk), Finding.status == "open")):
            f.status, f.resolved_at, f.close_reason = "resolved", now, RESOURCE_REMOVED
            findings += 1
        for v in db.scalars(select(Vulnerability).where(Vulnerability.asset_id.in_(chunk),
                                                        Vulnerability.status == "open")):
            v.status, v.resolved_at = "resolved", now
            vulns += 1
    db.flush()
    return findings, vulns


def clear_removed_reason(db: Session, asset_ids: list[str]) -> None:
    """Assets returned after being removed: their findings are no longer closed because of a removal.
    Posture evaluation then reopens the ones that still fail (a resolved finding that fails is a regression)."""
    for chunk in _chunks(asset_ids):
        db.execute(update(Finding).where(Finding.asset_id.in_(chunk), Finding.close_reason == RESOURCE_REMOVED)
                   .values(close_reason=None).execution_options(synchronize_session="fetch"))


# ----------------------------------------------------------------------------- deletion
def delete_assets(db: Session, asset_ids: Sequence[str]) -> dict[str, int]:
    """Delete assets of the session's organisation and everything that references them, children first (no
    reliance on ON DELETE CASCADE, which SQLite only honours with a pragma). Caller commits."""
    ids = list(dict.fromkeys(asset_ids))
    counts = dict.fromkeys(("assets", "findings", "vulnerabilities", "relationships", "packages", "alerts",
                            "runtime_events"), 0)

    def run(stmt) -> int:
        return db.execute(stmt.execution_options(synchronize_session=False)).rowcount or 0

    for chunk in _chunks(ids):
        counts["findings"] += run(delete(Finding).where(Finding.asset_id.in_(chunk)))
        counts["vulnerabilities"] += run(delete(Vulnerability).where(Vulnerability.asset_id.in_(chunk)))
        counts["relationships"] += run(delete(Relationship).where(or_(Relationship.source_id.in_(chunk),
                                                                      Relationship.target_id.in_(chunk))))
        counts["packages"] += run(delete(AssetPackage).where(AssetPackage.asset_id.in_(chunk)))
        run(delete(VulnMatchState).where(VulnMatchState.target_type == "asset",
                                         VulnMatchState.target_id.in_(chunk)))
        alert_ids = list(db.scalars(select(Alert.id).where(Alert.asset_id.in_(chunk))))
        event_ids = list(db.scalars(select(RuntimeEvent.id).where(RuntimeEvent.asset_id.in_(chunk))))
        for sub in _chunks(alert_ids):
            run(delete(AlertEvent).where(AlertEvent.alert_id.in_(sub)))
        for sub in _chunks(event_ids):
            run(delete(AlertEvent).where(AlertEvent.event_id.in_(sub)))
        counts["alerts"] += run(delete(Alert).where(Alert.asset_id.in_(chunk)))
        counts["runtime_events"] += run(delete(RuntimeEvent).where(RuntimeEvent.asset_id.in_(chunk)))
        # Plain references that are not history: unlink instead of deleting the host / device.
        run(update(ExternalHost).where(ExternalHost.asset_id.in_(chunk)).values(asset_id=None))
        run(update(NetworkDevice).where(NetworkDevice.asset_id.in_(chunk)).values(asset_id=None))
        run(update(NetworkDevice).where(NetworkDevice.sensor_asset_id.in_(chunk)).values(sensor_asset_id=None))
        counts["assets"] += run(delete(Asset).where(Asset.id.in_(chunk)))
    db.flush()
    db.expire_all()
    return counts


def purge_expired(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Delete the session organisation's cloud assets removed longer ago than the retention period, with their
    closed findings and dependent rows. Caller commits."""
    now = now or utcnow()
    cutoff = now - timedelta(days=config.settings.cloud_removed_retention_days)
    ids = list(db.scalars(select(Asset.id).where(Asset.removed_at.is_not(None), Asset.removed_at < cutoff,
                                                 Asset.source.in_(CLOUD_SOURCES))))
    return delete_assets(db, ids) if ids else {}


class CloudPurgeWorker:
    """Daily, leader-elected job (like app/services/dashboard_snapshots.py): permanently deletes removed cloud
    assets past their retention for every active organisation. `tick()` takes an explicit `now` for tests."""

    LOCK_NAME = "cloud-purge"

    def __init__(self, tick_seconds: float = 3600.0, clock: Callable[[], datetime] = utcnow):
        self.tick_seconds = tick_seconds
        self.clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    @property
    def is_leader(self) -> bool:
        return self._leader.acquired

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="cloud-purge", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> dict[str, dict[str, int]] | None:
        """Organisation id -> rows deleted; None when another process is the leader."""
        if not (self._leader.held() if self._leader.acquired else self._leader.try_acquire()):
            return None
        from ..auth import audit

        out: dict[str, dict[str, int]] = {}
        for org_id, db in tenancy.for_each_active_org():
            try:
                counts = purge_expired(db, now or self.clock())
                if counts.get("assets"):
                    audit(db, "cloud_resources_purged", actor_email="system", target=f"organization:{org_id}",
                          retention_days=config.settings.cloud_removed_retention_days, **counts)
                    db.commit()
                    out[org_id] = counts
                    log.info("purged %d removed cloud assets of %s", counts["assets"], org_id)
            except Exception:
                db.rollback()
                log.exception("purge of removed cloud assets of organisation %s failed", org_id)
        return out

    def _run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("cloud purge tick failed")
            if self._stop.wait(self.tick_seconds):
                return


# ----------------------------------------------------------------------------- scopes (Settings > Cloud connections)
def configured_scopes(provider: str, cfg: dict) -> list[str]:
    """The subscription / account / project ids a stored connector config scans."""
    if provider == "azure":
        return list(cfg.get("subscription_ids") or [])
    if provider == "aws":  # accounts of the role ARNs (arn:aws:iam::<account>:role/...)
        return [a.split(":")[4] for a in cfg.get("role_arns") or [] if a.count(":") >= 5]
    return list(cfg.get("project_ids") or [])


def _same(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()


def list_scopes(db: Session, provider: str, configured: Iterable[str]) -> list[dict]:
    """Every subscription / account / project known for `provider`: the configured ones plus any that only
    exist in data (e.g. left by a failed first scan). Counts are of the connector's assets, active and removed."""
    rows = db.execute(select(Asset.subscription_id, func.count(), func.max(Asset.last_seen),
                             func.sum(case((Asset.removed_at.is_(None), 1), else_=0)))
                      .where(Asset.source == provider, Asset.subscription_id.is_not(None))
                      .group_by(Asset.subscription_id)).all()
    return _merge(db, provider, list(configured), rows)


def _merge(db: Session, provider: str, configured: list[str], rows: list) -> list[dict]:
    scopes: dict[str, dict] = {}
    for sid in configured:
        scopes.setdefault(sid.lower(), {"id": sid, "configured": True, "resources": 0, "removed": 0,
                                        "last_scanned": None})
    for sid, total, last_seen, active in rows:
        d = scopes.setdefault(sid.lower(), {"id": sid, "configured": False, "resources": 0, "removed": 0,
                                            "last_scanned": None})
        d["resources"] = int(active or 0)
        d["removed"] = int(total or 0) - int(active or 0)
        d["last_scanned"] = last_seen
    runs = list(db.scalars(select(ScanRun).where(ScanRun.connector == provider, ScanRun.finished_at.is_not(None))
                           .order_by(ScanRun.started_at.desc()).limit(50)))
    for key, d in scopes.items():
        d["last_scan_status"], d["last_scan_at"] = None, None
        for run in runs:
            if any(str(e).lower().startswith(key) for e in run.errors or []):
                d["last_scan_status"], d["last_scan_at"] = "failed", run.finished_at
                break
        else:
            if d["configured"] and runs:
                d["last_scan_status"], d["last_scan_at"] = runs[0].status, runs[0].finished_at
    return sorted(scopes.values(), key=lambda d: (not d["configured"], d["id"].lower()))


def scope_asset_ids(db: Session, provider: str, scope_id: str) -> list[str]:
    return list(db.scalars(select(Asset.id).where(Asset.source == provider,
                                                  func.lower(Asset.subscription_id) == scope_id.lower())))


def drop_from_config(provider: str, cfg: dict, scope_id: str) -> dict:
    """The connector config without `scope_id` (AWS: without the role ARNs of that account)."""
    out = dict(cfg)
    if provider == "azure":
        out["subscription_ids"] = [s for s in cfg.get("subscription_ids") or [] if not _same(s, scope_id)]
    elif provider == "aws":
        out["role_arns"] = [a for a in cfg.get("role_arns") or []
                            if not (a.count(":") >= 5 and _same(a.split(":")[4], scope_id))]
    else:
        out["project_ids"] = [p for p in cfg.get("project_ids") or [] if not _same(p, scope_id)]
    return out
