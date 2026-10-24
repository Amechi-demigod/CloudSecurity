"""Agent update automation: "set and forget" rollout, "update now", the pending
state shown per device, and the optional GitHub Releases auto-import.

Update modes (docs/AGENT_UPDATES.md)
------------------------------------
* automatic (default): the newest imported (signed, non-withdrawn, non-expired)
  release is targeted to the Pilot ring at once, and to every other ring
  (including "All devices", i.e. devices nobody assigned) after the soak
  period, unless a Pilot device reported the release rolled back / rejected
  (or still failed at the end of the soak). Then the rollout pauses and a
  notification is sent; an admin can promote anyway.
* manual: rings are only changed by admins (the classic ring controls).

None of this weakens the trust model: the server still only chooses among
releases signed by the release key, and agents verify every one themselves.
Auto-import uses the same verification as a console upload (signature against
the trusted keys, sizes and SHA-256 of every binary, expiry).
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, tenancy
from .. import db as dbmod
from ..auth import audit
from ..locks import LeaderLock
from ..models import (
    AgentRelease,
    AgentUpdateEvent,
    AgentUpdateRing,
    AgentUpdateSettings,
    Device,
    DeviceCommand,
    utcnow,
)
from ..notifications import agent_update_source as notify
from . import agent_updates as svc

log = logging.getLogger(__name__)

MODES = ("automatic", "manual")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
TAG_RE = re.compile(r"^agent-v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")
BUNDLE_ASSET = "cnapp-agent-update.tar.gz"
UPDATE_NOW_COMMAND_TTL = timedelta(hours=1)
UPDATE_NOW_STAGGER_SECONDS = 20  # per wave of AGENT_UPDATE_MAX_PARALLEL_DOWNLOADS devices
IN_PROGRESS = ("downloading", "verified", "installing")


# ----------------------------------------------------------------------------- settings
def get_settings(db: Session) -> AgentUpdateSettings:
    """The session organisation's update settings (created on first use)."""
    oid = tenancy.require_org(db)
    st = db.get(AgentUpdateSettings, oid)
    if st is None:
        s = config.settings
        mode = s.agent_update_default_mode if s.agent_update_default_mode in MODES else "automatic"
        st = AgentUpdateSettings(organization_id=oid, mode=mode, soak_hours=max(0, min(720, s.agent_update_default_soak_hours)),
                                 updated_at=utcnow(), updated_by="system")
        db.add(st)
        db.flush()
    return st


def import_settings(db: Session) -> AgentUpdateSettings | None:
    """The platform-wide auto-import settings: the default organisation's row."""
    if tenancy.is_default(tenancy.org_id(db)):
        return get_settings(db)
    return db.scalar(select(AgentUpdateSettings).where(AgentUpdateSettings.organization_id == tenancy.DEFAULT_ORG_ID)
                     .execution_options(tenant_unscoped=True))


def import_enabled(st: AgentUpdateSettings) -> bool:
    return config.settings.agent_update_auto_import if st.auto_import_enabled is None else st.auto_import_enabled


def import_repo(st: AgentUpdateSettings) -> str:
    return st.auto_import_repo or config.settings.agent_update_releases_repo


def import_interval(st: AgentUpdateSettings) -> int:
    v = st.auto_import_interval_minutes or config.settings.agent_update_auto_import_interval_minutes
    return max(15, min(7 * 24 * 60, v))


# ----------------------------------------------------------------------------- rollout
def newest_release(db: Session, now: datetime | None = None) -> AgentRelease | None:
    now = now or utcnow()
    rels = [r for r in db.scalars(select(AgentRelease).where(AgentRelease.withdrawn_at.is_(None)))
            if r.expires_at > now]
    return max(rels, key=lambda r: svc.version_sort_key(r.version), default=None)


def pilot_ring(all_rings: list[AgentUpdateRing]) -> AgentUpdateRing | None:
    """The ring named "Pilot", else the first non-default ring by position."""
    for r in all_rings:
        if r.name.strip().lower() == "pilot":
            return r
    return next((r for r in all_rings if not r.is_default), None)


def _target(ring: AgentUpdateRing, rel: AgentRelease, now: datetime) -> dict | None:
    changes = {}
    if ring.target_release_id != rel.id:
        changes["target_release_id"] = {"from": ring.target_release_id, "to": rel.id, "version": rel.version}
        ring.target_release_id = rel.id
    if ring.rollout_percent != 100:
        changes["rollout_percent"] = {"from": ring.rollout_percent, "to": 100}
        ring.rollout_percent = 100
    if ring.paused:
        changes["paused"] = {"from": True, "to": False}
        ring.paused = False
    if changes:
        ring.updated_at, ring.updated_by = now, "automatic rollout"
        return changes
    return None


def pilot_devices(db: Session, pilot: AgentUpdateRing, all_rings: list[AgentUpdateRing]) -> list[Device]:
    devices = db.scalars(select(Device).where(Device.status == "active"))
    return [d for d in devices if (r := svc.ring_for(d, all_rings)) is not None and r.id == pilot.id]


def pilot_failures(db: Session, rel: AgentRelease, devices: list[Device], final: bool) -> list[str]:
    """Pilot devices on which `rel` was rolled back / rejected (and, at the end
    of the soak, devices whose last status for it is still `failed`)."""
    ids = {d.id: d for d in devices}
    if not ids:
        return []
    bad = set(db.scalars(select(AgentUpdateEvent.device_id).where(
        AgentUpdateEvent.release_id == rel.id, AgentUpdateEvent.device_id.in_(list(ids)),
        AgentUpdateEvent.status.in_(("rolled_back", "rejected")))))
    if final:
        bad |= {d.id for d in devices if d.update_status == "failed" and d.update_status_version == rel.version}
    return sorted(ids[i].hostname for i in bad)


@dataclass
class TickResult:
    action: str  # none | started | promoted | paused
    detail: str = ""


def promote_all(db: Session, st: AgentUpdateSettings, rel: AgentRelease, actor: str, now: datetime,
                reason: str) -> None:
    changed = {}
    for r in svc.rings(db):
        c = _target(r, rel, now)
        if c:
            changed[r.name] = c
    st.auto_stage, st.auto_stage_at, st.auto_paused_reason = "all", now, None
    audit(db, "agent_update_auto_promoted", actor_email=actor, target=f"agent-release:{rel.id}",
          version=rel.version, rings=changed, reason=reason)
    notify.rollout_event(db, "rollout_promoted", rel.version,
                         f"{rel.version} is now targeted to all devices ({reason}).")


def auto_tick(db: Session, now: datetime | None = None) -> TickResult:
    """Advance the automatic rollout (caller commits). Idempotent; cheap."""
    now = now or utcnow()
    st = get_settings(db)
    if st.mode != "automatic":
        return TickResult("none", "manual mode")
    svc.ensure_default_rings(db)
    rel = newest_release(db, now)
    if rel is None:
        return TickResult("none", "no release")
    all_rings = svc.rings(db)
    pilot = pilot_ring(all_rings)
    if st.auto_release_id != rel.id:
        st.auto_release_id, st.auto_paused_reason = rel.id, None
        if pilot is None:
            promote_all(db, st, rel, "automatic rollout", now, "no pilot ring")
            return TickResult("promoted", "no pilot ring")
        already = pilot.target_release_id == rel.id and not pilot.paused and pilot.rollout_percent == 100
        changes = _target(pilot, rel, now)
        st.auto_stage = "pilot"
        st.auto_stage_at = pilot.updated_at if already and pilot.updated_at else now
        audit(db, "agent_update_auto_pilot", actor_email="automatic rollout", target=f"agent-release:{rel.id}",
              version=rel.version, ring=pilot.name, changes=changes, soak_hours=st.soak_hours)
        notify.rollout_event(db, "rollout_started", rel.version,
                             f"{rel.version} is targeted to the {pilot.name} ring; everyone else gets it after "
                             f"{st.soak_hours} h unless a {pilot.name} device fails to update.")
        return TickResult("started", pilot.name)
    if st.auto_stage != "pilot":
        return TickResult("none", st.auto_stage or "")
    if pilot is None:
        promote_all(db, st, rel, "automatic rollout", now, "no pilot ring")
        return TickResult("promoted", "no pilot ring")
    devices = pilot_devices(db, pilot, all_rings)
    soaked = st.auto_stage_at is None or now - st.auto_stage_at >= timedelta(hours=st.soak_hours)
    failed = pilot_failures(db, rel, devices, final=soaked)
    if failed:
        st.auto_stage, st.auto_stage_at = "paused", now
        st.auto_paused_reason = (f"{len(failed)} {pilot.name} device(s) failed to update to {rel.version}: "
                                 + ", ".join(failed[:10]))[:500]
        audit(db, "agent_update_auto_paused", actor_email="automatic rollout", target=f"agent-release:{rel.id}",
              version=rel.version, devices=failed[:50])
        notify.rollout_event(db, "rollout_paused", rel.version,
                             f"Automatic rollout of {rel.version} paused: {st.auto_paused_reason}. Other rings "
                             "keep their current release. Publish a fixed release, or promote it anyway on "
                             "Devices > Agent updates.", severity="high")
        return TickResult("paused", st.auto_paused_reason)
    if soaked:
        promote_all(db, st, rel, "automatic rollout", now, f"soak of {st.soak_hours} h passed without failures")
        return TickResult("promoted", "soak passed")
    return TickResult("none", "soaking")


def automation_state(db: Session, now: datetime | None = None) -> dict:
    now = now or utcnow()
    st = get_settings(db)
    rel = db.get(AgentRelease, st.auto_release_id) if st.auto_release_id else None
    all_rings = svc.rings(db)
    pilot = pilot_ring(all_rings)
    promote_at = None
    if rel is not None and st.auto_stage == "pilot" and st.auto_stage_at:
        promote_at = st.auto_stage_at + timedelta(hours=st.soak_hours)
    pilot_count = len(pilot_devices(db, pilot, all_rings)) if pilot else 0
    imp = import_settings(db) or AgentUpdateSettings()
    return {
        "mode": st.mode, "soak_hours": st.soak_hours,
        "rollout": {"release_id": rel.id if rel else None, "version": rel.version if rel else None,
                    "stage": st.auto_stage if rel else None, "stage_at": _z(st.auto_stage_at) if rel else None,
                    "promote_at": _z(promote_at), "paused_reason": st.auto_paused_reason,
                    "pilot_ring": pilot.name if pilot else None, "pilot_devices": pilot_count},
        "auto_import": {"enabled": import_enabled(imp), "repo": import_repo(imp),
                        "interval_minutes": import_interval(imp),
                        "enabled_default": config.settings.agent_update_auto_import,
                        "checked_at": _z(imp.import_checked_at), "status": imp.import_status,
                        "message": imp.import_message, "failed_version": imp.import_failed_version,
                        "api": config.settings.agent_update_releases_api,
                        # Only the platform operator (default organisation) manages the import.
                        "managed_here": tenancy.is_default(tenancy.org_id(db))},
        "jitter_seconds": svc.effective_jitter_seconds(db),
        "updated_at": _z(st.updated_at), "updated_by": st.updated_by,
    }


def _z(d: datetime | None) -> str | None:
    return d.isoformat() + "Z" if d else None


# ----------------------------------------------------------------------------- per-device pending state
def pending_state(db: Session, d: Device, t: svc.Target, now: datetime | None = None) -> dict:
    """What happens next for this device, for the console (instead of "—")."""
    now = now or utcnow()
    interval = max(60, d.check_in_interval_seconds or 900)
    last = d.last_checkin_at or d.last_seen_at
    next_checkin = (last + timedelta(seconds=interval)) if last else None
    out = {"state": "none", "message": "", "offered_at": None, "starts_by": None, "next_checkin_by": _z(next_checkin),
           "check_in_interval_seconds": interval, "update_now_requested_at": _z(d.update_now_requested_at),
           "update_now_supported": "check_for_update" in (d.agent_features or "").split(","),
           "can_update_now": False}
    rel = t.release
    if d.status != "active":
        out.update(state="none", message="device is revoked")
        return out
    if rel is None:
        out.update(state="no_target", message=t.reason)
        return out
    plat = svc.platform_of(d)
    blocker = svc.offer_blocker(db, d, rel, d.agent_version or "", *(plat or (None, None)), now)
    if blocker == "already running the target version":
        out.update(state="up_to_date", message=f"running the target version {rel.version}")
        return out
    if d.update_status in IN_PROGRESS and d.update_status_version == rel.version:
        out.update(state="updating", message=f"updating to {rel.version} ({d.update_status.replace('_', ' ')})")
        return out
    if blocker:
        out.update(state="blocked", message=blocker)
        return out
    out["can_update_now"] = True
    if svc.update_now_active(d, now) and (d.update_offered_at is None or d.update_offered_at < d.update_now_requested_at):
        out.update(state="update_now_requested",
                   message=f"Update now requested: the agent checks in at its next command poll (about a minute) "
                           f"and starts {rel.version} right away")
        return out
    if d.update_offered_release_id == rel.id and d.update_offered_at is not None:
        starts_by = d.update_offered_at + timedelta(seconds=d.update_offer_jitter_seconds or 0)
        out.update(state="offered", offered_at=_z(d.update_offered_at), starts_by=_z(starts_by),
                   message=f"{rel.version} offered; the agent starts it after a random delay of up to "
                           f"{d.update_offer_jitter_seconds or 0} s")
        if d.update_status == "failed" and d.update_status_version == rel.version:
            out["message"] = (f"last attempt failed ({d.update_status_detail or 'see history'}); "
                              "retried at the next check-in")
        return out
    out.update(state="waiting_checkin",
               message=f"{rel.version} is offered at the device's next check-in (every {interval // 60} min)")
    return out


# ----------------------------------------------------------------------------- update now
def _queue(db: Session, device: Device, cmd_type: str, actor_id: str | None, actor_email: str, reason: str,
           now: datetime) -> DeviceCommand:
    existing = db.scalar(select(DeviceCommand).where(
        DeviceCommand.device_id == device.id, DeviceCommand.type == cmd_type, DeviceCommand.status == "pending",
        DeviceCommand.expires_at > now).limit(1))
    if existing is not None:
        return existing
    cmd = DeviceCommand(device_id=device.id, type=cmd_type, params={}, nonce=secrets.token_hex(16), reason=reason,
                        requested_by_id=actor_id, requested_by_email=actor_email, created_at=now,
                        expires_at=now + UPDATE_NOW_COMMAND_TTL)
    db.add(cmd)
    db.flush()
    return cmd


def request_update_now(db: Session, devices: list[Device], *, actor_id: str | None, actor_email: str, reason: str,
                       now: datetime | None = None) -> dict:
    """Make the given devices check in now and start their target release
    without jitter. Agents that support it get `check_for_update`, older ones
    `recheck_posture` (their next offer then carries a zero delay). Devices
    with nothing to install are skipped. Caller audits and commits."""
    now = now or utcnow()
    all_rings = svc.rings(db)
    slots = max(1, config.settings.agent_update_max_parallel_downloads)
    queued, skipped = [], []
    for d in devices:
        t = svc.target_for(db, d, all_rings)
        p = pending_state(db, d, t, now)
        if not p["can_update_now"]:
            skipped.append({"device_id": d.id, "hostname": d.hostname, "reason": p["message"] or p["state"]})
            continue
        delay = min(svc.MAX_UPDATE_NOW_DELAY, (len(queued) // slots) * UPDATE_NOW_STAGGER_SECONDS)
        d.update_now_requested_at, d.update_now_delay_seconds = now, delay
        cmd_type = "check_for_update" if p["update_now_supported"] else "recheck_posture"
        cmd = _queue(db, d, cmd_type, actor_id, actor_email, reason, now)
        queued.append({"device_id": d.id, "hostname": d.hostname, "command": cmd_type, "command_id": cmd.id,
                       "target_version": t.release.version if t.release else None, "delay_seconds": delay})
    return {"queued": queued, "skipped": skipped}


# ----------------------------------------------------------------------------- auto-import
class ImportCheckError(Exception):
    """Could not talk to GitHub (offline, proxy, rate limit): logged, not notified."""


def _client() -> httpx.Client:
    # trust_env: honours HTTPS_PROXY / HTTP_PROXY / NO_PROXY / SSL_CERT_FILE.
    return httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True, trust_env=True,
                        headers={"User-Agent": "cnapp-server-agent-update-import",
                                 "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})


def http_get_json(url: str):
    try:
        with _client() as c:
            r = c.get(url)
    except httpx.HTTPError as e:
        raise ImportCheckError(f"cannot reach {url.split('/repos/')[0]}: {e.__class__.__name__}: {e}") from None
    if r.status_code != 200:
        raise ImportCheckError(f"GET {url} returned HTTP {r.status_code}: {r.text[:200]}")
    try:
        return r.json()
    except ValueError:
        raise ImportCheckError(f"GET {url} did not return JSON") from None


def http_download(url: str, max_bytes: int) -> bytes:
    try:
        with _client() as c, c.stream("GET", url, headers={"Accept": "application/octet-stream"}) as r:
            if r.status_code != 200:
                raise ImportCheckError(f"download returned HTTP {r.status_code}")
            if r.url.scheme != "https":
                raise ImportCheckError("download was redirected to a non-HTTPS URL")
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > max_bytes:
                    raise ImportCheckError(f"bundle is larger than {max_bytes} bytes")
            return bytes(buf)
    except httpx.HTTPError as e:
        raise ImportCheckError(f"download failed: {e.__class__.__name__}: {e}") from None


def find_new_release(releases, imported_versions: set[str], max_bytes: int) -> dict | None:
    """Highest agent-vX.Y.Z GitHub release (not draft / pre-release) with the
    signed bundle asset, newer than everything imported so far."""
    best = None
    newest_imported = max(imported_versions, key=svc.version_sort_key, default=None)
    for r in releases if isinstance(releases, list) else []:
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        m = TAG_RE.match(str(r.get("tag_name") or ""))
        if not m:
            continue
        version = m[1]
        try:
            svc.parse_semver(version)
        except ValueError:
            continue
        if version in imported_versions:
            continue
        if newest_imported and svc.compare_versions(version, newest_imported) <= 0:
            continue
        asset = next((a for a in r.get("assets") or [] if isinstance(a, dict) and a.get("name") == BUNDLE_ASSET), None)
        if asset is None or not str(asset.get("browser_download_url", "")).startswith("https://"):
            continue
        if not isinstance(asset.get("size"), int) or asset["size"] > max_bytes:
            continue
        if best is None or svc.compare_versions(version, best["version"]) > 0:
            best = {"version": version, "tag": r["tag_name"], "url": asset["browser_download_url"],
                    "size": asset["size"]}
    return best


def check_github(db: Session, now: datetime | None = None, *, actor: str = "auto-import") -> dict:
    """One auto-import check (caller commits). Returns {"status", "message", "imported"}."""
    now = now or utcnow()
    st = get_settings(db)
    s = config.settings
    repo = import_repo(st)
    st.import_checked_at = now
    result = {"status": "ok", "message": "", "imported": None}

    def done(status: str, message: str) -> dict:
        st.import_status, st.import_message = status, message[:1000]
        result.update(status=status, message=message)
        return result

    if not REPO_RE.match(repo):
        return done("error", f"invalid repository {repo!r} (want OWNER/NAME)")
    if not s.agent_update_releases_api.startswith("https://"):
        return done("error", "AGENT_UPDATE_RELEASES_API must be an https:// URL")
    try:
        releases = http_get_json(f"{s.agent_update_releases_api}/repos/{repo}/releases?per_page=30")
        imported = set(db.scalars(select(AgentRelease.version)))
        cand = find_new_release(releases, imported, s.agent_update_max_bundle_bytes)
        if cand is None:
            newest = max(imported, key=svc.version_sort_key, default=None)
            return done("ok", f"no new release in github.com/{repo}"
                        + (f" (newest imported: {newest})" if newest else ""))
        if cand["version"] == st.import_failed_version:
            return done("error", f"{cand['tag']} was refused earlier and is not retried: "
                                 f"{(st.import_message or '')[:300]}")
        data = http_download(cand["url"], s.agent_update_max_bundle_bytes)
    except ImportCheckError as e:
        log.warning("agent release auto-import: %s", e)
        return done("offline", str(e))
    who = f"{actor}:github.com/{repo}"
    try:
        rel = svc.import_bundle(db, data, who)  # refuses before writing anything
    except svc.ReleaseError as e:
        msg = f"{cand['tag']} from github.com/{repo} was refused: {e}"
        log.error("agent release auto-import: %s", msg)
        st.import_failed_version = cand["version"]
        audit(db, "agent_release_rejected", actor_email=who, reason=str(e)[:500], size_bytes=len(data),
              tag=cand["tag"], source="auto-import")
        notify.import_event(db, "release_import_failed", cand["version"], msg, severity="high")
        return done("error", msg)
    audit(db, "agent_release_imported", actor_email=who, target=f"agent-release:{rel.id}", version=rel.version,
          key_id=rel.key_id, bundle_sha256=rel.bundle_sha256, tag=cand["tag"], source="auto-import",
          artifacts=[f"{a.os}/{a.arch} {a.sha256}" for a in rel.artifacts])
    notify.import_event(db, "release_imported", rel.version,
                        f"Imported {cand['tag']} from github.com/{repo} (signed by {rel.key_id}).")
    log.info("agent release auto-import: imported %s from github.com/%s", rel.version, repo)
    result["imported"] = rel.version
    tick = auto_tick(db, now)
    return done("ok", f"imported {rel.version} from {cand['tag']}"
                + (f"; automatic rollout: {tick.action} {tick.detail}".rstrip() if tick.action != "none" else ""))


def import_due(st: AgentUpdateSettings, now: datetime) -> bool:
    return import_enabled(st) and (st.import_checked_at is None
                                   or now - st.import_checked_at >= timedelta(minutes=import_interval(st)))


# ----------------------------------------------------------------------------- background worker
class AgentUpdateWorker:
    """Leader-elected background job: automatic rollout every minute, and the
    GitHub Releases auto-import when enabled and due."""

    LOCK_NAME = "agent-update-automation"

    def __init__(self, interval: float = 60.0):
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="agent-update-automation", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> bool:
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return False
        now = now or utcnow()
        # Releases are shared by every organisation: the GitHub auto-import is a
        # platform job, configured on (and audited / notified to) the default
        # organisation. Each organisation then rolls out with its own rings / mode.
        try:
            with dbmod.get_session(tenancy.DEFAULT_ORG_ID) as db:
                if import_due(get_settings(db), now):
                    check_github(db, now)
                db.commit()
        except Exception:
            log.exception("agent release auto-import failed")
        for org_id, db in tenancy.for_each_active_org():
            try:
                auto_tick(db, now)
                db.commit()
            except Exception:
                db.rollback()
                log.exception("automatic agent rollout step failed for organisation %s", org_id)
        return True

    def _run(self) -> None:
        # First pass shortly after start-up, then every interval.
        if self._stop.wait(5):
            return
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("agent update automation tick failed")
            if self._stop.wait(self.interval):
                return
