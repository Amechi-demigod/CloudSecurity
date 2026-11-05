"""Dedicated directory collectors (docs/DIRECTORY_DISCOVERY.md#dedicated-collectors).

A collector is the separate "collector" program (endpoint-agent/cmd/cnapp-collector)
on a Windows host in the customer's network. It is NOT an endpoint agent:

* its own identity class: enrollment tokens of kind "collector", its own
  credential (``cnc_`` prefix, only the SHA-256 is stored), its own table
  (``directory_collectors``); it never appears in Devices, IT assets, agent
  coverage or endpoint counts;
* its own command queue (``collector_commands``) restricted to COMMAND_TYPES:
  directory work, diagnostics, health and self-update. ``new_command`` refuses
  everything else, so the server can never queue a script, a remote session,
  isolation, lock or wipe to a collector (the binary does not contain them either);
* outbound only: it sends a heartbeat (host facts: domain, run-as identity,
  whether the host is a domain controller, version), polls commands and
  uploads directory batches exactly like the endpoint agent's directory_sync.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import config
from ..models import EnrollmentToken, utcnow
from .models import CollectorCommand, DirectoryCollector, DirectorySource

log = logging.getLogger(__name__)

# The only command types a collector accepts (mirrors cmd/cnapp-collector's
# allow-list, internal/collector.AllowedCommands).
DIRECTORY_SYNC = "directory_sync"
DIAGNOSTICS = "collector_diagnostics"
HEALTH = "collector_health"
CHECK_FOR_UPDATE = "check_for_update"
COMMAND_TYPES = (DIRECTORY_SYNC, DIAGNOSTICS, HEALTH, CHECK_FOR_UPDATE)

TOKEN_PREFIX = "cnct_"  # noqa: S105 (public prefixes, not secrets)
SECRET_PREFIX = "cnc_"  # noqa: S105
# A collector polls commands every ~60 s and sends a heartbeat every 5 minutes.
HEALTHY_WINDOW = timedelta(minutes=10)
# "Collector offline" is notified once a collector has been silent this long.
OFFLINE_AFTER = timedelta(minutes=15)
COMMAND_TTL = timedelta(minutes=30)
DIAGNOSTICS_TTL = timedelta(minutes=15)
UPLOAD_PREFIX = "/api/collector/directory/runs/"
RUN_AS_KINDS = ("computer_account", "gmsa", "user", "unknown")
FEATURES_RE = re.compile(r"^[a-z0-9_,]{0,256}$")


class CollectorError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ----------------------------------------------------------------------------- enrollment
def new_token(db: Session, *, name: str, max_uses: int | None, expires_in_hours: int, actor: str,
              package: str | None = None) -> tuple[EnrollmentToken, str]:
    """A collector enrollment token (kind "collector"; caller audits and commits)."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    now = utcnow()
    t = EnrollmentToken(name=name, token_hash=hash_secret(raw), token_prefix=raw[:12], max_uses=max_uses,
                        created_by=actor, created_at=now, expires_at=now + timedelta(hours=expires_in_hours),
                        package_platform=package, kind="collector")
    db.add(t)
    db.flush()
    return t, raw


def issue_secret(c: DirectoryCollector) -> str:
    """A fresh credential (the previous one stops working)."""
    secret = SECRET_PREFIX + secrets.token_urlsafe(32)
    c.secret_hash = hash_secret(secret)
    return secret


def enroll(db: Session, token: EnrollmentToken, info: dict[str, Any], ip: str | None) -> tuple[DirectoryCollector, str, bool]:
    """Create (or re-enroll, by machine id) a collector; returns (collector, secret, re-enrolled)."""
    now = utcnow()
    existing = None
    if info.get("machine_id"):
        existing = db.scalar(select(DirectoryCollector).where(DirectoryCollector.machine_id == info["machine_id"])
                             .order_by(DirectoryCollector.enrolled_at.desc()).limit(1))
    c = existing or DirectoryCollector(name=(info.get("hostname") or "collector")[:128],
                                       machine_id=info.get("machine_id") or "")
    c.status, c.revoked_at = "active", None
    c.enrolled_at, c.enrollment_token_id = now, token.id
    c.last_seen_at, c.last_ip = now, ip
    apply_facts(c, info)
    secret = issue_secret(c)
    if existing is None:
        db.add(c)
    db.flush()
    return c, secret, existing is not None


def apply_facts(c: DirectoryCollector, f: dict[str, Any]) -> None:
    """Host facts reported at enrollment / heartbeat (validated by the schema)."""
    for k in ("hostname", "dns_hostname", "domain", "os_name", "os_version", "architecture", "version", "run_as"):
        v = f.get(k)
        if v is not None:
            setattr(c, k, v)
    if f.get("run_as_kind") in RUN_AS_KINDS:
        c.run_as_kind = f["run_as_kind"]
    if isinstance(f.get("is_domain_controller"), bool):
        c.is_domain_controller = f["is_domain_controller"]
    if f.get("features") is not None and FEATURES_RE.match(f["features"]):
        c.features = f["features"]


def authenticate(db: Session, token: str) -> DirectoryCollector | None:
    """The active collector a credential belongs to (callers scope the session first)."""
    if not token.startswith(SECRET_PREFIX) or len(token) > 128:
        return None
    c = db.scalar(select(DirectoryCollector).where(DirectoryCollector.secret_hash == hash_secret(token)))
    return c


# ----------------------------------------------------------------------------- health
def is_healthy(c: DirectoryCollector | None, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return (c is not None and c.status == "active" and c.last_seen_at is not None
            and now - c.last_seen_at <= HEALTHY_WINDOW)


def state(c: DirectoryCollector, now: datetime | None = None) -> str:
    """online | offline | never | revoked."""
    now = now or utcnow()
    if c.status != "active":
        return "revoked"
    if c.last_seen_at is None:
        return "never"
    return "online" if now - c.last_seen_at <= HEALTHY_WINDOW else "offline"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt is not None else None


def collector_out(c: DirectoryCollector, now: datetime | None = None,
                  sources: list[dict[str, str]] | None = None) -> dict[str, Any]:
    now = now or utcnow()
    return {"id": c.id, "name": c.name, "status": c.status, "state": state(c, now), "healthy": is_healthy(c, now),
            "hostname": c.hostname, "dns_hostname": c.dns_hostname, "domain": c.domain, "os_name": c.os_name,
            "os_version": c.os_version, "architecture": c.architecture, "version": c.version,
            "run_as": c.run_as, "run_as_kind": c.run_as_kind, "is_domain_controller": c.is_domain_controller,
            "enrolled_at": _iso(c.enrolled_at), "last_seen_at": _iso(c.last_seen_at), "last_ip": c.last_ip,
            "revoked_at": _iso(c.revoked_at), "enrollment_token_id": c.enrollment_token_id,
            "update_status": c.update_status,
            "update_status_detail": c.update_status_detail, "diagnostics": dict(c.diagnostics or {}),
            "sources": sources or []}


def sources_by_collector(db: Session) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for s in db.scalars(select(DirectorySource).where(DirectorySource.type == "ad")):
        for cid in s.collector_ids or []:
            out.setdefault(cid, []).append({"id": s.id, "name": s.name})
    return out


def check_offline(db: Session, now: datetime | None = None) -> list[DirectoryCollector]:
    """Notify collectors that went silent (once) and clear the flag of those back
    online (caller commits). Returns the collectors newly notified."""
    from ..notifications import directory_source

    now = now or utcnow()
    out = []
    used = sources_by_collector(db)
    for c in db.scalars(select(DirectoryCollector).where(DirectoryCollector.status == "active")):
        silent = c.last_seen_at is None or now - c.last_seen_at > OFFLINE_AFTER
        if silent and c.offline_notified_at is None and c.last_seen_at is not None:
            c.offline_notified_at = now
            directory_source.collector_offline(db, c, used.get(c.id, []))
            out.append(c)
        elif not silent and c.offline_notified_at is not None:
            c.offline_notified_at = None
            directory_source.collector_online(db, c)
    return out


# ----------------------------------------------------------------------------- commands
def new_command(db: Session, c: DirectoryCollector, cmd_type: str, params: dict[str, Any], reason: str, *,
                actor: str | None, ttl: timedelta | None = None) -> CollectorCommand:
    """Queue a command for a collector (caller audits and commits). Only the
    collector command types can be queued; anything else is refused."""
    if cmd_type not in COMMAND_TYPES:
        raise CollectorError(422, f"{cmd_type!r} cannot be sent to a directory collector (allowed: "
                                  f"{', '.join(COMMAND_TYPES)})")
    if c.status != "active":
        raise CollectorError(409, "the collector is revoked")
    now = utcnow()
    cmd = CollectorCommand(collector_id=c.id, type=cmd_type, params=params, nonce=secrets.token_hex(16),
                           reason=reason, requested_by_email=actor, created_at=now,
                           expires_at=now + (ttl or COMMAND_TTL))
    db.add(cmd)
    db.flush()
    return cmd


def expire_commands(db: Session, collector_id: str, now: datetime | None = None) -> None:
    now = now or utcnow()
    db.execute(update(CollectorCommand).where(CollectorCommand.collector_id == collector_id,
                                              CollectorCommand.status.in_(("pending", "delivered")),
                                              CollectorCommand.expires_at < now)
               .values(status="expired", completed_at=now).execution_options(synchronize_session=False))


def deliver_pending(db: Session, c: DirectoryCollector) -> list[CollectorCommand]:
    """Hand pending commands to the collector exactly once (pending -> delivered)."""
    expire_commands(db, c.id)
    now = utcnow()
    cmds = list(db.scalars(select(CollectorCommand).where(CollectorCommand.collector_id == c.id,
                                                          CollectorCommand.status == "pending")
                           .order_by(CollectorCommand.created_at).limit(20)))
    out = []
    for cmd in cmds:
        res = db.execute(update(CollectorCommand).where(CollectorCommand.id == cmd.id,
                                                        CollectorCommand.status == "pending")
                         .values(status="delivered", delivered_at=now).execution_options(synchronize_session=False))
        if res.rowcount == 1:
            cmd.status, cmd.delivered_at = "delivered", now
            out.append(cmd)
    return out


def delivered_command(db: Session, c: DirectoryCollector, command_id: str, nonce: str) -> CollectorCommand:
    cmd = db.get(CollectorCommand, command_id)
    if cmd is None or cmd.collector_id != c.id:
        raise CollectorError(404, "command not found")
    if not hmac.compare_digest(nonce.encode(), cmd.nonce.encode()):
        raise CollectorError(403, "nonce mismatch")
    if cmd.status != "delivered":
        raise CollectorError(409, f"command is {cmd.status}, not awaiting a result")
    return cmd


# ----------------------------------------------------------------------------- diagnostics
DIAG_STEPS = ("dc_locator", "port", "certificate", "bind", "read")


def diagnostics_params(src: DirectorySource | None, c: DirectoryCollector,
                       config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Params of an on-collector Test (stored; the service-account credential is
    only added to the delivered copy, as for directory_sync). `config`: settings
    not saved yet (the Add directory wizard), tested as the collector's identity."""
    cfg = config if config is not None else ((src.config or {}) if src is not None else {})
    domain = cfg.get("domain") or c.domain
    if not domain:
        raise CollectorError(422, "the collector reports no domain: pick a directory source to test against")
    security = cfg.get("security") or "sealed"
    return {"source_id": src.id if src is not None else "", "domain": domain,
            "servers": list(cfg.get("servers") or []), "security": security,
            "port": int(cfg.get("port") or (636 if security == "ldaps" else 389)),
            "auth": "simple" if cfg.get("auth") == "service_account" else "kerberos",
            "ca_pem": cfg.get("ca_pem") or "", "base_dns": list(cfg.get("base_dns") or [])}


def record_diagnostics(c: DirectoryCollector, cmd: CollectorCommand, status: str, output: str,
                       data: dict[str, Any] | None) -> None:
    steps = []
    for s in (data or {}).get("steps") or []:
        if isinstance(s, dict) and s.get("id") and s.get("status") in ("pass", "fail", "warn", "skip"):
            steps.append({"id": str(s["id"])[:32], "label": str(s.get("label") or s["id"])[:128],
                          "status": s["status"], "detail": str(s.get("detail") or "")[:1000],
                          "duration_ms": int(s["duration_ms"]) if isinstance(s.get("duration_ms"), int) else None})
    c.diagnostics = {"command_id": cmd.id, "at": utcnow().isoformat() + "Z", "status": status,
                     "output": (output or "")[:2000], "steps": steps[:20],
                     "transport": str((data or {}).get("transport") or "")[:64],
                     "signed_sealed": bool((data or {}).get("signed_sealed")),
                     "server": str((data or {}).get("server") or "")[:253],
                     "identity": str((data or {}).get("identity") or "")[:256]}


# ----------------------------------------------------------------------------- self-update
def offer_for(db: Session, c: DirectoryCollector, version: str, goos: str, goarch: str) -> dict | None:
    """Collectors follow the organisation's default agent ring: when its target
    release ships collector binaries (collector-manifest.json) for this platform
    and is newer than the collector, it is offered. Signed manifest, hashes and
    version policy are verified by the collector itself."""
    from ..models import AgentRelease, AgentUpdateRing
    from ..services.agent_updates import compare_versions
    from .models import CollectorRelease, CollectorReleaseArtifact

    ring = db.scalar(select(AgentUpdateRing).where(AgentUpdateRing.is_default.is_(True)).limit(1))
    if ring is None or ring.paused or ring.target_release_id is None:
        return None
    rel = db.get(AgentRelease, ring.target_release_id)
    if rel is None or rel.withdrawn_at is not None:
        return None
    crel = db.scalar(select(CollectorRelease).where(CollectorRelease.agent_release_id == rel.id))
    if crel is None:
        return None
    try:
        if compare_versions(crel.version, version) <= 0:
            return None
    except ValueError:
        return None
    has = db.scalar(select(CollectorReleaseArtifact.id).where(
        CollectorReleaseArtifact.release_id == crel.id, CollectorReleaseArtifact.os == goos,
        CollectorReleaseArtifact.arch == goarch))
    if has is None:
        return None
    c.update_offered_version = crel.version
    base = f"/api/collector/updates/releases/{crel.id}"
    return {"release_id": crel.id, "version": crel.version, "manifest_path": f"{base}/manifest",
            "artifact_path": f"{base}/artifacts/{goos}/{goarch}",
            "health_timeout_seconds": max(60, min(3600, config.settings.agent_update_health_timeout_seconds)),
            "jitter_seconds": 0}
