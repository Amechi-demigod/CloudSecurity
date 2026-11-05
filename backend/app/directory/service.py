"""Directory sources, collectors, sync runs and batch ingestion
(docs/DIRECTORY_DISCOVERY.md).

Flow of one sync:

1. `queue_run` picks the first healthy collector of the source (an enrolled
   agent advertising `directory_collector`, seen in the last few minutes; for
   computer-account auth a Windows one) and queues a `directory_sync` device
   command. Its stored params never contain secrets.
2. When the agent fetches its commands, `delivery_params` mints the run's
   single-use upload token (only its SHA-256 is stored) and, for service-account
   auth, adds the decrypted credential to the delivered copy of the params.
3. The agent streams objects to POST /api/agent/directory/runs/{id}/batches
   (`ingest_batch`): device credential + upload token, strictly increasing
   sequence numbers, size and object caps; objects are upserted by
   (source, external id).
4. The final batch ends the run. Only a complete run (succeeded, not truncated
   by the safety cap, not a test) marks objects it did not return as missing.
   The token is cleared, the source status updated, matches and findings are
   re-evaluated (directory/reconcile.py).

The scheduler (directory/scheduler.py) queues runs on schedule, fails runs
whose collector did not pick them up or went silent, and fails over to the
next collector.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session

from .. import config
from ..device_class import directory_class
from ..models import Device, DeviceCommand, utcnow
from .matching import short_host
from .models import CLOUD_TYPES, RUN_ACTIVE, DirectoryComputer, DirectorySource, DirectorySyncRun, DirectoryUser
from .schemas import BatchIn, ComputerIn, UserIn

log = logging.getLogger(__name__)

COMMAND_TYPE = "directory_sync"
COLLECTOR_FEATURE = "directory_collector"
# A collector polls for commands every ~60 s (which updates last_seen_at).
COLLECTOR_HEALTHY_WINDOW = timedelta(minutes=10)
# A queued run whose collector has not fetched the command by then fails over.
PICKUP_TIMEOUT = timedelta(minutes=15)
# A running run that has sent nothing for this long is failed (agent gone).
STALL_TIMEOUT = timedelta(minutes=30)
COMMAND_TTL = timedelta(minutes=30)
SYNC_TIMEOUT_SECONDS = 3600
TEST_TIMEOUT_SECONDS = 300
TEST_MAX_OBJECTS = 10
PAGE_SIZE = 1000
BATCH_SIZE = 2000
UPLOAD_PREFIX = "/api/agent/directory/runs/"
SAMPLE_SIZE = 10
SYSTEM = "system"


class DirectoryError(Exception):
    """An API-level error: `status` is the HTTP status to answer."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ----------------------------------------------------------------------------- credentials
def credential_hint(username: str) -> str:
    """Display form of a service-account name: `svc-ldap@corp.example.com` ->
    `sv••••@corp.example.com`, `CORP\\svc-ldap` -> `CORP\\sv••••`."""
    u = (username or "").strip()
    if "@" in u:
        local, _, dom = u.partition("@")
        return f"{local[:2]}••••@{dom}"[:64]
    if "\\" in u:
        dom, _, local = u.rpartition("\\")
        return f"{dom}\\{local[:2]}••••"[:64]
    return f"{u[:2]}••••"


def store_secret(src: DirectorySource, data: dict[str, str], hint: str) -> None:
    """Store a source credential encrypted (Fernet, NOTIFICATIONS_ENCRYPTION_KEY)."""
    from ..notifications import crypto

    try:
        src.secret_ciphertext = crypto.encrypt_secrets(data)
    except crypto.EncryptionUnavailable as e:
        raise DirectoryError(503, f"cannot store the credential: {e}") from None
    src.credential_hint = hint[:64]


def load_secret(src: DirectorySource) -> dict[str, str] | None:
    """The decrypted credential, or None (none stored / the key changed)."""
    from ..notifications import crypto

    if not src.secret_ciphertext:
        return None
    try:
        return crypto.decrypt_secrets(src.secret_ciphertext)
    except (crypto.DecryptionFailed, crypto.EncryptionUnavailable):
        return None


def rotate_secrets(db: Session) -> int:
    """Re-encrypt every stored source credential with the primary key (any session mode)."""
    from ..notifications import crypto

    n = 0
    for src in db.scalars(select(DirectorySource).where(DirectorySource.secret_ciphertext.is_not(None))
                          .execution_options(tenant_unscoped=True)):
        src.secret_ciphertext = crypto.rotate(src.secret_ciphertext)
        n += 1
    return n


def set_credential(src: DirectorySource, username: str, password: str) -> None:
    """Store the AD service account encrypted."""
    store_secret(src, {"username": username, "password": password}, credential_hint(username))


def clear_credential(src: DirectorySource) -> None:
    src.secret_ciphertext = None
    src.credential_hint = None


def _credential(src: DirectorySource) -> dict[str, str] | None:
    data = load_secret(src)
    if not data or not data.get("username") or not data.get("password"):
        return None
    return {"username": data["username"], "password": data["password"]}


# ----------------------------------------------------------------------------- collectors
def _has_feature(d: Device) -> bool:
    return COLLECTOR_FEATURE in (d.agent_features or "").split(",")


def is_healthy(d: Device | None, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return (d is not None and d.status == "active" and _has_feature(d) and d.last_seen_at is not None
            and now - d.last_seen_at <= COLLECTOR_HEALTHY_WINDOW)


def collector_devices(db: Session) -> list[Device]:
    """Enrolled devices that can act as directory collectors (advertise the feature)."""
    rows = db.scalars(select(Device).where(Device.status == "active",
                                           Device.agent_features.like(f"%{COLLECTOR_FEATURE}%"))
                      .order_by(Device.hostname))
    return [d for d in rows if _has_feature(d)]


def collector_out(d: Device, now: datetime | None = None) -> dict[str, Any]:
    return {"id": d.id, "hostname": d.hostname, "os_family": d.os_family, "healthy": is_healthy(d, now),
            "last_seen_at": d.last_seen_at, "ad_domain": d.ad_domain, "agent_version": d.agent_version or ""}


def check_collectors(db: Session, ids: list[str], auth: str) -> None:
    """Every collector must be an enrolled device of this organisation advertising
    the feature; computer-account (Kerberos) auth needs Windows collectors."""
    ids = list(dict.fromkeys(ids))
    found = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(ids)))} if ids else {}
    for i in ids:
        d = found.get(i)
        if d is None:
            raise DirectoryError(404, f"collector device {i} not found")
        if d.status != "active" or not _has_feature(d):
            raise DirectoryError(422, f"{d.hostname} cannot collect directory data (agent 1.3.0 or later, "
                                      "enrolled and active, is required)")
        if auth == "computer_account" and d.os_family != "windows":
            raise DirectoryError(422, f"{d.hostname} is not Windows: the computer-account (Kerberos) option needs "
                                      "a domain-joined Windows collector; use a service account instead")


def pick_collector(db: Session, src: DirectorySource, exclude: set[str] | frozenset[str] = frozenset(),
                   now: datetime | None = None) -> Device | None:
    now = now or utcnow()
    ids = [i for i in (src.collector_device_ids or []) if i not in exclude]
    if not ids:
        return None
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(ids)))}
    windows_only = (src.config or {}).get("auth", "computer_account") == "computer_account"
    for i in ids:
        d = devices.get(i)
        if is_healthy(d, now) and (not windows_only or d.os_family == "windows"):
            return d
    return None


# ----------------------------------------------------------------------------- runs
def active_run(db: Session, source_id: str) -> DirectorySyncRun | None:
    return db.scalars(select(DirectorySyncRun).where(DirectorySyncRun.source_id == source_id,
                                                     DirectorySyncRun.status.in_(RUN_ACTIVE))
                      .order_by(DirectorySyncRun.queued_at.desc()).limit(1)).first()


def last_scheduled_run(db: Session, source_id: str) -> DirectorySyncRun | None:
    return db.scalars(select(DirectorySyncRun).where(DirectorySyncRun.source_id == source_id,
                                                     DirectorySyncRun.trigger == "scheduled",
                                                     DirectorySyncRun.attempt == 1)
                      .order_by(DirectorySyncRun.queued_at.desc()).limit(1)).first()


def interval(src: DirectorySource) -> timedelta:
    return timedelta(hours=float((src.config or {}).get("interval_hours") or 6))


def next_sync_at(db: Session, src: DirectorySource, now: datetime | None = None) -> datetime | None:
    if not src.enabled:
        return None
    now = now or utcnow()
    last = last_scheduled_run(db, src.id)
    due = last.queued_at + interval(src) if last is not None else now
    return max(due, now)


def command_params(src: DirectorySource, run: DirectorySyncRun, *, test: bool) -> dict[str, Any]:
    """The directory_sync params as STORED (no token, no credential)."""
    cfg = src.config or {}
    return {
        "source_id": src.id, "run_id": run.id, "domain": cfg["domain"], "servers": list(cfg.get("servers") or []),
        "port": int(cfg.get("port") or 636), "security": cfg.get("security") or "ldaps",
        "base_dns": list(cfg.get("base_dns") or []), "scopes": list(run.scopes),
        "page_size": PAGE_SIZE, "batch_size": BATCH_SIZE, "max_objects": run.max_objects,
        "timeout_seconds": TEST_TIMEOUT_SECONDS if test else SYNC_TIMEOUT_SECONDS,
        "auth": "simple" if cfg.get("auth") == "service_account" else "kerberos",
        "ca_pem": cfg.get("ca_pem") or "", "test": test, "upload_path": f"{UPLOAD_PREFIX}{run.id}/batches",
    }


def queue_run(db: Session, src: DirectorySource, *, trigger: str, actor: str | None, attempt: int = 1,
              tried: list[str] | None = None, now: datetime | None = None) -> DirectorySyncRun:
    """Queue a directory_sync on the first healthy collector (caller commits).
    Raises DirectoryError(409) when a run is active or no collector is healthy."""
    from ..services import devices as devsvc

    now = now or utcnow()
    if active_run(db, src.id) is not None:
        raise DirectoryError(409, "a sync of this directory is already queued or running")
    cfg = src.config or {}
    if src.type in CLOUD_TYPES:
        # Server-side collection (directory/cloud.py): no collector, no command;
        # the caller hands the run to cloud.kick() after committing.
        run = DirectorySyncRun(source_id=src.id, trigger=trigger, status="queued", device_id=None,
                               requested_by=actor, attempt=attempt, tried_device_ids=[],
                               scopes=list(cfg.get("scopes") or []), max_objects=config.settings.directory_max_objects,
                               queued_at=now)
        db.add(run)
        db.flush()
        src.last_sync_status = "queued"
        return run
    tried = list(tried or [])
    device = pick_collector(db, src, set(tried), now)
    if device is None:
        raise DirectoryError(409, "no healthy collector: the designated agents must be online (seen in the last "
                                  "10 minutes)" + (" and run Windows (computer-account auth)"
                                                   if (src.config or {}).get("auth") != "service_account" else ""))
    test = trigger == "test"
    run = DirectorySyncRun(source_id=src.id, trigger=trigger, status="queued", device_id=device.id,
                           requested_by=actor, attempt=attempt, tried_device_ids=[*tried, device.id],
                           scopes=list(cfg.get("scopes") or ["computers", "users"]),
                           max_objects=TEST_MAX_OBJECTS if test else config.settings.directory_max_objects,
                           queued_at=now)
    db.add(run)
    db.flush()
    cmd = devsvc.new_command(db, device, COMMAND_TYPE, command_params(src, run, test=test),
                             f"directory {trigger} sync of {src.name}", requested_by_id=None,
                             requested_by_email=actor or SYSTEM, ttl=COMMAND_TTL)
    run.command_id = cmd.id
    if trigger != "test":
        src.last_sync_status = "queued"
    return run


def delivery_params(db: Session, cmd: DeviceCommand) -> dict[str, Any] | None:
    """Params handed to the agent for a directory_sync: the stored ones plus a
    freshly minted single-use upload token and, for service-account auth, the
    decrypted credential. None (the caller cancels the command) when the run
    is no longer waiting or the credential cannot be decrypted. Caller commits."""
    now = utcnow()
    run = db.scalar(select(DirectorySyncRun).where(DirectorySyncRun.command_id == cmd.id))
    if run is None or run.status != "queued" or run.token_hash is not None:
        return None
    src = db.get(DirectorySource, run.source_id)
    if src is None or not src.enabled:
        fail_run(db, run, "the directory source was disabled or deleted", now=now)
        return None
    params = dict(cmd.params or {})
    if params.get("auth") == "simple":
        cred = _credential(src)
        if cred is None:
            fail_run(db, run, "the service-account credential is missing or cannot be decrypted "
                              "(NOTIFICATIONS_ENCRYPTION_KEY changed?): enter it again", now=now)
            return None
        params["credential"] = cred
    token = secrets.token_urlsafe(32)
    run.token_hash = hash_token(token)
    timeout = int(params.get("timeout_seconds") or SYNC_TIMEOUT_SECONDS)
    run.token_expires_at = now + timedelta(seconds=timeout) + timedelta(minutes=30)
    run.status, run.started_at = "running", now
    if run.trigger != "test":
        src.last_sync_status = "running"
    params["upload_token"] = token
    return params


def command_failed(db: Session, cmd: DeviceCommand, output: str) -> None:
    """The agent reported the directory_sync command itself as failed / rejected."""
    run = db.scalar(select(DirectorySyncRun).where(DirectorySyncRun.command_id == cmd.id))
    if run is not None and run.status in RUN_ACTIVE:
        fail_run(db, run, f"collector {cmd.status}: {output}"[:2000])


def fail_run(db: Session, run: DirectorySyncRun, error: str, *, now: datetime | None = None,
             status: str = "failed") -> None:
    """End a run without a final batch (caller commits)."""
    from ..auth import audit
    from ..notifications import directory_source

    now = now or utcnow()
    run.status, run.finished_at, run.error = status, now, error[:2000]
    run.token_hash = None
    db.flush()  # (sessions do not autoflush) a failover queued next must see it ended
    src = db.get(DirectorySource, run.source_id)
    if src is not None and run.trigger != "test":
        src.last_sync_at, src.last_sync_status, src.last_sync_error = now, status, run.error
    audit(db, "directory_sync_failed", actor_email=SYSTEM, target=f"directory-source:{run.source_id}",
          run_id=run.id, trigger=run.trigger, device_id=run.device_id, error=run.error)
    if src is not None and run.trigger != "test" and status == "failed":
        directory_source.sync_failed(db, src, run)


# ----------------------------------------------------------------------------- ingestion
_DN_SPLIT = re.compile(r"(?<!\\),")


def split_dn(dn: str) -> list[str]:
    return [p.strip() for p in _DN_SPLIT.split(dn or "") if p.strip()]


def domain_from_dn(dn: str) -> str:
    return ".".join(p[3:].lower() for p in split_dn(dn) if p[:3].lower() == "dc=")


def parent_dn(dn: str) -> str:
    parts = split_dn(dn)
    return ",".join(parts[1:])


def _naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        from datetime import UTC

        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _enabled(uac: int | None) -> bool:
    return not (uac or 0) & 0x2  # ACCOUNTDISABLE


# Platforms the endpoint agent runs on ("" = unknown, e.g. an AD computer without
# operatingSystem): only these can be "no agent" and count in agent coverage.
AGENT_PLATFORMS = frozenset({"windows", "macos", "linux", ""})


def platform_of(os_name: str) -> str:
    """windows | macos | linux | ios | android | chromeos | "" from a free-text OS name."""
    s = (os_name or "").strip().lower().replace("_", " ")
    if not s:
        return ""
    if "windows" in s:
        return "windows"
    if s.startswith(("mac", "os x")) or "macos" in s:
        return "macos"
    if s.startswith(("ios", "ipados", "iphone", "ipad")) or s == "ios sync":
        return "ios"
    if "android" in s:
        return "android"
    if "chrome" in s:
        return "chromeos"
    if any(x in s for x in ("linux", "ubuntu", "debian", "red hat", "rhel", "centos", "suse", "fedora", "rocky",
                            "alma")):
        return "linux"
    return "other"


def _apply_computer(row: DirectoryComputer, c: ComputerIn, default_domain: str) -> None:
    sam = c.sam_account_name
    row.name = (c.cn or sam.rstrip("$"))[:256]
    row.sam_account_name = sam
    row.dns_hostname = c.dns_hostname.lower().rstrip(".")
    row.short_name = (short_host(row.dns_hostname) or c.cn.lower() or sam.rstrip("$").lower())[:256]
    row.object_sid = c.object_sid.upper() or None
    row.distinguished_name = c.distinguished_name
    row.domain = (domain_from_dn(c.distinguished_name) or default_domain)[:255]
    row.ou = parent_dn(c.distinguished_name)
    row.operating_system, row.os_version = c.operating_system, c.operating_system_version
    row.device_kind = "ad"
    row.platform = platform_of(c.operating_system)
    # As in phase 1, every AD computer account is expected to run the agent
    # (unless its operatingSystem says it is a phone or a Chromebook).
    row.agent_expected = row.platform not in ("ios", "android", "chromeos")
    row.user_account_control = c.user_account_control
    row.enabled = _enabled(c.user_account_control)
    row.last_logon_at = _naive(c.last_logon_timestamp)
    row.when_created, row.when_changed = _naive(c.when_created), _naive(c.when_changed)
    row.device_class = directory_class("ad", c.operating_system, c.user_account_control, row.platform)


def _apply_user(row: DirectoryUser, u: UserIn, default_domain: str) -> None:
    row.sam_account_name = u.sam_account_name
    row.sam_key = u.sam_account_name.lower()
    row.user_principal_name = u.user_principal_name.lower()
    row.mail = u.mail.lower()
    row.display_name, row.given_name, row.surname = u.display_name, u.given_name, u.sn
    row.department, row.title, row.manager_dn = u.department, u.title, u.manager_dn
    row.object_sid = u.object_sid.upper() or None
    row.distinguished_name = u.distinguished_name
    row.domain = (domain_from_dn(u.distinguished_name) or default_domain)[:255]
    row.ou = parent_dn(u.distinguished_name)
    row.user_account_control = u.user_account_control
    row.enabled = _enabled(u.user_account_control)
    row.last_logon_at = _naive(u.last_logon_timestamp)
    row.when_created = _naive(u.when_created)
    row.pwd_last_set_at = _naive(u.pwd_last_set)


def _upsert(db: Session, model, src: DirectorySource, run: DirectorySyncRun, items: list, apply, now: datetime) -> int:
    domain = (src.config or {}).get("domain", "")
    unique: dict[str, Any] = {}
    for it in items:
        unique[it.object_guid] = it
    keys = list(unique)
    existing: dict[str, Any] = {}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        existing.update({o.external_id: o for o in db.scalars(
            select(model).where(model.source_id == src.id, model.external_id.in_(chunk)))})
    for key, it in unique.items():
        row = existing.get(key)
        if row is None:
            row = model(source_id=src.id, external_id=key, first_seen_at=now, attributes={})
            db.add(row)
        apply(row, it, domain)
        row.last_seen_at, row.missing_since, row.last_run_id = now, None, run.id
    return len(unique)


def upsert_records(db: Session, model, src: DirectorySource, run: DirectorySyncRun, items: list[dict[str, Any]],
                   now: datetime) -> int:
    """Upsert normalised records of a server-side (cloud) sync: each item has
    `external_id` plus column values (directory/cloud.py). Returns the number
    of distinct objects stored."""
    unique: dict[str, dict[str, Any]] = {}
    for it in items:
        unique[it["external_id"]] = it
    keys = list(unique)
    existing: dict[str, Any] = {}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        existing.update({o.external_id: o for o in db.scalars(
            select(model).where(model.source_id == src.id, model.external_id.in_(chunk)))})
    for key, it in unique.items():
        row = existing.get(key)
        if row is None:
            row = model(source_id=src.id, external_id=key, first_seen_at=now, attributes={})
            db.add(row)
        for col, value in it.items():
            if col != "external_id":
                setattr(row, col, value)
        if model is DirectoryComputer:
            row.device_class = directory_class(row.device_kind, row.operating_system, row.user_account_control,
                                               row.platform)
        row.last_seen_at, row.missing_since, row.last_run_id = now, None, run.id
    return len(unique)


def ingest_batch(db: Session, device: Device, run_id: str, token: str | None, batch: BatchIn,
                 now: datetime | None = None) -> dict[str, Any]:
    """Store one batch of a run (caller commits). Raises DirectoryError."""
    now = now or utcnow()
    run = db.get(DirectorySyncRun, run_id)
    if run is None or run.device_id != device.id:
        raise DirectoryError(404, "sync run not found")
    if not token or not run.token_hash or not hmac.compare_digest(hash_token(token), run.token_hash):
        raise DirectoryError(403, "invalid or used sync token")
    if run.token_expires_at is None or run.token_expires_at < now:
        raise DirectoryError(403, "the sync token expired")
    if run.status != "running":
        raise DirectoryError(409, f"the sync run is {run.status}")
    if batch.seq < run.next_seq:
        return {"accepted": 0, "duplicate": True}
    if batch.seq > run.next_seq:
        raise DirectoryError(409, f"expected batch {run.next_seq}, got {batch.seq}")
    if batch.computers and "computers" not in run.scopes or batch.users and "users" not in run.scopes:
        raise DirectoryError(422, "the batch contains objects outside the run's scopes")
    n = len(batch.computers) + len(batch.users)
    if run.computers_seen + run.users_seen + n > run.max_objects:
        fail_run(db, run, f"the collector sent more than the {run.max_objects} objects allowed for this run", now=now)
        raise DirectoryError(422, "max_objects exceeded")
    src = db.get(DirectorySource, run.source_id)
    if src is None:
        raise DirectoryError(404, "sync run not found")
    if run.trigger == "test":
        sample = list(run.sample or [])
        for kind, items in (("computer", batch.computers), ("user", batch.users)):
            for it in items:
                if len(sample) < SAMPLE_SIZE:
                    name = getattr(it, "cn", "") or getattr(it, "sam_account_name", "") or it.object_guid
                    sample.append({"kind": kind, "name": name[:128]})
        run.sample = sample
        run.computers_seen += len(batch.computers)
        run.users_seen += len(batch.users)
    else:
        run.computers_seen += _upsert(db, DirectoryComputer, src, run, batch.computers, _apply_computer, now)
        run.users_seen += _upsert(db, DirectoryUser, src, run, batch.users, _apply_user, now)
    run.next_seq += 1
    run.last_batch_at = now
    run.truncated = run.truncated or batch.truncated
    if batch.final:
        finish_run(db, src, run, batch, now)
    return {"accepted": n, "duplicate": False}


def finish_run(db: Session, src: DirectorySource, run: DirectorySyncRun, batch: BatchIn, now: datetime) -> None:
    run.finished_at = now
    run.token_hash = None
    run.server = batch.server[:253] or None
    run.agent_duration_ms = batch.duration_ms
    totals_ok = batch.totals is None or (batch.totals.computers == run.computers_seen
                                         and batch.totals.users == run.users_seen)
    if batch.status == "succeeded":
        run.status = "succeeded"
        run.error = None if totals_ok else "the collector's totals did not match the objects received"
    else:
        run.status = "failed"
        run.error = (batch.error or "the collector reported a failure")[:2000]
    complete = run.status == "succeeded" and not run.truncated and totals_ok and run.trigger != "test"
    if complete:
        for scope, model in (("computers", DirectoryComputer), ("users", DirectoryUser)):
            if scope in run.scopes:
                mark_missing(db, src, run, model, now)
    record_run_end(db, src, run, now, complete=complete, actor=f"device:{run.device_id}")


def mark_missing(db: Session, src: DirectorySource, run: DirectorySyncRun, model, now: datetime,
                 kinds: tuple[str, ...] | None = None) -> None:
    """Objects of `src` (computers: of these device kinds) that `run` did not return are missing."""
    stmt = update(model).where(model.source_id == src.id, model.missing_since.is_(None),
                               or_(model.last_run_id.is_(None), model.last_run_id != run.id))
    if kinds is not None:
        stmt = stmt.where(model.device_kind.in_(kinds))
    db.execute(stmt.values(missing_since=now).execution_options(synchronize_session=False))


def record_run_end(db: Session, src: DirectorySource, run: DirectorySyncRun, now: datetime, *, complete: bool,
                   actor: str) -> None:
    """Source status, object counts, audit and failure notification of an ended run (caller commits)."""
    from ..auth import audit
    from ..notifications import directory_source

    if run.trigger != "test":
        src.last_sync_at, src.last_sync_status = now, run.status
        src.last_sync_error = run.error if run.status != "succeeded" else (
            "incomplete: the safety cap was reached, missing objects were not marked" if run.truncated else run.error)
        if run.status == "succeeded":
            src.last_success_at = now
        if src.type in CLOUD_TYPES:
            src.scope_status = dict(run.scope_status or {})
        refresh_counts(db, src)
    audit(db, "directory_sync_finished" if run.status == "succeeded" else "directory_sync_failed",
          actor_email=actor, target=f"directory-source:{src.id}", run_id=run.id,
          trigger=run.trigger, computers=run.computers_seen, users=run.users_seen, truncated=run.truncated,
          complete=complete, error=run.error)
    if run.status == "failed" and run.trigger != "test":
        directory_source.sync_failed(db, src, run)


def refresh_counts(db: Session, src: DirectorySource) -> None:
    db.flush()
    src.computers_count = db.scalar(select(func.count()).select_from(DirectoryComputer).where(
        DirectoryComputer.source_id == src.id, DirectoryComputer.missing_since.is_(None))) or 0
    src.users_count = db.scalar(select(func.count()).select_from(DirectoryUser).where(
        DirectoryUser.source_id == src.id, DirectoryUser.missing_since.is_(None))) or 0


def purge_missing(db: Session, now: datetime) -> int:
    """Delete objects missing from complete syncs for DIRECTORY_MISSING_PURGE_DAYS (caller commits)."""
    from sqlalchemy import delete

    cutoff = now - timedelta(days=config.settings.directory_missing_purge_days)
    n = 0
    for model in (DirectoryComputer, DirectoryUser):
        res = db.execute(delete(model).where(model.missing_since.is_not(None), model.missing_since < cutoff)
                         .execution_options(synchronize_session=False))
        n += res.rowcount or 0
    return n


# ----------------------------------------------------------------------------- sources (API)
def run_out(r: DirectorySyncRun, hostnames: dict[str, str] | None = None) -> dict[str, Any]:
    dur = None
    if r.started_at and r.finished_at:
        dur = int((r.finished_at - r.started_at).total_seconds() * 1000)
    return {"id": r.id, "source_id": r.source_id, "trigger": r.trigger, "status": r.status,
            "device_id": r.device_id, "device_hostname": (hostnames or {}).get(r.device_id or ""),
            "queued_at": r.queued_at, "started_at": r.started_at, "finished_at": r.finished_at,
            "duration_ms": dur, "computers_seen": r.computers_seen, "users_seen": r.users_seen,
            "batches": r.next_seq, "truncated": r.truncated, "error": r.error, "attempt": r.attempt,
            "server": r.server, "sample": list(r.sample or []), "checks": list(r.checks or []),
            "scope_status": dict(r.scope_status or {})}


def hostnames_for(db: Session, ids: list[str | None]) -> dict[str, str]:
    ids = [i for i in set(ids) if i]
    if not ids:
        return {}
    return dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_(ids))).all())


def source_out(db: Session, src: DirectorySource, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    ids = list(src.collector_device_ids or [])
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(ids)))} if ids else {}
    run = active_run(db, src.id)
    cfg = dict(src.config or {})
    return {
        "id": src.id, "type": src.type, "name": src.name, "enabled": src.enabled, "config": cfg,
        "has_credential": bool(src.secret_ciphertext), "credential_username_hint": src.credential_hint,
        "collector_device_ids": ids,
        "collectors": [collector_out(devices[i], now) for i in ids if i in devices],
        "last_sync_at": src.last_sync_at, "last_sync_status": src.last_sync_status,
        "last_sync_error": src.last_sync_error, "last_success_at": src.last_success_at,
        "computers_count": src.computers_count, "users_count": src.users_count,
        "collection": "server" if src.type in CLOUD_TYPES else "agent",
        "scope_status": dict(src.scope_status or {}),
        "next_sync_at": next_sync_at(db, src, now),
        "active_run": run_out(run, hostnames_for(db, [run.device_id])) if run is not None else None,
        "created_at": src.created_at, "created_by": src.created_by, "updated_at": src.updated_at,
        "updated_by": src.updated_by,
    }


def validate_source(db: Session, src: DirectorySource) -> None:
    cfg = src.config or {}
    if src.type in CLOUD_TYPES:
        from . import cloud

        cloud.validate_source(db, src)
        return
    if not src.collector_device_ids:
        raise DirectoryError(422, "choose at least one collector agent")
    if cfg.get("auth") == "service_account" and not src.secret_ciphertext:
        raise DirectoryError(422, "service-account auth needs a username and password")
    check_collectors(db, list(src.collector_device_ids or []), cfg.get("auth", "computer_account"))


# ----------------------------------------------------------------------------- IT assets
def discovery_asset_for(db: Session, device: Device):
    """An IT asset an admin created from a directory computer ("Add to IT assets")
    that this newly seen agent device is: the computer must be matched to the
    device, or have the same short host name (and domain, when the device
    reports one). Only an unambiguous, unlinked asset is returned."""
    from ..asset_lifecycle.models import ItAsset

    short = short_host(device.hostname)
    if not short:
        return None
    conds = [DirectoryComputer.device_id == device.id]
    name_match = DirectoryComputer.short_name == short
    if device.ad_domain:
        name_match = and_(name_match, DirectoryComputer.domain == device.ad_domain)
    conds.append(name_match)
    rows = db.execute(select(ItAsset).join(DirectoryComputer, DirectoryComputer.it_asset_id == ItAsset.id)
                      .where(ItAsset.device_id.is_(None), ItAsset.source == "directory",
                             DirectoryComputer.missing_since.is_(None), or_(*conds))).scalars().unique().all()
    return rows[0] if len(rows) == 1 else None
