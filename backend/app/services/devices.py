"""Device management domain logic: credentials, check-in processing, derived
health/issues and the remote-command lifecycle.

Issues are deliberately simple, built-in signals (encryption off, firewall off,
...), not configurable compliance policies. They are derived on read from the
latest posture and timestamps, so time-based ones (stale / inactive, updates
pending for too long) are always current.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from .. import config
from ..models import (
    Device,
    DeviceCommand,
    DeviceCredential,
    DevicePostureSnapshot,
    DeviceSoftware,
    EnrollmentToken,
    utcnow,
)
from ..notifications import device_source
from ..schemas_devices import MAX_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS, CheckinRequest

ENROLL_TOKEN_PREFIX = "cne_"  # noqa: S105 (a public prefix, not a secret)
DEVICE_SECRET_PREFIX = "cnd_"  # noqa: S105
COMMAND_POLL_SECONDS = 60
DEFAULT_INTERVAL_SECONDS = 900
FINAL_COMMAND_STATES = frozenset({"succeeded", "failed", "rejected", "expired", "cancelled"})

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def hash_secret(value: str) -> str:
    """SHA-256 hex. The tokens are 256-bit random values, so a fast hash is
    enough (no dictionary attack is possible) and lookups stay O(1)."""
    return hashlib.sha256(value.encode()).hexdigest()


def new_enrollment_token() -> str:
    return ENROLL_TOKEN_PREFIX + secrets.token_urlsafe(32)


def new_device_secret() -> str:
    return DEVICE_SECRET_PREFIX + secrets.token_urlsafe(32)


# ----------------------------------------------------------------------------- tokens
def token_state(t: EnrollmentToken, now: datetime | None = None) -> str:
    now = now or utcnow()
    if t.revoked_at is not None:
        return "revoked"
    if t.expires_at <= now:
        return "expired"
    if t.max_uses is not None and t.use_count >= t.max_uses:
        return "exhausted"
    return "active"


def consume_enrollment_token(db: Session, raw: str) -> EnrollmentToken | None:
    """Atomically use one enrollment of a valid token; None if invalid.

    The conditional UPDATE makes concurrent enrollments with a single-use token
    race-safe on both PostgreSQL and SQLite."""
    now = utcnow()
    th = hash_secret(raw)
    res = db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.token_hash == th, EnrollmentToken.revoked_at.is_(None),
               EnrollmentToken.expires_at > now,
               (EnrollmentToken.max_uses.is_(None)) | (EnrollmentToken.use_count < EnrollmentToken.max_uses))
        .values(use_count=EnrollmentToken.use_count + 1, last_used_at=now)
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        return None
    return db.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == th))


def issue_credential(db: Session, device: Device) -> str:
    """Revoke the device's existing credentials and return a fresh secret."""
    now = utcnow()
    db.execute(update(DeviceCredential).where(DeviceCredential.device_id == device.id,
                                              DeviceCredential.revoked_at.is_(None)).values(revoked_at=now))
    secret = new_device_secret()
    db.add(DeviceCredential(device_id=device.id, secret_hash=hash_secret(secret), created_at=now))
    return secret


def revoke_device(db: Session, device: Device) -> None:
    now = utcnow()
    device.status = "revoked"
    device.revoked_at = now
    db.execute(update(DeviceCredential).where(DeviceCredential.device_id == device.id,
                                              DeviceCredential.revoked_at.is_(None)).values(revoked_at=now))
    db.execute(update(DeviceCommand).where(DeviceCommand.device_id == device.id,
                                           DeviceCommand.status.in_(("pending", "delivered")))
               .values(status="cancelled", completed_at=now, output="device revoked"))


# ----------------------------------------------------------------------------- check-in
def _pending_updates(posture: dict[str, Any]) -> int | None:
    upd = posture.get("os_updates") or {}
    n = (upd.get("data") or {}).get("pending_count")
    return n if isinstance(n, int) and n >= 0 else None


def apply_checkin(db: Session, device: Device, body: CheckinRequest, ip: str | None) -> list[str]:
    """Store a check-in: latest inventory/posture on the device, a history
    snapshot, and (if sent) the installed-software list. Returns issue codes."""
    s = config.settings
    now = utcnow()
    info = body.device
    device.hostname = info.hostname
    device.os_name, device.os_version, device.os_build = info.os_name, info.os_version, info.os_build
    device.architecture = info.architecture
    device.serial_number = info.serial_number or device.serial_number
    device.manufacturer, device.model = info.manufacturer, info.model
    if info.agent_version:
        device.agent_version = info.agent_version
    device.inventory = info.model_dump(mode="json")
    posture = {k: v.model_dump(mode="json") for k, v in body.posture.items()}
    device.posture = posture
    device.collection_errors = dict(body.errors)
    device.last_seen_at = device.last_checkin_at = now
    device.last_ip = ip
    _reconcile_lost_mode(device, posture, now)
    pending = _pending_updates(posture)
    if pending:
        device.updates_pending_since = device.updates_pending_since or now
    elif pending == 0:
        device.updates_pending_since = None

    if body.software is not None:
        db.execute(delete(DeviceSoftware).where(DeviceSoftware.device_id == device.id))
        seen: set[tuple[str, str]] = set()
        rows = []
        for item in body.software:
            key = (item.name.lower(), item.version)
            if key in seen:
                continue
            seen.add(key)
            rows.append(DeviceSoftware(device_id=device.id, name=item.name, version=item.version,
                                       publisher=item.publisher, identifier=item.identifier,
                                       install_date=item.install_date, source=item.source))
        db.add_all(rows)
        device.software_count = len(rows)

    # Issue codes at the previous check-in (None: first check-in), to notify about new ones only.
    prev = db.scalar(select(DevicePostureSnapshot.issues).where(DevicePostureSnapshot.device_id == device.id)
                     .order_by(DevicePostureSnapshot.id.desc()).limit(1))
    current = device_issues(device, now)
    issues = [i["code"] for i in current]
    device_source.issues_raised(db, device, current, set(prev) if prev is not None else None)
    collected = body.collected_at
    if collected is not None and collected.tzinfo is not None:
        collected = collected.astimezone(UTC).replace(tzinfo=None)
    db.add(DevicePostureSnapshot(device_id=device.id, received_at=now, collected_at=collected,
                                 agent_version=device.agent_version, os_version=info.os_version, posture=posture,
                                 issues=issues,
                                 software_count=device.software_count if body.software is not None else None))
    db.flush()
    _prune_history(db, device.id, s.device_history_limit)
    return issues


def _reconcile_lost_mode(device: Device, posture: dict[str, Any], now: datetime) -> None:
    """The agent reports whether lost mode is active (posture check `lost_mode`).
    While an enable/disable command is in flight the server state wins."""
    data = (posture.get("lost_mode") or {}).get("data") or {}
    active = data.get("active")
    if not isinstance(active, bool) or device.lost_mode_status in ("enabling", "disabling"):
        return
    if active and device.lost_mode_status is None:
        device.lost_mode_status, device.lost_mode_since = "active", device.lost_mode_since or now
    elif not active and device.lost_mode_status == "active":
        device.lost_mode_status = None


def _prune_history(db: Session, device_id: str, keep: int) -> None:
    cutoff = db.scalar(select(DevicePostureSnapshot.id).where(DevicePostureSnapshot.device_id == device_id)
                       .order_by(DevicePostureSnapshot.id.desc()).offset(keep).limit(1))
    if cutoff is not None:
        db.execute(delete(DevicePostureSnapshot).where(DevicePostureSnapshot.device_id == device_id,
                                                       DevicePostureSnapshot.id <= cutoff))


# ----------------------------------------------------------------------------- health
def connectivity(device: Device, now: datetime | None = None) -> str:
    s = config.settings
    now = now or utcnow()
    if device.last_seen_at is None:
        return "never"
    age = now - device.last_seen_at
    if age > timedelta(days=s.device_inactive_days):
        return "inactive"
    if age > timedelta(hours=s.device_stale_hours):
        return "stale"
    return "active"


def _check(posture: dict[str, Any], name: str) -> tuple[str | None, dict[str, Any], str]:
    c = posture.get(name)
    if not isinstance(c, dict):
        return None, {}, ""
    return c.get("status"), c.get("data") or {}, c.get("detail") or ""


ISSUE_DEFS: dict[str, tuple[str, str]] = {
    # code: (severity, title)
    "disk_encryption_off": ("high", "Disk encryption is off"),
    "firewall_off": ("high", "Firewall is off"),
    "antivirus_off": ("high", "Antivirus / real-time protection is off"),
    "av_signatures_outdated": ("medium", "Antivirus signatures are outdated"),
    "os_updates_pending": ("medium", "OS updates pending"),
    "screen_lock_off": ("low", "Screen lock / password on wake not enforced"),
    "sip_disabled": ("high", "System Integrity Protection is disabled"),
    "gatekeeper_off": ("medium", "Gatekeeper is disabled"),
    "secure_boot_off": ("medium", "Secure Boot is off"),
    "stale": ("medium", "No check-in for over a day"),
    "inactive": ("high", "No check-in for over a week"),
    "revoked": ("low", "Device credential revoked"),
    "lost_mode": ("high", "Device is in lost mode"),
    "wipe_pending": ("critical", "Remote wipe requested / in progress"),
}

LOST_STATES = ("enabling", "active", "disabling")
WIPE_PENDING_STATES = ("queued", "acknowledged", "started")
# Remote actions that are never queued directly: they need a two-person approval
# (app/services/approvals.py), or for low-risk scripts go through /api/scripts/run.
APPROVAL_COMMANDS = ("wipe_device", "run_script")


def device_issues(device: Device, now: datetime | None = None) -> list[dict[str, str]]:
    s = config.settings
    now = now or utcnow()
    p = device.posture or {}
    out: list[dict[str, str]] = []

    def add(code: str, detail: str = "") -> None:
        sev, title = ISSUE_DEFS[code]
        out.append({"code": code, "severity": sev, "title": title, "detail": detail})

    if device.status == "revoked":
        add("revoked")
    if device.wipe_status in WIPE_PENDING_STATES:
        add("wipe_pending", f"wipe {device.wipe_status}")
    elif device.lost_mode_status in LOST_STATES:
        add("lost_mode", f"lost mode {device.lost_mode_status}")
    simple = [("disk_encryption", "disk_encryption_off"), ("firewall", "firewall_off"),
              ("antivirus", "antivirus_off"), ("screen_lock", "screen_lock_off"), ("sip", "sip_disabled"),
              ("gatekeeper", "gatekeeper_off"), ("secure_boot", "secure_boot_off")]
    for check, code in simple:
        status, _, detail = _check(p, check)
        if status == "fail":
            add(code, detail)
    _, av, _ = _check(p, "antivirus")
    age = av.get("signature_age_days")
    if isinstance(age, int | float) and age > s.device_av_signature_max_age_days:
        add("av_signatures_outdated", f"signatures are {age:g} days old")
    if device.updates_pending_since is not None:
        days = (now - device.updates_pending_since).total_seconds() / 86400
        if days >= s.device_updates_grace_days:
            n = _pending_updates(p)
            add("os_updates_pending", f"{n if n is not None else 'some'} update(s) pending for {int(days)} days")
    conn = connectivity(device, now)
    if conn == "inactive":
        add("inactive")
    elif conn == "stale":
        add("stale")
    out.sort(key=lambda i: -SEVERITY_RANK[i["severity"]])
    return out


def health_from_issues(device: Device, issues: list[dict[str, str]]) -> str:
    if device.last_checkin_at is None:
        return "unknown"
    worst = max((SEVERITY_RANK[i["severity"]] for i in issues if i["code"] != "revoked"), default=-1)
    if worst >= SEVERITY_RANK["high"]:
        return "critical"
    if worst >= 0:
        return "warning"
    return "healthy"


def summarize(device: Device, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    issues = device_issues(device, now)
    inv = device.inventory or {}
    return {
        "id": device.id, "hostname": device.hostname, "os_family": device.os_family, "os_name": device.os_name,
        "os_version": device.os_version, "architecture": device.architecture,
        "serial_number": device.serial_number, "manufacturer": device.manufacturer, "model": device.model,
        "agent_version": device.agent_version, "status": device.status, "enrolled_at": device.enrolled_at,
        "last_seen_at": device.last_seen_at, "last_checkin_at": device.last_checkin_at,
        "logged_in_users": list(inv.get("logged_in_users") or [])[:10],
        "device_group": device.device_group,
        "health": health_from_issues(device, issues), "connectivity": connectivity(device, now), "issues": issues,
        "device_state": device_state(device),
    }


def device_state(device: Device) -> str:
    """Lifecycle-ish state for the UI / asset views: wipe_pending > lost > revoked > active."""
    if device.wipe_status in WIPE_PENDING_STATES:
        return "wipe_pending"
    if device.lost_mode_status in LOST_STATES:
        return "lost"
    return "revoked" if device.status == "revoked" else "active"


def lost_mode_info(device: Device) -> dict[str, Any]:
    rep = ((device.posture or {}).get("lost_mode") or {}).get("data") or {}
    return {"status": device.lost_mode_status, "message": device.lost_mode_message, "phone": device.lost_mode_phone,
            "since": device.lost_mode_since, "requested_by": device.lost_mode_by,
            "reported_active": rep.get("active") if isinstance(rep.get("active"), bool) else None}


def wipe_info(device: Device) -> dict[str, Any]:
    """Wipe state plus what the agent last reported about wipe readiness (Windows only)."""
    rep = ((device.posture or {}).get("remote_wipe") or {})
    data = rep.get("data") or {}
    supported = device.os_family == "windows"
    return {"supported": supported,
            "unsupported_reason": None if supported else (
                "Remote wipe is Windows only: a full erase of a Mac needs a real Apple MDM "
                "(EraseDevice), which this product does not have."),
            "opted_in": data.get("opt_in") is True, "ready": data.get("ready") is True,
            "readiness": data, "readiness_detail": rep.get("detail") or "",
            "status": device.wipe_status, "status_at": device.wipe_status_at, "command_id": device.wipe_command_id}


def fleet_summary(db: Session) -> dict[str, Any]:
    now = utcnow()
    devices = list(db.scalars(select(Device)))
    active = [d for d in devices if d.status == "active"]
    by_os: dict[str, int] = {}
    by_health = {"healthy": 0, "warning": 0, "critical": 0, "unknown": 0}
    issue_counts: dict[str, int] = {}
    conn_counts = {"active": 0, "stale": 0, "inactive": 0, "never": 0}
    enc = {"pass": 0, "known": 0}
    fw = {"pass": 0, "known": 0}
    for d in active:
        sm = summarize(d, now)
        by_os[d.os_family] = by_os.get(d.os_family, 0) + 1
        by_health[sm["health"]] += 1
        conn_counts[sm["connectivity"]] += 1
        for i in sm["issues"]:
            issue_counts[i["code"]] = issue_counts.get(i["code"], 0) + 1
        for name, acc in (("disk_encryption", enc), ("firewall", fw)):
            st = ((d.posture or {}).get(name) or {}).get("status")
            if st in ("pass", "fail"):
                acc["known"] += 1
                acc["pass"] += st == "pass"

    def pct(acc: dict[str, int]) -> float | None:
        return round(100 * acc["pass"] / acc["known"], 1) if acc["known"] else None

    return {
        "total": len(active), "revoked": len(devices) - len(active), "by_os": by_os, "by_health": by_health,
        "connectivity": conn_counts, "issues": issue_counts,
        "encrypted_percent": pct(enc), "firewall_percent": pct(fw),
        "encryption_known": enc["known"], "firewall_known": fw["known"],
    }


# ----------------------------------------------------------------------------- commands
_CTRL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")
PHONE_RE = re.compile(r"^[0-9+][0-9 ()./+-]{2,31}$")
LOST_MESSAGE_MAX = 300


def validate_params(cmd_type: str, params: dict[str, Any]) -> dict[str, Any]:
    """Server-side allowlist of parameters per command type."""
    if cmd_type == "enable_lost_mode":
        msg, phone = params.get("message"), params.get("phone")
        if set(params) != {"message", "phone"} or not isinstance(msg, str) or not isinstance(phone, str):
            raise ValueError("params must be {'message': text, 'phone': text}")
        msg, phone = msg.strip().replace("\r\n", "\n"), phone.strip()
        if not 1 <= len(msg) <= LOST_MESSAGE_MAX or _CTRL.search(msg) or msg.count("\n") > 5:
            raise ValueError(f"message must be 1-{LOST_MESSAGE_MAX} characters, at most 6 lines, "
                             "no control characters")
        if not PHONE_RE.match(phone):
            raise ValueError("phone must be 3-32 characters: digits, spaces and + ( ) . / -")
        return {"message": msg, "phone": phone}
    if cmd_type == "update_check_in_interval":
        v = params.get("interval_seconds")
        if set(params) != {"interval_seconds"} or not isinstance(v, int) or isinstance(v, bool) or not (
                MIN_INTERVAL_SECONDS <= v <= MAX_INTERVAL_SECONDS):
            raise ValueError(f"params must be {{'interval_seconds': {MIN_INTERVAL_SECONDS}..{MAX_INTERVAL_SECONDS}}}")
        return {"interval_seconds": v}
    if params:
        raise ValueError(f"{cmd_type} takes no parameters")
    return {}


# Command types whose outcome changes device state (lost mode, wipe).
STATEFUL_COMMANDS = ("enable_lost_mode", "disable_lost_mode", "wipe_device")


def expire_commands(db: Session, device_id: str | None = None) -> None:
    now = utcnow()
    stmt = update(DeviceCommand).where(DeviceCommand.status.in_(("pending", "delivered")),
                                       DeviceCommand.expires_at <= now)
    if device_id:
        stmt = stmt.where(DeviceCommand.device_id == device_id)
    # Stateful commands first, one by one, so the device state follows.
    sq = select(DeviceCommand).where(DeviceCommand.status.in_(("pending", "delivered")),
                                     DeviceCommand.expires_at <= now, DeviceCommand.type.in_(STATEFUL_COMMANDS))
    if device_id:
        sq = sq.where(DeviceCommand.device_id == device_id)
    for c in db.scalars(sq):
        c.status, c.completed_at = "expired", now
        dev = db.get(Device, c.device_id)
        if dev is not None:
            command_finished(dev, c)
    db.flush()
    db.execute(stmt.values(status="expired", completed_at=now).execution_options(synchronize_session=False))


def new_command(db: Session, device: Device, cmd_type: str, params: dict[str, Any], reason: str, *,
                requested_by_id: str | None, requested_by_email: str | None, ttl: timedelta | None = None,
                approval_id: str | None = None, approved_by_email: str | None = None) -> DeviceCommand:
    """Queue a validated command (callers audit and commit) and apply its device-state side effects."""
    now = utcnow()
    ttl = ttl or timedelta(hours=config.settings.device_command_ttl_hours)
    cmd = DeviceCommand(device_id=device.id, type=cmd_type, params=params, nonce=secrets.token_hex(16),
                        reason=reason, requested_by_id=requested_by_id, requested_by_email=requested_by_email,
                        created_at=now, expires_at=now + ttl, approval_id=approval_id,
                        approved_by_email=approved_by_email)
    db.add(cmd)
    db.flush()
    if cmd_type == "enable_lost_mode":
        device.lost_mode_status = "enabling"
        device.lost_mode_message, device.lost_mode_phone = params["message"], params["phone"]
        device.lost_mode_since, device.lost_mode_by = now, requested_by_email
    elif cmd_type == "disable_lost_mode":
        device.lost_mode_status = "disabling"
    elif cmd_type == "wipe_device":
        device.wipe_status, device.wipe_status_at, device.wipe_command_id = "queued", now, cmd.id
    return cmd


def command_finished(device: Device, cmd: DeviceCommand) -> None:
    """Update lost-mode / wipe state from a final command status."""
    now = utcnow()
    ok = cmd.status == "succeeded"
    if cmd.type == "enable_lost_mode" and device.lost_mode_status == "enabling":
        device.lost_mode_status = "active" if ok else None
    elif cmd.type == "disable_lost_mode" and device.lost_mode_status == "disabling":
        if ok:
            device.lost_mode_status = device.lost_mode_message = device.lost_mode_phone = None
            device.lost_mode_since = device.lost_mode_by = None
        else:
            device.lost_mode_status = "active"
    elif cmd.type == "wipe_device" and device.wipe_command_id == cmd.id:
        device.wipe_status = {"succeeded": "started", "cancelled": None}.get(
            cmd.status, "expired" if cmd.status == "expired" else "failed")
        if cmd.status == "expired" and cmd.acknowledged_at is not None:
            # Acknowledged but never reported back: the device is most likely wiping.
            device.wipe_status = "acknowledged"
        device.wipe_status_at = now


def deliver_pending(db: Session, device: Device) -> list[DeviceCommand]:
    """Hand pending commands to the agent exactly once (pending -> delivered)."""
    expire_commands(db, device.id)
    now = utcnow()
    cmds = list(db.scalars(select(DeviceCommand).where(DeviceCommand.device_id == device.id,
                                                       DeviceCommand.status == "pending")
                           .order_by(DeviceCommand.created_at).limit(20)))
    delivered = []
    for c in cmds:
        res = db.execute(update(DeviceCommand).where(DeviceCommand.id == c.id, DeviceCommand.status == "pending")
                         .values(status="delivered", delivered_at=now).execution_options(synchronize_session=False))
        if res.rowcount == 1:
            c.status, c.delivered_at = "delivered", now
            delivered.append(c)
    return delivered


def pending_count(db: Session, device_id: str) -> int:
    return db.scalar(select(func.count()).select_from(DeviceCommand).where(
        DeviceCommand.device_id == device_id, DeviceCommand.status == "pending")) or 0


def clamp_interval(v: int) -> int:
    return max(MIN_INTERVAL_SECONDS, min(MAX_INTERVAL_SECONDS, v))
