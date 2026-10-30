"""Attended remote desktop sessions (docs/DEVICE_MANAGEMENT.md#remote-sessions-windows).

Lifecycle
---------
requested         an analyst / admin asked; a start_remote_session command is queued
awaiting_consent  the agent opened its WebSocket with the single-use token; the
                  consent prompt is on the user's desktop
active            the user clicked Allow (consented) and capture runs (started)
ended | denied | failed   final

The token is minted when the agent polls the command (never stored in the
command's params, only its sha256 on the session) and is valid for
REMOTE_SESSION_TOKEN_TTL_SECONDS, once. Every transition is audited
(remote_session_requested / _consented / _denied / _started / _ended / _failed)
and sent to the "remote_session" notification source. Only metadata is kept:
never frame content or keystrokes.

The relay (app/api/remote_relay.py) runs in one process; it shares state with
the REST API only through these rows, re-checking each live session every
REMOTE_SESSION_RECHECK_SECONDS (`check_live`).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..auth import ROLE_RANK, audit, org_user
from ..models import REMOTE_SESSION_OPEN_STATES, Device, DeviceCommand, Organization, RemoteSession, User, UserSession, utcnow
from ..notifications import remote_session_source
from . import devices as svc

COMMAND_TYPE = "start_remote_session"
FEATURE = "remote_session"
MODE_ROLES = {"view": "analyst", "control": "admin"}
# Errors the agent reports with a failed start_remote_session result.
AGENT_ERRORS = frozenset({"ERR_NO_ATTENDED_USER", "ERR_UNSUPPORTED_PLATFORM", "ERR_HELPER", "ERR_BUSY",
                          "ERR_CONNECT", "ERR_INVALID"})
# How often a viewer's activity refreshes its sign-in session (as REST requests do).
VIEWER_SESSION_TOUCH = timedelta(seconds=30)


def heartbeat_grace() -> timedelta:
    """How long the relay may go without a heartbeat before the sweep calls the
    session lost: at least three of the relay's re-checks (which write it)."""
    return timedelta(seconds=max(60.0, 3 * config.settings.remote_session_recheck_seconds))


class RemoteSessionError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


@dataclass
class Limits:
    idle: timedelta
    max_duration: timedelta
    consent: timedelta
    token_ttl: timedelta


def limits() -> Limits:
    s = config.settings
    return Limits(idle=timedelta(minutes=s.remote_session_idle_timeout_minutes),
                  max_duration=timedelta(minutes=s.remote_session_max_duration_minutes),
                  consent=timedelta(seconds=s.remote_session_consent_timeout_seconds),
                  token_ttl=timedelta(seconds=s.remote_session_token_ttl_seconds))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def is_open(rs: RemoteSession) -> bool:
    return rs.state in REMOTE_SESSION_OPEN_STATES


def can_start(user: User, mode: str) -> bool:
    return ROLE_RANK.get(user.role, -1) >= ROLE_RANK[MODE_ROLES[mode]]


def can_end(user: User, rs: RemoteSession) -> bool:
    """The requester, or any admin of the organisation."""
    return user.id == rs.requested_by_id or ROLE_RANK.get(user.role, -1) >= ROLE_RANK["admin"]


def availability(device: Device) -> str | None:
    """Why a remote session cannot be started on `device` right now (None: it can)."""
    if not config.settings.remote_session_enabled:
        return "remote sessions are disabled on this server"
    if not relay_deployment_ok():
        return "remote sessions are not supported on this deployment (they need the single-process relay)"
    if device.status != "active":
        return "the device is revoked"
    if device.os_family != "windows":
        return "remote sessions are available on Windows devices only for now"
    if FEATURE not in (device.agent_features or "").split(","):
        return "the agent on this device does not support remote sessions yet (update the agent)"
    if device.lost_mode_status is not None:
        return "the device is in lost mode"
    if device.isolation_status is not None:
        return "sign-in is suspended on the device (host isolation)"
    return None


def relay_deployment_ok() -> bool:
    """REMOTE_RELAY_MODE=all pairs both sockets in this process, so it only works
    with one worker (development, tests). Several workers (the image default
    WEB_CONCURRENCY=2, e.g. Azure Container Apps) would split a session's two
    sockets: no button is offered there. On-prem runs mode api + the relay."""
    if config.settings.remote_relay_mode != "all":
        return True
    try:
        return int(os.getenv("WEB_CONCURRENCY", "1") or "1") <= 1
    except ValueError:
        return False


def _detail(rs: RemoteSession, device: Device | None, now: datetime | None = None, **extra) -> dict:
    d = {"session_id": rs.id, "hostname": device.hostname if device else None, "mode": rs.mode,
         "reason": rs.reason, "requested_by": rs.requested_by_email, "state": rs.state}
    if rs.started_at:
        d["started_at"] = rs.started_at.isoformat() + "Z"
    if rs.ended_at:
        d["ended_at"] = rs.ended_at.isoformat() + "Z"
        d["duration_s"] = duration_seconds(rs)
        d["bytes_to_viewer"], d["bytes_to_agent"] = rs.bytes_to_viewer or 0, rs.bytes_to_agent or 0
    d.update({k: v for k, v in extra.items() if v is not None})
    return d


def duration_seconds(rs: RemoteSession) -> int | None:
    if not rs.started_at:
        return None
    end = rs.ended_at or utcnow()
    return max(0, int((end - rs.started_at).total_seconds()))


def _audit(db: Session, rs: RemoteSession, device: Device | None, action: str, *, actor: User | None = None,
           actor_email: str | None = None, ip: str | None = None, **extra) -> None:
    audit(db, f"remote_session_{action}", actor=actor,
          actor_email=actor_email if actor is None else None,
          target=f"device:{rs.device_id}", ip=ip, **_detail(rs, device, **extra))


def _device_actor(device: Device | None) -> str:
    return f"device:{device.hostname if device else 'unknown'}"[:320]


# ----------------------------------------------------------------------------- create
def create(db: Session, device: Device, user: User, mode: str, reason: str, ip: str,
           org_name: str = "") -> RemoteSession:
    """Validate, record and queue a session (the caller commits)."""
    if mode not in MODE_ROLES:
        raise RemoteSessionError(422, "mode must be view or control")
    if not can_start(user, mode):
        raise RemoteSessionError(403, f"a {'View and control' if mode == 'control' else 'View only'} session "
                                      f"requires the {MODE_ROLES[mode]} role")
    why = availability(device)
    if why:
        raise RemoteSessionError(409, why)
    # Serialise creates per organisation so two racing requests cannot both pass
    # the cap (PostgreSQL row lock; SQLite serialises writers by itself).
    db.execute(select(Organization.id).where(Organization.id == device.organization_id).with_for_update())
    sweep(db)
    open_ = db.scalar(select(RemoteSession).where(RemoteSession.open_device_id == device.id))
    if open_ is not None:
        raise RemoteSessionError(409, "a remote session with this device is already open")
    n = db.scalar(select(func.count()).select_from(RemoteSession)
                  .where(RemoteSession.state.in_(REMOTE_SESSION_OPEN_STATES))) or 0
    if n >= config.settings.remote_session_max_per_org:
        raise RemoteSessionError(409, f"the organisation already has {n} open remote sessions "
                                      f"(limit {config.settings.remote_session_max_per_org})")
    lim = limits()
    rs = RemoteSession(device_id=device.id, open_device_id=device.id, requested_by_id=user.id,
                       requested_by_email=user.email, requested_by_name=(user.name or "")[:255],
                       requester_ip=ip, mode=mode, reason=reason, state="requested", created_at=utcnow())
    db.add(rs)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise RemoteSessionError(409, "a remote session with this device is already open") from None
    params = {
        "session_id": rs.id,
        "mode": mode,
        "requester_name": rs.requested_by_name,
        "requester_email": rs.requested_by_email,
        "org_name": (org_name or "")[:128],
        "reason": reason,
        "consent_timeout_seconds": int(lim.consent.total_seconds()),
        "idle_timeout_seconds": int(lim.idle.total_seconds()),
        "max_duration_seconds": int(lim.max_duration.total_seconds()),
        "max_fps": config.settings.remote_session_max_fps,
    }
    cmd = svc.new_command(db, device, COMMAND_TYPE, params, reason, requested_by_id=user.id,
                          requested_by_email=user.email, ttl=lim.token_ttl)
    rs.command_id = cmd.id
    _audit(db, rs, device, "requested", actor=user, ip=ip, command_id=cmd.id)
    remote_session_source.notify(db, device, rs, "session_requested")
    return rs


def issue_token(db: Session, cmd: DeviceCommand) -> str | None:
    """Mint the single-use agent token as `cmd` is handed to the agent (the caller
    commits). None when the session is no longer waiting for the device."""
    rs = db.scalar(select(RemoteSession).where(RemoteSession.command_id == cmd.id))
    if rs is None or rs.state != "requested" or rs.token_hash is not None:
        return None
    token = secrets.token_urlsafe(32)
    rs.token_hash = hash_token(token)
    rs.token_expires_at = utcnow() + limits().token_ttl
    return token


# ----------------------------------------------------------------------------- relay transitions
class RelayReject(Exception):
    """Refuse a WebSocket: `code` is the close code the client sees."""

    def __init__(self, code: int, reason: str):
        super().__init__(reason)
        self.code, self.reason = code, reason


CLOSE_AUTH = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_NOT_FOUND = 4404
CLOSE_IDLE = 4408
CLOSE_DUPLICATE = 4409
CLOSE_EXPIRED = 4410
CLOSE_RATE = 4429
CLOSE_ENDED = 4000
CLOSE_UNAVAILABLE = 1013


def agent_connect(db: Session, device: Device, session_id: str, token: str, ip: str) -> RemoteSession:
    """Check the agent's single-use token and move to awaiting_consent (commits).
    A replayed, expired or wrong token is refused, and a second agent connection
    for the same session too."""
    rs = db.get(RemoteSession, session_id)
    if rs is None or rs.device_id != device.id:
        raise RelayReject(CLOSE_NOT_FOUND, "session not found")
    now = utcnow()
    if not token or rs.token_hash is None or not hmac.compare_digest(hash_token(token), rs.token_hash):
        raise RelayReject(CLOSE_AUTH, "invalid session token")
    if rs.token_used_at is not None:
        raise RelayReject(CLOSE_DUPLICATE, "session token already used")
    if rs.state != "requested":
        raise RelayReject(CLOSE_DUPLICATE, f"session is {rs.state}")
    if rs.token_expires_at is None or rs.token_expires_at <= now:
        fail(db, rs, "ERR_TOKEN_EXPIRED", ip=ip, detail="the device connected after its session token expired")
        db.commit()
        raise RelayReject(CLOSE_EXPIRED, "session token expired")
    # Conditional update: two connections racing with the same token, only one wins.
    res = db.execute(update(RemoteSession).where(RemoteSession.id == rs.id, RemoteSession.token_used_at.is_(None),
                                                 RemoteSession.state == "requested")
                     .values(token_used_at=now, agent_connected_at=now, state="awaiting_consent",
                             consent_deadline_at=now + limits().consent + timedelta(seconds=15),
                             relay_heartbeat_at=now)
                     .execution_options(synchronize_session=False))
    if res.rowcount != 1:
        db.rollback()
        raise RelayReject(CLOSE_DUPLICATE, "session token already used")
    db.commit()
    db.refresh(rs)
    return rs


def viewer_check(db: Session, user: User, session_id: str) -> RemoteSession:
    rs = db.get(RemoteSession, session_id)
    if rs is None:
        raise RelayReject(CLOSE_NOT_FOUND, "session not found")
    if user.id != rs.requested_by_id:
        # Only the requester watches; admins can end anyone's session through the API.
        raise RelayReject(CLOSE_FORBIDDEN, "only the requester can view this session")
    if not is_open(rs):
        raise RelayReject(CLOSE_ENDED, f"session is {rs.state}")
    if not can_start(user, rs.mode):
        raise RelayReject(CLOSE_FORBIDDEN, f"requires the {MODE_ROLES[rs.mode]} role")
    return rs


def consented(db: Session, rs: RemoteSession, ip: str | None = None) -> None:
    if rs.state != "awaiting_consent":
        return
    now = utcnow()
    rs.state, rs.consented_at, rs.last_activity_at = "active", now, now
    device = db.get(Device, rs.device_id)
    _audit(db, rs, device, "consented", actor_email=_device_actor(device), ip=ip)


def started(db: Session, rs: RemoteSession, ip: str | None = None) -> None:
    if rs.state != "active" or rs.started_at is not None:
        return
    rs.started_at = utcnow()
    device = db.get(Device, rs.device_id)
    _audit(db, rs, device, "started", actor_email=_device_actor(device), ip=ip)
    remote_session_source.notify(db, device, rs, "session_started")


def _close(db: Session, rs: RemoteSession, state: str, *, end_reason: str | None = None,
           error_code: str | None = None, by_email: str | None = None) -> Device | None:
    now = utcnow()
    rs.state, rs.ended_at, rs.open_device_id = state, now, None
    rs.end_reason = (end_reason or None) and end_reason[:32]
    rs.error_code = (error_code or None) and error_code[:48]
    rs.ended_by_email = by_email
    # A command the device has not fetched yet must not start anything later.
    if rs.command_id:
        cmd = db.get(DeviceCommand, rs.command_id)
        if cmd is not None and cmd.status == "pending":
            cmd.status, cmd.completed_at, cmd.output = "cancelled", now, f"remote session {state}"
    return db.get(Device, rs.device_id)


def end(db: Session, rs: RemoteSession, end_reason: str, *, actor: User | None = None,
        by_email: str | None = None, ip: str | None = None, input_dropped: int | None = None) -> bool:
    """End an open session (the caller commits). False if it was already over.
    `input_dropped`: input messages the relay dropped (View only), audited when any."""
    if not is_open(rs):
        return False
    device = _close(db, rs, "ended", end_reason=end_reason, by_email=actor.email if actor else by_email)
    _audit(db, rs, device, "ended", actor=actor, actor_email=by_email or _device_actor(device), ip=ip,
           end_reason=end_reason, input_dropped=input_dropped or None)
    remote_session_source.notify(db, device, rs, "session_ended")
    return True


def deny(db: Session, rs: RemoteSession, end_reason: str = "user_denied", ip: str | None = None) -> bool:
    if not is_open(rs):
        return False
    device = _close(db, rs, "denied", end_reason=end_reason)
    _audit(db, rs, device, "denied", actor_email=_device_actor(device), ip=ip, end_reason=end_reason)
    remote_session_source.notify(db, device, rs, "session_denied")
    return True


def fail(db: Session, rs: RemoteSession, error_code: str, *, ip: str | None = None, detail: str = "") -> bool:
    if not is_open(rs):
        return False
    device = _close(db, rs, "failed", end_reason="failed", error_code=error_code)
    _audit(db, rs, device, "failed", actor_email=_device_actor(device), ip=ip, error_code=error_code,
           detail=detail[:500] or None)
    remote_session_source.notify(db, device, rs, "session_failed", detail=detail[:500])
    return True


def command_failed(db: Session, device: Device, cmd: DeviceCommand, error_code: str | None, output: str) -> None:
    """A failed / rejected start_remote_session result from the agent."""
    rs = db.scalar(select(RemoteSession).where(RemoteSession.command_id == cmd.id))
    if rs is None:
        return
    code = error_code if error_code in AGENT_ERRORS else "ERR_AGENT"
    fail(db, rs, code, detail=output)


def command_cancelled(db: Session, cmd: DeviceCommand, user: User, ip: str | None) -> None:
    """The pending start_remote_session command was cancelled from the Commands tab."""
    rs = db.scalar(select(RemoteSession).where(RemoteSession.command_id == cmd.id))
    if rs is not None:
        end(db, rs, "cancelled", actor=user, ip=ip)


def end_for_device(db: Session, device: Device, end_reason: str, *, actor: User | None = None,
                   by_email: str | None = None, ip: str | None = None) -> None:
    """Revoke / lost mode / isolation / wipe: end the device's open session
    (the caller commits; the relay closes both sockets on its next re-check)."""
    rs = db.scalar(select(RemoteSession).where(RemoteSession.open_device_id == device.id))
    if rs is not None:
        end(db, rs, end_reason, actor=actor, by_email=by_email, ip=ip)


# ----------------------------------------------------------------------------- liveness
def check_live(db: Session, rs: RemoteSession, now: datetime | None = None) -> str | None:
    """The reason a live session must end now, or None. Re-read by the relay
    every REMOTE_SESSION_RECHECK_SECONDS."""
    now = now or utcnow()
    if not is_open(rs):
        return rs.end_reason or rs.state
    device = db.get(Device, rs.device_id)
    if device is None or device.status != "active":
        return "device_revoked"
    if device.lost_mode_status in ("enabling", "active"):
        return "device_lost_mode"
    if device.isolation_status in ("isolating", "isolated"):
        return "device_isolated"
    org = tenancy.get_org(db, rs.organization_id)
    if org is None or org.status != "active":
        return "organization_suspended"
    if not config.settings.remote_session_enabled:
        return "disabled"
    user = org_user(db, rs.requested_by_id)
    if user is None or not user.is_active or not can_start(user, rs.mode):
        return "requester_access_revoked"
    lim = limits()
    if rs.state == "active":
        if rs.consented_at and now - rs.consented_at >= lim.max_duration:
            return "max_duration"
        if now - (rs.last_activity_at or rs.consented_at or now) >= lim.idle:
            return "idle"
    if rs.state == "awaiting_consent" and rs.consent_deadline_at and now >= rs.consent_deadline_at:
        return "consent_timeout"
    return None


def viewer_session_live(db: Session, session_id: str | None, activity_at: datetime | None = None,
                        now: datetime | None = None) -> bool:
    """Whether the sign-in session the viewer's socket authenticated with is
    still valid: not signed out (logout, sign-out everywhere, password reset),
    not expired, not idle. The viewer's own activity counts as use of it, as
    REST requests do (app/auth.py:session_from_connection)."""
    if session_id is None:
        return True
    now = now or utcnow()
    sess = db.get(UserSession, session_id)
    if sess is None or sess.revoked_at is not None or now >= sess.expires_at:
        return False
    if activity_at and activity_at - sess.last_seen_at >= VIEWER_SESSION_TOUCH:
        sess.last_seen_at = min(activity_at, now)
    return now < sess.last_seen_at + timedelta(minutes=config.settings.session_idle_minutes)


def apply_end(db: Session, rs: RemoteSession, reason: str, ip: str | None = None,
              input_dropped: int | None = None) -> None:
    """End `rs` for a `check_live` reason with the matching final state."""
    if reason == "consent_timeout":
        deny(db, rs, "consent_timeout", ip=ip)
    else:
        end(db, rs, reason, by_email="system", ip=ip, input_dropped=input_dropped)


def sweep(db: Session, now: datetime | None = None) -> int:
    """Close sessions nobody will finish: the device never connected before its
    token / command expired, the consent deadline passed, the relay stopped
    sending heartbeats, or `check_live` says so. Runs in the relay loop and on
    API reads (the caller commits). Returns how many were closed."""
    now = now or utcnow()
    n = 0
    for rs in db.scalars(select(RemoteSession).where(RemoteSession.state.in_(REMOTE_SESSION_OPEN_STATES))):
        reason = None
        if rs.state == "requested":
            cmd = db.get(DeviceCommand, rs.command_id) if rs.command_id else None
            expired = (rs.token_expires_at is not None and rs.token_expires_at <= now) or (
                cmd is None or cmd.status in ("expired", "cancelled") or cmd.expires_at <= now
                and cmd.status == "pending")
            if expired:
                n += fail(db, rs, "ERR_DEVICE_TIMEOUT",
                          detail="the device did not connect in time (it polls for commands about every 60 s)")
                continue
        elif rs.relay_heartbeat_at is not None and now - rs.relay_heartbeat_at > heartbeat_grace():
            n += end(db, rs, "relay_lost", by_email="system")
            continue
        reason = check_live(db, rs, now)
        if reason:
            apply_end(db, rs, reason)
            n += 1
    return n


def heartbeat(db: Session | None, rs: RemoteSession, *, to_viewer: int = 0, to_agent: int = 0,
              activity_at: datetime | None = None) -> None:
    rs.relay_heartbeat_at = utcnow()
    rs.bytes_to_viewer = (rs.bytes_to_viewer or 0) + to_viewer
    rs.bytes_to_agent = (rs.bytes_to_agent or 0) + to_agent
    if activity_at and (rs.last_activity_at is None or activity_at > rs.last_activity_at):
        rs.last_activity_at = activity_at
