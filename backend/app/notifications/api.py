"""Notification API: channels, rules, delivery log, test sends.

RBAC: analysts (and admins) may view channels (secrets masked), rules and the
delivery log; only admins create/change/delete channels and rules, send test
notifications and retry dead-lettered deliveries. Viewers have no access.
Every configuration change is written to the audit log (never secret values).
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import audit, client_ip, require_admin, require_analyst
from ..db import get_db
from ..models import User, utcnow
from . import channels as ch
from . import crypto, dispatcher, messages
from . import settings as nsettings
from .events import SEVERITIES, sources
from .models import NotificationChannel, NotificationDelivery, NotificationEvent, NotificationRule
from .schemas import (
    ChannelIn,
    ChannelOut,
    ChannelTestResult,
    ChannelUpdate,
    DeliveryOut,
    RuleIn,
    RuleOut,
)
from .worker import get_worker

router = APIRouter(prefix="/api/notifications", tags=["notifications"], dependencies=[Depends(require_analyst)])


def _encrypt(secrets: dict[str, str]) -> str | None:
    if not secrets:
        return None
    try:
        return crypto.encrypt_secrets(secrets)
    except crypto.EncryptionUnavailable as exc:
        raise HTTPException(503, str(exc)) from None


def _get_channel(db: Session, cid: str) -> NotificationChannel:
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise HTTPException(404, "channel not found")
    return c


def _get_rule(db: Session, rid: str) -> NotificationRule:
    r = db.get(NotificationRule, rid)
    if r is None:
        raise HTTPException(404, "rule not found")
    return r


# --- metadata / status ------------------------------------------------------------

@router.get("/meta")
def meta():
    """Channel types and their fields, event sources and severities (for the UI)."""
    s = nsettings.get()
    return {
        "channel_types": [{"type": t, "label": spec["label"], "description": spec["description"],
                           "fields": [asdict(f) for f in spec["fields"]],
                           "allowed_hosts": s.allowed_hosts("acs" if t == "email" else t)}
                          for t, spec in ch.CHANNEL_TYPES.items()],
        "sources": [{"name": src.name, "label": src.label, "event_types": list(src.event_types),
                     "description": src.description} for src in sources()],
        "severities": list(SEVERITIES),
        "public_base_url": s.public_base_url or None,
        "encryption_configured": bool(s.encryption_keys),
    }


@router.get("/status")
def status(db: Session = Depends(get_db)):
    w = get_worker()
    return {"worker_running": bool(w and w.running), "worker_leader": bool(w and w.is_leader),
            "last_tick_at": messages.iso(w.last_tick_at) if w else None, **dispatcher.queue_stats(db)}


# --- channels ---------------------------------------------------------------------

@router.get("/channels", response_model=list[ChannelOut])
def list_channels(db: Session = Depends(get_db)):
    return list(db.scalars(select(NotificationChannel).order_by(NotificationChannel.name)))


@router.get("/channels/{channel_id}", response_model=ChannelOut)
def get_channel(channel_id: str, db: Session = Depends(get_db)):
    return _get_channel(db, channel_id)


@router.post("/channels", response_model=ChannelOut, status_code=201)
def create_channel(body: ChannelIn, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    try:
        config, secrets = ch.validate(body.type, body.config, body.secrets)
    except ch.ChannelConfigError as exc:
        raise HTTPException(422, str(exc)) from None
    c = NotificationChannel(name=body.name.strip(), type=body.type, enabled=body.enabled, config=config,
                            secret_ciphertext=_encrypt(secrets), secret_hints=ch.hints(body.type, secrets),
                            created_by=admin.email)
    db.add(c)
    db.flush()
    audit(db, "notification_channel_created", actor=admin, target=c.id, ip=client_ip(request), name=c.name,
          type=c.type, secrets_set=sorted(secrets))
    db.commit()
    return c


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_channel(channel_id: str, body: ChannelUpdate, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    c = _get_channel(db, channel_id)
    changes: dict[str, Any] = {}
    if body.config is not None or body.secrets:
        try:
            existing = crypto.decrypt_secrets(c.secret_ciphertext)
        except (crypto.DecryptionFailed, crypto.EncryptionUnavailable):
            existing = {}  # unreadable: the admin must re-enter the secrets
        new_secrets = {k: v for k, v in (body.secrets or {}).items() if v}
        merged = {**existing, **new_secrets}
        config = body.config if body.config is not None else dict(c.config or {})
        try:
            config, merged = ch.validate(c.type, config, merged)
        except ch.ChannelConfigError as exc:
            raise HTTPException(422, str(exc)) from None
        if config != (c.config or {}):
            changes["config"] = sorted(k for k in set(config) | set(c.config or {})
                                       if config.get(k) != (c.config or {}).get(k))
        if merged != existing:
            changes["secrets_changed"] = sorted(k for k in set(merged) | set(existing)
                                                if merged.get(k) != existing.get(k))
            c.secret_ciphertext = _encrypt(merged)
            c.secret_hints = ch.hints(c.type, merged)
        c.config = config
    if body.name is not None and body.name.strip() != c.name:
        changes["name"] = [c.name, body.name.strip()]
        c.name = body.name.strip()
    if body.enabled is not None and body.enabled != c.enabled:
        changes["enabled"] = [c.enabled, body.enabled]
        c.enabled = body.enabled
    if changes:
        c.updated_at = utcnow()
        audit(db, "notification_channel_updated", actor=admin, target=c.id, ip=client_ip(request), name=c.name,
              changes=changes)
    db.commit()
    return c


@router.delete("/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: str, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    c = _get_channel(db, channel_id)
    for r in db.scalars(select(NotificationRule)):
        if channel_id in (r.channel_ids or []):
            r.channel_ids = [x for x in r.channel_ids if x != channel_id]
    audit(db, "notification_channel_deleted", actor=admin, target=c.id, ip=client_ip(request), name=c.name,
          type=c.type)
    db.delete(c)
    db.commit()


@router.post("/channels/{channel_id}/test", response_model=ChannelTestResult)
def test_channel(channel_id: str, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """Send a test message right away (single attempt) and record it in the delivery log."""
    c = _get_channel(db, channel_id)
    now = utcnow()
    msg = messages.test_message(c.name, admin.email, now)
    d = NotificationDelivery(channel_id=c.id, channel_name=c.name, channel_type=c.type, kind="test",
                             severity="info", title=msg["title"], message=msg, status="pending",
                             next_attempt_at=now, created_at=now)
    db.add(d)
    audit(db, "notification_channel_tested", actor=admin, target=c.id, ip=client_ip(request), name=c.name)
    db.commit()
    dispatcher.attempt(db, d, now)
    c = _get_channel(db, channel_id)
    c.last_test_at, c.last_test_status = now, "ok" if d.status == "sent" else "failed"
    db.commit()
    return ChannelTestResult(ok=d.status == "sent", delivery=_delivery_out(d))


@router.get("/preview")
def preview(channel_type: str = Query(..., pattern="^(teams|slack|email|webhook)$"),
            sample: str = Query("event", pattern="^(event|test)$")):
    """Rendered payload of a sample message for a channel type (no secrets involved)."""
    now = utcnow()
    if sample == "test":
        msg = messages.test_message("Preview", None, now)
    else:
        ev = NotificationEvent(id="sample", created_at=now, source="runtime_alert", event_type="created",
                               severity="high", title="Reverse shell detected", summary="bash -i >& /dev/tcp/…",
                               entity_id="sample", group_key="sample", asset_id=None, rule_id="CDR-001",
                               mitre_technique_id="T1059.004", link_path="/threats?alert=sample",
                               attributes={"mitre_technique_name": "Unix Shell", "asset_name": "web-01"})
        msg = messages.event_message(ev)
    return ch.render_preview(channel_type, msg)


# --- rules ------------------------------------------------------------------------

def _check_rule(db: Session, body: RuleIn) -> None:
    known = {c for (c,) in db.execute(select(NotificationChannel.id).where(NotificationChannel.id.in_(body.channel_ids)))}
    missing = [c for c in body.channel_ids if c not in known]
    if missing:
        raise HTTPException(422, f"unknown channel id(s): {', '.join(missing)}")
    names = {s.name for s in sources()}
    bad = [s for s in body.sources if s not in names]
    if bad:
        raise HTTPException(422, f"unknown source(s): {', '.join(bad)}")
    if bool(body.quiet_start) != bool(body.quiet_end):
        raise HTTPException(422, "quiet hours need both quiet_start and quiet_end")


@router.get("/rules", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db)):
    return list(db.scalars(select(NotificationRule).order_by(NotificationRule.created_at)))


@router.post("/rules", response_model=RuleOut, status_code=201)
def create_rule(body: RuleIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    _check_rule(db, body)
    r = NotificationRule(**body.model_dump(), created_by=admin.email)
    db.add(r)
    db.flush()
    audit(db, "notification_rule_created", actor=admin, target=r.id, ip=client_ip(request), name=r.name,
          rule=body.model_dump())
    db.commit()
    return r


@router.put("/rules/{rule_id}", response_model=RuleOut)
def replace_rule(rule_id: str, body: RuleIn, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    r = _get_rule(db, rule_id)
    _check_rule(db, body)
    new = body.model_dump()
    changes = {k: [getattr(r, k), v] for k, v in new.items() if getattr(r, k) != v}
    for k, v in new.items():
        setattr(r, k, v)
    if changes:
        r.updated_at = utcnow()
        audit(db, "notification_rule_updated", actor=admin, target=r.id, ip=client_ip(request), name=r.name,
              changes=changes)
    db.commit()
    return r


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    r = _get_rule(db, rule_id)
    audit(db, "notification_rule_deleted", actor=admin, target=r.id, ip=client_ip(request), name=r.name)
    db.delete(r)
    db.commit()


# --- delivery log -----------------------------------------------------------------

def _delivery_out(d: NotificationDelivery) -> DeliveryOut:
    out = DeliveryOut.model_validate(d)
    out.link = (d.message or {}).get("link")
    return out


@router.get("/deliveries", response_model=list[DeliveryOut])
def list_deliveries(db: Session = Depends(get_db), status: str | None = None, channel_id: str | None = None,
                    kind: str | None = None, limit: int = Query(200, ge=1, le=1000)):
    stmt = select(NotificationDelivery)
    if status:
        stmt = stmt.where(NotificationDelivery.status == status)
    if channel_id:
        stmt = stmt.where(NotificationDelivery.channel_id == channel_id)
    if kind:
        stmt = stmt.where(NotificationDelivery.kind == kind)
    rows = db.scalars(stmt.order_by(NotificationDelivery.created_at.desc(), NotificationDelivery.id).limit(limit))
    return [_delivery_out(d) for d in rows]


@router.post("/deliveries/{delivery_id}/retry", response_model=DeliveryOut)
def retry_delivery(delivery_id: str, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    d = db.get(NotificationDelivery, delivery_id)
    if d is None:
        raise HTTPException(404, "delivery not found")
    if d.status != "dead":
        raise HTTPException(409, "only dead-lettered deliveries can be retried")
    if d.kind == "test":
        raise HTTPException(409, "send a new test notification instead")
    d.status, d.attempts, d.next_attempt_at, d.last_error = "pending", 0, utcnow(), None
    audit(db, "notification_delivery_retried", actor=admin, target=d.id, ip=client_ip(request),
          channel=d.channel_name)
    db.commit()
    return _delivery_out(d)

