"""Delivery engine: events -> rules -> outbox -> channels.

All functions take an explicit `now` (naive UTC) so they are deterministic in
tests. They are run by the leader-elected NotificationWorker (worker.py); only
one replica at a time sends, so a message is never sent twice concurrently.
Delivery is at-least-once: a crash between sending and recording the result
re-sends after the "sending" lease expires (receivers can de-duplicate on the
delivery id).
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .. import tenancy
from ..models import Asset, get_asset, utcnow
from . import channels as ch
from . import crypto, messages
from . import settings as nsettings
from .events import SEV_RANK, emit, sources
from .models import (
    NotificationChannel,
    NotificationDelivery,
    NotificationDigestItem,
    NotificationEvent,
    NotificationRule,
    NotificationSourceState,
    NotificationThrottle,
)
from .rules import build_context, digest_due, matches, quiet_until

log = logging.getLogger(__name__)

SENDING_LEASE = timedelta(minutes=5)
MAX_DIGEST_ITEMS = 50
MAX_THROTTLE_MINUTES = 7 * 24 * 60


# --- events -> deliveries ---------------------------------------------------------------

def process_events(db: Session, now: datetime | None = None, limit: int | None = None) -> int:
    """Match unprocessed events against rules and queue deliveries. Returns events processed."""
    now = now or utcnow()
    limit = limit or nsettings.get().event_batch_size
    events = list(db.scalars(select(NotificationEvent).where(NotificationEvent.processed_at.is_(None))
                             .order_by(NotificationEvent.created_at, NotificationEvent.id).limit(limit)))
    if not events:
        return 0
    rules = list(db.scalars(select(NotificationRule).where(NotificationRule.enabled.is_(True))
                            .order_by(NotificationRule.created_at)))
    chans = {c.id: c for c in db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True)))}
    assets: dict[str, Asset | None] = {}
    throttles: dict[tuple[str, str, str], NotificationThrottle | None] = {}

    for ev in events:
        ev.processed_at = now
        if not rules:
            continue
        if ev.asset_id and ev.asset_id not in assets:
            assets[ev.asset_id] = get_asset(db, ev.asset_id)
        asset = assets.get(ev.asset_id) if ev.asset_id else None
        ctx = build_context(ev, asset)
        for rule in rules:
            # A rule applies from its creation on: creating the first rule must not
            # replay the backlog (e.g. seeded history) into a channel.
            if ev.created_at < rule.created_at or not matches(rule, ctx):
                continue
            for cid in rule.channel_ids or []:
                channel = chans.get(cid)
                if channel is None:
                    continue
                if rule.mode == "digest":
                    db.add(NotificationDigestItem(rule_id=rule.id, channel_id=cid, created_at=now,
                                                  severity=ev.severity, title=ev.title[:255], source=ev.source,
                                                  link_path=ev.link_path))
                    continue
                suppressed = 0
                minutes = min(max(rule.throttle_minutes or 0, 0), MAX_THROTTLE_MINUTES)
                if minutes:
                    key = (rule.id, cid, ev.group_key)
                    if key not in throttles:
                        throttles[key] = db.scalar(select(NotificationThrottle).where(
                            NotificationThrottle.rule_id == rule.id, NotificationThrottle.channel_id == cid,
                            NotificationThrottle.group_key == ev.group_key))
                    t = throttles[key]
                    if t is not None and t.last_sent_at > now - timedelta(minutes=minutes):
                        t.suppressed += 1
                        continue
                    if t is None:
                        t = NotificationThrottle(rule_id=rule.id, channel_id=cid, group_key=ev.group_key,
                                                 suppressed=0)
                        db.add(t)
                        throttles[key] = t
                    suppressed, t.suppressed, t.last_sent_at = t.suppressed, 0, now
                held = quiet_until(rule, now, ev.severity)
                db.add(NotificationDelivery(
                    channel_id=cid, channel_name=channel.name, channel_type=channel.type, rule_id=rule.id,
                    rule_name=rule.name, event_id=ev.id, kind="event", severity=ev.severity, title=ev.title[:255],
                    message=messages.event_message(ev, asset, suppressed=suppressed, rule_name=rule.name),
                    status="pending", next_attempt_at=held or now, created_at=now,
                    last_error=f"held for quiet hours until {messages.iso(held)}" if held else None))
    db.commit()
    return len(events)


def flush_digests(db: Session, now: datetime | None = None) -> int:
    """Send each digest rule's queued items once a day. Returns digests queued."""
    now = now or utcnow()
    queued = 0
    rules = db.scalars(select(NotificationRule).where(NotificationRule.enabled.is_(True),
                                                      NotificationRule.mode == "digest"))
    for rule in rules:
        if not digest_due(rule, now):
            continue
        items = list(db.scalars(select(NotificationDigestItem).where(NotificationDigestItem.rule_id == rule.id)
                                .order_by(NotificationDigestItem.id)))
        by_channel: dict[str, list[NotificationDigestItem]] = {}
        for it in items:
            by_channel.setdefault(it.channel_id, []).append(it)
        for cid, its in by_channel.items():
            channel = db.get(NotificationChannel, cid)
            if channel is None or not channel.enabled:
                continue
            ordered = sorted(its, key=lambda i: (-SEV_RANK.get(i.severity, 0), i.id))
            payload = [{"severity": i.severity, "title": i.title, "source": i.source, "link_path": i.link_path}
                       for i in ordered[:MAX_DIGEST_ITEMS]]
            msg = messages.digest_message(rule.name, payload, len(its), now)
            db.add(NotificationDelivery(channel_id=cid, channel_name=channel.name, channel_type=channel.type,
                                        rule_id=rule.id, rule_name=rule.name, kind="digest",
                                        severity=msg["severity"], title=msg["title"][:255], message=msg,
                                        status="pending", next_attempt_at=now, created_at=now))
            queued += 1
        for it in items:
            db.delete(it)
        rule.last_digest_at = now
    db.commit()
    return queued


# --- pull sources -------------------------------------------------------------------------

def poll_sources(db: Session, now: datetime | None = None, force: bool = False) -> int:
    """Run due pull sources (e.g. attack paths); emitted events go to the inbox."""
    now = now or utcnow()
    emitted = 0
    for src in sources():
        if src.poll is None:
            continue
        st = db.get(NotificationSourceState, (tenancy.require_org(db), src.name))
        interval = src.poll_interval() if src.poll_interval else 600.0
        if not force and st is not None and st.last_run_at and st.last_run_at > now - timedelta(seconds=interval):
            continue
        try:
            events, new_state = src.poll(db, dict(st.state or {}) if st else {}, now)
        except Exception:
            log.exception("notification source %s poll failed", src.name)
            db.rollback()
            continue
        if st is None:
            st = NotificationSourceState(source=src.name)
            db.add(st)
        st.state, st.last_run_at = new_state, now
        for e in events:
            if emit(db, e) is not None:
                emitted += 1
        db.commit()
    return emitted


# --- outbox -> channels --------------------------------------------------------------------

def backoff_seconds(attempts: int, retry_after: float | None = None, *, jitter: bool = True) -> float:
    s = nsettings.get()
    delay = min(s.backoff_base_seconds * (2 ** max(attempts - 1, 0)), s.backoff_max_seconds)
    if jitter:
        delay *= random.uniform(0.8, 1.2)  # noqa: S311 - not security sensitive
    if retry_after:
        delay = max(delay, min(retry_after, s.backoff_max_seconds))
    return delay


def _load_secrets(channel: NotificationChannel) -> dict[str, str]:
    try:
        return crypto.decrypt_secrets(channel.secret_ciphertext)
    except (crypto.DecryptionFailed, crypto.EncryptionUnavailable) as exc:
        raise ch.PermanentError(str(exc)) from None


def attempt(db: Session, d: NotificationDelivery, now: datetime | None = None) -> NotificationDelivery:
    """Make one delivery attempt and record the outcome (commits)."""
    s = nsettings.get()
    now = now or utcnow()
    channel = db.get(NotificationChannel, d.channel_id) if d.channel_id else None
    d.status, d.attempts, d.last_attempt_at = "sending", d.attempts + 1, now
    db.commit()  # lease: never hold a transaction open during network I/O
    secrets: dict[str, str] = {}
    try:
        if channel is None:
            raise ch.PermanentError("channel was deleted")
        if not channel.enabled and d.kind != "test":
            raise ch.PermanentError("channel is disabled")
        secrets = _load_secrets(channel)
        result = ch.send(channel.type, channel.config or {}, secrets, d.message or {}, d.id)
        d.status, d.sent_at, d.response_status, d.last_error = "sent", utcnow(), result.status, None
    except ch.TransientError as exc:
        d.response_status = exc.status
        d.last_error = crypto.redact(str(exc), secrets)[:1000]
        if d.attempts >= s.max_attempts or d.kind == "test":
            d.status = "dead"
        else:
            d.status = "pending"
            d.next_attempt_at = now + timedelta(seconds=backoff_seconds(d.attempts, exc.retry_after))
    except ch.PermanentError as exc:
        d.status, d.response_status = "dead", exc.status
        d.last_error = crypto.redact(str(exc), secrets)[:1000]
    except Exception as exc:  # unexpected: retry, but never leak secrets
        log.exception("notification delivery %s failed unexpectedly", d.id)
        d.last_error = crypto.redact(f"{type(exc).__name__}: {exc}", secrets)[:1000]
        if d.attempts >= s.max_attempts or d.kind == "test":
            d.status = "dead"
        else:
            d.status = "pending"
            d.next_attempt_at = now + timedelta(seconds=backoff_seconds(d.attempts))
    if d.status == "dead":
        log.warning("notification delivery %s to %s dead-lettered after %d attempt(s): %s", d.id,
                    d.channel_name, d.attempts, d.last_error)
    db.commit()
    return d


def send_due(db: Session, now: datetime | None = None, limit: int | None = None) -> dict[str, int]:
    now = now or utcnow()
    limit = limit or nsettings.get().send_batch_size
    due = list(db.scalars(select(NotificationDelivery).where(or_(
        (NotificationDelivery.status == "pending") & (NotificationDelivery.next_attempt_at <= now),
        # crash recovery: an attempt that never recorded its outcome
        (NotificationDelivery.status == "sending") & (NotificationDelivery.last_attempt_at < now - SENDING_LEASE),
    )).order_by(NotificationDelivery.next_attempt_at).limit(limit)))
    stats = {"sent": 0, "retry": 0, "dead": 0}
    for d in due:
        if d.last_error and d.last_error.startswith("held for quiet hours"):
            d.last_error = None
        attempt(db, d, now)
        stats["sent" if d.status == "sent" else "dead" if d.status == "dead" else "retry"] += 1
    return stats


def cleanup(db: Session, now: datetime | None = None) -> None:
    now = now or utcnow()
    cutoff = now - timedelta(days=nsettings.get().retention_days)
    db.execute(delete(NotificationEvent).where(NotificationEvent.processed_at < cutoff))
    db.execute(delete(NotificationDelivery).where(NotificationDelivery.status.in_(("sent", "dead")),
                                                  NotificationDelivery.created_at < cutoff))
    db.execute(delete(NotificationThrottle).where(
        NotificationThrottle.last_sent_at < now - timedelta(minutes=MAX_THROTTLE_MINUTES)))
    db.commit()


def queue_stats(db: Session) -> dict[str, Any]:
    counts = dict(db.execute(select(NotificationDelivery.status, func.count())
                             .group_by(NotificationDelivery.status)).all())
    since = utcnow() - timedelta(hours=24)
    sent_24h = db.scalar(select(func.count()).select_from(NotificationDelivery).where(
        NotificationDelivery.status == "sent", NotificationDelivery.sent_at >= since)) or 0
    backlog = db.scalar(select(func.count()).select_from(NotificationEvent)
                        .where(NotificationEvent.processed_at.is_(None))) or 0
    return {"deliveries": {k: counts.get(k, 0) for k in ("pending", "sending", "sent", "dead")},
            "sent_24h": sent_24h, "event_backlog": backlog}


def rotate_channel_secrets(db: Session) -> int:
    """Re-encrypt every channel's secrets with the primary (first) key, after a new
    key was put in front of NOTIFICATIONS_ENCRYPTION_KEY. Returns channels updated."""
    n = 0
    for c in db.scalars(select(NotificationChannel).where(NotificationChannel.secret_ciphertext.is_not(None))):
        c.secret_ciphertext = crypto.rotate(c.secret_ciphertext)
        n += 1
    db.commit()
    return n
