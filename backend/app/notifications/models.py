"""Notification tables: channels, rules, the event inbox, the delivery outbox,
throttle state, digest queue and pull-source state.

Flow:  domain code --emit()--> notification_events (same transaction as the
alert/finding, so nothing is lost)  --worker (leader only)--> rule matching,
dedup/throttle --> notification_deliveries (outbox) --worker--> channel.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    # teams | slack | email | webhook
    type: Mapped[str] = mapped_column(String(16), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Non-secret settings (SMTP host/port/from/to, ACS sender, ...).
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    # Fernet token of a JSON object with the secret fields. Never returned by the API.
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Masked preview per secret field, e.g. {"webhook_url": "https://hooks.slack.com/••••••"}.
    secret_hints: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_test_status: Mapped[str | None] = mapped_column(String(16), nullable=True)


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Matching (empty list = any). Severity is a threshold (>=).
    sources: Mapped[list] = mapped_column(JSON, default=list)
    event_types: Mapped[list] = mapped_column(JSON, default=list)
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    subscription_ids: Mapped[list] = mapped_column(JSON, default=list)
    asset_ids: Mapped[list] = mapped_column(JSON, default=list)
    asset_types: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)  # all key=value pairs must match
    rule_ids: Mapped[list] = mapped_column(JSON, default=list)  # detection / posture rule ids
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)  # T1059 also matches T1059.004
    include_status_changes: Mapped[bool] = mapped_column(Boolean, default=False)
    # Routing
    channel_ids: Mapped[list] = mapped_column(JSON, default=list)
    # Same group (e.g. one detection rule on one asset) at most once per N minutes (0 = no throttling).
    throttle_minutes: Mapped[int] = mapped_column(Integer, default=60)
    # immediate | digest (one daily summary per channel at digest_hour, rule time zone)
    mode: Mapped[str] = mapped_column(String(16), default="immediate")
    digest_hour: Mapped[int] = mapped_column(Integer, default=8)
    # IANA time zone for quiet hours and the digest hour.
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    # Optional quiet hours ("HH:MM", local time): deliveries are held until the
    # window ends, unless severity >= quiet_bypass_severity.
    quiet_start: Mapped[str | None] = mapped_column(String(5), nullable=True)
    quiet_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    quiet_bypass_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_digest_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NotificationEvent(Base):
    """Inbox: one row per notifiable event, written in the producer's transaction."""

    __tablename__ = "notification_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    # runtime_alert | posture_finding | vulnerability | attack_path | scan | <future sources, e.g. device>
    source: Mapped[str] = mapped_column(String(32), index=True)
    # created | status_changed | completed | failed | ...
    event_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text, default="")
    entity_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Dedup / throttle group, e.g. "runtime_alert:<rule>:<asset>".
    group_key: Mapped[str] = mapped_column(String(255))
    asset_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Deep link path in the web UI, e.g. "/threats?alert=<id>".
    link_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


class NotificationDelivery(Base):
    """Outbox + delivery log: one message to one channel."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_notification_deliveries_due", "status", "next_attempt_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    channel_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("notification_channels.id", ondelete="SET NULL"), nullable=True, index=True)
    channel_name: Mapped[str] = mapped_column(String(128), default="")
    channel_type: Mapped[str] = mapped_column(String(16), default="")
    rule_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(128), default="")
    event_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # event | digest | test
    kind: Mapped[str] = mapped_column(String(16), default="event")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    title: Mapped[str] = mapped_column(String(255), default="")
    # The channel-neutral message (rendered per channel at send time).
    message: Mapped[dict] = mapped_column(JSON, default=dict)
    # pending | sending | sent | dead
    status: Mapped[str] = mapped_column(String(16), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Secrets are redacted before this is stored.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class NotificationThrottle(Base):
    """When a (rule, channel, group) was last notified, and how much was suppressed since."""

    __tablename__ = "notification_throttle"
    __table_args__ = (UniqueConstraint("rule_id", "channel_id", "group_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(32), ForeignKey("notification_rules.id", ondelete="CASCADE"))
    channel_id: Mapped[str] = mapped_column(String(32), ForeignKey("notification_channels.id", ondelete="CASCADE"))
    group_key: Mapped[str] = mapped_column(String(255))
    last_sent_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    suppressed: Mapped[int] = mapped_column(Integer, default=0)


class NotificationDigestItem(Base):
    """Events waiting for a rule's next daily digest."""

    __tablename__ = "notification_digest_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("notification_rules.id", ondelete="CASCADE"), index=True)
    channel_id: Mapped[str] = mapped_column(String(32), ForeignKey("notification_channels.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32))
    link_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class NotificationSourceState(Base):
    """Bookkeeping for pull-based event sources (e.g. the attack-path poller)."""

    __tablename__ = "notification_source_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    state: Mapped[dict] = mapped_column(JSON, default=dict)
