"""ORM models.

The model is deliberately provider-agnostic: every connector (simulated, Azure,
future AWS/GCP/eBPF sensor) normalizes what it sees into `Asset` rows with a
`properties` JSON blob, and the rules engines operate on those normalized
properties.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class Asset(Base):
    __tablename__ = "assets"

    # For Azure this is the full ARM resource id (lower-cased).
    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    # Normalized type: vm, storage_account, aks_cluster, pod, sql_server, sql_database,
    # nsg, identity, key_vault, function_app, subscription
    type: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(32), default="azure")
    subscription_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    subscription_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_group: Mapped[str | None] = mapped_column(String(255), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(32), default="simulated", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Relationship(Base):
    """Directed edge between two assets (used for the risk graph / attack paths)."""

    __tablename__ = "relationships"
    __table_args__ = (UniqueConstraint("source_id", "target_id", "type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[str] = mapped_column(String(512), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str] = mapped_column(String(512), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    # contains | uses_identity | has_access | protects | connects_to
    type: Mapped[str] = mapped_column(String(64))
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(32), default="simulated")


class Finding(Base):
    """A posture (CSPM) finding: one rule failing on one asset."""

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("rule_id", "asset_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(512), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|resolved|suppressed
    remediation: Mapped[str] = mapped_column(Text, default="")
    compliance: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(32), default="simulated")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    asset: Mapped[Asset] = relationship(lazy="joined")


class Vulnerability(Base):
    """A CVE on a package inside a workload, enriched with runtime context."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(512), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    package: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64))
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    cvss: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16))
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    # Runtime context ------------------------------------------------------
    in_use: Mapped[bool] = mapped_column(Boolean, default=False)  # package loaded at runtime
    # "sensor" when set by a runtime sensor library_loaded event (expires without heartbeat)
    in_use_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    in_use_last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_data_access: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    priority: Mapped[str] = mapped_column(String(16), default="low")
    status: Mapped[str] = mapped_column(String(16), default="open")
    source: Mapped[str] = mapped_column(String(32), default="simulated")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    asset: Mapped[Asset] = relationship(lazy="joined")


class RuntimeEvent(Base):
    __tablename__ = "runtime_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    # process_exec | network_connection | file_access | privilege_escalation
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    summary: Mapped[str] = mapped_column(String(512), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # full normalized event payload
    sensor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="simulated")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[str] = mapped_column(String(32), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("runtime_events.id", ondelete="CASCADE"), primary_key=True
    )


class Alert(Base):
    """A runtime detection (CDR) produced by the detection rules engine."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    mitre_tactic: Mapped[str] = mapped_column(String(64))
    mitre_technique_id: Mapped[str] = mapped_column(String(16))
    mitre_technique_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|acknowledged|resolved
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    connector: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|succeeded|failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    assets_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_open: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    message: Mapped[str] = mapped_column(Text, default="")


# --- Authentication -----------------------------------------------------------
# New tables are created by `Base.metadata.create_all()` on startup and new
# nullable columns by `db._add_missing_columns()` (additive migration).

ROLES = ("viewer", "analyst", "admin")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # Always stored normalized (stripped + lower-cased).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class UserSession(Base):
    """Server-side login session. Only a SHA-256 of the cookie token is stored."""

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256(token) hex
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped[User] = relationship(lazy="joined")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    # login_success | login_failure | login_locked | logout | password_changed | user_created |
    # user_updated | password_reset | finding_updated | alert_updated | scan_started | user_bootstrapped
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


# Notification tables live in their own module; import them so they are part of
# Base.metadata (create_all on SQLite, Alembic autogenerate / schema checks).
from .notifications import models as _notification_models  # noqa: E402, F401
