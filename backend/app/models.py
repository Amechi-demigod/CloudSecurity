"""ORM models.

The model is deliberately provider-agnostic: every connector (simulated, Azure,
future AWS/GCP/eBPF sensor) normalizes what it sees into `Asset` rows with a
`properties` JSON blob, and the rules engines operate on those normalized
properties.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
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


# --- Device management (endpoint agent) ------------------------------------------
# Laptops / desktops running our own `cnapp-agent` (Windows, macOS). Agents
# authenticate with a per-device secret (only its SHA-256 is stored) and pull
# allow-listed commands; see docs/DEVICE_MANAGEMENT.md.

DEVICE_OS_FAMILIES = ("windows", "macos", "linux")


class EnrollmentToken(Base):
    """Admin-issued secret an agent exchanges for a per-device credential."""

    __tablename__ = "enrollment_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256(token) hex
    token_prefix: Mapped[str] = mapped_column(String(16))  # shown in the UI to tell tokens apart
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = unlimited until expiry
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (Index("ix_devices_os_machine", "os_family", "machine_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    os_family: Mapped[str] = mapped_column(String(16), index=True)  # windows | macos | linux
    os_name: Mapped[str] = mapped_column(String(128), default="")
    os_version: Mapped[str] = mapped_column(String(64), default="")
    os_build: Mapped[str] = mapped_column(String(64), default="")
    architecture: Mapped[str] = mapped_column(String(32), default="")
    serial_number: Mapped[str] = mapped_column(String(128), default="")
    manufacturer: Mapped[str] = mapped_column(String(128), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    # SHA-256 of the OS machine identifier (MachineGuid / IOPlatformUUID); used to
    # recognise a re-enrolling machine.
    machine_id: Mapped[str] = mapped_column(String(64), default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)  # active | revoked
    enrolled_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    enrollment_token_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_checkin_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    check_in_interval_seconds: Mapped[int] = mapped_column(Integer, default=900)
    # Latest full inventory (hardware/OS/network/users) and posture checks, as sent by the agent.
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    posture: Mapped[dict] = mapped_column(JSON, default=dict)
    collection_errors: Mapped[dict] = mapped_column(JSON, default=dict)
    software_count: Mapped[int] = mapped_column(Integer, default=0)
    # First check-in that reported pending OS updates (cleared when none are pending).
    updates_pending_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceCredential(Base):
    """Per-device secret. Only sha256(secret) is stored; rotated on re-enrollment."""

    __tablename__ = "device_credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    device: Mapped[Device] = relationship(lazy="joined")


class DevicePostureSnapshot(Base):
    """One row per check-in (history); the latest values are also on `devices`."""

    __tablename__ = "device_posture_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    os_version: Mapped[str] = mapped_column(String(64), default="")
    posture: Mapped[dict] = mapped_column(JSON, default=dict)
    issues: Mapped[list] = mapped_column(JSON, default=list)  # issue codes at that time
    software_count: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DeviceSoftware(Base):
    """Installed software (latest inventory). Kept with versions so that
    vulnerable-software matching can be added later."""

    __tablename__ = "device_software"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(128), default="")
    publisher: Mapped[str] = mapped_column(String(255), default="")
    identifier: Mapped[str] = mapped_column(String(255), default="")  # bundle id / registry key
    install_date: Mapped[str] = mapped_column(String(32), default="")
    source: Mapped[str] = mapped_column(String(32), default="")  # registry_hklm64 | applications | ...


class DeviceCommand(Base):
    """Allow-listed remote action, pulled by the agent and executed at most once."""

    __tablename__ = "device_commands"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    nonce: Mapped[str] = mapped_column(String(64))
    # pending -> delivered -> succeeded | failed | rejected ; or expired | cancelled
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    requested_by_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    requested_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    output: Mapped[str] = mapped_column(Text, default="")
    log_bundle_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class DeviceLogBundle(Base):
    """Agent log bundle uploaded for a collect_logs command (size-capped, gzip tar)."""

    __tablename__ = "device_log_bundles"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    content_type: Mapped[str] = mapped_column(String(64), default="application/gzip")
    data: Mapped[bytes] = mapped_column(LargeBinary)
