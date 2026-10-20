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
    BigInteger,
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
# password_hash of accounts that have no local password (SSO-only); never a valid Argon2 hash.
UNUSABLE_PASSWORD_PREFIX = "!"  # noqa: S105 (marker, not a password)


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

    # MFA / SSO (Phase 4). Loaded lazily: only the auth endpoints touch them.
    mfa: Mapped[UserMfa | None] = relationship(back_populates="user", uselist=False, cascade="all, delete-orphan",
                                               passive_deletes=True)
    identities: Mapped[list[UserIdentity]] = relationship(back_populates="user", cascade="all, delete-orphan",
                                                          passive_deletes=True)

    @property
    def mfa_enabled(self) -> bool:
        return self.mfa is not None and self.mfa.enabled_at is not None

    @property
    def has_password(self) -> bool:
        """False for accounts created by SSO just-in-time provisioning."""
        return bool(self.password_hash) and not self.password_hash.startswith(UNUSABLE_PASSWORD_PREFIX)

    @property
    def auth_sources(self) -> list[str]:
        sources = ["password"] if self.has_password else []
        return sources + sorted({i.provider for i in self.identities})


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
    # Set when the token was minted for a downloadable installer ("windows-msi" |
    # "macos-pkg"): its plaintext only exists inside that file.
    package_platform: Mapped[str | None] = mapped_column(String(16), nullable=True)
    package_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Group label applied to devices enrolling with this token.
    device_group: Mapped[str | None] = mapped_column(String(64), nullable=True)


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
    device_group: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
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
    # Agent auto-update: explicit ring membership (else by device_group / the
    # default ring), a pinned release (overrides the ring) and the last status
    # the agent reported (downloading, verified, installing, installed,
    # rolled_back, failed, rejected).
    update_ring_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    update_pinned_release_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    update_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    update_status_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    update_status_detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    update_status_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


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


# --- Agent auto-update -------------------------------------------------------------

class AgentRelease(Base):
    """A signed agent release imported by an admin (bundle = signed manifest +
    binaries). The manifest envelope is stored verbatim: agents verify its
    Ed25519 signature themselves with the keys compiled into them."""

    __tablename__ = "agent_releases"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    version: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    manifest_envelope: Mapped[str] = mapped_column(Text)
    manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    key_id: Mapped[str] = mapped_column(String(64))
    released_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    min_supported_version: Mapped[str] = mapped_column(String(64), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    bundle_sha256: Mapped[str] = mapped_column(String(64))
    imported_by: Mapped[str] = mapped_column(String(320))
    imported_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    withdrawn_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    artifacts: Mapped[list[AgentReleaseArtifact]] = relationship(
        back_populates="release", cascade="all, delete-orphan", passive_deletes=True, order_by="AgentReleaseArtifact.os")


class AgentReleaseArtifact(Base):
    """One platform binary of a release (bytes are only loaded when served)."""

    __tablename__ = "agent_release_artifacts"
    __table_args__ = (UniqueConstraint("release_id", "os", "arch", name="uq_agent_release_artifact_platform"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    release_id: Mapped[str] = mapped_column(String(32), ForeignKey("agent_releases.id", ondelete="CASCADE"), index=True)
    os: Mapped[str] = mapped_column(String(16))  # GOOS: windows | darwin
    arch: Mapped[str] = mapped_column(String(16))  # GOARCH: amd64 | arm64
    name: Mapped[str] = mapped_column(String(128))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)

    release: Mapped[AgentRelease] = relationship(back_populates="artifacts")


class AgentUpdateRing(Base):
    """Rollout ring: devices (by explicit assignment or device group) and the
    release they should run, with a percentage rollout and pause switch.
    Rings are evaluated by `position`; the default ring catches the rest."""

    __tablename__ = "agent_update_rings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    position: Mapped[int] = mapped_column(Integer, default=100)
    device_groups: Mapped[list] = mapped_column(JSON, default=list)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    target_release_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("agent_releases.id", ondelete="SET NULL"), nullable=True)
    rollout_percent: Mapped[int] = mapped_column(Integer, default=100)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(320), default="system")


class AgentUpdateEvent(Base):
    """Update status history reported by agents."""

    __tablename__ = "agent_update_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    release_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    from_version: Mapped[str] = mapped_column(String(64), default="")
    to_version: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


# --- MFA (TOTP) and single sign-on --------------------------------------------------

class UserMfa(Base):
    """TOTP state of one user. The shared secret is encrypted (Fernet, key from
    MFA_ENCRYPTION_KEY); `last_used_step` blocks reuse of a code within its window."""

    __tablename__ = "user_mfa"

    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    # Encrypted secret of the active authenticator (None until enrolment is confirmed).
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Encrypted secret being enrolled (set by /setup, moved to totp_secret_enc by /enable).
    pending_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    pending_created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    user: Mapped[User] = relationship(back_populates="mfa")


class MfaRecoveryCode(Base):
    """Single-use recovery code; only SHA-256 of the (80-bit random) code is stored."""

    __tablename__ = "mfa_recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MfaChallenge(Base):
    """Short-lived token between a successful first factor (password or SSO) and
    the second step (TOTP / recovery code, or forced enrolment). Only an HMAC of
    the token is stored; it never grants API access by itself."""

    __tablename__ = "mfa_challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))  # verify | enroll
    method: Mapped[str] = mapped_column(String(16), default="password")  # first factor: password | entra
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    pending_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # forced enrolment
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship(lazy="joined")


class UserIdentity(Base):
    """Link between a local user and an external identity (Entra ID: tenant + object id)."""

    __tablename__ = "user_identities"
    __table_args__ = (UniqueConstraint("provider", "tenant_id", "subject"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))  # entra
    tenant_id: Mapped[str] = mapped_column(String(64))
    subject: Mapped[str] = mapped_column(String(128))  # Entra object id (oid)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="identities")


class OidcAuthRequest(Base):
    """In-flight OIDC authorization request (state, nonce, PKCE verifier), bound to
    the browser that started it and deleted when the callback consumes it."""

    __tablename__ = "oidc_auth_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # HMAC of `state`
    browser_binding: Mapped[str] = mapped_column(String(64))  # HMAC of the binding cookie
    nonce: Mapped[str] = mapped_column(String(128))
    code_verifier: Mapped[str] = mapped_column(String(128))
    return_to: Mapped[str] = mapped_column(String(512), default="/")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


# Notification tables live in their own module; import them so they are part of
# Base.metadata (create_all on SQLite, Alembic autogenerate / schema checks).
# Same for the IT asset lifecycle tables (hardware assets, custody, offboarding, certificates).
from .asset_lifecycle import models as _asset_lifecycle_models  # noqa: E402, F401
from .notifications import models as _notification_models  # noqa: E402, F401
