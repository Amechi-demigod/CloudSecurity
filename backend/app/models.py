"""ORM models.

The model is deliberately provider-agnostic: every connector (simulated, Azure,
future AWS/GCP/eBPF sensor) normalizes what it sees into `Asset` rows with a
`properties` JSON blob, and the rules engines operate on those normalized
properties.
"""
from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .tenancy import TenantMixin


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


# --- Organisations (multi-tenancy, docs/MULTI_TENANCY.md) ---------------------------

ORG_STATUSES = ("active", "suspended")


class Organization(Base):
    """A customer organisation (tenant). Everything a customer owns carries its
    `organization_id` (app/tenancy.py). The default organisation (id "default")
    holds the data of the original single-organisation installation."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    # URL-safe short name, unique on the platform.
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    contact_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    logo_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # active | suspended (suspended: no sign-in, agent / sensor requests refused, no background jobs)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # Enabled product modules (app/modules.py); NULL = never set = all on.
    modules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Commercial plan and limits, for later (not enforced yet).
    plan: Mapped[str | None] = mapped_column(String(32), nullable=True)
    max_users: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_devices: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # customer | msp (docs/MSP.md). An MSP is a partner company that manages client organisations.
    kind: Mapped[str] = mapped_column(String(16), default="customer", server_default="customer", index=True)
    # Client organisations: the MSP that manages them (set by the platform owner or the MSP only).
    partner_org_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_organizations_partner_org_id"), nullable=True,
        index=True)
    # MSP organisations: most client organisations it may have (NULL = unlimited).
    max_clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Who last changed the status: "platform" | "partner" (NULL = unknown, treated as platform).
    # A client suspended by the platform owner cannot be reactivated by its MSP.
    status_set_by: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    suspended_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # An admin dismissed the console's "Getting started" checklist (app/services/onboarding.py).
    onboarding_dismissed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    onboarding_dismissed_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class OrganizationMembership(TenantMixin, Base):
    """A user's role in an organisation. Version 1 allows one membership per
    user (enforced by the application); the table already supports several."""

    __tablename__ = "organization_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_organization_memberships_org_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | analyst | viewer
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class OrganizationInvitation(TenantMixin, Base):
    """Email invitation to join an organisation (invite-only sign-up). The link
    carries a random single-use token; only its SHA-256 is stored."""

    __tablename__ = "organization_invitations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), index=True)  # normalized
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    invited_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    sent_count: Mapped[int] = mapped_column(Integer, default=0)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    accepted_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IngestToken(TenantMixin, Base):
    """Bearer token a runtime sensor sends to POST /api/runtime/*. Each token
    belongs to one organisation; only HMAC/SHA-256 of it is stored. The legacy
    INGEST_API_TOKEN environment variable keeps working for the default
    organisation."""

    __tablename__ = "ingest_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_prefix: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ConnectorConfig(TenantMixin, Base):
    """Per-organisation cloud connector settings (azure | aws | gcp). Secret
    fields (client secret, access key, service-account key) are stored
    encrypted (Fernet, NOTIFICATIONS_ENCRYPTION_KEY / MFA key, see
    app/connectors/org_config.py). The default organisation falls back to the
    AZURE_* / AWS_* / GCP_* environment variables while it has no row."""

    __tablename__ = "connector_configs"
    __table_args__ = (UniqueConstraint("organization_id", "provider", name="uq_connector_configs_org_provider"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_hints: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class Asset(TenantMixin, Base):
    __tablename__ = "assets"

    # Composite primary key (organization_id, id): the natural id comes from the
    # cloud (ARM resource id, ARN, GCP resource name, sensor host id), and two
    # organisations may well scan the same resource; rows referencing an asset
    # carry the organisation in their foreign key too, so a reference can never
    # point into another organisation.
    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_assets_organization_id"), primary_key=True)
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
    # Cloud resource lifecycle (app/services/cloud_lifecycle.py): consecutive successful scans of its
    # subscription / account / project that did not return it, and when it was marked removed (NULL = active).
    missed_scans: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    removed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


def get_asset(db, asset_id: str | None) -> Asset | None:
    """The asset `asset_id` of the session's organisation (composite primary key)."""
    from .tenancy import require_org

    return db.get(Asset, (require_org(db), asset_id)) if asset_id else None


def get_runtime_event(db, event_id: str | None) -> RuntimeEvent | None:
    from .tenancy import require_org

    return db.get(RuntimeEvent, (require_org(db), event_id)) if event_id else None


# Asset rows other modules add only so their findings have something to point at (network discovery:
# app/network/service.ensure_asset). They are not cloud resources: cloud inventory lists and counts skip them.
NON_CLOUD_SOURCES = ("network",)


class Relationship(TenantMixin, Base):
    """Directed edge between two assets (used for the risk graph / attack paths)."""

    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_id", "target_id", "type", name="uq_relationships_edge"),
        ForeignKeyConstraint(["organization_id", "source_id"], ["assets.organization_id", "assets.id"],
                             ondelete="CASCADE", name="fk_relationships_source_asset"),
        ForeignKeyConstraint(["organization_id", "target_id"], ["assets.organization_id", "assets.id"],
                             ondelete="CASCADE", name="fk_relationships_target_asset"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[str] = mapped_column(String(512), index=True)
    target_id: Mapped[str] = mapped_column(String(512), index=True)
    # contains | uses_identity | has_access | protects | connects_to
    type: Mapped[str] = mapped_column(String(64))
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(32), default="simulated")


class Finding(TenantMixin, Base):
    """A posture (CSPM) finding: one rule failing on one asset."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_id", "asset_id", name="uq_findings_rule_asset"),
        ForeignKeyConstraint(["organization_id", "asset_id"], ["assets.organization_id", "assets.id"],
                             ondelete="CASCADE", name="fk_findings_asset"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(512), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|resolved|suppressed
    # Why a resolved finding was closed: "resource_removed" (its cloud resource no longer exists); NULL = fixed.
    close_reason: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    remediation: Mapped[str] = mapped_column(Text, default="")
    compliance: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(32), default="simulated")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    asset: Mapped[Asset] = relationship(lazy="joined")


class Vulnerability(TenantMixin, Base):
    """A CVE on a package inside a workload (asset), on an endpoint device or on a
    network device (switch, firewall, ...), enriched with runtime context. Exactly
    one of asset_id / device_id / network_device_id is set: cloud workloads and
    sensor-reported Linux hosts are assets, laptops running the endpoint agent are
    devices, scanned switches / routers / firewalls are network devices
    (docs/VULNERABILITIES.md, docs/NETWORK_DISCOVERY.md)."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "asset_id"], ["assets.organization_id", "assets.id"],
                             ondelete="CASCADE", name="fk_vulnerabilities_asset"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    asset_id: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE",
                                                                         name="fk_vulnerabilities_device_id"),
                                                  index=True,
                                                  nullable=True)
    network_device_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("network_devices.id", ondelete="CASCADE", name="fk_vulnerabilities_network_device_id"),
        index=True, nullable=True)
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
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | resolved
    # simulated | nvd (endpoint software matched by CPE) | osv (Linux packages)
    source: Mapped[str] = mapped_column(String(32), default="simulated")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Real matching (app/vulnmatch): CISA KEV listing, FIRST EPSS probability,
    # what matched (CPE product / OSV ecosystem), when it was last confirmed and
    # when it was resolved (software upgraded or removed).
    kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    match_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Devices carry large inventory JSON, so there is no eager relationship to
    # them; readers look device names up in one query (api/vulns.py).
    asset: Mapped[Asset | None] = relationship(lazy="joined")


class AssetPackage(TenantMixin, Base):
    """Installed OS / language package on a Linux host, as reported by the
    runtime sensor's package inventory (POST /api/runtime/packages)."""

    __tablename__ = "asset_packages"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "asset_id"], ["assets.organization_id", "assets.id"],
                             ondelete="CASCADE", name="fk_asset_packages_asset"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(String(512), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(128), default="")
    # OSV ecosystem, e.g. "Debian:12", "Ubuntu:22.04:LTS", "Alpine:v3.20", "Rocky Linux:9", "PyPI"
    ecosystem: Mapped[str] = mapped_column(String(64), default="")
    # Source package (dpkg Source / apk origin / rpm source name); vulnerability feeds key on it.
    source_name: Mapped[str] = mapped_column(String(255), default="")
    kind: Mapped[str] = mapped_column(String(16), default="")  # deb | apk | rpm | python
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class VulnMatchState(TenantMixin, Base):
    """Vulnerability-matching state of one device or asset: a hash of its
    inventory (re-match when it changes), when a match was requested / last
    done, and which software could or could not be checked."""

    __tablename__ = "vuln_match_state"
    __table_args__ = (UniqueConstraint("organization_id", "target_type", "target_id", name="uq_vuln_match_target"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_type: Mapped[str] = mapped_column(String(8))  # device | asset
    target_id: Mapped[str] = mapped_column(String(512))
    inventory_hash: Mapped[str] = mapped_column(String(64), default="")
    requested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    matched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    checked: Mapped[list] = mapped_column(JSON, default=list)
    not_checked: Mapped[list] = mapped_column(JSON, default=list)
    os_info: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class VulnFeedCache(Base):
    """Cached vulnerability-feed responses (NVD per CPE product, OSV records,
    the KEV catalog, EPSS scores) with an expiry, so matching works offline
    from the last good copy and the public APIs are not hammered."""

    __tablename__ = "vuln_feed_cache"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class VulnFeedStatus(Base):
    """Freshness / last error of each feed (nvd, osv, kev, epss), shown on the
    Vulnerabilities page."""

    __tablename__ = "vuln_feed_status"

    feed: Mapped[str] = mapped_column(String(16), primary_key=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    items: Mapped[int | None] = mapped_column(Integer, nullable=True)


class RuntimeEvent(TenantMixin, Base):
    __tablename__ = "runtime_events"

    # Composite primary key: sensors may supply the event id (de-duplication),
    # so ids are only unique within an organisation.
    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_runtime_events_organization_id"), primary_key=True)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    # process_exec | network_connection | file_access | privilege_escalation
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    summary: Mapped[str] = mapped_column(String(512), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # full normalized event payload
    sensor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="simulated")


class AlertEvent(TenantMixin, Base):
    __tablename__ = "alert_events"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "event_id"], ["runtime_events.organization_id", "runtime_events.id"],
                             ondelete="CASCADE", name="fk_alert_events_event"),
    )

    alert_id: Mapped[str] = mapped_column(String(32), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(32), primary_key=True)


class Alert(TenantMixin, Base):
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


class ScanRun(TenantMixin, Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    connector: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|succeeded|failed|skipped
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    assets_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_open: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    message: Mapped[str] = mapped_column(Text, default="")
    # "manual" (Run scan / POST /api/scans) or "scheduled" (app/services/scan_schedule.py).
    # NULL on runs recorded before scheduled scans existed (all manual).
    trigger: Mapped[str | None] = mapped_column(String(16), nullable=True)


class ScanScheduleSettings(TenantMixin, Base):
    """Scheduled-scan overrides made in the console (one row per organisation).
    NULL fields fall back to SCAN_SCHEDULE_ENABLED / SCAN_INTERVAL_HOURS."""

    __tablename__ = "scan_schedule_settings"

    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_scan_schedule_settings_organization_id"), primary_key=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    interval_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(320), default="system")


class DashboardSnapshot(TenantMixin, Base):
    """Daily point-in-time dashboard metrics (open issues, exposed assets, risk
    score, compliance %...), one row per organisation, UTC day and account scope
    ("" = all cloud accounts). Written once a day by the snapshot job and lazily
    on the first dashboard read of a day; the dashboards compare against them for
    their "vs previous period" changes (app/services/dashboards.py)."""

    __tablename__ = "dashboard_snapshots"
    __table_args__ = (UniqueConstraint("organization_id", "day", "account",
                                       name="uq_dashboard_snapshots_org_day_account"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    day: Mapped[date] = mapped_column(Date, index=True)
    # Cloud account scope (subscription / account / project id); "" = all accounts.
    account: Mapped[str] = mapped_column(String(64), default="")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --- Authentication -----------------------------------------------------------
# New tables are created by `Base.metadata.create_all()` on startup and new
# nullable columns by `db._add_missing_columns()` (additive migration).

ROLES = ("viewer", "analyst", "admin")
# password_hash of accounts that have no local password (SSO-only); never a valid Argon2 hash.
UNUSABLE_PASSWORD_PREFIX = "!"  # noqa: S105 (marker, not a password)


class User(Base):
    """A person's account (platform-wide: an email address is unique on the
    platform). Roles are per organisation (`OrganizationMembership`)."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # Always stored normalized (stripped + lower-cased).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Platform owner ("super admin"): manages organisations in the platform
    # console. Separate from organisation roles. Also granted by
    # PLATFORM_ADMIN_EMAILS (app/auth.py:is_platform_admin).
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
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

    # Not columns: the organisation and role the current request acts with, set
    # by the authentication dependencies (app/auth.py) from the membership.
    role = None  # admin | analyst | viewer
    organization_id = None

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
    # The organisation this session acts in (the user's membership at sign-in).
    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE", name="fk_user_sessions_organization_id"),
        index=True)
    # MSP staff only: the client organisation currently worked in (validated on every request:
    # the client must still belong to the staff member's MSP). NULL = acting in `organization_id`.
    acting_org_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="SET NULL", name="fk_user_sessions_acting_org_id"),
        nullable=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped[User] = relationship(lazy="joined")

    # Not a column: the stand-in user a request made through a partner (MSP) acts as
    # (app/auth.py: acting_user); None for ordinary requests.
    acting_user = None

    @property
    def active_organization_id(self) -> str:
        """The organisation requests of this session act in."""
        return self.acting_org_id or self.organization_id


class AuditLog(TenantMixin, Base):
    __tablename__ = "audit_log"

    # Events that cannot be tied to an organisation (sign-in attempts for unknown
    # accounts, rejected enrollments, platform-wide jobs) are recorded in the
    # default organisation's log: the platform operator's (app/auth.py:audit).
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    # login_success | login_failure | login_locked | logout | password_changed | user_created |
    # user_updated | user_deleted | password_reset | finding_updated | alert_updated | scan_started | user_bootstrapped |
    # scan_schedule_updated
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    # Set when MSP staff acted inside this (client) organisation: the MSP's id. Such rows are
    # hidden from the client's own audit-log API (docs/MSP.md).
    via_partner_org_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


# --- Device management (endpoint agent) ------------------------------------------
# Laptops / desktops running our own `cnapp-agent` (Windows, macOS). Agents
# authenticate with a per-device secret (only its SHA-256 is stored) and pull
# allow-listed commands; see docs/DEVICE_MANAGEMENT.md.

DEVICE_OS_FAMILIES = ("windows", "macos", "linux")


class EnrollmentToken(TenantMixin, Base):
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
    # "agent" (endpoint agents) or "collector" (dedicated directory collectors):
    # each enrollment endpoint only accepts its own kind.
    kind: Mapped[str] = mapped_column(String(16), default="agent", server_default="agent")


class Device(TenantMixin, Base):
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
    # Device tracking: the newest device_locations row (docs/DEVICE_TRACKING.md); no foreign key on purpose (the
    # history is pruned independently and the link is cleared first).
    location_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
    # Lost mode (docs/DEVICE_MANAGEMENT.md#lost-mode): enabling | active |
    # disabling | None. Set when an admin queues enable/disable_lost_mode and
    # confirmed by the command result and by the state the agent reports.
    lost_mode_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    lost_mode_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    lost_mode_phone: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lost_mode_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lost_mode_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    # Missing-device mode (docs/DEVICE_TRACKING.md#missing-device-mode): the device is missing while missing_since is
    # set and missing_recovered_at is not. The *_label columns hold the display name ("Managed security team" for MSP
    # staff); the baseline is the hardware seen when it was marked, to spot changes later.
    missing_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    missing_by_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    missing_by_label: Mapped[str | None] = mapped_column(String(320), nullable=True)
    missing_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    missing_previous_check_in_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    missing_recovered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    missing_recovered_by_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    missing_recovered_by_label: Mapped[str | None] = mapped_column(String(320), nullable=True)
    missing_last_contact_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    missing_baseline: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Remote wipe (Windows only): queued (approved command waiting for the
    # device) | acknowledged (the agent confirmed it is about to wipe) | started
    # (the OS accepted the wipe) | failed | expired | None.
    wipe_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    wipe_status_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    wipe_command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Host isolation: isolating | isolated | restoring | None.
    # Set when an analyst or admin queues isolate_host / restore_host and
    # confirmed by the command result and by the state the agent reports.
    isolation_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    isolation_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    isolation_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    # When the server last offered which release (and the jitter it allowed),
    # so the console can say "offered at ..., starts within ...".
    update_offered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    update_offered_release_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    update_offer_jitter_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # "Update now": offers within a short window after this start without jitter
    # (after update_now_delay_seconds, a small stagger for fleet-wide requests).
    update_now_requested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    update_now_delay_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Optional capabilities the agent advertises (X-CNAPP-Agent-Features), e.g.
    # "check_for_update"; older agents send nothing.
    agent_features: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Directory membership the agent reports (check-in `directory_join`, docs/DIRECTORY_DISCOVERY.md):
    # the full validated document, plus the identifiers directory matching looks up, indexed.
    directory_join: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ad_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ad_computer_sid: Mapped[str | None] = mapped_column(String(184), nullable=True, index=True)
    entra_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Classification (app/device_class.py): workstation | server | domain_controller,
    # reported by the agent (class_source "agent", 1.4.0+) or inferred from the OS
    # name and model ("inferred"); form factor laptop | desktop | server | tablet |
    # other; virtualisation and cloud (instance id from SMBIOS, never IMDS).
    device_class: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    class_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    form_factor: Mapped[str | None] = mapped_column(String(16), nullable=True)
    is_virtual: Mapped[bool | None] = mapped_column(Boolean, nullable=True, index=True)
    hypervisor: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cloud_provider: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cloud_instance_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    # Latest Windows Update report (docs/PATCHING.md); None until an agent 1.4.0+ reports one.
    os_updates: Mapped[DeviceOsUpdates | None] = relationship(lazy="selectin", uselist=False, viewonly=True)


class DeviceCredential(TenantMixin, Base):
    """Per-device secret. Only sha256(secret) is stored; rotated on re-enrollment."""

    __tablename__ = "device_credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    device: Mapped[Device] = relationship(lazy="joined")


class DevicePostureSnapshot(TenantMixin, Base):
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


class DeviceSoftware(TenantMixin, Base):
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
    source: Mapped[str] = mapped_column(String(32), default="")  # registry_hklm64 | applications | dpkg | rpm | ...
    # Linux packages (agents 1.7.0+): OSV ecosystem ("" = OSV has no feed, e.g. Amazon Linux: listed, not
    # matched), source package and (dpkg) source version, which the distribution advisories are keyed on.
    ecosystem: Mapped[str] = mapped_column(String(64), default="")
    source_name: Mapped[str] = mapped_column(String(255), default="")
    source_version: Mapped[str] = mapped_column(String(128), default="")


class DeviceService(TenantMixin, Base):
    """Windows services (latest inventory, agents 1.4.0+): what the console's
    Services tab and the manage_service endpoint action work from."""

    __tablename__ = "device_services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(256))
    display_name: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="")  # running | stopped | ...
    start_type: Mapped[str] = mapped_column(String(16), default="")  # auto | auto_delayed | manual | disabled | ...


class DeviceCommand(TenantMixin, Base):
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
    # run_script: the script's exit code. Commands created from a two-person
    # approval reference it (and record who approved).
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # isolate_host / restore_host only (schemas_devices.validate_result_data):
    # pre-flight findings and crash-recovery outcomes reported with the result.
    result_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    approved_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceApproval(TenantMixin, Base):
    """Two-person ("maker-checker") approval of a high-risk device action
    (remote wipe, medium/high-risk script). The action only becomes a
    DeviceCommand once a different admin approves (or, when self-approval is
    enabled on a single-admin install, after a cooling-off delay)."""

    __tablename__ = "device_approvals"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(32))  # wipe_device | run_script
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[str] = mapped_column(String(500), default="")
    risk: Mapped[str] = mapped_column(String(16), default="high")
    reason: Mapped[str] = mapped_column(Text, default="")
    # pending -> approved (cooling-off, self-approval only) -> executed ;
    # or rejected | cancelled | expired | failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    requested_by_id: Mapped[str] = mapped_column(String(32))
    requested_by_email: Mapped[str] = mapped_column(String(320))
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    decided_by_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decided_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    self_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    execute_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class DeviceScriptBundle(Base):
    """A signed bundle of reviewed device scripts (docs/DEVICE_SCRIPTS.md). The
    manifest envelope is stored verbatim; agents verify its Ed25519 signature
    with the script-signing keys compiled into them, right before running."""

    __tablename__ = "device_script_bundles"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    version: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    manifest_envelope: Mapped[str] = mapped_column(Text)
    manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    key_id: Mapped[str] = mapped_column(String(64))
    released_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    notes: Mapped[str] = mapped_column(Text, default="")
    bundle_sha256: Mapped[str] = mapped_column(String(64))
    imported_by: Mapped[str] = mapped_column(String(320))
    imported_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    scripts: Mapped[list[DeviceScript]] = relationship(
        back_populates="bundle", cascade="all, delete-orphan", passive_deletes=True, order_by="DeviceScript.name")


class DeviceScript(Base):
    """One script of a signed bundle (content kept for agents to download)."""

    __tablename__ = "device_scripts"
    __table_args__ = (UniqueConstraint("bundle_id", "name", name="uq_device_script_bundle_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    bundle_id: Mapped[str] = mapped_column(String(32), ForeignKey("device_script_bundles.id", ondelete="CASCADE"),
                                           index=True)
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(1000), default="")
    platform: Mapped[str] = mapped_column(String(16))  # windows | macos
    interpreter: Mapped[str] = mapped_column(String(16))  # powershell | zsh | bash
    risk: Mapped[str] = mapped_column(String(16))  # low | medium | high
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    file: Mapped[str] = mapped_column(String(128))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    content: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)

    bundle: Mapped[DeviceScriptBundle] = relationship(back_populates="scripts")


class DeviceLogBundle(TenantMixin, Base):
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


class DeviceOsUpdates(TenantMixin, Base):
    """Missing OS updates of one device (docs/PATCHING.md): the latest report
    of the agent's Windows Update search, replaced on every report. Read-only:
    nothing here installs anything. The per-update list is deferred so fleet
    views (health, Devices list, dashboard) only load the summary columns."""

    __tablename__ = "device_os_updates"

    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    # First and latest report received.
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reported_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # When the agent ran the search, how it ended (ok | failed) and why it failed.
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_status: Mapped[str] = mapped_column(String(16), default="ok")
    scan_error: Mapped[str] = mapped_column(String(1024), default="")
    scan_trigger: Mapped[str] = mapped_column(String(16), default="schedule")  # schedule | command
    scan_duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Last search that succeeded (ours or Windows' own, whichever is later).
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_install_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # When the search that produced the stored update list ran (None: no search succeeded yet,
    # so the list and counts below are unknown rather than "nothing missing").
    listed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Configured update source: wsus | wufb | microsoft_update | windows_update | unknown.
    source: Mapped[str] = mapped_column(String(24), default="unknown")
    source_detail: Mapped[str] = mapped_column(String(255), default="")
    # Windows Update service (wuauserv): state and start type as reported.
    service_state: Mapped[str] = mapped_column(String(24), default="")
    service_start_type: Mapped[str] = mapped_column(String(24), default="")
    reboot_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    # First report that said a restart is pending (cleared when none is).
    reboot_pending_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    missing_count: Mapped[int] = mapped_column(Integer, default=0)
    # Security / critical classification, and MSRC severity Critical.
    security_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    oldest_security_release: Mapped[date | None] = mapped_column(Date, nullable=True)
    oldest_critical_release: Mapped[date | None] = mapped_column(Date, nullable=True)
    updates: Mapped[list] = mapped_column(JSON, default=list, deferred=True)


REMOTE_SESSION_OPEN_STATES = ("requested", "awaiting_consent", "active")


class RemoteSession(TenantMixin, Base):
    """Attended remote desktop session (docs/DEVICE_MANAGEMENT.md#remote-sessions).
    Only metadata is stored: never frame content or keystrokes."""

    __tablename__ = "remote_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    # Set to device_id while the session is open, NULL once it is over: the unique
    # constraint allows one open session per device (NULLs never collide).
    open_device_id: Mapped[str | None] = mapped_column(String(32), nullable=True, unique=True)
    requested_by_id: Mapped[str] = mapped_column(String(32))
    requested_by_email: Mapped[str] = mapped_column(String(320))
    requested_by_name: Mapped[str] = mapped_column(String(255), default="")
    requester_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mode: Mapped[str] = mapped_column(String(16))  # view | control
    reason: Mapped[str] = mapped_column(Text, default="")
    # requested -> awaiting_consent -> active -> ended ; or denied | failed
    state: Mapped[str] = mapped_column(String(24), default="requested", index=True)
    end_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # sha256 of the single-use agent token (minted when the command is delivered).
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    token_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    agent_connected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    consent_deadline_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    consented_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    relay_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    bytes_to_viewer: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_to_agent: Mapped[int] = mapped_column(BigInteger, default=0)


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
    packages: Mapped[list[AgentReleasePackage]] = relationship(
        back_populates="release", cascade="all, delete-orphan", passive_deletes=True,
        order_by="(AgentReleasePackage.format, AgentReleasePackage.arch)")


class AgentReleaseArtifact(Base):
    """One platform binary of a release (bytes are only loaded when served)."""

    __tablename__ = "agent_release_artifacts"
    __table_args__ = (UniqueConstraint("release_id", "os", "arch", name="uq_agent_release_artifact_platform"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    release_id: Mapped[str] = mapped_column(String(32), ForeignKey("agent_releases.id", ondelete="CASCADE"), index=True)
    os: Mapped[str] = mapped_column(String(16))  # GOOS: windows | darwin | linux
    arch: Mapped[str] = mapped_column(String(16))  # GOARCH: amd64 | arm64
    name: Mapped[str] = mapped_column(String(128))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)

    release: Mapped[AgentRelease] = relationship(back_populates="artifacts")


class AgentReleasePackage(Base):
    """An installer package (.deb / .rpm, amd64 / arm64) of a signed release. Its name, SHA-256 and size are in
    the signed manifest (`packages`); the bytes are only loaded when an admin downloads the package."""

    __tablename__ = "agent_release_packages"
    __table_args__ = (UniqueConstraint("release_id", "format", "arch", name="uq_agent_release_package"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    release_id: Mapped[str] = mapped_column(String(32), ForeignKey("agent_releases.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(8))  # deb | rpm
    arch: Mapped[str] = mapped_column(String(16))  # amd64 | arm64
    name: Mapped[str] = mapped_column(String(128))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)

    release: Mapped[AgentRelease] = relationship(back_populates="packages")


class AgentUpdateRing(TenantMixin, Base):
    """Rollout ring: devices (by explicit assignment or device group) and the
    release they should run, with a percentage rollout and pause switch.
    Rings are evaluated by `position`; the default ring catches the rest."""

    __tablename__ = "agent_update_rings"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_agent_update_rings_org_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64))
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


class AgentUpdateSettings(TenantMixin, Base):
    """Update automation (one row per organisation): the update mode and the
    automatic rollout state of the newest release. The GitHub Releases
    auto-import fields are platform-wide: only the default organisation's row
    is used (releases are shared by every organisation). Nullable auto-import
    fields fall back to the environment defaults."""

    __tablename__ = "agent_update_settings"

    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_agent_update_settings_organization_id"), primary_key=True)
    mode: Mapped[str] = mapped_column(String(16), default="automatic")  # automatic | manual
    soak_hours: Mapped[int] = mapped_column(Integer, default=24)
    auto_import_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    auto_import_repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    auto_import_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Automatic rollout: release being rolled out, stage (pilot | all | paused) and since when.
    auto_release_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    auto_stage: Mapped[str | None] = mapped_column(String(16), nullable=True)
    auto_stage_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    auto_paused_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Last auto-import check: ok | offline | error, message, and the last version
    # that failed verification (not retried / re-notified until a newer one appears).
    import_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    import_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    import_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    import_failed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(320), default="system")


class AgentUpdateEvent(TenantMixin, Base):
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
# Same for the IT asset lifecycle tables (hardware assets, custody, offboarding, certificates)
# directory discovery (docs/DIRECTORY_DISCOVERY.md) and compliance reports (docs/COMPLIANCE.md).
from .asset_lifecycle import models as _asset_lifecycle_models  # noqa: E402, F401
from .compliance import models as _compliance_models  # noqa: E402, F401
from .directory import models as _directory_models  # noqa: E402, F401
from .executive import models as _executive_models  # noqa: E402, F401
from .network import models as _network_models  # noqa: E402, F401
from .notifications import models as _notification_models  # noqa: E402, F401
from .tracking import models as _tracking_models  # noqa: E402, F401

# --- Attack surface & pre-ASV (app/external, docs/ATTACK_SURFACE.md) ---------------------------

class ExternalTarget(TenantMixin, Base):
    """A domain, public IPv4 address or CIDR (at most /24) to scan from the internet. Never scanned until
    `scannable` (verified domain / resolves to a verified domain / cloud inventory IP / approved by a platform owner)."""

    __tablename__ = "external_targets"
    __table_args__ = (UniqueConstraint("organization_id", "value", name="uq_external_targets_org_value"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(8))  # domain | ip | cidr
    value: Mapped[str] = mapped_column(String(255))
    token: Mapped[str] = mapped_column(String(64))  # sentrigis-verification=<token>
    # domain: dns | http | None.  ip/cidr: domain | cloud | platform | None
    verified_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_check_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Platform-owner approval of an IP / CIDR the customer cannot prove another way.
    attested_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    attested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attestation: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    approval_status: Mapped[str] = mapped_column(String(12), default="none")  # none|requested|approved|rejected
    approval_note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Opt-in vendor-default credential checks (consent is audit-logged).
    default_password_checks: Mapped[bool] = mapped_column(Boolean, default=False)
    consent_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    consent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Optional scan window (UTC hours 0-23; start == end or None = any time).
    window_start_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_end_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ExternalSettings(TenantMixin, Base):
    """Per organisation: scope declaration and schedule."""

    __tablename__ = "external_settings"

    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_external_settings_organization_id"), primary_key=True)
    scope_text: Mapped[str] = mapped_column(Text, default="")
    scope_confirmed_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    scope_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    schedule_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_hours: Mapped[float] = mapped_column(Float, default=168.0)  # weekly
    next_finding_seq: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DashboardLayout(TenantMixin, Base):
    """Per organisation: the Overview dashboard's widget layout (order, hidden widgets, widths),
    chosen by an admin and shown to everyone in the organisation (app/services/dashboard_layout.py)."""

    __tablename__ = "dashboard_layouts"

    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_dashboard_layouts_organization_id"), primary_key=True)
    layout: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class TablePreference(TenantMixin, Base):
    """One user's view of one console table (column widths, hidden columns, density), per organisation."""

    __tablename__ = "table_preferences"
    __table_args__ = (UniqueConstraint("user_id", "organization_id", "table_id", name="uq_table_preferences_user_org_table"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    table_id: Mapped[str] = mapped_column(String(64))
    prefs: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ExternalScan(TenantMixin, Base):
    __tablename__ = "external_scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    trigger: Mapped[str] = mapped_column(String(12), default="manual")  # manual | scheduled | retest | target
    status: Mapped[str] = mapped_column(String(12), default="running")  # running|succeeded|failed|partial
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    started_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    scanner_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)  # no longer recorded or shown
    hosts: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    new_hosts: Mapped[int] = mapped_column(Integer, default=0)
    findings_open: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str | None] = mapped_column(String(8), nullable=True)  # pass | fail
    targets: Mapped[list] = mapped_column(JSON, default=list)  # values scanned
    skipped: Mapped[list] = mapped_column(JSON, default=list)  # [{value, reason}]
    message: Mapped[str] = mapped_column(Text, default="")


class ExternalHost(TenantMixin, Base):
    __tablename__ = "external_hosts"
    __table_args__ = (UniqueConstraint("organization_id", "host", name="uq_external_hosts_org_host"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    host: Mapped[str] = mapped_column(String(255))  # name or IP as discovered
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dns: Mapped[dict] = mapped_column(JSON, default=dict)
    ports: Mapped[list] = mapped_column(JSON, default=list)  # [{port, service, product, version, banner}]
    tls: Mapped[dict] = mapped_column(JSON, default=dict)
    software: Mapped[list] = mapped_column(JSON, default=list)
    asset_id: Mapped[str | None] = mapped_column(String(512), nullable=True)  # linked cloud asset
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ExternalFinding(TenantMixin, Base):
    __tablename__ = "external_findings"
    __table_args__ = (UniqueConstraint("organization_id", "seq", name="uq_external_findings_org_seq"),
                      UniqueConstraint("organization_id", "key", name="uq_external_findings_org_key"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer)  # EXT-0001 per organisation
    key: Mapped[str] = mapped_column(String(400))  # check | host | port | path (one finding per key)
    check_id: Mapped[str] = mapped_column(String(48), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(12), index=True)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    vector: Mapped[str | None] = mapped_column(String(80), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # description, impact, steps, fix, references, compliance
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # headers only, never secrets / file contents
    auto_fail: Mapped[bool] = mapped_column(Boolean, default=False)
    dos_only: Mapped[bool] = mapped_column(Boolean, default=False)
    special_note: Mapped[str | None] = mapped_column(String(24), nullable=True)  # Part 3b category
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|resolved|accepted|disputed
    status_note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    status_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ExternalDispute(TenantMixin, Base):
    __tablename__ = "external_disputes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(String(32), ForeignKey("external_findings.id", ondelete="CASCADE"),
                                            index=True)
    kind: Mapped[str] = mapped_column(String(24))  # false_positive | compensating_control
    reason: Mapped[str] = mapped_column(Text)
    submitted_by: Mapped[str] = mapped_column(String(320))
    submitted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)  # pending|accepted|rejected
    reviewed_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    review_note: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class ExternalReport(TenantMixin, Base):
    """A generated pre-ASV report (snapshot of the data; the PDF is rendered on download)."""

    __tablename__ = "external_reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    generated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    result: Mapped[str] = mapped_column(String(8))
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class ReputationRun(TenantMixin, Base):
    """One run of the reputation checks over one or more verified domains (app/external/reputation)."""

    __tablename__ = "reputation_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    trigger: Mapped[str] = mapped_column(String(12), default="manual")  # manual | scheduled
    status: Mapped[str] = mapped_column(String(12), default="running")  # running | succeeded | partial | failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    started_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    domains: Mapped[list] = mapped_column(JSON, default=list)
    findings_open: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")


class ReputationDomain(TenantMixin, Base):
    """Latest reputation summary of one verified domain: grade, counts and the data behind them."""

    __tablename__ = "reputation_domains"
    __table_args__ = (UniqueConstraint("organization_id", "domain", name="uq_reputation_domains_org_domain"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    domain: Mapped[str] = mapped_column(String(255))
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0-100
    grade: Mapped[str | None] = mapped_column(String(2), nullable=True)  # A-F
    counts: Mapped[dict] = mapped_column(JSON, default=dict)  # open findings by severity
    details: Mapped[dict] = mapped_column(JSON, default=dict)  # email, lookalikes, certificates, blocklists
    known_issuers: Mapped[dict] = mapped_column(JSON, default=dict)  # certificate issuer -> first seen (ISO date)
    last_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ReputationFinding(TenantMixin, Base):
    """Same lifecycle as ExternalFinding: open, resolved automatically when a later run no longer sees it, accepted."""

    __tablename__ = "reputation_findings"
    __table_args__ = (UniqueConstraint("organization_id", "seq", name="uq_reputation_findings_org_seq"),
                      UniqueConstraint("organization_id", "key", name="uq_reputation_findings_org_key"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer)  # REP-0001 per organisation
    key: Mapped[str] = mapped_column(String(400))  # check | domain | subject (one finding per key)
    check_id: Mapped[str] = mapped_column(String(48), index=True)
    category: Mapped[str] = mapped_column(String(16), index=True)  # email | lookalike | blocklist | certificate
    domain: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(12), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # description, fix
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open | resolved | accepted
    status_note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    status_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
