"""Directory discovery tables (docs/DIRECTORY_DISCOVERY.md).

* `directory_sources`: one configured directory per row: on-prem Active
  Directory ("ad", read by an enrolled collector agent) or a cloud directory
  read by the server itself ("entra": Microsoft Entra ID + Intune through
  Microsoft Graph; "google": Google Workspace). Credentials (an AD service
  account, a Google service-account key) are stored Fernet-encrypted in
  `secret_ciphertext` and never returned by the API; an Entra source only
  references one of the organisation's Azure connectors (no copy of its secret).
* `directory_sync_runs`: one row per sync (scheduled, manual or test), the
  collector it ran on, its single-use upload token (SHA-256 only) and counts.
* `directory_computers` / `directory_users`: the objects a source returned,
  keyed by their stable provider id (`external_id`: objectGUID for AD, the
  Entra object id, "mdm:<Intune id>", ...) per source. A computer row is one
  device record of one kind (`device_kind`); the records of one physical
  machine (AD computer, Entra device, Intune device...) share a `machine_id`
  (directory/matching.py). Objects a complete run no longer returns get
  `missing_since` (they are purged later, never on the spot).
* `directory_findings`: materialised "discovery issues" (not managed, stale,
  disabled but active, ...), recomputed after each sync and periodically.

These are not the IT asset (`it_assets`) or agent device (`devices`) tables:
computers are linked to them by the matcher (directory/matching.py) and only
become IT assets when an admin adds them.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin

SOURCE_TYPES = ("ad", "entra", "google")  # future: "okta"
# Read by the server itself, no collector agent (docs/DIRECTORY_DISCOVERY.md#server-side-collection).
CLOUD_TYPES = ("entra", "google")
RUN_TRIGGERS = ("scheduled", "manual", "test")
RUN_ACTIVE = ("queued", "running")
RUN_FINAL = ("succeeded", "failed", "cancelled")
MATCH_STATUSES = ("matched", "ambiguous", "unmatched")


class DirectorySource(TenantMixin, Base):
    __tablename__ = "directory_sources"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    type: Mapped[str] = mapped_column(String(16), default="ad")
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Provider settings (AD: domain, servers, port, security, base_dns, scopes,
    # stale_days, interval_hours, auth, ca_pem). Never contains secrets.
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    # Fernet token of {"username", "password"} (service-account auth only).
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_hint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Ordered: the scheduler uses the first healthy collector, then fails over.
    collector_device_ids: Mapped[list] = mapped_column(JSON, default=list)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    computers_count: Mapped[int] = mapped_column(Integer, default=0)
    users_count: Mapped[int] = mapped_column(Integer, default=0)
    # Cloud sources: outcome of each part of the last finished sync, e.g.
    # {"intune": {"status": "unlicensed", "detail": "..."}} (directory/cloud.py).
    scope_status: Mapped[dict] = mapped_column(JSON, default=dict)
    # Last "not managed" count a notification was sent for (no repeats).
    notified_not_managed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class DirectorySyncRun(TenantMixin, Base):
    __tablename__ = "directory_sync_runs"
    __table_args__ = (Index("ix_directory_sync_runs_source_queued", "source_id", "queued_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(32), ForeignKey("directory_sources.id", ondelete="CASCADE"),
                                           index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="scheduled")
    # queued -> running -> succeeded | failed ; or cancelled
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    device_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("devices.id", ondelete="SET NULL"),
                                                  nullable=True)
    command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # SHA-256 of the single-use upload token (minted when the command is
    # delivered; cleared when the run ends).
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    # Collectors already tried for this slot (failover never repeats one).
    tried_device_ids: Mapped[list] = mapped_column(JSON, default=list)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    max_objects: Mapped[int] = mapped_column(Integer, default=0)
    queued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_batch_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_seq: Mapped[int] = mapped_column(Integer, default=0)
    computers_seen: Mapped[int] = mapped_column(Integer, default=0)
    users_seen: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    server: Mapped[str | None] = mapped_column(String(253), nullable=True)
    agent_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Test runs: a few object names (nothing else is stored).
    sample: Mapped[list] = mapped_column(JSON, default=list)
    # Cloud test runs: one entry per permission / licence check
    # ({"id", "label", "status": ok|missing|unlicensed|error, "detail", "required"}).
    checks: Mapped[list] = mapped_column(JSON, default=list)
    # Cloud runs: outcome per part (users, devices, intune, roles, sign_in, ...).
    scope_status: Mapped[dict] = mapped_column(JSON, default=dict)


class _DirectoryObject:
    """Columns shared by every directory object kind."""

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # Stable provider id: AD objectGUID (lower-case), Entra object id, ...
    external_id: Mapped[str] = mapped_column(String(64))
    object_sid: Mapped[str | None] = mapped_column(String(184), nullable=True, index=True)
    distinguished_name: Mapped[str] = mapped_column(Text, default="")
    # Lower-case DNS domain derived from the DN (DC=...) and parent container.
    domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    ou: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    user_account_control: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_logon_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    when_created: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    missing_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Provider attributes not modelled as columns.
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)


class DirectoryComputer(_DirectoryObject, TenantMixin, Base):
    __tablename__ = "directory_computers"
    __table_args__ = (UniqueConstraint("source_id", "external_id", name="uq_directory_computers_source_external"),)

    source_id: Mapped[str] = mapped_column(String(32), ForeignKey("directory_sources.id", ondelete="CASCADE"),
                                           index=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    # Lower-case short host name (cn / sAMAccountName without "$") and FQDN: match keys.
    short_name: Mapped[str] = mapped_column(String(256), default="", index=True)
    dns_hostname: Mapped[str] = mapped_column(String(256), default="", index=True)
    sam_account_name: Mapped[str] = mapped_column(String(256), default="")
    serial_number: Mapped[str] = mapped_column(String(128), default="")
    operating_system: Mapped[str] = mapped_column(String(256), default="")
    os_version: Mapped[str] = mapped_column(String(256), default="")
    when_changed: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # ad | entra | intune | endpoint (Google endpoint) | chromeos | mobile
    device_kind: Mapped[str] = mapped_column(String(16), default="ad")
    # Entra device id (deviceId of an Entra device, azureADDeviceId of an Intune
    # device): matched against the entra_device_id agents report.
    cloud_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # windows | macos | linux | ios | android | chromeos | "" (unknown)
    platform: Mapped[str] = mapped_column(String(16), default="")
    # False for devices an agent cannot or should not run on (phones, ChromeOS,
    # personal / registered-only devices): never "no agent", not in coverage.
    agent_expected: Mapped[bool] = mapped_column(Boolean, default=True)
    # workstation | server | domain_controller | None, from the directory itself
    # (app/device_class.py directory_class: AD SERVER_TRUST_ACCOUNT, OS names).
    device_class: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    # Intune complianceState (compliant, noncompliant, inGracePeriod, ...).
    compliance: Mapped[str | None] = mapped_column(String(24), nullable=True)
    encrypted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Lower-case UPN / email of the device's primary user (Intune, Google).
    primary_user: Mapped[str] = mapped_column(String(256), default="", index=True)
    # Representative row of the physical machine this record belongs to (set by
    # the matcher; NULL until the next evaluation = a machine of its own).
    machine_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    # Matcher output (directory/matching.py): the agent device / IT asset this
    # computer is, how it was matched (directory_sid, entra_device_id, serial,
    # fqdn, hostname_domain, hostname) and how sure (0-100); "ambiguous" keeps the candidates instead.
    match_status: Mapped[str] = mapped_column(String(16), default="unmatched", index=True)
    match_method: Mapped[str | None] = mapped_column(String(24), nullable=True)
    match_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    match_candidates: Mapped[list] = mapped_column(JSON, default=list)
    device_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("devices.id", ondelete="SET NULL"),
                                                  nullable=True, index=True)
    # The IT asset of the matched device, or the asset an admin created from
    # this computer ("Add to IT assets").
    it_asset_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("it_assets.id", ondelete="SET NULL"),
                                                    nullable=True, index=True)
    matched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DirectoryUser(_DirectoryObject, TenantMixin, Base):
    __tablename__ = "directory_users"
    __table_args__ = (UniqueConstraint("source_id", "external_id", name="uq_directory_users_source_external"),)

    source_id: Mapped[str] = mapped_column(String(32), ForeignKey("directory_sources.id", ondelete="CASCADE"),
                                           index=True)
    # Lower-case copies are the match keys (sAMAccountName, UPN, mail).
    sam_account_name: Mapped[str] = mapped_column(String(256), default="")
    sam_key: Mapped[str] = mapped_column(String(256), default="", index=True)
    user_principal_name: Mapped[str] = mapped_column(String(256), default="", index=True)
    mail: Mapped[str] = mapped_column(String(256), default="", index=True)
    display_name: Mapped[str] = mapped_column(String(256), default="")
    given_name: Mapped[str] = mapped_column(String(256), default="")
    surname: Mapped[str] = mapped_column(String(256), default="")
    department: Mapped[str] = mapped_column(String(256), default="")
    title: Mapped[str] = mapped_column(String(256), default="")
    manager_dn: Mapped[str] = mapped_column(Text, default="")
    pwd_last_set_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Holds a privileged admin role (an Entra directory role such as Global
    # Administrator, Google Super Admin...); role names kept for display.
    privileged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    privileged_roles: Mapped[list] = mapped_column(JSON, default=list)


FINDING_TYPES = ("not_managed", "stale_computer", "disabled_but_active", "unknown_to_directory",
                 "not_domain_joined", "non_compliant", "not_in_intune", "disabled_user_signed_in",
                 "stale_user_signed_in", "privileged_disabled", "privileged_stale", "privileged_no_agent")
USER_FINDING_TYPES = ("disabled_user_signed_in", "stale_user_signed_in", "privileged_disabled", "privileged_stale",
                      "privileged_no_agent")


class DirectoryFinding(TenantMixin, Base):
    """A discovery issue. One row per (type, object); `first_seen_at` survives
    re-evaluation so the console can show how long an issue has been open."""

    __tablename__ = "directory_findings"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_directory_findings_org_key"),
                      Index("ix_directory_findings_org_type", "organization_id", "type"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # "<type>:<computer|user|device id>[:<device id>]" or "<type>:<user id>:c<computer id>"
    key: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16))  # computer | user | device
    source_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("directory_sources.id", ondelete="CASCADE"),
                                                  nullable=True, index=True)
    computer_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("directory_computers.id", ondelete="CASCADE"), nullable=True)
    user_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("directory_users.id", ondelete="CASCADE"), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"),
                                                  nullable=True)
    # Denormalised for listing / search / CSV.
    name: Mapped[str] = mapped_column(String(256), default="")
    domain: Mapped[str] = mapped_column(String(255), default="")
    ou: Mapped[str] = mapped_column(Text, default="")
    os: Mapped[str] = mapped_column(String(256), default="")
    last_logon_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    detail: Mapped[str] = mapped_column(String(500), default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ----------------------------------------------------------------------------- agent deployment
class AgentDeployment(TenantMixin, Base):
    """A "Deploy agent" batch started from Discovery (docs/DIRECTORY_DISCOVERY.md#deploying-the-agent).

    Read-only towards the directories: the platform only plans the rollout,
    issues enrollment tokens and installers, and tracks which of the selected
    machines have since enrolled (through the existing directory matching).
    The tokens are ordinary `enrollment_tokens` rows (hashes only); their ids
    are kept here so revoking the deployment revokes them."""

    __tablename__ = "agent_deployments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    # Selected machines per route, and the ones left out per reason, at creation:
    # {"gpo": 12, "intune": 3, ...} / {"has_agent": 2, "unsupported_os": 1, ...}.
    route_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    excluded_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    # Issue filter the selection came from (type, source_id, q, domain), if any.
    selection_filter: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    device_group: Mapped[str | None] = mapped_column(String(64), nullable=True)
    token_ids: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class AgentDeploymentItem(TenantMixin, Base):
    """One selected machine of a deployment. `computer_id` is the machine's
    representative directory record at creation; name / OS / route are copied so
    the progress view still reads well once the record is gone."""

    __tablename__ = "agent_deployment_items"
    __table_args__ = (UniqueConstraint("deployment_id", "computer_id", name="uq_agent_deployment_items_computer"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    deployment_id: Mapped[str] = mapped_column(String(32), ForeignKey("agent_deployments.id", ondelete="CASCADE"),
                                               index=True)
    computer_id: Mapped[str] = mapped_column(String(32))
    route: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(256), default="")
    platform: Mapped[str] = mapped_column(String(16), default="")
    os: Mapped[str] = mapped_column(String(256), default="")
    domain: Mapped[str] = mapped_column(String(255), default="")
    ou: Mapped[str] = mapped_column(Text, default="")
    # Record kinds of the machine at creation (ad, entra, intune, endpoint).
    kinds: Mapped[list] = mapped_column(JSON, default=list)
