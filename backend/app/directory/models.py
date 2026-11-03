"""Directory discovery tables (docs/DIRECTORY_DISCOVERY.md).

* `directory_sources`: one configured directory per row (type "ad" today; the
  `type` column and provider-neutral object model leave room for Entra ID,
  Google Workspace and Okta). Optional service-account credentials are stored
  Fernet-encrypted in `secret_ciphertext` and never returned by the API.
* `directory_sync_runs`: one row per sync (scheduled, manual or test), the
  collector it ran on, its single-use upload token (SHA-256 only) and counts.
* `directory_computers` / `directory_users`: the objects a source returned,
  keyed by their stable provider id (`external_id`: objectGUID for AD) per
  source. Objects a complete run no longer returns get `missing_since` (they
  are purged later, never on the spot).
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

SOURCE_TYPES = ("ad",)  # future: "entra", "google", "okta"
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
    # Matcher output (directory/matching.py): the agent device / IT asset this
    # computer is, how it was matched (directory_sid, serial, fqdn, hostname_domain,
    # hostname) and how sure (0-100); "ambiguous" keeps the candidates instead.
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


FINDING_TYPES = ("not_managed", "stale_computer", "disabled_but_active", "unknown_to_directory",
                 "not_domain_joined", "disabled_user_signed_in", "stale_user_signed_in")


class DirectoryFinding(TenantMixin, Base):
    """A discovery issue. One row per (type, object); `first_seen_at` survives
    re-evaluation so the console can show how long an issue has been open."""

    __tablename__ = "directory_findings"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_directory_findings_org_key"),
                      Index("ix_directory_findings_org_type", "organization_id", "type"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # "<type>:<computer|user|device id>[:<device id>]"
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
