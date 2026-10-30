"""IT asset lifecycle tables (docs/ASSET_MANAGEMENT.md).

* `it_assets`: one row per physical asset: agent-enrolled devices (linked by
  `device_id`, created automatically) and assets without an agent (monitors,
  phones, docks, laptops not yet enrolled), added by hand or by CSV import.
* `it_asset_events`: chain of custody (assignments, returns, status changes,
  disposal ...) with who / when / notes. Append-only from the API.
* `it_asset_offboardings`: a person leaving on a date; their assets go to
  "retrieval pending" with a due date.
* `it_asset_certificates`: wipe / destruction certificates (PDF or image),
  stored in the database so `pg_dump` backups (`cnapp-ctl backup`) include them.
* `it_asset_settings`: admin-managed sites, custom field definitions, default
  currency and thresholds (one row per organisation).

These are not the cloud inventory `assets` table (VMs, storage accounts, ...).
"""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import JSON, Date, DateTime, ForeignKey, Integer, LargeBinary, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin

ASSET_STATUSES = ("in_stock", "assigned", "in_repair", "retrieval_pending", "retrieved", "lost", "stolen", "disposed")
ASSET_TYPES = ("laptop", "desktop", "computer", "monitor", "phone", "tablet", "dock", "peripheral", "headset",
               "printer", "network", "server", "other")
DISPOSAL_METHODS = ("recycled", "destroyed", "resold", "donated", "returned_to_vendor", "other")


class ItAsset(TenantMixin, Base):
    __tablename__ = "it_assets"
    # Asset tags are unique within an organisation.
    __table_args__ = (UniqueConstraint("organization_id", "asset_tag", name="uq_it_assets_org_asset_tag"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    asset_tag: Mapped[str] = mapped_column(String(64))
    serial_number: Mapped[str] = mapped_column(String(128), default="", index=True)
    asset_type: Mapped[str] = mapped_column(String(32), default="other", index=True)
    manufacturer: Mapped[str] = mapped_column(String(128), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(24), default="in_stock", index=True)
    # Agent-enrolled device (None for assets without an agent). Kept when the
    # device record is deleted (SET NULL) so the asset history survives.
    device_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, unique=True)
    # manual | agent | import
    source: Mapped[str] = mapped_column(String(16), default="manual")
    # Owner. Set by hand (name and/or email) or automatically from the agent's
    # signed-in user (the OS username in assignee_name, no email).
    assignee_name: Mapped[str] = mapped_column(String(128), default="")
    # Stored lower-cased; empty for owners known by name / username only.
    assignee_email: Mapped[str] = mapped_column(String(320), default="", index=True)
    assignee_department: Mapped[str] = mapped_column(String(128), default="")
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    location: Mapped[str] = mapped_column(String(128), default="")
    purchase_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    supplier: Mapped[str] = mapped_column(String(128), default="")
    purchase_cost: Mapped[Decimal | None] = mapped_column(Numeric(14, 2), nullable=True)
    currency: Mapped[str] = mapped_column(String(3), default="NGN")
    warranty_end: Mapped[date | None] = mapped_column(Date, nullable=True, index=True)
    refresh_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    custom_fields: Mapped[dict] = mapped_column(JSON, default=dict)
    # Retrieval (offboarding)
    retrieval_due: Mapped[date | None] = mapped_column(Date, nullable=True)
    offboarding_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("it_asset_offboardings.id", ondelete="SET NULL"), nullable=True, index=True)
    # Disposal
    disposal_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    disposal_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    disposal_vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    disposal_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ItAssetEvent(TenantMixin, Base):
    """Chain-of-custody entry. event_type: created, updated, assigned, returned,
    status_changed, offboarding, offboarding_cancelled, disposed, imported,
    device_linked, certificate_uploaded, certificate_deleted."""

    __tablename__ = "it_asset_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(String(32), ForeignKey("it_assets.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    from_assignee: Mapped[str | None] = mapped_column(String(320), nullable=True)
    to_assignee: Mapped[str | None] = mapped_column(String(320), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class ItAssetOffboarding(TenantMixin, Base):
    __tablename__ = "it_asset_offboardings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # Empty when the person is identified by username only.
    person_email: Mapped[str] = mapped_column(String(320), index=True)
    # OS login name (as the agent reports it, without DOMAIN\): matches owners
    # that have no email, e.g. set automatically from the agent.
    person_username: Mapped[str] = mapped_column(String(128), default="", server_default="", index=True)
    person_name: Mapped[str] = mapped_column(String(128), default="")
    department: Mapped[str] = mapped_column(String(128), default="")
    leave_date: Mapped[date] = mapped_column(Date)
    retrieval_due: Mapped[date] = mapped_column(Date)
    # open | completed | cancelled
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ItAssetCertificate(TenantMixin, Base):
    """Wipe / destruction certificate (size-capped; type checked by magic bytes)."""

    __tablename__ = "it_asset_certificates"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(32), ForeignKey("it_assets.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(128))
    content_type: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    uploaded_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    data: Mapped[bytes] = mapped_column(LargeBinary)


class ItAssetSettings(TenantMixin, Base):
    """Admin-managed settings (one row per organisation). Missing keys fall back
    to the ASSET_* environment variables."""

    __tablename__ = "it_asset_settings"

    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_it_asset_settings_organization_id"), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
