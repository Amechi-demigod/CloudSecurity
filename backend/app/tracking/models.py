"""Device tracking tables (docs/DEVICE_TRACKING.md)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin


class DeviceTrackingSettings(TenantMixin, Base):
    """One row per organisation. Off by default. The alert_* columns are stored now and used by the alerts feature."""

    __tablename__ = "device_tracking_settings"

    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", name="fk_device_tracking_settings_organization_id"),
        primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    allowed_countries: Mapped[list] = mapped_column(JSON, default=list)  # ISO 3166-1 alpha-2; empty = no rule
    alert_outside_countries: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_not_seen_days: Mapped[int | None] = mapped_column(Integer, nullable=True, default=7)
    alert_after_hours: Mapped[bool] = mapped_column(Boolean, default=False)
    after_hours_start: Mapped[str] = mapped_column(String(5), default="19:00")
    after_hours_end: Mapped[str] = mapped_column(String(5), default="07:00")
    after_hours_weekdays: Mapped[list] = mapped_column(JSON, default=lambda: [0, 1, 2, 3, 4, 5, 6])
    alert_hardware_changed: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_agent_stopped: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_lost_mode_outside_countries: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TrackingOffice(TenantMixin, Base):
    __tablename__ = "tracking_offices"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    networks: Mapped[list] = mapped_column(JSON, default=list)  # IPs / CIDRs, max 50
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)  # None: the organisation's
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DeviceLocation(TenantMixin, Base):
    """A stretch of time a device was seen at one internet address / office / city."""

    __tablename__ = "device_locations"
    __table_args__ = (Index("ix_device_locations_device_seen", "device_id", "last_seen_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    ip: Mapped[str] = mapped_column(String(64))
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    region: Mapped[str | None] = mapped_column(String(128), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    accuracy_km: Mapped[float | None] = mapped_column(Float, nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    office_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("tracking_offices.id", ondelete="SET NULL"), nullable=True, index=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    # Signed-in user(s) from the latest check-in; only recorded while the device is marked missing.
    signed_in: Mapped[str | None] = mapped_column(String(255), nullable=True)
