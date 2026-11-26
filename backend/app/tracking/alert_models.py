"""Device tracking alert tables (docs/DEVICE_TRACKING.md#alerts): the alert events shown in a device's location
history (also the de-duplication / rate-limit record) and the small per-device state the alerts need."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin


class DeviceTrackingEvent(TenantMixin, Base):
    """One alert that was raised for a device. Text holds a city and country only (never an address)."""

    __tablename__ = "device_tracking_events"
    __table_args__ = (Index("ix_device_tracking_events_device_at", "device_id", "at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32))  # outside_countries | not_seen | after_hours | ...
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)


class DeviceTrackingState(TenantMixin, Base):
    """Per-device bookkeeping so every alert fires once per occurrence."""

    __tablename__ = "device_tracking_state"

    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    hardware: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # baseline of the last inventory
    last_obs_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # last check-in / poll we saw
    regular_polls: Mapped[int] = mapped_column(Integer, default=0)  # consecutive polls about a minute apart
    stopped_alert_for: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # last_obs_at alerted on
    not_seen_alert_for: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # last_seen_at alerted on
    after_hours_night: Mapped[str | None] = mapped_column(String(10), nullable=True)  # night (date) alerted on
    auto_lost_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # automatic lost mode queued
