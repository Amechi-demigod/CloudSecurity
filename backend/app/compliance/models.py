"""Compliance report tables (docs/COMPLIANCE.md).

* `compliance_snapshots`: one framework summary (control counts, score,
  coverage) per organisation, UTC day, framework and scope ("" = whole
  organisation), for the trend chart. Written by the daily snapshot job and
  lazily on the first read of a day, like the dashboard snapshots.
* `compliance_report_schedules`: emailed PDF reports an admin configured
  (frameworks, weekly / monthly, recipients from the organisation's members).
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin

FREQUENCIES = ("weekly", "monthly")


class ComplianceSnapshot(TenantMixin, Base):
    __tablename__ = "compliance_snapshots"
    __table_args__ = (UniqueConstraint("organization_id", "day", "framework", "scope",
                                       name="uq_compliance_snapshots_org_day_fw_scope"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    day: Mapped[date] = mapped_column(Date, index=True)
    framework: Mapped[str] = mapped_column(String(64))
    # "" = whole organisation; "account:<id>" / "group:<name>" (not written by the daily job yet).
    scope: Mapped[str] = mapped_column(String(140), default="")
    mapping_version: Mapped[int] = mapped_column(Integer, default=1)
    # scoring.summarize(): pass, fail, partial, no_data, manual, total, assessed, score, coverage, mapped
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ComplianceReportSchedule(TenantMixin, Base):
    __tablename__ = "compliance_report_schedules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    frameworks: Mapped[list] = mapped_column(JSON, default=list)
    frequency: Mapped[str] = mapped_column(String(16), default="monthly")  # weekly | monthly
    # weekly: 0 = Monday .. 6 = Sunday; monthly: day of month 1-28. Sent at `hour` UTC.
    day: Mapped[int] = mapped_column(Integer, default=1)
    hour: Mapped[int] = mapped_column(Integer, default=6)
    # Lower-case email addresses of members of the organisation.
    recipients: Mapped[list] = mapped_column(JSON, default=list)
    # Optional report scope (one cloud account or one device group).
    account: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_group: Mapped[str | None] = mapped_column(String(64), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # sent | partial | failed
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
