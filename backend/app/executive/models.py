"""Executive report tables (docs/EXECUTIVE_REPORT.md).

* `executive_report_subscriptions`: one scheduled report (name, frequency, enabled) of an organisation.
* `executive_report_recipients`: who receives it. `admin` recipients are console users (resolved at send time:
  only while they are still active admins of the organisation); `external` recipients are named people with no
  console account (CEO, directors) who can unsubscribe through a signed link and never sign in through it.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin

FREQUENCIES = ("daily", "weekly", "monthly", "quarterly")


class ExecReportSubscription(TenantMixin, Base):
    __tablename__ = "executive_report_subscriptions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    frequency: Mapped[str] = mapped_column(String(16), default="monthly")  # daily | weekly | monthly | quarterly
    # weekly: 0 = Monday .. 6 = Sunday; monthly / quarterly: day of month 1-28 (quarterly: in Jan, Apr, Jul, Oct);
    # daily: unused. Sent at `hour` UTC.
    day: Mapped[int] = mapped_column(Integer, default=1)
    hour: Mapped[int] = mapped_column(Integer, default=6)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # sent | partial | failed
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class ExecReportRecipient(TenantMixin, Base):
    __tablename__ = "executive_report_recipients"
    __table_args__ = (UniqueConstraint("subscription_id", "email", name="uq_exec_report_recipients_sub_email"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    subscription_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("executive_report_subscriptions.id", ondelete="CASCADE",
                               name="fk_exec_report_recipients_subscription_id"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # admin | external
    user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # admin recipients
    name: Mapped[str] = mapped_column(String(120), default="")
    email: Mapped[str] = mapped_column(String(320))  # lower-case
    job_title: Mapped[str | None] = mapped_column(String(120), nullable=True)
    unsubscribed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
