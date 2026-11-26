"""Device tracking: optional IT support email on the automatic lost mode lock screen.

Revision ID: 0042_lost_mode_support_email
Revises: 0041_device_tracking_alerts
Create Date: 2026-11-26 09:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0042_lost_mode_support_email'
down_revision: str | None = '0041_device_tracking_alerts'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('device_tracking_settings', sa.Column('auto_lost_mode_email', sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column('device_tracking_settings', 'auto_lost_mode_email')
