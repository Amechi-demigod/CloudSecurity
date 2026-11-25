"""Missing-device mode: flag, who/why/when, interval to restore and a hardware baseline on devices.

Revision ID: 0040_missing_devices
Revises: 0039_device_tracking
Create Date: 2026-11-25 20:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0040_missing_devices'
down_revision: str | None = '0039_device_tracking'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = [
    ('missing_since', sa.DateTime()),
    ('missing_by_id', sa.String(length=32)),
    ('missing_by_label', sa.String(length=320)),
    ('missing_reason', sa.String(length=500)),
    ('missing_previous_check_in_seconds', sa.Integer()),
    ('missing_recovered_at', sa.DateTime()),
    ('missing_recovered_by_id', sa.String(length=32)),
    ('missing_recovered_by_label', sa.String(length=320)),
    ('missing_last_contact_at', sa.DateTime()),
    ('missing_baseline', sa.JSON()),
]


def upgrade() -> None:
    with op.batch_alter_table('devices') as batch:
        for name, type_ in COLUMNS:
            batch.add_column(sa.Column(name, type_, nullable=True))
    op.add_column('device_locations', sa.Column('signed_in', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('device_locations', 'signed_in')
    with op.batch_alter_table('devices') as batch:
        for name, _ in reversed(COLUMNS):
            batch.drop_column(name)
