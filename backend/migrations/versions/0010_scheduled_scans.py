"""Scheduled cloud posture scans: what started each scan run (manual /
scheduled, nullable) and the console overrides of the schedule (single row).

Revision ID: 0010_scheduled_scans
Revises: 0009_device_approvals_scripts
Create Date: 2026-10-23
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0010_scheduled_scans'
down_revision: str | None = '0009_device_approvals_scripts'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('scan_schedule_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.Column('interval_hours', sa.Float(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('scan_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('trigger', sa.String(length=16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('scan_runs', schema=None) as batch_op:
        batch_op.drop_column('trigger')
    op.drop_table('scan_schedule_settings')
