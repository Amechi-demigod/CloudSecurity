"""Daily dashboard metric snapshots (point-in-time counts for the dashboards'
"vs previous period" changes and trends; see app/services/dashboards.py).

Revision ID: 0016_dashboard_snapshots
Revises: 0015_command_result_data
Create Date: 2026-10-30
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0016_dashboard_snapshots'
down_revision: str | None = '0015_command_result_data'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('dashboard_snapshots',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('day', sa.Date(), nullable=False),
    sa.Column('account', sa.String(length=64), nullable=False),
    sa.Column('metrics', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_dashboard_snapshots_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'day', 'account', name='uq_dashboard_snapshots_org_day_account')
    )
    with op.batch_alter_table('dashboard_snapshots', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_dashboard_snapshots_day'), ['day'], unique=False)
        batch_op.create_index(batch_op.f('ix_dashboard_snapshots_organization_id'), ['organization_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('dashboard_snapshots', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_dashboard_snapshots_organization_id'))
        batch_op.drop_index(batch_op.f('ix_dashboard_snapshots_day'))
    op.drop_table('dashboard_snapshots')
