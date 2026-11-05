"""Compliance reports: daily per-framework summaries for the trend chart and
scheduled emailed PDF reports (docs/COMPLIANCE.md).

May need renumbering at merge time if another 0022 lands first.

Revision ID: 0025_compliance_reports
Revises: 0024_agent_deployments
Create Date: 2026-11-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0025_compliance_reports'
down_revision: str | None = '0024_agent_deployments'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('compliance_report_schedules',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('frameworks', sa.JSON(), nullable=False),
    sa.Column('frequency', sa.String(length=16), nullable=False),
    sa.Column('day', sa.Integer(), nullable=False),
    sa.Column('hour', sa.Integer(), nullable=False),
    sa.Column('recipients', sa.JSON(), nullable=False),
    sa.Column('account', sa.String(length=64), nullable=True),
    sa.Column('device_group', sa.String(length=64), nullable=True),
    sa.Column('next_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_status', sa.String(length=16), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_compliance_report_schedules_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('compliance_report_schedules', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_compliance_report_schedules_next_run_at'), ['next_run_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_compliance_report_schedules_organization_id'), ['organization_id'], unique=False)

    op.create_table('compliance_snapshots',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('day', sa.Date(), nullable=False),
    sa.Column('framework', sa.String(length=64), nullable=False),
    sa.Column('scope', sa.String(length=140), nullable=False),
    sa.Column('mapping_version', sa.Integer(), nullable=False),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_compliance_snapshots_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'day', 'framework', 'scope', name='uq_compliance_snapshots_org_day_fw_scope')
    )
    with op.batch_alter_table('compliance_snapshots', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_compliance_snapshots_day'), ['day'], unique=False)
        batch_op.create_index(batch_op.f('ix_compliance_snapshots_organization_id'), ['organization_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('compliance_snapshots', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_compliance_snapshots_organization_id'))
        batch_op.drop_index(batch_op.f('ix_compliance_snapshots_day'))

    op.drop_table('compliance_snapshots')
    with op.batch_alter_table('compliance_report_schedules', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_compliance_report_schedules_organization_id'))
        batch_op.drop_index(batch_op.f('ix_compliance_report_schedules_next_run_at'))

    op.drop_table('compliance_report_schedules')
