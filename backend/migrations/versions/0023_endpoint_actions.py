"""Built-in endpoint actions: the Windows services inventory (device_services)
that the Services tab and manage_service work from (docs/DEVICE_MANAGEMENT.md#endpoint-actions).

Revision ID: 0023_endpoint_actions
Revises: 0022_windows_updates
Create Date: 2026-11-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0023_endpoint_actions'
down_revision: str | None = '0022_windows_updates'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('device_services',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('display_name', sa.String(length=256), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('start_type', sa.String(length=16), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_device_services_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_services', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_services_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_services_organization_id'), ['organization_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('device_services', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_services_organization_id'))
        batch_op.drop_index(batch_op.f('ix_device_services_device_id'))

    op.drop_table('device_services')
