"""Agent deployments: "Deploy agent" batches started from Discovery, with the
machines they cover (docs/DIRECTORY_DISCOVERY.md#deploying-the-agent).

Revision ID: 0022_agent_deployments
Revises: 0021_directory_cloud_sources
Create Date: 2026-11-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0022_agent_deployments'
down_revision: str | None = '0021_directory_cloud_sources'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('agent_deployments',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('route_counts', sa.JSON(), nullable=False),
    sa.Column('excluded_counts', sa.JSON(), nullable=False),
    sa.Column('selection_filter', sa.JSON(), nullable=True),
    sa.Column('device_group', sa.String(length=64), nullable=True),
    sa.Column('token_ids', sa.JSON(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_agent_deployments_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('agent_deployments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_deployments_organization_id'), ['organization_id'], unique=False)

    op.create_table('agent_deployment_items',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('deployment_id', sa.String(length=32), nullable=False),
    sa.Column('computer_id', sa.String(length=32), nullable=False),
    sa.Column('route', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('platform', sa.String(length=16), nullable=False),
    sa.Column('os', sa.String(length=256), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('ou', sa.Text(), nullable=False),
    sa.Column('kinds', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['deployment_id'], ['agent_deployments.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_agent_deployment_items_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('deployment_id', 'computer_id', name='uq_agent_deployment_items_computer')
    )
    with op.batch_alter_table('agent_deployment_items', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_deployment_items_deployment_id'), ['deployment_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_deployment_items_organization_id'), ['organization_id'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('agent_deployment_items', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_deployment_items_organization_id'))
        batch_op.drop_index(batch_op.f('ix_agent_deployment_items_deployment_id'))

    op.drop_table('agent_deployment_items')
    with op.batch_alter_table('agent_deployments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_deployments_organization_id'))

    op.drop_table('agent_deployments')
