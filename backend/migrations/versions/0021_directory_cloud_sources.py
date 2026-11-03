"""Directory discovery, cloud sources (Microsoft Entra ID + Intune, Google
Workspace): device record kind / platform / compliance / primary user and the
physical-machine grouping of directory computers, privileged directory users,
and the per-part status and permission checks of server-side syncs
(docs/DIRECTORY_DISCOVERY.md).

Revision ID: 0021_directory_cloud_sources
Revises: 0020_directory_discovery
Create Date: 2026-11-03
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0021_directory_cloud_sources'
down_revision: str | None = '0020_directory_discovery'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('directory_sources', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scope_status', sa.JSON(), nullable=False, server_default='{}'))

    with op.batch_alter_table('directory_sync_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('checks', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('scope_status', sa.JSON(), nullable=False, server_default='{}'))

    with op.batch_alter_table('directory_computers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_kind', sa.String(length=16), nullable=False, server_default='ad'))
        batch_op.add_column(sa.Column('cloud_device_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('platform', sa.String(length=16), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('agent_expected', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column('compliance', sa.String(length=24), nullable=True))
        batch_op.add_column(sa.Column('encrypted', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('primary_user', sa.String(length=256), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('machine_id', sa.String(length=32), nullable=True))
        batch_op.create_index(batch_op.f('ix_directory_computers_cloud_device_id'), ['cloud_device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_machine_id'), ['machine_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_primary_user'), ['primary_user'], unique=False)

    with op.batch_alter_table('directory_users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('privileged', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('privileged_roles', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.create_index(batch_op.f('ix_directory_users_privileged'), ['privileged'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('directory_users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_users_privileged'))
        batch_op.drop_column('privileged_roles')
        batch_op.drop_column('privileged')

    with op.batch_alter_table('directory_computers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_computers_primary_user'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_machine_id'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_cloud_device_id'))
        batch_op.drop_column('machine_id')
        batch_op.drop_column('primary_user')
        batch_op.drop_column('encrypted')
        batch_op.drop_column('compliance')
        batch_op.drop_column('agent_expected')
        batch_op.drop_column('platform')
        batch_op.drop_column('cloud_device_id')
        batch_op.drop_column('device_kind')

    with op.batch_alter_table('directory_sync_runs', schema=None) as batch_op:
        batch_op.drop_column('scope_status')
        batch_op.drop_column('checks')

    with op.batch_alter_table('directory_sources', schema=None) as batch_op:
        batch_op.drop_column('scope_status')
