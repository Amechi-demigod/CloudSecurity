"""Linux server agent (agents 1.7.0, docs/DEVICE_MANAGEMENT.md#linux-servers): OSV ecosystem, source package and source
version on device_software, and the .deb / .rpm packages of a signed agent release (agent_release_packages).

Revision ID: 0030_linux_agent
Revises: 0029_network_sensor_link
Create Date: 2026-11-11 11:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0030_linux_agent'
down_revision: str | None = '0029_network_sensor_link'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('device_software', schema=None) as batch_op:
        batch_op.add_column(sa.Column('ecosystem', sa.String(length=64), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('source_name', sa.String(length=255), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('source_version', sa.String(length=128), nullable=False, server_default=''))

    op.create_table('agent_release_packages',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('release_id', sa.String(length=32), nullable=False),
    sa.Column('format', sa.String(length=8), nullable=False),
    sa.Column('arch', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.ForeignKeyConstraint(['release_id'], ['agent_releases.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('release_id', 'format', 'arch', name='uq_agent_release_package')
    )
    with op.batch_alter_table('agent_release_packages', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_release_packages_release_id'), ['release_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('agent_release_packages', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_release_packages_release_id'))
    op.drop_table('agent_release_packages')
    with op.batch_alter_table('device_software', schema=None) as batch_op:
        batch_op.drop_column('source_version')
        batch_op.drop_column('source_name')
        batch_op.drop_column('ecosystem')
