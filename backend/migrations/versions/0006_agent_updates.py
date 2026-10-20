"""Agent auto-update: signed releases and their binaries, rollout rings, update
history, and per-device ring / pin / last update status (nullable columns).

Revision ID: 0006_agent_updates
Revises: 0005_agent_installers
Create Date: 2026-10-20
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0006_agent_updates'
down_revision: str | None = '0005_agent_installers'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEVICE_COLUMNS = (
    ('update_ring_id', sa.String(length=32)),
    ('update_pinned_release_id', sa.String(length=32)),
    ('update_status', sa.String(length=16)),
    ('update_status_version', sa.String(length=64)),
    ('update_status_detail', sa.String(length=500)),
    ('update_status_at', sa.DateTime()),
)


def upgrade() -> None:
    op.create_table('agent_releases',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('version', sa.String(length=64), nullable=False),
    sa.Column('manifest_envelope', sa.Text(), nullable=False),
    sa.Column('manifest', sa.JSON(), nullable=False),
    sa.Column('key_id', sa.String(length=64), nullable=False),
    sa.Column('released_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('min_supported_version', sa.String(length=64), nullable=False),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('bundle_sha256', sa.String(length=64), nullable=False),
    sa.Column('imported_by', sa.String(length=320), nullable=False),
    sa.Column('imported_at', sa.DateTime(), nullable=False),
    sa.Column('withdrawn_at', sa.DateTime(), nullable=True),
    sa.Column('withdrawn_reason', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('agent_releases', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_releases_version'), ['version'], unique=True)

    op.create_table('agent_release_artifacts',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('release_id', sa.String(length=32), nullable=False),
    sa.Column('os', sa.String(length=16), nullable=False),
    sa.Column('arch', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.ForeignKeyConstraint(['release_id'], ['agent_releases.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('release_id', 'os', 'arch', name='uq_agent_release_artifact_platform')
    )
    with op.batch_alter_table('agent_release_artifacts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_release_artifacts_release_id'), ['release_id'], unique=False)

    op.create_table('agent_update_rings',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('description', sa.String(length=500), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('device_groups', sa.JSON(), nullable=False),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('target_release_id', sa.String(length=32), nullable=True),
    sa.Column('rollout_percent', sa.Integer(), nullable=False),
    sa.Column('paused', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=False),
    sa.ForeignKeyConstraint(['target_release_id'], ['agent_releases.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )

    op.create_table('agent_update_events',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('release_id', sa.String(length=32), nullable=True),
    sa.Column('from_version', sa.String(length=64), nullable=False),
    sa.Column('to_version', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('detail', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('agent_update_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_update_events_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_update_events_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_update_events_release_id'), ['release_id'], unique=False)

    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, col in DEVICE_COLUMNS:
            batch_op.add_column(sa.Column(name, col, nullable=True))
        batch_op.create_index(batch_op.f('ix_devices_update_ring_id'), ['update_ring_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_update_ring_id'))
        for name, _ in reversed(DEVICE_COLUMNS):
            batch_op.drop_column(name)
    op.drop_table('agent_update_events')
    op.drop_table('agent_update_rings')
    op.drop_table('agent_release_artifacts')
    op.drop_table('agent_releases')
