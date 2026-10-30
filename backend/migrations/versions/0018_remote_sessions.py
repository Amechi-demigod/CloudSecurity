"""Attended remote desktop sessions (metadata only; docs/DEVICE_MANAGEMENT.md#remote-sessions).

Revision ID: 0018_remote_sessions
Revises: 0017_onboarding_dismissed
Create Date: 2026-10-30
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0018_remote_sessions'
down_revision: str | None = '0017_onboarding_dismissed'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('remote_sessions',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('open_device_id', sa.String(length=32), nullable=True),
    sa.Column('requested_by_id', sa.String(length=32), nullable=False),
    sa.Column('requested_by_email', sa.String(length=320), nullable=False),
    sa.Column('requested_by_name', sa.String(length=255), nullable=False),
    sa.Column('requester_ip', sa.String(length=64), nullable=True),
    sa.Column('mode', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('state', sa.String(length=24), nullable=False),
    sa.Column('end_reason', sa.String(length=32), nullable=True),
    sa.Column('error_code', sa.String(length=48), nullable=True),
    sa.Column('command_id', sa.String(length=32), nullable=True),
    sa.Column('token_hash', sa.String(length=64), nullable=True),
    sa.Column('token_expires_at', sa.DateTime(), nullable=True),
    sa.Column('token_used_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('agent_connected_at', sa.DateTime(), nullable=True),
    sa.Column('consent_deadline_at', sa.DateTime(), nullable=True),
    sa.Column('consented_at', sa.DateTime(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('ended_at', sa.DateTime(), nullable=True),
    sa.Column('ended_by_email', sa.String(length=320), nullable=True),
    sa.Column('last_activity_at', sa.DateTime(), nullable=True),
    sa.Column('relay_heartbeat_at', sa.DateTime(), nullable=True),
    sa.Column('bytes_to_viewer', sa.BigInteger(), nullable=False),
    sa.Column('bytes_to_agent', sa.BigInteger(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_remote_sessions_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('open_device_id')
    )
    with op.batch_alter_table('remote_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_remote_sessions_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_remote_sessions_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_remote_sessions_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_remote_sessions_state'), ['state'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('remote_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_remote_sessions_state'))
        batch_op.drop_index(batch_op.f('ix_remote_sessions_organization_id'))
        batch_op.drop_index(batch_op.f('ix_remote_sessions_device_id'))
        batch_op.drop_index(batch_op.f('ix_remote_sessions_created_at'))
    op.drop_table('remote_sessions')
