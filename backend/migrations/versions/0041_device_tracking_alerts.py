"""Device tracking alerts: alert events, per-device alert state, automatic lost mode contact phone.

Revision ID: 0041_device_tracking_alerts
Revises: 0040_missing_devices
Create Date: 2026-11-26 09:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0041_device_tracking_alerts'
down_revision: str | None = '0040_missing_devices'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('device_tracking_settings', sa.Column('auto_lost_mode_phone', sa.String(length=32), nullable=True))
    op.create_table('device_tracking_events',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('at', sa.DateTime(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('city', sa.String(length=128), nullable=True),
    sa.Column('country_code', sa.String(length=2), nullable=True),
    sa.Column('country', sa.String(length=128), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'],
                            name='fk_device_tracking_events_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_tracking_events_device_id'), 'device_tracking_events', ['device_id'], unique=False)
    op.create_index(op.f('ix_device_tracking_events_at'), 'device_tracking_events', ['at'], unique=False)
    op.create_index(op.f('ix_device_tracking_events_organization_id'), 'device_tracking_events',
                    ['organization_id'], unique=False)
    op.create_index('ix_device_tracking_events_device_at', 'device_tracking_events', ['device_id', 'at'], unique=False)
    op.create_table('device_tracking_state',
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('hardware', sa.JSON(), nullable=True),
    sa.Column('last_obs_at', sa.DateTime(), nullable=True),
    sa.Column('regular_polls', sa.Integer(), nullable=False),
    sa.Column('stopped_alert_for', sa.DateTime(), nullable=True),
    sa.Column('not_seen_alert_for', sa.DateTime(), nullable=True),
    sa.Column('after_hours_night', sa.String(length=10), nullable=True),
    sa.Column('auto_lost_at', sa.DateTime(), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'],
                            name='fk_device_tracking_state_organization_id'),
    sa.PrimaryKeyConstraint('device_id')
    )
    op.create_index(op.f('ix_device_tracking_state_organization_id'), 'device_tracking_state',
                    ['organization_id'], unique=False)


def downgrade() -> None:
    op.drop_table('device_tracking_state')
    op.drop_table('device_tracking_events')
    op.drop_column('device_tracking_settings', 'auto_lost_mode_phone')
