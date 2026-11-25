"""Device tracking: settings, offices and location history.

Revision ID: 0039_device_tracking
Revises: 0038_executive_reports
Create Date: 2026-11-25 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0039_device_tracking'
down_revision: str | None = '0038_executive_reports'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('device_tracking_settings',
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=False),
    sa.Column('allowed_countries', sa.JSON(), nullable=False),
    sa.Column('alert_outside_countries', sa.Boolean(), nullable=False),
    sa.Column('alert_not_seen_days', sa.Integer(), nullable=True),
    sa.Column('alert_after_hours', sa.Boolean(), nullable=False),
    sa.Column('after_hours_start', sa.String(length=5), nullable=False),
    sa.Column('after_hours_end', sa.String(length=5), nullable=False),
    sa.Column('after_hours_weekdays', sa.JSON(), nullable=False),
    sa.Column('alert_hardware_changed', sa.Boolean(), nullable=False),
    sa.Column('alert_agent_stopped', sa.Boolean(), nullable=False),
    sa.Column('auto_lost_mode_outside_countries', sa.Boolean(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_device_tracking_settings_organization_id'),
    sa.PrimaryKeyConstraint('organization_id')
    )
    op.create_table('tracking_offices',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('networks', sa.JSON(), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_tracking_offices_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tracking_offices_organization_id'), 'tracking_offices', ['organization_id'], unique=False)
    op.create_table('device_locations',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=False),
    sa.Column('country_code', sa.String(length=2), nullable=True),
    sa.Column('country', sa.String(length=128), nullable=True),
    sa.Column('region', sa.String(length=128), nullable=True),
    sa.Column('city', sa.String(length=128), nullable=True),
    sa.Column('latitude', sa.Float(), nullable=True),
    sa.Column('longitude', sa.Float(), nullable=True),
    sa.Column('accuracy_km', sa.Float(), nullable=True),
    sa.Column('asn', sa.Integer(), nullable=True),
    sa.Column('provider', sa.String(length=255), nullable=True),
    sa.Column('office_id', sa.String(length=32), nullable=True),
    sa.Column('is_private', sa.Boolean(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['office_id'], ['tracking_offices.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_device_locations_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_locations_device_id'), 'device_locations', ['device_id'], unique=False)
    op.create_index(op.f('ix_device_locations_last_seen_at'), 'device_locations', ['last_seen_at'], unique=False)
    op.create_index(op.f('ix_device_locations_office_id'), 'device_locations', ['office_id'], unique=False)
    op.create_index(op.f('ix_device_locations_organization_id'), 'device_locations', ['organization_id'], unique=False)
    op.create_index('ix_device_locations_device_seen', 'device_locations', ['device_id', 'last_seen_at'], unique=False)
    op.add_column('devices', sa.Column('location_id', sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'location_id')
    op.drop_table('device_locations')
    op.drop_table('tracking_offices')
    op.drop_table('device_tracking_settings')
