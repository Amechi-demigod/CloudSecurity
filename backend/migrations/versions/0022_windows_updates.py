"""Missing OS updates (read-only Windows Update report per device, docs/PATCHING.md).

Revision ID: 0022_windows_updates
Revises: 0021_directory_cloud_sources
Create Date: 2026-11-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0022_windows_updates'
down_revision: str | None = '0021_directory_cloud_sources'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('device_os_updates',
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('reported_at', sa.DateTime(), nullable=False),
    sa.Column('scanned_at', sa.DateTime(), nullable=True),
    sa.Column('scan_status', sa.String(length=16), nullable=False),
    sa.Column('scan_error', sa.String(length=1024), nullable=False),
    sa.Column('scan_trigger', sa.String(length=16), nullable=False),
    sa.Column('scan_duration_seconds', sa.Integer(), nullable=True),
    sa.Column('last_success_at', sa.DateTime(), nullable=True),
    sa.Column('last_install_success_at', sa.DateTime(), nullable=True),
    sa.Column('listed_at', sa.DateTime(), nullable=True),
    sa.Column('source', sa.String(length=24), nullable=False),
    sa.Column('source_detail', sa.String(length=255), nullable=False),
    sa.Column('service_state', sa.String(length=24), nullable=False),
    sa.Column('service_start_type', sa.String(length=24), nullable=False),
    sa.Column('reboot_pending', sa.Boolean(), nullable=False),
    sa.Column('reboot_pending_since', sa.DateTime(), nullable=True),
    sa.Column('missing_count', sa.Integer(), nullable=False),
    sa.Column('security_count', sa.Integer(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('oldest_security_release', sa.Date(), nullable=True),
    sa.Column('oldest_critical_release', sa.Date(), nullable=True),
    sa.Column('updates', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_device_os_updates_organization_id'),
    sa.PrimaryKeyConstraint('device_id')
    )
    with op.batch_alter_table('device_os_updates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_os_updates_organization_id'), ['organization_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('device_os_updates', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_os_updates_organization_id'))

    op.drop_table('device_os_updates')
