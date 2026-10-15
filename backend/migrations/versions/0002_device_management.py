"""Device management: enrolled endpoints (Windows/macOS agent), enrollment tokens,
per-device credentials, posture history, installed software, remote commands and
uploaded log bundles.

Revision ID: 0002_device_management
Revises: 0001_baseline
Create Date: 2026-10-15
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002_device_management'
down_revision: str | None = '0001_baseline'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('devices',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('os_family', sa.String(length=16), nullable=False),
    sa.Column('os_name', sa.String(length=128), nullable=False),
    sa.Column('os_version', sa.String(length=64), nullable=False),
    sa.Column('os_build', sa.String(length=64), nullable=False),
    sa.Column('architecture', sa.String(length=32), nullable=False),
    sa.Column('serial_number', sa.String(length=128), nullable=False),
    sa.Column('manufacturer', sa.String(length=128), nullable=False),
    sa.Column('model', sa.String(length=128), nullable=False),
    sa.Column('machine_id', sa.String(length=64), nullable=False),
    sa.Column('agent_version', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('enrolled_at', sa.DateTime(), nullable=False),
    sa.Column('enrollment_token_id', sa.String(length=32), nullable=True),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.Column('last_checkin_at', sa.DateTime(), nullable=True),
    sa.Column('last_ip', sa.String(length=64), nullable=True),
    sa.Column('check_in_interval_seconds', sa.Integer(), nullable=False),
    sa.Column('inventory', sa.JSON(), nullable=False),
    sa.Column('posture', sa.JSON(), nullable=False),
    sa.Column('collection_errors', sa.JSON(), nullable=False),
    sa.Column('software_count', sa.Integer(), nullable=False),
    sa.Column('updates_pending_since', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_devices_hostname'), ['hostname'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_last_seen_at'), ['last_seen_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_os_family'), ['os_family'], unique=False)
        batch_op.create_index('ix_devices_os_machine', ['os_family', 'machine_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_status'), ['status'], unique=False)

    op.create_table('enrollment_tokens',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('token_prefix', sa.String(length=16), nullable=False),
    sa.Column('max_uses', sa.Integer(), nullable=True),
    sa.Column('use_count', sa.Integer(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('last_used_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )
    op.create_table('device_commands',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('nonce', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('requested_by_id', sa.String(length=32), nullable=True),
    sa.Column('requested_by_email', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('delivered_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('output', sa.Text(), nullable=False),
    sa.Column('log_bundle_id', sa.String(length=32), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_commands', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_commands_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_commands_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_commands_status'), ['status'], unique=False)

    op.create_table('device_credentials',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('secret_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_used_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('secret_hash')
    )
    with op.batch_alter_table('device_credentials', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_credentials_device_id'), ['device_id'], unique=False)

    op.create_table('device_log_bundles',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('command_id', sa.String(length=32), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('content_type', sa.String(length=64), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_log_bundles', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_log_bundles_device_id'), ['device_id'], unique=False)

    op.create_table('device_posture_snapshots',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('received_at', sa.DateTime(), nullable=False),
    sa.Column('collected_at', sa.DateTime(), nullable=True),
    sa.Column('agent_version', sa.String(length=32), nullable=False),
    sa.Column('os_version', sa.String(length=64), nullable=False),
    sa.Column('posture', sa.JSON(), nullable=False),
    sa.Column('issues', sa.JSON(), nullable=False),
    sa.Column('software_count', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_posture_snapshots', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_posture_snapshots_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_posture_snapshots_received_at'), ['received_at'], unique=False)

    op.create_table('device_software',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('version', sa.String(length=128), nullable=False),
    sa.Column('publisher', sa.String(length=255), nullable=False),
    sa.Column('identifier', sa.String(length=255), nullable=False),
    sa.Column('install_date', sa.String(length=32), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_software', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_software_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_software_name'), ['name'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('device_software', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_software_name'))
        batch_op.drop_index(batch_op.f('ix_device_software_device_id'))

    op.drop_table('device_software')
    with op.batch_alter_table('device_posture_snapshots', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_posture_snapshots_received_at'))
        batch_op.drop_index(batch_op.f('ix_device_posture_snapshots_device_id'))

    op.drop_table('device_posture_snapshots')
    with op.batch_alter_table('device_log_bundles', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_log_bundles_device_id'))

    op.drop_table('device_log_bundles')
    with op.batch_alter_table('device_credentials', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_credentials_device_id'))

    op.drop_table('device_credentials')
    with op.batch_alter_table('device_commands', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_commands_status'))
        batch_op.drop_index(batch_op.f('ix_device_commands_device_id'))
        batch_op.drop_index(batch_op.f('ix_device_commands_created_at'))

    op.drop_table('device_commands')
    op.drop_table('enrollment_tokens')
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_status'))
        batch_op.drop_index('ix_devices_os_machine')
        batch_op.drop_index(batch_op.f('ix_devices_os_family'))
        batch_op.drop_index(batch_op.f('ix_devices_last_seen_at'))
        batch_op.drop_index(batch_op.f('ix_devices_hostname'))

    op.drop_table('devices')
