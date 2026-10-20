"""Two-person approvals for high-risk device actions, lost mode / remote wipe
state on devices, and the signed device-script library.

Revision ID: 0008_device_approvals_scripts
Revises: 0007_it_asset_lifecycle
Create Date: 2026-10-20
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0008_device_approvals_scripts'
down_revision: str | None = '0007_it_asset_lifecycle'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEVICE_COLUMNS = (
    ('lost_mode_status', sa.String(length=16)),
    ('lost_mode_message', sa.String(length=500)),
    ('lost_mode_phone', sa.String(length=32)),
    ('lost_mode_since', sa.DateTime()),
    ('lost_mode_by', sa.String(length=320)),
    ('wipe_status', sa.String(length=16)),
    ('wipe_status_at', sa.DateTime()),
    ('wipe_command_id', sa.String(length=32)),
)
COMMAND_COLUMNS = (
    ('exit_code', sa.Integer()),
    ('approval_id', sa.String(length=32)),
    ('approved_by_email', sa.String(length=320)),
    ('acknowledged_at', sa.DateTime()),
)


def upgrade() -> None:
    op.create_table('device_approvals',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('action', sa.String(length=32), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('summary', sa.String(length=500), nullable=False),
    sa.Column('risk', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('requested_by_id', sa.String(length=32), nullable=False),
    sa.Column('requested_by_email', sa.String(length=320), nullable=False),
    sa.Column('requested_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('decided_by_id', sa.String(length=32), nullable=True),
    sa.Column('decided_by_email', sa.String(length=320), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=True),
    sa.Column('decision_reason', sa.Text(), nullable=True),
    sa.Column('self_approved', sa.Boolean(), nullable=False),
    sa.Column('execute_after', sa.DateTime(), nullable=True),
    sa.Column('executed_at', sa.DateTime(), nullable=True),
    sa.Column('command_id', sa.String(length=32), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_approvals', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_approvals_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_approvals_requested_at'), ['requested_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_approvals_status'), ['status'], unique=False)

    op.create_table('device_script_bundles',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('version', sa.String(length=64), nullable=False),
    sa.Column('manifest_envelope', sa.Text(), nullable=False),
    sa.Column('manifest', sa.JSON(), nullable=False),
    sa.Column('key_id', sa.String(length=64), nullable=False),
    sa.Column('released_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('bundle_sha256', sa.String(length=64), nullable=False),
    sa.Column('imported_by', sa.String(length=320), nullable=False),
    sa.Column('imported_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('device_script_bundles', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_script_bundles_version'), ['version'], unique=True)

    op.create_table('device_scripts',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('bundle_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('description', sa.String(length=1000), nullable=False),
    sa.Column('platform', sa.String(length=16), nullable=False),
    sa.Column('interpreter', sa.String(length=16), nullable=False),
    sa.Column('risk', sa.String(length=16), nullable=False),
    sa.Column('timeout_seconds', sa.Integer(), nullable=False),
    sa.Column('parameters', sa.JSON(), nullable=False),
    sa.Column('file', sa.String(length=128), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('content', sa.LargeBinary(), nullable=False),
    sa.ForeignKeyConstraint(['bundle_id'], ['device_script_bundles.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('bundle_id', 'name', name='uq_device_script_bundle_name')
    )
    with op.batch_alter_table('device_scripts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_scripts_bundle_id'), ['bundle_id'], unique=False)

    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, col in DEVICE_COLUMNS:
            batch_op.add_column(sa.Column(name, col, nullable=True))
    with op.batch_alter_table('device_commands', schema=None) as batch_op:
        for name, col in COMMAND_COLUMNS:
            batch_op.add_column(sa.Column(name, col, nullable=True))
        batch_op.create_index(batch_op.f('ix_device_commands_approval_id'), ['approval_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('device_commands', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_commands_approval_id'))
        for name, _ in reversed(COMMAND_COLUMNS):
            batch_op.drop_column(name)
    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, _ in reversed(DEVICE_COLUMNS):
            batch_op.drop_column(name)
    op.drop_table('device_scripts')
    op.drop_table('device_script_bundles')
    op.drop_table('device_approvals')
