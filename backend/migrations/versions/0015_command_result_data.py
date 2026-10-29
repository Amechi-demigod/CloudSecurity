"""Structured result_data on device commands (Suspend sign-in pre-flight
findings and crash-recovery outcomes; see schemas_devices.validate_result_data).

Revision ID: 0015_command_result_data
Revises: 0014_host_isolation
Create Date: 2026-10-29
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0015_command_result_data'
down_revision: str | None = '0014_host_isolation'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('device_commands', schema=None) as batch_op:
        batch_op.add_column(sa.Column('result_data', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('device_commands', schema=None) as batch_op:
        batch_op.drop_column('result_data')
