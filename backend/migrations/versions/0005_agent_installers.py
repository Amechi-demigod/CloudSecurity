"""Pre-configured agent installers: package-bound enrollment tokens and device
group labels. Adds nullable columns only.

Revision ID: 0005_agent_installers
Revises: 0004_mfa_sso
Create Date: 2026-10-19
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0005_agent_installers'
down_revision: str | None = '0004_mfa_sso'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_column(table: str, column: str) -> bool:
    return column in {c['name'] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    for name, col in (('package_platform', sa.String(length=16)), ('package_sha256', sa.String(length=64)),
                      ('device_group', sa.String(length=64))):
        if not _has_column('enrollment_tokens', name):
            op.add_column('enrollment_tokens', sa.Column(name, col, nullable=True))
    if not _has_column('devices', 'device_group'):
        op.add_column('devices', sa.Column('device_group', sa.String(length=64), nullable=True))
        op.create_index('ix_devices_device_group', 'devices', ['device_group'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_devices_device_group', table_name='devices')
    op.drop_column('devices', 'device_group')
    for name in ('device_group', 'package_sha256', 'package_platform'):
        op.drop_column('enrollment_tokens', name)
