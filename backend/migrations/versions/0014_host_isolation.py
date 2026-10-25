"""Host isolation state on devices.

Revision ID: 0014_host_isolation
Revises: 0013_organizations
Create Date: 2026-10-25
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0014_host_isolation'
down_revision: str | None = '0013_organizations'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEVICE_COLUMNS = (
    ('isolation_status', sa.String(length=16)),
    ('isolation_since', sa.DateTime()),
    ('isolation_by', sa.String(length=320)),
)


def upgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, col in DEVICE_COLUMNS:
            batch_op.add_column(sa.Column(name, col, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, _ in reversed(DEVICE_COLUMNS):
            batch_op.drop_column(name)
