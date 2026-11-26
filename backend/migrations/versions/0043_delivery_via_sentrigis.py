"""Notification deliveries: remember which emails went out through the Sentrigis sender.

The daily limit counts these rows, so it stays right after a channel is deleted.

Revision ID: 0043_delivery_via_sentrigis
Revises: 0042_lost_mode_support_email
Create Date: 2026-11-26 20:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0043_delivery_via_sentrigis'
down_revision: str | None = '0042_lost_mode_support_email'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('notification_deliveries') as batch_op:
        batch_op.add_column(sa.Column('via_sentrigis', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table('notification_deliveries') as batch_op:
        batch_op.drop_column('via_sentrigis')
