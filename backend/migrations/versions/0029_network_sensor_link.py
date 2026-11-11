"""Network devices: link to the runtime sensor's asset (network_devices.sensor_asset_id).

Revision ID: 0029_network_sensor_link
Revises: 0028_network_discovery
Create Date: 2026-11-11 09:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0029_network_sensor_link'
down_revision: str | None = '0028_network_discovery'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('network_devices') as batch:
        batch.add_column(sa.Column('sensor_asset_id', sa.String(length=512), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('network_devices') as batch:
        batch.drop_column('sensor_asset_id')
