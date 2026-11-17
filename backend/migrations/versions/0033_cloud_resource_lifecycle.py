"""Cloud resource lifecycle (app/services/cloud_lifecycle.py): `assets.missed_scans` / `assets.removed_at` and
`findings.close_reason`. Existing assets start active with no missed scans (nothing is removed at deploy time:
a resource missing today is only marked removed after it is missed by the configured number of successful scans),
and existing resolved findings keep an empty close reason.

Revision ID: 0033_cloud_resource_lifecycle
Revises: 0032_attack_surface
Create Date: 2026-11-16 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0033_cloud_resource_lifecycle'
down_revision: str | None = '0032_attack_surface'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('missed_scans', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('removed_at', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_assets_removed_at'), ['removed_at'], unique=False)
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('close_reason', sa.String(length=32), nullable=True))
        batch_op.create_index(batch_op.f('ix_findings_close_reason'), ['close_reason'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_close_reason'))
        batch_op.drop_column('close_reason')
    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_assets_removed_at'))
        batch_op.drop_column('removed_at')
        batch_op.drop_column('missed_scans')
