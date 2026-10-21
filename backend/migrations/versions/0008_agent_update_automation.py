"""Agent update automation: update mode / automatic rollout / auto-import
settings (single row), and per-device offer, "update now" and agent feature
columns (all nullable).

Revision ID: 0008_agent_update_automation
Revises: 0007_it_asset_lifecycle
Create Date: 2026-10-20
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0008_agent_update_automation'
down_revision: str | None = '0007_it_asset_lifecycle'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEVICE_COLUMNS = (
    ('update_offered_at', sa.DateTime()),
    ('update_offered_release_id', sa.String(length=32)),
    ('update_offer_jitter_seconds', sa.Integer()),
    ('update_now_requested_at', sa.DateTime()),
    ('update_now_delay_seconds', sa.Integer()),
    ('agent_features', sa.String(length=128)),
)


def upgrade() -> None:
    op.create_table('agent_update_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('mode', sa.String(length=16), nullable=False),
    sa.Column('soak_hours', sa.Integer(), nullable=False),
    sa.Column('auto_import_enabled', sa.Boolean(), nullable=True),
    sa.Column('auto_import_repo', sa.String(length=200), nullable=True),
    sa.Column('auto_import_interval_minutes', sa.Integer(), nullable=True),
    sa.Column('auto_release_id', sa.String(length=32), nullable=True),
    sa.Column('auto_stage', sa.String(length=16), nullable=True),
    sa.Column('auto_stage_at', sa.DateTime(), nullable=True),
    sa.Column('auto_paused_reason', sa.String(length=500), nullable=True),
    sa.Column('import_checked_at', sa.DateTime(), nullable=True),
    sa.Column('import_status', sa.String(length=16), nullable=True),
    sa.Column('import_message', sa.String(length=1000), nullable=True),
    sa.Column('import_failed_version', sa.String(length=64), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, col in DEVICE_COLUMNS:
            batch_op.add_column(sa.Column(name, col, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        for name, _ in reversed(DEVICE_COLUMNS):
            batch_op.drop_column(name)
    op.drop_table('agent_update_settings')
