"""Alert notifications: channels, rules, event inbox, delivery outbox, throttle
state, digest queue and pull-source state.

NOTE for merging: chained off feature/azure-deploy's head (0001_baseline).
Other branches developed in parallel may add their own 0002_* revision; re-chain
`down_revision` so the history stays linear (the tables are independent).

Revision ID: 0002_notifications
Revises: 0001_baseline
Create Date: 2026-10-15
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002_notifications'
down_revision: str | None = '0001_baseline'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('notification_channels',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('type', sa.String(length=16), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('config', sa.JSON(), nullable=False),
    sa.Column('secret_ciphertext', sa.Text(), nullable=True),
    sa.Column('secret_hints', sa.JSON(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('last_test_at', sa.DateTime(), nullable=True),
    sa.Column('last_test_status', sa.String(length=16), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification_channels', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_channels_type'), ['type'], unique=False)

    op.create_table('notification_events',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('event_type', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('entity_id', sa.String(length=512), nullable=True),
    sa.Column('group_key', sa.String(length=255), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=True),
    sa.Column('rule_id', sa.String(length=64), nullable=True),
    sa.Column('mitre_technique_id', sa.String(length=16), nullable=True),
    sa.Column('link_path', sa.String(length=1024), nullable=True),
    sa.Column('attributes', sa.JSON(), nullable=False),
    sa.Column('processed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_events_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_notification_events_processed_at'), ['processed_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_notification_events_source'), ['source'], unique=False)

    op.create_table('notification_rules',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('sources', sa.JSON(), nullable=False),
    sa.Column('event_types', sa.JSON(), nullable=False),
    sa.Column('min_severity', sa.String(length=16), nullable=False),
    sa.Column('subscription_ids', sa.JSON(), nullable=False),
    sa.Column('asset_ids', sa.JSON(), nullable=False),
    sa.Column('asset_types', sa.JSON(), nullable=False),
    sa.Column('tags', sa.JSON(), nullable=False),
    sa.Column('rule_ids', sa.JSON(), nullable=False),
    sa.Column('mitre_techniques', sa.JSON(), nullable=False),
    sa.Column('include_status_changes', sa.Boolean(), nullable=False),
    sa.Column('channel_ids', sa.JSON(), nullable=False),
    sa.Column('throttle_minutes', sa.Integer(), nullable=False),
    sa.Column('mode', sa.String(length=16), nullable=False),
    sa.Column('digest_hour', sa.Integer(), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=False),
    sa.Column('quiet_start', sa.String(length=5), nullable=True),
    sa.Column('quiet_end', sa.String(length=5), nullable=True),
    sa.Column('quiet_bypass_severity', sa.String(length=16), nullable=True),
    sa.Column('last_digest_at', sa.DateTime(), nullable=True),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('notification_source_state',
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('state', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('source')
    )
    op.create_table('notification_deliveries',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('channel_id', sa.String(length=32), nullable=True),
    sa.Column('channel_name', sa.String(length=128), nullable=False),
    sa.Column('channel_type', sa.String(length=16), nullable=False),
    sa.Column('rule_id', sa.String(length=32), nullable=True),
    sa.Column('rule_name', sa.String(length=128), nullable=False),
    sa.Column('event_id', sa.String(length=32), nullable=True),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('message', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(), nullable=False),
    sa.Column('last_attempt_at', sa.DateTime(), nullable=True),
    sa.Column('sent_at', sa.DateTime(), nullable=True),
    sa.Column('response_status', sa.Integer(), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['rule_id'], ['notification_rules.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification_deliveries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_deliveries_channel_id'), ['channel_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_notification_deliveries_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_notification_deliveries_due', ['status', 'next_attempt_at'], unique=False)

    op.create_table('notification_digest_items',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('rule_id', sa.String(length=32), nullable=False),
    sa.Column('channel_id', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('link_path', sa.String(length=1024), nullable=True),
    sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['rule_id'], ['notification_rules.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification_digest_items', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notification_digest_items_rule_id'), ['rule_id'], unique=False)

    op.create_table('notification_throttle',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('rule_id', sa.String(length=32), nullable=False),
    sa.Column('channel_id', sa.String(length=32), nullable=False),
    sa.Column('group_key', sa.String(length=255), nullable=False),
    sa.Column('last_sent_at', sa.DateTime(), nullable=False),
    sa.Column('suppressed', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['rule_id'], ['notification_rules.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('rule_id', 'channel_id', 'group_key')
    )


def downgrade() -> None:
    op.drop_table('notification_throttle')
    with op.batch_alter_table('notification_digest_items', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_digest_items_rule_id'))

    op.drop_table('notification_digest_items')
    with op.batch_alter_table('notification_deliveries', schema=None) as batch_op:
        batch_op.drop_index('ix_notification_deliveries_due')
        batch_op.drop_index(batch_op.f('ix_notification_deliveries_created_at'))
        batch_op.drop_index(batch_op.f('ix_notification_deliveries_channel_id'))

    op.drop_table('notification_deliveries')
    op.drop_table('notification_source_state')
    op.drop_table('notification_rules')
    with op.batch_alter_table('notification_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_events_source'))
        batch_op.drop_index(batch_op.f('ix_notification_events_processed_at'))
        batch_op.drop_index(batch_op.f('ix_notification_events_created_at'))

    op.drop_table('notification_events')
    with op.batch_alter_table('notification_channels', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notification_channels_type'))

    op.drop_table('notification_channels')
