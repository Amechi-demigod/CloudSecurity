"""Executive report subscriptions and recipients (app/executive).

Revision ID: 0038_executive_reports
Revises: 0037_reputation
Create Date: 2026-11-25 14:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0038_executive_reports'
down_revision: str | None = '0037_reputation'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('executive_report_subscriptions',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('frequency', sa.String(length=16), nullable=False),
    sa.Column('day', sa.Integer(), nullable=False),
    sa.Column('hour', sa.Integer(), nullable=False),
    sa.Column('next_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_status', sa.String(length=16), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_executive_report_subscriptions_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_executive_report_subscriptions_next_run_at'), 'executive_report_subscriptions', ['next_run_at'], unique=False)
    op.create_index(op.f('ix_executive_report_subscriptions_organization_id'), 'executive_report_subscriptions', ['organization_id'], unique=False)
    op.create_table('executive_report_recipients',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('subscription_id', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=8), nullable=False),
    sa.Column('user_id', sa.String(length=32), nullable=True),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('job_title', sa.String(length=120), nullable=True),
    sa.Column('unsubscribed_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_executive_report_recipients_organization_id'),
    sa.ForeignKeyConstraint(['subscription_id'], ['executive_report_subscriptions.id'], name='fk_exec_report_recipients_subscription_id', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('subscription_id', 'email', name='uq_exec_report_recipients_sub_email')
    )
    op.create_index(op.f('ix_executive_report_recipients_organization_id'), 'executive_report_recipients', ['organization_id'], unique=False)
    op.create_index(op.f('ix_executive_report_recipients_subscription_id'), 'executive_report_recipients', ['subscription_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_executive_report_recipients_subscription_id'), table_name='executive_report_recipients')
    op.drop_index(op.f('ix_executive_report_recipients_organization_id'), table_name='executive_report_recipients')
    op.drop_table('executive_report_recipients')
    op.drop_index(op.f('ix_executive_report_subscriptions_organization_id'), table_name='executive_report_subscriptions')
    op.drop_index(op.f('ix_executive_report_subscriptions_next_run_at'), table_name='executive_report_subscriptions')
    op.drop_table('executive_report_subscriptions')
