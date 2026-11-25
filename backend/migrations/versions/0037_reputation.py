"""Reputation checks of verified domains (app/external/reputation).

Revision ID: 0037_reputation
Revises: 0036_msp_partners
Create Date: 2026-11-25 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0037_reputation'
down_revision: str | None = '0036_msp_partners'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('reputation_runs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('trigger', sa.String(length=12), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('started_by', sa.String(length=320), nullable=True),
    sa.Column('domains', sa.JSON(), nullable=False),
    sa.Column('findings_open', sa.Integer(), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_reputation_runs_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reputation_runs_organization_id'), 'reputation_runs', ['organization_id'], unique=False)
    op.create_index(op.f('ix_reputation_runs_started_at'), 'reputation_runs', ['started_at'], unique=False)
    op.create_table('reputation_domains',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('score', sa.Integer(), nullable=True),
    sa.Column('grade', sa.String(length=2), nullable=True),
    sa.Column('counts', sa.JSON(), nullable=False),
    sa.Column('details', sa.JSON(), nullable=False),
    sa.Column('known_issuers', sa.JSON(), nullable=False),
    sa.Column('last_run_id', sa.String(length=32), nullable=True),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_reputation_domains_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'domain', name='uq_reputation_domains_org_domain')
    )
    op.create_index(op.f('ix_reputation_domains_organization_id'), 'reputation_domains', ['organization_id'], unique=False)
    op.create_table('reputation_findings',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=400), nullable=False),
    sa.Column('check_id', sa.String(length=48), nullable=False),
    sa.Column('category', sa.String(length=16), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('severity', sa.String(length=12), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('status_note', sa.String(length=1000), nullable=True),
    sa.Column('status_by', sa.String(length=320), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('last_run_id', sa.String(length=32), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_reputation_findings_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'key', name='uq_reputation_findings_org_key'),
    sa.UniqueConstraint('organization_id', 'seq', name='uq_reputation_findings_org_seq')
    )
    op.create_index(op.f('ix_reputation_findings_category'), 'reputation_findings', ['category'], unique=False)
    op.create_index(op.f('ix_reputation_findings_check_id'), 'reputation_findings', ['check_id'], unique=False)
    op.create_index(op.f('ix_reputation_findings_domain'), 'reputation_findings', ['domain'], unique=False)
    op.create_index(op.f('ix_reputation_findings_organization_id'), 'reputation_findings', ['organization_id'], unique=False)
    op.create_index(op.f('ix_reputation_findings_severity'), 'reputation_findings', ['severity'], unique=False)
    op.create_index(op.f('ix_reputation_findings_status'), 'reputation_findings', ['status'], unique=False)


def downgrade() -> None:
    op.drop_table('reputation_findings')
    op.drop_table('reputation_domains')
    op.drop_table('reputation_runs')
