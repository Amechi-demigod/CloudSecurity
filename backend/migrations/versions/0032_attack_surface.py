"""Attack surface & pre-ASV module (app/external): targets, scans, hosts, findings, disputes, reports. Existing
organisations do NOT get the new `external` product module (they never bought it): their explicit module list
from 0031 is left as it is.

Revision ID: 0032_attack_surface
Revises: 0031_org_modules
Create Date: 2026-11-15 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0032_attack_surface'
down_revision: str | None = '0031_org_modules'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('external_targets',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=8), nullable=False),
    sa.Column('value', sa.String(length=255), nullable=False),
    sa.Column('token', sa.String(length=64), nullable=False),
    sa.Column('verified_method', sa.String(length=16), nullable=True),
    sa.Column('verified_at', sa.DateTime(), nullable=True),
    sa.Column('verified_detail', sa.String(length=255), nullable=True),
    sa.Column('last_check_at', sa.DateTime(), nullable=True),
    sa.Column('last_check_error', sa.String(length=255), nullable=True),
    sa.Column('attested_by', sa.String(length=320), nullable=True),
    sa.Column('attested_at', sa.DateTime(), nullable=True),
    sa.Column('attestation', sa.String(length=1000), nullable=True),
    sa.Column('approval_status', sa.String(length=12), nullable=False),
    sa.Column('approval_note', sa.String(length=1000), nullable=True),
    sa.Column('approved_by', sa.String(length=320), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('default_password_checks', sa.Boolean(), nullable=False),
    sa.Column('consent_by', sa.String(length=320), nullable=True),
    sa.Column('consent_at', sa.DateTime(), nullable=True),
    sa.Column('window_start_hour', sa.Integer(), nullable=True),
    sa.Column('window_end_hour', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_targets_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'value', name='uq_external_targets_org_value')
    )
    op.create_index(op.f('ix_external_targets_organization_id'), 'external_targets', ['organization_id'], unique=False)
    op.create_table('external_settings',
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('scope_text', sa.Text(), nullable=False),
    sa.Column('scope_confirmed_by', sa.String(length=320), nullable=True),
    sa.Column('scope_confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('schedule_enabled', sa.Boolean(), nullable=False),
    sa.Column('interval_hours', sa.Float(), nullable=False),
    sa.Column('next_finding_seq', sa.Integer(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_settings_organization_id'),
    sa.PrimaryKeyConstraint('organization_id')
    )
    op.create_table('external_scans',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('trigger', sa.String(length=12), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('started_by', sa.String(length=320), nullable=True),
    sa.Column('scanner_ip', sa.String(length=64), nullable=True),
    sa.Column('hosts', sa.Integer(), nullable=False),
    sa.Column('open_ports', sa.Integer(), nullable=False),
    sa.Column('new_hosts', sa.Integer(), nullable=False),
    sa.Column('findings_open', sa.Integer(), nullable=False),
    sa.Column('result', sa.String(length=8), nullable=True),
    sa.Column('targets', sa.JSON(), nullable=False),
    sa.Column('skipped', sa.JSON(), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_scans_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_external_scans_organization_id'), 'external_scans', ['organization_id'], unique=False)
    op.create_index(op.f('ix_external_scans_started_at'), 'external_scans', ['started_at'], unique=False)
    op.create_table('external_hosts',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('host', sa.String(length=255), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('target_id', sa.String(length=32), nullable=True),
    sa.Column('dns', sa.JSON(), nullable=False),
    sa.Column('ports', sa.JSON(), nullable=False),
    sa.Column('tls', sa.JSON(), nullable=False),
    sa.Column('software', sa.JSON(), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('last_scan_id', sa.String(length=32), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_hosts_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'host', name='uq_external_hosts_org_host')
    )
    op.create_index(op.f('ix_external_hosts_ip'), 'external_hosts', ['ip'], unique=False)
    op.create_index(op.f('ix_external_hosts_organization_id'), 'external_hosts', ['organization_id'], unique=False)
    op.create_table('external_findings',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=400), nullable=False),
    sa.Column('check_id', sa.String(length=48), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('severity', sa.String(length=12), nullable=False),
    sa.Column('cvss', sa.Float(), nullable=False),
    sa.Column('vector', sa.String(length=80), nullable=True),
    sa.Column('cwe', sa.String(length=16), nullable=True),
    sa.Column('cve_id', sa.String(length=32), nullable=True),
    sa.Column('host', sa.String(length=255), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('port', sa.Integer(), nullable=True),
    sa.Column('url', sa.String(length=1024), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('auto_fail', sa.Boolean(), nullable=False),
    sa.Column('dos_only', sa.Boolean(), nullable=False),
    sa.Column('special_note', sa.String(length=24), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('status_note', sa.String(length=1000), nullable=True),
    sa.Column('status_by', sa.String(length=320), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('last_scan_id', sa.String(length=32), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_findings_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'key', name='uq_external_findings_org_key'),
    sa.UniqueConstraint('organization_id', 'seq', name='uq_external_findings_org_seq')
    )
    op.create_index(op.f('ix_external_findings_check_id'), 'external_findings', ['check_id'], unique=False)
    op.create_index(op.f('ix_external_findings_host'), 'external_findings', ['host'], unique=False)
    op.create_index(op.f('ix_external_findings_organization_id'), 'external_findings', ['organization_id'], unique=False)
    op.create_index(op.f('ix_external_findings_severity'), 'external_findings', ['severity'], unique=False)
    op.create_index(op.f('ix_external_findings_status'), 'external_findings', ['status'], unique=False)
    op.create_table('external_disputes',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('finding_id', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=24), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('submitted_by', sa.String(length=320), nullable=False),
    sa.Column('submitted_at', sa.DateTime(), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('reviewed_by', sa.String(length=320), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(), nullable=True),
    sa.Column('review_note', sa.String(length=1000), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['external_findings.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_disputes_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_external_disputes_finding_id'), 'external_disputes', ['finding_id'], unique=False)
    op.create_index(op.f('ix_external_disputes_organization_id'), 'external_disputes', ['organization_id'], unique=False)
    op.create_index(op.f('ix_external_disputes_status'), 'external_disputes', ['status'], unique=False)
    op.create_table('external_reports',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('scan_id', sa.String(length=32), nullable=True),
    sa.Column('generated_at', sa.DateTime(), nullable=False),
    sa.Column('generated_by', sa.String(length=320), nullable=True),
    sa.Column('result', sa.String(length=8), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_external_reports_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_external_reports_generated_at'), 'external_reports', ['generated_at'], unique=False)
    op.create_index(op.f('ix_external_reports_organization_id'), 'external_reports', ['organization_id'], unique=False)


def downgrade() -> None:
    op.drop_table('external_reports')
    op.drop_table('external_disputes')
    op.drop_table('external_findings')
    op.drop_table('external_hosts')
    op.drop_table('external_scans')
    op.drop_table('external_settings')
    op.drop_table('external_targets')
