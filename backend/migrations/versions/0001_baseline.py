"""Baseline schema: inventory, findings, vulnerabilities, runtime events/alerts,
scan runs and the Phase 2 authentication tables (users, sessions, audit log).

Matches the schema `create_all()` produced before Alembic was introduced, so an
existing database without `alembic_version` is stamped at this revision (see
app.db.run_migrations).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-15
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0001_baseline'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('alerts',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('rule_id', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=True),
    sa.Column('mitre_tactic', sa.String(length=64), nullable=False),
    sa.Column('mitre_technique_id', sa.String(length=16), nullable=False),
    sa.Column('mitre_technique_name', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('event_count', sa.Integer(), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_asset_id'), 'alerts', ['asset_id'], unique=False)
    op.create_index(op.f('ix_alerts_first_seen'), 'alerts', ['first_seen'], unique=False)
    op.create_index(op.f('ix_alerts_rule_id'), 'alerts', ['rule_id'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_table('assets',
    sa.Column('id', sa.String(length=512), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('subscription_id', sa.String(length=64), nullable=True),
    sa.Column('subscription_name', sa.String(length=128), nullable=True),
    sa.Column('resource_group', sa.String(length=255), nullable=True),
    sa.Column('region', sa.String(length=64), nullable=True),
    sa.Column('tags', sa.JSON(), nullable=False),
    sa.Column('internet_exposed', sa.Boolean(), nullable=False),
    sa.Column('sensitive_data', sa.Boolean(), nullable=False),
    sa.Column('properties', sa.JSON(), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_source'), 'assets', ['source'], unique=False)
    op.create_index(op.f('ix_assets_subscription_id'), 'assets', ['subscription_id'], unique=False)
    op.create_index(op.f('ix_assets_type'), 'assets', ['type'], unique=False)
    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('actor_id', sa.String(length=32), nullable=True),
    sa.Column('actor_email', sa.String(length=320), nullable=True),
    sa.Column('target', sa.String(length=512), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_log_action'), 'audit_log', ['action'], unique=False)
    op.create_index(op.f('ix_audit_log_timestamp'), 'audit_log', ['timestamp'], unique=False)
    op.create_table('runtime_events',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=True),
    sa.Column('event_type', sa.String(length=32), nullable=False),
    sa.Column('summary', sa.String(length=512), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.Column('sensor_id', sa.String(length=128), nullable=True),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_runtime_events_asset_id'), 'runtime_events', ['asset_id'], unique=False)
    op.create_index(op.f('ix_runtime_events_event_type'), 'runtime_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_runtime_events_timestamp'), 'runtime_events', ['timestamp'], unique=False)
    op.create_table('scan_runs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('connector', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('assets_found', sa.Integer(), nullable=False),
    sa.Column('findings_open', sa.Integer(), nullable=False),
    sa.Column('errors', sa.JSON(), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_login_at', sa.DateTime(), nullable=True),
    sa.Column('failed_login_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(), nullable=True),
    sa.Column('password_changed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_table('alert_events',
    sa.Column('alert_id', sa.String(length=32), nullable=False),
    sa.Column('event_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['event_id'], ['runtime_events.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('alert_id', 'event_id')
    )
    op.create_table('findings',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('rule_id', sa.String(length=64), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=False),
    sa.Column('compliance', sa.JSON(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('rule_id', 'asset_id')
    )
    op.create_index(op.f('ix_findings_asset_id'), 'findings', ['asset_id'], unique=False)
    op.create_index(op.f('ix_findings_rule_id'), 'findings', ['rule_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_status'), 'findings', ['status'], unique=False)
    op.create_table('relationships',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('source_id', sa.String(length=512), nullable=False),
    sa.Column('target_id', sa.String(length=512), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('properties', sa.JSON(), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['source_id'], ['assets.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_id'], ['assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_id', 'target_id', 'type')
    )
    op.create_index(op.f('ix_relationships_source_id'), 'relationships', ['source_id'], unique=False)
    op.create_index(op.f('ix_relationships_target_id'), 'relationships', ['target_id'], unique=False)
    op.create_table('user_sessions',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('user_id', sa.String(length=32), nullable=False),
    sa.Column('csrf_token', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_sessions_expires_at'), 'user_sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_table('vulnerabilities',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=False),
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('package', sa.String(length=128), nullable=False),
    sa.Column('version', sa.String(length=64), nullable=False),
    sa.Column('fixed_version', sa.String(length=64), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('cvss', sa.Float(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('exploit_available', sa.Boolean(), nullable=False),
    sa.Column('in_use', sa.Boolean(), nullable=False),
    sa.Column('in_use_source', sa.String(length=16), nullable=True),
    sa.Column('in_use_last_seen', sa.DateTime(), nullable=True),
    sa.Column('internet_exposed', sa.Boolean(), nullable=False),
    sa.Column('sensitive_data_access', sa.Boolean(), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('priority', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerabilities_asset_id'), 'vulnerabilities', ['asset_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_cve_id'), 'vulnerabilities', ['cve_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_risk_score'), 'vulnerabilities', ['risk_score'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_vulnerabilities_risk_score'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_cve_id'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_asset_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_expires_at'), table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_index(op.f('ix_relationships_target_id'), table_name='relationships')
    op.drop_index(op.f('ix_relationships_source_id'), table_name='relationships')
    op.drop_table('relationships')
    op.drop_index(op.f('ix_findings_status'), table_name='findings')
    op.drop_index(op.f('ix_findings_severity'), table_name='findings')
    op.drop_index(op.f('ix_findings_rule_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_asset_id'), table_name='findings')
    op.drop_table('findings')
    op.drop_table('alert_events')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_table('scan_runs')
    op.drop_index(op.f('ix_runtime_events_timestamp'), table_name='runtime_events')
    op.drop_index(op.f('ix_runtime_events_event_type'), table_name='runtime_events')
    op.drop_index(op.f('ix_runtime_events_asset_id'), table_name='runtime_events')
    op.drop_table('runtime_events')
    op.drop_index(op.f('ix_audit_log_timestamp'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_action'), table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_index(op.f('ix_assets_type'), table_name='assets')
    op.drop_index(op.f('ix_assets_subscription_id'), table_name='assets')
    op.drop_index(op.f('ix_assets_source'), table_name='assets')
    op.drop_table('assets')
    op.drop_index(op.f('ix_alerts_status'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_rule_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_first_seen'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_asset_id'), table_name='alerts')
    op.drop_table('alerts')
