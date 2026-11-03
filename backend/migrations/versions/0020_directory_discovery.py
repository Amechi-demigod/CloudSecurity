"""Directory discovery: directory sources (on-prem Active Directory), sync runs,
directory computers / users, discovery findings, and the domain-join facts
agents report on devices (docs/DIRECTORY_DISCOVERY.md).

Revision ID: 0020_directory_discovery
Revises: 0019_offboarding_username
Create Date: 2026-11-03
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0020_directory_discovery'
down_revision: str | None = '0019_offboarding_username'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('directory_sources',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('type', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('config', sa.JSON(), nullable=False),
    sa.Column('secret_ciphertext', sa.Text(), nullable=True),
    sa.Column('credential_hint', sa.String(length=64), nullable=True),
    sa.Column('collector_device_ids', sa.JSON(), nullable=False),
    sa.Column('last_sync_at', sa.DateTime(), nullable=True),
    sa.Column('last_sync_status', sa.String(length=16), nullable=True),
    sa.Column('last_sync_error', sa.Text(), nullable=True),
    sa.Column('last_success_at', sa.DateTime(), nullable=True),
    sa.Column('computers_count', sa.Integer(), nullable=False),
    sa.Column('users_count', sa.Integer(), nullable=False),
    sa.Column('notified_not_managed', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_directory_sources_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('directory_sources', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_directory_sources_organization_id'), ['organization_id'], unique=False)

    op.create_table('directory_sync_runs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('source_id', sa.String(length=32), nullable=False),
    sa.Column('trigger', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=True),
    sa.Column('command_id', sa.String(length=32), nullable=True),
    sa.Column('token_hash', sa.String(length=64), nullable=True),
    sa.Column('token_expires_at', sa.DateTime(), nullable=True),
    sa.Column('requested_by', sa.String(length=320), nullable=True),
    sa.Column('attempt', sa.Integer(), nullable=False),
    sa.Column('tried_device_ids', sa.JSON(), nullable=False),
    sa.Column('scopes', sa.JSON(), nullable=False),
    sa.Column('max_objects', sa.Integer(), nullable=False),
    sa.Column('queued_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('last_batch_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('next_seq', sa.Integer(), nullable=False),
    sa.Column('computers_seen', sa.Integer(), nullable=False),
    sa.Column('users_seen', sa.Integer(), nullable=False),
    sa.Column('truncated', sa.Boolean(), nullable=False),
    sa.Column('server', sa.String(length=253), nullable=True),
    sa.Column('agent_duration_ms', sa.Integer(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('sample', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_directory_sync_runs_organization_id'),
    sa.ForeignKeyConstraint(['source_id'], ['directory_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('directory_sync_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_directory_sync_runs_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_sync_runs_source_id'), ['source_id'], unique=False)
        batch_op.create_index('ix_directory_sync_runs_source_queued', ['source_id', 'queued_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_sync_runs_status'), ['status'], unique=False)

    op.create_table('directory_users',
    sa.Column('source_id', sa.String(length=32), nullable=False),
    sa.Column('sam_account_name', sa.String(length=256), nullable=False),
    sa.Column('sam_key', sa.String(length=256), nullable=False),
    sa.Column('user_principal_name', sa.String(length=256), nullable=False),
    sa.Column('mail', sa.String(length=256), nullable=False),
    sa.Column('display_name', sa.String(length=256), nullable=False),
    sa.Column('given_name', sa.String(length=256), nullable=False),
    sa.Column('surname', sa.String(length=256), nullable=False),
    sa.Column('department', sa.String(length=256), nullable=False),
    sa.Column('title', sa.String(length=256), nullable=False),
    sa.Column('manager_dn', sa.Text(), nullable=False),
    sa.Column('pwd_last_set_at', sa.DateTime(), nullable=True),
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('external_id', sa.String(length=64), nullable=False),
    sa.Column('object_sid', sa.String(length=184), nullable=True),
    sa.Column('distinguished_name', sa.Text(), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('ou', sa.Text(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('user_account_control', sa.Integer(), nullable=True),
    sa.Column('last_logon_at', sa.DateTime(), nullable=True),
    sa.Column('when_created', sa.DateTime(), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('missing_since', sa.DateTime(), nullable=True),
    sa.Column('last_run_id', sa.String(length=32), nullable=True),
    sa.Column('attributes', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_directory_users_organization_id'),
    sa.ForeignKeyConstraint(['source_id'], ['directory_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_id', 'external_id', name='uq_directory_users_source_external')
    )
    with op.batch_alter_table('directory_users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_directory_users_domain'), ['domain'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_mail'), ['mail'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_missing_since'), ['missing_since'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_object_sid'), ['object_sid'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_sam_key'), ['sam_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_source_id'), ['source_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_users_user_principal_name'), ['user_principal_name'], unique=False)

    op.create_table('directory_computers',
    sa.Column('source_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('short_name', sa.String(length=256), nullable=False),
    sa.Column('dns_hostname', sa.String(length=256), nullable=False),
    sa.Column('sam_account_name', sa.String(length=256), nullable=False),
    sa.Column('serial_number', sa.String(length=128), nullable=False),
    sa.Column('operating_system', sa.String(length=256), nullable=False),
    sa.Column('os_version', sa.String(length=256), nullable=False),
    sa.Column('when_changed', sa.DateTime(), nullable=True),
    sa.Column('match_status', sa.String(length=16), nullable=False),
    sa.Column('match_method', sa.String(length=24), nullable=True),
    sa.Column('match_confidence', sa.Integer(), nullable=True),
    sa.Column('match_candidates', sa.JSON(), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=True),
    sa.Column('it_asset_id', sa.String(length=32), nullable=True),
    sa.Column('matched_at', sa.DateTime(), nullable=True),
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('external_id', sa.String(length=64), nullable=False),
    sa.Column('object_sid', sa.String(length=184), nullable=True),
    sa.Column('distinguished_name', sa.Text(), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('ou', sa.Text(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('user_account_control', sa.Integer(), nullable=True),
    sa.Column('last_logon_at', sa.DateTime(), nullable=True),
    sa.Column('when_created', sa.DateTime(), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('missing_since', sa.DateTime(), nullable=True),
    sa.Column('last_run_id', sa.String(length=32), nullable=True),
    sa.Column('attributes', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['it_asset_id'], ['it_assets.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_directory_computers_organization_id'),
    sa.ForeignKeyConstraint(['source_id'], ['directory_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_id', 'external_id', name='uq_directory_computers_source_external')
    )
    with op.batch_alter_table('directory_computers', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_directory_computers_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_dns_hostname'), ['dns_hostname'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_domain'), ['domain'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_it_asset_id'), ['it_asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_match_status'), ['match_status'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_missing_since'), ['missing_since'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_object_sid'), ['object_sid'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_short_name'), ['short_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_computers_source_id'), ['source_id'], unique=False)

    op.create_table('directory_findings',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('key', sa.String(length=128), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('source_id', sa.String(length=32), nullable=True),
    sa.Column('computer_id', sa.String(length=32), nullable=True),
    sa.Column('user_id', sa.String(length=32), nullable=True),
    sa.Column('device_id', sa.String(length=32), nullable=True),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('ou', sa.Text(), nullable=False),
    sa.Column('os', sa.String(length=256), nullable=False),
    sa.Column('last_logon_at', sa.DateTime(), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.Column('detail', sa.String(length=500), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_evaluated_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['computer_id'], ['directory_computers.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_directory_findings_organization_id'),
    sa.ForeignKeyConstraint(['source_id'], ['directory_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['directory_users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'key', name='uq_directory_findings_org_key')
    )
    with op.batch_alter_table('directory_findings', schema=None) as batch_op:
        batch_op.create_index('ix_directory_findings_org_type', ['organization_id', 'type'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_findings_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_findings_source_id'), ['source_id'], unique=False)

    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('directory_join', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('ad_domain', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('ad_computer_sid', sa.String(length=184), nullable=True))
        batch_op.add_column(sa.Column('entra_device_id', sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f('ix_devices_ad_computer_sid'), ['ad_computer_sid'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_ad_domain'), ['ad_domain'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_entra_device_id'), ['entra_device_id'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_entra_device_id'))
        batch_op.drop_index(batch_op.f('ix_devices_ad_domain'))
        batch_op.drop_index(batch_op.f('ix_devices_ad_computer_sid'))
        batch_op.drop_column('entra_device_id')
        batch_op.drop_column('ad_computer_sid')
        batch_op.drop_column('ad_domain')
        batch_op.drop_column('directory_join')

    with op.batch_alter_table('directory_findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_findings_source_id'))
        batch_op.drop_index(batch_op.f('ix_directory_findings_organization_id'))
        batch_op.drop_index('ix_directory_findings_org_type')

    op.drop_table('directory_findings')
    with op.batch_alter_table('directory_computers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_computers_source_id'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_short_name'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_organization_id'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_object_sid'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_missing_since'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_match_status'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_it_asset_id'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_domain'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_dns_hostname'))
        batch_op.drop_index(batch_op.f('ix_directory_computers_device_id'))

    op.drop_table('directory_computers')
    with op.batch_alter_table('directory_users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_users_user_principal_name'))
        batch_op.drop_index(batch_op.f('ix_directory_users_source_id'))
        batch_op.drop_index(batch_op.f('ix_directory_users_sam_key'))
        batch_op.drop_index(batch_op.f('ix_directory_users_organization_id'))
        batch_op.drop_index(batch_op.f('ix_directory_users_object_sid'))
        batch_op.drop_index(batch_op.f('ix_directory_users_missing_since'))
        batch_op.drop_index(batch_op.f('ix_directory_users_mail'))
        batch_op.drop_index(batch_op.f('ix_directory_users_domain'))

    op.drop_table('directory_users')
    with op.batch_alter_table('directory_sync_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_sync_runs_status'))
        batch_op.drop_index('ix_directory_sync_runs_source_queued')
        batch_op.drop_index(batch_op.f('ix_directory_sync_runs_source_id'))
        batch_op.drop_index(batch_op.f('ix_directory_sync_runs_organization_id'))

    op.drop_table('directory_sync_runs')
    with op.batch_alter_table('directory_sources', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_sources_organization_id'))

    op.drop_table('directory_sources')
