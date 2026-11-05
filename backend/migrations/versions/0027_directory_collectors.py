"""Dedicated directory collectors (docs/DIRECTORY_DISCOVERY.md#dedicated-collectors):
the collector identity class (directory_collectors) with its own command queue
(collector_commands), collector enrollment tokens (enrollment_tokens.kind),
dedicated collectors of a source (directory_sources.collector_ids; existing
sources keep their endpoint-agent collectors as "legacy"), the collector of a
run, and the signed collector binaries imported with agent releases.

Revision ID: 0027_directory_collectors
Revises: 0026_device_classification
Create Date: 2026-11-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0027_directory_collectors'
down_revision: str | None = '0026_device_classification'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('collector_releases',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('version', sa.String(length=64), nullable=False),
    sa.Column('agent_release_id', sa.String(length=32), nullable=True),
    sa.Column('manifest_envelope', sa.Text(), nullable=False),
    sa.Column('key_id', sa.String(length=64), nullable=False),
    sa.Column('imported_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['agent_release_id'], ['agent_releases.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('collector_releases', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_collector_releases_agent_release_id'), ['agent_release_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_collector_releases_version'), ['version'], unique=True)

    op.create_table('directory_collectors',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('secret_hash', sa.String(length=64), nullable=False),
    sa.Column('machine_id', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('dns_hostname', sa.String(length=255), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=False),
    sa.Column('os_family', sa.String(length=16), nullable=False),
    sa.Column('os_name', sa.String(length=128), nullable=False),
    sa.Column('os_version', sa.String(length=64), nullable=False),
    sa.Column('architecture', sa.String(length=16), nullable=False),
    sa.Column('version', sa.String(length=64), nullable=False),
    sa.Column('run_as', sa.String(length=256), nullable=False),
    sa.Column('run_as_kind', sa.String(length=24), nullable=False),
    sa.Column('is_domain_controller', sa.Boolean(), nullable=False),
    sa.Column('features', sa.String(length=256), nullable=False),
    sa.Column('enrolled_at', sa.DateTime(), nullable=False),
    sa.Column('enrollment_token_id', sa.String(length=32), nullable=True),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.Column('last_heartbeat_at', sa.DateTime(), nullable=True),
    sa.Column('last_ip', sa.String(length=64), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('offline_notified_at', sa.DateTime(), nullable=True),
    sa.Column('update_offered_version', sa.String(length=64), nullable=True),
    sa.Column('update_status', sa.String(length=16), nullable=True),
    sa.Column('update_status_detail', sa.String(length=500), nullable=True),
    sa.Column('update_status_at', sa.DateTime(), nullable=True),
    sa.Column('diagnostics', sa.JSON(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_directory_collectors_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('secret_hash')
    )
    with op.batch_alter_table('directory_collectors', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_directory_collectors_last_seen_at'), ['last_seen_at'], unique=False)
        batch_op.create_index('ix_directory_collectors_org_machine', ['organization_id', 'machine_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_collectors_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_directory_collectors_status'), ['status'], unique=False)

    op.create_table('collector_commands',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('collector_id', sa.String(length=32), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('nonce', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('requested_by_email', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('delivered_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('output', sa.Text(), nullable=False),
    sa.Column('result_data', sa.JSON(), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['collector_id'], ['directory_collectors.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_collector_commands_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('collector_commands', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_collector_commands_collector_id'), ['collector_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_collector_commands_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_collector_commands_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_collector_commands_status'), ['status'], unique=False)

    op.create_table('collector_release_artifacts',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('release_id', sa.String(length=32), nullable=False),
    sa.Column('os', sa.String(length=16), nullable=False),
    sa.Column('arch', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.ForeignKeyConstraint(['release_id'], ['collector_releases.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('release_id', 'os', 'arch', name='uq_collector_release_artifact_platform')
    )
    with op.batch_alter_table('collector_release_artifacts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_collector_release_artifacts_release_id'), ['release_id'], unique=False)

    with op.batch_alter_table('directory_sources', schema=None) as batch_op:
        batch_op.add_column(sa.Column('collector_ids', sa.JSON(), server_default='[]', nullable=False))

    with op.batch_alter_table('directory_sync_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('collector_id', sa.String(length=32), nullable=True))
        batch_op.create_foreign_key('fk_directory_sync_runs_collector_id', 'directory_collectors', ['collector_id'],
                                    ['id'], ondelete='SET NULL')

    with op.batch_alter_table('enrollment_tokens', schema=None) as batch_op:
        batch_op.add_column(sa.Column('kind', sa.String(length=16), server_default='agent', nullable=False))



def downgrade() -> None:
    with op.batch_alter_table('enrollment_tokens', schema=None) as batch_op:
        batch_op.drop_column('kind')

    with op.batch_alter_table('directory_sync_runs', schema=None) as batch_op:
        batch_op.drop_constraint('fk_directory_sync_runs_collector_id', type_='foreignkey')
        batch_op.drop_column('collector_id')

    with op.batch_alter_table('directory_sources', schema=None) as batch_op:
        batch_op.drop_column('collector_ids')

    with op.batch_alter_table('collector_release_artifacts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_collector_release_artifacts_release_id'))

    op.drop_table('collector_release_artifacts')
    with op.batch_alter_table('collector_commands', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_collector_commands_status'))
        batch_op.drop_index(batch_op.f('ix_collector_commands_organization_id'))
        batch_op.drop_index(batch_op.f('ix_collector_commands_created_at'))
        batch_op.drop_index(batch_op.f('ix_collector_commands_collector_id'))

    op.drop_table('collector_commands')
    with op.batch_alter_table('directory_collectors', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_collectors_status'))
        batch_op.drop_index(batch_op.f('ix_directory_collectors_organization_id'))
        batch_op.drop_index('ix_directory_collectors_org_machine')
        batch_op.drop_index(batch_op.f('ix_directory_collectors_last_seen_at'))

    op.drop_table('directory_collectors')
    with op.batch_alter_table('collector_releases', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_collector_releases_version'))
        batch_op.drop_index(batch_op.f('ix_collector_releases_agent_release_id'))

    op.drop_table('collector_releases')
