"""Multi-tenant organisations (docs/MULTI_TENANCY.md).

* New tables: organizations, organization_memberships, ingest_tokens,
  connector_configs.
* Every tenant-owned table gets organization_id (NOT NULL, indexed, FK to
  organizations); all existing rows go to the default organisation (id
  "default", name from DEFAULT_ORG_NAME), so an upgraded installation keeps
  working with zero manual steps.
* Natural / client-supplied keys become unique per organisation:
  assets and runtime_events get the composite primary key
  (organization_id, id) and the rows referencing them composite foreign keys;
  uniqueness of findings (rule, asset), relationships (edge), vulnerability
  match state, update ring names and IT asset tags includes the organisation.
* Single-row settings tables (scan schedule, agent update automation, IT asset
  settings) and notification source state are keyed by organisation.
* User roles move to memberships of the default organisation (users.role is
  dropped); users get is_platform_admin; login sessions record their
  organisation.

Revision ID: 0013_organizations
Revises: 0011_vulnerability_matching
Create Date: 2026-10-24
"""
from __future__ import annotations

import os
import warnings
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = '0013_organizations'
down_revision: str | None = '0011_vulnerability_matching'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT = 'default'
# Names batch mode gives to the unnamed constraints it reflects on SQLite.
CONVENTION = {"uq": "uq_%(table_name)s_%(column_0_N_name)s",
              "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}

# Tenant tables whose organization_id is an ordinary indexed column.
INDEXED = (
    'relationships', 'findings', 'vulnerabilities', 'asset_packages', 'vuln_match_state', 'alert_events', 'alerts',
    'scan_runs', 'audit_log', 'enrollment_tokens', 'devices', 'device_credentials', 'device_posture_snapshots',
    'device_software', 'device_commands', 'device_approvals', 'device_log_bundles', 'agent_update_rings',
    'agent_update_events', 'notification_channels', 'notification_rules', 'notification_events',
    'notification_deliveries', 'notification_throttle', 'notification_digest_items', 'it_assets', 'it_asset_events',
    'it_asset_offboardings', 'it_asset_certificates',
)
# Tenant tables where organization_id is part of the primary key (no extra index).
PRIMARY_KEYS = {
    'assets': ['organization_id', 'id'],
    'runtime_events': ['organization_id', 'id'],
    'scan_schedule_settings': ['organization_id'],
    'agent_update_settings': ['organization_id'],
    'it_asset_settings': ['organization_id'],
    'notification_source_state': ['organization_id', 'source'],
}
SINGLETONS = ('scan_schedule_settings', 'agent_update_settings', 'it_asset_settings')
# Unique constraints that now include the organisation: table -> (old columns, new name, new columns)
UNIQUES = {
    'relationships': (['source_id', 'target_id', 'type'], 'uq_relationships_edge',
                      ['organization_id', 'source_id', 'target_id', 'type']),
    'findings': (['rule_id', 'asset_id'], 'uq_findings_rule_asset', ['organization_id', 'rule_id', 'asset_id']),
    'vuln_match_state': (['target_type', 'target_id'], 'uq_vuln_match_target',
                         ['organization_id', 'target_type', 'target_id']),
    'agent_update_rings': (['name'], 'uq_agent_update_rings_org_name', ['organization_id', 'name']),
    'it_assets': (['asset_tag'], 'uq_it_assets_org_asset_tag', ['organization_id', 'asset_tag']),
}
# Foreign keys to assets / runtime_events that become composite: (table, column, parent, name)
COMPOSITE_FKS = (
    ('relationships', 'source_id', 'assets', 'fk_relationships_source_asset'),
    ('relationships', 'target_id', 'assets', 'fk_relationships_target_asset'),
    ('findings', 'asset_id', 'assets', 'fk_findings_asset'),
    ('vulnerabilities', 'asset_id', 'assets', 'fk_vulnerabilities_asset'),
    ('asset_packages', 'asset_id', 'assets', 'fk_asset_packages_asset'),
    ('alert_events', 'event_id', 'runtime_events', 'fk_alert_events_event'),
)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _sqlite() -> bool:
    return op.get_bind().dialect.name == 'sqlite'


def _insp():
    return sa.inspect(op.get_bind())


def _fk_name(table: str, column: str, parent: str) -> str | None:
    for fk in _insp().get_foreign_keys(table):
        if fk['referred_table'] == parent and fk['constrained_columns'] == [column]:
            return fk.get('name') or CONVENTION['fk'] % {
                'table_name': table, 'column_0_name': column, 'referred_table_name': parent}
    return None


def _uq_name(table: str, columns: list[str]) -> str | None:
    for uq in _insp().get_unique_constraints(table):
        if list(uq['column_names']) == columns:
            return uq.get('name') or CONVENTION['uq'] % {
                'table_name': table, 'column_0_N_name': '_'.join(columns)}
    return None


def _pk_name(table: str) -> str:
    return _insp().get_pk_constraint(table).get('name') or f'{table}_pkey'


@contextmanager
def _quiet_pk_change():
    """SQLite batch mode reflects the old primary key and warns that the new one
    replaces it: that is the intent here."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*primary_key=True, not matching locally specified columns.*")
        yield


def _batch(table: str):
    return op.batch_alter_table(table, recreate='auto', naming_convention=CONVENTION)


def upgrade() -> None:
    op.create_table('organizations',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('slug', sa.String(length=64), nullable=False),
    sa.Column('contact_email', sa.String(length=320), nullable=True),
    sa.Column('logo_url', sa.String(length=1024), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('plan', sa.String(length=32), nullable=True),
    sa.Column('max_users', sa.Integer(), nullable=True),
    sa.Column('max_devices', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('suspended_at', sa.DateTime(), nullable=True),
    sa.Column('suspended_reason', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_organizations_slug'), ['slug'], unique=True)
        batch_op.create_index(batch_op.f('ix_organizations_status'), ['status'], unique=False)

    now = _now()
    name = (os.getenv('DEFAULT_ORG_NAME') or 'Default organisation').strip()[:128]
    orgs = sa.table('organizations', sa.column('id'), sa.column('name'), sa.column('slug'), sa.column('status'),
                    sa.column('is_default'), sa.column('created_at'), sa.column('updated_at'),
                    sa.column('created_by'))
    op.bulk_insert(orgs, [{'id': DEFAULT, 'name': name, 'slug': DEFAULT, 'status': 'active', 'is_default': True,
                           'created_at': now, 'updated_at': now, 'created_by': 'migration'}])

    op.create_table('organization_memberships',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.String(length=32), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'],
                            name='fk_organization_memberships_organization_id'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'user_id', name='uq_organization_memberships_org_user')
    )
    with op.batch_alter_table('organization_memberships', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_organization_memberships_organization_id'), ['organization_id'],
                              unique=False)
        batch_op.create_index(batch_op.f('ix_organization_memberships_user_id'), ['user_id'], unique=False)

    op.create_table('ingest_tokens',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('token_prefix', sa.String(length=16), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_used_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_ingest_tokens_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )
    with op.batch_alter_table('ingest_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ingest_tokens_organization_id'), ['organization_id'], unique=False)

    op.create_table('connector_configs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('config', sa.JSON(), nullable=False),
    sa.Column('secret_ciphertext', sa.Text(), nullable=True),
    sa.Column('secret_hints', sa.JSON(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_connector_configs_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('organization_id', 'provider', name='uq_connector_configs_org_provider')
    )
    with op.batch_alter_table('connector_configs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_connector_configs_organization_id'), ['organization_id'], unique=False)

    # --- users: roles become memberships of the default organisation ---------------------
    op.execute(sa.text("INSERT INTO organization_memberships (organization_id, user_id, role, created_at) "
                       "SELECT 'default', id, role, created_at FROM users"))
    with _batch('users') as batch_op:
        batch_op.add_column(sa.Column('is_platform_admin', sa.Boolean(), nullable=False,
                                      server_default=sa.false()))
        batch_op.drop_column('role')
    with _batch('users') as batch_op:
        batch_op.alter_column('is_platform_admin', existing_type=sa.Boolean(), server_default=None)

    op.add_column('user_sessions', sa.Column('organization_id', sa.String(length=32), nullable=True))
    op.execute(sa.text("UPDATE user_sessions SET organization_id = :org").bindparams(org=DEFAULT))
    with _batch('user_sessions') as batch_op:
        batch_op.alter_column('organization_id', existing_type=sa.String(length=32), nullable=False)
        batch_op.create_index(batch_op.f('ix_user_sessions_organization_id'), ['organization_id'], unique=False)
        batch_op.create_foreign_key('fk_user_sessions_organization_id', 'organizations', ['organization_id'], ['id'],
                                    ondelete='CASCADE')

    # --- organization_id on every tenant table, existing rows -> default ----------------
    for table in (*PRIMARY_KEYS, *INDEXED):
        op.add_column(table, sa.Column('organization_id', sa.String(length=32), nullable=True))
        op.execute(sa.text(f"UPDATE {table} SET organization_id = :org").bindparams(org=DEFAULT))  # noqa: S608

    # Old single-column foreign keys to assets / runtime_events go first (their
    # parents' primary keys change).
    old_fks = {(t, c): _fk_name(t, c, parent) for t, c, parent, _ in COMPOSITE_FKS}
    for (table, _column), fk in old_fks.items():
        if fk:
            with _batch(table) as batch_op:
                batch_op.drop_constraint(fk, type_='foreignkey')

    # Primary keys that include the organisation.
    for table, cols in PRIMARY_KEYS.items():
        pk = _pk_name(table)
        with _quiet_pk_change(), _batch(table) as batch_op:
            batch_op.alter_column('organization_id', existing_type=sa.String(length=32), nullable=False)
            if not _sqlite():
                batch_op.drop_constraint(pk, type_='primary')
            if table in SINGLETONS:
                batch_op.drop_column('id')
            batch_op.create_primary_key(pk if not _sqlite() else f'{table}_pkey', cols)
            batch_op.create_foreign_key(f'fk_{table}_organization_id', 'organizations', ['organization_id'], ['id'])

    for table in INDEXED:
        uq = UNIQUES.get(table)
        old_uq = _uq_name(table, uq[0]) if uq else None
        with _batch(table) as batch_op:
            batch_op.alter_column('organization_id', existing_type=sa.String(length=32), nullable=False)
            batch_op.create_index(batch_op.f(f'ix_{table}_organization_id'), ['organization_id'], unique=False)
            batch_op.create_foreign_key(f'fk_{table}_organization_id', 'organizations', ['organization_id'], ['id'])
            if uq:
                if old_uq:
                    batch_op.drop_constraint(old_uq, type_='unique')
                batch_op.create_unique_constraint(uq[1], uq[2])

    for table, column, parent, name in COMPOSITE_FKS:
        with _batch(table) as batch_op:
            batch_op.create_foreign_key(name, parent, ['organization_id', column], ['organization_id', 'id'],
                                        ondelete='CASCADE')


def downgrade() -> None:
    """Back to a single organisation: everything that is not the default
    organisation's is deleted (it cannot be represented without the column)."""
    for table, _column, _parent, name in COMPOSITE_FKS:
        with _batch(table) as batch_op:
            batch_op.drop_constraint(name, type_='foreignkey')
    for table in (*PRIMARY_KEYS, *INDEXED, 'user_sessions'):
        op.execute(sa.text(f"DELETE FROM {table} WHERE organization_id <> :org").bindparams(org=DEFAULT))  # noqa: S608

    for table in INDEXED:
        uq = UNIQUES.get(table)
        with _batch(table) as batch_op:
            if uq:
                batch_op.drop_constraint(uq[1], type_='unique')
                batch_op.create_unique_constraint(f"{table}_{'_'.join(uq[0])}_key", uq[0])
            batch_op.drop_constraint(f'fk_{table}_organization_id', type_='foreignkey')
            batch_op.drop_index(batch_op.f(f'ix_{table}_organization_id'))
            batch_op.drop_column('organization_id')

    for table in PRIMARY_KEYS:
        old = ['source'] if table == 'notification_source_state' else ['id']
        pk = _pk_name(table)
        if table in SINGLETONS:
            with _batch(table) as batch_op:
                batch_op.add_column(sa.Column('id', sa.Integer(), nullable=True))
            op.execute(sa.text(f"UPDATE {table} SET id = 1"))  # noqa: S608 - one row left (default organisation)
        with _quiet_pk_change(), _batch(table) as batch_op:
            batch_op.drop_constraint(f'fk_{table}_organization_id', type_='foreignkey')
            if not _sqlite():
                batch_op.drop_constraint(pk, type_='primary')
            if table in SINGLETONS:
                batch_op.alter_column('id', existing_type=sa.Integer(), nullable=False)
            batch_op.create_primary_key(pk if not _sqlite() else f'{table}_pkey', old)
            batch_op.drop_column('organization_id')

    for table, column, parent, _name in COMPOSITE_FKS:
        with _batch(table) as batch_op:
            batch_op.create_foreign_key(f'{table}_{column}_fkey', parent, [column], ['id'],
                                        ondelete='CASCADE')

    with _batch('user_sessions') as batch_op:
        batch_op.drop_constraint('fk_user_sessions_organization_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_user_sessions_organization_id'))
        batch_op.drop_column('organization_id')

    # Accounts of other organisations must not become default-organisation users.
    op.execute(sa.text("UPDATE users SET is_active = :f WHERE id NOT IN (SELECT user_id FROM "
                       "organization_memberships WHERE organization_id = :org)").bindparams(f=False, org=DEFAULT))
    with _batch('users') as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=16), nullable=True))
        batch_op.drop_column('is_platform_admin')
    op.execute(sa.text("UPDATE users SET role = COALESCE((SELECT m.role FROM organization_memberships m "
                       "WHERE m.user_id = users.id AND m.organization_id = :org), 'viewer')").bindparams(org=DEFAULT))
    with _batch('users') as batch_op:
        batch_op.alter_column('role', existing_type=sa.String(length=16), nullable=False)

    with op.batch_alter_table('connector_configs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_connector_configs_organization_id'))
    op.drop_table('connector_configs')
    with op.batch_alter_table('ingest_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ingest_tokens_organization_id'))
    op.drop_table('ingest_tokens')
    with op.batch_alter_table('organization_memberships', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_organization_memberships_user_id'))
        batch_op.drop_index(batch_op.f('ix_organization_memberships_organization_id'))
    op.drop_table('organization_memberships')
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_organizations_status'))
        batch_op.drop_index(batch_op.f('ix_organizations_slug'))
    op.drop_table('organizations')
