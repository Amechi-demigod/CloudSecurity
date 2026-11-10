"""Network discovery (docs/NETWORK_DISCOVERY.md): scans, SNMP credentials, scan runs, discovered network
devices with their ports, interfaces, switch forwarding tables and history, and vulnerabilities.network_device_id
(a CVE belongs to exactly one of asset / device / network device).

Revision ID: 0028_network_discovery
Revises: 0027_directory_collectors
Create Date: 2026-11-10 14:55:48.302092
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0028_network_discovery'
down_revision: str | None = '0027_directory_collectors'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('network_snmp_credentials',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('version', sa.String(length=4), nullable=False),
    sa.Column('username', sa.String(length=128), nullable=False),
    sa.Column('level', sa.String(length=16), nullable=False),
    sa.Column('auth_proto', sa.String(length=8), nullable=False),
    sa.Column('priv_proto', sa.String(length=8), nullable=False),
    sa.Column('secret_ciphertext', sa.Text(), nullable=True),
    sa.Column('hint', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_snmp_credentials_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('network_snmp_credentials', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_snmp_credentials_organization_id'), ['organization_id'], unique=False)

    op.create_table('network_scans',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('collector_id', sa.String(length=32), nullable=True),
    sa.Column('targets', sa.JSON(), nullable=False),
    sa.Column('exclude', sa.JSON(), nullable=False),
    sa.Column('target_notes', sa.JSON(), nullable=False),
    sa.Column('port_check', sa.Boolean(), nullable=False),
    sa.Column('ports', sa.JSON(), nullable=False),
    sa.Column('concurrency', sa.Integer(), nullable=False),
    sa.Column('timeout_ms', sa.Integer(), nullable=False),
    sa.Column('credential_ids', sa.JSON(), nullable=False),
    sa.Column('schedule', sa.String(length=8), nullable=False),
    sa.Column('schedule_time', sa.String(length=5), nullable=False),
    sa.Column('schedule_weekday', sa.Integer(), nullable=False),
    sa.Column('address_count', sa.Integer(), nullable=False),
    sa.Column('last_run_id', sa.String(length=32), nullable=True),
    sa.Column('last_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_status', sa.String(length=16), nullable=True),
    sa.Column('last_summary', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['collector_id'], ['directory_collectors.id'], name='fk_network_scans_collector_id', ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_scans_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('network_scans', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_scans_collector_id'), ['collector_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_scans_organization_id'), ['organization_id'], unique=False)

    op.create_table('network_scan_runs',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('scan_id', sa.String(length=32), nullable=True),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('trigger', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('collector_id', sa.String(length=32), nullable=True),
    sa.Column('command_id', sa.String(length=32), nullable=True),
    sa.Column('params', sa.JSON(), nullable=False),
    sa.Column('requested_by', sa.String(length=320), nullable=True),
    sa.Column('queued_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('last_batch_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('seqs', sa.JSON(), nullable=False),
    sa.Column('devices_seen', sa.Integer(), nullable=False),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['collector_id'], ['directory_collectors.id'], name='fk_network_scan_runs_collector_id', ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_scan_runs_organization_id'),
    sa.ForeignKeyConstraint(['scan_id'], ['network_scans.id'], name='fk_network_scan_runs_scan_id', ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('network_scan_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_scan_runs_organization_id'), ['organization_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_scan_runs_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index('ix_network_scan_runs_scan_queued', ['scan_id', 'queued_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_scan_runs_status'), ['status'], unique=False)

    op.create_table('network_devices',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('mac', sa.String(length=17), nullable=False),
    sa.Column('mac_vendor', sa.String(length=128), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('sys_name', sa.String(length=255), nullable=False),
    sa.Column('sys_descr', sa.Text(), nullable=False),
    sa.Column('sys_object_id', sa.String(length=128), nullable=False),
    sa.Column('sys_location', sa.String(length=255), nullable=False),
    sa.Column('sys_contact', sa.String(length=255), nullable=False),
    sa.Column('uptime_s', sa.Integer(), nullable=True),
    sa.Column('snmp_version', sa.String(length=4), nullable=False),
    sa.Column('snmp_credential_id', sa.String(length=32), nullable=False),
    sa.Column('default_community', sa.String(length=16), nullable=False),
    sa.Column('alive_via', sa.JSON(), nullable=False),
    sa.Column('device_type', sa.String(length=16), nullable=False),
    sa.Column('vendor', sa.String(length=64), nullable=False),
    sa.Column('model', sa.String(length=128), nullable=False),
    sa.Column('firmware', sa.String(length=64), nullable=False),
    sa.Column('serial', sa.String(length=128), nullable=False),
    sa.Column('family', sa.String(length=32), nullable=False),
    sa.Column('cpe_product', sa.String(length=64), nullable=False),
    sa.Column('cpe_version', sa.String(length=64), nullable=False),
    sa.Column('cpe_update', sa.String(length=32), nullable=False),
    sa.Column('subnet', sa.String(length=64), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('last_run_id', sa.String(length=32), nullable=True),
    sa.Column('device_id', sa.String(length=32), nullable=True),
    sa.Column('directory_computer_id', sa.String(length=32), nullable=True),
    sa.Column('it_asset_id', sa.String(length=32), nullable=True),
    sa.Column('asset_id', sa.String(length=512), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['directory_computer_id'], ['directory_computers.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['it_asset_id'], ['it_assets.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_devices_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('network_devices', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_devices_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_devices_device_type'), ['device_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_devices_it_asset_id'), ['it_asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_devices_last_seen'), ['last_seen'], unique=False)
        batch_op.create_index('ix_network_devices_org_ip', ['organization_id', 'ip'], unique=False)
        batch_op.create_index('ix_network_devices_org_mac', ['organization_id', 'mac'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_devices_organization_id'), ['organization_id'], unique=False)

    op.create_table('network_device_events',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('at', sa.DateTime(), nullable=False),
    sa.Column('kind', sa.String(length=24), nullable=False),
    sa.Column('detail', sa.String(length=512), nullable=False),
    sa.Column('run_id', sa.String(length=32), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['network_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_device_events_organization_id'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('network_device_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_device_events_at'), ['at'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_device_events_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_device_events_organization_id'), ['organization_id'], unique=False)

    op.create_table('network_device_interfaces',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('if_index', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('descr', sa.String(length=255), nullable=False),
    sa.Column('mac', sa.String(length=17), nullable=False),
    sa.Column('oper_up', sa.Boolean(), nullable=False),
    sa.Column('speed_mbps', sa.Integer(), nullable=True),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['network_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_device_interfaces_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id', 'if_index', name='uq_network_device_interfaces')
    )
    with op.batch_alter_table('network_device_interfaces', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_device_interfaces_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_device_interfaces_organization_id'), ['organization_id'], unique=False)

    op.create_table('network_device_ports',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('proto', sa.String(length=3), nullable=False),
    sa.Column('service', sa.String(length=64), nullable=False),
    sa.Column('banner', sa.String(length=200), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['network_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_device_ports_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id', 'port', 'proto', name='uq_network_device_ports')
    )
    with op.batch_alter_table('network_device_ports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_device_ports_device_id'), ['device_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_device_ports_organization_id'), ['organization_id'], unique=False)

    op.create_table('network_fdb',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=False),
    sa.Column('mac', sa.String(length=17), nullable=False),
    sa.Column('port_name', sa.String(length=64), nullable=False),
    sa.Column('vlan', sa.Integer(), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['network_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_network_fdb_organization_id'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id', 'mac', 'port_name', name='uq_network_fdb')
    )
    with op.batch_alter_table('network_fdb', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_fdb_device_id'), ['device_id'], unique=False)
        batch_op.create_index('ix_network_fdb_org_mac', ['organization_id', 'mac'], unique=False)
        batch_op.create_index(batch_op.f('ix_network_fdb_organization_id'), ['organization_id'], unique=False)

    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('network_device_id', sa.String(length=32), nullable=True))
        batch_op.create_index(batch_op.f('ix_vulnerabilities_network_device_id'), ['network_device_id'], unique=False)
        batch_op.create_foreign_key('fk_vulnerabilities_network_device_id', 'network_devices', ['network_device_id'], ['id'], ondelete='CASCADE')



def downgrade() -> None:
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_constraint('fk_vulnerabilities_network_device_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_network_device_id'))
        batch_op.drop_column('network_device_id')

    with op.batch_alter_table('network_fdb', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_fdb_organization_id'))
        batch_op.drop_index('ix_network_fdb_org_mac')
        batch_op.drop_index(batch_op.f('ix_network_fdb_device_id'))

    op.drop_table('network_fdb')
    with op.batch_alter_table('network_device_ports', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_device_ports_organization_id'))
        batch_op.drop_index(batch_op.f('ix_network_device_ports_device_id'))

    op.drop_table('network_device_ports')
    with op.batch_alter_table('network_device_interfaces', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_device_interfaces_organization_id'))
        batch_op.drop_index(batch_op.f('ix_network_device_interfaces_device_id'))

    op.drop_table('network_device_interfaces')
    with op.batch_alter_table('network_device_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_device_events_organization_id'))
        batch_op.drop_index(batch_op.f('ix_network_device_events_device_id'))
        batch_op.drop_index(batch_op.f('ix_network_device_events_at'))

    op.drop_table('network_device_events')
    with op.batch_alter_table('network_devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_devices_organization_id'))
        batch_op.drop_index('ix_network_devices_org_mac')
        batch_op.drop_index('ix_network_devices_org_ip')
        batch_op.drop_index(batch_op.f('ix_network_devices_last_seen'))
        batch_op.drop_index(batch_op.f('ix_network_devices_it_asset_id'))
        batch_op.drop_index(batch_op.f('ix_network_devices_device_type'))
        batch_op.drop_index(batch_op.f('ix_network_devices_device_id'))

    op.drop_table('network_devices')
    with op.batch_alter_table('network_scan_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_scan_runs_status'))
        batch_op.drop_index('ix_network_scan_runs_scan_queued')
        batch_op.drop_index(batch_op.f('ix_network_scan_runs_scan_id'))
        batch_op.drop_index(batch_op.f('ix_network_scan_runs_organization_id'))

    op.drop_table('network_scan_runs')
    with op.batch_alter_table('network_scans', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_scans_organization_id'))
        batch_op.drop_index(batch_op.f('ix_network_scans_collector_id'))

    op.drop_table('network_scans')
    with op.batch_alter_table('network_snmp_credentials', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_snmp_credentials_organization_id'))

    op.drop_table('network_snmp_credentials')
