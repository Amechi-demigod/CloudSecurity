"""Device classification: workstation / server / domain controller, form
factor, virtualisation and cloud instance of agent devices, the class of
directory computers, and whether an IT asset's type was set automatically
(docs/DEVICE_MANAGEMENT.md#device-class).

Existing devices are classified from their OS name and model and marked
"inferred" until their agent (1.4.0+) reports its own classification.
Existing assets created by the agent or from directory discovery with a
computer type keep following their device ("auto"); every other type counts
as chosen by hand.

Revision ID: 0022_device_classification
Revises: 0021_directory_cloud_sources
Create Date: 2026-11-04
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0022_device_classification'
down_revision: str | None = '0021_directory_cloud_sources'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same rules as app/device_class.py (infer / directory_class), in SQL.
_VIRTUAL = ("vmware", "virtualbox", "innotek", "parallels", "virtual machine", "qemu", "kvm", "xen",
            "amazon ec2", "google compute engine", "virtualmac")


def upgrade() -> None:
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_class', sa.String(length=24), nullable=True))
        batch_op.add_column(sa.Column('class_source', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('form_factor', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('is_virtual', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('hypervisor', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('cloud_provider', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('cloud_instance_id', sa.String(length=128), nullable=True))
        batch_op.create_index(batch_op.f('ix_devices_device_class'), ['device_class'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_is_virtual'), ['is_virtual'], unique=False)
        batch_op.create_index(batch_op.f('ix_devices_cloud_instance_id'), ['cloud_instance_id'], unique=False)

    with op.batch_alter_table('directory_computers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_class', sa.String(length=24), nullable=True))
        batch_op.create_index(batch_op.f('ix_directory_computers_device_class'), ['device_class'], unique=False)

    with op.batch_alter_table('it_assets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('asset_type_source', sa.String(length=8), nullable=False,
                                      server_default='manual'))

    text = "lower(coalesce(manufacturer, '') || ' ' || coalesce(model, ''))"
    virtual = " OR ".join(f"{text} LIKE '%{v}%'" for v in _VIRTUAL)
    op.execute(f"""UPDATE devices SET class_source = 'inferred',
        device_class = CASE WHEN os_family = 'macos' THEN 'workstation'
                            WHEN os_family = 'windows' AND lower(os_name) LIKE '%server%' THEN 'server'
                            WHEN os_family = 'windows' THEN 'workstation'
                            ELSE 'server' END,
        is_virtual = CASE WHEN ({virtual}) AND NOT lower(coalesce(model, '')) LIKE '%.metal' THEN TRUE
                          ELSE NULL END""")  # noqa: S608 - constants only
    op.execute("""UPDATE directory_computers SET device_class = CASE
        WHEN device_kind = 'ad' AND user_account_control IS NOT NULL
             AND (user_account_control / 8192) % 2 = 1 THEN 'domain_controller'
        WHEN lower(operating_system) LIKE '%server%' THEN 'server'
        WHEN platform = 'linux' THEN 'server'
        WHEN platform IN ('windows', 'macos', 'chromeos') THEN 'workstation'
        ELSE NULL END""")
    op.execute("""UPDATE it_assets SET asset_type_source = 'auto'
        WHERE source IN ('agent', 'directory') AND asset_type IN ('computer', 'laptop', 'desktop', 'server')""")
    # Agent servers: their type follows the device class from now on.
    op.execute("""UPDATE it_assets SET asset_type = 'server'
        WHERE asset_type_source = 'auto' AND device_id IN (
            SELECT id FROM devices WHERE device_class = 'server')""")


def downgrade() -> None:
    with op.batch_alter_table('it_assets', schema=None) as batch_op:
        batch_op.drop_column('asset_type_source')

    with op.batch_alter_table('directory_computers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_directory_computers_device_class'))
        batch_op.drop_column('device_class')

    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_cloud_instance_id'))
        batch_op.drop_index(batch_op.f('ix_devices_is_virtual'))
        batch_op.drop_index(batch_op.f('ix_devices_device_class'))
        batch_op.drop_column('cloud_instance_id')
        batch_op.drop_column('cloud_provider')
        batch_op.drop_column('hypervisor')
        batch_op.drop_column('is_virtual')
        batch_op.drop_column('form_factor')
        batch_op.drop_column('class_source')
        batch_op.drop_column('device_class')
