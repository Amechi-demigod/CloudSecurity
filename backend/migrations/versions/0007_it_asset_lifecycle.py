"""IT asset lifecycle: hardware asset records (agent devices and assets without
an agent), chain-of-custody events, offboarding / retrieval, disposal
certificates and admin settings. New tables only (no change to existing ones).

If another migration lands on main first with down_revision 0006_agent_updates,
rebase this one onto it (change down_revision) to keep a single linear chain.

Revision ID: 0007_it_asset_lifecycle
Revises: 0006_agent_updates
Create Date: 2026-10-20
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007_it_asset_lifecycle'
down_revision: str | None = '0006_agent_updates'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('it_asset_offboardings',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('person_email', sa.String(length=320), nullable=False),
    sa.Column('person_name', sa.String(length=128), nullable=False),
    sa.Column('department', sa.String(length=128), nullable=False),
    sa.Column('leave_date', sa.Date(), nullable=False),
    sa.Column('retrieval_due', sa.Date(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('closed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('it_asset_offboardings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_it_asset_offboardings_person_email'), ['person_email'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_asset_offboardings_status'), ['status'], unique=False)

    op.create_table('it_asset_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('it_assets',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('asset_tag', sa.String(length=64), nullable=False),
    sa.Column('serial_number', sa.String(length=128), nullable=False),
    sa.Column('asset_type', sa.String(length=32), nullable=False),
    sa.Column('manufacturer', sa.String(length=128), nullable=False),
    sa.Column('model', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('device_id', sa.String(length=32), nullable=True),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('assignee_name', sa.String(length=128), nullable=False),
    sa.Column('assignee_email', sa.String(length=320), nullable=False),
    sa.Column('assignee_department', sa.String(length=128), nullable=False),
    sa.Column('assigned_at', sa.DateTime(), nullable=True),
    sa.Column('location', sa.String(length=128), nullable=False),
    sa.Column('purchase_date', sa.Date(), nullable=True),
    sa.Column('supplier', sa.String(length=128), nullable=False),
    sa.Column('purchase_cost', sa.Numeric(precision=14, scale=2), nullable=True),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('warranty_end', sa.Date(), nullable=True),
    sa.Column('refresh_date', sa.Date(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('custom_fields', sa.JSON(), nullable=False),
    sa.Column('retrieval_due', sa.Date(), nullable=True),
    sa.Column('offboarding_id', sa.String(length=32), nullable=True),
    sa.Column('disposal_method', sa.String(length=32), nullable=True),
    sa.Column('disposal_date', sa.Date(), nullable=True),
    sa.Column('disposal_vendor', sa.String(length=128), nullable=True),
    sa.Column('disposal_notes', sa.Text(), nullable=True),
    sa.Column('created_by', sa.String(length=320), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['offboarding_id'], ['it_asset_offboardings.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('asset_tag'),
    sa.UniqueConstraint('device_id')
    )
    with op.batch_alter_table('it_assets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_it_assets_asset_type'), ['asset_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_assets_assignee_email'), ['assignee_email'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_assets_offboarding_id'), ['offboarding_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_assets_serial_number'), ['serial_number'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_assets_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_assets_warranty_end'), ['warranty_end'], unique=False)

    op.create_table('it_asset_certificates',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('asset_id', sa.String(length=32), nullable=False),
    sa.Column('filename', sa.String(length=128), nullable=False),
    sa.Column('content_type', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('uploaded_by', sa.String(length=320), nullable=True),
    sa.Column('uploaded_at', sa.DateTime(), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['it_assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('it_asset_certificates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_it_asset_certificates_asset_id'), ['asset_id'], unique=False)

    op.create_table('it_asset_events',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('asset_id', sa.String(length=32), nullable=False),
    sa.Column('at', sa.DateTime(), nullable=False),
    sa.Column('actor_email', sa.String(length=320), nullable=True),
    sa.Column('event_type', sa.String(length=32), nullable=False),
    sa.Column('from_status', sa.String(length=24), nullable=True),
    sa.Column('to_status', sa.String(length=24), nullable=True),
    sa.Column('from_assignee', sa.String(length=320), nullable=True),
    sa.Column('to_assignee', sa.String(length=320), nullable=True),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['it_assets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('it_asset_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_it_asset_events_asset_id'), ['asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_it_asset_events_at'), ['at'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('it_asset_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_it_asset_events_at'))
        batch_op.drop_index(batch_op.f('ix_it_asset_events_asset_id'))

    op.drop_table('it_asset_events')
    with op.batch_alter_table('it_asset_certificates', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_it_asset_certificates_asset_id'))

    op.drop_table('it_asset_certificates')
    with op.batch_alter_table('it_assets', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_it_assets_warranty_end'))
        batch_op.drop_index(batch_op.f('ix_it_assets_status'))
        batch_op.drop_index(batch_op.f('ix_it_assets_serial_number'))
        batch_op.drop_index(batch_op.f('ix_it_assets_offboarding_id'))
        batch_op.drop_index(batch_op.f('ix_it_assets_assignee_email'))
        batch_op.drop_index(batch_op.f('ix_it_assets_asset_type'))

    op.drop_table('it_assets')
    op.drop_table('it_asset_settings')
    with op.batch_alter_table('it_asset_offboardings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_it_asset_offboardings_status'))
        batch_op.drop_index(batch_op.f('ix_it_asset_offboardings_person_email'))

    op.drop_table('it_asset_offboardings')
