"""MSP accounts: partner organisations (docs/MSP.md).

Revision ID: 0036_msp_partners
Revises: 0035_table_preferences
Create Date: 2026-11-24 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0036_msp_partners'
down_revision: str | None = '0035_table_preferences'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing organisations become ordinary customers (server default).
    op.add_column('organizations', sa.Column('kind', sa.String(length=16), nullable=False, server_default='customer'))
    op.add_column('organizations', sa.Column('partner_org_id', sa.String(length=32), nullable=True))
    op.add_column('organizations', sa.Column('max_clients', sa.Integer(), nullable=True))
    op.add_column('organizations', sa.Column('status_set_by', sa.String(length=16), nullable=True))
    with op.batch_alter_table('organizations') as batch:
        batch.create_foreign_key('fk_organizations_partner_org_id', 'organizations', ['partner_org_id'], ['id'])
    op.create_index(op.f('ix_organizations_kind'), 'organizations', ['kind'], unique=False)
    op.create_index(op.f('ix_organizations_partner_org_id'), 'organizations', ['partner_org_id'], unique=False)

    op.add_column('user_sessions', sa.Column('acting_org_id', sa.String(length=32), nullable=True))
    with op.batch_alter_table('user_sessions') as batch:
        batch.create_foreign_key('fk_user_sessions_acting_org_id', 'organizations', ['acting_org_id'], ['id'],
                                 ondelete='SET NULL')

    op.add_column('audit_log', sa.Column('via_partner_org_id', sa.String(length=32), nullable=True))
    op.create_index(op.f('ix_audit_log_via_partner_org_id'), 'audit_log', ['via_partner_org_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_log_via_partner_org_id'), table_name='audit_log')
    op.drop_column('audit_log', 'via_partner_org_id')
    with op.batch_alter_table('user_sessions') as batch:
        batch.drop_constraint('fk_user_sessions_acting_org_id', type_='foreignkey')
    op.drop_column('user_sessions', 'acting_org_id')
    op.drop_index(op.f('ix_organizations_partner_org_id'), table_name='organizations')
    op.drop_index(op.f('ix_organizations_kind'), table_name='organizations')
    with op.batch_alter_table('organizations') as batch:
        batch.drop_constraint('fk_organizations_partner_org_id', type_='foreignkey')
    op.drop_column('organizations', 'status_set_by')
    op.drop_column('organizations', 'max_clients')
    op.drop_column('organizations', 'partner_org_id')
    op.drop_column('organizations', 'kind')
