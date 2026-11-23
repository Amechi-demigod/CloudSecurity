"""Per-user table preferences (app/api/table_prefs.py).

Revision ID: 0035_table_preferences
Revises: 0034_dashboard_layouts
Create Date: 2026-11-23 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0035_table_preferences'
down_revision: str | None = '0034_dashboard_layouts'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('table_preferences',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('user_id', sa.String(length=32), nullable=False),
    sa.Column('table_id', sa.String(length=64), nullable=False),
    sa.Column('prefs', sa.JSON(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_table_preferences_organization_id'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'organization_id', 'table_id', name='uq_table_preferences_user_org_table')
    )
    op.create_index(op.f('ix_table_preferences_organization_id'), 'table_preferences', ['organization_id'], unique=False)
    op.create_index(op.f('ix_table_preferences_user_id'), 'table_preferences', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_table_preferences_user_id'), table_name='table_preferences')
    op.drop_index(op.f('ix_table_preferences_organization_id'), table_name='table_preferences')
    op.drop_table('table_preferences')
