"""Per-organisation Overview dashboard layout (app/services/dashboard_layout.py).

Revision ID: 0034_dashboard_layouts
Revises: 0033_cloud_resource_lifecycle
Create Date: 2026-11-20 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0034_dashboard_layouts'
down_revision: str | None = '0033_cloud_resource_lifecycle'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('dashboard_layouts',
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('layout', sa.JSON(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by', sa.String(length=320), nullable=True),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name='fk_dashboard_layouts_organization_id'),
    sa.PrimaryKeyConstraint('organization_id')
    )


def downgrade() -> None:
    op.drop_table('dashboard_layouts')
