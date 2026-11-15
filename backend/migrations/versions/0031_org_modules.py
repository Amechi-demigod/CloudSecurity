"""Product modules per organisation (app/modules.py): organizations.modules, the JSON list of enabled modules.
Every existing organisation gets all four modules, so current customers are unaffected; new organisations
are created with none.

Revision ID: 0031_org_modules
Revises: 0030_linux_agent
Create Date: 2026-11-14 10:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0031_org_modules'
down_revision: str | None = '0030_linux_agent'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ALL_MODULES = ['cloud', 'endpoints', 'vulnerabilities', 'assets']


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('modules', sa.JSON(), nullable=True))
    orgs = sa.table('organizations', sa.column('modules', sa.JSON()))
    op.execute(orgs.update().values(modules=ALL_MODULES))


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('modules')
