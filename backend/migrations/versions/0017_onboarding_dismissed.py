"""Per-organisation dismissal of the console's "Getting started" checklist
(GET /api/organization/onboarding; see app/services/onboarding.py).

Revision ID: 0017_onboarding_dismissed
Revises: 0016_dashboard_snapshots
Create Date: 2026-10-30
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0017_onboarding_dismissed'
down_revision: str | None = '0016_dashboard_snapshots'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('onboarding_dismissed_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('onboarding_dismissed_by', sa.String(length=320), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('onboarding_dismissed_by')
        batch_op.drop_column('onboarding_dismissed_at')
