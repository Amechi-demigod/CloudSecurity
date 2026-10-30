"""IT asset offboarding by username: owners set automatically from the agent's
signed-in user have a username but no email (docs/ASSET_MANAGEMENT.md#offboarding-and-retrieval).

Revision ID: 0019_offboarding_username
Revises: 0018_remote_sessions
Create Date: 2026-10-30
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0019_offboarding_username'
down_revision: str | None = '0018_remote_sessions'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('it_asset_offboardings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('person_username', sa.String(length=128), nullable=False, server_default=''))
        batch_op.create_index(batch_op.f('ix_it_asset_offboardings_person_username'), ['person_username'],
                              unique=False)


def downgrade() -> None:
    with op.batch_alter_table('it_asset_offboardings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_it_asset_offboardings_person_username'))
        batch_op.drop_column('person_username')
