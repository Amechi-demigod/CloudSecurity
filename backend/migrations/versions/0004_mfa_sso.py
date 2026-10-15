"""MFA (TOTP + recovery codes, login challenges) and Microsoft Entra ID SSO
(linked identities, in-flight OIDC requests). Adds tables only.

Originally developed as 0002_mfa_sso off 0001_baseline; re-chained after
0003_notifications when the feature branches were integrated so the history
stays linear.

Revision ID: 0004_mfa_sso
Revises: 0003_notifications
Create Date: 2026-10-15
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0004_mfa_sso'
down_revision: str | None = '0003_notifications'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _missing(table: str) -> bool:
    # A database created with create_all() before Alembic (stamped at the baseline)
    # may already have these tables.
    return not sa.inspect(op.get_bind()).has_table(table)


def upgrade() -> None:
    if _missing('oidc_auth_requests'):
        op.create_table('oidc_auth_requests',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('browser_binding', sa.String(length=64), nullable=False),
        sa.Column('nonce', sa.String(length=128), nullable=False),
        sa.Column('code_verifier', sa.String(length=128), nullable=False),
        sa.Column('return_to', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_oidc_auth_requests_expires_at'), 'oidc_auth_requests', ['expires_at'], unique=False)

    if _missing('mfa_challenges'):
        op.create_table('mfa_challenges',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=False),
        sa.Column('purpose', sa.String(length=16), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('consumed_at', sa.DateTime(), nullable=True),
        sa.Column('pending_secret_enc', sa.Text(), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_mfa_challenges_expires_at'), 'mfa_challenges', ['expires_at'], unique=False)
        op.create_index(op.f('ix_mfa_challenges_user_id'), 'mfa_challenges', ['user_id'], unique=False)

    if _missing('mfa_recovery_codes'):
        op.create_table('mfa_recovery_codes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=False),
        sa.Column('code_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_mfa_recovery_codes_user_id'), 'mfa_recovery_codes', ['user_id'], unique=False)

    if _missing('user_identities'):
        op.create_table('user_identities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=False),
        sa.Column('provider', sa.String(length=32), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('subject', sa.String(length=128), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('provider', 'tenant_id', 'subject')
        )
        op.create_index(op.f('ix_user_identities_user_id'), 'user_identities', ['user_id'], unique=False)

    if _missing('user_mfa'):
        op.create_table('user_mfa',
        sa.Column('user_id', sa.String(length=32), nullable=False),
        sa.Column('totp_secret_enc', sa.Text(), nullable=True),
        sa.Column('pending_secret_enc', sa.Text(), nullable=True),
        sa.Column('pending_created_at', sa.DateTime(), nullable=True),
        sa.Column('enabled_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_step', sa.BigInteger(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id')
        )


def downgrade() -> None:
    op.drop_table('user_mfa')
    op.drop_index(op.f('ix_user_identities_user_id'), table_name='user_identities')
    op.drop_table('user_identities')
    op.drop_index(op.f('ix_mfa_recovery_codes_user_id'), table_name='mfa_recovery_codes')
    op.drop_table('mfa_recovery_codes')
    op.drop_index(op.f('ix_mfa_challenges_user_id'), table_name='mfa_challenges')
    op.drop_index(op.f('ix_mfa_challenges_expires_at'), table_name='mfa_challenges')
    op.drop_table('mfa_challenges')
    op.drop_index(op.f('ix_oidc_auth_requests_expires_at'), table_name='oidc_auth_requests')
    op.drop_table('oidc_auth_requests')
