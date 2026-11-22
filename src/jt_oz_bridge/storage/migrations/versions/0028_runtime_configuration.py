"""Scoped runtime presentation settings and separate session-bound decisions."""

import sqlalchemy as sa
from alembic import op

revision = "0028_runtime_configuration"
down_revision = "0027_admin_decisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_configuration",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("id = 'site'", name="ck_runtime_configuration_singleton"),
        sa.CheckConstraint("revision >= 1", name="ck_runtime_configuration_revision"),
    )
    op.create_table(
        "runtime_setting_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("admin_id", sa.String(36), sa.ForeignKey("admin_accounts.id"), nullable=False),
        sa.Column("session_hash", sa.String(64), nullable=False),
        sa.Column("client_action_id", sa.String(36), nullable=False),
        sa.Column("setting_key", sa.String(64), nullable=False),
        sa.Column("configuration_revision", sa.Integer(), nullable=False),
        sa.Column("holder", sa.String(36), nullable=False),
        sa.Column("fencing", sa.Integer(), nullable=False),
        sa.Column("confirmation_hash", sa.String(64), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("admin_id", "client_action_id"),
        sa.CheckConstraint("setting_key = 'i18n.default_locale'", name="ck_runtime_setting_key"),
        sa.CheckConstraint(
            "state IN ('pending','confirmed','cancelled')", name="ck_runtime_setting_state"
        ),
    )
    for name in ("admin_id", "state", "expires_at"):
        op.create_index("ix_runtime_setting_decisions_" + name, "runtime_setting_decisions", [name])


def downgrade() -> None:
    raise ValueError("runtime_configuration_and_administrative_evidence_must_be_preserved")
