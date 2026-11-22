"""Scoped encrypted artifact metadata and atomic quota reservations."""

import sqlalchemy as sa
from alembic import op

revision = "0005_artifacts"
down_revision = "0004_delivery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_budgets",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("reserved_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("object_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("binding_id", sa.String(36), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("project_id", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=False),
        sa.Column("source_message_id", sa.BigInteger(), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reserved_bytes", sa.BigInteger(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("checksum", sa.String(64), nullable=True),
        sa.Column("key_id", sa.String(32), nullable=False),
        sa.Column("action_id", sa.String(36), nullable=True),
        sa.Column("pinned", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
    )
    for column in ("binding_id", "state", "action_id", "expires_at"):
        op.create_index("ix_artifacts_" + column, "artifacts", [column])


def downgrade() -> None:
    for column in ("expires_at", "action_id", "state", "binding_id"):
        op.drop_index("ix_artifacts_" + column, table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_table("artifact_budgets")
