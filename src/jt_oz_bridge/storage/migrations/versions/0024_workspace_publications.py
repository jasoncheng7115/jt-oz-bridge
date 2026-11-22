"""Reserve ordinary workspace bytes and retain publication/cleanup identities."""

import sqlalchemy as sa
from alembic import op

revision = "0024_workspace_publications"
down_revision = "0023_file_transfers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspace_budgets",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("reserved_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("object_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "workspace_publications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("namespace_sha256", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(36), sa.ForeignKey("actions.id"), nullable=False),
        sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reserved_bytes", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("pinned", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("namespace_sha256", "action_id", "artifact_id"),
    )
    for field in ("namespace_sha256", "action_id", "artifact_id", "state", "expires_at"):
        op.create_index("ix_workspace_publications_" + field, "workspace_publications", [field])


def downgrade() -> None:
    raise ValueError("workspace_reservation_and_cleanup_evidence_must_be_preserved")
