"""Pin generated-file origin and original bytes before encrypted storage."""

import sqlalchemy as sa
from alembic import op

revision = "0025_generated_outputs"
down_revision = "0024_workspace_publications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "generated_output_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("action_id", sa.String(36), sa.ForeignKey("actions.id"), nullable=False),
        sa.Column("output_index", sa.Integer(), nullable=False),
        sa.Column("reserved_artifact_id", sa.String(36), nullable=False, unique=True),
        sa.Column("transfer_id", sa.String(36), sa.ForeignKey("file_transfers.id"), unique=True),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("action_id", "output_index"),
    )
    op.create_index(
        "ix_generated_output_records_action_id", "generated_output_records", ["action_id"]
    )


def downgrade() -> None:
    raise ValueError("generated_output_capture_evidence_must_be_preserved")
