"""Atomic completion/capture reservation and durable original-root write barrier."""

import sqlalchemy as sa
from alembic import op

revision = "0026_generated_capture_jobs"
down_revision = "0025_generated_outputs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "generated_capture_jobs",
        sa.Column("action_id", sa.String(36), sa.ForeignKey("actions.id"), primary_key=True),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("holder", sa.String(36)),
        sa.Column("fencing", sa.Integer()),
        sa.Column("retry_at", sa.Float(), nullable=False),
        sa.Column("status_reason", sa.String(96)),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
    )
    for field in ("binding_id", "state"):
        op.create_index("ix_generated_capture_jobs_" + field, "generated_capture_jobs", [field])


def downgrade() -> None:
    raise ValueError("generated_capture_and_acknowledgement_evidence_must_be_preserved")
