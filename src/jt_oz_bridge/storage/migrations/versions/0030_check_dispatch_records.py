"""Retain the original dispatch owner without rewriting old Actions or receipts."""

import sqlalchemy as sa
from alembic import op

revision = "0030_check_dispatch_records"
down_revision = "0029_rendering_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "check_dispatch_records",
        sa.Column("action_id", sa.String(36), sa.ForeignKey("actions.id"), primary_key=True),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )


def downgrade() -> None:
    raise ValueError("original_check_dispatch_owner_evidence_must_be_preserved")
