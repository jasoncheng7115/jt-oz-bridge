"""Atomic immutable reply plans and ordered pages."""

import sqlalchemy as sa
from alembic import op

revision = "0008_delivery_batches"
down_revision = "0007_command_receipts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "delivery_batches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("dedupe_key", sa.String(255), nullable=False, unique=True),
        sa.Column("binding_id", sa.String(36), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.String(64), nullable=False),
        sa.Column("renderer_version", sa.String(64), nullable=False),
        sa.Column("message_limit", sa.Integer(), nullable=False),
        sa.Column("topic_limit", sa.Integer(), nullable=False),
        sa.Column("page_count", sa.Integer(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.add_column("deliveries", sa.Column("batch_id", sa.String(36), nullable=True))
    op.add_column("deliveries", sa.Column("batch_index", sa.Integer(), nullable=True))
    op.create_index(
        "uq_delivery_batch_position", "deliveries", ["batch_id", "batch_index"], unique=True
    )


def downgrade() -> None:
    raise ValueError("delivery_batch_evidence_must_be_preserved")
