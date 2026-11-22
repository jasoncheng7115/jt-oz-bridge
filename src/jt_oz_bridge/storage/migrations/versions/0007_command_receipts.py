"""Fenced one-attempt command receipts and encrypted cached responses."""

import sqlalchemy as sa
from alembic import op

revision = "0007_command_receipts"
down_revision = "0006_payload_encryption"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "command_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("message_id", sa.BigInteger(), nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=False),
        sa.Column("channel_id", sa.BigInteger(), nullable=False),
        sa.Column("topic", sa.String(255), nullable=False),
        sa.Column("source_revision", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("command", sa.String(32), nullable=False),
        sa.Column("binding_id", sa.String(36), nullable=True),
        sa.Column("binding_revision", sa.Integer(), nullable=True),
        sa.Column("holder", sa.String(36), nullable=False),
        sa.Column("fencing", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("response", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("realm_id", "message_id"),
    )
    op.create_index("ix_command_receipts_state", "command_receipts", ["state"])


def downgrade() -> None:
    raise ValueError("command_receipt_history_must_be_preserved")
