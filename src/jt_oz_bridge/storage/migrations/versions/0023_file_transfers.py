"""Persist upload attempts, acknowledged files and same-topic publication receipts."""

import sqlalchemy as sa
from alembic import op

revision = "0023_file_transfers"
down_revision = "0022_zulip_retry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "file_transfers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("dedupe_key", sa.String(64), nullable=False, unique=True),
        sa.Column("artifact_id", sa.String(36), sa.ForeignKey("artifacts.id"), nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("source_message_id", sa.BigInteger(), nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("holder", sa.String(36)),
        sa.Column("fencing", sa.Integer()),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("retry_at", sa.Float(), nullable=False),
        sa.Column("status_reason", sa.String(96)),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("delivery_batches.id"), unique=True),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
    )
    for name in ("artifact_id", "binding_id", "state"):
        op.create_index("ix_file_transfers_" + name, "file_transfers", [name])


def downgrade() -> None:
    raise ValueError("upload_attempt_and_publication_evidence_must_be_preserved")
