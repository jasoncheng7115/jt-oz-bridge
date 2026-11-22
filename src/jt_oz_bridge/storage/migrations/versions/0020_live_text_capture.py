"""Add own feed receipts and separate visible-text captures; preserve prior evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0020_live_text_capture"
down_revision = "0019_transcript_drafts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_feed_receipts",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("connection_epoch", sa.String(64), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )
    op.create_index(
        "ix_native_feed_receipts_connection_epoch", "native_feed_receipts", ["connection_epoch"]
    )
    op.create_table(
        "native_live_captures",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("source_key", "revision"),
    )
    op.create_index("ix_native_live_captures_source_key", "native_live_captures", ["source_key"])


def downgrade() -> None:
    raise ValueError("live_source_evidence_must_be_preserved")
