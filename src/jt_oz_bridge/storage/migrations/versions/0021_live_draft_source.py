"""Separate captured fragments from actual Native header snapshots and plans."""

import sqlalchemy as sa
from alembic import op

revision = "0021_live_draft_source"
down_revision = "0020_live_text_capture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "transcript_live_draft_publications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "source_version_id",
            sa.String(36),
            sa.ForeignKey("transcript_versions.id"),
            nullable=False,
        ),
        sa.Column(
            "live_capture_id",
            sa.String(64),
            sa.ForeignKey("native_live_captures.id"),
            nullable=False,
        ),
        sa.Column("observation_revision", sa.BigInteger(), nullable=False),
        sa.Column("connection_epoch", sa.String(64), nullable=False),
        sa.Column(
            "record_id", sa.String(36), sa.ForeignKey("transcript_messages.id"), nullable=False
        ),
        sa.Column(
            "scope_key", sa.String(64), sa.ForeignKey("transcript_streams.key"), nullable=False
        ),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("retry_at", sa.Float(), nullable=False),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("delivery_batches.id"), unique=True),
        sa.Column("candidate", sa.LargeBinary(), nullable=False),
        sa.Column("candidate_hash", sa.String(64), nullable=False),
        sa.Column("plan", sa.LargeBinary()),
        sa.Column("plan_hash", sa.String(64)),
        sa.UniqueConstraint("live_capture_id", "record_id"),
    )
    for column in (
        "source_version_id",
        "live_capture_id",
        "record_id",
        "scope_key",
        "state",
        "connection_epoch",
    ):
        op.create_index(
            "ix_transcript_live_draft_publications_" + column,
            "transcript_live_draft_publications",
            [column],
        )


def downgrade() -> None:
    raise ValueError("live_draft_source_and_delivery_evidence_must_be_preserved")
