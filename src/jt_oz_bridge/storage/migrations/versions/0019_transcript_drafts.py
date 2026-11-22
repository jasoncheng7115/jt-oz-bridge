"""Scoped immutable draft proposals/plans and current frame pointers."""

import sqlalchemy as sa
from alembic import op

revision = "0019_transcript_drafts"
down_revision = "0018_native_transcript"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "transcript_drafts",
        sa.Column(
            "record_id", sa.String(36), sa.ForeignKey("transcript_messages.id"), primary_key=True
        ),
        sa.Column(
            "scope_key", sa.String(64), sa.ForeignKey("transcript_streams.key"), nullable=False
        ),
        sa.Column("finalized", sa.Boolean(), nullable=False),
        sa.Column("terminal_version_id", sa.String(36), sa.ForeignKey("transcript_versions.id")),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_transcript_drafts_scope_key", "transcript_drafts", ["scope_key"])
    op.create_index("ix_transcript_drafts_finalized", "transcript_drafts", ["finalized"])
    op.create_table(
        "transcript_draft_publications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "source_version_id",
            sa.String(36),
            sa.ForeignKey("transcript_versions.id"),
            nullable=False,
        ),
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
        sa.UniqueConstraint("source_version_id", "record_id"),
    )
    for column in ("source_version_id", "record_id", "scope_key", "state"):
        op.create_index(
            "ix_transcript_draft_publications_" + column, "transcript_draft_publications", [column]
        )


def downgrade() -> None:
    raise ValueError("draft_outbound_evidence_must_be_preserved")
