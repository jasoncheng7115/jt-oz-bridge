"""Scoped original-transcript scans, immutable versions and publications."""

import sqlalchemy as sa
from alembic import op

revision = "0018_native_transcript"
down_revision = "0017_resource_results"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "transcript_streams",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_transcript_streams_binding_id", "transcript_streams", ["binding_id"])
    op.create_table(
        "transcript_candidates",
        sa.Column("scan_id", sa.String(36), primary_key=True),
        sa.Column("native_id", sa.String(255), primary_key=True),
        sa.Column(
            "scope_key", sa.String(64), sa.ForeignKey("transcript_streams.key"), nullable=False
        ),
        sa.Column("offset", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("scan_id", "offset"),
    )
    op.create_index("ix_transcript_candidates_scope_key", "transcript_candidates", ["scope_key"])
    op.create_table(
        "transcript_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scope_key", sa.String(64), sa.ForeignKey("transcript_streams.key"), nullable=False
        ),
        sa.Column("native_id", sa.String(255), nullable=False),
        sa.Column("ordinal", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("current_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("scope_key", "native_id"),
    )
    op.create_index("ix_transcript_messages_scope_key", "transcript_messages", ["scope_key"])
    op.create_table(
        "transcript_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "record_id", sa.String(36), sa.ForeignKey("transcript_messages.id"), nullable=False
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source_action_id", sa.String(36), sa.ForeignKey("actions.id")),
        sa.Column("context_action_id", sa.String(36), sa.ForeignKey("actions.id")),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("record_id", "version"),
    )
    op.create_index("ix_transcript_versions_record_id", "transcript_versions", ["record_id"])
    op.create_table(
        "transcript_publications",
        sa.Column(
            "version_id", sa.String(36), sa.ForeignKey("transcript_versions.id"), primary_key=True
        ),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("delivery_batches.id"), unique=True),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    raise ValueError("native_transcript_observations_must_be_preserved")
