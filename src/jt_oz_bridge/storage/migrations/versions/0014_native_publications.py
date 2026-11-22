"""Atomically link native source publications and ordered outbound page batches."""

import sqlalchemy as sa
from alembic import op

revision = "0014_native_publications"
down_revision = "0013_native_projection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "batch_dependencies",
        sa.Column(
            "batch_id", sa.String(36), sa.ForeignKey("delivery_batches.id"), primary_key=True
        ),
        sa.Column(
            "before_batch_id", sa.String(36), sa.ForeignKey("delivery_batches.id"), nullable=False
        ),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("batch_id <> before_batch_id", name="ck_batch_dependency_not_self"),
    )
    op.create_index(
        "ix_batch_dependencies_before_batch_id", "batch_dependencies", ["before_batch_id"]
    )
    op.create_table(
        "native_publications",
        sa.Column(
            "input_event_id",
            sa.String(36),
            sa.ForeignKey("native_projection_records.input_event_id"),
            primary_key=True,
        ),
        sa.Column("ordinal", sa.BigInteger(), nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column(
            "batch_id",
            sa.String(36),
            sa.ForeignKey("delivery_batches.id"),
            nullable=True,
            unique=True,
        ),
        sa.Column(
            "previous_batch_id", sa.String(36), sa.ForeignKey("delivery_batches.id"), nullable=True
        ),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(state IN ('queued','needs_full_output') AND batch_id IS NOT NULL) OR (state IN ('history','empty','recovery') AND batch_id IS NULL AND previous_batch_id IS NULL)",
            name="ck_native_publication_output",
        ),
    )
    op.create_index("ix_native_publications_ordinal", "native_publications", ["ordinal"])
    op.create_index("ix_native_publications_binding_id", "native_publications", ["binding_id"])


def downgrade() -> None:
    raise ValueError("native_publication_and_dependency_evidence_must_be_preserved")
