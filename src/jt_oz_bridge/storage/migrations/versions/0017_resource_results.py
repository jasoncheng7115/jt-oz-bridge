"""Durable resource-result/text indices and atomic publication plans."""

import sqlalchemy as sa
from alembic import op

revision = "0017_resource_results"
down_revision = "0016_model_publications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "resource_result_records",
        sa.Column("action_id", sa.String(36), sa.ForeignKey("actions.id"), primary_key=True),
        sa.Column("ordinal", sa.BigInteger(), unique=True, nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.create_index(
        "ix_resource_result_records_binding_id", "resource_result_records", ["binding_id"]
    )
    op.create_table(
        "resource_text_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(36),
            sa.ForeignKey("resource_result_records.action_id"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.BigInteger(), unique=True, nullable=False),
        sa.Column("part_index", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("action_id", "part_index"),
    )
    op.create_index("ix_resource_text_records_action_id", "resource_text_records", ["action_id"])
    op.create_table(
        "resource_publications",
        sa.Column(
            "action_id",
            sa.String(36),
            sa.ForeignKey("resource_result_records.action_id"),
            primary_key=True,
        ),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column(
            "batch_id",
            sa.String(36),
            sa.ForeignKey("delivery_batches.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_resource_publications_binding_id", "resource_publications", ["binding_id"])


def downgrade() -> None:
    raise ValueError("resource_result_evidence_must_be_preserved")
