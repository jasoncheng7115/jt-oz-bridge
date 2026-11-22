"""Atomically seal model-setting admissions and their confirmation batches."""

import sqlalchemy as sa
from alembic import op

revision = "0016_model_publications"
down_revision = "0015_zulip_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_setting_publications",
        sa.Column("action_id", sa.String(36), sa.ForeignKey("actions.id"), primary_key=True),
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
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.create_index(
        "ix_model_setting_publications_binding_id", "model_setting_publications", ["binding_id"]
    )


def downgrade() -> None:
    raise ValueError("model_setting_publication_evidence_must_be_preserved")
