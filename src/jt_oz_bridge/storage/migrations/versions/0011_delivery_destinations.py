"""Exactly one bound-session or independent discovery authorization per output."""

import sqlalchemy as sa
from alembic import op

revision = "0011_delivery_destinations"
down_revision = "0010_output_destinations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table, prefix, check in (
        ("deliveries", "deliveries", "ck_delivery_authorization_source"),
        ("delivery_batches", "delivery_batches", "ck_delivery_batch_authorization_source"),
    ):
        with op.batch_alter_table(table) as batch:
            batch.alter_column("binding_id", existing_type=sa.String(36), nullable=True)
            batch.alter_column("binding_revision", existing_type=sa.Integer(), nullable=True)
            batch.add_column(sa.Column("destination_id", sa.String(36), nullable=True))
            batch.create_foreign_key(
                "fk_" + prefix + "_output_destination",
                "output_destinations",
                ["destination_id"],
                ["id"],
            )
            batch.create_check_constraint(
                check,
                "(destination_id IS NULL AND binding_id IS NOT NULL AND binding_revision IS NOT NULL) OR (destination_id IS NOT NULL AND binding_id IS NULL AND binding_revision IS NULL)",
            )
        op.create_index("ix_" + table + "_destination_id", table, ["destination_id"])


def downgrade() -> None:
    raise ValueError("delivery_authorization_evidence_must_be_preserved")
