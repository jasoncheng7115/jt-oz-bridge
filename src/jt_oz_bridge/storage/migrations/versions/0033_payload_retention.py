"""Nullable retention timestamps only; preserve all original rows and ciphertext."""

import sqlalchemy as sa
from alembic import op

revision = "0033_payload_retention"
down_revision = "0032_registration_extensions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in (
        "input_events",
        "actions",
        "deliveries",
        "command_receipts",
        "output_destinations",
        "control_tokens",
    ):
        op.add_column(table, sa.Column("payload_compacted_at", sa.Float(), nullable=True))
    for table in ("input_events", "actions"):
        op.add_column(table, sa.Column("retention_observed_at", sa.Float(), nullable=True))
        op.add_column(table, sa.Column("retention_fingerprint", sa.String(64), nullable=True))


def downgrade() -> None:
    raise ValueError("payload_tombstones_and_dedupe_history_must_be_preserved")
