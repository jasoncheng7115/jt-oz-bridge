"""Indexed retry scheduling; raw receipts and saved route results stay encrypted."""

import sqlalchemy as sa
from alembic import op

revision = "0022_zulip_retry"
down_revision = "0021_live_draft_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zulip_receipt_retries",
        sa.Column(
            "input_event_id", sa.String(36), sa.ForeignKey("input_events.id"), primary_key=True
        ),
        sa.Column("retry_at", sa.Float(), nullable=False),
    )
    op.create_index("ix_zulip_receipt_retries_retry_at", "zulip_receipt_retries", ["retry_at"])


def downgrade() -> None:
    raise ValueError("zulip_receipt_retry_and_route_evidence_must_be_preserved")
