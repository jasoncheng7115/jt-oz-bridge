"""Nullable live-source retention scope and interaction age; no rows are rewritten."""

import sqlalchemy as sa
from alembic import op

revision = "0037_live_source_retention"
down_revision = "0036_session_configuration_heads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Old rows stay NULL. The fenced retention sweep stamps/backfills them in
    # bounded batches; migration never decrypts or deletes live evidence.
    op.add_column("native_feed_receipts", sa.Column("recorded_at", sa.Float(), nullable=True))
    op.create_index("ix_native_feed_receipts_recorded_at", "native_feed_receipts", ["recorded_at"])
    for name, column in (
        ("connection_epoch", sa.String(64)),
        ("receipt_key", sa.String(64)),
        ("recorded_at", sa.Float()),
    ):
        op.add_column("native_live_captures", sa.Column(name, column, nullable=True))
        op.create_index("ix_native_live_captures_" + name, "native_live_captures", [name])
    op.add_column("pending_interactions", sa.Column("created_at", sa.Float(), nullable=True))


def downgrade() -> None:
    raise ValueError("live_source_retention_scope_must_be_preserved")
