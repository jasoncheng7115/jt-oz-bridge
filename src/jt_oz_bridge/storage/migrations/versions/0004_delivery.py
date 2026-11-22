"""Outbox attempts, revisions, scheduling and shared realm pacing."""

import sqlalchemy as sa
from alembic import op

revision = "0004_delivery"
down_revision = "0003_execution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "deliveries", sa.Column("version", sa.Integer(), nullable=False, server_default="1")
    )
    op.add_column(
        "deliveries", sa.Column("attempts", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "deliveries", sa.Column("retry_at", sa.Float(), nullable=False, server_default="0")
    )
    op.add_column(
        "deliveries", sa.Column("priority", sa.Integer(), nullable=False, server_default="100")
    )
    op.add_column("deliveries", sa.Column("status_reason", sa.String(128), nullable=True))
    op.add_column(
        "deliveries", sa.Column("updated_at", sa.Float(), nullable=False, server_default="0")
    )
    op.create_index("ix_deliveries_retry_at", "deliveries", ["retry_at"])
    op.create_table(
        "delivery_lanes",
        sa.Column("realm_id", sa.String(255), primary_key=True),
        sa.Column("not_before", sa.Float(), nullable=False, server_default="0"),
        sa.Column("backoff", sa.Float(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("delivery_lanes")
    op.drop_index("ix_deliveries_retry_at", table_name="deliveries")
    for column in ("updated_at", "status_reason", "priority", "retry_at", "attempts", "version"):
        op.drop_column("deliveries", column)
