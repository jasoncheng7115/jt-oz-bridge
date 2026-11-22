"""Durable Zulip queue generations and trusted numeric message scope."""

import sqlalchemy as sa
from alembic import op

revision = "0015_zulip_source"
down_revision = "0014_native_publications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zulip_queues",
        sa.Column("source", sa.String(64), primary_key=True),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("bot_user_id", sa.BigInteger(), nullable=False),
        sa.Column("queue_id", sa.String(255), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("enrolled_fencing", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
    )
    op.create_table(
        "zulip_message_index",
        sa.Column("realm_id", sa.String(255), primary_key=True),
        sa.Column("message_id", sa.BigInteger(), primary_key=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("channel_id", sa.BigInteger(), nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column(
            "input_event_id", sa.String(36), sa.ForeignKey("input_events.id"), nullable=False
        ),
        sa.Column("version", sa.Integer(), nullable=False),
    )
    op.create_index("ix_zulip_message_index_source", "zulip_message_index", ["source"])


def downgrade() -> None:
    raise ValueError("zulip_source_and_tombstone_evidence_must_be_preserved")
