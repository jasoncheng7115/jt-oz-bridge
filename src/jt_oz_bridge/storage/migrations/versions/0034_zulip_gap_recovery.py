"""Fenced original Zulip message-gap recovery and explicit Human review."""

import sqlalchemy as sa
from alembic import op

revision = "0034_zulip_gap_recovery"
down_revision = "0033_payload_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zulip_recovery_checkpoints",
        sa.Column("source", sa.String(64), primary_key=True),
        sa.Column("channel_id", sa.BigInteger(), primary_key=True),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("bot_user_id", sa.BigInteger(), nullable=False),
        sa.Column("message_id", sa.BigInteger(), nullable=False),
        sa.Column("coverage", sa.String(32), nullable=False),
        sa.Column("binding_scopes", sa.LargeBinary(), nullable=False),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("input_events.id"), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
    )
    op.create_table(
        "zulip_recovery_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("message_id", sa.BigInteger(), nullable=False),
        sa.Column("source_revision", sa.BigInteger(), nullable=False),
        sa.Column(
            "input_event_id", sa.String(36), sa.ForeignKey("input_events.id"), nullable=False
        ),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("input_events.id"), nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "action_id", sa.String(36), sa.ForeignKey("actions.id"), nullable=True, unique=True
        ),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "review_receipt_id", sa.String(36), sa.ForeignKey("input_events.id"), nullable=True
        ),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("source", "message_id", "source_revision"),
    )
    for column in ("source", "binding_id", "state"):
        op.create_index("ix_zulip_recovery_items_" + column, "zulip_recovery_items", [column])


def downgrade() -> None:
    raise ValueError("original_gap_recovery_evidence_must_be_preserved")
