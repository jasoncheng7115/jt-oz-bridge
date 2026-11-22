"""Add an empty table of confirmed repeating prompts; no existing row is touched."""

import sqlalchemy as sa
from alembic import op

revision = "0038_prompt_schedules"
down_revision = "0037_live_source_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "prompt_schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("dedupe_key", sa.String(255), nullable=False, unique=True),
        sa.Column("binding_id", sa.String(36), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=False),
        sa.Column("source_message_id", sa.BigInteger(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("starts_at", sa.Float(), nullable=False),
        sa.Column("ends_at", sa.Float(), nullable=False),
        sa.Column("next_at", sa.Float(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("sent", sa.Integer(), nullable=False),
        sa.Column("skipped", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("status_reason", sa.String(128)),
        sa.Column("last_action_id", sa.String(36), sa.ForeignKey("actions.id")),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.CheckConstraint(
            "state IN ('active','completed','cancelled')", name="ck_prompt_schedule_state"
        ),
        sa.CheckConstraint(
            "sent >= 0 AND skipped >= 0 AND sent + skipped <= total",
            name="ck_prompt_schedule_counts",
        ),
    )
    op.create_index("ix_prompt_schedules_binding_id", "prompt_schedules", ["binding_id"])
    op.create_index("ix_prompt_schedules_next_at", "prompt_schedules", ["next_at"])
    op.create_index("ix_prompt_schedules_state", "prompt_schedules", ["state"])


def downgrade() -> None:
    raise ValueError("prompt_schedules_must_be_preserved")
