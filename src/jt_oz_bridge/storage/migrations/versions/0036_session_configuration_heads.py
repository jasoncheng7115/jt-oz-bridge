"""Add empty configuration heads; never qualify or rewrite existing original Roots."""

import sqlalchemy as sa
from alembic import op

revision = "0036_session_configuration_heads"
down_revision = "0035_projection_ordinal_width"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "session_configuration_heads",
        sa.Column("root_key", sa.String(64), primary_key=True),
        sa.Column("root_reference_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("phase", sa.String(32), nullable=False),
        sa.Column("active_action_id", sa.String(36), sa.ForeignKey("actions.id"), unique=True),
        sa.Column(
            "last_activation_action_id", sa.String(36), sa.ForeignKey("actions.id"), unique=True
        ),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.CheckConstraint("revision >= 1", name="ck_configuration_head_revision"),
        sa.CheckConstraint(
            "phase IN ('stable','dispatching','activation_prepared','quarantined',"
            "'external_unqualified')",
            name="ck_configuration_head_phase",
        ),
        sa.CheckConstraint(
            "(phase IN ('stable','external_unqualified') AND active_action_id IS NULL) OR "
            "(phase IN ('dispatching','activation_prepared','quarantined') "
            "AND active_action_id IS NOT NULL)",
            name="ck_configuration_head_active_action",
        ),
    )


def downgrade() -> None:
    raise ValueError("session_configuration_attempt_barriers_must_be_preserved")
