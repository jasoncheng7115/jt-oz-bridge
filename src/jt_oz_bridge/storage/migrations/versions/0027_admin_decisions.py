"""Independent session-bound administrative preview and confirmation evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0027_admin_decisions"
down_revision = "0026_generated_capture_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("admin_id", sa.String(36), sa.ForeignKey("admin_accounts.id"), nullable=False),
        sa.Column("session_hash", sa.String(64), nullable=False),
        sa.Column("client_action_id", sa.String(36), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("queue_revision", sa.Integer(), nullable=False),
        sa.Column("holder", sa.String(36), nullable=False),
        sa.Column("fencing", sa.Integer(), nullable=False),
        sa.Column("confirmation_hash", sa.String(64), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("admin_id", "client_action_id"),
        sa.CheckConstraint("operation IN ('pause', 'unbind')", name="ck_admin_decision_operation"),
        sa.CheckConstraint(
            "state IN ('pending', 'confirmed', 'cancelled')", name="ck_admin_decision_state"
        ),
    )
    for field in ("admin_id", "binding_id", "state", "expires_at"):
        op.create_index("ix_admin_decisions_" + field, "admin_decisions", [field])


def downgrade() -> None:
    raise ValueError("administrative_decision_and_confirmation_evidence_must_be_preserved")
