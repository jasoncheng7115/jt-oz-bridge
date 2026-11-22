"""Keep original-session identities without replaying any Native operation."""

import sqlalchemy as sa
from alembic import op

revision = "0031_session_registrations"
down_revision = "0030_check_dispatch_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "session_registrations",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("project_id", sa.String(255), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("identity_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("prepared_holder", sa.String(255), nullable=False),
        sa.Column("prepared_fencing", sa.Integer(), nullable=False),
        sa.Column("activated_fencing", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
    )
    op.create_index("ix_session_registrations_realm_id", "session_registrations", ["realm_id"])
    op.create_index("ix_session_registrations_project_id", "session_registrations", ["project_id"])


def downgrade() -> None:
    raise ValueError("original_session_registration_evidence_must_be_preserved")
