"""Independent encrypted authorization for outputs with no session binding."""

import sqlalchemy as sa
from alembic import op

revision = "0010_output_destinations"
down_revision = "0009_form_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "output_destinations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("dedupe_key", sa.String(255), nullable=False, unique=True),
        sa.Column("realm_id", sa.String(255), nullable=False),
        sa.Column("authorization", sa.LargeBinary(), nullable=False),
        sa.Column("authorization_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    for name in ("realm_id", "state", "expires_at"):
        op.create_index("ix_output_destinations_" + name, "output_destinations", [name])


def downgrade() -> None:
    raise ValueError("output_authorization_evidence_must_be_preserved")
