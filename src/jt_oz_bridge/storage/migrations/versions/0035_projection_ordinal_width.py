"""Match PostgreSQL projection references to the existing 64-bit log ordinal.

SQLite INTEGER already stores signed 64-bit values; leave its tables untouched.
Historical migration0013 stays immutable. No identity or ciphertext is rewritten.
"""

import sqlalchemy as sa
from alembic import op

revision = "0035_projection_ordinal_width"
down_revision = "0034_zulip_gap_recovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.alter_column(
            "native_projection_records",
            "ordinal",
            existing_type=sa.Integer(),
            type_=sa.BigInteger(),
            existing_nullable=False,
        )


def downgrade() -> None:
    raise ValueError("projection_ordinals_must_not_be_narrowed")
