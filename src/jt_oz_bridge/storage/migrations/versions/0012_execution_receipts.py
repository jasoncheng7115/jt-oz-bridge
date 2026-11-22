"""Preserve native admission details independently of immutable action requests."""

import sqlalchemy as sa
from alembic import op

from jt_oz_bridge.storage.cipher_types import checked_json, key_state, payload_scope

revision = "0012_execution_receipts"
down_revision = "0011_delivery_destinations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    cipher = key_state(connection.dialect).cipher
    op.add_column("actions", sa.Column("admission", sa.LargeBinary(), nullable=True))
    while True:
        ids = (
            connection.execute(sa.text("SELECT id FROM actions WHERE admission IS NULL LIMIT 100"))
            .scalars()
            .all()
        )
        if not ids:
            break
        for identity in ids:
            encrypted = cipher.seal(checked_json({}), payload_scope("actions", "admission"))
            connection.execute(
                sa.text("UPDATE actions SET admission=:value WHERE id=:identity"),
                {"value": encrypted, "identity": identity},
            )
    with op.batch_alter_table("actions") as batch:
        batch.alter_column("admission", existing_type=sa.LargeBinary(), nullable=False)


def downgrade() -> None:
    raise ValueError("native_admission_evidence_must_be_preserved")
