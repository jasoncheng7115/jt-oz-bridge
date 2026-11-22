"""Encrypted optional-field progress and pinned draft schema hashes."""

import sqlalchemy as sa
from alembic import op

from jt_oz_bridge.storage.cipher_types import checked_json, key_state, payload_scope

revision = "0009_form_progress"
down_revision = "0008_delivery_batches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    cipher = key_state(connection.dialect).cipher
    op.add_column("form_drafts", sa.Column("snapshot_hash", sa.String(64), nullable=True))
    op.add_column("form_drafts", sa.Column("progress", sa.LargeBinary(), nullable=True))
    while True:
        rows = connection.execute(
            sa.text(
                "SELECT d.key,p.snapshot_hash FROM form_drafts d LEFT JOIN pending_interactions p ON p.id=d.interaction_id WHERE d.progress IS NULL LIMIT 100"
            )
        ).all()
        if not rows:
            break
        for identity, snapshot_hash in rows:
            encrypted = cipher.seal(
                checked_json({"skipped": []}), payload_scope("form_drafts", "progress")
            )
            connection.execute(
                sa.text(
                    "UPDATE form_drafts SET progress=:progress,snapshot_hash=:snapshot_hash WHERE key=:identity"
                ),
                {"identity": identity, "progress": encrypted, "snapshot_hash": snapshot_hash},
            )
    with op.batch_alter_table("form_drafts") as batch:
        batch.alter_column("progress", existing_type=sa.LargeBinary(), nullable=False)


def downgrade() -> None:
    raise ValueError("form_draft_progress_must_be_preserved")
