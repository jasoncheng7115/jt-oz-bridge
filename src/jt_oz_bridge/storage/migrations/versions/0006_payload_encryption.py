"""Encrypt bridge payloads; refuse a silent plaintext fallback."""

import json

import sqlalchemy as sa
from alembic import op

from jt_oz_bridge.storage.cipher_types import checked_json, key_state, payload_scope
from jt_oz_bridge.storage.operations import operation_kind

revision = "0006_payload_encryption"
down_revision = "0005_artifacts"
branch_labels = None
depends_on = None

COLUMNS = (
    ("input_events", "payload", "id"),
    ("actions", "payload", "id"),
    ("deliveries", "payload", "id"),
    ("control_tokens", "context", "token_hash"),
    ("pending_interactions", "snapshot", "id"),
    ("form_drafts", "answers", "key"),
)


def upgrade() -> None:
    connection = op.get_bind()
    cipher = key_state(connection.dialect).cipher
    op.add_column(
        "actions", sa.Column("operation", sa.String(128), nullable=False, server_default="unknown")
    )
    op.create_table(
        "payload_key_checks",
        sa.Column("key_id", sa.String(32), primary_key=True),
        sa.Column("challenge", sa.LargeBinary(), nullable=False),
    )
    op.create_table(
        "maintenance_flags",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("pending", sa.Boolean(), nullable=False),
    )
    converted = 0
    for table, column, primary in COLUMNS:
        temporary = column + "_encrypted"
        op.add_column(table, sa.Column(temporary, sa.LargeBinary(), nullable=True))
        while True:
            # Identifiers are the immutable constants above, never user input.
            rows = connection.execute(
                sa.text(
                    f'SELECT "{primary}", "{column}" FROM "{table}" WHERE "{temporary}" IS NULL LIMIT 100'
                )
            ).all()
            if not rows:
                break
            if connection.dialect.name != "sqlite":
                raise ValueError("legacy_postgresql_requires_offline_encrypted_rebuild")
            for identity, value in rows:
                decoded = json.loads(value) if isinstance(value, str) else value
                envelope = cipher.seal(checked_json(decoded), payload_scope(table, column))
                extra = ", operation=:operation" if table == "actions" else ""
                connection.execute(
                    sa.text(
                        f'UPDATE "{table}" SET "{temporary}"=:value{extra} WHERE "{primary}"=:identity'
                    ),
                    {"value": envelope, "identity": identity, "operation": operation_kind(decoded)},
                )
                converted += 1
        with op.batch_alter_table(table) as batch:
            batch.drop_column(column)
            batch.alter_column(
                temporary, new_column_name=column, existing_type=sa.LargeBinary(), nullable=False
            )
    if converted:
        connection.execute(
            sa.text(
                "INSERT INTO maintenance_flags (name, pending) VALUES ('payload_disk_cleanup', true)"
            )
        )


def downgrade() -> None:
    raise ValueError("payload_encryption_downgrade_forbidden")
