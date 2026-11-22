"""Index native captures in commit order and preserve encrypted native results.

Existing captured events have no provable commit ordinal. Do not synthesize one
from wall time/UUID or silently reinterpret them; explicit reconciliation is needed.
"""

import sqlalchemy as sa
from alembic import op

from jt_oz_bridge.storage.cipher_types import checked_json, key_state, payload_scope

revision = "0013_native_projection"
down_revision = "0012_execution_receipts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    cipher = key_state(connection.dialect).cipher
    op.add_column("actions", sa.Column("native_result", sa.LargeBinary(), nullable=True))
    while True:
        ids = (
            connection.execute(
                sa.text("SELECT id FROM actions WHERE native_result IS NULL LIMIT 100")
            )
            .scalars()
            .all()
        )
        if not ids:
            break
        for identity in ids:
            connection.execute(
                sa.text("UPDATE actions SET native_result=:value WHERE id=:identity"),
                {
                    "value": cipher.seal(
                        checked_json({}), payload_scope("actions", "native_result")
                    ),
                    "identity": identity,
                },
            )
    with op.batch_alter_table("actions") as batch:
        batch.alter_column("native_result", existing_type=sa.LargeBinary(), nullable=False)
    op.create_table(
        "native_log_index",
        sa.Column(
            "ordinal",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "input_event_id",
            sa.String(36),
            sa.ForeignKey("input_events.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("bindings.id"), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("scope_key", sa.String(64), nullable=False),
        sa.Column("native_sequence", sa.BigInteger(), nullable=True),
        sa.Column("capture_epoch", sa.String(255), nullable=False),
        sqlite_autoincrement=True,
    )
    for column in ("source", "scope_key", "binding_id"):
        op.create_index("ix_native_log_index_" + column, "native_log_index", [column])
    op.create_table(
        "native_projections",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("binding_id", sa.String(36), nullable=False),
        sa.Column("binding_revision", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("semantics_sha256", sa.String(64), nullable=False),
        sa.Column("last_ordinal", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_native_projections_binding_id", "native_projections", ["binding_id"])
    op.create_table(
        "native_projection_records",
        sa.Column(
            "input_event_id", sa.String(36), sa.ForeignKey("input_events.id"), primary_key=True
        ),
        sa.Column(
            "ordinal",
            sa.Integer(),
            sa.ForeignKey("native_log_index.ordinal"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "scope_key", sa.String(64), sa.ForeignKey("native_projections.key"), nullable=False
        ),
        sa.Column("native_type", sa.String(255), nullable=False),
        sa.Column("native_inbox_id", sa.String(255), nullable=True),
        sa.Column("window_key", sa.String(64), nullable=True),
        sa.Column("assistant_message_id", sa.String(255), nullable=True),
        sa.Column("part_ordinal", sa.BigInteger(), nullable=True),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
    )
    for column in (
        "scope_key",
        "native_type",
        "native_inbox_id",
        "window_key",
        "assistant_message_id",
    ):
        op.create_index(
            "ix_native_projection_records_" + column, "native_projection_records", [column]
        )


def downgrade() -> None:
    raise ValueError("native_projection_and_result_evidence_must_be_preserved")
