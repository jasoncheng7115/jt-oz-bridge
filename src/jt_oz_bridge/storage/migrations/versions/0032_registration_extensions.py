"""Preserve bounded encrypted original-graph extension history."""

import sqlalchemy as sa
from alembic import op

from jt_oz_bridge.storage.cipher_types import checked_json, key_state, payload_scope
from jt_oz_bridge.storage.session_registration_models import registration_history_seal

revision = "0032_registration_extensions"
down_revision = "0031_session_registrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "session_registrations",
        sa.Column("extension_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "session_registrations", sa.Column("extension_tip_hash", sa.String(64), nullable=True)
    )
    op.add_column(
        "session_registrations", sa.Column("history_seal", sa.LargeBinary(), nullable=True)
    )
    connection = op.get_bind()
    cipher = key_state(connection.dialect).cipher
    # Existing payload ciphertext is copied verbatim; only the new column is sealed.
    rows = connection.execute(sa.text("SELECT * FROM session_registrations")).mappings()
    for row in rows:
        seal = cipher.seal(
            checked_json(registration_history_seal(dict(row))),
            payload_scope("session_registrations", "history_seal"),
        )
        connection.execute(
            sa.text("UPDATE session_registrations SET history_seal=:seal WHERE key=:key"),
            {"seal": seal, "key": row["key"]},
        )
    with op.batch_alter_table("session_registrations") as batch:
        batch.alter_column("history_seal", existing_type=sa.LargeBinary(), nullable=False)
    op.create_table(
        "session_registration_extensions",
        sa.Column(
            "registration_key",
            sa.String(64),
            sa.ForeignKey("session_registrations.key"),
            primary_key=True,
        ),
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("predecessor_revision", sa.Integer(), nullable=False),
        sa.Column("successor_revision", sa.Integer(), nullable=False),
        sa.Column("predecessor_identity_hash", sa.String(64), nullable=False),
        sa.Column("successor_identity_hash", sa.String(64), nullable=False),
        sa.Column("predecessor_payload_hash", sa.String(64), nullable=False),
        sa.Column("successor_payload_hash", sa.String(64), nullable=False),
        sa.Column("added_count", sa.Integer(), nullable=False),
        sa.Column("delta", sa.LargeBinary(), nullable=False),
        sa.Column("delta_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.CheckConstraint(
            "sequence >= 1 AND sequence <= 999", name="ck_registration_extension_sequence"
        ),
        sa.CheckConstraint(
            "added_count >= 1 AND added_count <= 999", name="ck_registration_extension_count"
        ),
        sa.CheckConstraint(
            "predecessor_revision > 0 AND successor_revision = predecessor_revision + 1",
            name="ck_registration_extension_revision",
        ),
        sa.UniqueConstraint(
            "registration_key", "successor_revision", name="uq_registration_extension_revision"
        ),
    )


def downgrade() -> None:
    raise ValueError("original_graph_extension_history_must_be_preserved")
