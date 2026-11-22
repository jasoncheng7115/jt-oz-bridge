"""Expand the own administrative key allowlist without rewriting encrypted payloads."""

from alembic import op

revision = "0029_rendering_runtime"
down_revision = "0028_runtime_configuration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runtime_setting_decisions") as batch:
        batch.drop_constraint("ck_runtime_setting_key", type_="check")
        batch.create_check_constraint(
            "ck_runtime_setting_key",
            "setting_key IN ('i18n.default_locale','rendering.stream_update_min_interval_ms')",
        )


def downgrade() -> None:
    raise ValueError("confirmed_runtime_settings_and_encrypted_receipts_must_be_preserved")
