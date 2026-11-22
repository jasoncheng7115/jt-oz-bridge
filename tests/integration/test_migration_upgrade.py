import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.database import Database, migrate

RETENTION_COLUMNS = {
    "input_events": (
        ("payload_compacted_at", "FLOAT"),
        ("retention_observed_at", "FLOAT"),
        ("retention_fingerprint", "VARCHAR(64)"),
    ),
    "actions": (
        ("payload_compacted_at", "FLOAT"),
        ("retention_observed_at", "FLOAT"),
        ("retention_fingerprint", "VARCHAR(64)"),
    ),
    "deliveries": (("payload_compacted_at", "FLOAT"),),
    "command_receipts": (("payload_compacted_at", "FLOAT"),),
    "output_destinations": (("payload_compacted_at", "FLOAT"),),
    "control_tokens": (("payload_compacted_at", "FLOAT"),),
    # Schema37 live-source retention scope and interaction age.
    "native_feed_receipts": (("recorded_at", "FLOAT"),),
    "native_live_captures": (
        ("connection_epoch", "VARCHAR(64)"),
        ("receipt_key", "VARCHAR(64)"),
        ("recorded_at", "FLOAT"),
    ),
    "pending_interactions": (("created_at", "FLOAT"),),
}


async def retention_preimage(connection, schema):
    return {
        name: list((await connection.execute(text('PRAGMA table_info("' + name + '")'))).all())
        for name in RETENTION_COLUMNS
        if name in schema
    }


async def verify_retention_additions(connection, before_columns, current):
    """Permit only schema33/37's exact nullable ADD COLUMN DDL; retain old equality."""
    normalized = dict(current)
    for name, columns in before_columns.items():
        after = list((await connection.execute(text('PRAGMA table_info("' + name + '")'))).all())
        assert after[: len(columns)] == columns
        expected = RETENTION_COLUMNS[name]
        assert [tuple(row[1:]) for row in after[len(columns) :]] == [
            (column, sqltype, 0, None, 0) for column, sqltype in expected
        ]
        for column, sqltype in expected:
            assert (
                await connection.scalar(
                    text('SELECT COUNT(*) FROM "' + name + '" WHERE "' + column + '" IS NOT NULL')
                )
            ) == 0
            needle = ", " + column + " " + sqltype
            assert normalized[name].count(needle) == 1
            normalized[name] = normalized[name].replace(needle, "", 1)
    return normalized


@pytest.mark.parametrize(
    "starting_revision", ["0001_foundation", "0003_execution", "0004_delivery"]
)
async def test_incremental_upgrade_preserves_receipts_and_prior_outbox(tmp_path, starting_revision):
    database = Database(
        f"sqlite+aiosqlite:///{tmp_path / 'upgrade.db'}",
        cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"),
    )

    def install_foundation(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, starting_revision)

    try:
        async with database.engine.begin() as connection:
            await connection.run_sync(install_foundation)
            await connection.execute(
                text(
                    "INSERT INTO checkpoints (source, queue_id, event_id, updated_at) VALUES ('realm', 'original-queue', 42, 1.0)"
                )
            )
            if starting_revision in {"0003_execution", "0004_delivery"}:
                await connection.execute(
                    text(
                        "INSERT INTO deliveries (id,dedupe_key,binding_id,binding_revision,payload,payload_hash,state,created_at) VALUES ('original','source','binding',1,'{}','hash','pending',1.0)"
                    )
                )
        assert not await database.ready()
        await migrate(database.engine)
        assert await database.ready()
        async with database.engine.connect() as connection:
            value = (
                await connection.execute(
                    text("SELECT queue_id, event_id FROM checkpoints WHERE source = 'realm'")
                )
            ).one()
            assert value == ("original-queue", 42)
            assert (await connection.execute(text("SELECT COUNT(*) FROM bindings"))).scalar() == 0
            if starting_revision in {"0003_execution", "0004_delivery"}:
                assert (
                    await connection.execute(
                        text("SELECT id,state,version,attempts,retry_at,priority FROM deliveries")
                    )
                ).one() == ("original", "pending", 1, 0, 0, 100)
    finally:
        await database.close()


@pytest.mark.parametrize(
    "starting_revision",
    [
        "0017_resource_results",
        "0018_native_transcript",
        "0019_transcript_drafts",
        "0020_live_text_capture",
        "0021_live_draft_source",
        "0022_zulip_retry",
        "0023_file_transfers",
        "0024_workspace_publications",
        "0025_generated_outputs",
        "0026_generated_capture_jobs",
        "0027_admin_decisions",
    ],
)
async def test_transcript_migration_only_adds_own_tables_and_preserves_encrypted_receipts(
    tmp_path, starting_revision
):
    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'transcript-upgrade.db'}", cipher=cipher)
    from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope

    captured = cipher.seal(
        checked_json({"private": "unchanged receipt"}), payload_scope("input_events", "payload")
    )

    def previous(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, starting_revision)

    try:
        async with database.engine.begin() as connection:
            await connection.run_sync(previous)
            await connection.execute(
                text(
                    "INSERT INTO input_events (id,source,source_id,revision,payload_hash,payload,state,created_at) VALUES ('receipt','original','event',1,'hash',:payload,'captured',123)"
                ),
                {"payload": captured},
            )
            schema = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            prior_retention_columns = await retention_preimage(connection, schema)
        assert not await database.ready()
        await migrate(database.engine)
        assert await database.ready()
        async with database.engine.connect() as connection:
            current = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            if starting_revision in {
                "0025_generated_outputs",
                "0026_generated_capture_jobs",
                "0027_admin_decisions",
            }:
                added = set()
            elif starting_revision == "0024_workspace_publications":
                added = {"generated_output_records"}
            else:
                added = {"workspace_budgets", "workspace_publications", "generated_output_records"}
                if starting_revision != "0023_file_transfers":
                    added |= {"file_transfers"}
                if starting_revision not in {"0022_zulip_retry", "0023_file_transfers"}:
                    added |= {"zulip_receipt_retries"}
                if starting_revision not in {
                    "0021_live_draft_source",
                    "0022_zulip_retry",
                    "0023_file_transfers",
                }:
                    added |= {"transcript_live_draft_publications"}
                if starting_revision not in {
                    "0020_live_text_capture",
                    "0021_live_draft_source",
                    "0022_zulip_retry",
                    "0023_file_transfers",
                }:
                    added |= {"native_feed_receipts", "native_live_captures"}
                if starting_revision not in {
                    "0019_transcript_drafts",
                    "0020_live_text_capture",
                    "0021_live_draft_source",
                    "0022_zulip_retry",
                    "0023_file_transfers",
                }:
                    added |= {"transcript_drafts", "transcript_draft_publications"}
                if starting_revision == "0017_resource_results":
                    added |= {
                        "transcript_streams",
                        "transcript_candidates",
                        "transcript_messages",
                        "transcript_versions",
                        "transcript_publications",
                    }
            if starting_revision not in {"0026_generated_capture_jobs", "0027_admin_decisions"}:
                added |= {"generated_capture_jobs"}
            if starting_revision != "0027_admin_decisions":
                added |= {"admin_decisions"}
            added |= {
                "runtime_configuration",
                "runtime_setting_decisions",
                "check_dispatch_records",
                "session_registrations",
                "session_registration_extensions",
                "session_configuration_heads",
                "zulip_recovery_checkpoints",
                "zulip_recovery_items",
                "prompt_schedules",
            }
            assert set(current) - set(schema) == added
            normalized = await verify_retention_additions(
                connection, prior_retention_columns, current
            )
            assert all(normalized[name] == value for name, value in schema.items())
            assert (
                await connection.scalar(text("SELECT payload FROM input_events WHERE id='receipt'"))
                == captured
            )
            assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()
    finally:
        await database.close()


@pytest.mark.parametrize(
    "starting_revision", ["0030_check_dispatch_records", "0031_session_registrations"]
)
async def test_graph_extension_upgrade_preserves_prior_schema_and_encrypted_receipt_bytes(
    tmp_path, starting_revision
):
    """Actual predecessor databases, not create_all or a synthetic head stamp."""
    from sqlalchemy import select

    from jt_oz_bridge.services.session_registration_journal import (
        decode_registration,
        registration_identity,
        registration_key,
    )
    from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
    from jt_oz_bridge.storage.database import CURRENT_REVISION
    from jt_oz_bridge.storage.durable import digest
    from jt_oz_bridge.storage.session_registration_models import SessionRegistration
    from tests.integration.test_session_registration_journal import record
    from tests.support import REF

    cipher = EnvelopeCipher({"original": os.urandom(32)}, "original")
    database = Database(
        f"sqlite+aiosqlite:///{tmp_path / 'graph-extension-upgrade.db'}", cipher=cipher
    )
    ciphertext = cipher.seal(
        checked_json({"original_private_receipt": "must survive byte for byte"}),
        payload_scope("input_events", "payload"),
    )

    def install_previous(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, starting_revision)

    old_heads = {}
    try:
        async with database.engine.begin() as connection:
            await connection.run_sync(install_previous)
            await connection.execute(
                text(
                    "INSERT INTO input_events (id,source,source_id,revision,payload_hash,payload,state,created_at) VALUES ('retained','fixture','original',1,'hash',:payload,'captured',123)"
                ),
                {"payload": ciphertext},
            )
            if starting_revision == "0031_session_registrations":
                # Exercise populated predecessor rows. The new seal must not
                # rewrite either the payload envelope or historical receipts.
                for state in ("prepared", "active"):
                    value = record(
                        observed=123.0,
                        reference=REF.model_copy(update={"upstream_session_id": state}),
                    )
                    payload = value.model_dump(mode="json")
                    row = {
                        "key": registration_key("realm", value.root),
                        "realm_id": "realm",
                        "project_id": value.root.project_id,
                        "payload": cipher.seal(
                            checked_json(payload), payload_scope("session_registrations", "payload")
                        ),
                        "payload_hash": digest(payload),
                        "identity_hash": registration_identity(value),
                        "state": state,
                        "revision": 7,
                        "prepared_holder": "old-consumer",
                        "prepared_fencing": 3,
                        "activated_fencing": 3 if state == "active" else None,
                        "created_at": 100.0,
                        "updated_at": 123.0,
                    }
                    await connection.execute(
                        text(
                            "INSERT INTO session_registrations ("
                            + ",".join(row)
                            + ") VALUES ("
                            + ",".join(":" + key for key in row)
                            + ")"
                        ),
                        row,
                    )
                    old_heads[row["key"]] = (row, value)
            prior_registration_columns = (
                await connection.execute(text("PRAGMA table_info(session_registrations)"))
            ).all()
            old_schema = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            prior_retention_columns = await retention_preimage(connection, old_schema)
        assert not await database.ready()
        await migrate(database.engine)
        assert await database.ready()
        async with database.engine.connect() as connection:
            after = dict(
                (
                    await connection.execute(
                        text("SELECT name,sql FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            )
            expected = {
                "session_registration_extensions",
                "session_configuration_heads",
                "zulip_recovery_checkpoints",
                "zulip_recovery_items",
                "prompt_schedules",
            }
            if starting_revision == "0030_check_dispatch_records":
                expected.add("session_registrations")
            assert set(after) - set(old_schema) == expected
            normalized = await verify_retention_additions(
                connection, prior_retention_columns, after
            )
            assert {
                name: normalized[name] for name in old_schema if name != "session_registrations"
            } == {
                name: value for name, value in old_schema.items() if name != "session_registrations"
            }
            columns = (
                await connection.execute(text("PRAGMA table_info(session_registrations)"))
            ).all()
            if prior_registration_columns:
                assert columns[: len(prior_registration_columns)] == prior_registration_columns
                assert {row[1] for row in columns[len(prior_registration_columns) :]} == {
                    "extension_count",
                    "extension_tip_hash",
                    "history_seal",
                }
            assert {row[1] for row in columns} >= {
                "extension_count",
                "extension_tip_hash",
                "history_seal",
            }
            assert next(row for row in columns if row[1] == "history_seal")[3] == 1
            for key, (original_row, _) in old_heads.items():
                upgraded = (
                    (
                        await connection.execute(
                            text("SELECT * FROM session_registrations WHERE key=:key"), {"key": key}
                        )
                    )
                    .mappings()
                    .one()
                )
                assert {name: upgraded[name] for name in original_row} == original_row
                assert isinstance(upgraded["history_seal"], bytes)
                assert b"old-consumer" not in upgraded["history_seal"]
                assert upgraded["extension_count"] == 0
                assert upgraded["extension_tip_hash"] is None
            assert (
                await connection.scalar(
                    text("SELECT payload FROM input_events WHERE id='retained'")
                )
                == ciphertext
            )
            assert (
                await connection.scalar(text("SELECT version_num FROM alembic_version"))
                == CURRENT_REVISION
            )
            assert len(CURRENT_REVISION) <= 32  # PostgreSQL Alembic version_num width.
            assert not (await connection.execute(text("PRAGMA foreign_key_check"))).all()
        async with database.sessions() as session:
            for row in (await session.scalars(select(SessionRegistration))).all():
                saved = decode_registration(row)
                original_row, original_record = old_heads[row.key]
                assert saved.record == original_record
                assert saved.state == original_row["state"]
                assert saved.receipt.revision == 7
                assert saved.receipt.prepared_holder == "old-consumer"
                assert saved.receipt.prepared_fencing == 3
                assert saved.extension_count == 0 and saved.extension_tip_hash is None
    finally:
        await database.close()
