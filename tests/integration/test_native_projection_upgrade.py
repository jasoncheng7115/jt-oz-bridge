import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
from jt_oz_bridge.storage.database import Database, migrate
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.models import Action, InputEvent
from tests.contract.test_event_semantics import CONTEXT
from tests.integration.test_native_log_reader import event


async def test_upgrade_preserves_admission_request_and_unordered_legacy_capture(tmp_path):
    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}", cipher=cipher)
    payload = {
        "operation": "prompt",
        "reference": CONTEXT.reference.model_dump(),
        "text": "PRIVATE_LEGACY_REQUEST",
    }
    admission = {"legacy": "PRIVATE_LEGACY_ADMISSION"}
    captured = {
        "format": "v2-log-capture-v1",
        "provenance": CONTEXT.model_dump(mode="json"),
        "capture_epoch": "old-capture",
        "native": event(),
    }
    encoded = {
        name: cipher.seal(checked_json(value), payload_scope(table, column))
        for name, value, table, column in [
            ("request", payload, "actions", "payload"),
            ("admission", admission, "actions", "admission"),
            ("captured", captured, "input_events", "payload"),
        ]
    }

    def legacy(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, "0012_execution_receipts")

    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(legacy)
            await connection.execute(
                text(
                    "INSERT INTO actions (id,dedupe_key,binding_id,binding_revision,actor_id,operation_digest,payload,admission,state,version,created_at,owner,operation,upstream_id) VALUES ('old','old','binding',1,7,:digest,:payload,:admission,'admitted',9,123,'opencode','prompt','msg_original')"
                ),
                {
                    "digest": digest(payload),
                    "payload": encoded["request"],
                    "admission": encoded["admission"],
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO input_events (id,source,source_id,revision,payload_hash,payload,state,created_at) VALUES ('captured','old-source','evt_0',1,:hash,:payload,'captured',123)"
                ),
                {"hash": digest(captured), "payload": encoded["captured"]},
            )
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(text("SELECT payload FROM actions")) == encoded["request"]
            )
            assert (
                await connection.scalar(text("SELECT admission FROM actions"))
                == encoded["admission"]
            )
            assert (
                await connection.scalar(text("SELECT payload FROM input_events"))
                == encoded["captured"]
            )
            assert (
                await connection.scalar(text("SELECT count(*) FROM native_log_index")) == 0
            )  # No fabricated commit ordering.
            assert isinstance(
                await connection.scalar(text("SELECT native_result FROM actions")), bytes
            )
            sql = await connection.scalar(
                text("SELECT sql FROM sqlite_master WHERE name='native_log_index'")
            )
            assert "AUTOINCREMENT" in sql
        async with db.sessions() as session:
            saved = await session.get(Action, "old")
            assert (
                saved.state,
                saved.version,
                saved.upstream_id,
                saved.payload,
                saved.admission,
                saved.native_result,
            ) == ("admitted", 9, "msg_original", payload, admission, {})
            assert (await session.get(InputEvent, "captured")).state == "captured"
    finally:
        await db.close()
