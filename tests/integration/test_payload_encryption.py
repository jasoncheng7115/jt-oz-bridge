import asyncio
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import event, select, text
from sqlalchemy.exc import StatementError
from sqlalchemy.util.concurrency import await_only

from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.cipher_types import PayloadUnavailable, key_state
from jt_oz_bridge.storage.database import CURRENT_REVISION, Database, migrate
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Action, Delivery

MARKER = "PRIVATE_PROMPT_4f952becf3c64b9f"


def cipher():
    return EnvelopeCipher({"test": os.urandom(32)}, "test")


def install_legacy(connection):
    config = Config()
    config.set_main_option(
        "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
    )
    config.attributes["connection"] = connection
    command.upgrade(config, "0005_artifacts")
    connection.execute(
        text(
            "INSERT INTO actions (id,dedupe_key,binding_id,binding_revision,actor_id,operation_digest,payload,state,version,owner,created_at) VALUES ('legacy','legacy','b',1,7,'digest',:payload,'held',1,'bridge',1)"
        ),
        {"payload": '{"operation":"prompt","text":"' + MARKER + '"}'},
    )


async def test_payload_is_blob_encrypted_and_restart_requires_original_key(db):
    identity = await DurableStore(db).enqueue(
        "encrypted", "b", 1, 7, {"operation": "prompt", "text": MARKER}
    )
    async with db.engine.connect() as connection:
        row = (
            await connection.execute(
                text("SELECT typeof(payload), payload, operation FROM actions")
            )
        ).one()
        assert row[0] == "blob" and MARKER.encode() not in row[1] and row[2] == "prompt"
    original = Database(str(db.engine.url), cipher=db.cipher)
    wrong = Database(str(db.engine.url), cipher=cipher())
    absent = Database(str(db.engine.url))
    try:
        assert await original.ready()
        assert not await wrong.ready() and not await absent.ready()
        async with original.sessions() as session:
            assert (await session.get(Action, identity)).payload["text"] == MARKER
        for rejected in (wrong, absent):
            with pytest.raises(StatementError) as captured:
                await DurableStore(rejected).enqueue("reject", "b", 1, 7, {"text": MARKER})
            assert MARKER not in str(captured.value)
            with pytest.raises(ValueError):
                await migrate(rejected.engine)
    finally:
        await asyncio.gather(original.close(), wrong.close(), absent.close())


async def test_engine_keys_are_isolated_and_key_canaries_guard_replacement(tmp_path):
    first = Database(f"sqlite+aiosqlite:///{tmp_path / 'one.db'}", cipher=cipher())
    second = Database(f"sqlite+aiosqlite:///{tmp_path / 'two.db'}", cipher=cipher())
    try:
        await asyncio.gather(migrate(first.engine), migrate(second.engine))
        await asyncio.gather(
            DurableStore(first).enqueue("a", "b", 1, 1, {"text": MARKER}),
            DurableStore(second).enqueue("a", "b", 1, 1, {"text": MARKER}),
        )
        async with first.engine.connect() as connection:
            blob = await connection.scalar(text("SELECT payload FROM actions"))
        async with second.engine.begin() as connection:
            await connection.execute(text("UPDATE actions SET payload=:blob"), {"blob": blob})
        async with second.sessions() as session:
            with pytest.raises(PayloadUnavailable):
                await session.scalar(select(Action))
    finally:
        await asyncio.gather(first.close(), second.close())


async def test_ciphertext_column_scope_prevents_cross_table_swap(db):
    await DurableStore(db).enqueue("a", "b", 1, 1, {"text": MARKER})
    await DurableStore(db).queue_delivery("a", "b", 1, {"text": MARKER})
    async with db.engine.begin() as connection:
        await connection.execute(
            text("UPDATE deliveries SET payload=(SELECT payload FROM actions LIMIT 1)")
        )
    async with db.sessions() as session:
        with pytest.raises(PayloadUnavailable):
            await session.scalar(select(Delivery))


async def test_tampered_canary_blocks_readiness_and_migration(db):
    async with db.engine.begin() as connection:
        await connection.execute(
            text("UPDATE payload_key_checks SET challenge=:bad"), {"bad": b"invalid"}
        )
    assert not await db.ready()
    with pytest.raises(PayloadUnavailable):
        await migrate(db.engine)


async def test_active_consumer_prevents_migration_without_revoking_consumer(db):
    store = DurableStore(db)
    fencing = await store.acquire_lease("running")
    assert fencing
    with pytest.raises(ValueError, match="stopped_consumer"):
        await migrate(db.engine)
    # A migration rejection must not silently replace the still-active lease.
    assert await store.renew_lease("running", fencing)
    assert await db.ready()
    await store.release_lease("running", fencing)
    await migrate(db.engine)


async def test_legacy_payload_upgrade_and_physical_cleanup(tmp_path):
    path = tmp_path / "legacy.db"
    db = Database(f"sqlite+aiosqlite:///{path}", cipher=cipher())
    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(install_legacy)
        await migrate(db.engine)
        assert await db.ready()
        async with db.sessions() as session:
            action = await session.get(Action, "legacy")
            assert action.payload == {"operation": "prompt", "text": MARKER}
            assert action.operation == "prompt" and action.operation_digest == "digest"
            assert action.state == "held"
        for candidate in (path, Path(str(path) + "-wal")):
            if candidate.exists():
                assert MARKER.encode() not in candidate.read_bytes()
    finally:
        await db.close()


async def test_interrupted_cleanup_stays_not_ready_until_explicit_retry(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}", cipher=cipher())
    async with db.engine.begin() as connection:
        await connection.run_sync(install_legacy)

    def fail_vacuum(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement == "VACUUM":
            raise RuntimeError("injected maintenance interruption")

    event.listen(db.engine.sync_engine, "before_cursor_execute", fail_vacuum)
    try:
        with pytest.raises(RuntimeError, match="maintenance interruption"):
            await migrate(db.engine)
        assert not await db.ready()
        assert await DurableStore(db).acquire_lease("must-not-run") is None
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(text("SELECT version_num FROM alembic_version"))
                == CURRENT_REVISION
            )
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", fail_vacuum)
    try:
        await migrate(db.engine)
        assert await db.ready()
    finally:
        await db.close()


async def test_missing_key_cannot_create_schema(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'absent.db'}")
    try:
        with pytest.raises(PayloadUnavailable):
            await migrate(db.engine)
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(
                    text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                )
                == 0
            )
    finally:
        await db.close()


async def test_all_sensitive_json_columns_store_authenticated_blobs(db):
    from jt_oz_bridge.storage.control_models import ControlToken, FormDraft, PendingInteraction
    from jt_oz_bridge.storage.models import InputEvent

    payload = {"private": MARKER}
    async with db.sessions.begin() as session:
        session.add_all(
            [
                InputEvent(
                    source="source",
                    source_id="message",
                    revision=1,
                    payload_hash="digest",
                    payload=payload,
                ),
                ControlToken(
                    token_hash="token",
                    kind="menu",
                    realm_id="r",
                    user_id=1,
                    context=payload,
                    context_hash="digest",
                    expires_at=9999999999,
                ),
                PendingInteraction(
                    identity_key="pending",
                    binding_id="b",
                    binding_revision=1,
                    snapshot=payload,
                    snapshot_hash="digest",
                    expires_at=9999999999,
                ),
                FormDraft(key="draft", interaction_id="pending", user_id=1, answers=payload),
            ]
        )
    await DurableStore(db).enqueue("one", "b", 1, 1, payload)
    await DurableStore(db).queue_delivery("one", "b", 1, payload)
    async with db.engine.connect() as connection:
        for table, column in [
            ("input_events", "payload"),
            ("actions", "payload"),
            ("deliveries", "payload"),
            ("control_tokens", "context"),
            ("pending_interactions", "snapshot"),
            ("form_drafts", "answers"),
        ]:
            blob = await connection.scalar(text(f"SELECT {column} FROM {table}"))
            assert isinstance(blob, bytes) and MARKER.encode() not in blob
    async with db.sessions() as session:
        assert (await session.get(ControlToken, "token")).context == payload
        assert (await session.get(FormDraft, "draft")).answers == payload


async def test_failed_encryption_migration_rolls_back_schema_and_plaintext_rows(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'rollback.db'}", cipher=cipher())
    async with db.engine.begin() as connection:
        await connection.run_sync(install_legacy)

    def fail_later(_conn, _cursor, statement, _parameters, _context, _executemany):
        if "ALTER TABLE deliveries ADD COLUMN payload_encrypted" in statement:
            raise RuntimeError("injected midway DDL failure")

    event.listen(db.engine.sync_engine, "before_cursor_execute", fail_later)
    try:
        with pytest.raises(RuntimeError, match="midway DDL"):
            await migrate(db.engine)
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(text("SELECT version_num FROM alembic_version"))
                == "0005_artifacts"
            )
            assert MARKER in await connection.scalar(text("SELECT payload FROM actions"))
            names = (await connection.execute(text("PRAGMA table_info(actions)"))).all()
            assert "operation" not in {row[1] for row in names}
            assert (
                await connection.scalar(
                    text("SELECT COUNT(*) FROM sqlite_master WHERE name='payload_key_checks'")
                )
                == 0
            )
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", fail_later)
    try:
        await migrate(db.engine)
        assert await db.ready()
    finally:
        await db.close()


async def test_explicit_retained_keyring_can_initialize_new_active_key(tmp_path):
    key_one, key_two = os.urandom(32), os.urandom(32)
    url = f"sqlite+aiosqlite:///{tmp_path / 'keys.db'}"
    first = Database(url, cipher=EnvelopeCipher({"one": key_one}, "one"))
    await migrate(first.engine)
    identity = await DurableStore(first).enqueue("old", "b", 1, 1, {"text": MARKER})
    await first.close()
    next_db = Database(url, cipher=EnvelopeCipher({"one": key_one, "two": key_two}, "two"))
    try:
        assert not await next_db.ready()
        await migrate(next_db.engine)
        assert await next_db.ready()
        async with next_db.sessions() as session:
            assert (await session.get(Action, identity)).payload["text"] == MARKER
        await DurableStore(next_db).enqueue("new", "b", 1, 1, {"text": MARKER})
    finally:
        await next_db.close()
    lost = Database(url, cipher=EnvelopeCipher({"two": key_two}, "two"))
    try:
        assert not await lost.ready()
        with pytest.raises(PayloadUnavailable):
            await migrate(lost.engine)
    finally:
        await lost.close()


async def test_healthy_concurrent_key_check_does_not_revoke_verified_writer(db):
    """Hold real canary IO while another connection commits an encrypted row."""
    assert await db.ready()
    entered, release = asyncio.Event(), asyncio.Event()

    def pause_canary(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement == "SELECT key_id, challenge FROM payload_key_checks" and not entered.is_set():
            entered.set()
            await_only(release.wait())

    event.listen(db.engine.sync_engine, "before_cursor_execute", pause_canary)
    check = asyncio.create_task(db.ready())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        identity = await asyncio.wait_for(
            DurableStore(db).enqueue("concurrent-canary", "b", 1, 7, {"text": MARKER}), 5
        )
    finally:
        release.set()
        outcome = await asyncio.wait_for(check, 5)
        event.remove(db.engine.sync_engine, "before_cursor_execute", pause_canary)
    assert outcome
    async with db.sessions() as session:
        assert (await session.get(Action, identity)).payload == {"text": MARKER}


async def test_first_key_check_does_not_authorize_writes_before_completion(db):
    fresh = Database(str(db.engine.url), cipher=db.cipher)
    entered, release = asyncio.Event(), asyncio.Event()

    def pause_canary(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement == "SELECT key_id, challenge FROM payload_key_checks" and not entered.is_set():
            entered.set()
            await_only(release.wait())

    event.listen(fresh.engine.sync_engine, "before_cursor_execute", pause_canary)
    check = asyncio.create_task(fresh.ready())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        with pytest.raises(StatementError, match="payload_key_verification_required"):
            await DurableStore(fresh).enqueue("unverified", "b", 1, 7, {"text": MARKER})
        release.set()
        assert await asyncio.wait_for(check, 5)
        assert await DurableStore(fresh).enqueue("verified", "b", 1, 7, {"text": MARKER})
    finally:
        release.set()
        await asyncio.wait_for(check, 5)
        event.remove(fresh.engine.sync_engine, "before_cursor_execute", pause_canary)
        await fresh.close()


async def test_stale_successful_key_check_cannot_clear_a_newer_canary_failure(db):
    assert await db.ready()
    entered, release = asyncio.Event(), asyncio.Event()
    async with db.engine.connect() as connection:
        original = await connection.scalar(text("SELECT challenge FROM payload_key_checks"))

    def pause_snapshot(_connection, _cursor, statement, _parameters, _context, _executemany):
        # The driver already fetched this connection's original canary rows.
        if statement == "SELECT key_id, challenge FROM payload_key_checks" and not entered.is_set():
            entered.set()
            await_only(release.wait())

    event.listen(db.engine.sync_engine, "after_cursor_execute", pause_snapshot)
    stale = asyncio.create_task(db.ready())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        async with db.engine.begin() as connection:
            await connection.execute(
                text("UPDATE payload_key_checks SET challenge=:bad"), {"bad": b"invalid"}
            )
        assert not await db.ready()
        release.set()
        assert not await asyncio.wait_for(stale, 5)
        with pytest.raises(StatementError, match="payload_key_verification_required"):
            await DurableStore(db).enqueue("stale", "b", 1, 7, {"text": MARKER})
        async with db.engine.begin() as connection:
            await connection.execute(
                text("UPDATE payload_key_checks SET challenge=:original"), {"original": original}
            )
        assert await db.ready()
        assert await DurableStore(db).enqueue("fresh", "b", 1, 7, {"text": MARKER})
    finally:
        release.set()
        await asyncio.wait_for(stale, 5)
        event.remove(db.engine.sync_engine, "after_cursor_execute", pause_snapshot)


async def test_cancelled_key_check_invalidates_writes_until_a_new_complete_check(db):
    assert await db.ready()
    entered, release = asyncio.Event(), asyncio.Event()

    def pause_canary(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement == "SELECT key_id, challenge FROM payload_key_checks" and not entered.is_set():
            entered.set()
            await_only(release.wait())

    event.listen(db.engine.sync_engine, "before_cursor_execute", pause_canary)
    check = asyncio.create_task(db.ready())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        check.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(check, 5)
        assert not key_state(db.engine.dialect).verified
        with pytest.raises(StatementError, match="payload_key_verification_required"):
            await DurableStore(db).enqueue("cancelled", "b", 1, 7, {"text": MARKER})
        release.set()
        assert await db.ready()
    finally:
        release.set()
        await asyncio.gather(check, return_exceptions=True)
        event.remove(db.engine.sync_engine, "before_cursor_execute", pause_canary)
