"""Bounded live-receipt/capture deletion on real own SQL; synthetic feeds, not live evidence."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import event, func, select, text, update

from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture
from jt_oz_bridge.config import Retention
from jt_oz_bridge.services.live_capture import LiveTextCollector, read_live_capture
from jt_oz_bridge.services.live_retention import FeedGenerations, LiveSourceRetention, LiveSweep
from jt_oz_bridge.services.retention import RetentionExecutor
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.live_models import NativeFeedReceipt, NativeLiveCapture
from tests.contract.test_public_live_feed import frame, index
from tests.contract.test_visible_text_capture import event as text_event
from tests.integration.test_live_capture import journal

DAY = 86400
ENDED = "e" * 64


def later(days):
    return lambda: time.time() + days * DAY


def retention(store, *, feeds=(), clock=None, **limits):
    value = LiveSourceRetention(
        store.db, store.fence, Retention(), clock=clock or later(8), **limits
    )
    value.generations = FeedGenerations(tuple(SimpleNamespace(index=i) for i in feeds))
    return value


async def receipts(store, i, count, *, start=0):
    for offset in range(start, start + count, 128):
        batch = tuple(frame(text_event(n)) for n in range(offset, min(offset + 128, start + count)))
        admitted = await i.accept_receipted(batch, store)
        for item in admitted:
            assert i.pop() is item


async def captured(db, store, i, assistants):
    """Real receipted text events and coalesced captures for each assistant."""
    capture = VisibleTextCapture(i)
    for n, assistant in enumerate(assistants, start=1000):
        (item,) = await i.accept_receipted(
            (frame(text_event(n, assistant=assistant, text="PRIVATE_LIVE_TEXT")),), store
        )
        capture.observe(item)
        i.pop()
    feed = SimpleNamespace(current_owner=AsyncMock(), visible_text=capture)
    assert await LiveTextCollector(db, store.fence, feed).collect() == len(assistants)


async def counts(db):
    async with db.sessions() as session:
        return (
            await session.scalar(select(func.count()).select_from(NativeFeedReceipt)),
            await session.scalar(select(func.count()).select_from(NativeLiveCapture)),
        )


def ended():
    value = index()
    value.connection_epoch = ENDED
    return value


async def test_new_rows_carry_retention_scope_without_decrypting_later(db):
    store = await journal(db)
    i = index()
    await captured(db, store, i, ("msg_a",))
    async with db.sessions() as session:
        receipt = (await session.scalars(select(NativeFeedReceipt))).one()
        row = (await session.scalars(select(NativeLiveCapture))).one()
        assert receipt.recorded_at and abs(receipt.recorded_at - time.time()) < 60
        assert row.connection_epoch == i.connection_epoch and row.receipt_key == receipt.key
        assert row.recorded_at and abs(row.recorded_at - time.time()) < 60
        read_live_capture(row)


async def test_only_expired_rows_of_an_ended_connection_are_deleted(db):
    store = await journal(db)
    current, old = index(), ended()
    await receipts(store, current, 3)
    await receipts(store, old, 4, start=100)
    await captured(db, store, old, ("msg_old",))
    await captured(db, store, current, ("msg_current",))
    assert await counts(db) == (9, 2)
    # Inside the horizon nothing goes, even for the ended generation.
    assert await retention(store, feeds=(current,), clock=later(6)).sweep() == LiveSweep(0, 0, 0, 0)
    result = await retention(store, feeds=(current,)).sweep()
    assert result == LiveSweep(0, 0, 1, 5)
    async with db.sessions() as session:
        kept = (await session.scalars(select(NativeFeedReceipt))).all()
        assert {r.connection_epoch for r in kept} == {current.connection_epoch}
        (capture,) = (await session.scalars(select(NativeLiveCapture))).all()
        assert capture.connection_epoch == current.connection_epoch
        assert capture.receipt_key in {r.key for r in kept}
    # A fresh index of the live generation still deduplicates from SQL alone.
    assert await index().accept_receipted((frame(text_event(0)),), store) == ()


async def test_closed_generation_of_this_process_stays_protected(db):
    store = await journal(db)
    i = index()
    await receipts(store, i, 2)
    i.invalidate("EOF")
    assert await retention(store, feeds=(i,), clock=later(30)).sweep() == LiveSweep(0, 0, 0, 0)
    assert await counts(db) == (2, 0)
    # A fresh process does not own that epoch any more.
    assert (await retention(store, clock=later(30)).sweep()).receipts_deleted == 2


async def test_unknown_generations_or_lost_fence_delete_nothing(db):
    store = await journal(db)
    await receipts(store, ended(), 3)
    standalone = LiveSourceRetention(db, store.fence, Retention(), clock=later(30))
    assert await standalone.sweep() == LiveSweep(0, 0, 0, 0)
    executor = RetentionExecutor(db, store.fence, Retention(), clock=later(30))
    assert executor.live.generations is None and executor.live.fence == store.fence
    assert await executor.live.sweep() == LiveSweep(0, 0, 0, 0)
    lost = retention(SimpleNamespace(db=db, fence=ConsumerFence("other", 1)), clock=later(30))
    with pytest.raises(Conflict, match="lease"):
        await lost.sweep()
    assert await counts(db) == (3, 0)


async def test_referenced_capture_and_its_receipt_are_kept_past_the_horizon(db):
    store = await journal(db)
    old = ended()
    await captured(db, store, old, ("msg_published", "msg_unpublished"))
    async with db.sessions() as session:
        rows = {
            read_live_capture(r).assistant_id: r
            for r in (await session.scalars(select(NativeLiveCapture))).all()
        }
    pinned = rows["msg_published"]
    # Synthetic dependent row (FKs off only for this insert); its bytes are never read.
    async with db.engine.execution_options(
        jtoz_autocommit_maintenance=True
    ).connect() as connection:
        await connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        await connection.execute(
            text(
                "INSERT INTO transcript_live_draft_publications (id,source_version_id,"
                "live_capture_id,observation_revision,connection_epoch,record_id,scope_key,"
                "state,retry_at,candidate,candidate_hash) VALUES ('pub','version',:capture,1,"
                ":epoch,'record','scope','pending',0,x'00','hash')"
            ),
            {"capture": pinned.id, "epoch": ENDED},
        )
        await connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    assert await retention(store, clock=later(30)).sweep() == LiveSweep(0, 0, 1, 1)
    async with db.sessions() as session:
        (kept,) = (await session.scalars(select(NativeLiveCapture))).all()
        (receipt,) = (await session.scalars(select(NativeFeedReceipt))).all()
        assert kept.id == pinned.id and receipt.key == kept.receipt_key


async def test_pre_schema37_rows_are_stamped_and_backfilled_before_any_deletion(db):
    store = await journal(db)
    old = ended()
    await receipts(store, old, 5)
    await captured(db, store, old, ("msg_a", "msg_b"))
    async with db.sessions.begin() as session:
        await session.execute(update(NativeFeedReceipt).values(recorded_at=None))
        await session.execute(
            update(NativeLiveCapture).values(
                recorded_at=None, receipt_key=None, connection_epoch=None
            )
        )
    first = retention(store, clock=later(30), backfill_size=1, max_batches=1)
    # One capture is still unscoped: no receipt may go, whatever its age.
    async with db.sessions.begin() as session:
        await session.execute(update(NativeFeedReceipt).values(recorded_at=1.0))
    assert await first.sweep() == LiveSweep(0, 1, 0, 0)
    assert await counts(db) == (7, 2)
    # Stamped legacy rows start their full horizon when first observed.
    async with db.sessions.begin() as session:
        await session.execute(update(NativeFeedReceipt).values(recorded_at=None))
    assert await retention(store, clock=later(30)).sweep() == LiveSweep(7, 1, 0, 0)
    async with db.sessions() as session:
        for row in (await session.scalars(select(NativeLiveCapture))).all():
            value = read_live_capture(row)
            assert row.connection_epoch == ENDED == value.connection_epoch
    assert await counts(db) == (7, 2)
    assert await retention(store, clock=later(39)).sweep() == LiveSweep(0, 0, 2, 7)
    assert await counts(db) == (0, 0)


async def test_tampered_scope_copy_is_rejected_not_trusted(db):
    store = await journal(db)
    await captured(db, store, ended(), ("msg_a",))
    async with db.sessions.begin() as session:
        await session.execute(update(NativeLiveCapture).values(connection_epoch="f" * 64))
    async with db.sessions() as session:
        with pytest.raises(Conflict, match="scope_changed"):
            read_live_capture((await session.scalars(select(NativeLiveCapture))).one())


async def test_deletes_run_in_bounded_short_transactions(db):
    store = await journal(db)
    await receipts(store, ended(), 250)
    deleted = []

    def observe(_conn, cursor, statement, _params, _context, _many):
        if statement.lstrip().upper().startswith("DELETE"):
            deleted.append(cursor.rowcount)

    commits = []

    def committed(_conn):
        commits.append(1)

    event.listen(db.engine.sync_engine, "after_cursor_execute", observe)
    event.listen(db.engine.sync_engine, "commit", committed)
    try:
        limited = retention(store, clock=later(30), batch_size=100, max_batches=2)
        assert (await limited.sweep()).receipts_deleted == 200
        assert [n for n in deleted if n] == [100, 100] and len(commits) == 2
        assert await counts(db) == (50, 0)
        assert (await limited.sweep()).receipts_deleted == 50
        assert limited.deleted == {"native_feed_receipts": 250, "native_live_captures": 0}
    finally:
        event.remove(db.engine.sync_engine, "after_cursor_execute", observe)
        event.remove(db.engine.sync_engine, "commit", committed)
    assert await counts(db) == (0, 0)


async def test_migration37_adds_nullable_columns_and_refuses_downgrade(tmp_path):
    import os

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.storage.database import CURRENT_REVISION, Database, migrate

    assert CURRENT_REVISION == "0038_prompt_schedules"
    value = Database(
        "sqlite+aiosqlite:///" + str(tmp_path / "schema36.db"),
        cipher=EnvelopeCipher({"test": os.urandom(32)}, "test"),
    )

    def config(connection):
        cfg = Config()
        cfg.set_main_option("script_location", "src/jt_oz_bridge/storage/migrations")
        cfg.attributes["connection"] = connection
        return cfg

    try:
        async with value.engine.begin() as connection:
            await connection.run_sync(
                lambda c: command.upgrade(config(c), "0036_session_configuration_heads")
            )
            await connection.execute(
                text(
                    "INSERT INTO native_feed_receipts (key,connection_epoch,payload,payload_hash) "
                    "VALUES ('old',:epoch,x'01','hash')"
                ),
                {"epoch": ENDED},
            )
            # Schema37 itself, so its own downgrade refusal is what is exercised.
            await connection.run_sync(
                lambda c: command.upgrade(config(c), "0037_live_source_retention")
            )
        async with value.engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT recorded_at,payload FROM native_feed_receipts")
                )
            ).one() == (None, b"\x01")
            indexes = {
                row[1]
                for table in ("native_feed_receipts", "native_live_captures")
                for row in (
                    await connection.execute(text("PRAGMA index_list(" + table + ")"))
                ).all()
            }
            assert {
                "ix_native_feed_receipts_recorded_at",
                "ix_native_live_captures_connection_epoch",
                "ix_native_live_captures_receipt_key",
                "ix_native_live_captures_recorded_at",
            } <= indexes
        with pytest.raises(ValueError, match="live_source_retention_scope_must_be_preserved"):
            async with value.engine.begin() as connection:
                await connection.run_sync(
                    lambda c: command.downgrade(config(c), "0036_session_configuration_heads")
                )
        await migrate(value.engine)
        assert await value.ready()
    finally:
        await value.close()
