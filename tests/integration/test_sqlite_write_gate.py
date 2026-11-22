"""In-process FIFO order for SQLite writers and its explicit lock failure."""

import asyncio
import time

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from jt_oz_bridge.config import DatabaseConfig
from jt_oz_bridge.security.cipher import EnvelopeCipher
from jt_oz_bridge.storage.database import DEFAULT_SQLITE_BUSY_TIMEOUT_MS, Database
from jt_oz_bridge.storage.models import Checkpoint
from jt_oz_bridge.storage.sessions import WriteGate, WriteGateExpired


async def short_timeout(template, path, milliseconds):
    """A clone of the empty schema whose busy timeout and queue budget are short."""
    await asyncio.to_thread(template._copy, path)
    value = Database(
        "sqlite+aiosqlite:///" + str(path),
        milliseconds,
        cipher=EnvelopeCipher({"test": template.key}, "test"),
    )
    assert await value.ready()
    return value


async def counter(db, source="counter"):
    async with db.sessions() as session:
        return await session.scalar(select(Checkpoint.event_id).where(Checkpoint.source == source))


async def test_default_busy_timeout_is_thirty_seconds_for_sqlite_and_queue(db):
    assert DEFAULT_SQLITE_BUSY_TIMEOUT_MS == 30000
    assert DatabaseConfig().sqlite_busy_timeout_ms == 30000
    async with db.sessions() as session:
        assert await session.scalar(text("PRAGMA busy_timeout")) == 30000
    assert db.sessions.write_gate is not None
    assert db.sessions.write_gate.timeout_seconds == 30


async def test_waiting_writers_start_in_arrival_order(db):
    async with db.sessions.begin() as session:
        session.add(Checkpoint(source="counter", queue_id="queue", event_id=0))
    entered, release = asyncio.Event(), asyncio.Event()
    order: list[int] = []

    async def holder():
        async with db.sessions.begin() as session:
            await session.get(Checkpoint, "counter")
            entered.set()
            await release.wait()

    async def writer(number):
        async with db.sessions.begin() as session:
            order.append(number)
            value = await session.get(Checkpoint, "counter")
            value.event_id += 1

    first = asyncio.create_task(holder())
    await asyncio.wait_for(entered.wait(), 2)
    waiting = []
    for number in range(6):
        waiting.append(asyncio.create_task(writer(number)))
        await asyncio.sleep(0.01)  # A definite arrival order.
    assert db.sessions.write_gate.waiting == 6
    assert order == []  # None of them reached SQLite while the holder ran.
    release.set()
    await asyncio.wait_for(asyncio.gather(first, *waiting), 10)
    assert order == list(range(6))
    assert await counter(db) == 6
    assert db.sessions.write_gate.waiting == 0


async def test_a_writer_waits_for_a_holder_that_finishes_within_the_budget(
    tmp_path, empty_database_template
):
    db = await short_timeout(empty_database_template, tmp_path / "wait.db", 2000)
    try:
        async with db.sessions.begin() as session:
            session.add(Checkpoint(source="counter", queue_id="queue", event_id=0))
        entered = asyncio.Event()

        async def holder():
            async with db.sessions.begin() as session:
                value = await session.get(Checkpoint, "counter")
                entered.set()
                await asyncio.sleep(0.5)
                value.event_id += 1

        task = asyncio.create_task(holder())
        await asyncio.wait_for(entered.wait(), 2)
        started = time.monotonic()
        async with db.sessions.begin() as session:
            value = await session.get(Checkpoint, "counter")
            assert value.event_id == 1  # It started only after the holder committed.
            value.event_id += 1
        assert 0.3 < time.monotonic() - started < 2
        await task
        assert await counter(db) == 2
    finally:
        await db.close()


async def test_queue_wait_past_its_budget_fails_as_database_locked_and_writes_nothing(
    tmp_path, empty_database_template
):
    db = await short_timeout(empty_database_template, tmp_path / "expired.db", 300)
    try:
        async with db.sessions.begin() as session:
            session.add(Checkpoint(source="counter", queue_id="queue", event_id=0))
        entered, release = asyncio.Event(), asyncio.Event()

        async def holder():
            async with db.sessions.begin() as session:
                await session.get(Checkpoint, "counter")
                entered.set()
                await release.wait()

        task = asyncio.create_task(holder())
        await asyncio.wait_for(entered.wait(), 2)
        reached = False
        started = time.monotonic()
        with pytest.raises(OperationalError, match="database is locked") as failed:
            async with db.sessions.begin() as session:
                reached = True
                value = await session.get(Checkpoint, "counter")
                value.event_id = 99
        assert isinstance(failed.value, WriteGateExpired)
        assert 0.25 < failed.value.waited < 1.5 and time.monotonic() - started < 1.5
        assert not reached
        assert db.sessions.write_gate.waiting == 0
        release.set()
        await task
        assert await counter(db) == 0
        # A later attempt starts normally: the failure released nothing it held.
        async with db.sessions.begin() as session:
            value = await session.get(Checkpoint, "counter")
            value.event_id = 1
        assert await counter(db) == 1
    finally:
        await db.close()


async def test_a_cancelled_waiter_leaves_the_queue_usable(db):
    async with db.sessions.begin() as session:
        session.add(Checkpoint(source="counter", queue_id="queue", event_id=0))
    entered, release = asyncio.Event(), asyncio.Event()

    async def holder():
        async with db.sessions.begin() as session:
            await session.get(Checkpoint, "counter")
            entered.set()
            await release.wait()

    async def writer():
        async with db.sessions.begin() as session:
            value = await session.get(Checkpoint, "counter")
            value.event_id += 1

    first = asyncio.create_task(holder())
    await asyncio.wait_for(entered.wait(), 2)
    cancelled = asyncio.create_task(writer())
    await asyncio.sleep(0.02)
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    later = asyncio.create_task(writer())
    release.set()
    await asyncio.wait_for(asyncio.gather(first, later), 5)
    assert await counter(db) == 1
    assert db.sessions.write_gate.waiting == 0


async def test_a_failing_writer_releases_its_turn(db):
    with pytest.raises(RuntimeError, match="injected"):
        async with db.sessions.begin() as session:
            session.add(Checkpoint(source="rolled-back", queue_id="queue", event_id=0))
            raise RuntimeError("injected")
    async with asyncio.timeout(2):
        async with db.sessions.begin() as session:
            session.add(Checkpoint(source="after", queue_id="queue", event_id=0))
    assert await counter(db, "rolled-back") is None
    assert await counter(db, "after") == 0


async def test_a_nested_writer_in_the_same_task_keeps_sqlites_own_failure(
    tmp_path, empty_database_template
):
    # Not queued behind its own outer transaction: SQLite's busy handler waits
    # on the outer write lock and then fails, exactly as before the queue.
    db = await short_timeout(empty_database_template, tmp_path / "nested.db", 200)
    try:
        started = time.monotonic()
        with pytest.raises(OperationalError, match="database is locked") as failed:
            async with db.sessions.begin() as outer:
                outer.add(Checkpoint(source="outer", queue_id="queue", event_id=0))
                await outer.flush()
                async with db.sessions.begin() as inner:
                    inner.add(Checkpoint(source="inner", queue_id="queue", event_id=0))
        assert not isinstance(failed.value, WriteGateExpired)
        assert time.monotonic() - started < 3
        assert await counter(db, "outer") is None
        assert await counter(db, "inner") is None
    finally:
        await db.close()


async def test_other_processes_still_meet_sqlites_busy_timeout(tmp_path, empty_database_template):
    # The queue orders this process only; an outside writer is met by SQLite itself.
    import sqlite3

    db = await short_timeout(empty_database_template, tmp_path / "external.db", 300)
    outside = sqlite3.connect(tmp_path / "external.db", isolation_level=None)
    try:
        outside.execute("BEGIN IMMEDIATE")
        with pytest.raises(OperationalError, match="database is locked") as failed:
            async with db.sessions.begin() as session:
                session.add(Checkpoint(source="blocked", queue_id="queue", event_id=0))
        assert not isinstance(failed.value, WriteGateExpired)
        outside.execute("ROLLBACK")
        async with db.sessions.begin() as session:
            session.add(Checkpoint(source="after", queue_id="queue", event_id=0))
        assert await counter(db, "after") == 0
    finally:
        outside.close()
        await db.close()


async def test_gate_rejects_a_nonpositive_budget_and_separates_event_loops():
    with pytest.raises(ValueError, match="positive"):
        WriteGate(0)
    gate = WriteGate(1)
    async with gate.hold():
        pass

    def other_loop():
        async def use():
            async with gate.hold():
                return True

        return asyncio.run(use())

    assert await asyncio.to_thread(other_loop) is True


def test_postgresql_has_no_process_write_queue(monkeypatch):
    from types import SimpleNamespace

    from jt_oz_bridge.storage import database as module

    engine = SimpleNamespace(dialect=object())
    built = []
    monkeypatch.setattr(module, "create_async_engine", lambda url, **options: engine)
    monkeypatch.setattr(module, "SessionFactory", lambda *args, **kwargs: built.append(kwargs))
    module.Database("postgresql+asyncpg://local.invalid/synthetic")
    assert built == [{}]  # Row locks there; no in-process queue.


async def test_the_turn_passes_on_after_commit_but_a_failure_keeps_it_until_close(db, monkeypatch):
    from jt_oz_bridge.storage import sessions as module

    seen = []
    original = module.JoinedAsyncSession.close

    async def close(self):
        lock = db.sessions.write_gate._locks.get(asyncio.get_running_loop())
        seen.append(lock is not None and lock.locked())
        await original(self)

    monkeypatch.setattr(module.JoinedAsyncSession, "close", close)
    async with db.sessions.begin() as session:
        session.add(Checkpoint(source="committed", queue_id="queue", event_id=0))
    with pytest.raises(RuntimeError, match="injected"):
        async with db.sessions.begin() as session:
            session.add(Checkpoint(source="rolled-back", queue_id="queue", event_id=0))
            raise RuntimeError("injected")
    # COMMIT returned: SQLite holds no write lock while the connection goes back.
    # A failed transaction keeps its turn until its session has rolled back and closed.
    assert seen == [False, True]
    assert await counter(db, "committed") == 0 and await counter(db, "rolled-back") is None


def test_an_expired_queue_wait_has_its_own_fixed_failure_label():
    from jt_oz_bridge.services.runtime import error_label

    assert error_label(WriteGateExpired(5.0)) == "WriteGateExpired"
    assert error_label(OperationalError("x", None, Exception("y"))) == "OperationalError"
