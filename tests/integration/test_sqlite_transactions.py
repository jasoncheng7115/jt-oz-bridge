import asyncio

import pytest
from sqlalchemy import select, text

from jt_oz_bridge.storage.models import Checkpoint


async def test_schema_changes_roll_back_with_the_explicit_database_transaction(db):
    with pytest.raises(RuntimeError, match="injected"):
        async with db.engine.begin() as connection:
            await connection.execute(text("CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY)"))
            raise RuntimeError("injected DDL failure")
    async with db.engine.connect() as connection:
        assert (
            await connection.execute(
                text("SELECT count(*) FROM sqlite_master WHERE name='rollback_probe'")
            )
        ).scalar() == 0


async def test_wal_reader_keeps_a_repeatable_snapshot_without_blocking_writer(db):
    async with db.sessions.begin() as session:
        session.add(Checkpoint(source="snapshot", queue_id="queue", event_id=0))
    async with db.sessions() as reader:
        query = select(Checkpoint.event_id).where(Checkpoint.source == "snapshot")
        assert await reader.scalar(query) == 0
        async with db.sessions.begin() as writer:
            value = await writer.get(Checkpoint, "snapshot")
            value.event_id = 1
        assert await reader.scalar(query) == 0
    async with db.sessions() as reader:
        assert await reader.scalar(query) == 1


async def test_read_then_write_transactions_reserve_the_writer_before_first_read(db):
    async with db.sessions.begin() as session:
        session.add(Checkpoint(source="counter", queue_id="queue", event_id=0))
    entered, release, second_read = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def first():
        async with db.sessions.begin() as session:
            value = await session.get(Checkpoint, "counter")
            entered.set()
            await release.wait()
            value.event_id += 1

    async def second():
        async with db.sessions.begin() as session:
            value = await session.get(Checkpoint, "counter")
            second_read.set()
            value.event_id += 1

    one = asyncio.create_task(first())
    await asyncio.wait_for(entered.wait(), 2)
    two = asyncio.create_task(second())
    try:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(second_read.wait(), 0.02)
    finally:
        release.set()
        await asyncio.gather(one, two)
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, "counter")).event_id == 2
