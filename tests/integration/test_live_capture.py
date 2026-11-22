"""Real own SQL receipts/coalescing; synthetic wire fixtures are not live certification."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select, text, update

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture
from jt_oz_bridge.services.live_capture import (
    LiveEventJournal,
    LiveTextCollector,
    read_live_capture,
)
from jt_oz_bridge.services.runtime_enrollment import BackendRuntimeObserver
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.live_models import NativeFeedReceipt, NativeLiveCapture
from jt_oz_bridge.storage.models import Action
from tests.contract.test_public_live_feed import REAL, REF, frame, index, runtime
from tests.contract.test_visible_text_capture import event


async def journal(db):
    fencing = await DurableStore(db).acquire_lease("live-test", ttl=120)
    return LiveEventJournal(db, ConsumerFence("live-test", fencing))


async def test_drained_connection_exceeds_previous_lifetime_cap_and_dedups_evicted_events(db):
    store = await journal(db)
    i = index(max_events=128)
    first = event(0)
    # 12,032 unique events exceed the prior 10k connection ceiling. Real SQL,
    # bounded batches and tiny cache; the required timed load remains separate.
    for offset in range(0, 12032, 128):
        batch = tuple(frame(event(n, text="片")) for n in range(offset, offset + 128))
        admitted = await i.accept_receipted(batch, store)
        assert len(admitted) == 128 and len(i._seen) <= 128
        for item in admitted:
            assert i.pop() is item
        assert i._retained_bytes == 0
    # Use the exact original payload, not merely its Native event identity.
    first["data"]["delta"] = "片"
    assert await i.accept_receipted((frame(first),), store) == ()
    assert i.revision == 12032 and i.pop() is None and not i.closed
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(NativeFeedReceipt)) == 12032
    first["data"]["delta"] = "different"
    with pytest.raises(Conflict, match="identity_changed"):
        await i.accept_receipted((frame(first),), store)
    assert i.closed and not i._queue


async def test_replayed_durable_id_after_cache_eviction_is_not_a_new_sequence_regression(db):
    store = await journal(db)
    i = index(max_events=1)
    for value in (REAL[0], event()):
        await i.accept_receipted((frame(value),), store)
        i.pop()
    assert await i.accept_receipted((frame(REAL[0]),), store) == ()
    changed = {**REAL[0], "id": "evt_new_id_at_old_position"}
    with pytest.raises(ContractError, match="regressed"):
        await i.accept_receipted((frame(changed),), store)


async def test_duplicate_batch_conflict_rolls_back_all_new_receipts(db):
    store = await journal(db)
    i = index()
    old = event()
    changed = event(text="conflict")
    with pytest.raises(Conflict):
        await i.accept_receipted((frame(old), frame(changed)), store)
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(NativeFeedReceipt)) == 0


async def test_fenced_receipt_failure_does_not_admit_to_memory_or_retry(db):
    store = await journal(db)
    i = index()
    store.fence = ConsumerFence("wrong-holder", store.fence.fencing)
    with pytest.raises(Conflict, match="lease"):
        await i.accept_receipted((frame(event()),), store)
    assert i.revision == 0 and i.closed


async def test_receipt_corruption_is_detected_and_same_id_other_connection_is_independent(db):
    store = await journal(db)
    i = index()
    await i.accept_receipted((frame(event()),), store)
    other = index()
    other.connection_epoch = "b" * 64
    assert len(await other.accept_receipted((frame(event()),), store)) == 1
    async with db.sessions.begin() as session:
        await session.execute(update(NativeFeedReceipt).values(payload_hash="0" * 64))
    another = index()
    with pytest.raises(Conflict):
        await another.accept_receipted((frame(event()),), store)


async def test_current_owner_capture_coalesces_to_encrypted_archives_without_native_actions(db):
    store = await journal(db)
    i = index()
    capture = VisibleTextCapture(i)
    feed = SimpleNamespace(current_owner=AsyncMock(), visible_text=capture)
    collector = LiveTextCollector(db, store.fence, feed)
    items = await i.accept_receipted(
        tuple(frame(event(n, text="PRIVATE_VISIBLE_FRAGMENT")) for n in range(1, 101)), store
    )
    for item in items:
        capture.observe(item)
    assert await collector.collect() == 1
    assert await collector.collect() == 0
    async with db.sessions() as session:
        saved = (await session.scalars(select(NativeLiveCapture))).one()
        assert read_live_capture(saved).revision == 100
        assert read_live_capture(saved).text == "PRIVATE_VISIBLE_FRAGMENT" * 100
        assert await session.scalar(select(func.count()).select_from(Action)) == 0
    async with db.engine.connect() as conn:
        for table in ("native_live_captures", "native_feed_receipts"):
            payloads = (await conn.execute(text("SELECT payload FROM " + table))).scalars().all()
            assert all(
                isinstance(p, bytes) and b"PRIVATE_VISIBLE_FRAGMENT" not in p for p in payloads
            )
    # Restarting only the collector retains exact provenance and does not add a
    # second snapshot. A restored DTO has no current authority in the capture.
    assert await LiveTextCollector(db, store.fence, feed).collect() == 1
    assert not capture.current(read_live_capture(saved))
    i.invalidate("EOF")
    with pytest.raises(ContractError):
        await collector.collect()


async def test_bad_capture_envelope_and_metadata_are_rejected(db):
    store = await journal(db)
    i = index()
    capture = VisibleTextCapture(i)
    (item,) = await i.accept_receipted((frame(event()),), store)
    capture.observe(item)
    feed = SimpleNamespace(current_owner=AsyncMock(), visible_text=capture)
    assert await LiveTextCollector(db, store.fence, feed).collect() == 1
    async with db.sessions.begin() as session:
        saved = (await session.scalars(select(NativeLiveCapture))).one()
        saved.revision += 1
    async with db.sessions() as session:
        with pytest.raises(Conflict, match="scope_changed"):
            read_live_capture((await session.scalars(select(NativeLiveCapture))).one())


async def test_real_feed_task_batches_receipts_flushes_single_frame_and_cancels_cleanly(db):
    store = await journal(db)
    feed, _ = runtime()
    feed.receipts = store
    feed.capture_text = True
    release = asyncio.Event()

    async def events(operation, *, oversized_event_bytes):
        from tests.contract.test_public_live_feed import CONNECTED

        yield frame(CONNECTED)
        yield frame(event(1, text="first"))
        await release.wait()

    feed.transport.events = events
    await feed.start()
    assert feed.visible_text.snapshots()[0].text == "first"
    assert feed.index.revision == 1
    observer = BackendRuntimeObserver(feed, (), LiveTextCollector(db, store.fence, feed))
    await observer.pulse()
    assert feed.index.pop() is None
    await feed.close()
    assert feed.task.done() and not feed.visible_text._values
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(NativeLiveCapture)) == 1


async def test_foreign_events_and_reasoning_do_not_enter_receipt_journal_or_text_capture(db):
    store = await journal(db)
    i = index()
    foreign = event()
    foreign["data"]["sessionID"] = "ses_foreign"
    reasoning = event(2)
    reasoning["type"] = "session.reasoning.delta"
    assert await i.accept_receipted((frame(foreign), frame(reasoning)), store) == ()
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(NativeFeedReceipt)) == 0


async def test_missing_or_changed_durable_receipt_cannot_back_a_capture_archive(db):
    from sqlalchemy import delete

    store = await journal(db)
    i = index()
    capture = VisibleTextCapture(i)
    (item,) = await i.accept_receipted((frame(event()),), store)
    capture.observe(item)
    async with db.sessions.begin() as session:
        await session.execute(delete(NativeFeedReceipt))
    feed = SimpleNamespace(current_owner=AsyncMock(), visible_text=capture)
    with pytest.raises(Conflict, match="receipt_missing"):
        await LiveTextCollector(db, store.fence, feed).collect()
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(NativeLiveCapture)) == 0


async def test_evicted_assistant_rejoins_as_a_distinct_gap_window_without_revision_collision(db):
    store = await journal(db)
    i = index()
    capture = VisibleTextCapture(i, max_messages=1)
    feed = SimpleNamespace(current_owner=AsyncMock(), visible_text=capture)
    collector = LiveTextCollector(db, store.fence, feed)
    windows = []
    for n, assistant in enumerate(("msg_a", "msg_b", "msg_a"), start=1):
        (item,) = await i.accept_receipted(
            (frame(event(n, assistant=assistant, text=str(n))),), store
        )
        capture.observe(item)
        i.pop()
        assert await collector.collect() == 1
        windows.append(capture.snapshots()[0])
    assert windows[0].source_key != windows[2].source_key
    assert windows[0].assistant_id == windows[2].assistant_id
    assert windows[2].parts[0].prefix_missing and windows[2].text == "3"
    assert [value.revision for value in windows] == [1, 1, 1]
    assert [value.observation_revision for value in windows] == [1, 2, 3]
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(NativeLiveCapture)) == 3


async def test_bursty_large_foreign_frames_apply_byte_backpressure_and_keep_the_original_reader(db):
    store = await journal(db)
    feed, _ = runtime()
    reached = asyncio.Event()

    async def record_many(values):
        result = await store.record_many(values)
        if any(value.native_id == "evt_visible_100" for value in values):
            reached.set()
        return result

    feed.receipts, feed.capture_text = SimpleNamespace(record_many=record_many), True
    release = asyncio.Event()

    async def events(operation, *, oversized_event_bytes):
        from tests.contract.test_public_live_feed import CONNECTED

        yield frame(CONNECTED)
        for n in range(96):
            foreign = event(n, text="x" * (512 * 1024))
            foreign["data"]["sessionID"] = "ses_foreign"
            yield frame(foreign)
        yield frame(event(100, text="Retained own output"))
        await release.wait()

    feed.transport.events = events
    try:
        await feed.start()
        await asyncio.wait_for(reached.wait(), timeout=10)
        assert feed.visible_text.snapshots()[0].text == "Retained own output"
        assert 15 * 1024 * 1024 < feed.buffer_peak_bytes <= feed.index.max_bytes
        assert feed.index.revision == 1 and not feed.index.closed
    finally:
        await feed.close()


async def test_private_reasoning_is_discarded_before_our_microbatch_buffer(db):
    store = await journal(db)
    feed, _ = runtime()
    feed.receipts, feed.capture_text = store, True
    release = asyncio.Event()

    async def events(operation, *, oversized_event_bytes):
        from tests.contract.test_public_live_feed import CONNECTED

        yield frame(CONNECTED)
        for n in range(8):
            private = event(n, text="hidden" * 100000)
            private["type"] = "session.reasoning.delta"
            yield frame(private)
        yield frame(event(100, text="Only the visible output"))
        await release.wait()

    feed.transport.events = events
    try:
        await feed.start()
        assert feed.visible_text.snapshots()[0].text == "Only the visible output"
        assert feed.buffer_peak_bytes < 4096 and len(feed.index._queue) == 1
        async with db.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(NativeFeedReceipt)) == 1
    finally:
        await feed.close()


@pytest.mark.parametrize("change", ["missing_marker", "conflicting_directory"])
async def test_private_prefilter_still_rejects_protocol_and_enrolled_scope_conflicts(db, change):
    store = await journal(db)
    feed, _ = runtime()
    feed.receipts = store

    async def events(operation, *, oversized_event_bytes):
        from tests.contract.test_public_live_feed import CONNECTED

        if change != "missing_marker":
            yield frame(CONNECTED)
        private = event()
        private["type"] = "session.reasoning.delta"
        if change == "conflicting_directory":
            private["location"] = {"directory": "/another-directory"}
        yield frame(private)

    feed.transport.events = events
    with pytest.raises(ContractError):
        await feed.start()
    assert feed.index.closed and feed.buffer_peak_bytes < 4096


@pytest.mark.parametrize("result", [(), (True, True), (1,)])
async def test_invalid_journal_results_cannot_admit_events(result):
    i = index()
    fake = SimpleNamespace(record_many=AsyncMock(return_value=result))
    with pytest.raises(ContractError, match="receipt_result"):
        await i.accept_receipted((frame(event()),), fake)
    assert i.closed and i.revision == 0


@pytest.mark.parametrize("neutral", [True, False])
async def test_received_state_changes_expire_old_fences_before_a_slow_journal_commit(db, neutral):
    store = await journal(db)
    feed, _ = runtime()
    trigger, entered, release, committed, finish = (asyncio.Event() for _ in range(5))

    async def record_many(values):
        entered.set()
        await release.wait()
        result = await store.record_many(values)
        committed.set()
        return result

    async def events(operation, *, oversized_event_bytes):
        from tests.contract.test_public_live_feed import CONNECTED

        yield frame(CONNECTED)
        await trigger.wait()
        yield frame(event() if neutral else REAL[0])
        await finish.wait()

    feed.receipts = SimpleNamespace(record_many=record_many)
    feed.transport.events = events
    try:
        await feed.start()
        old = feed.index.state_revision_for(REF)
        trigger.set()
        await asyncio.wait_for(entered.wait(), 2)
        assert feed.index.revision_for(REF) > 0
        assert (feed.index.state_revision_for(REF) == old) is neutral
        assert feed.index.revision == 0 and feed.index.pop() is None
        release.set()
        await asyncio.wait_for(committed.wait(), 2)
        assert feed.index.revision == 1
    finally:
        await feed.close()
