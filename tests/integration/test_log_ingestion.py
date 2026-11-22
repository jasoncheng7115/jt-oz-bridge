import time

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.orm import Session

from jt_oz_bridge.services.log_ingestion import LogCapture
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Checkpoint, InputEvent, WorkerLease
from tests.contract.test_sse_log import event as log_event
from tests.contract.test_sse_log import frame
from tests.support import REF, bound


async def capture(db):
    bindings, binding, _, _ = await bound(db)
    fence = await DurableStore(db).acquire_lease("capture-test")
    return await LogCapture.open(bindings, binding.id, "capture-test", fence)


async def test_capture_and_sync_watermark_commit_together_and_restart_uses_real_cursor(db):
    stream = await capture(db)
    assert stream.read.position is None and not stream.read.synced
    await stream.accept(frame(log_event(0)))
    await stream.accept(
        frame({"type": "log.synced", "aggregateID": REF.upstream_session_id, "seq": 3})
    )
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, stream.source)).event_id == 3
        assert len((await session.scalars(select(InputEvent))).all()) == 2
    reopened = await LogCapture.open(
        stream.bindings, stream.binding.id, stream.holder, stream.fencing
    )
    assert reopened.read.position == 3 and not reopened.read.synced
    with pytest.raises(Conflict, match="epoch"):
        await stream.accept(frame(log_event(4, id="evt_next")))
    assert stream.read.position == 3
    await reopened.accept(frame(log_event(4, id="evt_next")))


async def test_failure_before_commit_preserves_both_stored_and_memory_positions(db):
    stream = await capture(db)

    def fail(_):
        raise RuntimeError("injected commit failure")

    event.listen(Session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            await stream.accept(frame(log_event(0)))
    finally:
        event.remove(Session, "before_commit", fail)
    assert stream.read.position is None
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, stream.source)).event_id == -1
        assert await session.scalar(select(InputEvent.id)) is None
    await stream.accept(frame(log_event(0)))


@pytest.mark.parametrize("change", ["expired", "takeover", "binding", "backend", "project"])
async def test_revocation_and_stale_lease_cannot_advance_capture(db, change):
    stream = await capture(db)
    async with db.sessions.begin() as session:
        if change == "expired":
            await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
        elif change == "takeover":
            await session.execute(update(WorkerLease).values(holder="new-worker", fencing=2))
        elif change == "binding":
            await session.execute(update(Binding).values(revision=2))
        elif change == "backend":
            await session.execute(update(EnrolledBackend).values(identity="replaced"))
        else:
            await session.execute(update(EnrolledProject).values(enabled=False))
    with pytest.raises(Conflict):
        await stream.accept(frame(log_event(0)))
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, stream.source)).event_id == -1
        assert await session.scalar(select(InputEvent.id)) is None


async def test_reused_durable_event_id_does_not_acknowledge_different_payload(db):
    stream = await capture(db)
    await stream.accept(frame(log_event(0)))
    with pytest.raises(Conflict, match="identity reused"):
        await stream.accept(frame(log_event(1)))
    assert stream.read.position == 0
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, stream.source)).event_id == 0


async def test_migrated_empty_log_records_marker_without_fabricating_sequence_zero(db):
    stream = await capture(db)
    await stream.accept(frame({"type": "log.synced", "aggregateID": REF.upstream_session_id}))
    assert stream.read.synced and stream.read.position is None
    async with db.sessions() as session:
        assert (await session.get(Checkpoint, stream.source)).event_id == -1
        receipt = (await session.scalars(select(InputEvent))).one()
        assert receipt.state == "captured" and "seq" not in receipt.payload
