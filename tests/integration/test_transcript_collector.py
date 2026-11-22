"""Fenced SQLite resource scans with synthetic original-message pages."""

import asyncio

import pytest
from sqlalchemy import func, select, text, update

from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_records import read_snapshot
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from jt_oz_bridge.storage.transcript_models import (
    TranscriptCandidate,
    TranscriptMessage,
    TranscriptStream,
    TranscriptVersion,
)
from tests.integration.test_transcript_commands import OriginalReader
from tests.support import REF, bound


def entry(identity, body="Original Native text"):
    return project_message({"id": identity, "type": "user", "time": {"created": 1}, "text": body})


async def setup(db, *, holder="transcript-collector"):
    bindings, binding, control, audience = await bound(db)
    n = await DurableStore(db).acquire_lease(holder)
    reader = OriginalReader()
    collector = TranscriptCollector(bindings, {REF: reader}, ConsumerFence(holder, n))
    return collector, binding, reader, audience


async def versions(db):
    async with db.sessions() as s:
        return (
            await s.scalars(
                select(TranscriptVersion)
                .join(TranscriptMessage)
                .order_by(TranscriptMessage.ordinal, TranscriptVersion.version)
            )
        ).all()


async def test_initial_history_is_archived_without_actions_and_native_repoll_is_idempotent(db):
    collector, binding, reader, _ = await setup(db)
    state = await collector.collect(binding)
    rows = await versions(db)
    assert len(rows) == 17 and all(row.payload["historical"] for row in rows)
    assert [row.payload["observation"]["entry"]["native_id"] for row in rows] == [
        "msg_" + str(i) for i in range(16, -1, -1)
    ]
    assert len(state.bootstrap_versions) == 17 and state.anchor == "msg_0"
    await collector.collect(binding)
    assert len(await versions(db)) == 17
    async with db.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(Action)) == 0
    async with db.engine.connect() as c:
        for table in ("transcript_streams", "transcript_versions"):
            values = (await c.execute(text("SELECT payload FROM " + table))).scalars().all()
            assert values and all(
                isinstance(v, bytes) and v.startswith(b"JTOZ\x01") for v in values
            )


async def test_large_gap_is_scanned_across_restart_before_ordered_versions_become_visible(db):
    collector, binding, reader, _ = await setup(db)
    await collector.collect(binding)
    reader.messages = [entry("new_" + str(i)) for i in range(44)] + reader.messages
    state = await collector.collect(binding)
    assert state.status == "scanning" and state.scan.cursor == "opaque:20"
    assert len(await versions(db)) == 17
    successor = TranscriptCollector(collector.bindings, {REF: reader}, collector.fence)
    state = await successor.collect(binding)
    assert state.status == "scanning"
    state = await successor.collect(binding)
    assert state.status == "live" and state.anchor == "new_0"
    rows = await versions(db)
    fresh = [
        row.payload["observation"]["entry"]["native_id"]
        for row in rows
        if not row.payload["historical"]
    ]
    assert fresh == ["new_" + str(i) for i in range(43, -1, -1)]
    async with db.sessions() as s:
        assert await s.scalar(select(func.count()).select_from(TranscriptCandidate)) == 0
    await successor.collect(binding)
    assert len(await versions(db)) == 61


async def test_missing_anchor_pauses_without_creating_replacement_or_new_action(db):
    collector, binding, reader, _ = await setup(db)
    await collector.collect(binding)
    reader.messages = [entry("after_revert")]
    state = await collector.collect(binding)
    assert (
        state.status == "gap"
        and state.gap_reason == "native_history_anchor_or_open_message_missing"
    )
    async with db.sessions() as s:
        assert (await s.get(Binding, binding.id)).dispatch_paused
        assert await s.scalar(select(func.count()).select_from(Action)) == 0
    with pytest.raises(Conflict):
        await collector.require_continuity(binding)
    assert len(await versions(db)) == 17


@pytest.mark.parametrize("change", ["grant", "audience", "binding", "witness", "owner"])
async def test_changes_during_native_read_cannot_commit_observations_or_versions(db, change):
    collector, binding, reader, audience = await setup(db)

    async def revoke():
        if change == "grant":
            async with db.sessions.begin() as s:
                await s.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        elif change == "audience":
            audience.users = frozenset({7, 8, 999})
        elif change == "binding":
            async with db.sessions.begin() as s:
                await s.execute(update(Binding).where(Binding.id == binding.id).values(revision=2))
        elif change == "witness":
            reader.alive = False

    reader.hook = revoke
    if change == "owner":
        await collector.collect(binding)
        original = reader.capture

        async def changed(*args, **kwargs):
            page = await original(*args, **kwargs)
            page = page.model_copy(update={"owner_epoch": "changed-owner"})
            reader.pages.append(page)
            return page

        reader.capture = changed
    with pytest.raises(ValueError):
        await collector.collect(binding)
    assert len(await versions(db)) == (17 if change == "owner" else 0)


async def test_incomplete_historical_assistant_is_updated_as_live_original_work(db):
    collector, binding, reader, _ = await setup(db)
    raw = {
        "id": "msg_running",
        "type": "assistant",
        "agent": "build",
        "model": {"providerID": "fixture", "id": "fixture"},
        "time": {"created": 2},
        "content": [{"type": "text", "text": ""}],
    }
    reader.messages.insert(0, project_message(raw))
    state = await collector.collect(binding)
    assert state.open_ids == ("msg_running",)
    raw["time"]["completed"] = 3
    raw["content"][0]["text"] = "Finished original computer work"
    reader.messages[0] = project_message(raw)
    state = await collector.collect(binding)
    assert not state.open_ids and state.status == "live"
    async with db.sessions() as s:
        record = await s.scalar(
            select(TranscriptMessage).where(TranscriptMessage.native_id == "msg_running")
        )
        version = await s.scalar(
            select(TranscriptVersion).where(
                TranscriptVersion.record_id == record.id, TranscriptVersion.version == 2
            )
        )
        stored = read_snapshot(version, record, state)
        assert (
            not stored.historical
            and stored.observation.entry.projection()["content"][0]["text"]
            == "Finished original computer work"
        )


async def test_concurrent_polls_have_one_atomic_initial_frontier(db):
    collector, binding, reader, _ = await setup(db)
    results = await asyncio.gather(
        collector.collect(binding), collector.collect(binding), return_exceptions=True
    )
    assert sum(not isinstance(r, BaseException) for r in results) == 1
    assert len(await versions(db)) == 17


async def test_corrupt_encrypted_state_lookup_hash_is_not_fresh_authority(db):
    collector, binding, reader, _ = await setup(db)
    await collector.collect(binding)
    async with db.sessions.begin() as s:
        await s.execute(update(TranscriptStream).values(payload_hash="0" * 64))
    with pytest.raises(Conflict):
        await collector.collect(binding)


async def test_old_untracked_incomplete_message_below_initial_window_is_not_new_work(db):
    collector, binding, reader, _ = await setup(db)
    from tests.integration.test_transcript_publisher import assistant

    reader.messages = [entry("initial_" + str(i)) for i in range(20)] + [
        assistant("outside_history_window", completed=False)
    ]
    await collector.collect(binding)
    # The second scan includes older history below the anchor. It must neither
    # enroll that old unfinished item nor later demand its presence forever.
    state = await collector.collect(binding)
    assert not state.open_ids and len(await versions(db)) == 20


async def test_original_feed_reconnect_marks_resource_recovery_without_claiming_event_replay(db):
    collector, binding, reader, _ = await setup(db)
    await collector.collect(binding)
    capture = reader.capture

    async def reconnect(*args, **kwargs):
        page = (await capture(*args, **kwargs)).model_copy(
            update={"connection_epoch": "reconnected"}
        )
        reader.pages.append(page)
        return page

    reader.capture = reconnect
    reader.messages.insert(0, entry("during_disconnect"))
    await collector.collect(binding)
    assert (await versions(db))[-1].payload["recovering"] is True
