"""Qualified-reader doubles + real encrypted proposals, plans and Bot edit worker."""

import asyncio
import time

import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_drafts import TranscriptDraftPublisher
from jt_oz_bridge.services.transcript_publisher import TranscriptPublisher
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch
from jt_oz_bridge.storage.transcript_models import (
    TranscriptDraft,
    TranscriptDraftPublication,
    TranscriptVersion,
)
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_resource_publisher import rows
from tests.integration.test_transcript_collector import entry
from tests.integration.test_transcript_collector import setup as collector_setup
from tests.integration.test_transcript_publisher import assistant, baseline, drain, output
from tests.support import REF


async def setup(db, *, locale="en", limit=1000, holder="transcript-collector"):
    previous, binding, reader, audience = await collector_setup(db, holder=holder)
    if locale != binding.locale:
        from jt_oz_bridge.storage.control_models import Binding

        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(locale=locale))
        binding.locale = locale
    collector = TranscriptCollector(
        previous.bindings, {REF: reader}, previous.fence, drafts_enabled=True
    )
    rendered = output(collector, reader, limit=limit)
    primary = TranscriptPublisher(
        collector, rendered.replies, rendered.formatter, drafts_enabled=True
    )
    clock = [time.time()]
    drafts = TranscriptDraftPublisher(
        collector, primary.replies, primary.formatter, clock=lambda: clock[0]
    )
    chat = SyntheticChat()
    worker = DeliveryWorker(
        primary.outbox,
        chat,
        collector.fence.holder,
        collector.fence.fencing,
        minimum_interval=0,
        draft_readers={REF: reader},
    )
    await baseline(primary, collector, binding)
    await deliver(worker)
    return collector, binding, reader, primary, drafts, worker, chat, clock, audience


async def deliver(worker):
    for _ in range(100):
        async with worker.db.sessions() as session:
            identity = await session.scalar(worker.next_pending("realm", time.time()))
        if identity is None:
            return
        state = await worker.advance(identity)
        assert state in {"delivered", "ambiguous", "held"}
    raise AssertionError("unbounded fixture delivery")


async def current_candidate(drafts):
    identity = await drafts.next_pending()
    assert identity is not None
    return identity


async def live(collector, binding, reader, primary, text="Partial original text"):
    reader.messages[:0] = [
        assistant(text=text, completed=False),
        entry("original_live_user", "Computer input"),
    ]
    reader.state = ExecutionState.RUNNING
    await collector.collect(binding)
    await drain(primary)


async def update_text(collector, binding, reader, primary, text):
    reader.messages[0] = assistant(text=text, completed=False)
    await collector.collect(binding)
    await drain(primary)


async def finish(
    collector,
    binding,
    reader,
    primary,
    text="Complete original answer",
    outcome="succeeded",
    identity="native_idle",
):
    reader.messages[0] = assistant(text=text)
    reader.messages.insert(
        0,
        project_message(
            {"id": identity, "type": "idle", "time": {"created": 4}, "outcome": outcome}
        ),
    )
    reader.state = ExecutionState.IDLE
    await collector.collect(binding)
    await drain(primary)


async def allow_edit(drafts, db, clock):
    frames = await rows(db, TranscriptDraft)
    assert len(frames) == 1
    previous = await drafts.outbox.load(frames[0].payload["last_delivery_id"])
    clock[0] = previous.updated_at + 1.1


async def test_partial_versions_edit_one_bot_message_and_do_not_create_native_actions(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    first = await d.publish(await current_candidate(d))
    assert first
    await deliver(w)
    frame = (await rows(db, TranscriptDraft))[0]
    root_message = chat.messages[
        (await d.outbox.load(frame.payload["last_delivery_id"])).posted_message_id
    ]
    assert (
        "Partial original text" in root_message.content and "draft" in root_message.content.lower()
    )
    for text in ["Partial original text plus more", "Partial original text plus more again"]:
        await update_text(c, b, r, p, text)
        await allow_edit(d, db, clock)
        assert await d.publish(await current_candidate(d))
        await deliver(w)
    assert len(chat.messages) == 3  # History, original input, one draft.
    assert [kind for kind, _ in chat.calls] == ["send", "send", "send", "edit", "edit"]
    assert not await rows(db, Action)


async def test_cooldown_coalesces_many_versions_and_preserves_the_latest_text(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    await update_text(c, b, r, p, "Second partial")
    waiting = await current_candidate(d)
    assert await d.publish(waiting) is None
    assert (await rows(db, TranscriptDraftPublication))[-1].state == "pending"
    for i in range(8):
        await update_text(c, b, r, p, "Latest partial " + str(i))
    await allow_edit(d, db, clock)
    newest = await current_candidate(d)
    assert newest != waiting and await d.publish(newest)
    await deliver(w)
    while candidate := await d.next_pending():
        assert await d.publish(candidate) is None
    assert sum(operation == "edit" for operation, _ in chat.calls) == 1
    assert any("Latest partial 7" in m.content for m in chat.messages.values())


async def test_terminal_cancels_unposted_preview_and_does_not_block_full_final_or_notification(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    draft_batch = await d.publish(await current_candidate(d))
    assert draft_batch
    # Success publishes nothing further, so a failure proves the notification still posts.
    await finish(c, b, r, p, outcome="failed")
    candidate = await current_candidate(d)
    assert await d.publish(candidate) is None
    frame = (await rows(db, TranscriptDraft))[0]
    assert (
        frame.finalized
        and (await d.outbox.load(frame.payload["last_delivery_id"])).state == "cancelled"
    )
    await deliver(w)
    bodies = "\n".join(message.content for message in chat.messages.values())
    assert "Complete original answer" in bodies and "failed" in bodies
    assert "Partial original text" not in bodies
    assert all(operation == "send" for operation, _ in chat.calls)


@pytest.mark.parametrize("outcome", ["succeeded", "failed", "interrupted"])
async def test_delivered_draft_is_finalized_with_actual_outcome_and_full_reply_posts_separately(
    db, outcome
):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    await finish(c, b, r, p, outcome=outcome)
    await allow_edit(d, db, clock)
    assert await d.publish(await current_candidate(d))
    await deliver(w)
    frame = (await rows(db, TranscriptDraft))[0]
    edited = await d.outbox.load(frame.payload["last_delivery_id"])
    assert frame.finalized and edited.payload["operation"] == "edit"
    assert outcome in chat.messages[edited.posted_message_id].content
    # A succeeded run has no separate terminal message.
    assert len(chat.messages) == (4 if outcome == "succeeded" else 5)
    assert sum(operation == "edit" for operation, _ in chat.calls) == 1
    assert sum("Complete original answer" in m.content for m in chat.messages.values()) == 2


async def test_long_complete_reply_is_not_replaced_by_one_page_draft_preview(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db, limit=512)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    final = "A substantial final answer. " * 200 + "FINAL_SOURCE_TAIL"
    await finish(c, b, r, p, text=final)
    await allow_edit(d, db, clock)
    await d.publish(await current_candidate(d))
    await deliver(w)
    assert any("FINAL_SOURCE_TAIL" in m.content.replace("\\", "") for m in chat.messages.values())
    assert len(chat.messages) > 5 and all(len(m.content) <= 512 for m in chat.messages.values())


async def test_ambiguous_draft_edit_does_not_block_final_posts_or_trigger_another_edit(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    await update_text(c, b, r, p, "Another partial")
    await allow_edit(d, db, clock)
    await d.publish(await current_candidate(d))
    frame = (await rows(db, TranscriptDraft))[0]
    unknown = frame.payload["last_delivery_id"]
    chat.mode = "timeout"
    assert await w.advance(unknown) == "ambiguous"
    await finish(c, b, r, p)
    candidate = await current_candidate(d)
    assert await d.publish(candidate) is None
    chat.mode = "success"
    await deliver(w)
    assert any("Complete original answer" in m.content for m in chat.messages.values())
    assert sum(kind == "edit" for kind, _ in chat.calls) == 1
    assert await w.reconcile(unknown) == "delivered"
    await allow_edit(d, db, clock)
    assert await d.publish(candidate)
    await deliver(w)
    assert sum(kind == "edit" for kind, _ in chat.calls) == 2


async def test_shared_draft_locale_is_pinned_when_topic_locale_changes(db):
    from jt_oz_bridge.storage.control_models import Binding

    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(locale="zh-TW"))
    await update_text(c, b, r, p, "Updated English-pinned draft")
    await allow_edit(d, db, clock)
    assert await d.publish(await current_candidate(d))
    await deliver(w)
    frame = (await rows(db, TranscriptDraft))[0]
    assert frame.payload["locale"] == "en"


async def test_parallel_planners_commit_one_draft_batch(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    candidate = await current_candidate(d)
    before = len(await rows(db, DeliveryBatch))
    first, second = await asyncio.gather(d.publish(candidate), d.publish(candidate))
    assert first == second and len(await rows(db, DeliveryBatch)) == before + 1
    await deliver(w)
    assert len(chat.messages) == 3


@pytest.mark.parametrize("corrupt", ["candidate", "frame", "plan", "body"])
async def test_generic_delivery_refuses_corrupt_draft_evidence(db, corrupt):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    candidate = await current_candidate(d)
    queued = await d.publish(candidate)
    assert queued
    async with db.sessions.begin() as session:
        row = await session.get(TranscriptDraftPublication, candidate)
        if corrupt == "candidate":
            row.candidate_hash = "0" * 64
        elif corrupt == "plan":
            row.plan_hash = "0" * 64
        elif corrupt == "frame":
            frame = await session.get(TranscriptDraft, row.record_id)
            frame.payload_hash = "0" * 64
        else:
            version = await session.get(TranscriptVersion, row.source_version_id)
            version.payload_hash = "0" * 64
    await deliver(w)
    draft_delivery = next(x for x in await rows(db, Delivery) if x.batch_id == queued)
    assert draft_delivery.state == "held" and len(chat.messages) == 2


async def test_current_private_audience_and_grants_are_required_before_draft_plan(db):
    c, b, r, p, d, w, chat, clock, audience = await setup(db)
    await live(c, b, r, p)
    audience.users = frozenset({7, 8, 999})
    before = len(await rows(db, DeliveryBatch))
    with pytest.raises((Conflict, AccessDenied)):
        await d.publish(await current_candidate(d))
    assert len(await rows(db, DeliveryBatch)) == before and not await rows(db, TranscriptDraft)


async def test_older_incomplete_assistant_before_known_idle_is_not_a_new_live_draft(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    r.messages[:0] = [
        project_message(
            {"id": "old_idle", "type": "idle", "time": {"created": 3}, "outcome": "interrupted"}
        ),
        assistant(identity="old_partial", text="STALE_UNFINISHED_TEXT", completed=False),
    ]
    r.state = ExecutionState.IDLE
    await c.collect(b)
    await drain(p)
    assert await d.publish(await current_candidate(d)) is None
    await live(c, b, r, p, text="Current original work")
    assert await d.publish(await current_candidate(d))
    await deliver(w)
    assert len(await rows(db, TranscriptDraft)) == 1
    assert all("STALE_UNFINISHED_TEXT" not in m.content for m in chat.messages.values())


async def test_first_terminal_stays_pinned_when_a_later_turn_finishes_differently(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    await finish(c, b, r, p, outcome="succeeded", identity="first_idle")
    original_frame = (await rows(db, TranscriptDraft))[0]
    first_terminal = original_frame.terminal_version_id
    assert first_terminal
    r.messages[:0] = [
        project_message(
            {"id": "second_idle", "type": "idle", "time": {"created": 8}, "outcome": "failed"}
        ),
        assistant(identity="second_assistant", text="Another task failed"),
        entry("second_user", "Different task"),
    ]
    await c.collect(b)
    await drain(p)
    frame = (await rows(db, TranscriptDraft))[0]
    assert frame.terminal_version_id == first_terminal
    await allow_edit(d, db, clock)
    assert await d.publish(await current_candidate(d))
    await deliver(w)
    frame = (await rows(db, TranscriptDraft))[0]
    posted = await d.outbox.load(frame.payload["last_delivery_id"])
    assert "succeeded" in chat.messages[posted.posted_message_id].content


async def test_restart_uses_sealed_frame_locale_lineage_and_actual_delivery_timestamp(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await d.publish(await current_candidate(d))
    await deliver(w)
    await update_text(c, b, r, p, "Text observed after restart")
    successor = TranscriptDraftPublisher(c, p.replies, p.formatter, clock=lambda: clock[0])
    candidate = await current_candidate(successor)
    assert await successor.publish(candidate) is None
    await allow_edit(successor, db, clock)
    assert await successor.publish(candidate)
    await deliver(w)
    assert len(chat.messages) == 3 and sum(operation == "edit" for operation, _ in chat.calls) == 1


async def test_draft_redacts_secrets_and_preserves_bounded_balanced_code_preview(db):
    c, b, r, p, d, w, chat, clock, _ = await setup(db, limit=512)
    secret = "sk-proj-" + ("a" * 32)
    text = "Original output " + secret + "\n```python\n" + ("print(123)\n" * 100)
    await live(c, b, r, p, text=text)
    assert await d.publish(await current_candidate(d))
    await deliver(w)
    frame = (await rows(db, TranscriptDraft))[0]
    saved = await d.outbox.load(frame.payload["last_delivery_id"])
    body = chat.messages[saved.posted_message_id].content
    assert secret not in body and len(body) <= 512
    assert body.count("```") % 2 == 0


async def test_superseded_primary_partial_requires_no_wire_but_draft_still_reauthorizes(db):
    from unittest.mock import AsyncMock

    c, b, r, p, d, w, chat, clock, audience = await setup(db)
    await live(c, b, r, p)
    r.messages[0] = assistant(text="A later partial", completed=False)
    await c.collect(b)
    old_preflight = c.preflight
    c.preflight = AsyncMock(side_effect=AssertionError("No external output in draft-owned primary"))
    try:
        kind, identity = await p.next_pending()
        assert kind == "version" and await p.publish(identity) is None
        c.preflight.assert_not_awaited()
    finally:
        c.preflight = old_preflight
    audience.private = False
    with pytest.raises((Conflict, AccessDenied)):
        await d.publish(await current_candidate(d))


@pytest.mark.parametrize("change", ["idle", "reader"])
async def test_resource_preview_also_requires_current_original_authority_at_send(db, change):
    c, b, r, p, d, w, chat, clock, _ = await setup(db)
    await live(c, b, r, p)
    await deliver(w)
    assert await d.publish(await current_candidate(d))
    frame = (await rows(db, TranscriptDraft))[0]
    calls = len(chat.calls)
    if change == "idle":
        r.state = ExecutionState.IDLE
    else:
        w = DeliveryWorker(p.outbox, chat, c.fence.holder, c.fence.fencing, minimum_interval=0)
    identity = frame.payload["last_delivery_id"]
    assert await w.advance(identity) == "held"
    assert (await w.outbox.load(identity)).attempts == 0
    assert len(chat.calls) == calls
