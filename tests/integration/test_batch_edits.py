"""Atomic immutable edit batches on the same Bot message; synthetic chat only."""

import asyncio
import copy

import pytest
from sqlalchemy import update

from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch, Grant
from tests.integration.test_routed_output import setup
from tests.integration.test_router import count


async def batch(outbox, binding, key, text, **kwargs):
    return await outbox.queue_batch(
        key,
        binding.id,
        binding.revision,
        (text,),
        renderer_version="edit-test-v1",
        message_limit=512,
        topic_limit=100,
        **kwargs,
    )


async def test_post_and_multiple_atomic_edits_keep_one_message_and_strict_target_chain(db):
    outbox, binding, worker, _, chat = await setup(db)
    first = await batch(outbox, binding, "first", "First draft")
    assert await worker.advance(first.deliveries[0]) == "delivered"
    previous = first
    for index in range(3):
        text = "Draft update " + str(index)
        current = await batch(
            outbox,
            binding,
            "edit" + str(index),
            text,
            edit_of=previous.deliveries[0],
            after_batch_id=previous.id,
        )
        assert await outbox.batch_by_id(current.id, binding.id, 1) == current
        assert await worker.advance(current.deliveries[0]) == "delivered"
        assert len(chat.messages) == 1 and text in chat.messages[1000].content
        assert (await outbox.load(current.deliveries[0])).posted_message_id == 1000
        previous = current
    assert [operation for operation, _ in chat.calls] == ["send", "edit", "edit", "edit"]
    assert await count(db, DeliveryBatch) == await count(db, Delivery) == 4
    stale = await batch(outbox, binding, "stale", "Do not overwrite", edit_of=first.deliveries[0])
    assert await worker.advance(stale.deliveries[0]) == "held"
    assert len(chat.calls) == 4


async def test_concurrent_edit_planners_are_idempotent_but_target_change_is_not(db):
    outbox, binding, worker, _, chat = await setup(db)
    first = await batch(outbox, binding, "first", "Original")
    other = await batch(outbox, binding, "other", "Other original")
    await worker.advance(first.deliveries[0])
    await worker.advance(other.deliveries[0])
    values = await asyncio.gather(
        *[
            batch(outbox, binding, "edit", "One update", edit_of=first.deliveries[0])
            for _ in range(4)
        ]
    )
    assert all(value == values[0] for value in values)
    with pytest.raises(Conflict, match="plan_changed"):
        await batch(outbox, binding, "edit", "One update", edit_of=other.deliveries[0])
    await worker.advance(values[0].deliveries[0])
    assert len(chat.messages) == 2 and len(chat.calls) == 3


async def test_ambiguous_edit_is_reconciled_by_get_and_never_repeated(db):
    outbox, binding, worker, _, chat = await setup(db)
    first = await batch(outbox, binding, "first", "Initial")
    await worker.advance(first.deliveries[0])
    edited = await batch(outbox, binding, "edit", "Partial update", edit_of=first.deliveries[0])
    chat.mode = "timeout"
    assert await worker.advance(edited.deliveries[0]) == "ambiguous"
    assert await worker.advance(edited.deliveries[0]) == "ambiguous"
    assert await worker.reconcile(edited.deliveries[0]) == "delivered"
    assert len(chat.calls) == 2 and len(chat.messages) == 1


@pytest.mark.parametrize("change", ["undelivered", "foreign_bot", "hash", "scope", "grant"])
async def test_edit_planning_rejects_unverified_or_unauthorized_parent(db, change):
    outbox, binding, worker, _, chat = await setup(db)
    first = await batch(outbox, binding, "first", "Initial")
    if change != "undelivered":
        await worker.advance(first.deliveries[0])
    async with db.sessions.begin() as session:
        previous = await session.get(Delivery, first.deliveries[0])
        if change == "hash":
            previous.payload_hash = "0" * 64
        elif change == "scope":
            previous.binding_revision = 2
        elif change == "grant":
            await session.execute(update(Grant).values(active=False))
        elif change == "foreign_bot":
            payload = copy.deepcopy(previous.payload)
            payload["bot_user_id"] = 999
            previous.payload = payload
            from jt_oz_bridge.storage.durable import digest

            previous.payload_hash = digest(payload)
    with pytest.raises((Conflict, AccessDenied)):
        await batch(outbox, binding, "edit", "Never queue", edit_of=first.deliveries[0])
    assert await count(db, DeliveryBatch) == 1


async def test_edit_batches_are_single_page_and_current_target_changes_hold(db):
    outbox, binding, worker, _, chat = await setup(db)
    first = await batch(outbox, binding, "first", "Initial")
    await worker.advance(first.deliveries[0])
    with pytest.raises(ValueError, match="single_page"):
        await outbox.queue_batch(
            "invalid",
            binding.id,
            1,
            ("one", "two"),
            renderer_version="test",
            message_limit=512,
            topic_limit=100,
            edit_of=first.deliveries[0],
        )
    edited = await batch(outbox, binding, "edit", "Updated", edit_of=first.deliveries[0])
    chat.messages[1000] = chat.messages[1000].model_copy(update={"content": "External change"})
    assert await worker.advance(edited.deliveries[0]) == "held"
    assert len(chat.calls) == 1


async def test_corrupt_cached_edit_target_is_refused_on_generic_outbox_path(db):
    outbox, binding, worker, _, _ = await setup(db)
    first = await batch(outbox, binding, "first", "Initial")
    await worker.advance(first.deliveries[0])
    edited = await batch(outbox, binding, "edit", "Updated", edit_of=first.deliveries[0])
    async with db.sessions.begin() as session:
        previous = await session.get(Delivery, first.deliveries[0])
        previous.posted_message_id = 9999
    with pytest.raises(Conflict):
        await outbox.batch_by_id(edited.id, binding.id, 1)
