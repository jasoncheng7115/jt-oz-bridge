"""Synthetic resource evidence + real own transactions; no upstream mutations."""

import asyncio
import copy
from html import unescape

import pytest
from sqlalchemy import delete, event, select, update

from jt_oz_bridge.adapters.opencode.turn_resources import ResourceText
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.resource_publisher import ResourcePublisher, publication_plan
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant, WorkerLease
from jt_oz_bridge.storage.publication_models import BatchDependency
from jt_oz_bridge.storage.resource_models import (
    ResourcePublication,
    ResourceResultRecord,
    ResourceTextRecord,
)
from tests.integration.test_resource_execution_results import setup as resource_setup
from tests.integration.test_router import Source, message


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


async def setup(db, *, text=None, outcome="succeeded", locale="en", limit=1000):
    collector, binding, identity, reader, execution, audience = await resource_setup(
        db, locale=locale
    )
    reader.mode = outcome
    if text is not None:

        async def change():
            reader.evidence = reader.evidence.model_copy(
                update={
                    "turn": reader.evidence.turn.model_copy(
                        update={
                            "text": tuple(
                                ResourceText(
                                    assistant_id="msg_synthetic_final", content_index=i, text=value
                                )
                                for i, value in enumerate(text)
                            )
                        }
                    )
                }
            )

        reader.hook = change
    if locale != "en":
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(locale=locale)
            )
    await collector.collect(identity, "realm")
    outbox = Outbox(collector.bindings, 77, fence=collector.fence)
    publisher = ResourcePublisher(
        RoutedOutbox(outbox, realm_id="realm", message_limit=limit, topic_limit=60)
    )
    return publisher, collector, binding, identity, execution, audience


@pytest.mark.parametrize(
    "outcome,notice",
    [
        ("succeeded", "OpenCode finished"),
        ("failed", "reported a failure"),
        ("interrupted", "stopped this work"),
    ],
)
async def test_only_sealed_completed_input_is_published_once_with_its_actual_outcome(
    db, outcome, notice
):
    publisher, collector, _binding, identity, execution, _audience = await setup(
        db, outcome=outcome
    )
    assert await publisher.next_pending() == identity
    first = await publisher.publish(identity)
    assert await publisher.next_pending() is None
    assert await publisher.publish(identity) == first
    assert len(await rows(db, DeliveryBatch)) == len(await rows(db, ResourcePublication)) == 1
    content = "\n".join(r.payload["content"] for r in await rows(db, Delivery))
    assert (
        notice in content
        and "PRIVATE_NATIVE_FINAL_RESULT" in unescape(content)
        and identity not in content
    )
    assert len(execution.submitted) == 1 and collector.reader.calls == 1


async def test_restart_retains_sealed_locale_limits_pages_and_markers(db):
    publisher, _collector, _binding, identity, execution, _audience = await setup(
        db, locale="zh-TW", text=["原生結果 " * 300], limit=512
    )
    first = await publisher.publish(identity)
    original = [(r.payload, r.payload_hash) for r in await rows(db, Delivery)]
    assert len(first.deliveries) > 1 and "已完成" in original[0][0]["content"]
    assert all(len(payload["content"]) <= 512 for payload, _ in original)
    other = ResourcePublisher(
        RoutedOutbox(publisher.outbox, realm_id="realm", message_limit=900, topic_limit=60)
    )
    assert await other.publish(identity) == first
    assert original == [(r.payload, r.payload_hash) for r in await rows(db, Delivery)]
    assert len(execution.submitted) == 1


async def test_every_page_and_publication_plan_roll_back_and_recover_without_native_resubmission(
    db,
):
    publisher, _collector, _binding, identity, execution, _audience = await setup(
        db, text=["bounded final text " * 200], limit=512
    )

    def fail(*args):
        raise OSError("synthetic publication write failure")

    event.listen(ResourcePublication, "before_insert", fail)
    try:
        with pytest.raises(OSError):
            await publisher.publish(identity)
    finally:
        event.remove(ResourcePublication, "before_insert", fail)
    assert (
        not await rows(db, ResourcePublication)
        and not await rows(db, DeliveryBatch)
        and not await rows(db, Delivery)
    )
    assert (await rows(db, Action))[0].state == "completed"
    assert await publisher.next_pending() == identity
    assert len((await publisher.publish(identity)).deliveries) > 1 and len(execution.submitted) == 1


async def test_parallel_planners_create_one_atomic_batch(db):
    publisher, _collector, _binding, identity, _execution, _audience = await setup(db)
    first, second = await asyncio.gather(
        publisher.publish(identity), ResourcePublisher(publisher.replies).publish(identity)
    )
    assert (
        first == second
        and len(await rows(db, ResourcePublication)) == len(await rows(db, DeliveryBatch)) == 1
    )


@pytest.mark.parametrize("change", ["audience", "public", "revision", "view"])
async def test_publication_rechecks_current_private_audience_scope_and_grants(db, change):
    publisher, _collector, binding, identity, _execution, audience = await setup(db)
    if change == "audience":
        audience.users = frozenset({7, 8, 999})
    elif change == "public":
        audience.private = False
    else:
        async with db.sessions.begin() as session:
            if change == "revision":
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(revision=2)
                )
            else:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
    with pytest.raises((Conflict, AccessDenied)):
        await publisher.publish(identity)
    assert not await rows(db, ResourcePublication) and not await rows(db, Delivery)


async def test_expired_consumer_cannot_publish_and_successor_recovers_local_result(db):
    publisher, _collector, _binding, identity, execution, _audience = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
    with pytest.raises(Conflict):
        await publisher.publish(identity)
    fencing = await DurableStore(db).acquire_lease("resource-successor")
    outbox = Outbox(
        publisher.outbox.bindings, 77, fence=ConsumerFence("resource-successor", fencing)
    )
    fresh = ResourcePublisher(
        RoutedOutbox(outbox, realm_id="realm", message_limit=1000, topic_limit=60)
    )
    await fresh.publish(identity)
    assert len(execution.submitted) == 1


@pytest.mark.parametrize("change", ["index", "result", "page", "plan"])
async def test_cached_publication_rejects_changed_result_index_page_or_encrypted_plan(db, change):
    publisher, _collector, _binding, identity, _execution, _audience = await setup(db)
    first = await publisher.publish(identity)
    async with db.sessions.begin() as session:
        if change == "index":
            await session.execute(update(ResourceResultRecord).values(source_hash="c" * 64))
        elif change == "result":
            saved = await session.get(Action, identity)
            payload = copy.deepcopy(saved.native_result)
            payload["evidence"]["turn"]["text"][0]["text"] = "another result"
            saved.native_result = payload
        elif change == "page":
            await session.execute(
                update(Delivery)
                .where(Delivery.id == first.deliveries[0])
                .values(payload_hash="c" * 64)
            )
        else:
            await session.execute(update(ResourcePublication).values(payload_hash="c" * 64))
    with pytest.raises(ValueError):
        await publisher.publish(identity)
    assert len(await rows(db, DeliveryBatch)) == 1


async def test_no_text_is_an_explicit_outcome_notice_not_an_invented_assistant_message(db):
    publisher, _collector, _binding, identity, _execution, _audience = await setup(db, text=[])
    await publisher.publish(identity)
    assert "No text reply" in (await rows(db, Delivery))[0].payload["content"]
    assert not await rows(db, ResourceTextRecord)


async def test_secret_redaction_is_display_only_and_oversize_uses_full_output_notice(db):
    secret = "sk-" + "A" * 24
    publisher, _collector, _binding, identity, _execution, _audience = await setup(
        db, text=["test credential " + secret]
    )
    await publisher.publish(identity)
    content = (await rows(db, Delivery))[0].payload["content"]
    assert secret not in content and "REDACTED" in content and "hidden" in content
    assert (
        secret in (await rows(db, Action))[0].native_result["evidence"]["turn"]["text"][0]["text"]
    )
    result = (await rows(db, Action))[0]
    from jt_oz_bridge.services.resource_execution_results import resource_result

    sealed = resource_result(result)
    large = sealed.model_copy(
        update={
            "evidence": sealed.evidence.model_copy(
                update={
                    "turn": sealed.evidence.turn.model_copy(
                        update={
                            "text": (
                                ResourceText(assistant_id="m", content_index=0, text="z" * 1000000),
                            )
                        }
                    )
                }
            )
        }
    )
    state, pages = publisher.pages(large, "en")
    assert state == "needs_full_output" and "!output" in unescape("".join(pages))
    assert publication_plan((await rows(db, ResourcePublication))[0]).state == "queued"


async def test_earlier_result_must_be_planned_first_and_its_dependency_cannot_disappear(db):
    publisher, collector, binding, first_id, execution, _audience = await setup(db)
    source = Source()
    item = message("Second exact prompt", 301)
    source.messages[item.message_id] = item
    second = await QueueService(collector.bindings).receive(binding.id, item)
    dispatcher = Dispatcher(
        collector.bindings, execution, source, collector.fence.holder, collector.fence.fencing
    )
    assert await dispatcher.advance(second.action_id) == "admitted"
    await collector.collect(second.action_id, "realm")
    with pytest.raises(Conflict, match="earlier_result_pending"):
        await publisher.publish(second.action_id)
    assert not await rows(db, DeliveryBatch)
    first = await publisher.publish(first_id)
    following = await publisher.publish(second.action_id)
    dependency = (await rows(db, BatchDependency))[0]
    assert dependency.batch_id == following.id and dependency.before_batch_id == first.id
    async with db.sessions.begin() as session:
        await session.execute(
            delete(BatchDependency).where(BatchDependency.batch_id == following.id)
        )
    with pytest.raises(Conflict, match="publication_batch_evidence_changed"):
        await publisher.publish(second.action_id)
    assert len(execution.submitted) == 2


async def test_prompt_language_is_frozen_before_dispatch_and_preserved_on_source_refresh(db):
    collector, binding, _identity, _reader, execution, _audience = await resource_setup(db)
    source = Source()
    original = message("A queued prompt", 401)
    queue = QueueService(collector.bindings)
    queued = await queue.receive(binding.id, original, reply_locale="zh-TW")
    edited = original.model_copy(update={"revision": 1, "text": "Edited queued prompt"})
    source.messages[edited.message_id] = edited
    dispatcher = Dispatcher(
        collector.bindings, execution, source, collector.fence.holder, collector.fence.fencing
    )
    # Complete the earlier action so this synthetic root queue can advance.
    await collector.collect(_identity, "realm")
    assert await dispatcher.advance(queued.action_id) == "admitted"
    saved = next(r for r in await rows(db, Action) if r.id == queued.action_id)
    assert saved.payload["reply_locale"] == "zh-TW" and saved.payload["text"] == edited.text
