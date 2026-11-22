import asyncio
from dataclasses import replace

import pytest
from sqlalchemy import delete, update

from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import RoutedInput
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_router import count, message, router, send
from tests.support import bound


async def setup(db):
    bindings, binding, _control, _audience = await bound(db)
    fencing = await DurableStore(db).acquire_lease("batch")
    outbox = Outbox(bindings, 77, fence=ConsumerFence("batch", fencing))
    chat = SyntheticChat()
    worker = DeliveryWorker(outbox, chat, "batch", fencing, minimum_interval=0)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=300, topic_limit=100)
    return outbox, binding, worker, publisher, chat


async def queue(outbox, binding, **changes):
    return await outbox.queue_batch(
        "source",
        binding.id,
        1,
        changes.pop("pages", ("page zero", "page one", "page two")),
        renderer_version="test-v1",
        message_limit=300,
        topic_limit=100,
        **changes,
    )


async def test_atomic_batch_is_idempotent_with_concurrent_callers_and_immutable_plan(db):
    outbox, binding, _worker, _publisher, _chat = await setup(db)
    results = await asyncio.gather(*[queue(outbox, binding) for _ in range(6)])
    assert all(item == results[0] for item in results)
    assert len(results[0].deliveries) == 3
    assert await count(db, DeliveryBatch) == 1 and await count(db, Delivery) == 3
    with pytest.raises(Conflict, match="plan_changed"):
        await queue(outbox, binding, pages=("different",))
    assert await count(db, Delivery) == 3


async def test_reply_batch_commit_failure_leaves_no_parent_or_partial_pages(db):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    outbox, binding, _worker, _publisher, _chat = await setup(db)

    def fail(_session):
        raise RuntimeError("injected before batch commit")

    event.listen(Session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="batch commit"):
            await queue(outbox, binding)
    finally:
        event.remove(Session, "before_commit", fail)
    assert await count(db, DeliveryBatch) == await count(db, Delivery) == 0
    assert len((await queue(outbox, binding)).deliveries) == 3


async def test_pages_cannot_overtake_each_other_even_with_reversed_clock_order(db):
    outbox, binding, worker, _publisher, chat = await setup(db)
    batch = await queue(outbox, binding)
    async with db.sessions.begin() as session:
        for index, identity in enumerate(batch.deliveries):
            await session.execute(
                update(Delivery).where(Delivery.id == identity).values(created_at=100 - index)
            )
    assert await worker.advance(batch.deliveries[2]) == "pending"
    assert await worker.advance(batch.deliveries[1]) == "pending"
    assert chat.calls == []
    for identity in batch.deliveries:
        assert await worker.advance(identity) == "delivered"
    assert [call[1].split("[")[0] for call in chat.calls] == ["page zero", "page one", "page two"]


@pytest.mark.parametrize("change", ["audience", "private", "grant"])
async def test_fresh_audience_and_grants_are_checked_after_all_local_batch_metadata_awaits(
    db, change
):
    from jt_oz_bridge.storage.models import Grant

    outbox, binding, worker, _publisher, chat = await setup(db)
    batch = await queue(outbox, binding)
    validate = outbox._validated_batch

    async def changed(*args):
        result = await validate(*args)
        if change == "audience":
            outbox.bindings.audience.users = frozenset({7, 8, 999})
        elif change == "private":
            outbox.bindings.audience.private = False
        else:
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        return result

    outbox._validated_batch = changed
    assert await worker.advance(batch.deliveries[0]) == "held"
    assert (await outbox.load(batch.deliveries[0])).attempts == 0
    assert not chat.calls and not chat.messages


async def test_uncertain_first_page_blocks_later_pages_without_blocking_other_controls(db):
    outbox, binding, worker, _publisher, chat = await setup(db)
    batch = await queue(outbox, binding)
    chat.mode = "timeout"
    assert await worker.advance(batch.deliveries[0]) == "ambiguous"
    chat.mode = "success"
    assert await worker.advance(batch.deliveries[1]) == "pending"
    urgent = await outbox.queue("other-control", binding.id, 1, "independent control", priority=0)
    assert await worker.advance(urgent) == "delivered"
    assert len(chat.calls) == 2
    assert await worker.reconcile(batch.deliveries[0]) == "delivered"
    assert await worker.advance(batch.deliveries[1]) == "delivered"
    assert len(chat.calls) == 3


async def test_missing_page_or_false_delivery_proof_never_unlocks_following_page(db):
    outbox, binding, worker, _publisher, chat = await setup(db)
    batch = await queue(outbox, binding)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Delivery)
            .where(Delivery.id == batch.deliveries[0])
            .values(state="delivered", posted_message_id=None)
        )
    assert await worker.advance(batch.deliveries[1]) == "pending"
    assert chat.calls == []
    async with db.sessions.begin() as session:
        await session.execute(delete(Delivery).where(Delivery.id == batch.deliveries[0]))
    assert await worker.advance(batch.deliveries[1]) == "held"
    assert chat.calls == []
    with pytest.raises(Conflict, match="incomplete"):
        await outbox.cached_batch("source", binding.id, 1)


async def test_renderer_uses_verified_limits_headers_safe_content_and_cached_plan(db):
    outbox, binding, worker, publisher, chat = await setup(db)
    source = "## Help\n\n" + "\n\n".join(
        f"Paragraph {index}: exact user-visible text." for index in range(20)
    )
    routed = RoutedInput("reply", binding.id, 1, source, "routed-1", locale="zh-TW")
    batch = await publisher.publish(routed)
    assert len(batch.deliveries) > 1
    assert await publisher.publish(routed) == batch
    # Once projected, the original plan survives renderer/limit or current-state
    # changes for the same event. No new posts or silent page reshaping.
    changed_publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=500, topic_limit=100)
    assert await changed_publisher.publish(replace(routed, text="new dynamic status")) == batch
    for identity in batch.deliveries:
        saved = await outbox.load(identity)
        assert len(saved.payload["content"]) <= 300
        assert "頁" in saved.payload["content"]
        assert await worker.advance(identity) == "delivered"
    combined = "\n".join(item.content for item in chat.messages.values())
    assert all(f"Paragraph {index}" in combined for index in range(20))
    assert await count(db, DeliveryBatch) == 1


async def test_router_reply_survives_crash_before_projection_and_replays_same_batch(db):
    service, binding, source, _control, _audience = await router(db)
    routed = await send(service, source, message("!oz menu"))
    outbox = Outbox(service.bindings, 77, fence=service.inbox.fence)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=10000, topic_limit=100)
    # A committed receipt can regenerate its reply without issuing a second menu
    # after a crash before any delivery rows were written.
    replayed = await service.route(source.messages[101])
    assert replayed == routed
    first = await publisher.publish(replayed)
    second = await publisher.publish(await service.route(source.messages[101]))
    assert first == second and await count(db, DeliveryBatch) == 1


async def test_lost_fence_and_foreign_realm_cannot_create_reply_batches(db):
    outbox, binding, _worker, publisher, _chat = await setup(db)
    routed = RoutedInput("reply", binding.id, 1, "safe text", "source")
    foreign = RoutedOutbox(outbox, realm_id="other", message_limit=10000, topic_limit=100)
    with pytest.raises(Conflict, match="realm"):
        await foreign.publish(routed)
    await DurableStore(db).release_lease("batch", outbox.fence.fencing)
    with pytest.raises(Conflict, match="lease"):
        await publisher.publish(routed)
    assert await count(db, DeliveryBatch) == 0


async def test_invalid_or_oversize_reply_contract_never_creates_partial_batch(db):
    outbox, binding, _worker, publisher, _chat = await setup(db)
    for pages in [(), ("x" * 300,), tuple("x" for _ in range(101))]:
        with pytest.raises(ValueError):
            await queue(outbox, binding, pages=pages)
    assert await publisher.publish(RoutedInput("ignore")) is None
    tiny_topic = RoutedOutbox(outbox, realm_id="realm", message_limit=300, topic_limit=2)
    with pytest.raises(ValueError, match="topic"):
        await tiny_topic.publish(RoutedInput("reply", binding.id, 1, "safe", "limited-topic"))
    assert await count(db, DeliveryBatch) == await count(db, Delivery) == 0


async def test_tampered_plan_manifest_or_page_content_is_held_before_first_post(db):
    outbox, binding, worker, _publisher, chat = await setup(db)
    batch = await queue(outbox, binding)
    async with db.sessions.begin() as session:
        await session.execute(
            update(DeliveryBatch).where(DeliveryBatch.id == batch.id).values(plan_hash="0" * 64)
        )
    assert await worker.advance(batch.deliveries[0]) == "held"
    assert chat.calls == []
    with pytest.raises(Conflict, match="plan_changed"):
        await outbox.cached_batch("source", binding.id, 1)


async def test_restart_keeps_same_plan_and_held_pages_without_automatic_release(db):
    outbox, binding, worker, publisher, chat = await setup(db)
    routed = RoutedInput(
        "reply", binding.id, 1, "First paragraph.\n\nSecond paragraph.", "restart-source"
    )
    batch = await publisher.publish(routed)
    await DurableStore(db).recover()
    assert await publisher.publish(routed) == batch
    for identity in batch.deliveries:
        assert (await outbox.load(identity)).state == "held"
        assert await worker.advance(identity) == "held"
    assert chat.calls == []


async def committed_discovery_reply(db):
    """Synthetic completed command and full outbox share the real finish SQL transaction."""
    from jt_oz_bridge.presentation.markdown import MobileMarkdown
    from jt_oz_bridge.services.command_receipts import CommandInbox
    from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox, DiscoveryReplyPublisher
    from jt_oz_bridge.services.reply_publisher import ReplyPublisher
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from tests.integration.test_output_destinations import prepared

    destinations, reader, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    discovery = DiscoveryReplyPublisher(outbox, realm_id="realm", message_limit=300, topic_limit=60)
    publisher = ReplyPublisher(
        RoutedOutbox(
            Outbox(destinations.discovery.bindings, 77, fence=destinations.fence),
            realm_id="realm",
            message_limit=300,
            topic_limit=60,
        ),
        discovery,
    )
    text, locale = "## Original menu\n\n" + "Exact original choice.\n\n" * 12, "en"
    header = discovery.tr.render("output.page", locale, index=100, total=100) + "\n\n"
    rendered = MobileMarkdown(locale=locale).render(
        text,
        300,
        reserved_characters=len(header) + MARKER_FOOTER_SIZE,
    )
    pages = tuple(
        discovery.tr.render("output.page", locale, index=i, total=len(rendered.pages))
        + "\n\n"
        + page
        for i, page in enumerate(rendered.pages, 1)
    )
    inbox = CommandInbox(db, destinations.fence.holder, destinations.fence.fencing)
    claim = await inbox.claim(target.source, "sessions")
    batches = []
    response = dict(
        origin="discovery", text=text, locale=locale, target=target.model_dump(mode="json")
    )

    async def commit(session):
        batch = await outbox.queue_scope_batch_in_session(
            session,
            "command:" + claim.id,
            target,
            pages,
            renderer_version="discovery-mobile-markdown-v2",
            message_limit=300,
            topic_limit=60,
        )
        batches.append(batch)
        await session.execute(
            update(CommandReceipt)
            .where(CommandReceipt.id == claim.id)
            .values(
                response={**response, "queued_batch_id": batch.id},
            )
        )

    await inbox.finish(claim, response, commit=commit)
    routed = RoutedInput(
        "reply",
        text=text,
        locale=locale,
        discovery_target=target,
        delivery_key="command:" + claim.id,
        queued_batch_id=batches[0].id,
    )
    return publisher, routed, batches[0], destinations, reader


async def test_committed_reply_fastpath_never_reauthorizes_or_queues(db, monkeypatch):
    from unittest.mock import AsyncMock

    publisher, routed, batch, destinations, reader = await committed_discovery_reply(db)
    forbidden = AsyncMock(side_effect=AssertionError("committed output must not re-read or queue"))
    monkeypatch.setattr(destinations, "authorize", forbidden)
    monkeypatch.setattr(destinations, "persist_in_session", forbidden)
    monkeypatch.setattr(reader, "read", forbidden)
    monkeypatch.setattr(destinations.discovery.bindings.audience, "inspect", forbidden)
    monkeypatch.setattr(publisher.discovery.outbox, "queue_scope_batch", forbidden)
    monkeypatch.setattr(publisher.discovery.outbox, "queue_scope_batch_in_session", forbidden)
    before = await count(db, Delivery)
    assert await publisher.publish(routed) == batch
    assert await publisher.publish(routed) == batch
    forbidden.assert_not_awaited()
    assert await count(db, Delivery) == before and await count(db, DeliveryBatch) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "body",
        "body_and_saved",
        "rehashed_page",
        "locale",
        "source_actor",
        "source_topic",
        "foreign_realm",
        "receipt_processing",
        "receipt_hash",
        "response_body",
        "response_origin",
        "response_batch",
        "response_binding",
        "destination_key",
        "destination_hash",
        "destination_state",
        "destination_expiry",
        "batch_key",
        "batch_renderer",
        "batch_limit",
        "batch_plan",
        "missing_page",
        "page_hash",
        "routed_binding",
        "routed_action",
        "wrong_key",
        "wrong_batch",
        "oversize_text",
    ],
)
async def test_committed_reply_rejects_changed_or_incomplete_evidence_without_new_work(db, fault):
    from uuid import uuid4

    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.output_models import OutputDestination

    publisher, routed, batch, _, _ = await committed_discovery_reply(db)
    target = routed.discovery_target
    assert target is not None
    async with db.sessions.begin() as session:
        receipt = await session.get(CommandReceipt, routed.delivery_key.removeprefix("command:"))
        destination = await session.get(OutputDestination, str(target.id))
        parent = await session.get(DeliveryBatch, batch.id)
        if fault == "body":
            routed = replace(routed, text="different visible body")
        elif fault == "body_and_saved":
            routed = replace(routed, text="different saved and routed text")
            receipt.response = {**receipt.response, "text": routed.text}
        elif fault == "rehashed_page":
            from jt_oz_bridge.storage.durable import digest

            page = await session.get(Delivery, batch.deliveries[-1])
            payload = {**page.payload, "content": "changed body\n" + page.payload["content"]}
            assert len(payload["content"]) <= publisher.discovery.message_limit
            page.payload, page.payload_hash = payload, digest(payload)
        elif fault == "locale":
            routed = replace(routed, locale="zh-TW")
        elif fault in {"source_actor", "source_topic", "foreign_realm"}:
            source, audience = target.source, target.audience
            if fault == "source_actor":
                source = source.model_copy(update={"author_id": 8})
            elif fault == "source_topic":
                source = source.model_copy(update={"topic": "other"})
                audience = audience.model_copy(update={"canonical_topic": "other"})
            else:
                source = source.model_copy(update={"realm_id": "other"})
                audience = audience.model_copy(update={"realm_id": "other"})
            routed = replace(
                routed,
                discovery_target=target.model_copy(update={"source": source, "audience": audience}),
            )
        elif fault == "receipt_processing":
            receipt.state = "processing"
        elif fault == "receipt_hash":
            receipt.source_hash = "f" * 64
        elif fault.startswith("response_"):
            change = {
                "body": {"text": "changed saved text"},
                "origin": {"origin": "foreign"},
                "batch": {"queued_batch_id": str(uuid4())},
                "binding": {"target": None, "binding_id": str(uuid4()), "binding_revision": 1},
            }[fault.removeprefix("response_")]
            receipt.response = {**receipt.response, **change}
        elif fault.startswith("destination_"):
            field, value = {
                "key": ("dedupe_key", "foreign-key"),
                "hash": ("authorization_hash", "f" * 64),
                "state": ("state", "revoked"),
                "expiry": ("expires_at", 1),
            }[fault.removeprefix("destination_")]
            setattr(destination, field, value)
        elif fault.startswith("batch_"):
            field, value = {
                "key": ("dedupe_key", "foreign-key"),
                "renderer": ("renderer_version", "other"),
                "limit": ("message_limit", 301),
                "plan": ("plan_hash", "f" * 64),
            }[fault.removeprefix("batch_")]
            setattr(parent, field, value)
        elif fault == "missing_page":
            await session.execute(delete(Delivery).where(Delivery.id == batch.deliveries[-1]))
        elif fault == "page_hash":
            await session.execute(
                update(Delivery)
                .where(Delivery.id == batch.deliveries[-1])
                .values(payload_hash="f" * 64)
            )
        elif fault == "routed_binding":
            routed = replace(routed, binding_id=str(uuid4()), binding_revision=1)
        elif fault == "routed_action":
            routed = replace(routed, action_id=str(uuid4()))
        elif fault == "wrong_key":
            routed = replace(routed, delivery_key="source:other")
        elif fault == "wrong_batch":
            routed = replace(routed, queued_batch_id=str(uuid4()))
        else:
            routed = replace(routed, text="x" * 1000001)
    before = await count(db, Delivery)
    with pytest.raises((Conflict, ValueError)):
        await publisher.publish(routed)
    assert await count(db, Delivery) == before and await count(db, DeliveryBatch) == 1


@pytest.mark.parametrize("fault", ["grant", "enrollment", "fence"])
async def test_committed_reply_rechecks_authority_after_last_page_sql_and_rolls_back(db, fault):
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.control_models import EnrolledBackend
    from jt_oz_bridge.storage.models import Grant, WorkerLease

    publisher, routed, _, destinations, _ = await committed_discovery_reply(db)
    outbox = publisher.discovery.outbox
    original = outbox.validated_scope_batch_in_session

    async def changed(session, *args):
        result = await original(session, *args)
        if fault == "grant":
            await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        elif fault == "enrollment":
            await session.execute(update(EnrolledBackend).values(enabled=False))
        else:
            await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
        return result

    outbox.validated_scope_batch_in_session = changed
    with pytest.raises((AccessDenied, Conflict)):
        await publisher.publish(routed)
    async with db.sessions() as session:
        from sqlalchemy import select

        assert all((await session.scalars(select(Grant.active))).all())
        assert all((await session.scalars(select(EnrolledBackend.enabled))).all())
        assert await session.scalar(select(WorkerLease.fencing)) == destinations.fence.fencing


async def test_committed_reply_cancellation_leaves_same_original_source_and_existing_batch(db):
    publisher, routed, batch, _, _ = await committed_discovery_reply(db)
    original = publisher.discovery.outbox.validated_scope_batch_in_session

    async def cancelled(*args):
        raise asyncio.CancelledError("synthetic cancellation after receipt inspection")

    publisher.discovery.outbox.validated_scope_batch_in_session = cancelled
    with pytest.raises(asyncio.CancelledError):
        await publisher.publish(routed)
    publisher.discovery.outbox.validated_scope_batch_in_session = original
    assert await publisher.publish(routed) == batch
    assert await count(db, DeliveryBatch) == 1 and await count(db, Delivery) == len(
        batch.deliveries
    )


async def test_committed_preview_requires_current_actor_operate_not_just_view(db):
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.models import Grant

    publisher, routed, batch, _, _ = await committed_discovery_reply(db)
    actor = routed.discovery_target.source.author_id
    async with db.sessions.begin() as session:
        receipt = await session.get(CommandReceipt, routed.delivery_key.removeprefix("command:"))
        receipt.response = {**receipt.response, "shortcuts": {"confirm": "a" * 32}}
        await session.execute(delete(Grant).where(Grant.user_id == actor))
        for project in routed.discovery_target.projects:
            session.add(
                Grant(
                    realm_id="realm",
                    user_id=actor,
                    project_id=project.scope.project_id,
                    role="operator",
                )
            )
    assert await publisher.publish(routed) == batch
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == actor).values(role="viewer"))
    with pytest.raises(AccessDenied, match="operate_revoked"):
        await publisher.publish(routed)


async def test_reply_without_committed_batch_keeps_original_public_discovery_path(db, monkeypatch):
    from unittest.mock import AsyncMock

    publisher, routed, batch, _, _ = await committed_discovery_reply(db)
    legacy = AsyncMock(return_value=batch)
    monkeypatch.setattr(publisher.discovery, "publish", legacy)
    legacy_routed = replace(routed, queued_batch_id=None)
    assert await publisher.publish(legacy_routed) == batch
    legacy.assert_awaited_once_with(
        routed.delivery_key, routed.discovery_target, routed.text, routed.locale, widget=None
    )
    assert await publisher.publish(RoutedInput("ignore")) is None


async def test_committed_reply_recovery_uses_fresh_fence_without_rewriting_historical_receipt(db):
    from jt_oz_bridge.storage.command_models import CommandReceipt

    publisher, routed, batch, destinations, _ = await committed_discovery_reply(db)
    old = destinations.fence
    await DurableStore(db).release_lease(old.holder, old.fencing)
    fresh = await DurableStore(db).acquire_lease("new-consumer")
    destinations.fence = ConsumerFence("new-consumer", fresh)
    publisher.discovery.outbox.fence = destinations.fence
    assert await publisher.publish(routed) == batch
    async with db.sessions() as session:
        receipt = await session.get(CommandReceipt, routed.delivery_key.removeprefix("command:"))
        assert (receipt.holder, receipt.fencing) == (old.holder, old.fencing)
    assert await count(db, Delivery) == len(batch.deliveries)
