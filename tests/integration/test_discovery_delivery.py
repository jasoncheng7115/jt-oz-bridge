import asyncio
import time

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.discovery_delivery import DiscoveryDeliveryWorker
from jt_oz_bridge.services.discovery_outbox import (
    DiscoveryOutbox,
    DiscoveryPayload,
    DiscoveryReplyPublisher,
)
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch, DeliveryLane, Grant, WorkerLease
from jt_oz_bridge.storage.output_models import OutputDestination
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_output_destinations import prepared
from tests.integration.test_router import count
from tests.support import REF


async def worker(db, pages=("First discovery page", "Second discovery page"), *, interval=0):
    destinations, reader, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    batch = await outbox.queue_scope_batch(
        "source-reply",
        target,
        pages,
        renderer_version="synthetic-v1",
        message_limit=1000,
        topic_limit=60,
    )
    gateway = SyntheticChat()
    sender = DiscoveryDeliveryWorker(
        outbox,
        gateway,
        destinations.fence.holder,
        destinations.fence.fencing,
        minimum_interval=interval,
    )
    return sender, gateway, target, batch


async def test_atomic_scoped_batch_has_no_binding_and_sends_pages_in_order(db):
    sender, gateway, target, batch = await worker(db)
    assert await count(db, Binding) == 0 and await count(db, OutputDestination) == 1
    assert await sender.advance(batch.deliveries[1]) == "pending" and not gateway.calls
    assert await sender.advance(batch.deliveries[0]) == "delivered"
    assert await sender.advance(batch.deliveries[1]) == "delivered"
    assert len(gateway.calls) == 2
    async with db.sessions() as session:
        rows = (await session.scalars(select(Delivery).order_by(Delivery.batch_index))).all()
        assert all(
            row.binding_id is None
            and row.binding_revision is None
            and row.destination_id == str(target.id)
            for row in rows
        )
        assert all(
            DiscoveryPayload.model_validate(row.payload).authorization_id == target.id
            for row in rows
        )


async def test_discovery_scope_429_is_retryable_without_weakening_current_source_checks(db):
    sender, gateway, _, batch = await worker(db, pages=("Only page",))
    destinations = sender.scoped.destinations
    authorize = destinations.authorize

    async def limited(*args):
        raise DeliveryRateLimited(10)

    destinations.authorize = limited
    identity = batch.deliveries[0]
    assert await sender.advance(identity) == "pending"
    assert not gateway.calls and (await sender.outbox.load(identity)).attempts == 0
    destinations.authorize = authorize
    async with db.sessions.begin() as session:
        await session.execute(update(DeliveryLane).values(not_before=0))
        await session.execute(update(Delivery).values(retry_at=0))
        await session.execute(update(Grant).values(active=False))
    assert await sender.advance(identity) == "held" and not gateway.calls


async def test_concurrent_same_scoped_reply_commits_one_target_parent_and_all_pages(db):
    destinations, reader, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    batches = await asyncio.gather(
        *(
            outbox.queue_scope_batch(
                "same",
                target,
                ("one", "two"),
                renderer_version="test",
                message_limit=300,
                topic_limit=60,
            )
            for _ in range(4)
        )
    )
    assert len({batch.id for batch in batches}) == 1
    assert await count(db, OutputDestination) == await count(db, DeliveryBatch) == 1
    assert await count(db, Delivery) == 2


async def test_source_projection_cannot_renew_target_or_change_plan_but_publisher_reuses_original(
    db,
):
    sender, gateway, target, batch = await worker(db)
    publisher = DiscoveryReplyPublisher(
        sender.scoped, realm_id="realm", message_limit=500, topic_limit=60
    )
    assert await publisher.publish("source-reply", target, "New dynamic status") == batch
    with pytest.raises(Conflict, match="plan_changed"):
        await sender.scoped.queue_scope_batch(
            "source-reply",
            target,
            ("different",),
            renderer_version="synthetic-v1",
            message_limit=1000,
            topic_limit=60,
        )
    fresh = await sender.scoped.destinations.prepare(target.source, ("project",))
    with pytest.raises(Conflict):
        await publisher.publish("source-reply", fresh, "new plan")
    assert await count(db, Delivery) == 2


async def test_real_mobile_renderer_reserves_headers_footers_and_actual_server_limit(db):
    destinations, reader, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    publisher = DiscoveryReplyPublisher(outbox, realm_id="realm", message_limit=300, topic_limit=60)
    batch = await publisher.publish(
        "render", target, "# Native title\n\n" + "exact original text\n" * 100, "zh-TW"
    )
    assert len(batch.deliveries) > 1
    for identity in batch.deliveries:
        row = await outbox.load(identity)
        assert len(row.payload["content"]) <= 300 and "第" in row.payload["content"]
    with pytest.raises(Conflict):
        await DiscoveryReplyPublisher(
            outbox, realm_id="foreign", message_limit=300, topic_limit=60
        ).publish("other", target, "text")


async def test_positive_lost_post_evidence_reconciles_without_reposting_and_unblocks_next_page(db):
    sender, gateway, target, batch = await worker(db)
    gateway.mode = "timeout"
    assert await sender.advance(batch.deliveries[0]) == "ambiguous"
    assert await sender.advance(batch.deliveries[0]) == "ambiguous"
    assert await sender.advance(batch.deliveries[1]) == "pending" and len(gateway.calls) == 1
    assert await sender.reconcile(batch.deliveries[0]) == "delivered"
    gateway.mode = "success"
    assert await sender.advance(batch.deliveries[1]) == "delivered" and len(gateway.calls) == 2


async def test_missing_positive_evidence_never_justifies_another_post(db):
    sender, gateway, target, batch = await worker(db)
    gateway.mode = "timeout"
    assert await sender.advance(batch.deliveries[0]) == "ambiguous"
    gateway.messages.clear()
    assert await sender.reconcile(batch.deliveries[0]) == "ambiguous" and len(gateway.calls) == 1


@pytest.mark.parametrize("change", ["role", "source", "audience", "bound", "revoke"])
async def test_changed_authority_after_queue_holds_before_any_bot_post(db, change):
    sender, gateway, target, batch = await worker(db)
    if change == "role":
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant)
                .where(Grant.user_id == 8, Grant.project_id == "project")
                .values(active=False)
            )
    elif change == "source":
        sender.scoped.destinations.reader.messages[201] = target.source.model_copy(
            update={"deleted": True}
        )
    elif change == "audience":
        sender.scoped.bindings.audience.users = frozenset({7, 8, 999})
    elif change == "bound":
        await sender.scoped.bindings.bind("realm", 7, 10, "Original work", REF)
    else:
        await sender.scoped.destinations.revoke(str(target.id))
    assert await sender.advance(batch.deliveries[0]) == "held" and not gateway.calls


@pytest.mark.parametrize("change", ["hash", "index", "bot", "authorization", "page_count"])
async def test_complete_manifest_or_payload_tampering_is_refused_before_post(db, change):
    sender, gateway, target, batch = await worker(db)
    async with db.sessions.begin() as session:
        first = await session.get(Delivery, batch.deliveries[0])
        if change == "hash":
            first.payload_hash = "b" * 64
        elif change == "index":
            first.batch_index = 8
        elif change == "page_count":
            parent = await session.get(DeliveryBatch, batch.id)
            parent.page_count = 1
        else:
            data = dict(first.payload)
            data["bot_user_id" if change == "bot" else "authorization_hash"] = (
                88 if change == "bot" else "b" * 64
            )
            first.payload = data
            from jt_oz_bridge.storage.durable import digest

            first.payload_hash = digest(data)
    assert await sender.advance(batch.deliveries[0]) == "held" and not gateway.calls


async def test_bound_and_unbound_share_priority_and_one_realm_pacing_lane(db):
    sender, gateway, target, batch = await worker(db, pages=("Discovery control",), interval=1)
    binding = await sender.scoped.bindings.bind("realm", 7, 10, "Bound work", REF)
    bound_outbox = Outbox(sender.scoped.bindings, 77, fence=sender.scoped.fence)
    bound = await bound_outbox.queue(
        "bound-output", binding.id, binding.revision, "Bound output", priority=100
    )
    bound_worker = DeliveryWorker(
        bound_outbox, gateway, sender.holder, sender.fencing, minimum_interval=1
    )
    assert await bound_worker.advance(bound) == "pending" and not gateway.calls
    assert await sender.advance(batch.deliveries[0]) == "delivered"
    assert await bound_worker.advance(bound) == "pending" and len(gateway.calls) == 1
    async with db.sessions.begin() as session:
        await session.execute(update(DeliveryLane).values(not_before=0))
    assert await bound_worker.advance(bound) == "delivered" and len(gateway.calls) == 2


async def test_bound_control_with_higher_priority_can_precede_scoped_discovery(db):
    sender, gateway, target, batch = await worker(db, pages=("Discovery",))
    binding = await sender.scoped.bindings.bind("realm", 7, 10, "Bound work", REF)
    outbox = Outbox(sender.scoped.bindings, 77, fence=sender.scoped.fence)
    control = await outbox.queue("urgent", binding.id, binding.revision, "Urgent", priority=0)
    bound = DeliveryWorker(outbox, gateway, sender.holder, sender.fencing, minimum_interval=0)
    assert await sender.advance(batch.deliveries[0]) == "pending"
    assert await bound.advance(control) == "delivered"
    assert await sender.advance(batch.deliveries[0]) == "delivered"


async def test_explicit_rate_limit_backoff_is_shared_with_bound_messages(db):
    sender, gateway, target, batch = await worker(db, pages=("Discovery",))
    binding = await sender.scoped.bindings.bind("realm", 7, 10, "Bound work", REF)
    outbox = Outbox(sender.scoped.bindings, 77, fence=sender.scoped.fence)
    later = await outbox.queue("later", binding.id, binding.revision, "Later", priority=100)
    bound = DeliveryWorker(outbox, gateway, sender.holder, sender.fencing, minimum_interval=0)
    gateway.mode = "rate"
    assert await sender.advance(batch.deliveries[0]) == "pending"
    gateway.mode = "success"
    assert await bound.advance(later) == "pending" and len(gateway.calls) == 1
    async with db.sessions() as session:
        row = await session.get(Delivery, batch.deliveries[0])
        assert row.retry_at > time.time()


async def test_outbox_source_scope_and_every_page_roll_back_as_one_transaction(db):
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    destinations, reader, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)

    def fail(session, context, instances):
        if any(isinstance(row, Delivery) for row in session.new):
            raise RuntimeError("injected page storage failure")

    event.listen(Session, "before_flush", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            await outbox.queue_scope_batch(
                "source",
                target,
                ("one", "two"),
                renderer_version="test",
                message_limit=300,
                topic_limit=60,
            )
    finally:
        event.remove(Session, "before_flush", fail)
    assert (
        await count(db, OutputDestination)
        == await count(db, DeliveryBatch)
        == await count(db, Delivery)
        == 0
    )


async def test_lost_fence_cannot_post_or_release_scoped_output(db):
    sender, gateway, target, batch = await worker(db)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
    assert await sender.advance(batch.deliveries[0]) == "pending" and not gateway.calls


@pytest.mark.parametrize(
    "fields",
    [
        {"binding_id": None, "binding_revision": None, "destination_id": None},
        {"binding_id": "fake", "binding_revision": 1, "destination_id": "scope"},
    ],
)
async def test_database_refuses_missing_or_mixed_authorization_sources(db, fields):
    with pytest.raises(IntegrityError):
        async with db.sessions.begin() as session:
            session.add(
                Delivery(
                    dedupe_key="bad", payload={"test": "data"}, payload_hash="a" * 64, **fields
                )
            )


async def test_held_discovery_requires_explicit_original_actor_resume_and_never_releases_ambiguous(
    db,
):
    from jt_oz_bridge.security.policy import AccessDenied

    sender, gateway, target, batch = await worker(db, pages=("Only page",))
    gateway.writes_enabled = False
    assert await sender.advance(batch.deliveries[0]) == "held"
    saved = await sender.scoped.load(batch.deliveries[0])
    assert await sender.scoped.cached_scope_batch("source-reply", target) == batch
    assert (await sender.scoped.load(saved.id)).state == "held"
    with pytest.raises(AccessDenied):
        await sender.scoped.resume(saved.id, "realm", 8, saved.version)
    await sender.scoped.resume(saved.id, "realm", 7, saved.version)
    gateway.writes_enabled = True
    gateway.mode = "timeout"
    assert await sender.advance(saved.id) == "ambiguous"
    ambiguous = await sender.scoped.load(saved.id)
    with pytest.raises(Conflict):
        await sender.scoped.resume(saved.id, "realm", 7, ambiguous.version)
    assert len(gateway.calls) == 1


async def test_expired_destination_holds_even_when_worker_lease_is_still_valid(db, monkeypatch):
    sender, gateway, target, batch = await worker(db)
    advanced = target.expires_at + 1
    monkeypatch.setattr("time.time", lambda: advanced)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=advanced + 60))
    assert await sender.advance(batch.deliveries[0]) == "held" and not gateway.calls


async def test_lost_worker_cancellation_during_send_is_ambiguous_with_no_second_post(db):
    sender, gateway, target, batch = await worker(db, pages=("Only page",))
    gateway.mode = "wait"
    running = asyncio.create_task(sender.advance(batch.deliveries[0]))
    await asyncio.wait_for(gateway.entered.wait(), 2)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert (await sender.scoped.load(batch.deliveries[0])).state == "ambiguous"
    assert await sender.advance(batch.deliveries[0]) == "ambiguous" and len(gateway.calls) == 1


async def test_duplicate_positive_markers_do_not_falsely_resolve_an_uncertain_post(db):
    sender, gateway, target, batch = await worker(db, pages=("Only page",))
    gateway.mode = "timeout"
    assert await sender.advance(batch.deliveries[0]) == "ambiguous"
    original = next(iter(gateway.messages.values()))
    gateway.messages[1001] = original.model_copy(update={"id": 1001})
    assert await sender.reconcile(batch.deliveries[0]) == "ambiguous" and len(gateway.calls) == 1


async def test_legacy_encrypted_pages_and_parent_survive_nullable_authorization_upgrade_exactly(
    tmp_path,
):
    import os
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.services.outbox import OutboundPayload
    from jt_oz_bridge.storage.cipher_types import checked_json, payload_scope
    from jt_oz_bridge.storage.database import Database, migrate
    from jt_oz_bridge.storage.durable import digest
    from jt_oz_bridge.storage.models import uid

    cipher = EnvelopeCipher({"legacy": os.urandom(32)}, "legacy")
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'legacy-delivery.db'}", cipher=cipher)
    parent, identity, binding = uid(), uid(), uid()
    payload = OutboundPayload(
        operation="post",
        realm_id="realm",
        channel_id=10,
        topic="Original work",
        bot_user_id=77,
        content="PRIVATE_LEGACY_OUTPUT\n\n`jtoz:" + identity + "`",
        marker="jtoz:" + identity,
    ).model_dump(mode="json")
    encrypted = cipher.seal(checked_json(payload), payload_scope("deliveries", "payload"))

    def legacy(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        command.upgrade(config, "0010_output_destinations")

    try:
        async with db.engine.begin() as connection:
            await connection.run_sync(legacy)
            await connection.execute(
                text(
                    "INSERT INTO delivery_batches (id,dedupe_key,binding_id,binding_revision,plan_hash,renderer_version,message_limit,topic_limit,page_count,priority,created_at) VALUES (:id,'old-parent',:binding,3,:hash,'old-renderer',1000,60,1,10,123)"
                ),
                {"id": parent, "binding": binding, "hash": "a" * 64},
            )
            await connection.execute(
                text(
                    "INSERT INTO deliveries (id,dedupe_key,binding_id,binding_revision,payload,payload_hash,state,created_at,version,attempts,retry_at,priority,updated_at,batch_id,batch_index) VALUES (:id,'old-page',:binding,3,:payload,:hash,'ambiguous',123,7,1,99,10,124,:parent,0)"
                ),
                {
                    "id": identity,
                    "binding": binding,
                    "payload": encrypted,
                    "hash": digest(payload),
                    "parent": parent,
                },
            )
        await migrate(db.engine)
        assert await db.ready()
        async with db.engine.connect() as connection:
            assert (
                await connection.scalar(
                    text("SELECT payload FROM deliveries WHERE id=:id"), {"id": identity}
                )
                == encrypted
            )
        async with db.sessions() as session:
            row = await session.get(Delivery, identity)
            batch = await session.get(DeliveryBatch, parent)
            assert (
                row.payload == payload
                and row.state == "ambiguous"
                and row.version == 7
                and row.attempts == 1
            )
            assert (
                row.binding_id == batch.binding_id == binding
                and row.binding_revision == batch.binding_revision == 3
            )
            assert row.destination_id is batch.destination_id is None
    finally:
        await db.close()


async def test_bound_preflight_payload_change_cannot_claim_an_untracked_message(db):
    from tests.integration.test_delivery import worker as bound_worker

    sender, binding, gateway = await bound_worker(db)
    identity = await sender.outbox.queue(
        "race", binding.id, binding.revision, "Exact original output"
    )
    original = sender.payload

    async def corrupted(saved):
        payload = await original(saved)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery).where(Delivery.id == saved.id).values(payload_hash="c" * 64)
            )
        return payload

    sender.payload = corrupted
    assert await sender.advance(identity) == "pending" and not gateway.calls
    sender.payload = original
    assert await sender.advance(identity) == "held" and not gateway.calls


@pytest.mark.parametrize("fault", ["second_project_grant", "enrollment", "fence"])
async def test_discovery_batch_late_local_authority_loss_rolls_back_complete_output(db, fault):
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.control_models import EnrolledBackend

    destinations, _, target = await prepared(db, ("project", "second-project"))
    outbox = DiscoveryOutbox(destinations, 77)
    original, changed = destinations.persist_in_session, False

    async def persist(session, key, value):
        nonlocal changed
        result = await original(session, key, value)
        if not changed:
            changed = True
            if fault == "second_project_grant":
                await session.execute(
                    update(Grant)
                    .where(Grant.project_id == "second-project", Grant.user_id == 8)
                    .values(active=False)
                )
            elif fault == "enrollment":
                await session.execute(update(EnrolledBackend).values(enabled=False))
            else:
                await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
        return result

    destinations.persist_in_session = persist
    with pytest.raises((AccessDenied, Conflict)):
        await outbox.queue_scope_batch(
            "late-local-change",
            target,
            ("one", "two"),
            renderer_version="test",
            message_limit=300,
            topic_limit=60,
        )
    assert await count(db, OutputDestination) == await count(db, DeliveryBatch) == 0
    assert await count(db, Delivery) == 0
    async with db.sessions() as session:
        assert all((await session.scalars(select(Grant.active))).all())
        assert all((await session.scalars(select(EnrolledBackend.enabled))).all())
        assert await session.scalar(select(WorkerLease.fencing)) == destinations.fence.fencing


@pytest.mark.parametrize("fault", ["footer", "dedupe"])
async def test_cached_scope_batch_validates_exact_footer_and_page_dedupe_even_if_rehashed(
    db, fault
):
    from jt_oz_bridge.storage.durable import digest

    sender, _, target, batch = await worker(db, pages=("Exact immutable body",))
    async with db.sessions.begin() as session:
        row = await session.get(Delivery, batch.deliveries[0])
        if fault == "dedupe":
            row.dedupe_key = "discovery-page:other-parent:0"
        else:
            payload = dict(row.payload)
            assert f"#jtoz:{row.id})" in payload["content"]
            payload["content"] = payload["content"].replace("#jtoz:", "#fake:")
            row.payload, row.payload_hash = payload, digest(payload)
    with pytest.raises((Conflict, ValueError)):
        await sender.scoped.scope_batch_by_id(batch.id, target)


async def test_in_session_discovery_batch_uses_only_callers_transaction_and_all_100_pages(
    db, monkeypatch
):
    from unittest.mock import AsyncMock

    destinations, reader, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    pages = tuple(f"page {index}" for index in range(100))
    no_remote = AsyncMock(side_effect=AssertionError("unexpected remote authorization"))
    monkeypatch.setattr(destinations, "authorize", no_remote)
    monkeypatch.setattr(reader, "read", no_remote)
    monkeypatch.setattr(destinations.discovery.bindings.audience, "inspect", no_remote)
    async with db.sessions.begin() as session:
        with monkeypatch.context() as local:
            local.setattr(db, "sessions", lambda *a, **kw: pytest.fail("nested SQL session"))
            batch = await outbox.queue_scope_batch_in_session(
                session,
                "atomic-100",
                target,
                pages,
                renderer_version="test",
                message_limit=300,
                topic_limit=60,
            )
            replay = await outbox.queue_scope_batch_in_session(
                session,
                "atomic-100",
                target,
                pages,
                renderer_version="test",
                message_limit=300,
                topic_limit=60,
            )
            parent = await session.get(DeliveryBatch, batch.id)
            assert await outbox.validated_scope_batch_in_session(session, target, parent) == batch
            assert replay == batch and len(batch.deliveries) == 100
    no_remote.assert_not_awaited()
    assert await count(db, OutputDestination) == await count(db, DeliveryBatch) == 1
    assert await count(db, Delivery) == 100


@pytest.mark.parametrize("fail_after_queue", [False, True])
async def test_command_finish_and_scoped_batch_share_one_atomic_commit(db, fail_after_queue):
    from jt_oz_bridge.services.command_receipts import CommandInbox
    from jt_oz_bridge.storage.command_models import CommandReceipt

    destinations, _, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    inbox = CommandInbox(db, destinations.fence.holder, destinations.fence.fencing)
    claim = await inbox.claim(target.source, "sessions")
    queued = []

    async def commit(session):
        queued.append(
            await outbox.queue_scope_batch_in_session(
                session,
                "command:" + claim.id,
                target,
                ("first", "last"),
                renderer_version="test",
                message_limit=300,
                topic_limit=60,
            )
        )
        # This fixture tests rollback after the actual last-page flush. It is
        # not live Human authorization, a server POST, or a delivery ACK.
        if fail_after_queue:
            raise RuntimeError("synthetic producer failure")

    if fail_after_queue:
        with pytest.raises(RuntimeError, match="synthetic producer failure"):
            await inbox.finish(claim, {"synthetic": "response"}, commit=commit)
    else:
        await inbox.finish(claim, {"synthetic": "response"}, commit=commit)
    async with db.sessions() as session:
        receipt = await session.get(CommandReceipt, claim.id)
        assert (receipt.state, receipt.version, receipt.response) == (
            ("processing", claim.version, {})
            if fail_after_queue
            else ("completed", claim.version + 1, {"synthetic": "response"})
        )
    assert len(queued) == 1
    assert await count(db, Delivery) == (0 if fail_after_queue else 2)
    assert (
        await count(db, DeliveryBatch)
        == await count(db, OutputDestination)
        == (0 if fail_after_queue else 1)
    )


@pytest.mark.parametrize(
    "change",
    [
        {"pages": ()},
        {"pages": ("",)},
        {"pages": ("p",) * 101},
        {"pages": ("p" * 10001,) * 100, "message_limit": 20000},
        {"pages": ("p" * 300,)},
        {"key": "k" * 256},
        {"renderer_version": "r" * 65},
        {"message_limit": 172},
        {"topic_limit": 0},
        {"priority": 1001},
        {"pages": ["p"]},
    ],
)
async def test_in_session_discovery_plan_rejects_bounds_before_any_persistence(db, change):
    from unittest.mock import AsyncMock

    destinations, _, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    never = AsyncMock(side_effect=AssertionError("invalid plan must not persist"))
    destinations.persist_in_session = destinations.authorize = never
    values = dict(
        key="bounded",
        pages=("page",),
        renderer_version="test",
        message_limit=300,
        topic_limit=60,
        priority=10,
    )
    values.update(change)
    async with db.sessions.begin() as session:
        with pytest.raises(ValueError):
            await outbox.queue_scope_batch_in_session(session, target=target, **values)
    never.assert_not_awaited()
    assert await count(db, Delivery) == await count(db, DeliveryBatch) == 0
    assert await count(db, OutputDestination) == 0


@pytest.mark.parametrize(
    "change",
    [
        {"pages": ("changed", "last")},
        {"priority": 11},
        {"renderer_version": "other"},
        {"message_limit": 301},
        {"topic_limit": 61},
    ],
)
async def test_in_session_cache_requires_exact_immutable_plan(db, change):
    destinations, _, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    values = dict(
        key="immutable",
        pages=("first", "last"),
        renderer_version="test",
        message_limit=300,
        topic_limit=60,
        priority=10,
    )
    async with db.sessions.begin() as session:
        batch = await outbox.queue_scope_batch_in_session(session, target=target, **values)
    values.update(change)
    with pytest.raises(Conflict, match="plan_changed"):
        async with db.sessions.begin() as session:
            await outbox.queue_scope_batch_in_session(session, target=target, **values)
    assert await outbox.scope_batch_by_id(batch.id, target) == batch
    assert await count(db, Delivery) == 2 and await count(db, DeliveryBatch) == 1


async def test_in_session_cached_validation_sees_all_page_changes_in_same_transaction(db):
    from sqlalchemy import delete

    destinations, _, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    values = dict(
        key="same-session",
        pages=("first", "last"),
        renderer_version="test",
        message_limit=300,
        topic_limit=60,
    )
    async with db.sessions.begin() as session:
        batch = await outbox.queue_scope_batch_in_session(session, target=target, **values)
    with pytest.raises(Conflict, match="incomplete"):
        async with db.sessions.begin() as session:
            await session.execute(delete(Delivery).where(Delivery.id == batch.deliveries[1]))
            await outbox.queue_scope_batch_in_session(session, target=target, **values)
    assert await count(db, Delivery) == 2
    assert await outbox.scope_batch_by_id(batch.id, target) == batch


@pytest.mark.parametrize("fault", ["expired", "source_kind"])
async def test_in_session_writer_rejects_expired_or_non_catalog_source_without_remote(db, fault):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.security.policy import AccessDenied

    destinations, _, target = await prepared(db)
    outbox = DiscoveryOutbox(destinations, 77)
    if fault == "expired":
        now = time.time()
        target = target.model_copy(update={"issued_at": now - 901, "expires_at": now - 1})
    else:
        target = target.model_copy(
            update={"source": target.source.model_copy(update={"text": "!oz nonexistent"})}
        )
    never = AsyncMock(side_effect=AssertionError("internal writer must not use HTTP"))
    destinations.authorize = never
    with pytest.raises((AccessDenied, Conflict)):
        async with db.sessions.begin() as session:
            await outbox.queue_scope_batch_in_session(
                session,
                "invalid-target",
                target,
                ("page",),
                renderer_version="test",
                message_limit=300,
                topic_limit=60,
            )
    never.assert_not_awaited()
    assert await count(db, OutputDestination) == await count(db, DeliveryBatch) == 0
    assert await count(db, Delivery) == 0


@pytest.fixture
async def qualified_discovery_delivery(db):
    # Reuse the original whole-graph server and actual production Bot identity
    # guard. No synthetic custom guard is used to qualify the optimized path.
    from tests.integration.test_consumer_runtime import closed_menu_http_fixture

    async for value in closed_menu_http_fixture.__wrapped__(db):
        value.server.input("!projects", 101, topic="Independent delivery observation")
        value.server.next_mid = 102
        assert await value.pipeline.consumer.poll() == ("reply",)
        async with db.sessions() as session:
            saved = await session.scalar(select(Delivery).order_by(Delivery.created_at))
        value.delivery_id = saved.id
        yield value


async def test_qualified_delivery_one_complete_source_audience_observation_spends_at_most_20_gets(
    db, qualified_discovery_delivery, request
):
    import httpx

    p = qualified_discovery_delivery
    delegate, calls = p.client.client._transport, []

    def peer(request):
        calls.append((request.method, request.url.path.removeprefix("/api/v1/")))
        return delegate.handler(request)

    p.client.client._transport = httpx.MockTransport(peer)
    assert await p.pipeline.discovery_delivery.advance(p.delivery_id) == "delivered"
    get_count = sum(method == "GET" for method, _ in calls)
    request.node.user_properties.append(("qualified_delivery_get_count", get_count))
    assert get_count <= 20, calls
    assert calls.count(("GET", "messages/101")) == 2
    assert calls.count(("GET", "streams/10/members")) == 2
    assert calls.count(("POST", "messages")) == 1
    assert len(p.server.posts) == 1 and not p.native.submitted


@pytest.mark.parametrize(
    "fault", ["source", "audience", "public", "inactive", "untrusted_bot", "401", "403"]
)
async def test_closed_delivery_rejects_last_source_audience_or_auth_change_without_fallback(
    db, qualified_discovery_delivery, fault, monkeypatch
):
    from collections import Counter
    from unittest.mock import AsyncMock

    import httpx

    p = qualified_discovery_delivery
    delegate, seen = p.client.client._transport, Counter()
    forbidden = AsyncMock(side_effect=AssertionError("selected observer must not fall back"))
    monkeypatch.setattr(p.pipeline.discovery_outbox, "scope_batch_by_id", forbidden)

    def peer(request):
        path = request.url.path.removeprefix("/api/v1/")
        seen[path] += 1
        response = delegate.handler(request)
        if path == "messages/101" and seen[path] == 2 and fault in {"401", "403"}:
            return httpx.Response(int(fault), json={"result": "error", "msg": "denied"})
        data = response.json()
        if seen[path] == 2:
            if path == "messages/101" and fault == "source":
                data["message"]["content"] = "changed original human text"
            elif path == "streams/10/members" and fault == "audience":
                data["subscribers"] = [7, 11]
            elif path == "streams/10" and fault == "public":
                data["stream"]["invite_only"] = False
            elif path == "users/8" and fault == "inactive":
                data["user"]["is_active"] = False
            elif path == "users/8" and fault == "untrusted_bot":
                data["user"]["is_bot"] = True
        return httpx.Response(response.status_code, json=data)

    p.client.client._transport = httpx.MockTransport(peer)
    assert await p.pipeline.discovery_delivery.advance(p.delivery_id) == "held"
    forbidden.assert_not_awaited()
    saved = await p.pipeline.discovery_outbox.load(p.delivery_id)
    assert saved.attempts == 0 and not p.server.posts and not p.native.submitted
    if fault in {"401", "403"}:
        assert seen["messages/101"] == 2


@pytest.mark.parametrize("fault", ["project", "late_grant", "gateway", "attestation", "manifest"])
async def test_closed_delivery_rechecks_local_authority_and_full_manifest_before_claim(
    db, qualified_discovery_delivery, fault
):
    from dataclasses import replace

    from jt_oz_bridge.storage.control_models import EnrolledProject

    p = qualified_discovery_delivery
    outbox = p.pipeline.discovery_outbox
    destinations, calls = outbox.destinations, 0
    original = destinations._authorize_observed

    async def changed(target, audience):
        nonlocal calls
        calls += 1
        await original(target, audience)
        if calls == 2:
            if fault == "gateway":
                p.pipeline.discovery_delivery.gateway.client = object()
            elif fault == "attestation":
                p.client.attestation = replace(p.client.attestation)
            else:
                async with db.sessions.begin() as session:
                    if fault == "project":
                        await session.execute(update(EnrolledProject).values(enabled=False))
                    elif fault == "late_grant":
                        await session.execute(
                            update(Grant).where(Grant.user_id == 8).values(active=False)
                        )
                    else:
                        await session.execute(update(DeliveryBatch).values(plan_hash="f" * 64))

    destinations._authorize_observed = changed
    assert await p.pipeline.discovery_delivery.advance(p.delivery_id) in {"held", "pending"}
    saved = await outbox.load(p.delivery_id)
    assert saved.attempts == 0 and not p.server.posts and not p.native.submitted


async def test_closed_delivery_reobserves_original_source_independently_for_every_page(
    db, qualified_discovery_delivery
):
    p = qualified_discovery_delivery
    sender, outbox = p.pipeline.discovery_delivery, p.pipeline.discovery_outbox
    assert await sender.advance(p.delivery_id) == "delivered"
    first = await outbox.load(p.delivery_id)
    target = await outbox.destinations.snapshot(first.destination_id)
    batch = await outbox.queue_scope_batch(
        "two-independent-pages",
        target,
        ("first additional page", "last additional page"),
        renderer_version="test",
        message_limit=1000,
        topic_limit=60,
    )
    assert await sender.advance(batch.deliveries[0]) == "delivered"
    p.server.messages[101]["content"] = "edited before the second page"
    assert await sender.advance(batch.deliveries[1]) == "held"
    assert len(p.server.posts) == 2
    assert (await outbox.load(batch.deliveries[1])).attempts == 0


async def test_custom_identity_guard_keeps_original_public_delivery_authorization(
    db, qualified_discovery_delivery, monkeypatch
):
    from unittest.mock import AsyncMock

    p = qualified_discovery_delivery
    p.client.verify_identity = AsyncMock(return_value=True)
    outbox = p.pipeline.discovery_outbox
    legacy = AsyncMock(wraps=outbox.scope_batch_by_id)
    monkeypatch.setattr(outbox, "scope_batch_by_id", legacy)
    assert await p.pipeline.discovery_delivery.advance(p.delivery_id) == "delivered"
    legacy.assert_awaited_once()
    assert len(p.server.posts) == 1 and not p.native.submitted
