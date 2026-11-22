import asyncio
from pathlib import Path

import pytest
from sqlalchemy import event as sql_event
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.event_semantics import DATA, SEMANTICS_SHA256
from jt_oz_bridge.domain.delivery import without_marker
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.native_projection import EventSemanticAttestation, NativeProjector
from jt_oz_bridge.services.native_publisher import NativePublisher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch, Grant
from jt_oz_bridge.storage.projection_models import NativeProjectionRecord
from jt_oz_bridge.storage.publication_models import BatchDependency, NativePublication
from tests.contract.test_v2_execution import REF
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_native_log_reader import reader, sse, synced
from tests.integration.test_native_projection import native, project_all


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


async def setup(db, profile, texts=None, *, historical=True, limit=1000, late_open=False):
    texts = ["Live native first", "Live native second"] if texts is None else texts
    events = []
    if historical:
        events.append(
            native(
                "session.text.ended",
                0,
                assistantMessageID="msg_history",
                ordinal=0,
                text="PRIVATE_HISTORY_ONLY",
            )
        )
    events.append(synced(0 if historical else None))
    start = 1 if historical else 0
    events.append(native("session.execution.started", start))
    for index, text in enumerate(texts, start + 1):
        events.append(
            native(
                "session.text.ended",
                index,
                assistantMessageID="msg_live_" + str(index),
                ordinal=0,
                text=text,
            )
        )
    events.append(native("session.execution.succeeded", start + len(texts) + 1))
    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(value) for value in events]
    )
    projector = NativeProjector(
        pump.bindings,
        ConsumerFence(pump.holder, pump.fencing),
        attestation=EventSemanticAttestation(
            REF.backend_id,
            REF.backend_identity,
            profile.sha256,
            SEMANTICS_SHA256,
            "f" * 64,
            frozenset(DATA),
        ),
    )
    outbox = Outbox(pump.bindings, 77, fence=projector.fence)
    if not late_open:
        publisher = await NativePublisher.open(
            projector, outbox, realm_id="realm", message_limit=limit, topic_limit=60
        )
    with pytest.raises(Conflict, match="ended_without_continuity"):
        await pump.run(binding.id, follow=True)
    await project_all(projector)
    if late_open:
        publisher = await NativePublisher.open(
            projector, outbox, realm_id="realm", message_limit=limit, topic_limit=60
        )
    chat = SyntheticChat()
    worker = DeliveryWorker(outbox, chat, pump.holder, pump.fencing, minimum_interval=0)
    return publisher, binding, transport, worker, chat


async def publish_all(publisher):
    results = []
    while (identity := await publisher.next_pending()) is not None:
        result = await publisher.advance(identity)
        assert result.state != "waiting"
        results.append((identity, result))
    return results


async def test_historical_capture_is_saved_only_and_live_parts_enter_authorized_outbox_once(
    db, profile
):
    publisher, binding, transport, worker, chat = await setup(db, profile)
    try:
        results = await publish_all(publisher)
        assert [result.state for _, result in results] == ["history", "queued", "queued"]
        assert not chat.calls
        async with db.sessions() as session:
            deliveries = (await session.scalars(select(Delivery))).all()
            assert len(deliveries) == 2 and all(
                "PRIVATE_HISTORY_ONLY" not in row.payload["content"] for row in deliveries
            )
            assert len((await session.scalars(select(NativePublication))).all()) == 3
        for identity, original in results:
            assert await publisher.advance(identity) == original
        async with db.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(Delivery)) == 2
    finally:
        await transport.close()


async def test_positive_prior_batch_evidence_blocks_later_native_part_until_exact_reconciliation(
    db, profile
):
    publisher, binding, transport, worker, chat = await setup(db, profile, historical=False)
    try:
        results = await publish_all(publisher)
        first, second = [result.batch for _, result in results]
        assert await worker.advance(second.deliveries[0]) == "pending"
        assert not chat.calls
        chat.mode = "timeout"
        assert await worker.advance(first.deliveries[0]) == "ambiguous"
        assert await worker.advance(second.deliveries[0]) == "pending"
        assert len(chat.calls) == 1
        assert await worker.reconcile(first.deliveries[0]) == "delivered"
        chat.mode = "success"
        assert await worker.advance(second.deliveries[0]) == "delivered"
        assert len(chat.calls) == 2
        assert (
            "Live native first" in chat.messages[1000].content
            and "Live native second" in chat.messages[1001].content
        )
    finally:
        await transport.close()


async def test_restart_cutoff_does_not_automatically_publish_old_unplanned_live_records(
    db, profile
):
    publisher, binding, transport, worker, chat = await setup(db, profile, late_open=True)
    try:
        results = await publish_all(publisher)
        assert [result.state for _, result in results] == ["history", "recovery", "recovery"]
        async with db.sessions() as session:
            assert await session.scalar(select(Delivery.id)) is None
        assert not chat.calls
    finally:
        await transport.close()


async def test_replayed_publication_keeps_original_locale_plan_and_held_delivery_state(db, profile):
    publisher, binding, transport, worker, chat = await setup(
        db, profile, historical=False, texts=["Native original text"]
    )
    try:
        identity, result = (await publish_all(publisher))[0]
        original = (await publisher.outbox.load(result.batch.deliveries[0])).payload
        await DurableStore(db).recover()
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(locale="zh-TW"))
        restored = await NativePublisher.open(
            publisher.projector,
            publisher.outbox,
            realm_id="realm",
            message_limit=1000,
            topic_limit=60,
        )
        assert await restored.advance(identity) == result
        saved = await publisher.outbox.load(result.batch.deliveries[0])
        assert saved.payload == original and saved.state == "held" and saved.attempts == 0
    finally:
        await transport.close()


async def test_source_batch_and_pages_roll_back_as_one_transaction_and_local_retry_is_safe(
    db, profile
):
    publisher, binding, transport, worker, chat = await setup(
        db, profile, historical=False, texts=["Native original text"]
    )
    try:
        identity = await publisher.next_pending()

        def fail(_):
            raise RuntimeError("injected publication commit failure")

        sql_event.listen(Session, "before_commit", fail)
        try:
            with pytest.raises(RuntimeError, match="injected"):
                await publisher.advance(identity)
        finally:
            sql_event.remove(Session, "before_commit", fail)
        async with db.sessions() as session:
            assert await session.scalar(select(NativePublication.input_event_id)) is None
            assert await session.scalar(select(Delivery.id)) is None
            assert await session.scalar(select(DeliveryBatch.id)) is None
        assert (await publisher.advance(identity)).state == "queued"
        assert not chat.calls
    finally:
        await transport.close()


async def test_concurrent_publication_of_same_native_record_has_one_immutable_batch(db, profile):
    publisher, binding, transport, worker, chat = await setup(
        db, profile, historical=False, texts=["Native original text"]
    )
    try:
        identity = await publisher.next_pending()
        results = await asyncio.gather(*(publisher.advance(identity) for _ in range(3)))
        assert results[0] == results[1] == results[2]
        async with db.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(DeliveryBatch)) == 1
            assert await session.scalar(select(func.count()).select_from(NativePublication)) == 1
    finally:
        await transport.close()


async def test_requesting_later_source_first_waits_for_the_earlier_source_publication(db, profile):
    publisher, binding, transport, worker, chat = await setup(db, profile, historical=False)
    try:
        async with db.sessions() as session:
            rows = (
                await session.scalars(
                    select(NativeProjectionRecord)
                    .where(NativeProjectionRecord.native_type == "session.text.ended")
                    .order_by(NativeProjectionRecord.ordinal)
                )
            ).all()
        assert (await publisher.advance(rows[-1].input_event_id)).state == "waiting"
        async with db.sessions() as session:
            assert await session.scalar(select(NativePublication.input_event_id)) is None
        assert len(await publish_all(publisher)) == 2
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "text,state",
    [
        ("   ", "empty"),
        ("-----BEGIN PRIVATE KEY-----\nPRIVATE_INCOMPLETE_VALUE", "needs_full_output"),
        ("API_TOKEN=\x1b[31mPRIVATE_VISIBLE_VALUE\x1b[0m", "queued"),
    ],
)
async def test_display_policy_keeps_original_and_never_posts_incomplete_or_recognizable_credentials(
    db, profile, text, state
):
    publisher, binding, transport, worker, chat = await setup(
        db, profile, historical=False, texts=[text]
    )
    try:
        result = (await publish_all(publisher))[0][1]
        assert result.state == state
        if result.batch:
            body = (await publisher.outbox.load(result.batch.deliveries[0])).payload["content"]
            assert "PRIVATE_INCOMPLETE_VALUE" not in body and "PRIVATE_VISIBLE_VALUE" not in body
        async with db.sessions() as session:
            source = await session.scalar(
                select(NativeProjectionRecord).where(
                    NativeProjectionRecord.native_type == "session.text.ended"
                )
            )
            assert source.payload["change"]["text"]["text"] == text
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["grant", "binding", "source", "dependency"])
async def test_revoked_or_changed_publication_evidence_cannot_send_native_text(db, profile, change):
    publisher, binding, transport, worker, chat = await setup(db, profile, historical=False)
    try:
        identity = await publisher.next_pending()
        if change == "dependency":
            results = await publish_all(publisher)
            second = results[1][1].batch
            async with db.sessions.begin() as session:
                await session.execute(
                    update(BatchDependency)
                    .where(BatchDependency.batch_id == second.id)
                    .values(payload_hash="0" * 64)
                )
            assert await worker.advance(second.deliveries[0]) == "held"
        else:
            async with db.sessions.begin() as session:
                if change == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 8).values(active=False)
                    )
                elif change == "binding":
                    await session.execute(update(Binding).values(revision=2))
                else:
                    await session.execute(
                        update(NativeProjectionRecord)
                        .where(NativeProjectionRecord.input_event_id == identity)
                        .values(payload_hash="0" * 64)
                    )
            with pytest.raises(ValueError):
                await publisher.advance(identity)
        assert not chat.calls
    finally:
        await transport.close()


async def test_dependency_changed_after_payload_read_is_held_before_any_post(db, profile):
    publisher, binding, transport, worker, chat = await setup(db, profile, historical=False)
    try:
        results = await publish_all(publisher)
        first, second = [result.batch for _, result in results]
        assert await worker.advance(first.deliveries[0]) == "delivered"
        original = worker.payload

        async def changed(saved):
            payload = await original(saved)
            async with db.sessions.begin() as session:
                await session.execute(
                    update(BatchDependency)
                    .where(BatchDependency.batch_id == second.id)
                    .values(payload_hash="0" * 64)
                )
            return payload

        worker.payload = changed
        assert await worker.advance(second.deliveries[0]) == "held"
        assert len(chat.calls) == 1
    finally:
        await transport.close()


async def test_all_pages_of_previous_batch_need_positive_delivery_ids(db, profile):
    publisher, binding, transport, worker, chat = await setup(
        db,
        profile,
        historical=False,
        texts=["Long native output.\n\n" * 180, "Second native reply"],
        limit=600,
    )
    try:
        first, second = [result.batch for _, result in await publish_all(publisher)]
        assert len(first.deliveries) > 1
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery)
                .where(Delivery.batch_id == first.id)
                .values(state="delivered", posted_message_id=None)
            )
        assert await worker.advance(second.deliveries[0]) == "pending" and not chat.calls
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery).where(Delivery.batch_id == first.id).values(state="pending")
            )
        for identity in first.deliveries:
            assert await worker.advance(identity) == "delivered"
        assert await worker.advance(second.deliveries[0]) == "delivered"
    finally:
        await transport.close()


async def test_cached_batch_dependency_cannot_be_removed_or_replaced_by_caller(db, profile):
    from jt_oz_bridge.services.native_publisher import RENDERER_VERSION

    publisher, binding, transport, worker, chat = await setup(db, profile, historical=False)
    try:
        results = await publish_all(publisher)
        source_id, second = results[1]
        saved = await publisher.outbox.load(second.batch.deliveries[0])
        page = without_marker(saved.payload["content"], "jtoz:" + saved.id)
        with pytest.raises(Conflict, match="dependency_changed"):
            async with db.sessions.begin() as session:
                await publisher.outbox.queue_batch_in_session(
                    session,
                    "native-text:" + source_id,
                    binding,
                    (page,),
                    renderer_version=RENDERER_VERSION,
                    message_limit=1000,
                    topic_limit=60,
                    priority=100,
                    after_batch_id=None,
                )
        assert not chat.calls
    finally:
        await transport.close()


async def test_role_revocation_after_source_preflight_rolls_back_publication_and_batch(db, profile):
    publisher, binding, transport, worker, chat = await setup(
        db, profile, historical=False, texts=["Native secret project text"]
    )
    try:
        identity = await publisher.next_pending()
        original = publisher.source

        async def revoked(selected):
            result = await original(selected)
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
            return result

        publisher.source = revoked
        with pytest.raises(ValueError):
            await publisher.advance(identity)
        async with db.sessions() as session:
            assert await session.scalar(select(NativePublication.input_event_id)) is None
            assert await session.scalar(select(DeliveryBatch.id)) is None
        assert not chat.calls
    finally:
        await transport.close()


async def test_publication_is_in_topic_language_and_body_dependency_manifest_are_encrypted(
    db, profile
):
    from sqlalchemy import text

    publisher, binding, transport, worker, chat = await setup(
        db, profile, historical=False, texts=["PRIVATE_NATIVE_BODY_A", "PRIVATE_NATIVE_BODY_B"]
    )
    try:
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(locale="zh-TW"))
        results = await publish_all(publisher)
        first = results[0][1].batch
        assert (
            "OpenCode 回覆" in (await publisher.outbox.load(first.deliveries[0])).payload["content"]
        )
        async with db.engine.connect() as connection:
            for table in ("native_publications", "batch_dependencies"):
                raw = (
                    (await connection.execute(text("SELECT payload FROM " + table))).scalars().all()
                )
                assert raw and all(
                    isinstance(item, bytes) and b"PRIVATE_NATIVE_BODY" not in item for item in raw
                )
    finally:
        await transport.close()
