"""Synthetic Humans/Native admission with real isolated encrypted DB and durable outbox."""

import asyncio
import copy
from dataclasses import replace
from html import unescape

import pytest
from sqlalchemy import event, select, update

from jt_oz_bridge.domain.execution import Admission, MutationNotSent
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.domain.session_lifecycle import SessionRename, SessionRenameOutcome
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.session_lifecycle_commands import SessionLifecycleCommands
from jt_oz_bridge.services.session_lifecycle_publisher import SessionRenamePublisher
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant, WorkerLease
from jt_oz_bridge.storage.publication_models import ModelSettingPublication
from jt_oz_bridge.storage.transcript_models import TranscriptStream
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message, send
from tests.support import bound


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


class RenameExecution(SyntheticExecution):
    def __init__(self):
        super().__init__()
        self.title, self.enabled, self.hook = "Original running work", True, None

    async def snapshot(self, ref):
        if self.hook:
            await self.hook()
        return (await super().snapshot(ref)).model_copy(
            update={"title": self.title, "reference": self.ref}
        )

    def capabilities(self, ref):
        result = super().capabilities(ref)
        result["session.rename"] = Capability(
            supported=self.enabled,
            scope="session",
            reason="synthetic only",
            verification="synthetic_test",
        )
        return result

    async def submit(self, ref, payload, identity):
        assert ref == self.ref and payload["operation"] == "session.rename"
        if self.mode == "not-sent":
            raise MutationNotSent("synthetic fixed preflight rejected")
        self.submitted.append((ref, payload, identity))
        change = SessionRename.model_validate(payload["change"])
        assert change.previous_title == self.title
        self.title = change.target_title
        if self.mode == "lost-ack":
            raise TimeoutError("synthetic lost reply after title changed")
        return Admission(
            status="completed",
            details=SessionRenameOutcome(
                change=change,
                observed_title=self.title,
                owner_evidence_sha256="a" * 64,
                session_info_sha256="b" * 64,
            ).model_dump(mode="json"),
        )


async def setup(db):
    execution = RenameExecution()
    bindings, binding, _, audience = await bound(db, control=execution)
    lease = await DurableStore(db).acquire_lease("lifecycle", ttl=120)
    inbox, source = CommandInbox(db, "lifecycle", lease), Source()
    commands = SessionLifecycleCommands(bindings, source, inbox.fence, execution.capabilities)
    router = CommandRouter(bindings, source, inbox, lifecycle=commands)
    worker = Dispatcher(bindings, execution, source, "lifecycle", lease)
    publisher = SessionRenamePublisher(
        RoutedOutbox(
            Outbox(bindings, 77, fence=inbox.fence),
            realm_id="realm",
            message_limit=1000,
            topic_limit=60,
        )
    )
    return router, binding, source, execution, commands, worker, publisher, audience


async def completed(db, locale="en"):
    values = await setup(db)
    router, binding, source, execution, commands, worker, publisher, audience = values
    if locale != "en":
        await send(router, source, message("!oz lang " + locale, 99))
    await send(router, source, message("!oz rename New @**all** title", 101))
    action = (await rows(db, Action))[0]
    assert await worker.advance(action.id) == "completed"
    return values, action.id


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_rename_routes_once_dispatches_original_and_publishes_sealed_non_turn_notice(
    db, locale
):
    values, identity = await completed(db, locale)
    router, binding, source, execution, commands, worker, publisher, audience = values
    assert await publisher.next_pending() == identity
    one, two = await asyncio.gather(publisher.publish(identity), publisher.publish(identity))
    assert one == two and await publisher.next_pending() is None
    assert len(await rows(db, DeliveryBatch)) == len(await rows(db, ModelSettingPublication)) == 1
    content = unescape(" ".join(x.payload["content"] for x in await rows(db, Delivery)))
    assert "New @**all** title" in content and binding.topic not in execution.title
    assert "話題名稱不變" in content if locale == "zh-TW" else "topic name stays" in content
    assert not any(x in content for x in ["completed turn", "turn result"])
    # Redelivery after the native title changed recovers the saved command reply.
    assert (
        await send(router, source, message("!oz rename New @**all** title", 101))
    ).state == "reply"
    assert len(await rows(db, Action)) == len(execution.submitted) == 1
    await worker.advance(identity)
    assert len(execution.submitted) == 1 and reference(binding) == execution.ref


@pytest.mark.parametrize(
    "fault", ["edited", "deleted", "bot", "grant", "revision", "audience", "title", "capability"]
)
async def test_changed_source_or_authority_before_dispatch_cannot_rename(db, fault):
    router, binding, source, execution, commands, worker, publisher, audience = await setup(db)
    item = message("!oz rename New title", 101)
    await send(router, source, item)
    action = (await rows(db, Action))[0]
    if fault in {"edited", "deleted", "bot"}:
        updates = {
            "edited": {"revision": 1, "text": "!oz rename Edited"},
            "deleted": {"deleted": True},
            "bot": {"is_bot": True},
        }[fault]
        source.messages[101] = item.model_copy(update=updates)
    elif fault in {"grant", "revision"}:
        async with db.sessions.begin() as session:
            if fault == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            else:
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(revision=2)
                )
    elif fault == "audience":
        audience.private = False
    elif fault == "title":
        execution.title = "Concurrent TUI title"
    else:
        execution.enabled = False
    assert await worker.advance(action.id) in {"held", "rejected"}
    assert not execution.submitted and await publisher.next_pending() is None


@pytest.mark.parametrize("fault", ["source", "grant", "revision", "audience", "scope"])
async def test_awaited_snapshot_changes_are_rechecked_before_action_commit(db, fault):
    router, binding, source, execution, commands, worker, publisher, audience = await setup(db)
    item = message("!oz rename New title", 101)
    source.messages[101] = item

    async def change():
        if fault == "source":
            source.messages[101] = item.model_copy(update={"revision": 1})
        elif fault == "audience":
            audience.private = False
        elif fault == "scope":
            execution.ref = execution.ref.model_copy(update={"canonical_directory": "/foreign"})
        else:
            async with db.sessions.begin() as session:
                if fault == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                else:
                    await session.execute(
                        update(Binding).where(Binding.id == binding.id).values(revision=2)
                    )

    execution.hook = change
    with pytest.raises((Conflict, AccessDenied)):
        await commands.rename(binding, item, "en", "New title")
    assert not await rows(db, Action) and not execution.submitted


async def test_dispatch_pause_retains_explicit_action_and_unqualified_command_stays_local(db):
    router, binding, source, execution, commands, worker, publisher, audience = await setup(db)
    execution.enabled = False
    reply = await send(router, source, message("!oz rename Title", 101))
    assert "renamed right now" in reply.text and not await rows(db, Action)
    execution.enabled = True
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    await send(router, source, message("!oz rename Held title", 102))
    action = (await rows(db, Action))[0]
    assert action.state == "held" and not execution.submitted


async def test_lost_ack_stays_ambiguous_without_repeat_and_without_success_notice(db):
    router, binding, source, execution, commands, worker, publisher, audience = await setup(db)
    execution.mode = "lost-ack"
    await send(router, source, message("!oz rename Applied but uncertain", 101))
    action = (await rows(db, Action))[0]
    assert await worker.advance(action.id) == "ambiguous"
    assert execution.title == "Applied but uncertain" and len(execution.submitted) == 1
    assert await worker.advance(action.id) == "ambiguous" and len(execution.submitted) == 1
    assert await publisher.next_pending() is None and not await rows(db, DeliveryBatch)


async def test_unknown_title_mutation_blocks_later_rename_and_pause_is_rechecked_at_claim(db):
    router, binding, source, execution, commands, worker, publisher, audience = await setup(db)
    await send(router, source, message("!oz rename First title", 101))
    first = (await rows(db, Action))[0]
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    assert await worker.advance(first.id) == "queued" and not execution.submitted
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=False)
        )
    execution.mode = "lost-ack"
    assert await worker.advance(first.id) == "ambiguous"
    await send(router, source, message("!oz rename Later title", 102))
    second = next(x for x in await rows(db, Action) if x.id != first.id)
    assert await worker.advance(second.id) == "queued" and len(execution.submitted) == 1


async def test_title_confirmation_is_available_even_for_a_mirrored_original_session(db):
    values, identity = await completed(db)
    _, binding, _, execution, _, _, publisher, _ = values
    async with db.sessions.begin() as session:
        session.add(
            TranscriptStream(
                key="a" * 64,
                binding_id=binding.id,
                binding_revision=binding.revision,
                payload={},
                payload_hash=digest({}),
            )
        )
    assert await publisher.next_pending() == identity
    await publisher.publish(identity)
    assert len(await rows(db, DeliveryBatch)) == 1 and len(execution.submitted) == 1


async def test_atomic_notice_commit_failure_recovers_from_admission_without_native_retry(db):
    values, identity = await completed(db)
    publisher = values[6]
    execution = values[3]

    def fail(conn, cursor, statement, *args):
        if statement.startswith("INSERT INTO model_setting_publications"):
            raise OSError("synthetic publication commit failure")

    event.listen(db.engine.sync_engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(OSError):
            await publisher.publish(identity)
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", fail)
    assert not await rows(db, DeliveryBatch) and not await rows(db, ModelSettingPublication)
    await publisher.publish(identity)
    assert len(await rows(db, DeliveryBatch)) == 1 and len(execution.submitted) == 1


@pytest.mark.parametrize("fault", ["title", "turn", "owner", "contract", "scope"])
async def test_tampered_or_wrong_kind_admission_is_not_announced_as_a_rename(db, fault):
    values, identity = await completed(db)
    publisher = values[6]
    async with db.sessions.begin() as session:
        action = await session.get(Action, identity)
        admission = copy.deepcopy(action.admission)
        if fault == "title":
            admission["admission"]["details"]["observed_title"] = "Different"
        elif fault == "turn":
            admission["admission"]["details"]["turn_completed"] = True
        elif fault == "owner":
            admission["admission"]["owner"] = "bridge"
        elif fault == "contract":
            admission["contract_sha256"] = "b" * 64
        else:
            admission["reference"]["upstream_session_id"] = "foreign"
        action.admission = admission
    with pytest.raises(ValueError):
        await publisher.publish(identity)
    assert not await rows(db, DeliveryBatch)


@pytest.mark.parametrize("fault", ["public", "grant", "revision", "lease"])
async def test_publication_rechecks_current_authority_without_resending_native(db, fault):
    values, identity = await completed(db)
    _, binding, _, execution, _, _, publisher, audience = values
    if fault == "public":
        audience.private = False
    else:
        async with db.sessions.begin() as session:
            if fault == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            elif fault == "revision":
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(revision=2)
                )
            else:
                await session.execute(update(WorkerLease).values(expires_at=0))
    with pytest.raises((Conflict, AccessDenied)):
        await publisher.publish(identity)
    assert not await rows(db, DeliveryBatch) and len(execution.submitted) == 1


async def test_restarted_publisher_keeps_sealed_chinese_pages_after_limit_change(db):
    values, identity = await completed(db, "zh-TW")
    publisher = values[6]
    original = await publisher.publish(identity)
    bodies = [(x.payload, x.payload_hash) for x in await rows(db, Delivery)]
    restarted = SessionRenamePublisher(
        RoutedOutbox(publisher.replies.outbox, realm_id="realm", message_limit=512, topic_limit=60)
    )
    assert await restarted.publish(identity) == original
    assert [(x.payload, x.payload_hash) for x in await rows(db, Delivery)] == bodies


async def test_whole_consumer_graph_acknowledges_and_delivers_title_readback_without_bot_echo(db):
    from tests.integration.test_consumer_runtime import post_containing, until
    from tests.integration.test_consumer_runtime import setup as graph_setup

    previous, server, old_native, results, binding, pulse = await graph_setup(db)
    ref = reference(binding)
    backend = previous.backends[ref.backend_id]
    native = RenameExecution()
    native.contract_hash = backend.registered.contract_sha256
    backend = replace(backend, registered=replace(backend.registered, client=native))
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {ref.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz rename Whole graph title", 101)
        delivered = await post_containing(server, "Conversation renamed")

        async def all_delivered():
            saved = await rows(db, Delivery)
            return bool(saved) and all(x.state == "delivered" for x in saved)

        await until(all_delivered)
        assert delivered["sender_id"] == 11 and delivered["subject"] == binding.topic
        assert native.title == "Whole graph title" and len(native.submitted) == 1
        assert len(await rows(db, Action)) == len(await rows(db, ModelSettingPublication)) == 1
        assert runtime.healthy and not old_native.submitted
    finally:
        await runtime.close()
