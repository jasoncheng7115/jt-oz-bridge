"""Owned creation + real authorized moves/SQL, with synthetic Human/Native peers."""

import copy

import pytest
from sqlalchemy import event, update

from jt_oz_bridge.domain.control import AudienceSnapshot
from jt_oz_bridge.services.binding_scope_history import EVENT
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.session_creation_activation import SessionCreationActivation
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.storage.control_models import Binding, EnrolledProject
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch, Grant
from tests.integration.test_session_creation_activation import cleanup, setup
from tests.integration.test_session_creation_journal import rows


async def moved(db, *, users=frozenset({7, 8})):
    e = await setup(db)
    binding = await e["service"].reconcile(e["identity"])
    e["old_binding"] = binding
    async with db.sessions.begin() as session:
        session.add(
            Grant(realm_id="realm", user_id=7, project_id=binding.project_id, role="administrator")
        )
        if 9 in users:
            session.add(
                Grant(realm_id="realm", user_id=9, project_id=binding.project_id, role="viewer")
            )
    original = e["audience"].inspect
    e["destination_users"] = users

    async def inspect(realm, channel, topic):
        if channel == 10:
            return await original(realm, channel, topic)
        return AudienceSnapshot(
            realm_id=realm,
            channel_id=channel,
            canonical_topic=topic,
            user_ids=e["destination_users"],
            private=True,
            revision="destination:" + str(channel),
        )

    e["audience"].inspect = inspect
    await e["journal"].bindings.move(binding.id, "realm", 7, 1, 11, "Moved topic", whole_topic=True)
    return e


def restored(e):
    registry = SessionRegistry({e["anchor"].reference: e["anchor"]})
    factory = V2CreatedRootFactory(e["factory"].creator, e["factory"].policies, registry)
    e["journal"].bindings.control = registry
    return SessionCreationActivation(
        e["journal"], {e["intent"].scope.project_id: factory}, e["replies"]
    ), registry


@pytest.mark.parametrize("source_state", ["moved", "edited", "deleted", "gone"])
async def test_authorized_move_restores_same_root_without_replaying_historical_source_or_notice(
    db, source_state
):
    e = await moved(db)
    try:
        before = [
            (r.id, r.payload_hash, r.state, r.binding_revision) for r in await rows(db, Delivery)
        ]
        if source_state == "gone":
            del e["source"].messages[101]
        else:
            changes = {
                "moved": {"channel_id": 11, "topic": "Moved topic"},
                "edited": {"revision": 1, "text": "edited historical command"},
                "deleted": {"deleted": True},
            }[source_state]
            e["source"].messages[101] = e["item"].model_copy(update=changes)
        e["source"].calls.clear()
        service, registry = restored(e)
        assert await service.restore_active() == (e["identity"],)
        action, binding = await e["journal"].load(e["identity"])
        assert binding.revision == 2 and binding.channel_id == 11 and binding.topic == "Moved topic"
        assert binding.dispatch_paused and action.binding_revision == 1
        assert action.native_result["activation"]["binding_revision"] == 1
        assert registry.sessions[e["candidate"].reference].reference == e["candidate"].reference
        assert not e["source"].calls and not e["writes"]
        assert [
            (r.id, r.payload_hash, r.state, r.binding_revision) for r in await rows(db, Delivery)
        ] == before
        assert len(await rows(db, DeliveryBatch)) == 1
        with pytest.raises(ValueError):
            await e["replies"].outbox.target(binding.id, 1)
        if source_state == "moved":
            with pytest.raises(ValueError):
                await e["journal"].reserve(e["source"].messages[101])
            assert len(await rows(db, Action)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


async def test_multiple_moves_and_explicit_queue_resume_keep_notice_at_original_revision(db):
    e = await moved(db)
    try:
        action, binding = await e["journal"].load(e["identity"])
        await e["journal"].bindings.move(
            binding.id, "realm", 7, 2, 12, "Moved again", whole_topic=True
        )
        service, registry = restored(e)
        assert await service.restore_active() == (e["identity"],)
        _, current = await e["journal"].load(e["identity"])
        assert current.revision == 3 and current.dispatch_paused
        await QueueService(e["journal"].bindings, fence=e["journal"].fence).resume(
            current.id,
            "realm",
            7,
            3,
            current.queue_revision,
        )
        assert (await service.reconcile(e["identity"])).dispatch_paused is False
        assert len([x for x in await rows(db, AuditEvent) if x.event == EVENT]) == 2
        assert [x.binding_revision for x in await rows(db, Delivery)] == [1]
        assert (await rows(db, Action))[0].native_result == action.native_result
    finally:
        await cleanup(e)


async def test_completed_origin_restore_uses_current_approved_readers_after_creator_revocation(db):
    e = await moved(db, users=frozenset({8, 9}))
    try:
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        e["source"].messages.clear()
        service, registry = restored(e)
        assert await service.restore_active() == (e["identity"],)
        assert (await e["journal"].load(e["identity"]))[1].audience_user_ids == [8, 9]
        assert [
            d.payload["to"] if "to" in d.payload else d.payload["channel_id"]
            for d in await rows(db, Delivery)
        ] == [10]
        assert not e["writes"]
    finally:
        await cleanup(e)


@pytest.mark.parametrize("fault", ["grant", "project", "audience", "public"])
async def test_current_scope_revocation_rejects_restore_even_with_valid_move_chain(db, fault):
    e = await moved(db, users=frozenset({8, 9}))
    try:
        if fault == "audience":
            e["destination_users"] = frozenset({8, 9, 99})
        elif fault == "public":
            original = e["audience"].inspect

            async def inspect(*args):
                return (await original(*args)).model_copy(update={"private": False})

            e["audience"].inspect = inspect
        else:
            async with db.sessions.begin() as session:
                if fault == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 9).values(active=False)
                    )
                else:
                    await session.execute(update(EnrolledProject).values(enabled=False))
        service, registry = restored(e)
        # The Root waits alone, unregistered, instead of stopping the Bridge.
        assert await service.restore_active() == ()
        assert service.unrestored_roots() == frozenset({e["candidate"].reference})
        assert e["candidate"].reference not in registry.sessions
        assert len(await rows(db, Delivery)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate",
        "before",
        "after",
        "actor",
        "gap",
        "current-topic",
        "current-audience",
        "duplicate-readers",
        "actor-format",
        "current-owner",
        "current-reference",
        "backward",
        "capacity",
    ],
)
async def test_incomplete_tampered_or_fabricated_move_chains_cannot_restore(db, fault):
    e = await moved(db)
    try:
        async with db.sessions.begin() as session:
            moves = [r for r in (await rows(db, AuditEvent)) if r.event == EVENT]
            move = await session.get(AuditEvent, moves[0].id)
            if fault == "missing":
                await session.delete(move)
            elif fault == "duplicate":
                session.add(
                    AuditEvent(actor=move.actor, event=move.event, object_id=move.object_id)
                )
            elif fault in {"before", "after", "gap", "actor", "actor-format"}:
                parts = move.object_id.split(":")
                if fault in {"actor", "actor-format"}:
                    move.actor = "other-realm:7" if fault == "actor" else "realm:007"
                else:
                    parts[{"before": 3, "after": 4, "gap": 2}[fault]] = (
                        "f" * 64 if fault != "gap" else "3"
                    )
                    move.object_id = ":".join(parts)
            else:
                await session.execute(
                    update(Binding).values(
                        **{
                            "current-topic": {
                                "topic": "Unapproved",
                                "topic_key": digest(
                                    {"realm": "realm", "channel": 11, "topic": "Unapproved"}
                                ),
                            },
                            "current-audience": {"audience_revision": "unknown"},
                            "duplicate-readers": {"audience_user_ids": [7, 8, 8]},
                            "current-owner": {"owner_id": 8},
                            "current-reference": {"session_id": "ses_replacement"},
                            "backward": {"revision": 1},
                            "capacity": {"revision": 1002},
                        }[fault]
                    )
                )
        calls = len(e["calls"])
        service, registry = restored(e)
        with pytest.raises(ValueError):
            await service.restore_active()
        assert len(e["calls"]) == calls and e["candidate"].reference not in registry.sessions
        assert len(await rows(db, Delivery)) == 1
    finally:
        await cleanup(e)


@pytest.mark.parametrize("fault", ["target", "bot", "revision", "hash", "marker", "plan"])
async def test_historical_notice_stays_exact_even_after_legitimate_scope_move(db, fault):
    e = await moved(db)
    try:
        async with db.sessions.begin() as session:
            delivery = await session.get(Delivery, (await rows(db, Delivery))[0].id)
            if fault == "revision":
                delivery.binding_revision = 2
            elif fault == "hash":
                delivery.payload_hash = "f" * 64
            elif fault == "plan":
                batch = await session.get(DeliveryBatch, delivery.batch_id)
                batch.plan_hash = "f" * 64
            else:
                data = copy.deepcopy(delivery.payload)
                if fault == "target":
                    data.update(channel_id=11, topic="Moved topic")
                elif fault == "bot":
                    data["bot_user_id"] = 99
                else:
                    data["marker"] = "jtoz:" + "f" * 36
                delivery.payload, delivery.payload_hash = data, digest(data)
        service, registry = restored(e)
        # This check fails after the Root was registered: only a stopped startup
        # keeps it unused, so it never waits alone like an unregistered Root.
        with pytest.raises(ValueError):
            await service.restore_active()
        assert e["candidate"].reference in registry.sessions
        assert not service.unrestored_roots()
        assert len(await rows(db, Delivery)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


@pytest.mark.parametrize("fault", ["manage", "destination-view", "project"])
async def test_move_rechecks_commit_authority_and_leaves_no_scope_receipt_when_revoked(db, fault):
    e = await setup(db)
    try:
        binding = await e["service"].reconcile(e["identity"])
        async with db.sessions.begin() as session:
            session.add(
                Grant(
                    realm_id="realm", user_id=7, project_id=binding.project_id, role="administrator"
                )
            )
        original, count = e["audience"].inspect, 0

        async def inspect(realm, channel, topic):
            nonlocal count
            found = await original(realm, channel, topic)
            if channel == 11:
                count += 1
                if count == 2:
                    async with db.sessions.begin() as session:
                        if fault == "manage":
                            await session.execute(
                                update(Grant)
                                .where(Grant.role == "administrator")
                                .values(active=False)
                            )
                        elif fault == "destination-view":
                            await session.execute(
                                update(Grant).where(Grant.user_id == 8).values(active=False)
                            )
                        else:
                            await session.execute(update(EnrolledProject).values(enabled=False))
            return found

        e["audience"].inspect = inspect
        with pytest.raises(ValueError):
            await e["journal"].bindings.move(
                binding.id, "realm", 7, 1, 11, "Moved topic", whole_topic=True
            )
        current = (await rows(db, Binding))[0]
        assert current.revision == 1 and current.channel_id == 10
        assert not [r for r in await rows(db, AuditEvent) if r.event == EVENT]
    finally:
        await cleanup(e)


async def test_scope_receipt_insert_failure_rolls_back_the_move_and_old_notice_remains(db):
    e = await setup(db)
    try:
        binding = await e["service"].reconcile(e["identity"])
        async with db.sessions.begin() as session:
            session.add(
                Grant(
                    realm_id="realm", user_id=7, project_id=binding.project_id, role="administrator"
                )
            )

        def fail(conn, cursor, statement, parameters, context, many):
            if statement.startswith("INSERT INTO audit_events"):
                raise RuntimeError("synthetic audit write failure")

        event.listen(db.engine.sync_engine, "before_cursor_execute", fail)
        try:
            with pytest.raises(RuntimeError):
                await e["journal"].bindings.move(
                    binding.id, "realm", 7, 1, 11, "Moved topic", whole_topic=True
                )
        finally:
            event.remove(db.engine.sync_engine, "before_cursor_execute", fail)
        current = (await rows(db, Binding))[0]
        assert current.revision == 1 and current.topic == e["item"].topic
        assert not [r for r in await rows(db, AuditEvent) if r.event == EVENT]
        assert len(await rows(db, Delivery)) == 1
    finally:
        await cleanup(e)
