import asyncio
import time

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.control import FieldAnswer, InteractionSnapshot, QuestionField
from jt_oz_bridge.domain.models import ActionState
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.storage.control_models import Binding, FormDraft, PendingInteraction
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant, WorkerLease
from tests.support import REF, bound


async def pending(db, *, form=False):
    bindings, binding, control, audience = await bound(db)
    interactions = InteractionService(bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="original-pending",
        generation="g1",
        kind="form" if form else "permission",
        pending=True,
        description="Original request",
        fields=(QuestionField(id="note", label="Note", kind="text"),) if form else (),
    )
    control.requests[snapshot.upstream_request_id] = snapshot
    identity = await interactions.observe(binding, snapshot)
    token = await interactions.issue(identity, "realm", 7)
    return bindings, binding, control, interactions, snapshot, identity, token


async def moved(bindings, binding):
    await bindings.move(binding.id, "realm", 7, binding.revision, 11, "New topic", whole_topic=True)
    return await bindings.get(binding.id, "realm", 7)


@pytest.mark.parametrize("mode", ["move", "unbind"])
async def test_exact_unadmitted_pending_rescopes_with_new_tokens_and_no_draft_or_expiry_carryover(
    db, mode
):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(
        db, form=True
    )
    await interactions.save_answer(
        token, "realm", 7, "note", FieldAnswer(text="PRIVATE_UNSUBMITTED_DRAFT")
    )
    async with db.sessions() as session:
        original = await session.get(PendingInteraction, identity)
        expiry, version = original.expires_at, original.version
    if mode == "move":
        current = await moved(bindings, binding)
    else:
        await bindings.unbind(binding.id, "realm", 7, 1)
        current = await bindings.bind("realm", 7, 12, "Rebound topic", REF)
    assert await interactions.observe(current, snapshot) == identity
    async with db.sessions() as session:
        row = await session.get(PendingInteraction, identity)
        assert (row.binding_id, row.binding_revision, row.version, row.expires_at) == (
            current.id,
            current.revision,
            version + 1,
            expiry,
        )
        assert row.state == "pending" and row.action_id is None and row.winner_user_id is None
        assert (
            await session.scalar(select(FormDraft.key).where(FormDraft.interaction_id == identity))
            is None
        )
    with pytest.raises(Conflict):
        await interactions.save_answer(
            token, "realm", 7, "note", FieldAnswer(text="old-token"), expected_revision=1
        )
    fresh = await interactions.issue(identity, "realm", 7)
    assert fresh != token
    assert (
        await interactions.save_answer(
            fresh, "realm", 7, "note", FieldAnswer(text="New deliberate draft")
        )
        == 1
    )
    # Duplicate observation does not increment a second time or erase the new draft.
    assert await interactions.observe(current, snapshot) == identity
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).version == version + 1
        assert await session.scalar(
            select(FormDraft.key).where(FormDraft.interaction_id == identity)
        )


@pytest.mark.parametrize("state", ["queued", "dispatching", "admitted", "ambiguous", "rejected"])
async def test_queued_or_attempted_decision_never_rescopes_or_becomes_replayable(db, state):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    action = await interactions.reply(token, "realm", 7, decision="once")
    if state != "queued":
        store = DurableStore(db)
        assert await store.transition(action, ActionState.QUEUED, ActionState.DISPATCHING, 1)
        if state != "dispatching":
            assert await store.transition(action, ActionState.DISPATCHING, ActionState(state), 2)
    current = await moved(bindings, binding)
    with pytest.raises(Conflict, match="cannot_change_binding"):
        await interactions.observe(current, snapshot)
    async with db.sessions() as session:
        row = await session.get(PendingInteraction, identity)
        assert row.binding_revision == 1 and row.action_id == action and row.winner_user_id == 7


@pytest.mark.parametrize("change", ["resolved", "schema", "generation", "missing"])
async def test_rescope_needs_fresh_exact_native_pending_not_replayed_old_event(db, change):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    current = await moved(bindings, binding)
    if change == "resolved":
        control.resolved = True
    elif change == "missing":
        control.requests.clear()
    else:
        control.requests[snapshot.upstream_request_id] = snapshot.model_copy(
            update={"description" if change == "schema" else "generation": "changed"}
        )
    with pytest.raises(Conflict):
        await interactions.observe(current, snapshot)
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).binding_revision == 1


@pytest.mark.parametrize("mode", ["unbound", "moved", "realm"])
async def test_cached_observer_cannot_insert_or_update_against_stale_binding(db, mode):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    if mode == "unbound":
        await bindings.unbind(binding.id, "realm", 7, 1)
    elif mode == "moved":
        await moved(bindings, binding)
    else:
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(realm_id="foreign")
            )
    # Exercise both existing and genuinely new event insertion.
    for incoming in (snapshot, snapshot.model_copy(update={"upstream_request_id": "new-request"})):
        with pytest.raises((Conflict, AccessDenied)):
            await interactions.observe(binding, incoming)
    async with db.sessions() as session:
        assert len((await session.scalars(select(PendingInteraction))).all()) == 1


async def test_expired_pending_does_not_gain_new_lifetime_through_move_or_polling(db):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    async with db.sessions.begin() as session:
        await session.execute(update(PendingInteraction).values(expires_at=0))
    current = await moved(bindings, binding)
    assert await interactions.observe(current, snapshot) == identity
    with pytest.raises(Conflict, match="expired"):
        await interactions.issue(identity, "realm", 7)
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).expires_at == 0


async def test_two_observers_rescope_once_and_keep_original_request_identity(db):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    current = await moved(bindings, binding)
    other = InteractionService(bindings)
    assert await asyncio.gather(
        interactions.observe(current, snapshot), other.observe(current, snapshot)
    ) == [identity, identity]
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).version == 2
        assert len((await session.scalars(select(PendingInteraction))).all()) == 1


async def test_current_native_lineage_with_another_active_binding_cannot_steal_pending(db):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    other_ref = REF.model_copy(update={"upstream_session_id": "another-original"})
    original_snapshot = control.snapshot

    async def qualified(reference):
        result = await original_snapshot(reference)
        return result.model_copy(
            update={"reference": reference, "descendants": (REF,) if reference == other_ref else ()}
        )

    control.snapshot = qualified
    other = await bindings.bind("realm", 7, 11, "Other topic", other_ref)
    with pytest.raises(Conflict, match="cannot_change_binding"):
        await interactions.observe(other, snapshot)
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).binding_id == binding.id


@pytest.mark.parametrize("change", ["fence", "grant", "binding"])
async def test_rescope_rechecks_local_authority_after_final_native_read(db, change):
    bindings, binding, control, interactions, snapshot, identity, token = await pending(db)
    current = await moved(bindings, binding)
    fencing = await DurableStore(db).acquire_lease("fixture", ttl=30)
    scoped = InteractionService(bindings, fence=ConsumerFence("fixture", fencing))
    original = control.interaction

    async def revoke(reference, request_id):
        result = await original(reference, request_id)
        async with db.sessions.begin() as session:
            if change == "fence":
                await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
            elif change == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
            else:
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(revision=3)
                )
        return result

    control.interaction = revoke
    with pytest.raises((Conflict, AccessDenied)):
        await scoped.observe(current, snapshot)
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, identity)).binding_revision == 1
