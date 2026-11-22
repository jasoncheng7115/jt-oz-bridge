"""Synthetic Humans/Native fork graph, real encrypted SQL and outbox; no live peers."""

import asyncio
import copy
import time
from dataclasses import replace
from functools import partial
from html import unescape
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.session_fork import V2ForkedRootObserver, V2ForkPolicy
from jt_oz_bridge.config import Runtime
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import Admission, MutationNotSent
from jt_oz_bridge.domain.session_fork import FORK_REGISTRATION, ForkedRootIntent
from jt_oz_bridge.domain.session_lifecycle import (
    SessionLifecycleChange,
    SessionLifecycleOutcome,
    SessionLifecycleRequest,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import BindingService, topic_key
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.runtime_enrollment import fork_source
from jt_oz_bridge.services.session_creation_journal import CreationProject, SessionCreationJournal
from jt_oz_bridge.services.session_fork_registration import (
    SessionForkRegistration,
    topic_hash,
)
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch, Grant
from tests.contract.test_created_root_factory import setup as factory_setup
from tests.contract.test_leaf_resources import REF, finish
from tests.integration.test_router import Source, message
from tests.integration.test_session_creation_journal import rows
from tests.support import SyntheticAudience

FORK_ID = "ses_forkchild0001"
TOPIC = "Original work"
NATIVE = Path(__file__).parents[1] / "fixtures/installed/opencode-v2.0.32/source"


def fork_row(anchor_info, **changes):
    """What Native 2.0.32's projectFork stores, as session.get returns it."""
    row = copy.deepcopy(anchor_info)
    row.pop("outcome", None)
    row.pop("parentID", None)
    row.update(
        id=FORK_ID,
        title=f"{anchor_info.get('title', 'Original native title')} (fork #1)",
        fork={
            "sessionID": REF.upstream_session_id,
            "boundary": {"type": "through", "messageID": "msg_idle"},
        },
        time={"created": 100, "updated": 100},
        cost=0,
    )
    row.update(changes)
    return row


def fork_request(locale="en", before=None):
    preview = message("!fork pick" if before else "!fork", 100, topic=TOPIC)
    sources = (preview,)
    if before:
        sources += (message("!1", 101, topic=TOPIC),)
    confirm = message("!confirm", 102, topic=TOPIC)
    request = SessionLifecycleRequest(
        operation="session.fork",
        reference=REF,
        source=confirm,
        preview_sources=sources,
        change=SessionLifecycleChange(
            operation="session.fork",
            message_id=before,
            message_preview="first turn" if before else "",
        ),
        reply_locale=locale,
        confirm_expires_at=time.time() + 120,
        confirmation_token_sha256="a" * 64,
    )
    return request, (*sources, confirm)


async def add_fork_action(db, binding, contract, *, locale="en", before=None, state="completed"):
    request, sources = fork_request(locale, before)
    payload = request.model_dump(mode="json")
    identity = str(uuid4())
    outcome = SessionLifecycleOutcome(
        operation="session.fork",
        change=request.change,
        session_id=REF.upstream_session_id,
        new_session_id=FORK_ID,
        owner_evidence_sha256="a" * 64,
        session_info_sha256="b" * 64,
    )
    receipt = ExecutionReceipt(
        action_id=identity,
        operation_digest=digest(payload),
        reference=REF,
        contract_sha256=contract,
        admission=Admission(status="completed", details=outcome.model_dump(mode="json")),
    )
    async with db.sessions.begin() as session:
        session.add(
            Action(
                id=identity,
                dedupe_key="session-lifecycle:" + uuid4().hex,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=7,
                operation="session.fork",
                payload=payload,
                operation_digest=digest(payload),
                admission=receipt.model_dump(mode="json") if state == "completed" else {},
                owner="opencode",
                state=state,
            )
        )
    return identity, sources


def fork_factory(creator_factory, registry=None):
    t = creator_factory.creator.transport
    registry = registry or creator_factory.registry
    template = creator_factory.policies.template
    return V2CreatedRootFactory(
        V2ForkedRootObserver(t, creator_factory.creator.owner, {REF.project_id: template.creation}),
        V2ForkPolicy(creator_factory.policies.anchor, template, partial(fork_source, registry)),
        registry,
    )


async def setup(db, *, locale="en", before=None, fork_state="completed", **row_changes):
    env = {}

    async def make_intent(creator, policies, epoch):
        scope = policies.template.creation.scope
        async with db.sessions.begin() as session:
            session.add(
                EnrolledBackend(
                    id=scope.backend_id,
                    identity=scope.backend_identity,
                    contract_hash=creator.transport.profile.sha256,
                    enabled=True,
                    verified=True,
                    version="synthetic",
                )
            )
            session.add(
                EnrolledProject(
                    id=scope.project_id,
                    backend_id=scope.backend_id,
                    realm_id="realm",
                    canonical_directory=scope.canonical_directory,
                    enabled=True,
                )
            )
            for user in (7, 8):
                session.add(
                    Grant(
                        realm_id="realm", user_id=user, project_id=scope.project_id, role="operator"
                    )
                )
        env["epoch"] = epoch
        # Only the Native path matters to the synthetic peer; the real intent comes
        # later. The title gives the peer's first (pristine creation) row a valid shape.
        return ForkedRootIntent.model_construct(
            title="Synthetic placeholder",
            intent_id="f" * 32,
            scope=scope,
            native_session_id=FORK_ID,
            source_sha256="c" * 64,
            owner_epoch=epoch,
            fork_of=REF.upstream_session_id,
            fork_action_id=str(uuid4()),
        )

    p, t, d, creator, _intent, _candidate, state, calls, writes, anchor = await factory_setup(
        make_intent=make_intent
    )
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | {"session.fork"}
    )
    state["info"] = fork_row(d["session.get"]["data"], **row_changes)
    audience, source = SyntheticAudience(), Source()
    bindings = BindingService(db, creator.registry, audience)
    lease = await DurableStore(db).acquire_lease("forks", ttl=120)
    project = CreationProject(
        template=creator.policies.template.creation,
        owner_epoch=env["epoch"],
        contract_sha256=t.profile.sha256,
        policy_template_sha256=creator.policies.template.checksum(),
    )
    journal = SessionCreationJournal(
        bindings, source, ConsumerFence("forks", lease), {REF.project_id: project}
    )
    async with db.sessions.begin() as session:
        origin = Binding(
            realm_id="realm",
            channel_id=10,
            topic=TOPIC,
            anchor_message_id=50,
            **REF.model_dump(exclude={"upstream_session_id", "project_id"}),
            project_id=REF.project_id,
            session_id=REF.upstream_session_id,
            title="Original native title",
            owner_id=7,
            locale=locale,
            state="active",
            audience_revision=audience.revision,
            audience_user_ids=[7, 8],
            observed_cursor="",
            topic_key=topic_key("realm", 10, TOPIC),
            session_key=digest({"realm": "realm", "session": REF.upstream_session_id}),
        )
        session.add(origin)
    fork_id, sources = await add_fork_action(
        db,
        origin,
        creator.registry.contract_for(REF),
        locale=locale,
        before=before,
        state=fork_state,
    )
    for item in sources:
        source.messages[item.message_id] = item
    replies = RoutedOutbox(
        Outbox(bindings, 9, fence=journal.fence),
        realm_id="realm",
        message_limit=10000,
        topic_limit=60,
    )
    factory = fork_factory(creator)
    service = SessionForkRegistration(
        journal, {REF.project_id: factory}, replies, realm_url="https://chat.invalid"
    )
    env.update(
        p=p,
        t=t,
        d=d,
        state=state,
        calls=calls,
        writes=writes,
        anchor=anchor,
        creator=creator,
        factory=factory,
        journal=journal,
        bindings=bindings,
        audience=audience,
        source=source,
        origin=origin,
        fork_id=fork_id,
        replies=replies,
        service=service,
    )
    return env


async def cleanup(env):
    await finish(env["p"], env["t"])


async def reserved(env):
    identity = await env["service"].reserve(env["fork_id"])
    action, binding = await env["service"].load(identity)
    return identity, action, binding


async def opened(env, text="Now try the other approach", message_id=200, **changes):
    actions = await rows(env["journal"].db, Action)
    action = next(a for a in actions if a.operation == FORK_REGISTRATION)
    item = message(text, message_id, topic=action.payload["topic"], **changes)
    env["source"].messages[message_id] = item
    return item, await env["service"].opened(item, "en")


async def bound(env, text="Now try the other approach"):
    identity, _, _ = await reserved(env)
    item, _ = await opened(env, text)
    binding = await env["service"].reconcile(identity)
    return identity, item, binding


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_confirmed_fork_gets_its_own_topic_root_and_first_prompt(db, locale):
    e = await setup(db, locale=locale)
    try:
        identity, action, binding = await reserved(e)
        assert action.operation == FORK_REGISTRATION and action.state == "admitted"
        assert binding.state == "creating" and binding.session_id == FORK_ID
        assert binding.channel_id == e["origin"].channel_id and binding.topic != TOPIC
        assert (
            len(binding.topic) <= 60 and ("分支" if locale == "zh-TW" else "fork") in binding.topic
        )
        link = (await rows(db, Delivery))[0]
        assert link.binding_id == e["origin"].id and link.payload["topic"] == TOPIC
        content = unescape(link.payload["content"])
        assert FORK_ID in content and binding.topic in content
        assert "https://chat.invalid/#narrow/channel/10/topic/" + topic_hash(binding.topic) in (
            content
        )
        assert FORK_ID not in e["factory"].registry.sessions.keys().__repr__()
        item, (status, project) = await opened(e)
        assert project == REF.project_id and status
        result = await e["service"].reconcile(identity)
        assert result.state == "active" and result.revision == 1
        action, binding = await e["service"].load(identity)
        assert action.state == "completed" and binding.observed_cursor
        fork_ref = next(
            r for r in e["factory"].registry.sessions if r.upstream_session_id == FORK_ID
        )
        assert e["factory"].registry.sessions[REF] is e["anchor"]
        enrollment = e["factory"].registry.sessions[fork_ref].execution.scope_guard.enrollments
        source = e["anchor"].execution.scope_guard.enrollments[REF]
        assert enrollment[fork_ref].operations <= source.operations
        assert (await e["factory"].registry.snapshot(fork_ref)).state == ExecutionState.IDLE
        prompts = [a for a in await rows(db, Action) if a.operation == "prompt"]
        assert len(prompts) == 1 and prompts[0].binding_id == binding.id
        assert prompts[0].payload["text"] == item.text
        notices = [d for d in await rows(db, Delivery) if d.binding_id == binding.id]
        assert len(notices) == 1 and FORK_ID in unescape(notices[0].payload["content"])
        origin = await e["bindings"].get(e["origin"].id, "realm", 7)
        assert (origin.revision, origin.session_id, origin.topic) == (
            1,
            REF.upstream_session_id,
            TOPIC,
        )
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
        events = {r.event for r in await rows(db, AuditEvent)}
        assert {"session_fork_topic_reserved", "session_fork_topic_opened"} <= events
        assert "session_fork_topic_bound" in events
    finally:
        await cleanup(e)


async def test_native_fork_has_no_parent_and_its_event_never_reaches_the_source_topic():
    # Native 2.0.32 itself: a fork is a new top-level session that records its source.
    projector = (NATIVE / "packages_core_src_session_projector.ts").read_text()
    assert "parent_id: null," in projector and "fork_session_id: event.data.parentID," in projector
    assert "permission: parent.permission," in projector
    bus = (NATIVE / "packages_core_src_bus.ts").read_text()
    assert 'event.type === "session.forked" ? event.data.parentID : id' in bus
    p, t, *_ = await factory_setup()
    try:
        before = p.feed.index.revision_for(REF)
        raw = {
            "id": "evt_fork",
            "type": "session.forked",
            "data": {"sessionID": FORK_ID, "parentID": REF.upstream_session_id},
            "durable": {"aggregateID": FORK_ID, "seq": 1, "version": 2},
            "location": {"directory": REF.canonical_directory},
        }
        assert p.feed.index._scope(raw) is None
        p.feed.index._notice_arrival(raw)
        # Not the source's own event: its mirror and fences are unchanged and the feed stays live.
        assert p.feed.index.revision_for(REF) == before and not p.feed.index.closed
    finally:
        await finish(p, t)


async def test_duplicate_processing_reserves_one_topic_and_one_link(db):
    e = await setup(db)
    try:
        first, second = await asyncio.gather(
            e["service"].reserve(e["fork_id"]), e["service"].reserve(e["fork_id"])
        )
        assert first == second
        await e["service"].once()
        await e["service"].once()
        assert len([a for a in await rows(db, Action) if a.operation == FORK_REGISTRATION]) == 1
        assert len(await rows(db, Binding)) == 2 and len(await rows(db, DeliveryBatch)) == 1
        item, _ = await opened(e)
        assert await e["service"].opened(item, "en") is not None
        await e["service"].once()
        await e["service"].once()
        assert len([a for a in await rows(db, Action) if a.operation == "prompt"]) == 1
        assert len(await rows(db, DeliveryBatch)) == 2
    finally:
        await cleanup(e)


@pytest.mark.parametrize("state", ["ambiguous", "dispatching", "rejected", "queued"])
async def test_an_unconfirmed_or_unknown_fork_result_gets_no_topic(db, state):
    e = await setup(db, fork_state=state)
    try:
        assert await e["service"].unreserved() == ()
        await e["service"].once()
        with pytest.raises(ValueError):
            await e["service"].reserve(e["fork_id"])
        assert len(await rows(db, Binding)) == 1 and not await rows(db, Delivery)
    finally:
        await cleanup(e)


async def test_a_moved_source_topic_or_changed_confirm_gets_no_topic(db):
    e = await setup(db)
    try:
        confirm = e["source"].messages[102]
        e["source"].messages[102] = confirm.model_copy(update={"revision": 1})
        with pytest.raises(ValueError):
            await e["service"].reserve(e["fork_id"])
        e["source"].messages[102] = confirm
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(revision=2))
        assert await e["service"].unreserved() == ()
        assert len(await rows(db, Binding)) == 1 and not await rows(db, Delivery)
    finally:
        await cleanup(e)


@pytest.mark.parametrize("failure", ["raise", "cancel"])
async def test_crash_while_reserving_leaves_nothing_then_retry_reserves_once(
    db, monkeypatch, failure
):
    e = await setup(db)
    original = e["replies"].outbox.queue_batch_in_session
    try:

        async def fail(*args, **kwargs):
            await original(*args, **kwargs)
            if failure == "cancel":
                raise asyncio.CancelledError()
            raise RuntimeError("synthetic crash after the link was queued")

        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", fail)
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            await e["service"].reserve(e["fork_id"])
        assert len(await rows(db, Binding)) == 1 and not await rows(db, DeliveryBatch)
        assert not [a for a in await rows(db, Action) if a.operation == FORK_REGISTRATION]
        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", original)
        assert await e["service"].unreserved() == (e["fork_id"],)
        await e["service"].once()
        assert len([a for a in await rows(db, Action) if a.operation == FORK_REGISTRATION]) == 1
    finally:
        await cleanup(e)


@pytest.mark.parametrize("failure", ["raise", "cancel", "new-arrival"])
async def test_crash_between_native_readback_and_binding_rolls_back_then_restart_binds(
    db, monkeypatch, failure
):
    e = await setup(db)
    identity, _, _ = await reserved(e)
    await opened(e)
    original = e["replies"].outbox.queue_batch_in_session
    try:

        async def fail(*args, **kwargs):
            result = await original(*args, **kwargs)
            if failure == "new-arrival":
                index = e["p"].feed.index
                index._arrival_revisions[FORK_ID] = index._arrival_revisions.get(FORK_ID, 0) + 1
                return result
            if failure == "cancel":
                raise asyncio.CancelledError()
            raise RuntimeError("synthetic crash after the binding notice was queued")

        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", fail)
        with pytest.raises((ValueError, RuntimeError, asyncio.CancelledError)):
            await e["service"].reconcile(identity)
        action, binding = await e["service"].load(identity)
        assert action.state == "admitted" and binding.state == "creating"
        assert "activation" not in action.native_result
        assert not [a for a in await rows(db, Action) if a.operation == "prompt"]
        assert len(await rows(db, DeliveryBatch)) == 1  # Only the original topic's link.
        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", original)
        # A restart: fresh registry, factory and coordinator; the fork is never created again.
        registry = SessionRegistry({REF: e["anchor"]})
        e["bindings"].control = registry
        restarted = SessionForkRegistration(
            e["journal"],
            {REF.project_id: fork_factory(e["creator"], registry)},
            e["replies"],
        )
        await restarted.once()
        action, binding = await restarted.load(identity)
        assert action.state == "completed" and binding.state == "active"
        assert len([a for a in await rows(db, Action) if a.operation == "prompt"]) == 1
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
    finally:
        await cleanup(e)


@pytest.mark.parametrize("when", ["before", "during"])
async def test_revoked_audience_during_registration_never_binds_or_posts(db, when):
    e = await setup(db)
    identity, _, _ = await reserved(e)
    await opened(e)
    try:
        if when == "before":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        else:

            def revoke(request):
                if request.url.path == "/api/session/" + FORK_ID:
                    e["audience"].users = frozenset({7})

            e["state"]["on_get"] = revoke
        with pytest.raises((AccessDenied, Conflict)):
            await e["service"].reconcile(identity)
        action, binding = await e["service"].load(identity)
        assert action.state == "admitted" and binding.state == "creating"
        assert len(await rows(db, DeliveryBatch)) == 1
        assert not [a for a in await rows(db, Action) if a.operation == "prompt"]
        await e["service"].once()  # Held with a fixed code; retried later, GET-only.
        assert (await e["service"].load(identity))[0].state == "admitted"
        assert await e["service"].opened_ids() == ()
        assert not e["writes"]
    finally:
        await cleanup(e)


async def test_a_message_older_than_the_fork_cannot_open_its_topic(db):
    e = await setup(db)
    try:
        await reserved(e)
        with pytest.raises(Conflict):
            await opened(e, message_id=99)
        action = [a for a in await rows(db, Action) if a.operation == FORK_REGISTRATION][0]
        assert "opening" not in action.native_result
    finally:
        await cleanup(e)


async def test_a_wider_audience_cannot_open_the_reserved_topic(db):
    e = await setup(db)
    try:
        await reserved(e)
        e["audience"].users = frozenset({7, 8, 9})
        with pytest.raises(AccessDenied):
            await opened(e)
        action = [a for a in await rows(db, Action) if a.operation == FORK_REGISTRATION][0]
        assert "opening" not in action.native_result
    finally:
        await cleanup(e)


@pytest.mark.parametrize(
    "fault",
    ["parent", "source", "boundary", "broader", "agent", "archived", "project", "location"],
)
async def test_an_unexpected_native_fork_never_binds(db, fault):
    changes = {
        "parent": {"parentID": REF.upstream_session_id},
        "source": {
            "fork": {
                "sessionID": "ses_other",
                "boundary": {"type": "through", "messageID": "msg_idle"},
            }
        },
        "boundary": {
            "fork": {
                "sessionID": REF.upstream_session_id,
                "boundary": {"type": "before", "messageID": "msg_other"},
            }
        },
        "broader": {"permissions": [{"action": "*", "resource": "*", "effect": "allow"}]},
        "agent": {"agent": "plan"},
        "archived": {"time": {"created": 100, "updated": 100, "archived": 101}},
        "project": {"projectID": "other-project"},
        "location": {"location": {"directory": "/elsewhere"}},
    }[fault]
    e = await setup(db, before="msg_idle" if fault == "boundary" else None, **changes)
    try:
        identity, _, _ = await reserved(e)
        await opened(e)
        with pytest.raises(ValueError):
            await e["service"].reconcile(identity)
        action, binding = await e["service"].load(identity)
        assert action.state == "admitted" and binding.state == "creating"
        assert not any(r.upstream_session_id == FORK_ID for r in e["factory"].registry.sessions)
        assert len(await rows(db, DeliveryBatch)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


async def test_a_chosen_boundary_must_be_the_one_native_copied(db):
    e = await setup(
        db,
        before="msg_idle",
        fork={
            "sessionID": REF.upstream_session_id,
            "boundary": {"type": "before", "messageID": "msg_idle"},
        },
    )
    try:
        identity, item, binding = await bound(e)
        assert binding.state == "active"
        intent = ForkedRootIntent.model_validate(
            (await e["service"].load(identity))[0].payload["intent"]
        )
        assert intent.before == "msg_idle"
    finally:
        await cleanup(e)


async def test_restart_restores_the_bound_fork_from_its_sealed_receipt_get_only(db):
    e = await setup(db)
    try:
        identity, _, _ = await bound(e)
        before = [r.payload_hash for r in await rows(db, Delivery)]
        e["state"]["info"].update(title="Used after the fork", cost=1.0)
        registry = SessionRegistry({REF: e["anchor"]})
        e["bindings"].control = registry
        factory = fork_factory(e["creator"], registry)
        restarted = SessionForkRegistration(e["journal"], {REF.project_id: factory}, e["replies"])
        assert await restarted.restore_active() == (identity,)
        fork_ref = next(r for r in registry.sessions if r.upstream_session_id == FORK_ID)
        assert (await registry.snapshot(fork_ref)).title == "Used after the fork"
        assert [r.payload_hash for r in await rows(db, Delivery)] == before
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
    finally:
        await cleanup(e)


async def test_restore_of_a_fork_that_no_longer_reads_back_keeps_the_bridge_running(db):
    e = await setup(db)
    try:
        await bound(e)
        e["state"]["info"]["fork"] = {
            "sessionID": "ses_other",
            "boundary": {"type": "through", "messageID": "msg_idle"},
        }
        registry = SessionRegistry({REF: e["anchor"]})
        e["bindings"].control = registry
        restarted = SessionForkRegistration(
            e["journal"], {REF.project_id: fork_factory(e["creator"], registry)}, e["replies"]
        )
        assert await restarted.restore_active() == ()
        assert set(registry.sessions) == {REF}
        await restarted.once()  # Backed off: nothing is retried immediately.
        assert set(registry.sessions) == {REF}
        # Native reads back again: a later GET-only retry registers the same fork.
        e["state"]["info"]["fork"] = {
            "sessionID": REF.upstream_session_id,
            "boundary": {"type": "through", "messageID": "msg_idle"},
        }
        restarted._retry_at.clear()
        await restarted.once()
        assert any(r.upstream_session_id == FORK_ID for r in registry.sessions)
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
    finally:
        await cleanup(e)


async def test_the_fork_observer_and_policy_never_create_or_widen(db):
    e = await setup(db)
    try:
        observer = e["factory"].creator
        intent = ForkedRootIntent(
            intent_id="e" * 32,
            scope=e["journal"].projects[REF.project_id].template.scope,
            native_session_id=FORK_ID,
            source_sha256="c" * 64,
            owner_epoch=e["journal"].projects[REF.project_id].owner_epoch,
            fork_of=REF.upstream_session_id,
            fork_action_id=str(uuid4()),
        )
        with pytest.raises(MutationNotSent):
            await observer.create(intent, before_send=lambda: None)
        with pytest.raises(ValueError):
            observer.body(intent)
        with pytest.raises(ValueError):
            await observer.observe(intent)
        with pytest.raises(ValueError):
            ForkedRootIntent.model_validate(
                {**intent.model_dump(mode="json"), "native_session_id": REF.upstream_session_id}
            )
        with pytest.raises(ValueError):
            ForkedRootIntent.model_validate({**intent.model_dump(mode="json"), "title": "Named"})
        assert not e["writes"]
    finally:
        await cleanup(e)


def test_topic_names_fit_and_links_use_zulip_hash_encoding():
    assert topic_hash("a b.(c)") == "a.20b.2E.28c.29"
    assert topic_hash("分支") == ".E5.88.86.E6.94.AF"


async def test_only_a_fork_factory_on_the_same_registry_may_register_forks(db):
    e = await setup(db)
    try:
        with pytest.raises(ValueError):
            SessionForkRegistration(e["journal"], {REF.project_id: e["creator"]}, e["replies"])
        other = fork_factory(e["creator"], SessionRegistry({REF: e["anchor"]}))
        with pytest.raises(ValueError):
            SessionForkRegistration(e["journal"], {REF.project_id: other}, e["replies"])
    finally:
        await cleanup(e)


def test_fork_topics_stay_off_unless_chat_creation_is_on():
    assert Runtime().session_fork_topics_enabled is False
    with pytest.raises(ValueError):
        Runtime(session_fork_topics_enabled=True)
