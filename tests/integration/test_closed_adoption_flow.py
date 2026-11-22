"""Synthetic HTTP/ownDB composition, never live Human or mobile acceptance.

The real Source observer, Bot identity guard, Native adapters, graph journal,
TokenPlan and outbox remain in the path. Neither peer creates a Native session.
"""

import asyncio
import copy
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject, V2SessionCatalog
from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline, RuntimeBackend
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant, WorkerLease
from jt_oz_bridge.storage.session_registration_models import (
    SessionRegistration,
    SessionRegistrationExtension,
)
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import CHILD, TARGET
from tests.integration.test_consumer_runtime import WholeServer, rows, visible
from tests.integration.test_session_adoption import setup as adoption_setup
from tests.integration.test_zulip_consumer import URL


@asynccontextmanager
async def original_menu(db):
    """One original factory and original Native transport, with two HTTP peers."""
    controller, _, _, _, factory, state, writes, anchor, native = await adoption_setup(db)
    tree = state["metadata_tree"]
    saved = copy.deepcopy((tree["rows"], tree["edges"], state["resources"]))
    for ref in tuple(tree["rows"]):
        if ref != TARGET:
            del tree["rows"][ref]
            del state["resources"][ref]
    tree["edges"].clear()
    delegate = native.client._transport

    def native_peer(request):
        if request.url.path == "/api/session":
            parent = request.url.params.get("parentID")
            if parent == "null":
                assert request.method == "GET"
                state["resource_calls"].append(request)
                return httpx.Response(
                    200, json={"data": [copy.deepcopy(tree["rows"][TARGET])], "cursor": {}}
                )
            if request.url.params.get("limit") == "1":
                ref = TARGET.model_copy(update={"upstream_session_id": parent})
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            copy.deepcopy(tree["rows"][child])
                            for child in tree["edges"].get(ref, [])[:1]
                        ],
                        "cursor": {},
                    },
                )
        return delegate.handler(request)

    native.client._transport = httpx.MockTransport(native_peer)
    server = WholeServer()
    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic-only-key",
        attestation=ZulipAttestation(
            URL,
            "realm",
            11,
            500,
            10000,
            60,
            verified_scope_operations=SCOPE_OPERATIONS,
            verified_event_operations=EVENT_OPERATIONS | {"cleanup"},
        ),
        transport=httpx.MockTransport(server.handle),
    )
    client.budget = ZulipRequestBudget(requests=10000)

    def zulip_peer(request):
        path = request.url.path.removeprefix("/api/v1/")
        if path == "users/me":
            data = {
                "user_id": 11,
                "is_bot": True,
                "is_active": True,
                "bot_owner_id": 7,
                "role": 400,
            }
        elif path == "server_settings":
            data = {"realm_url": client.url, "zulip_version": "12.3", "zulip_feature_level": 500}
        else:
            return server.handle(request)
        return httpx.Response(200, json={"result": "success", **data})

    client.client._transport = httpx.MockTransport(zulip_peer)
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=7, url=URL, zulip_version="12.3", feature_level=500
        ),
    )
    registry = factory.registry
    project = ProjectScope.model_validate(TARGET.model_dump(exclude={"upstream_session_id"}))
    catalog = V2SessionCatalog(
        native,
        {TARGET.project_id: V2CatalogProject(project, tree["rows"][TARGET]["projectID"])},
        root_projects=frozenset({TARGET.project_id}),
    )
    contract = factory.policy.contract_sha256
    backend = RuntimeBackend(
        RegisteredBackend(TARGET.backend_identity, contract, registry.projects, registry),
        RegisteredCatalog(TARGET.backend_identity, contract, registry.projects, catalog),
        registry.models,
        registry.results,
        registry.reference_snapshot(),
        registry.pending,
        _pulse,
        (),
        transcripts=registry.transcripts,
        metadata=registry.metadata,
        live_text=registry.live_text,
        reference_provider=registry.reference_snapshot,
    )

    def adopter(bindings, source):
        return SessionAdoptionService(
            bindings, source, controller.journal.fence, {TARGET.project_id: factory}
        )

    pipeline = ConsumerPipeline(
        db,
        controller.journal.fence,
        ZulipScopeReader(client, channel_ids=frozenset({10})),
        {TARGET.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
        adoption_factory=adopter,
    )
    env = SimpleNamespace(
        db=db,
        pipeline=pipeline,
        factory=factory,
        registry=registry,
        server=server,
        client=client,
        native=native,
        state=state,
        tree=tree,
        saved=saved,
        writes=writes,
    )
    try:
        await pipeline.consumer.start()
        yield env
    finally:
        await client.close()
        await finish(anchor, native)


async def _pulse():
    return None


async def command(env, text, *, topic="Synthetic original adoption", author=7, deliver=True):
    mid = max(env.server.messages) + 1
    env.server.input(text, mid, author=author, topic=topic)
    env.server.next_mid = mid + 1
    statuses = await env.pipeline.consumer.poll()
    if deliver:
        await env.pipeline.deliver_once()
    return mid, statuses


async def menu_to(env, count=4, *, topic="Synthetic original adoption"):
    expected = (
        ("!projects", "Choose a project"),
        ("!1", "Choose a conversation"),
        ("!1", "Connect this conversation"),
        ("!confirm", "Connected."),
    )
    mids = []
    for text, fragment in expected[:count]:
        before = len(env.server.posts)
        mid, statuses = await command(env, text, topic=topic)
        assert "reply" in statuses and not {"held", "ambiguous", "deferred"} & set(statuses), (
            text,
            statuses,
            len(env.server.posts),
            env.client.budget.deferred,
        )
        assert len(env.server.posts) == before + 1
        post = env.server.posts[-1]
        assert post["id"] > mid and post["subject"] == topic
        assert fragment in visible(post["content"])
        mids.append(mid)
    return mids


async def registration_projection(env):
    return [
        (r.key, r.payload_hash, r.identity_hash, r.revision, r.state, r.extension_count)
        for r in await rows(env.db, SessionRegistration)
    ]


@pytest.mark.parametrize("running", [False, True])
async def test_unregistered_root_four_short_controls_commit_original_binding_and_complete_ack(
    db, running
):
    async with original_menu(db) as env:
        # This one complete flow retains the deployed quota. Multi-flow fault
        # fixtures above use the existing synthetic 10000-request attestation;
        # they prove authority/atomicity, not a second rate-window certificate.
        env.client.budget = ZulipRequestBudget()
        original = dict(env.registry.sessions)
        assert TARGET not in original
        if running:
            env.state["active"][TARGET.upstream_session_id] = {"type": "running"}
        mids = await menu_to(env)
        binding = (await rows(db, Binding))[0]
        assert (binding.session_id, binding.backend_identity, binding.canonical_directory) == (
            TARGET.upstream_session_id,
            TARGET.backend_identity,
            TARGET.canonical_directory,
        )
        assert binding.owner_id == 7 and binding.audience_user_ids == [7, 8]
        assert all(env.registry.sessions[ref] is entry for ref, entry in original.items())
        entry = env.registry.selected(TARGET)
        assert entry.reference == TARGET and entry.execution.transport is env.native
        receipts = await rows(db, CommandReceipt)
        assert {r.message_id for r in receipts} == set(mids)
        assert all(r.state == "completed" for r in receipts)
        assert len(await rows(db, DeliveryBatch)) == len(env.server.posts) == 4
        confirmation = next(r for r in receipts if r.message_id == mids[-1])
        response = confirmation.response
        assert response["confirmed_reference"] == TARGET.model_dump(mode="json")
        assert response["confirmed_title"] == binding.title
        assert response["confirmation_source"]["message_id"] == mids[-1]
        final_batch = next(
            r for r in await rows(db, DeliveryBatch) if r.id == response["queued_batch_id"]
        )
        assert (final_batch.binding_id, final_batch.binding_revision) == (binding.id, 1)
        assert response["binding_id"] == binding.id and response["binding_revision"] == 1
        assert all(r.state == "delivered" for r in await rows(db, Delivery))
        assert (await rows(db, SessionRegistration))[0].state == "active"
        assert env.client.budget.deferred == 0
        assert (env.client.budget.limit, env.client.budget.window, env.client.budget.reserved) == (
            180,
            60,
            64,
        )
        assert not env.writes and not await rows(db, Action)
        assert all(request.method == "GET" for request in env.state["resource_calls"])


async def test_registered_no_growth_keeps_original_facades_and_journal_head(db):
    async with original_menu(db) as env:
        await menu_to(env, 3, topic="First genuine synthetic Source")
        before = env.registry.selected(TARGET)
        head = await registration_projection(env)
        await menu_to(env, topic="Second genuine synthetic Source")
        assert env.registry.selected(TARGET) is before
        assert env.registry.selected(TARGET).execution.proofs is before.execution.proofs
        assert await registration_projection(env) == head
        assert not await rows(db, SessionRegistrationExtension)
        assert not env.writes and not await rows(db, Action)


@pytest.mark.parametrize("running", [False, True])
async def test_registered_growth_extends_original_graph_and_cas_history_without_replacing_parent(
    db, running
):
    async with original_menu(db) as env:
        await menu_to(env, 3, topic="Original graph before child")
        before = env.registry.selected(TARGET)
        proofs = before.execution.proofs
        generation = env.registry.publication.generation(TARGET)
        original_policy = before.execution.scope_guard.enrollments[TARGET]
        previous = (await rows(db, SessionRegistration))[0]
        original_node = next(
            node
            for node in previous.payload["nodes"]
            if node["reference"] == TARGET.model_dump(mode="json")
        )
        saved_rows, _, saved_resources = env.saved
        env.tree["rows"][CHILD] = copy.deepcopy(saved_rows[CHILD])
        env.tree["edges"][TARGET] = [CHILD]
        env.state["resources"][CHILD] = copy.deepcopy(saved_resources[CHILD])
        if running:
            env.state["active"][CHILD.upstream_session_id] = {"type": "running"}
        await menu_to(env, topic="Original graph after child")
        assert env.registry.selected(TARGET) is before and before.execution.proofs is proofs
        assert env.registry.publication.generation(TARGET) is not generation
        assert before.execution.scope_guard.enrollments[TARGET] is original_policy
        assert env.registry.selected(CHILD).reference == CHILD
        snapshot = await env.registry.snapshot(TARGET)
        assert snapshot.descendants == (CHILD,)
        history = await rows(db, SessionRegistrationExtension)
        assert len(history) == 1 and history[0].added_count == 1
        head = (await rows(db, SessionRegistration))[0]
        assert head.extension_count == 1
        assert history[0].predecessor_revision == previous.revision
        assert history[0].successor_revision == previous.revision + 1
        assert history[0].predecessor_identity_hash == previous.identity_hash
        assert history[0].successor_identity_hash == head.identity_hash
        assert (
            next(
                node
                for node in head.payload["nodes"]
                if node["reference"] == TARGET.model_dump(mode="json")
            )
            == original_node
        )
        child_node = next(
            node
            for node in head.payload["nodes"]
            if node["reference"] == CHILD.model_dump(mode="json")
        )
        assert child_node["parent_reference"] == TARGET.model_dump(mode="json")
        assert child_node["parent_created_at"] == original_node["native_created_at"]
        assert not env.writes and not await rows(db, Action)


@pytest.mark.parametrize("fault", ["missing", "created", "qualification", "actor"])
async def test_delivered_menu_token_is_not_original_selection_or_another_actors_authority(
    db, fault
):
    async with original_menu(db) as env:
        await menu_to(env, 2)
        if fault != "actor":
            async with db.sessions.begin() as session:
                tokens = list(await session.scalars(select(ControlToken)))
                selected = [
                    token
                    for token in tokens
                    if token.kind == "discover-menu"
                    and token.context.get("data", {}).get("items", [{}])[0].get("kind") == "session"
                ]
                assert len(selected) == 1
                token = selected[0]
                context = copy.deepcopy(token.context)
                item = context["data"]["items"][0]
                assert "selection" in item
                if fault == "missing":
                    del item["selection"]
                elif fault == "created":
                    item["selection"]["native_created_at"] += 1
                else:
                    item["selection"]["qualification_sha256"] = "0" * 64
                token.context, token.context_hash = context, digest(context)
        before = len(env.server.posts)
        native_calls = len(env.state["resource_calls"])
        _, statuses = await command(env, "!1", author=8 if fault == "actor" else 7)
        if fault == "actor":
            # A safe static error is permitted; another Human's delivered menu
            # must not become this actor's Native selection or write authority.
            assert "deferred" not in statuses
            assert len(env.server.posts) == before + 1
            assert "Connect this conversation" not in visible(env.server.posts[-1]["content"])
            assert len(env.state["resource_calls"]) == native_calls
        else:
            assert "held" in statuses and not {"reply", "deferred"} & set(statuses)
            assert len(env.server.posts) == before
        assert TARGET not in env.registry.sessions
        assert not await rows(db, Binding)
        assert not await rows(db, SessionRegistration) and not env.writes


@pytest.mark.parametrize(
    "fault", ["source", "prior_source", "audience", "native_created", "native_owner"]
)
async def test_actual_native_get_cannot_outlive_original_source_audience_or_identity(db, fault):
    async with original_menu(db) as env:
        mids = await menu_to(env, 2)
        fired = False

        def change_during_native_get(request, _state):
            nonlocal fired
            if fired or request.url.path != "/api/session/" + TARGET.upstream_session_id:
                return None
            fired = True
            if fault in {"source", "prior_source"}:
                mid = max(env.server.messages) if fault == "source" else mids[-1]
                # The current actor has just been read, but its original HTTP
                # body must be read again after the actual Native phase.
                env.server.messages[mid]["content"] += " edited during Native GET"
            elif fault == "audience":
                env.server.private = False
            elif fault == "native_created":
                env.tree["rows"][TARGET]["time"]["created"] += 1
            else:
                read_owner = env.factory._feed.owner.read.side_effect

                def wrong_owner():
                    owner = read_owner()
                    owner.owner_epoch = "f" * 64
                    return owner

                env.factory._feed.owner.read.side_effect = wrong_owner
            return None

        env.state["hook"] = change_during_native_get
        before = len(env.server.posts)
        _, statuses = await command(env, "!1")
        assert fired and "held" in statuses and "deferred" not in statuses
        assert TARGET not in env.registry.sessions
        assert len(env.server.posts) == before and not await rows(db, Binding)
        assert not await rows(db, SessionRegistration) and not env.writes


@pytest.mark.parametrize("fault", ["grant", "fence", "cancel", "rate_after_commit"])
async def test_real_prepared_journal_then_revocation_or_cancel_never_defers_or_publishes(db, fault):
    async with original_menu(db) as env:
        await menu_to(env, 2)
        journal = env.pipeline.adoption.journal
        prepare = journal.prepare
        committed = []

        async def after_real_commit(*args, **kwargs):
            receipt = await prepare(*args, **kwargs)
            committed.append(receipt)
            if fault == "cancel":
                raise asyncio.CancelledError()
            if fault == "rate_after_commit":
                raise DeliveryRateLimited(60)
            async with db.sessions.begin() as session:
                if fault == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 7).values(active=False)
                    )
                else:
                    await session.execute(
                        update(WorkerLease).values(fencing=WorkerLease.fencing + 1)
                    )
            return receipt

        journal.prepare = after_real_commit
        if fault == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await command(env, "!1", deliver=False)
        elif fault == "fence":
            # This worker cannot persist even a held receipt under the new
            # owner's fence; the supervisor must receive the typed failure.
            with pytest.raises(Conflict, match="consumer_lease_unavailable"):
                await command(env, "!1", deliver=False)
        else:
            _, statuses = await command(env, "!1", deliver=False)
            assert "held" in statuses and "deferred" not in statuses
        assert len(committed) == 1
        assert TARGET not in env.registry.sessions and not await rows(db, Binding)
        assert len(env.server.posts) == 2 and len(await rows(db, DeliveryBatch)) == 2
        assert [r.state for r in await rows(db, SessionRegistration)] == ["prepared"]
        receipts = await rows(db, CommandReceipt)
        assert not any(r.state == "deferred" for r in receipts)
        if fault in {"cancel", "rate_after_commit"}:
            statuses = await env.pipeline.consumer.poll()
            assert "deferred" not in statuses and len(committed) == 1
            assert len(env.server.posts) == 2 and TARGET not in env.registry.sessions
        assert not env.writes and not await rows(db, Action)


@pytest.mark.parametrize("fault", ["operate", "viewer", "fence"])
async def test_confirm_binding_ack_and_tokens_roll_back_after_late_sql_revocation(db, fault):
    async with original_menu(db) as env:
        await menu_to(env, 3)
        original = env.registry.selected(TARGET)
        before = sorted((r.token_hash, r.used) for r in await rows(db, ControlToken))
        outbox = env.pipeline.discovery_outbox
        queue = outbox.queue_batch_in_session
        reached = False

        async def revoke_in_transaction(session, *args, **kwargs):
            nonlocal reached
            result = await queue(session, *args, **kwargs)
            reached = True
            if fault == "fence":
                await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
            else:
                await session.execute(
                    update(Grant)
                    .where(Grant.user_id == (7 if fault == "operate" else 8))
                    .values(active=False)
                )
            return result

        outbox.queue_batch_in_session = revoke_in_transaction
        _, statuses = await command(env, "!confirm", deliver=False)
        assert reached and "held" in statuses and "deferred" not in statuses
        assert not await rows(db, Binding) and env.registry.selected(TARGET) is original
        assert before == sorted((r.token_hash, r.used) for r in await rows(db, ControlToken))
        assert len(await rows(db, DeliveryBatch)) == 3 and len(env.server.posts) == 3
        assert not env.writes and not await rows(db, Action)


async def test_completed_original_confirmation_replay_keeps_one_binding_and_one_ack_batch(db):
    async with original_menu(db) as env:
        mids = await menu_to(env)
        before = await registration_projection(env)
        source = await env.pipeline.source.read("realm", mids[-1])
        result = await env.pipeline.router.route(source)
        assert result.state == "reply" and result.delivery_key is not None
        await env.pipeline.consumer.publish(result)
        assert len(await rows(db, Binding)) == 1 and len(await rows(db, DeliveryBatch)) == 4
        assert len(await rows(db, CommandReceipt)) == 4
        assert await registration_projection(env) == before
        await env.pipeline.deliver_once()
        assert len(env.server.posts) == 4 and not env.writes and not await rows(db, Action)
