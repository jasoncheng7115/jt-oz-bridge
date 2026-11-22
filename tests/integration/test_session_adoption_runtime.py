"""Actual runtime graph with synthetic Native/HTTP and isolated ownDB only."""

import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.domain.catalog import CatalogPage, CatalogSession, ProjectScope
from jt_oz_bridge.domain.runtime_readiness import RootModeFact, scope_key
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.consumer_runtime import (
    ConsumerPipeline,
    EnrolledSessionCatalog,
    RuntimeBackend,
)
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.models import Grant
from tests.contract.test_existing_session_factory import setup as factory_setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import TARGET
from tests.contract.test_public_live_feed import REF
from tests.integration.test_consumer_runtime import WholeServer
from tests.integration.test_session_adoption import setup as adoption_setup
from tests.integration.test_zulip_consumer import URL


def runtime_child_queries(transport, tree, state):
    """Serve exact leaf admission and retain the complete paginated tree mock."""
    original = transport.client._transport
    state["runtime_child_queries"] = []

    def handle(request):
        if request.url.path != "/api/session":
            return original.handler(request)
        assert request.method == "GET"
        query = dict(request.url.params)
        assert len(request.url.params.multi_items()) == len(query)
        parent = TARGET.model_copy(update={"upstream_session_id": query["parentID"]})
        assert parent == REF or parent in tree["rows"]
        if (query["limit"], query["order"]) == ("1", "desc"):
            assert set(query) == {"parentID", "limit", "order"}
            children = sorted(
                tree["edges"].get(parent, []),
                key=lambda ref: tree["rows"][ref]["time"]["created"],
                reverse=True,
            )
            state["runtime_child_queries"].append((parent, "leaf"))
            return httpx.Response(
                200,
                json={
                    "data": [copy.deepcopy(tree["rows"][ref]) for ref in children[:1]],
                    "cursor": {"next": "leaf-next"} if len(children) > 1 else {},
                },
            )
        assert (query["limit"], query["order"]) == ("100", "asc")
        assert set(query) in (
            {"parentID", "limit", "order"},
            {"parentID", "limit", "order", "cursor"},
        )
        if "cursor" in query:
            assert query["cursor"] == "second"
            assert parent == TARGET and len(tree["edges"].get(parent, [])) == 2
        state["runtime_child_queries"].append((parent, "tree"))
        return original.handler(request)

    transport.client._transport = httpx.MockTransport(handle)


async def setup(db):
    initial, item, _, source, factory, state, writes, anchor, transport = await adoption_setup(
        db, leaf=True, routed=True
    )
    runtime_child_queries(transport, state["metadata_tree"], state)
    server = WholeServer()
    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic-key",
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
        verify_identity=AsyncMock(return_value=True),
        transport=httpx.MockTransport(server.handle),
    )
    scope = ZulipScopeReader(client, channel_ids=frozenset({10}))

    class Catalog:
        def contract_for_project(self, selected):
            return factory.policy.contract_sha256

        async def list_sessions(self, selected, *, search, cursor, limit):
            return CatalogPage(
                scope=selected,
                contract_sha256=factory.policy.contract_sha256,
                search=search,
                cursor=cursor,
                items=(CatalogSession(reference=TARGET, title="Original existing work"),),
            )

    registry = factory.registry
    backend = RuntimeBackend(
        RegisteredBackend(
            REF.backend_identity, factory.policy.contract_sha256, registry.projects, registry
        ),
        RegisteredCatalog(
            REF.backend_identity, factory.policy.contract_sha256, registry.projects, Catalog()
        ),
        registry.models,
        registry.results,
        registry.reference_snapshot(),
        registry.pending,
        AsyncMock(),
        (),
        registry.transcripts,
        registry.live_text,
        registry.metadata,
        reference_provider=registry.reference_snapshot,
        mode_snapshot=lambda: (
            RootModeFact(
                scope_key=scope_key(REF),
                mode="strict",
                reason="strict-observation",
                transition_at=1.0,
            ),
        ),
    )

    def make(bindings, reader):
        return SessionAdoptionService(
            bindings, reader, initial.journal.fence, {TARGET.project_id: factory}
        )

    pipeline = ConsumerPipeline(
        db, initial.journal.fence, scope, {REF.backend_id: backend}, adoption_factory=make
    )
    return (
        pipeline,
        server,
        factory,
        state,
        writes,
        anchor,
        transport,
        initial,
        item,
        client,
        backend,
    )


async def test_runtime_exposes_original_unregistered_metadata_then_wires_adoption_before_consumer(
    db,
):
    (
        pipeline,
        server,
        factory,
        state,
        writes,
        anchor,
        transport,
        initial,
        item,
        client,
        backend,
    ) = await setup(db)
    try:
        scope = ProjectScope(**TARGET.model_dump(exclude={"upstream_session_id"}))
        assert TARGET not in factory.registry.sessions
        filtered = EnrolledSessionCatalog(
            backend.catalog.client,
            backend.references,
            reference_provider=backend.reference_snapshot,
        )
        assert not (await filtered.list_sessions(scope, search="", cursor=None, limit=10)).items
        original_event = server.input("!projects", mid=201)
        await pipeline.journal.enroll("original-queue", -1)
        await pipeline.journal.capture("original-queue", [original_event])
        selected = await pipeline.source.read("realm", 201)
        page = await pipeline.discovery.sessions(selected, TARGET.project_id)
        assert page.items[0].selection.reference == TARGET
        assert TARGET not in factory.registry.sessions and not writes
        resources = [resource.name for resource in pipeline.runtime().resources]
        assert resources.index("original-session-restoration") < resources.index("zulip-consumer")
        assert pipeline.router.unbound.confirmations.adoption is pipeline.adoption
        assert pipeline.router.unbound.discovery is pipeline.discovery
    finally:
        await client.close()
        await finish(anchor, transport)


async def test_startup_fresh_get_recovery_restores_same_original_before_serving_without_source_replay(
    db,
):
    (
        pipeline,
        server,
        factory,
        state,
        writes,
        anchor,
        transport,
        initial,
        item,
        client,
        backend,
    ) = await setup(db)
    next_anchor = next_transport = None
    try:
        await initial.adopt(item, TARGET)
        (
            next_anchor,
            next_transport,
            fresh,
            fresh_tree,
            fresh_state,
            fresh_writes,
            _,
        ) = await factory_setup(leaf=True)
        runtime_child_queries(next_transport, fresh_tree, fresh_state)
        # Assemble a new full pipeline around the fresh original backend readers.
        fresh_registry = fresh.registry
        fresh_backend = RuntimeBackend(
            RegisteredBackend(
                REF.backend_identity,
                fresh.policy.contract_sha256,
                fresh_registry.projects,
                fresh_registry,
            ),
            backend.catalog,
            fresh_registry.models,
            fresh_registry.results,
            fresh_registry.reference_snapshot(),
            fresh_registry.pending,
            AsyncMock(),
            (),
            fresh_registry.transcripts,
            fresh_registry.live_text,
            fresh_registry.metadata,
            reference_provider=fresh_registry.reference_snapshot,
        )
        fresh_pipeline = ConsumerPipeline(
            db,
            initial.journal.fence,
            pipeline.scope,
            {REF.backend_id: fresh_backend},
            adoption_factory=lambda bindings, reader: SessionAdoptionService(
                bindings, reader, initial.journal.fence, {TARGET.project_id: fresh}
            ),
        )
        assert TARGET not in fresh.registry.sessions
        await fresh_pipeline.restore_adopted()
        assert TARGET in fresh.registry.sessions and not fresh_writes and not writes
        assert not server.posts  # Startup did not invent a Human confirmation or notice.
        assert all(request.method == "GET" for request in fresh_state["resource_calls"])
        assert (REF, "leaf") in fresh_state["runtime_child_queries"]
        assert (TARGET, "tree") in fresh_state["runtime_child_queries"]
        async with db.sessions() as session:
            assert not (await session.scalars(select(Binding))).all()
    finally:
        if next_anchor is not None:
            await finish(next_anchor, next_transport)
        await client.close()
        await finish(anchor, transport)


async def test_revoked_all_current_operators_prevents_startup_recovery(db):
    (
        pipeline,
        server,
        factory,
        state,
        writes,
        anchor,
        transport,
        initial,
        item,
        client,
        backend,
    ) = await setup(db)
    try:
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).values(active=False))
        with pytest.raises(ValueError, match="current_operator"):
            await pipeline.restore_adopted()
        assert TARGET not in factory.registry.sessions and not writes and not server.posts
    finally:
        await client.close()
        await finish(anchor, transport)


async def test_adopted_session_modes_are_diagnostic_and_do_not_change_watches_or_read_native(db):
    (
        pipeline,
        server,
        factory,
        state,
        writes,
        anchor,
        transport,
        initial,
        item,
        client,
        backend,
    ) = await setup(db)
    try:
        await initial.adopt(item, TARGET)
        before = len(state["resource_calls"]), dict(factory._registered[TARGET].proofs._watched)
        first = factory.mode_facts()
        second = factory.mode_facts()
        assert first == second and first[0].scope_key == scope_key(TARGET)
        assert first[0].mode == "strict" and first[0].authority == "diagnostic_only"
        published = pipeline.mode_facts()
        assert {fact.scope_key for fact in published} == {scope_key(REF), scope_key(TARGET)}
        assert all(fact.authority == "diagnostic_only" for fact in published)
        anchor.feed.index.owner_epoch = "f" * 64
        unavailable = factory.mode_facts()
        assert unavailable[0].mode == "unavailable"
        assert before == (
            len(state["resource_calls"]),
            dict(factory._registered[TARGET].proofs._watched),
        )
        assert not writes
    finally:
        await client.close()
        await finish(anchor, transport)


async def test_restore_error_prevents_consumer_start_and_closes_started_resources(db):
    (
        pipeline,
        server,
        factory,
        state,
        writes,
        anchor,
        transport,
        initial,
        item,
        client,
        backend,
    ) = await setup(db)
    pipeline.adoption.recover_project = AsyncMock(
        side_effect=ValueError("original identity changed")
    )
    runtime = pipeline.runtime()
    try:
        with pytest.raises(RuntimeError, match="runtime_start_failed"):
            await runtime.start()
        assert not runtime.healthy and pipeline.consumer.queue_id is None
        assert client.client.is_closed
        assert not writes and not server.posts
    finally:
        await runtime.close()
        await client.close()
        await finish(anchor, transport)


@pytest.mark.parametrize("creation_fails", [False, True])
async def test_created_root_base_restores_before_graph_recovery_or_consumer_start(
    db, creation_fails
):
    """Exercise actual resource startup/cleanup; callbacks stand in for Native."""
    pipeline, server, _, _, writes, anchor, transport, _, _, client, _ = await setup(db)
    order = []

    async def created():
        order.append("created-root-base")
        if creation_fails:
            raise ValueError("synthetic original creation restore failure")
        return ()

    async def creation_journal():
        order.append("creation-journal")

    async def graphs(*args, **kwargs):
        order.append("original-graphs")
        return ()

    async def consumer():
        order.append("consumer")
        raise ValueError("synthetic stop before workers start")

    pipeline.creation = SimpleNamespace(restore_active=created, unrestored_roots=frozenset)
    pipeline.creation_commands = SimpleNamespace(recover=creation_journal)
    pipeline.adoption.recover_project = graphs
    pipeline.start_consumer = consumer
    runtime = pipeline.runtime()
    try:
        with pytest.raises(RuntimeError, match="runtime_start_failed"):
            await runtime.start()
        assert order == (
            ["created-root-base"]
            if creation_fails
            else ["created-root-base", "creation-journal", "original-graphs", "consumer"]
        )
        assert not runtime.healthy and pipeline.consumer.queue_id is None
        assert client.client.is_closed and not writes and not server.posts
    finally:
        await runtime.close()
        await client.close()
        await finish(anchor, transport)
