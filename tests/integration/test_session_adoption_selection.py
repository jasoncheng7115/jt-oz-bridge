"""Original selection to Binding with real ownDB/adapters and synthetic peers."""

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.orm import Session

from jt_oz_bridge.domain.catalog import CatalogPage, CatalogSession
from jt_oz_bridge.domain.session_adoption import ExistingSessionSelection
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.discovery import DiscoveryService, RegisteredCatalog
from jt_oz_bridge.services.discovery_delivery import DiscoveryDeliveryWorker
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox, DiscoveryReplyPublisher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.reply_publisher import ReplyPublisher
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant
from jt_oz_bridge.storage.session_registration_models import SessionRegistration
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import TARGET
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_discovery_shortcuts import show
from tests.integration.test_router import count, message, send
from tests.integration.test_session_adoption import setup as adoption_setup


async def setup(db, *, running=False, leaf=True):
    adopter, _, audience, source, factory, state, writes, anchor, transport = await adoption_setup(
        db, leaf=leaf, routed=True
    )
    if running:
        state["active"][TARGET.upstream_session_id] = {"type": "running"}

    class Catalog:
        def contract_for_project(self, scope):
            return factory.policy.contract_sha256

        async def list_sessions(self, scope, *, search, cursor, limit):
            return CatalogPage(
                scope=scope,
                contract_sha256=factory.policy.contract_sha256,
                search=search,
                cursor=cursor,
                items=(CatalogSession(reference=TARGET, title="Original existing work"),),
            )

    discovery = DiscoveryService(
        adopter.bindings,
        {
            TARGET.backend_id: RegisteredCatalog(
                TARGET.backend_identity,
                factory.policy.contract_sha256,
                factory.registry.projects,
                Catalog(),
            )
        },
        adoption=adopter,
    )
    inbox = CommandInbox(db, adopter.journal.fence.holder, adopter.journal.fence.fencing)
    router = CommandRouter(
        adopter.bindings,
        source,
        inbox,
        discovery=discovery,
        capabilities=adopter.bindings.control.capabilities,
    )
    bound, scoped = (
        Outbox(adopter.bindings, 77, fence=inbox.fence),
        DiscoveryOutbox(router.unbound.destinations, 77),
    )
    publisher = ReplyPublisher(
        RoutedOutbox(bound, realm_id="realm", message_limit=4000, topic_limit=60),
        DiscoveryReplyPublisher(scoped, realm_id="realm", message_limit=4000, topic_limit=60),
    )
    chat = SyntheticChat()
    workers = (
        DeliveryWorker(bound, chat, inbox.holder, inbox.fencing, minimum_interval=0),
        DiscoveryDeliveryWorker(scoped, chat, inbox.holder, inbox.fencing, minimum_interval=0),
    )
    return (
        router,
        source,
        publisher,
        chat,
        workers,
        adopter,
        factory,
        state,
        writes,
        anchor,
        transport,
    )


async def menu(env):
    router, source, publisher, chat, workers, *_ = env
    project = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, project)
    sessions = await send(router, source, message("!1", 2001))
    assert "Choose a conversation" in sessions.text
    await show(source, publisher, chat, workers, sessions)
    return sessions


@pytest.mark.parametrize("running", [False, True])
@pytest.mark.parametrize("leaf", [False, True])
async def test_short_menu_preserves_original_identity_then_confirms_same_session_without_native_input(
    db, running, leaf
):
    env = await setup(db, running=running, leaf=leaf)
    router, source, publisher, chat, workers, adopter, factory, state, writes, anchor, t = env
    try:
        original = dict(factory.registry.sessions)
        await menu(env)
        assert TARGET not in factory.registry.sessions
        assert await count(db, SessionRegistration) == 0
        preview = await send(router, source, message("!1", 2002))
        assert "Connect this conversation" in preview.text, preview.text
        assert await count(db, Binding) == 0 and await count(db, Action) == 0
        async with db.sessions() as session:
            token = await session.scalar(
                select(ControlToken).where(ControlToken.kind == "binding-confirm")
            )
            choice = ExistingSessionSelection.model_validate(token.context["selection"])
            assert choice.reference == TARGET
            assert choice.qualification_sha256 == factory.qualification_sha256()
        await show(source, publisher, chat, workers, preview)
        connected = await send(router, source, message("!confirm", 2003))
        assert connected.binding_id and "Connected." in connected.text, connected.text
        assert await router.route(source.messages[2003]) == connected
        assert await count(db, Binding) == 1 and await count(db, Action) == 0
        async with db.sessions() as session:
            binding = await session.get(Binding, connected.binding_id)
            assert binding.session_id == TARGET.upstream_session_id
            assert binding.canonical_directory == TARGET.canonical_directory
        assert all(factory.registry.sessions[ref] is entry for ref, entry in original.items())
        assert not writes and all(request.method == "GET" for request in state["resource_calls"])
        queued = await send(router, source, message("continue the same original work", 2004))
        assert queued.action_id and await count(db, Action) == 1 and not writes
        async with db.sessions() as session:
            action = await session.get(Action, queued.action_id)
            assert action.binding_id == connected.binding_id and action.state == "queued"
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("when", ["menu", "preview"])
async def test_native_id_recreated_between_menu_preview_or_confirm_never_binds_replacement(
    db, when
):
    env = await setup(db)
    router, source, publisher, chat, workers, adopter, factory, state, writes, anchor, t = env
    try:
        await menu(env)
        if when == "preview":
            preview = await send(router, source, message("!1", 2002))
            assert "Connect this conversation" in preview.text
            await show(source, publisher, chat, workers, preview)
        # The actual synthetic Native session.get, not the menu DTO, changes.
        old = t.client._transport
        import copy

        import httpx

        def replaced(request):
            response = old.handler(request)
            if request.url.path == "/api/session/" + TARGET.upstream_session_id:
                body = copy.deepcopy(response.json())
                body["data"]["time"]["created"] += 1
                return httpx.Response(200, json=body)
            return response

        t.client._transport = httpx.MockTransport(replaced)
        denied = await send(router, source, message("!1" if when == "menu" else "!confirm", 2003))
        assert not denied.binding_id and not denied.action_id
        assert await count(db, Binding) == await count(db, Action) == 0 and not writes
        if when == "menu":
            assert (
                TARGET not in factory.registry.sessions
                and await count(db, SessionRegistration) == 0
            )
    finally:
        await finish(anchor, t)


async def test_native_arrival_during_final_binding_sql_rolls_back_binding_audit_and_confirmation(
    db,
):
    env = await setup(db)
    router, source, publisher, chat, workers, adopter, factory, state, writes, anchor, t = env
    triggered = False

    def arrival(session, context, instances):
        nonlocal triggered
        if not triggered and any(
            isinstance(row, AuditEvent) and row.event == "session_bound" for row in session.new
        ):
            triggered = True
            # Payload-free invalidation, before a retained event or async dispatch.
            anchor.feed.index._notice_arrival(
                {"id": "new-child-arrival", "type": "plugin.new-child", "data": {}}
            )

    try:
        await menu(env)
        preview = await send(router, source, message("!1", 2002))
        assert "Connect this conversation" in preview.text
        await show(source, publisher, chat, workers, preview)
        event.listen(Session, "before_flush", arrival)
        denied = await send(router, source, message("!confirm", 2003))
        assert triggered and not denied.binding_id and not denied.action_id
        assert await count(db, Binding) == await count(db, Action) == 0 and not writes
        async with db.sessions() as session:
            token = await session.scalar(
                select(ControlToken).where(ControlToken.kind == "binding-confirm")
            )
            assert not token.used
            assert not (
                await session.scalars(select(AuditEvent).where(AuditEvent.event == "session_bound"))
            ).all()
    finally:
        event.remove(Session, "before_flush", arrival)
        await finish(anchor, t)


async def test_viewer_can_list_original_metadata_but_cannot_adopt_or_create_binding(db):
    env = await setup(db)
    router, source, publisher, chat, workers, adopter, factory, state, writes, anchor, t = env
    try:
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(role="viewer"))
        await menu(env)
        denied = await send(router, source, message("!1", 2002))
        assert not denied.binding_id and not denied.action_id
        assert TARGET not in factory.registry.sessions
        assert (
            await count(db, SessionRegistration)
            == await count(db, Binding)
            == await count(db, Action)
            == 0
        )
        assert not writes
    finally:
        await finish(anchor, t)


async def test_menu_created_before_opt_in_cannot_omit_original_identity_after_reload(db):
    env = await setup(db)
    router, source, publisher, chat, workers, adopter, factory, state, writes, anchor, t = env
    try:
        router.unbound.discovery.adoption = None
        await menu(env)
        router.unbound.discovery.adoption = adopter
        reloaded = CommandRouter(
            adopter.bindings,
            source,
            router.inbox,
            discovery=router.unbound.discovery,
            capabilities=adopter.bindings.control.capabilities,
        )
        denied = await send(reloaded, source, message("!1", 2002))
        assert not denied.binding_id and not denied.action_id
        assert TARGET not in factory.registry.sessions and not writes
        assert await count(db, SessionRegistration) == await count(db, Binding) == 0
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("leaf", [False, True])
async def test_short_flow_continues_during_get_usage_and_original_feed_text_deltas(db, leaf):
    import copy

    import httpx

    from tests.contract.test_lineage_progress import assistant
    from tests.contract.test_public_live_feed import frame, text_delta

    env = await setup(db, running=True, leaf=leaf)
    router, source, publisher, chat, workers, adopter, factory, state, writes, anchor, t = env
    old = t.client._transport
    gets, messages = 0, 0

    def progressing(request):
        nonlocal gets, messages
        response = old.handler(request)
        if request.url.path == "/api/session/" + TARGET.upstream_session_id:
            gets += 1
            body = copy.deepcopy(response.json())
            body["data"]["cost"] = gets / 100
            body["data"]["tokens"]["output"] = gets
            body["data"]["time"]["updated"] += gets
            return httpx.Response(200, json=body)
        if request.url.path == "/api/session/" + TARGET.upstream_session_id + "/message":
            messages += 1
            value = assistant()
            raw = text_delta("evt_synthetic_shortflow_" + str(messages))
            raw["data"]["sessionID"] = TARGET.upstream_session_id
            anchor.feed.index.accept(frame(raw))
            return httpx.Response(200, json={"data": [value], "cursor": {}})
        return response

    t.client._transport = httpx.MockTransport(progressing)
    try:
        await menu(env)
        preview = await send(router, source, message("!1", 2002))
        assert "Connect this conversation" in preview.text, preview.text
        await show(source, publisher, chat, workers, preview)
        connected = await send(router, source, message("!confirm", 2003))
        assert connected.binding_id and "Connected." in connected.text, connected.text
        queued = await send(router, source, message("continue this original work", 2004))
        assert queued.action_id and gets > 10 and messages > 4
        assert await count(db, Binding) == await count(db, Action) == 1 and not writes
        current = await adopter.bindings.control.snapshot(TARGET)
        assert current.reference == TARGET and current.state.value == "running"
    finally:
        await finish(anchor, t)
