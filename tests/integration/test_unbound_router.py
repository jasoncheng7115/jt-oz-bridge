import asyncio
import json
import re
from html import unescape

import pytest
from sqlalchemy import delete, select, update

from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.delivery import DeliveryWorker
from jt_oz_bridge.services.discovery_delivery import DiscoveryDeliveryWorker
from jt_oz_bridge.services.discovery_outbox import DiscoveryOutbox, DiscoveryReplyPublisher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.reply_publisher import ReplyPublisher
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from tests.integration.test_delivery import SyntheticChat
from tests.integration.test_discovery import discovery
from tests.integration.test_router import Source, count, message, send


def menu_token(text):
    text = unescape(text)
    return re.search(r"!oz choose ([A-Za-z0-9_-]{32}) 1", text)[1]


def confirm_token(text):
    text = unescape(text)
    return re.search(r"!(?:oz confirm|ok) ([A-Za-z0-9_-]{32})", text)[1]


async def test_unbound_language_defaults_to_platform_and_auto_removes_only_personal_override(db):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.i18n import get_locale

    router, source, _, _, _, _ = await pipeline(db)
    source.preferred_locale = AsyncMock(return_value="zh-TW")
    first = await send(router, source, message("!help", message_id=201))
    assert first.locale == "zh-TW" and "`!go`" in first.text
    manual = await send(router, source, message("!oz lang en", message_id=202))
    assert manual.locale == "en" and await get_locale(db, "user:realm:7") == "en"
    automatic = await send(router, source, message("!oz lang auto", message_id=203))
    assert automatic.locale == "zh-TW" and "跟隨聊天平台" in automatic.text
    assert await get_locale(db, "user:realm:7", "zh-TW") == "zh-TW"


async def pipeline(db):
    catalog, clients = await discovery(db)
    fencing = await DurableStore(db).acquire_lease("unbound-router")
    source = Source()
    inbox = CommandInbox(db, "unbound-router", fencing)
    router = CommandRouter(
        catalog.bindings,
        source,
        inbox,
        discovery=catalog,
        capabilities=catalog.bindings.control.capabilities,
    )
    bound = Outbox(catalog.bindings, 77, fence=inbox.fence)
    scoped = DiscoveryOutbox(router.unbound.destinations, 77)
    publisher = ReplyPublisher(
        RoutedOutbox(bound, realm_id="realm", message_limit=2000, topic_limit=60),
        DiscoveryReplyPublisher(scoped, realm_id="realm", message_limit=2000, topic_limit=60),
    )
    chat = SyntheticChat()
    workers = (
        DeliveryWorker(bound, chat, "unbound-router", fencing, minimum_interval=0),
        DiscoveryDeliveryWorker(scoped, chat, "unbound-router", fencing, minimum_interval=0),
    )
    return router, source, clients, publisher, chat, workers


async def choose(router, source, shown, number=1, message_id=202, **changes):
    return await send(
        router,
        source,
        message("!oz choose " + menu_token(shown.text) + " " + str(number), message_id, **changes),
    )


async def emit(publisher, workers, routed):
    batch = await publisher.publish(routed)
    if batch:
        worker = workers[1] if routed.discovery_target is not None else workers[0]
        for identity in batch.deliveries:
            assert await worker.advance(identity) == "delivered"
    return batch


async def session_preview(router, source):
    backends = await send(router, source, message("!oz backends", 201))
    projects = await choose(router, source, backends, message_id=202)
    sessions = await choose(router, source, projects, message_id=203)
    preview = await choose(router, source, sessions, message_id=204)
    return preview


async def test_official_text_chain_publishes_real_scopes_then_binds_and_queues_original_followup(
    db,
):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    step = await send(router, source, message("!oz backends", 201))
    assert "Choose a backend" in step.text and step.discovery_target is not None
    await emit(publisher, workers, step)
    step = await choose(router, source, step, message_id=202)
    assert "Choose a project" in step.text
    await emit(publisher, workers, step)
    step = await choose(router, source, step, message_id=203)
    assert "Choose a conversation" in step.text and "Work 0" in step.text
    await emit(publisher, workers, step)
    step = await choose(router, source, step, message_id=204)
    assert "Connect this conversation" in step.text
    assert await count(db, Binding) == 0 and await count(db, Action) == 0
    await emit(publisher, workers, step)
    final = await send(router, source, message("!oz confirm " + confirm_token(step.text), 205))
    assert final.binding_id and final.discovery_target is None
    assert "Connected." in final.text
    await emit(publisher, workers, final)
    assert await router.route(source.messages[205]) == final
    assert await count(db, Binding) == 1
    async with db.sessions() as session:
        binding = await session.get(Binding, final.binding_id)
        assert binding.session_id == "session:0" and binding.anchor_message_id == 205
    followup = await send(router, source, message("continue the same original work", 206))
    async with db.sessions() as session:
        action = await session.get(Action, followup.action_id)
        assert (
            action.binding_id == binding.id
            and action.payload["text"] == "continue the same original work"
        )
    execution = router.bindings.control.backends["backend"].client
    assert not execution.submitted  # Routing/admission is not native completion.
    assert len(chat.calls) >= 5 and clients["second"].calls == []


async def test_duplicate_menu_receipt_reuses_original_tokens_target_and_outbox_plan(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    first = await send(router, source, message("!oz backends", 201))
    token_count = await count(db, ControlToken)
    duplicate = await router.route(source.messages[201])
    assert duplicate == first and await count(db, ControlToken) == token_count
    one = await publisher.publish(first)
    two = await publisher.publish(duplicate)
    assert one == two and await count(db, Delivery) == len(one.deliveries)


async def test_actor_or_target_cannot_steal_discovery_menu_even_with_project_admin_grants(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    first = await send(router, source, message("!oz backends", 201))
    wrong = await choose(router, source, first, message_id=202, author_id=8)
    assert "expired" in wrong.text
    other = await choose(router, source, first, message_id=203, topic="Other topic")
    assert "expired" in other.text
    valid = await choose(router, source, first, message_id=204)
    assert "Choose a project" in valid.text and await count(db, Binding) == 0


async def test_native_cursor_is_opaque_and_wrong_route_cannot_consume_it(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    projects = await send(router, source, message("!oz projects", 201))
    sessions = await choose(router, source, projects, message_id=202)
    next_token = re.search(r"!oz sessions ([A-Za-z0-9_-]{32})", unescape(sessions.text))[1]
    assert "position:10" not in sessions.text and "Work 10" not in sessions.text
    wrong = await send(router, source, message("!oz backends " + next_token, 203))
    assert "expired" in wrong.text
    next_page = await send(router, source, message("!oz sessions " + next_token, 204))
    assert "Work 10" in next_page.text and "Work 0" not in next_page.text
    assert clients["backend"].calls[-1][2] == "position:10"


async def test_typed_project_search_and_bind_selection_keep_original_ids_and_literal_query(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    projects = await send(router, source, message("!oz projects", 201))
    selected = re.search(r"!oz sessions ([A-Za-z0-9_-]{32})", unescape(projects.text))[1]
    sessions = await send(
        router, source, message("!oz sessions " + selected + " -- !oz exact literal query", 202)
    )
    assert clients["backend"].calls[-1][1] == "!oz exact literal query"
    selected = re.search(r"!oz bind ([A-Za-z0-9_-]{32})", unescape(sessions.text))[1]
    preview = await send(router, source, message("!oz bind " + selected, 203))
    assert "session:0" in preview.text and confirm_token(preview.text)
    assert await count(db, Action) == 0


async def test_viewer_can_list_but_cannot_prepare_binding_or_execute_a_prompt(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        for project in ("project", "second-project"):
            session.add(Grant(realm_id="realm", user_id=7, project_id=project, role="viewer"))
    projects = await send(router, source, message("!oz projects", 201))
    sessions = await choose(router, source, projects, message_id=202)
    denied = await choose(router, source, sessions, message_id=203)
    assert "have permission" in denied.text and "!oz confirm" not in denied.text
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_scope_change_after_menu_refuses_selection_without_a_native_list(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    first = await send(router, source, message("!oz backends", 201))
    async with db.sessions.begin() as session:
        await session.execute(
            update(Grant)
            .where(Grant.user_id == 8, Grant.project_id == "project")
            .values(active=False)
        )
    result = await choose(router, source, first, message_id=202)
    assert "permission" in result.text or "expired" in result.text
    assert all(not client.calls for client in clients.values())


async def test_recovered_control_is_held_with_static_notice_and_does_not_issue_navigation(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    held = await send(router, source, message("!oz backends", 201), recovered=True)
    assert held.state == "held" and "did not run" in held.text
    assert held.discovery_target.purpose == "static"
    assert await count(db, ControlToken) == 0
    assert all(not client.calls for client in clients.values())
    await emit(publisher, workers, held)
    assert await router.route(source.messages[201]) == held


async def test_unbound_literal_send_has_immutable_receipt_and_never_becomes_a_delayed_prompt(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    item = message("!oz send -- !oz stop", 199)
    result = await send(router, source, item)
    assert "Choose a conversation first" in result.text
    assert await count(db, CommandReceipt) == 1 and await count(db, Action) == 0
    preview = await session_preview(router, source)
    await send(router, source, message("!oz confirm " + confirm_token(preview.text), 205))
    with pytest.raises(Conflict):
        await router.route(item)  # Its old unbound output cannot enter the new binding.
    assert await count(db, Action) == 0


async def test_edited_control_to_plain_text_only_gets_static_changed_notice(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    await send(router, source, message("!oz projects", 201))
    edited = message("normal edited conversation", 201, revision=1)
    changed = await send(router, source, edited)
    assert "edited" in changed.text and changed.discovery_target.purpose == "static"
    await emit(publisher, workers, changed)
    assert await router.route(edited) == changed
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_chinese_personal_language_does_not_silently_change_new_topic_output_default(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    saved = await send(router, source, message("!oz lang zh-TW", 200))
    assert saved.locale == "zh-TW"
    preview = await session_preview(router, source)
    assert "要把這個對話連到此話題嗎" in preview.text
    final = await send(router, source, message("!oz confirm " + confirm_token(preview.text), 205))
    assert final.locale == "zh-TW" and "已連上" in final.text
    async with db.sessions() as session:
        assert (await session.get(Binding, final.binding_id)).locale == "en"


async def test_empty_native_page_with_more_keeps_forward_navigation(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    client = clients["backend"]
    original = client.list_sessions

    async def empty_first(scope, **options):
        page = await original(scope, **options)
        return page.model_copy(update={"items": ()}) if options["cursor"] is None else page

    client.list_sessions = empty_first
    projects = await send(router, source, message("!oz projects", 201))
    empty = await choose(router, source, projects, message_id=202)
    assert "Nothing to choose" in empty.text and "Next page" in empty.text
    token = re.search(r"!oz sessions ([A-Za-z0-9_-]{32})", unescape(empty.text))[1]
    next_page = await send(router, source, message("!oz sessions " + token, 203))
    assert "Work 10" in next_page.text


@pytest.mark.parametrize("kind", ["bot", "public", "plain", "deleted"])
async def test_noncommand_or_untrusted_unbound_input_cannot_start_discovery(db, kind):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    if kind == "public":
        router.bindings.audience.private = False
    item = message(
        "plain conversation" if kind == "plain" else "!oz backends",
        201,
        is_bot=kind == "bot",
        deleted=kind == "deleted",
    )
    result = await send(router, source, item)
    if kind == "plain":
        assert result.state == "reply" and result.discovery_target.purpose == "catalog"
        assert "`!1`" in result.text and "plain conversation" not in result.text
        assert not result.action_id and not result.binding_id
        await emit(publisher, workers, result)
        assert len(chat.calls) == 1
    else:
        assert result.state == "ignore" and await publisher.publish(result) is None
    if kind != "plain":
        assert await count(db, ControlToken) == 0 and all(
            not client.calls for client in clients.values()
        )


@pytest.mark.parametrize("kind", ["bot", "public", "deleted", "edited", "recovered", "empty"])
async def test_onboarding_never_replies_to_untrusted_or_historical_plain_text(db, kind):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    if kind == "public":
        router.bindings.audience.private = False
    item = message(
        " " if kind == "empty" else "hi",
        201,
        is_bot=kind == "bot",
        deleted=kind == "deleted",
        revision=1 if kind == "edited" else 0,
    )
    result = await send(router, source, item, recovered=kind == "recovered")
    assert result.state == "ignore" and await publisher.publish(result) is None
    assert not chat.calls and all(not client.calls for client in clients.values())
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_plain_text_menu_duplicate_reuses_original_delivery_without_prompt(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    item = message("PRIVATE_PLAIN_TEXT", 201)
    first = await send(router, source, item)
    batch = await emit(publisher, workers, first)
    duplicate = await send(router, source, item)
    assert await publisher.publish(duplicate) == batch
    assert len(chat.calls) == 1 and "PRIVATE_PLAIN_TEXT" not in first.text
    assert await count(db, CommandReceipt) == 1
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_concurrent_same_discovery_source_issues_one_navigation_and_one_receipt(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    item = message("!oz backends", 201)
    source.messages[201] = item
    replies = await asyncio.gather(router.route(item), router.route(item))
    assert all(reply.state in {"reply", "busy"} for reply in replies)
    assert await count(db, CommandReceipt) == 1 and await count(db, ControlToken) == 1
    valid = next(reply for reply in replies if reply.discovery_target is not None)
    await emit(publisher, workers, valid)
    assert await publisher.publish(await router.route(item)) == await publisher.publish(valid)


async def test_crash_after_binding_before_receipt_finish_preserves_binding_and_ambiguity(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    preview = await session_preview(router, source)
    original = router.inbox.finish

    async def interrupted(claim, response):
        raise RuntimeError("injected after local binding before receipt finish")

    router.inbox.finish = interrupted
    item = message("!oz confirm " + confirm_token(preview.text), 205)
    with pytest.raises(RuntimeError, match="injected"):
        await send(router, source, item)
    router.inbox.finish = original
    assert await count(db, Binding) == 1
    retry = await router.route(item)
    assert retry.state == "ambiguous" and retry.binding_id is not None
    assert "rerun automatically" in retry.text and await count(db, Binding) == 1
    assert await count(db, Action) == 0


async def test_expired_selection_cannot_read_native_session_catalog_or_become_prompt(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    projects = await send(router, source, message("!oz projects", 201))
    async with db.sessions.begin() as session:
        await session.execute(update(ControlToken).values(expires_at=0))
    refused = await choose(router, source, projects, message_id=202)
    assert "expired" in refused.text and all(not client.calls for client in clients.values())
    assert await count(db, Action) == 0


async def test_cached_ciphertext_reply_cannot_be_replayed_for_another_source_message(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    await send(router, source, message("!oz backends", 201))
    await send(router, source, message("!oz help", 202, topic="Other topic"))
    async with db.sessions.begin() as session:
        a = await session.scalar(select(CommandReceipt).where(CommandReceipt.message_id == 201))
        b = await session.scalar(select(CommandReceipt).where(CommandReceipt.message_id == 202))
        a.response = b.response
    with pytest.raises(Conflict, match="source_changed"):
        await router.route(source.messages[201])
    assert await count(db, Binding) == await count(db, Delivery) == 0


async def test_unknown_controls_and_unbound_stop_are_local_not_backend_work(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    unknown = await send(router, source, message("!oz definitely-unknown", 201))
    stop = await send(router, source, message("!oz stop", 202))
    assert (
        "nothing was sent to OpenCode" in unknown.text
        and "Choose a conversation first" in stop.text
    )
    assert unknown.discovery_target.purpose == stop.discovery_target.purpose == "static"
    assert await count(db, Action) == 0 and all(not client.calls for client in clients.values())


async def test_recent_selection_preserves_original_session_id_and_rechecks_current_snapshot(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    preview = await session_preview(router, source)
    final = await send(router, source, message("!oz confirm " + confirm_token(preview.text), 205))
    binding = await router.bindings.get(final.binding_id, "realm", 7)
    await router.bindings.unbind(binding.id, "realm", 7, binding.revision)
    recent = await send(router, source, message("!oz sessions recent", 206))
    assert "Your recent conversations" in recent.text
    preview = await choose(router, source, recent, message_id=207)
    assert "session:0" in preview.text and confirm_token(preview.text)
    assert await count(db, Action) == 0


async def test_project_menu_uses_only_final_page_observation_before_fresh_output_prepare(db):
    router, source, _, _, _, _ = await pipeline(db)
    original, calls = router.bindings.audience.inspect, []

    async def inspect(*args):
        calls.append(args)
        return await original(*args)

    router.bindings.audience.inspect = inspect
    result = await send(router, source, message("!projects", 201))
    assert result.discovery_target is not None and result.discovery_target.projects
    # Initial unbound authorization; page before/after; independent output prepare.
    # No permission cache or weakened public binding_for/projects entry point.
    assert len(calls) == 4
    assert await count(db, ControlToken) > 0 and await count(db, Action) == 0


@pytest.mark.parametrize("change", ["author_id", "topic", "revision"])
async def test_sql_absence_does_not_authorize_changed_source_before_unbound_delegate(db, change):
    router, source, clients, _, _, _ = await pipeline(db)
    original = router.unbound.route

    async def delegate(event, **options):
        replacement = {"author_id": 8, "topic": "Other topic", "revision": 1}[change]
        source.messages[event.message_id] = event.model_copy(update={change: replacement})
        return await original(event, **options)

    router.unbound.route = delegate
    result = await send(router, source, message("!projects", 201))
    assert result.state == "ignore"
    assert await count(db, ControlToken) == await count(db, CommandReceipt) == 0
    assert all(not client.calls for client in clients.values())


@pytest.mark.parametrize("change", ["public", "foreign_topic", "membership", "role"])
async def test_sql_absence_keeps_private_canonical_audience_and_grants_before_catalog(db, change):
    router, source, clients, _, _, _ = await pipeline(db)
    original, audience = router.unbound.route, router.bindings.audience

    async def delegate(event, **options):
        if change == "public":
            audience.private = False
        elif change == "membership":
            audience.users = frozenset({8})
        elif change == "foreign_topic":
            inspect = audience.inspect

            async def noncanonical(*args):
                return (await inspect(*args)).model_copy(update={"canonical_topic": "Other"})

            audience.inspect = noncanonical
        else:
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        return await original(event, **options)

    router.unbound.route = delegate
    result = await send(router, source, message("!projects", 201))
    if change == "role":
        assert not result.discovery_target.projects
    else:
        assert result.state == "ignore"
    assert await count(db, ControlToken) == await count(db, Action) == 0
    assert all(not client.calls for client in clients.values())


async def test_binding_appearing_after_sql_absence_cannot_commit_unbound_tokens_or_output(db):
    from tests.support import REF

    router, source, _, _, _, _ = await pipeline(db)
    original = router.unbound.route

    async def delegate(event, **options):
        await router.bindings.bind(
            event.realm_id, event.author_id, event.channel_id, event.topic, REF
        )
        return await original(event, **options)

    router.unbound.route = delegate
    with pytest.raises(Conflict, match="became_bound"):
        await send(router, source, message("!projects", 201))
    assert await count(db, Binding) == 1
    assert (
        await count(db, ControlToken) == await count(db, Delivery) == await count(db, Action) == 0
    )


@pytest.mark.parametrize("change", ["source", "audience", "grant"])
async def test_final_project_page_observation_cannot_replace_fresh_output_authorization(db, change):
    router, source, _, _, _, _ = await pipeline(db)
    original = router.unbound.context_from_audience

    async def context(event, scopes, audience):
        result = await original(event, scopes, audience)
        if change == "source":
            source.messages[event.message_id] = event.model_copy(update={"revision": 1})
        elif change == "audience":
            router.bindings.audience.users = frozenset({7, 8, 999})
        else:
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        return result

    router.unbound.context_from_audience = context
    with pytest.raises((Conflict, AccessDenied)):
        await send(router, source, message("!projects", 201))
    assert (
        await count(db, ControlToken) == await count(db, Delivery) == await count(db, Action) == 0
    )


@pytest.mark.parametrize(
    "change", [None, "public", "membership", "untrusted_bot", "grant", "noncanonical"]
)
async def test_sql_absence_sessions_delegate_rechecks_authority_before_actual_native_catalog(
    db, change
):
    router, source, clients, _, _, _ = await pipeline(db)
    projects = await send(router, source, message("!projects", 201))
    token = re.search(r"!oz sessions ([A-Za-z0-9_-]{32})", unescape(projects.text))[1]
    assert all(not client.calls for client in clients.values())
    original, audience = router.unbound.route, router.bindings.audience

    async def delegate(event, **options):
        if change == "public":
            audience.private = False
        elif change == "membership":
            audience.users = frozenset({8})
        elif change in {"untrusted_bot", "noncanonical"}:
            inspect = audience.inspect

            async def changed(*args):
                return (await inspect(*args)).model_copy(
                    update={"untrusted_bot_ids": frozenset({999})}
                    if change == "untrusted_bot"
                    else {"canonical_topic": "Other"}
                )

            audience.inspect = changed
        elif change == "grant":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        return await original(event, **options)

    router.unbound.route = delegate
    result = await send(router, source, message("!oz sessions " + token, 202))
    if change is None:
        assert "Choose a conversation" in result.text and clients["backend"].calls
    else:
        assert all(not client.calls for client in clients.values())
        assert result.discovery_target is None or not result.discovery_target.projects
    assert await count(db, Action) == await count(db, Binding) == 0


async def visible(source, publisher, chat, workers, reply):
    await emit(publisher, workers, reply)
    for item in chat.messages.values():
        source.messages[item.id] = message(
            item.content,
            item.id,
            channel_id=item.channel_id,
            topic=item.topic,
            author_id=item.sender_id,
            is_bot=True,
        )


def next_id(source):
    return max(source.messages) + 1


async def test_go_lists_every_project_with_readable_rows_and_buttons(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    menu = await send(router, source, message("!go", 201))
    assert "**Work 0**" in menu.text and "project" in menu.text
    assert "!oz" not in menu.text and "session:0" not in menu.text
    widget = json.loads(menu.widget)
    assert widget["widget_type"] == "zform"
    assert [c["reply"] for c in widget["extra_data"]["choices"]][:2] == ["!1", "!2"]
    # Web clients show only the widget, as plain text, so it must stand on its own.
    heading = widget["extra_data"]["heading"]
    assert "`" not in heading and "!go" in heading
    assert " · " in widget["extra_data"]["choices"][0]["long_name"]
    assert await count(db, Binding) == await count(db, Action) == 0
    await emit(publisher, workers, menu)
    assert json.loads(chat.widgets[-1])["widget_type"] == "zform"


async def test_plain_text_then_number_connects_and_sends_the_text_once(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    menu = await send(router, source, message("please do the work", 201))
    assert "`!1`" in menu.text and not menu.binding_id
    await visible(source, publisher, chat, workers, menu)
    choice = message("!1", next_id(source))
    bound = await send(router, source, choice)
    assert bound.binding_id and "**" in bound.text and "sent too" in bound.text
    assert await count(db, Binding) == 1 and await count(db, Action) == 1
    async with db.sessions() as session:
        action = await session.scalar(select(Action))
    assert action.payload["text"] == "please do the work" and action.binding_id == bound.binding_id
    assert await router.route(choice) == bound and await count(db, Action) == 1


async def test_a_transient_failure_tells_the_person_to_resend_the_opening_text(db, monkeypatch):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.services import unbound_router

    async def unavailable(self, binding_id, message, **_):
        raise ZulipReadUnavailable("zulip_read_service_unavailable")

    monkeypatch.setattr(unbound_router.QueueService, "receive", unavailable)
    router, source, _, publisher, chat, workers = await pipeline(db)
    menu = await send(router, source, message("please do the work", 201))
    await visible(source, publisher, chat, workers, menu)
    bound = await send(router, source, message("!1", next_id(source)))
    assert bound.binding_id and "not sent" in bound.text
    assert await count(db, Action) == 0


async def test_go_keyword_with_one_match_connects_and_many_matches_list(db):
    router, source, clients, *_ = await pipeline(db)
    many = await send(router, source, message("!go Work", 201))
    assert not many.binding_id and "`!1`" in many.text
    for client in clients.values():
        client.size = 1
        original = client.list_sessions

        async def only_first_project(scope, *, _original=original, **options):
            page = await _original(scope, **options)
            return page.model_copy(update={"items": ()}) if scope.project_id != "project" else page

        client.list_sessions = only_first_project
    other = await send(router, source, message("!go Work", 202, topic="one match"))
    assert other.binding_id and await count(db, Binding) == 1
    assert await count(db, Action) == 0
    plain = await send(router, source, message("!go", 203, topic="no keyword"))
    assert not plain.binding_id


async def test_recovered_or_edited_plain_text_never_opens_a_menu(db):
    router, source, *_ = await pipeline(db)
    item = message("old offline text", 201)
    source.messages[201] = item
    assert (await router.route(item, recovered=True)).state == "ignore"
    assert await count(db, CommandReceipt) == await count(db, ControlToken) == 0


async def test_connected_session_is_not_offered_again_in_another_topic(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    menu = await send(router, source, message("!go", 201))
    await visible(source, publisher, chat, workers, menu)
    bound = await send(router, source, message("!1", next_id(source)))
    assert bound.binding_id
    other = await send(router, source, message("!go", next_id(source), topic="another topic"))
    title = re.search(r"\*\*(.+?)\*\*", bound.text)[1]
    assert f"**{title}**" not in other.text and title in other.text


async def test_viewer_without_operate_cannot_connect_by_number(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    async with db.sessions.begin() as session:
        await session.execute(delete(Grant).where(Grant.user_id == 7, Grant.role != "viewer"))
    menu = await send(router, source, message("!go", 201))
    await visible(source, publisher, chat, workers, menu)
    result = await send(router, source, message("!1", next_id(source)))
    assert not result.binding_id and await count(db, Binding) == await count(db, Action) == 0


async def test_long_form_choice_still_shows_preview_before_binding(db):
    router, source, *_ = await pipeline(db)
    projects = await send(router, source, message("!oz projects", 201))
    sessions = await choose(router, source, projects, message_id=202)
    preview = await choose(router, source, sessions, message_id=203)
    assert "!ok" in preview.text and not preview.binding_id
    assert await count(db, Binding) == 0


@pytest.mark.parametrize("text", ["why did it stop?", "!go", "!oz backends"])
async def test_the_status_topic_is_answered_and_never_offered_a_conversation(db, text):
    from jt_oz_bridge.services.unbound_router import STATUS_TOPIC

    router, source, clients, publisher, chat, workers = await pipeline(db)
    reply = await send(router, source, message(text, 231, topic=STATUS_TOPIC))
    assert reply.state == "reply" and reply.discovery_target is not None
    assert unescape(reply.text) == router.tr.render("router.status_topic", "en")
    await emit(publisher, workers, reply)
    assert await count(db, ControlToken) == 0 and await count(db, Binding) == 0
    # Every other topic still gets the conversation menu.
    other = await send(router, source, message(text, 232))
    assert unescape(other.text) != router.tr.render("router.status_topic", "en")


def test_the_status_topic_is_the_one_the_stop_notice_posts_to():
    from jt_oz_bridge.services.unbound_router import STATUS_TOPIC
    from ops.server import bridge_notice, bridge_standby

    assert STATUS_TOPIC == bridge_notice.TOPIC == bridge_standby.STATUS_TOPIC
