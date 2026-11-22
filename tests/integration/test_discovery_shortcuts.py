"""Synthetic whole-router short controls; never live Human or mobile evidence."""

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.services.discovery_shortcuts import DiscoveryShortcutService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Delivery, WorkerLease
from tests.integration.test_router import count, message, send
from tests.integration.test_unbound_router import emit, pipeline


def long_form_preview(menu, message_id):
    """The explicit long form keeps the visible preview-then-confirm path."""
    from tests.integration.test_unbound_router import menu_token

    return message("!oz choose " + menu_token(menu.text) + " 1", message_id)


async def show(source, publisher, chat, workers, reply):
    batch = await emit(publisher, workers, reply)
    for item in chat.messages.values():
        source.messages[item.id] = message(
            item.content,
            item.id,
            channel_id=item.channel_id,
            topic=item.topic,
            author_id=item.sender_id,
            is_bot=True,
        )
    return batch


async def duplicate_menus(db, *, second_actor=7, multipage=False):
    """Two original commands before the first reply, with monotonic server IDs."""
    router, source, clients, publisher, chat, workers = await pipeline(db)
    original_send = chat.send

    async def monotonic_send(*args, **kwargs):
        posted = await original_send(*args, **kwargs)
        if posted <= max(source.messages):
            actual = max(source.messages) + 1
            chat.messages[actual] = chat.messages.pop(posted).model_copy(update={"id": actual})
            return actual
        return posted

    chat.send = monotonic_send
    first = await send(router, source, message("!projects", 201))
    second = await send(router, source, message("!projects", 202, author_id=second_actor))
    await show(source, publisher, chat, workers, first)
    assert max(chat.messages) == 1000
    choice = message("!1", 1001)
    source.messages[choice.message_id] = choice
    if multipage:
        publisher.discovery.message_limit = 256
    batch = await publisher.publish(second)
    assert batch is not None
    if multipage:
        assert len(batch.deliveries) > 1
    return router, source, clients, publisher, chat, workers, first, second, choice, batch


@pytest.mark.parametrize("second_actor", [7, 8])
@pytest.mark.parametrize("phase", ["unattempted", "future", "mixed_future_unattempted"])
async def test_causal_short_choice_uses_only_menu_visible_before_original_human(
    db, second_actor, phase
):
    from tests.integration.test_unbound_router import menu_token

    (
        router,
        source,
        _,
        publisher,
        chat,
        workers,
        first,
        second,
        choice,
        batch,
    ) = await duplicate_menus(
        db, second_actor=second_actor, multipage=phase == "mixed_future_unattempted"
    )
    if phase == "future":
        await show(source, publisher, chat, workers, second)
    elif phase == "mixed_future_unattempted":
        assert await workers[1].advance(batch.deliveries[0]) == "delivered"
    async with db.sessions() as session:
        rows = list(await session.scalars(select(Delivery).where(Delivery.batch_id == batch.id)))
        assert all(
            row.posted_message_id is None or row.posted_message_id > choice.message_id
            for row in rows
        )
    selected = await DiscoveryShortcutService(db, source).latest(choice)
    assert selected.choose == menu_token(first.text)
    assert selected.choose != menu_token(second.text)
    if phase == "future":
        later = message("!1", max(chat.messages) + 1, author_id=second_actor)
        source.messages[later.message_id] = later
        assert (await DiscoveryShortcutService(db, source).latest(later)).choose == menu_token(
            second.text
        )
    reply = await router.route(choice)
    assert "Choose a conversation" in reply.text and not reply.binding_id and not reply.action_id
    async with db.sessions() as session:
        old = await session.get(ControlToken, token_hash(menu_token(first.text)))
        new = await session.get(ControlToken, token_hash(menu_token(second.text)))
        assert old.used is True and new.used is False
    assert source.messages[choice.message_id] == choice
    assert await count(db, Binding) == await count(db, Action) == 0


@pytest.mark.parametrize("token_state", ["active", "used", "expired"])
@pytest.mark.parametrize(
    "fault",
    ["attempted", "sending", "ambiguous", "held", "missing_id", "equal_id", "unknown"],
)
async def test_causal_uncertain_menu_never_falls_back_to_an_older_owned_menu(
    db, token_state, fault
):
    from tests.integration.test_unbound_router import menu_token

    router, source, _, _, _, _, first, second, choice, batch = await duplicate_menus(db)
    changes = {
        "attempted": {"attempts": 1},
        "sending": {"state": "sending", "attempts": 1},
        "ambiguous": {"state": "ambiguous", "attempts": 1},
        "held": {"state": "held"},
        "missing_id": {"state": "delivered", "attempts": 1},
        "equal_id": {"state": "delivered", "attempts": 1, "posted_message_id": 1001},
        "unknown": {"state": "unknown"},
    }[fault]
    async with db.sessions.begin() as session:
        await session.execute(
            update(Delivery).where(Delivery.batch_id == batch.id).values(**changes)
        )
        if token_state != "active":
            await session.execute(
                update(ControlToken)
                .where(ControlToken.token_hash == token_hash(menu_token(second.text)))
                .values(**({"used": True} if token_state == "used" else {"expires_at": 0}))
            )
    with pytest.raises(Conflict):
        await DiscoveryShortcutService(db, source).latest(choice)
    async with db.sessions() as session:
        assert (await session.get(ControlToken, token_hash(menu_token(first.text)))).used is False
    assert await count(db, Binding) == await count(db, Action) == 0


@pytest.mark.parametrize("remaining", ["future", "unattempted"])
async def test_causal_partly_visible_newer_menu_cannot_choose_old_menu(db, remaining):
    (
        router,
        source,
        _,
        publisher,
        chat,
        workers,
        first,
        second,
        choice,
        batch,
    ) = await duplicate_menus(db, multipage=True)
    # A real newer page is posted before this separate Human instruction; its
    # remaining pages are then either still unattempted or posted afterward.
    del source.messages[choice.message_id]
    assert await workers[1].advance(batch.deliveries[0]) == "delivered"
    shown = chat.messages[max(chat.messages)]
    source.messages[shown.id] = message(
        shown.content, shown.id, author_id=shown.sender_id, is_bot=True
    )
    choice = message("!1", shown.id + 1)
    source.messages[choice.message_id] = choice
    if remaining == "future":
        for identity in batch.deliveries[1:]:
            assert await workers[1].advance(identity) == "delivered"
    with pytest.raises(Conflict):
        await DiscoveryShortcutService(db, source).latest(choice)
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_causal_future_reply_does_not_bypass_current_consumer_fence(db):
    router, source, _, _, _, _, first, second, choice, batch = await duplicate_menus(db)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
    with pytest.raises(Conflict):
        await router.route(choice)
    async with db.sessions() as session:
        assert all(not token.used for token in await session.scalars(select(ControlToken)))
    assert await count(db, Binding) == await count(db, Action) == 0


@pytest.mark.parametrize(
    "text,command,args",
    [
        ("!1", "choose", "1"),
        ("!10", "choose", "10"),
        ("!confirm", "confirm", ""),
        ("!projects", "projects", ""),
        ("!sessions", "sessions", ""),
        ("!recent", "sessions", "recent"),
        ("!backends", "backends", ""),
        ("!next", "next", ""),
        ("!help", "help", ""),
    ],
)
def test_explicit_shortcuts_normalize_without_changing_literal_source(text, command, args):
    assert parse_input(text).command == command and parse_input(text).arguments == args
    assert parse_input(text + "\n").command == command
    assert parse_input("quoted " + text, bound=True).kind == "prompt"
    assert parse_input("1", bound=True).kind == "prompt"
    assert parse_input(text, is_bot=True).kind == "ignore"


async def test_short_session_choice_connects_same_original_and_replays_once(db):
    router, source, clients, publisher, chat, workers = await pipeline(db)
    projects = await send(router, source, message("!projects", 201))
    assert "!1" in projects.text
    await show(source, publisher, chat, workers, projects)
    sessions = await send(router, source, message("!1", 2001))
    assert "Choose a conversation" in sessions.text and "Work 0" in sessions.text
    await show(source, publisher, chat, workers, sessions)
    confirmed = await send(router, source, message("!1", 2002))
    assert confirmed.binding_id and "Connected to" in confirmed.text
    assert await router.route(source.messages[2002]) == confirmed
    assert await count(db, Binding) == 1 and await count(db, Action) == 0
    async with db.sessions() as session:
        binding = await session.get(Binding, confirmed.binding_id)
        assert binding.session_id == "session:0" and binding.anchor_message_id == 2002
    followup = await send(router, source, message("continue original work", 2004))
    assert followup.action_id and await count(db, Action) == 1


@pytest.mark.parametrize(
    "kind",
    [
        "unpublished",
        "pending",
        "late_bot_post",
        "other_actor",
        "other_topic",
        "other_channel",
        "edited_origin",
        "deleted_bot",
        "edited_bot",
        "replaced_bot",
        "expired",
        "used",
    ],
)
async def test_short_choice_fails_closed_without_current_owned_visible_menu(db, kind):
    router, source, _, publisher, chat, workers = await pipeline(db)
    shown = await send(router, source, message("!projects", 201))
    if kind == "unpublished":
        pass
    elif kind == "pending":
        await publisher.publish(shown)
    else:
        await show(source, publisher, chat, workers, shown)
    item = message("!1", 2001)
    if kind == "late_bot_post":
        item = message("!1", 999)
    elif kind == "other_actor":
        item = item.model_copy(update={"author_id": 8})
    elif kind == "other_topic":
        item = item.model_copy(update={"topic": "Other"})
    elif kind == "other_channel":
        item = item.model_copy(update={"channel_id": 11})
    elif kind == "edited_origin":
        source.messages[201] = source.messages[201].model_copy(
            update={"revision": 1, "text": "!help"}
        )
    elif kind in {"deleted_bot", "edited_bot", "replaced_bot"}:
        key = max(chat.messages)
        change = (
            {"deleted": True}
            if kind == "deleted_bot"
            else {"text": "changed"}
            if kind == "edited_bot"
            else {"author_id": 7, "is_bot": False}
        )
        source.messages[key] = source.messages[key].model_copy(update=change)
    elif kind in {"expired", "used"}:
        async with db.sessions.begin() as session:
            await session.execute(
                update(ControlToken).values(
                    **({"expires_at": 0} if kind == "expired" else {"used": True})
                )
            )
    result = await send(router, source, item)
    assert (
        not result.binding_id
        and not result.action_id
        and "Choose a conversation" not in result.text
    )
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_latest_visible_reply_is_only_target_and_help_does_not_replace_it(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    projects = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, projects)
    help_reply = await send(router, source, message("!help", 2001))
    await show(source, publisher, chat, workers, help_reply)
    # A help result has no menu; the latest actual menu still selects a project.
    sessions = await send(router, source, message("!1", 2002))
    assert "Choose a conversation" in sessions.text
    await show(source, publisher, chat, workers, sessions)
    premature = await send(router, source, message("!confirm", 2003))
    assert not premature.binding_id and await count(db, Binding) == 0
    # A newer undelivered preview must not capture a shortcut aimed at the
    # older, visible sessions menu.
    preview = await send(router, source, long_form_preview(sessions, 2004))
    assert "!ok" in preview.text
    failed = await send(router, source, message("!confirm", 2005))
    assert not failed.binding_id and await count(db, Binding) == 0


async def test_no_menu_shortcut_never_becomes_agent_prompt(db):
    router, source, _, _, _, _ = await pipeline(db)
    for mid, text in enumerate(("!1", "!confirm", "!next"), 201):
        result = await send(router, source, message(text, mid))
        assert not result.binding_id and not result.action_id
    assert await count(db, Action) == await count(db, Binding) == 0


async def test_bot_post_edit_after_menu_lookup_is_rejected_before_token_use(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    shown = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, shown)
    original = source.read

    async def edited(realm, mid):
        row = await original(realm, mid)
        return row.model_copy(update={"text": "edited"}) if row.is_bot else row

    source.read = edited
    with pytest.raises(Conflict):
        await DiscoveryShortcutService(db, source).latest(message("!1", 2001))
    async with db.sessions() as session:
        assert all(not token.used for token in await session.scalars(select(ControlToken)))


async def test_another_persons_newer_menu_cannot_select_own_older_menu(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    own = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, own)
    other = await send(router, source, message("!projects", 2001, author_id=8))
    assert "Choose a project" in other.text
    await show(source, publisher, chat, workers, other)
    rejected = await send(router, source, message("!1", 2002))
    assert "Choose a conversation" not in rejected.text and not rejected.binding_id
    owner = await send(router, source, message("!1", 2003, author_id=8))
    assert "Choose a conversation" in owner.text


async def test_next_page_shortcut_uses_only_current_visible_page(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    first = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, first)
    sessions = await send(router, source, message("!1", 2001))
    assert "Work 0" in sessions.text and "!next" in sessions.text
    await show(source, publisher, chat, workers, sessions)
    second = await send(router, source, message("!next", 2002))
    assert "Work 10" in second.text and "Work 0" not in second.text
    assert await count(db, Binding) == await count(db, Action) == 0


async def test_short_confirm_rechecks_visible_preview_before_binding_commit(db, monkeypatch):
    router, source, _, publisher, chat, workers = await pipeline(db)
    reply = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, reply)
    reply = await send(router, source, message("!1", 2001))
    await show(source, publisher, chat, workers, reply)
    reply = await send(router, source, long_form_preview(reply, 2002))
    await show(source, publisher, chat, workers, reply)
    original = DiscoveryShortcutService.token
    changed = False

    async def edit_after_first_read(service, item, kind):
        nonlocal changed
        value = await original(service, item, kind)
        if kind == "confirm" and not changed:
            changed = True
            mid = max(chat.messages)
            source.messages[mid] = source.messages[mid].model_copy(
                update={"text": "changed preview"}
            )
        return value

    monkeypatch.setattr(DiscoveryShortcutService, "token", edit_after_first_read)
    result = await send(router, source, message("!confirm", 2003))
    assert changed and not result.binding_id
    assert await count(db, Binding) == await count(db, Action) == 0


@pytest.mark.parametrize("text", ["!0", "!11", "!01", "!99999999999999999999"])
def test_invalid_numeric_shortcuts_are_never_agent_prompts(text):
    for bound in (False, True):
        result = parse_input(text, bound=bound)
        assert result.kind == "invalid" and result.command == "choose"


async def test_empty_recent_menu_invalidates_an_older_unconsumed_project_menu(db):
    router, source, _, publisher, chat, workers = await pipeline(db)
    shown = await send(router, source, message("!projects", 201))
    await show(source, publisher, chat, workers, shown)
    empty = await send(router, source, message("!recent", 2001))
    await show(source, publisher, chat, workers, empty)
    result = await send(router, source, message("!1", 2002))
    assert "Choose a conversation" not in result.text and not result.binding_id
    assert await count(db, Binding) == await count(db, Action) == 0


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_short_discovery_instructions_do_not_replace_bound_or_permission_menu_protocol(locale):
    from jt_oz_bridge.i18n import Translator

    tr = Translator()
    legacy = tr.render("menu.choose", locale, menu_id="a" * 32, item_number=1)
    discovery = tr.render("discovery.choose", locale, menu_id="a" * 32, item_number=1)
    assert "!oz choose" in legacy and "`!1`" not in legacy
    assert "`!1`" in discovery and "```spoiler" in discovery


async def test_shared_menu_scope_cannot_commit_without_fresh_matching_output_source(db):
    router, source, _, _, _, _ = await pipeline(db)
    item = message("!projects", 201)
    source.messages[201] = item
    unbound = router.unbound
    with unbound.tokens.planning() as plan:
        result = await unbound.projects(item, "en")
        assert result.shortcuts.choose and plan.required_output_source == item
        with pytest.raises(Conflict, match="fresh_output_source"):
            async with db.sessions.begin() as session:
                await plan.commit(session)
    assert await count(db, ControlToken) == 0


async def test_shared_menu_tokens_must_match_current_output_audience_before_commit(db):
    router, source, _, _, _, _ = await pipeline(db)
    item = message("!projects", 201)
    source.messages[201] = item
    unbound = router.unbound
    with unbound.tokens.planning() as plan:
        result = await unbound.projects(item, "en")
        target = await unbound.destinations.prepare(item, result.projects)
        changed = target.model_copy(
            update={"audience": target.audience.model_copy(update={"revision": "changed"})}
        )
        with pytest.raises(Conflict, match="output_audience"):
            async with db.sessions.begin() as session:
                await plan.commit(session, target=changed)
    assert await count(db, ControlToken) == 0


@pytest.mark.parametrize("boundary", ["source", "snapshot", "final_source", "post_write"])
async def test_confirmation_throttle_retries_only_proven_prewrite_preparation(db, boundary):
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited
    from jt_oz_bridge.domain.routing import RoutingRateDeferred
    from jt_oz_bridge.storage.command_models import CommandReceipt

    router, source, _, publisher, chat, workers = await pipeline(db)
    for mid, text in ((201, "!projects"), (2001, "!1")):
        reply = await send(router, source, message(text, mid))
        await show(source, publisher, chat, workers, reply)
    reply = await send(router, source, long_form_preview(reply, 2002))
    await show(source, publisher, chat, workers, reply)
    assert "!ok" in reply.text, reply.text
    confirmation = router.unbound.confirmations
    execution = confirmation.bindings.control.backends["backend"].client
    original_source = confirmation.source
    original_snapshot = execution.snapshot
    original_bind = confirmation.bindings.bind
    calls = 0

    async def limited_source(*args, **kwargs):
        nonlocal calls
        calls += 1
        if boundary == "source" and calls == 1 or boundary == "final_source" and calls == 2:
            raise DeliveryRateLimited(1)
        return await original_source(*args, **kwargs)

    async def limited_snapshot(*args, **kwargs):
        raise DeliveryRateLimited(1)

    async def post_write(*args, **kwargs):
        await original_bind(*args, **kwargs)
        raise DeliveryRateLimited(1)

    confirmation.source = limited_source
    if boundary == "snapshot":
        execution.snapshot = limited_snapshot
    if boundary == "post_write":
        confirmation.bindings.bind = post_write
    current = message("!confirm", 2003)
    source.messages[current.message_id] = current
    try:
        with pytest.raises(
            DeliveryRateLimited if boundary == "post_write" else RoutingRateDeferred
        ):
            await router.route(current)
        async with db.sessions() as session:
            saved = await session.scalar(
                select(CommandReceipt).where(CommandReceipt.message_id == 2003)
            )
            token = await session.scalar(
                select(ControlToken).where(ControlToken.kind == "binding-confirm")
            )
            assert saved.state == ("ambiguous" if boundary == "post_write" else "deferred")
            assert token.used is (boundary == "post_write")
        assert await count(db, Binding) == (1 if boundary == "post_write" else 0)
        assert await count(db, Action) == 0
    finally:
        confirmation.source = original_source
        execution.snapshot = original_snapshot
        confirmation.bindings.bind = original_bind
    if boundary != "post_write":
        confirmed = await router.route(current)
        assert confirmed.binding_id and await count(db, Binding) == 1
        assert await router.route(current) == confirmed


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_menu_guidance_distinguishes_project_session_and_real_confirmation(db, locale):
    from unittest.mock import AsyncMock

    router, source, _, publisher, chat, workers = await pipeline(db)
    source.preferred_locale = AsyncMock(return_value=locale)
    projects = await send(router, source, message("!projects", 201))
    project_hint = "to choose a project" if locale == "en" else "選專案"
    session_hint = "to connect right away" if locale == "en" else "就會直接連上"
    assert project_hint in projects.text and session_hint not in projects.text
    assert "!ok" not in projects.text
    await show(source, publisher, chat, workers, projects)
    sessions = await send(router, source, message("!1", 2001))
    assert session_hint in sessions.text and project_hint not in sessions.text
    assert "`!1`" in sessions.text and "`!ok`" not in sessions.text
    warning = "Choose a conversation" if locale == "en" else "選擇對話"
    assert warning in sessions.text
    async with db.sessions() as session:
        tokens = list(await session.scalars(select(ControlToken)))
        assert not any(token.kind == "binding-confirm" for token in tokens)
    assert await count(db, Binding) == 0
    await show(source, publisher, chat, workers, sessions)
    preview = await send(router, source, long_form_preview(sessions, 2002))
    assert "!ok " in preview.text and not preview.binding_id
    await show(source, publisher, chat, workers, preview)
    confirmed = await send(router, source, message("!confirm", 2003))
    assert confirmed.binding_id and await count(db, Binding) == 1
    assert await count(db, Action) == 0


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_direct_discovery_entry_guidance_matches_actual_menu_not_fixed_step(db, locale):
    from unittest.mock import AsyncMock

    from tests.integration.test_unbound_router import choose, confirm_token, session_preview

    router, source, _, _, _, _ = await pipeline(db)
    source.preferred_locale = AsyncMock(return_value=locale)
    backend = await send(router, source, message("!backends", 101))
    assert ("to choose a backend" if locale == "en" else "選後端") in backend.text
    projects = await choose(router, source, backend, message_id=102)
    assert ("to choose a project" if locale == "en" else "選專案") in projects.text
    direct = await send(router, source, message("!sessions", 103))
    assert ("to choose a project" if locale == "en" else "選專案") in direct.text
    preview = await session_preview(router, source)
    final = await send(router, source, message("!oz confirm " + confirm_token(preview.text), 205))
    binding = await router.bindings.get(final.binding_id, "realm", 7)
    await router.bindings.unbind(binding.id, "realm", 7, binding.revision)
    recent = await send(router, source, message("!recent", 206))
    assert ("to connect right away" if locale == "en" else "就會直接連上") in recent.text
    warning = "Your recent conversations" if locale == "en" else "你最近連過的對話"
    assert warning in recent.text and "`!ok`" not in recent.text
    assert "1/3" not in recent.text
