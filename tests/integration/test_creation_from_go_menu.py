"""A new topic's menu also offers a fresh conversation; choosing it creates one Native Root.

Typed Native mock, real pipeline, router and encrypted SQL. All Humans are synthetic;
this is not installed, Human or mobile acceptance.
"""

import re
from html import unescape

from sqlalchemy import select, update

from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.models import Action
from tests.integration.test_creation_commands import close, environment, route


def shortcuts(e, monkeypatch):
    """`!N` resolves against the menu just shown; Zulip delivery is covered elsewhere."""
    unbound, shown = e["pipe"].router.unbound, {}
    original = unbound.menu

    async def menu(*args, **kwargs):
        result = await original(*args, **kwargs)
        shown["choose"] = result.shortcuts.choose
        return result

    async def token(message, kind):
        return shown[kind]

    monkeypatch.setattr(unbound, "menu", menu)
    monkeypatch.setattr(unbound.shortcuts, "token", token)


def new_row(text):
    rows = re.findall(r"(\d+)\. \*\*Start a brand-new conversation in project", unescape(text))
    assert len(rows) == 1, text
    return int(rows[0])


async def choose_new(e, monkeypatch, prompt="Check the security status", mid=200):
    shortcuts(e, monkeypatch)
    _, menu = await route(e, prompt, mid)
    assert menu.state == "reply" and not menu.binding_id
    row = new_row(menu.text)
    item, reply = await route(e, f"!{row}", mid + 1)
    assert reply.state == "ignore" and reply.action_id
    action, binding = await e["pipe"].creation.journal.load(reply.action_id)
    _, e["live_intent"], _ = e["pipe"].creation.journal.payload(action, binding)
    return row, item, reply, action


async def actions(db, operation):
    async with db.sessions() as session:
        return list(
            (await session.scalars(select(Action).where(Action.operation == operation))).all()
        )


async def test_number_on_the_new_row_creates_one_root_and_sends_the_opening_message(
    db, monkeypatch
):
    e = await environment(db)
    try:
        row, item, reply, action = await choose_new(e, monkeypatch)
        assert action.payload["menu_choice"] == row
        assert action.payload["prompt"]["text"] == "Check the security status"
        assert action.payload["intent"]["title"] is None
        assert not [m for m, _ in e["wire"] if m == "POST"]
        await e["pipe"].creation_commands.once()
        action, active = await e["pipe"].creation.journal.load(action.id)
        assert action.state == "completed" and active.state == "active"
        assert e["wire"].count(("POST", "/api/session")) == 1
        (prompt,) = await actions(db, "prompt")
        assert prompt.binding_id == active.id and prompt.state == "queued"
        assert prompt.payload["text"] == "Check the security status"
        # A replayed choice is the same reservation, never a second Root or prompt.
        again = await e["pipe"].router.route(item)
        assert again.action_id == reply.action_id
        await e["pipe"].creation_commands.once()
        assert len(await actions(db, "session.create")) == 1
        assert len(await actions(db, "prompt")) == 1
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


async def test_an_opening_message_edited_before_creation_is_not_sent(db, monkeypatch):
    e = await environment(db)
    try:
        *_, action = await choose_new(e, monkeypatch)
        original = e["source"].messages[200]
        e["source"].messages[200] = original.model_copy(
            update={"revision": 1, "text": "something else"}
        )
        await e["pipe"].creation_commands.once()
        action, active = await e["pipe"].creation.journal.load(action.id)
        assert action.state == "completed" and active.state == "active"
        assert not await actions(db, "prompt")
    finally:
        await close(e)


async def test_an_opening_message_left_for_long_is_not_sent_when_creation_finishes(db, monkeypatch):
    from jt_oz_bridge.services.session_creation_activation import FIRST_PROMPT_SECONDS

    e = await environment(db)
    try:
        *_, action = await choose_new(e, monkeypatch)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Action)
                .where(Action.id == action.id)
                .values(created_at=Action.created_at - FIRST_PROMPT_SECONDS - 1)
            )
        await e["pipe"].creation_commands.once()
        action, active = await e["pipe"].creation.journal.load(action.id)
        assert action.state == "completed" and active.state == "active"
        assert not await actions(db, "prompt")
    finally:
        await close(e)


async def test_go_command_offers_creation_without_carrying_a_prompt(db, monkeypatch):
    e = await environment(db)
    try:
        shortcuts(e, monkeypatch)
        _, menu = await route(e, "!go", 200)
        row = new_row(menu.text)
        _, reply = await route(e, f"!{row}", 201)
        action, _ = await e["pipe"].creation.journal.load(reply.action_id)
        assert "prompt" not in action.payload and action.payload["menu_choice"] == row
    finally:
        await close(e)


async def test_a_topic_with_a_reservation_cannot_reserve_again(db, monkeypatch):
    e = await environment(db)
    try:
        await choose_new(e, monkeypatch)
        _, menu = await route(e, "another message", 210)
        async with db.sessions() as session:
            reserved = (await session.scalars(select(Binding))).all()
        assert len(reserved) == 1 and len(await actions(db, "session.create")) == 1
        assert menu.action_id is None
    finally:
        await close(e)


async def test_plain_text_while_creating_shows_the_creation_status(db, monkeypatch):
    e = await environment(db)
    try:
        await choose_new(e, monkeypatch)
        _, status = await route(e, "are you there?", 210)
        assert "still creating its new conversation" in status.text
        assert "!no" in status.text and "!stop" in status.text and status.action_id is None
        assert len(await actions(db, "session.create")) == 1
        assert not await actions(db, "prompt")
    finally:
        await close(e)


async def test_an_opening_message_deleted_before_creation_never_strands_the_root(db, monkeypatch):
    from jt_oz_bridge.adapters.zulip.client import ZulipSourceUnavailable

    e = await environment(db)
    try:
        *_, action = await choose_new(e, monkeypatch)
        read = e["pipe"].source.read

        async def deleted(realm, message_id):
            if message_id == 200:
                raise ZulipSourceUnavailable("original_message_unavailable")
            return await read(realm, message_id)

        monkeypatch.setattr(e["pipe"].source, "read", deleted)
        monkeypatch.setattr(e["source"], "read", deleted)
        await e["pipe"].creation_commands.once()
        action, active = await e["pipe"].creation.journal.load(action.id)
        assert action.state == "completed" and active.state == "active"
        assert not await actions(db, "prompt")
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


async def test_a_project_channel_offers_no_other_projects_creation(db, monkeypatch):
    from types import MappingProxyType

    e = await environment(db)
    try:
        e["pipe"].discovery.channel_projects = MappingProxyType({10: frozenset({"elsewhere"})})
        shortcuts(e, monkeypatch)
        _, menu = await route(e, "!go", 200)
        assert "Start a new conversation" not in menu.text
        _, listed = await route(e, "!oz new", 201)
        assert "!oz new " not in listed.text and not await actions(db, "session.create")
    finally:
        await close(e)
