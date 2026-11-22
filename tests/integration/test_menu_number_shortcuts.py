"""`!N` picks row N of this person's latest visible menu in a connected topic.

Phones show no buttons, so `!N` runs the command that row's button would have sent,
with every check that command has when typed. Real ownDB, router, outbox and
dispatcher; synthetic Zulip and Native only. Not Human or mobile evidence.
"""

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.services.menu_shortcuts import expand
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import RoutedInput
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Delivery
from tests.integration.test_model_commands import rows, setup, tokens
from tests.integration.test_native_history import history, profile  # noqa: F401
from tests.integration.test_permission_commands import pending
from tests.integration.test_router import message, router, send


async def shown(service, routed, posted):
    """Publish a routed reply and record every page as posted with that Zulip id."""
    outbox = Outbox(service.bindings, 77, fence=service.inbox.fence)
    publisher = RoutedOutbox(outbox, realm_id="realm", message_limit=10000, topic_limit=100)
    batch = await publisher.publish(routed)
    async with service.db.sessions.begin() as session:
        await session.execute(
            update(Delivery)
            .where(Delivery.id.in_(batch.deliveries))
            .values(state="delivered", posted_message_id=posted)
        )
    return routed


def test_expansion_only_ever_turns_a_number_into_its_saved_command():
    assert expand("!2", None).command == "choose"
    assert expand("!2", "!oz model " + "A" * 32).arguments == "A" * 32
    for text, row in [
        ("!oz model " + "A" * 32, "!oz model " + "A" * 32),  # not a number
        ("!2", "!3"),  # a row can never be another shortcut
        ("!2", "just text for the AI"),  # a row is always a command
    ]:
        with pytest.raises(Conflict):
            expand(text, row)


async def test_number_runs_the_row_of_the_latest_visible_menu(db):
    service, _binding, source, control, _audience = await router(db)
    menu = await send(service, source, message("!oz menu"))
    assert "Reply `!1`–`!6` to choose." in menu.text
    await shown(service, menu, 150)
    status = await send(service, source, message("!2", 151))
    assert status.text == (await send(service, source, message("!oz status", 152))).text
    # A newer menu replaces the older one; `!1` now opens the first pending request.
    await pending(service, control)
    listed = await shown(service, await send(service, source, message("!oz pending", 153)), 160)
    opened = await send(service, source, message("!1", 161))
    assert "Operation:" in opened.text and opened.text != listed.text


async def test_number_without_a_menu_seen_first_runs_nothing(db):
    service, _binding, source, _control, _audience = await router(db)
    nothing = await send(service, source, message("!2"))
    assert "no menu to pick from by number" in nothing.text
    menu = await send(service, source, message("!oz menu", 102))
    # Not posted yet: the person cannot have seen it.
    assert "no menu" in (await send(service, source, message("!2", 103))).text
    # Posted only after the `!N`: still not what that person saw.
    await shown(service, menu, 200)
    assert "no menu" in (await send(service, source, message("!2", 104))).text
    # Those failed numbers were the last commands, so the menu must be opened again.
    assert "no menu" in (await send(service, source, message("!2", 201))).text
    again = await shown(service, await send(service, source, message("!oz menu", 202)), 210)
    status = await send(service, source, message("!2", 211))
    assert again.widget is not None and "Conversation" in status.text


async def test_anything_after_the_menu_closes_it(db):
    service, _binding, source, _control, _audience = await router(db)
    # Another command, even one without numbered rows, is the newer thing on screen.
    await shown(service, await send(service, source, message("!oz menu")), 150)
    await shown(service, await send(service, source, message("!oz status", 151)), 152)
    assert "no menu" in (await send(service, source, message("!2", 153))).text
    # Any other post here after the menu (a notice, an AI reply) also closes it.
    await shown(service, await send(service, source, message("!oz menu", 154)), 160)
    notice = RoutedInput(
        "reply", _binding.id, _binding.revision, "OpenCode needs your input", "notice:x"
    )
    await shown(service, notice, 161)
    assert "no menu" in (await send(service, source, message("!2", 162))).text
    # A post still being sent may already be visible: that closes it too.
    await shown(service, await send(service, source, message("!oz menu", 163)), 170)
    sending = RoutedInput("reply", _binding.id, _binding.revision, "Working", "notice:y")
    batch = await RoutedOutbox(
        Outbox(service.bindings, 77, fence=service.inbox.fence),
        realm_id="realm",
        message_limit=10000,
        topic_limit=100,
    ).publish(sending)
    async with service.db.sessions.begin() as session:
        await session.execute(
            update(Delivery).where(Delivery.id.in_(batch.deliveries)).values(state="sending")
        )
    assert "no menu" in (await send(service, source, message("!2", 171))).text


async def test_number_is_this_actors_own_menu_and_must_be_in_range(db):
    service, _binding, source, _control, _audience = await router(db)
    menu = await shown(service, await send(service, source, message("!oz menu")), 150)
    other = await send(service, source, message("!2", 151, author_id=8))
    assert "no menu" in other.text
    too_far = await send(service, source, message("!9", 152))
    assert too_far.text == service.tr.render("router.usage", "en")
    # Opening another menu without numbered rows closes the older one.
    await shown(service, await send(service, source, message("!oz history", 153)), 160)
    assert "no menu" in (await send(service, source, message("!2", 161))).text
    assert menu.widget is not None


async def test_number_switches_the_model_with_every_dispatch_check(db):
    router_, binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    providers = await shown(router_, await send(router_, source, message("!oz models", 101)), 110)
    assert "`!1`" in providers.text
    page = await shown(router_, await send(router_, source, message("!1", 111)), 120)
    choices = tokens(page.text, "model")
    assert len(choices) == 9 and "Reply `!1`–`!9` to choose." in page.text
    queued = await send(router_, source, message("!2", 121))
    assert "Received and queued" in queued.text
    (action,) = await rows(db, Action)
    assert action.payload["shortcut"] == f"!oz model {choices[1]}"
    assert action.payload["selection"]["target"]["model_id"] == "hf.co/Team/Model-01:Q4"
    # Output still being sent when dispatch runs (the "queued" reply, an AI answer)
    # came after the `!N`; it must not hold the switch.
    batch = await RoutedOutbox(
        Outbox(router_.bindings, 77, fence=router_.inbox.fence),
        realm_id="realm",
        message_limit=10000,
        topic_limit=100,
    ).publish(queued)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Delivery).where(Delivery.id.in_(batch.deliveries)).values(state="sending")
        )
    assert await worker.advance(action.id) == "completed" and len(execution.submitted) == 1
    # That choice was the last command: another number needs the menu again.
    assert "no menu" in (await send(router_, source, message("!3", 130))).text
    assert binding.id == action.binding_id and len(await rows(db, Action)) == 1


async def test_dispatch_holds_a_number_whose_menu_changed_after_queueing(db):
    router_, _binding, source, _catalog, execution, _commands, worker, _audience = await setup(db)
    providers = await shown(router_, await send(router_, source, message("!oz models", 101)), 110)
    await shown(router_, await send(router_, source, message("!1", 111)), 120)
    await send(router_, source, message("!2", 121))
    (action,) = await rows(db, Action)
    async with db.sessions.begin() as session:
        receipt = await session.scalar(
            select(CommandReceipt).where(CommandReceipt.message_id == 111)
        )
        receipt.response = {
            **receipt.response,
            "shortcuts": list(reversed(receipt.response["shortcuts"])),
        }
    assert await worker.advance(action.id) == "held"
    assert not execution.submitted and providers.widget is not None


async def test_number_opens_a_saved_reply_from_the_history_menu(db, profile):  # noqa: F811
    router_, _binding, source, transport, _stored, _seen = await history(db, profile)
    try:
        menu = await shown(router_, await send(router_, source, message("!oz history")), 150)
        assert "Reply `!1`–`!2` to choose." in menu.text
        reply = await send(router_, source, message("!1", 151))
        assert "Native reply two" in reply.text and "Native reply one" not in reply.text
    finally:
        await transport.close()


async def test_a_channel_button_click_runs_the_row_after_its_bot_mention(db):
    service, _binding, source, _control, _audience = await router(db)
    await shown(service, await send(service, source, message("!oz menu")), 150)
    clicked = await send(service, source, message("@**jt-oz-bridge** !2", 151))
    assert "Conversation" in clicked.text
