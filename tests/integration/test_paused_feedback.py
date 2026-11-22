"""Actual synthetic Router + SQL admission receipts; no live Human or Native IO."""

from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.models import Action
from tests.integration.test_router import message, router, send


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_paused_prompt_explains_preserved_not_started_and_resume_risk(db, locale):
    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding)
            .where(Binding.id == binding.id)
            .values(dispatch_paused=True, locale=locale)
        )
    response = await send(service, source, message("please answer", message_id=15001))
    async with db.sessions() as session:
        action = await session.get(Action, response.action_id)
        assert action.state == "held" and action.upstream_id is None
        saved = await session.get(Binding, binding.id)
        assert saved.dispatch_paused
    assert unescape(response.text) == service.tr.render("router.paused_input", locale)
    assert "!go" in response.text and "!no" in response.text
    assert all(call[0] == "snapshot" for call in control.calls)


async def test_a_conversation_gap_points_the_paused_reply_and_status_to_reconnect(db):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.storage.durable import Conflict

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    service.resume_guard = AsyncMock(
        side_effect=Conflict("transcript_gap_requires_review_and_rebind")
    )
    response = await send(service, source, message("hi", message_id=15010))
    assert unescape(response.text) == service.tr.render("router.paused_gap", "en")
    # One `!ok` reconnects; `!reconnect` is only the optional details view.
    assert "`!ok`" in response.text and "!reconnect" not in response.text
    status = await send(service, source, message("!status", message_id=15011))
    assert service.tr.render("router.gap_go", "en") in unescape(status.text)
    # `!go` on this path names the same next step, not "expired".
    go = await send(service, source, message("!go", message_id=15013))
    assert unescape(go.text) == service.tr.render("router.gap_go", "en")
    service.resume_guard = AsyncMock()
    status = await send(service, source, message("!status", message_id=15012))
    assert service.tr.render("router.gap_go", "en") not in unescape(status.text)


@pytest.mark.parametrize("pause_after_read", [True, False])
async def test_router_acknowledges_locked_admission_pause_even_when_initial_binding_changed(
    db, pause_after_read
):
    service, binding, source, control, audience = await router(db)
    if not pause_after_read:
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
            )
    original = service.queue.receive

    async def receive(*args, **kwargs):
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding)
                .where(Binding.id == binding.id)
                .values(dispatch_paused=pause_after_read)
            )
        return await original(*args, **kwargs)

    service.queue.receive = receive
    result = await send(service, source, message("preserve exact prompt", message_id=15002))
    key = "router.paused_input" if pause_after_read else "action.received"
    assert unescape(result.text) == service.tr.render(key, "en")
    async with db.sessions() as session:
        action = await session.get(Action, result.action_id)
        assert action.state == ("held" if pause_after_read else "queued")
        assert action.payload["text"] == "preserve exact prompt" and action.upstream_id is None
    assert all(call[0] == "snapshot" for call in control.calls)


@pytest.mark.parametrize("paused", [True, False])
async def test_original_queue_receipt_preserves_paused_admission_in_duplicate_and_edit(db, paused):
    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=paused)
        )
    item = message("first", message_id=15003)
    first = await service.queue.receive(binding.id, item)
    duplicate = await service.queue.receive(binding.id, item)
    edited = await service.queue.receive(
        binding.id, item.model_copy(update={"revision": 1, "text": "updated"})
    )
    assert first.action_id == duplicate.action_id == edited.action_id
    assert (
        first.paused_at_admission
        is duplicate.paused_at_admission
        is edited.paused_at_admission
        is paused
    )
    async with db.sessions() as session:
        rows = list((await session.scalars(select(Action))).all())
        assert len(rows) == 1 and rows[0].payload["text"] == "updated"
        assert rows[0].upstream_id is None
    assert all(call[0] == "snapshot" for call in control.calls)


def test_only_a_whole_yes_or_no_word_reads_as_a_bare_answer():
    from jt_oz_bridge.presentation.commands import bare_answer
    from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue

    for text in ("ok", "OK", " Okay! ", "好", "好的。", "yes~", "確認"):
        assert bare_answer(text) == "ok"
    for text in ("no", "No.", "不要", "取消！"):
        assert bare_answer(text) == "no"
    for text in ("!ok", "ok go ahead", "好，繼續", "nope", "@**Bot** ok", "", "3", "12", "1 2"):
        assert bare_answer(text) is None
    # A lone 1 or 2 picks a notice's first or second button by number.
    assert [bare_answer(text) for text in ("1", "2", "１", " 2。")] == ["ok", "no", "ok", "no"]
    # The original router decides, since only it can see an open question.
    assert not ClosedBoundQueue.eligible(message("ok"))
    assert ClosedBoundQueue.eligible(message("ok go ahead"))


async def test_a_bare_ok_during_a_gap_asks_instead_of_holding_the_word(db):
    import json
    from unittest.mock import AsyncMock

    from jt_oz_bridge.storage.durable import Conflict

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    service.resume_guard = AsyncMock(
        side_effect=Conflict("transcript_gap_requires_review_and_rebind")
    )
    asked = await send(service, source, message("OK", message_id=15020))
    assert asked.state == "reply"
    assert unescape(asked.text) == service.tr.render("router.bare_answer_ok", "en", word="OK")
    assert "`!ok`" in asked.text and "`!no`" in asked.text and "`!send OK`" in asked.text
    replies = [c["reply"] for c in json.loads(asked.widget)["extra_data"]["choices"]]
    assert replies == ["!ok", "!no", "!send OK"]
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []
    # `!send` still hands the same word to the AI, held behind the pause as before.
    sent = await send(service, source, message("!send OK", message_id=15021))
    async with db.sessions() as session:
        action = await session.get(Action, sent.action_id)
        assert action.state == "held" and action.payload["text"] == "OK"
    assert all(call[0] == "snapshot" for call in control.calls)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_a_bare_answer_to_an_open_question_asks_and_otherwise_reaches_the_ai(db, locale):
    from jt_oz_bridge.domain.schedules import SCHEDULE_TOKEN

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).where(Binding.id == binding.id).values(locale=locale))
    plain = await send(service, source, message("好", message_id=15030))
    async with db.sessions() as session:
        first = await session.get(Action, plain.action_id)
        assert first.state == "queued" and first.payload["text"] == "好"
    await service.tokens.issue(
        SCHEDULE_TOKEN,
        "realm",
        7,
        {},
        binding_id=binding.id,
        binding_revision=binding.revision,
    )
    asked = await send(service, source, message("不要", message_id=15031))
    assert unescape(asked.text) == service.tr.render("router.bare_answer_no", locale, word="不要")
    assert asked.action_id is None and asked.widget is not None
    # Someone else's open question is not this person's to answer.
    other = await send(service, source, message("ok", message_id=15032, author_id=8))
    assert other.text != asked.text
    declined = await send(service, source, message("!no", message_id=15033))
    assert unescape(declined.text) == service.tr.render("router.declined", locale)
    after = await send(service, source, message("ok", message_id=15034))
    async with db.sessions() as session:
        assert (await session.get(Action, after.action_id)).payload["text"] == "ok"
    assert all(call[0] == "snapshot" for call in control.calls)


def buttons(widget):
    import json

    return [c["reply"] for c in json.loads(widget)["extra_data"]["choices"]]


async def test_pause_and_stop_notices_carry_desktop_buttons_for_their_commands(db):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.storage.durable import Conflict

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    held = await send(service, source, message("please wait", message_id=15040))
    assert unescape(held.text) == service.tr.render("router.paused_input", "en")
    assert buttons(held.widget) == ["!go", "!no"]
    service.resume_guard = AsyncMock(
        side_effect=Conflict("transcript_gap_requires_review_and_rebind")
    )
    gap = await send(service, source, message("and this", message_id=15041))
    assert buttons(gap.widget) == ["!ok", "!no"]
    go = await send(service, source, message("!go", message_id=15042))
    assert unescape(go.text) == service.tr.render("router.gap_go", "en")
    assert buttons(go.widget) == ["!ok"]
    # A replayed command keeps the same buttons.
    assert (await service.route(source.messages[15042])).widget == go.widget
    service.resume_guard = AsyncMock()
    stop = await send(service, source, message("!stop", message_id=15043))
    # Messages queued before the stop are sent or dropped; a new one just goes.
    assert buttons(stop.widget) == ["!go", "!no"]
    # Help and other replies stay plain.
    assert (await send(service, source, message("!help", message_id=15044))).widget is None
    assert all(call[0] == "snapshot" for call in control.calls)


@pytest.mark.parametrize("kind", ["form", "permission"])
async def test_a_bare_answer_while_the_ai_asks_points_to_pending_not_ok(db, kind):
    import time

    from jt_oz_bridge.services.interactions import short_code
    from jt_oz_bridge.storage.control_models import PendingInteraction

    service, binding, source, control, audience = await router(db)
    row = PendingInteraction(
        identity_key="bare-" + kind,
        binding_id=binding.id,
        binding_revision=binding.revision,
        snapshot={"kind": kind},
        snapshot_hash="0" * 64,
        state="pending",
        expires_at=time.time() + 900,
    )
    async with db.sessions.begin() as session:
        session.add(row)
    asked = await send(service, source, message("好", message_id=15050))
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []
    if kind == "form":
        # A question is answered with `!a`, which `!pending` shows.
        assert unescape(asked.text) == service.tr.render(
            "router.bare_answer_question", "en", word="好"
        )
        assert buttons(asked.widget) == ["!pending", "!send 好"]
    else:
        # A permission takes its code; a plain `!ok` button would do nothing.
        code = short_code(row.id)
        assert unescape(asked.text) == service.tr.render(
            "router.bare_answer_permission", "en", word="好", code=code
        )
        assert buttons(asked.widget) == [f"!ok {code}", f"!no {code}", "!send 好"]
    assert all(call[0] == "snapshot" for call in control.calls)


@pytest.mark.parametrize("word", ["好", "no"])
async def test_the_buttons_under_a_bare_answer_decide_the_one_waiting_permission(db, word):
    from jt_oz_bridge.services.interactions import short_code
    from tests.integration.test_permission_commands import pending

    service, binding, source, control, audience = await router(db)
    identity = await pending(service, control)
    code = short_code(identity)
    asked = await send(service, source, message(word, message_id=15070))
    assert buttons(asked.widget) == [f"!ok {code}", f"!no {code}", f"!send {word}"]
    assert f"`!ok {code}`" in asked.text and f"`!no {code}`" in asked.text
    # Tapping a button sends its reply as the person's own message.
    tapped = await send(service, source, message(buttons(asked.widget)[0], message_id=15071))
    assert "Received" in tapped.text
    async with db.sessions() as session:
        (action,) = (await session.scalars(select(Action))).all()
    assert action.payload["decision"] == "once"


async def test_a_bare_answer_with_several_requests_waiting_lists_them_instead(db):
    from tests.integration.test_permission_commands import pending

    service, binding, source, control, audience = await router(db)
    await pending(service, control, "first")
    await pending(service, control, "second", resources=("ruff check", "/workspace/project"))
    asked = await send(service, source, message("ok", message_id=15080))
    assert unescape(asked.text) == service.tr.render("router.bare_answer_several", "en", word="ok")
    assert buttons(asked.widget) == ["!pending", "!send ok"]
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []


async def test_an_edit_of_an_asked_about_ok_never_reaches_the_ai(db):
    from jt_oz_bridge.domain.schedules import SCHEDULE_TOKEN

    service, binding, source, control, audience = await router(db)
    await service.tokens.issue(
        SCHEDULE_TOKEN, "realm", 7, {}, binding_id=binding.id, binding_revision=binding.revision
    )
    first = message("ok", message_id=15060)
    asked = await send(service, source, first)
    assert unescape(asked.text) == service.tr.render("router.bare_answer_ok", "en", word="ok")
    # The same event again gives the same reply and still sends nothing.
    again = await service.route(first)
    assert (again.text, again.widget) == (asked.text, asked.widget)
    edited = await send(
        service, source, first.model_copy(update={"revision": 1, "text": "ok, but use the old one"})
    )
    assert unescape(edited.text) == service.tr.render("router.changed", "en")
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []
    assert all(call[0] == "snapshot" for call in control.calls)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_status_says_how_to_answer_what_waits(db, locale):
    from jt_oz_bridge.services.interactions import short_code
    from tests.integration.test_permission_commands import pending

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).where(Binding.id == binding.id).values(locale=locale))
    plain = await send(service, source, message("!status", message_id=15090))
    assert "!pending" not in plain.text
    identity = await pending(service, control)
    one = await send(service, source, message("!status", message_id=15091))
    note = service.tr.render("router.status_permission", locale, code=short_code(identity))
    assert note in unescape(one.text)
    await pending(service, control, "second", resources=("ruff check", "/workspace/project"))
    several = await send(service, source, message("!status", message_id=15092))
    assert service.tr.render("router.status_pending", locale) in unescape(several.text)
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []


def test_go_new_is_its_own_choice_only_in_a_connected_topic():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input

    for text in ("!go new", "!go 新的", "!go 只送新的", "!go NEW"):
        assert parse_input(text, bound=True) == ParsedInput("command", "queue", "resume new")
    # Before a topic is connected, the word still searches conversations.
    assert parse_input("!go new", bound=False) == ParsedInput("command", "go", "new")
    assert parse_input("!go newer", bound=True).command == "go"


async def test_status_offers_go_new_when_old_and_new_messages_both_wait(db):
    import time

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    for message_id, text in ((15100, "old ok"), (15101, "new hi")):
        held = await send(service, source, message(text, message_id=message_id))
        assert held.state == "reply"
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(
                Action.id
                == (await session.scalars(select(Action.id).order_by(Action.created_at))).first()
            )
            .values(created_at=time.time() - 7200)
        )
    status = await send(service, source, message("!status", message_id=15102))
    assert service.tr.render("router.held_hint_old", "en") in unescape(status.text)
    assert buttons(status.widget) == ["!go new", "!go", "!no"]
    went = await send(service, source, message("!go new", message_id=15103))
    assert unescape(went.text) == service.tr.render("router.resumed_new", "en", count="1")
    async with db.sessions() as session:
        states = {a.payload["text"]: a.state for a in (await session.scalars(select(Action))).all()}
    assert states == {"old ok": "cancelled", "new hi": "queued"}
    assert all(call[0] == "snapshot" for call in control.calls)


def test_a_mistyped_everyday_command_is_caught_but_other_bang_text_is_not():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input, typo_of

    assert parse_input("!stauts", bound=True) == ParsedInput("unknown", "stauts", "!status")
    assert parse_input("!comit fix the test", bound=True) == ParsedInput(
        "unknown", "comit", "!commit fix the test"
    )
    assert parse_input("!sotp", bound=True).arguments == "!stop"
    # One wrong letter in a short word is too often a real word.
    for text in ("!stoa", "!hell yes", "!ozone", "!important: read this", "!stauts\nmore"):
        assert parse_input(text, bound=True).kind == "prompt", text
    # Ambiguous or unconnected: nothing is guessed.
    assert typo_of("fiel") == "file" and typo_of("filse") == "files"
    assert parse_input("!stauts", bound=False).kind == "ignore"


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_a_mistyped_command_asks_and_its_buttons_send_either_one(db, locale):
    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).where(Binding.id == binding.id).values(locale=locale))
    asked = await send(service, source, message("!stauts", message_id=15110))
    assert unescape(asked.text) == service.tr.render(
        "router.typo", locale, typed="!stauts", meant="!status"
    )
    assert buttons(asked.widget) == ["!status", "!send !stauts"]
    # The same event again gives the same reply.
    again = await service.route(message("!stauts", message_id=15110))
    assert (again.text, again.widget) == (asked.text, asked.widget)
    sent = await send(service, source, message(buttons(asked.widget)[1], message_id=15111))
    async with db.sessions() as session:
        (action,) = (await session.scalars(select(Action))).all()
    assert action.payload["text"] == "!stauts" and sent.action_id == action.id


def test_a_full_width_bang_from_a_chinese_keyboard_is_a_command_too():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input

    assert parse_input("！ok 1234", bound=True) == ParsedInput("command", "approve", "1234 once")
    assert parse_input("！status", bound=True) == ParsedInput("command", "status")
    assert parse_input("@**jt-oz-bridge** ！stop", bound=True).command == "stop"
    assert parse_input("！2", bound=True) == ParsedInput("command", "choose", "2")
    assert parse_input("！new", bound=False).command == "new"
    # Text that is no command still reaches the AI exactly as typed.
    assert parse_input("！好棒", bound=True) == ParsedInput("prompt", arguments="！好棒")
    assert parse_input("！send ！stop", bound=True) == ParsedInput("prompt", arguments="！stop")
    assert parse_input("ok！", bound=True).kind == "prompt"
    assert parse_input("！好棒", bound=False).kind == "ignore"


def test_help_for_a_mistyped_word_explains_the_word_meant():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input

    assert parse_input("!help stauts", bound=True) == ParsedInput("command", "help", "status")
    assert parse_input("!help me", bound=True).kind == "prompt"


async def test_a_full_width_status_and_typo_reply_like_their_ascii_forms(db):
    service, binding, source, control, audience = await router(db)
    wide = await send(service, source, message("！status", message_id=15120))
    ascii_ = await send(service, source, message("!status", message_id=15121))
    assert wide.text == ascii_.text
    asked = await send(service, source, message("！stauts", message_id=15122))
    assert buttons(asked.widget) == ["!status", "!send ！stauts"]
    helped = await send(service, source, message("!help stauts", message_id=15123))
    plain = await send(service, source, message("!help status", message_id=15124))
    assert helped.text == plain.text
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []


def test_a_capitalized_command_word_from_a_phone_keyboard_is_a_command_too():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input

    assert parse_input("!OK 1234", bound=True) == ParsedInput("command", "approve", "1234 once")
    assert parse_input("!Status", bound=True) == ParsedInput("command", "status")
    assert parse_input("！Go New", bound=True) == ParsedInput("command", "queue", "resume new")
    assert parse_input("!New", bound=False).command == "new"
    # Only the command word is folded; what follows keeps its case.
    assert parse_input("!Commit Fix the README", bound=True).arguments == (
        "commit -m 'Fix the README'"
    )
    assert parse_input("!Send Hello", bound=True) == ParsedInput("prompt", arguments="Hello")
    assert parse_input("!Important: read this", bound=True) == ParsedInput(
        "prompt", arguments="!Important: read this"
    )


def test_a_lone_command_with_input_method_punctuation_or_widths_is_a_command_too():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input

    # A Chinese input method closes with `。`, writes full-width letters and spaces;
    # a phone keyboard may put a space after the `!`.
    assert parse_input("!stop。", bound=True) == ParsedInput("command", "stop")
    assert parse_input("!ok!", bound=True) == ParsedInput("command", "confirm")
    assert parse_input("!status？", bound=True) == ParsedInput("command", "status")
    assert parse_input("! status", bound=True) == ParsedInput("command", "status")
    assert parse_input("！　ｓｔａｔｕｓ", bound=True) == ParsedInput("command", "status")
    assert parse_input("!ok 1234。", bound=True) == ParsedInput("command", "approve", "1234 once")
    assert parse_input("!ｏｋ　１２３４", bound=True) == ParsedInput(
        "command", "approve", "1234 once"
    )
    assert parse_input("!go！", bound=True) == ParsedInput("command", "queue", "resume")
    assert parse_input("!2。", bound=True) == ParsedInput("command", "choose", "2")
    assert parse_input("@**jt-oz-bridge** !stop。", bound=True).command == "stop"
    assert parse_input("!new。", bound=False).command == "new"
    assert parse_input("!stauts。", bound=True) == ParsedInput("unknown", "stauts", "!status")
    # Only a lone word (and code) is read so; other text keeps its punctuation or goes on.
    assert parse_input("!hi.", bound=True) == ParsedInput("prompt", arguments="!hi.")
    assert parse_input("! next step please", bound=True) == ParsedInput(
        "prompt", arguments="! next step please"
    )
    assert parse_input("!rename Foo.", bound=True) == ParsedInput("command", "rename", "Foo.")
    assert parse_input("!no 1234 不要。", bound=True).arguments == "1234 不要。"
    assert parse_input("!status。", bound=False).kind == "ignore"


async def test_a_status_with_a_closing_full_stop_replies_like_status(db):
    service, binding, source, control, audience = await router(db)
    closed = await send(service, source, message("!status。", message_id=15130))
    plain = await send(service, source, message("!status", message_id=15131))
    assert closed.text == plain.text
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []


async def test_a_lone_number_under_the_reconnect_notice_asks_instead_of_holding_it(db):
    # Under the paused notice's "1 重新接上 / 2 丟掉" buttons, a lone "1" must not be
    # held as a prompt and later refused instead of reconnecting.
    from unittest.mock import AsyncMock

    from jt_oz_bridge.storage.durable import Conflict

    service, binding, source, control, audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    service.resume_guard = AsyncMock(
        side_effect=Conflict("transcript_gap_requires_review_and_rebind")
    )
    asked = await send(service, source, message("1", message_id=15140))
    assert unescape(asked.text) == service.tr.render("router.bare_answer_ok", "en", word="1")
    assert buttons(asked.widget) == ["!ok", "!no", "!send 1"]
    async with db.sessions() as session:
        assert list((await session.scalars(select(Action))).all()) == []
    # Any other number is ordinary text, held behind the pause as before.
    held = await send(service, source, message("3", message_id=15141))
    async with db.sessions() as session:
        assert (await session.get(Action, held.action_id)).state == "held"
