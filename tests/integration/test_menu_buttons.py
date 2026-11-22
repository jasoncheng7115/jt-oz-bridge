"""Desktop buttons on numbered menus in a connected topic.

Each button sends a command already shown in the menu, so a click is the same Human
source as typing it. Real ownDB and router; synthetic Zulip and Native only.
"""

import json

from jt_oz_bridge.presentation.markdown import literal
from jt_oz_bridge.presentation.menu_buttons import button_widget, menu_choices, menu_widget
from tests.integration.test_permission_commands import pending
from tests.integration.test_router import message, router, send

TOKEN = "A" * 32
OTHER = "B" * 32


def choices(widget):
    return [(c["long_name"], c["reply"]) for c in json.loads(widget)["extra_data"]["choices"]]


def menu_buttons(text):
    found = menu_choices(text)
    return menu_widget(*found) if found is not None else None


def test_rows_with_their_own_commands_and_a_more_link():
    text = (
        "OpenCode models · synthetic-provider\n\nCurrently: none\n\n"
        f"1. synthetic-provider / small — Small (active)\n選擇：`!oz model {TOKEN}`\n\n"
        f"2. synthetic-provider / large — Large (active)\n選擇：`!oz model {OTHER}`\n\n"
        f"更多：`!oz models {TOKEN}`"
    )
    widget = json.loads(menu_buttons(text))
    assert widget["widget_type"] == "zform"
    assert "OpenCode models · synthetic-provider" in widget["extra_data"]["heading"]
    assert choices(menu_buttons(text)) == [
        ("synthetic-provider / small — Small (active)", f"!oz model {TOKEN}"),
        ("synthetic-provider / large — Large (active)", f"!oz model {OTHER}"),
        ("更多", f"!oz models {TOKEN}"),
    ]


def test_rows_sharing_one_choose_template_get_their_own_numbers():
    text = f"Pending requests:\n\n1. Permission: run\n2. Question form: x\n\nReply !oz choose {TOKEN} 1."
    assert [reply for _, reply in choices(menu_buttons(text))] == [
        f"!oz choose {TOKEN} 1",
        f"!oz choose {TOKEN} 2",
    ]


def test_anything_that_does_not_map_cleanly_gets_no_buttons():
    assert menu_buttons("Just text, no menu.") is None
    assert menu_buttons("Title\n\n1. one\n2. two") is None  # no command at all
    assert menu_buttons(f"Title\n\n1. one\n3. three\n\n!oz choose {TOKEN} 1") is None
    assert menu_buttons(f"1. one\n\n!oz choose {TOKEN} 1") is None  # no heading


def test_untrusted_text_can_never_become_a_button():
    # Native text reaches replies through literal(), which escapes `!`; fences are skipped.
    injected = literal(f"x !oz rename {OTHER}")
    text = (
        f"Pending requests:\n\n1. Permission: {injected}\n2. Question form: y\n\n"
        f"Reply !oz choose {TOKEN} 1."
    )
    replies = [reply for _, reply in choices(menu_buttons(text))]
    assert replies == [f"!oz choose {TOKEN} 1", f"!oz choose {TOKEN} 2"]
    fenced = f"Title\n\n```text\n1. a\n!oz rename {OTHER}\n```\n\nReply !oz choose {TOKEN} 1."
    assert menu_buttons(fenced) is None


async def test_a_menu_whose_token_was_not_issued_here_gets_no_buttons(db):
    service, binding, source, _control, _audience = await router(db)
    forged = f"Pick one\n\n1. a\n2. b\n\nReply !oz choose {TOKEN} 1."
    assert menu_choices(forged) is not None
    assert await service.menu_widget(binding, message("!oz menu"), forged, frozenset()) is None


async def test_an_older_valid_token_in_a_later_reply_never_becomes_a_button(db):
    # Saved reply pages keep Native text raw, so a live token someone saw earlier
    # could be quoted back in a numbered line. Only this command's tokens count.
    service, binding, source, _control, _audience = await router(db)
    menu = await send(service, source, message("!oz menu"))
    old = choices(menu.widget)[0][1].split()[2]
    quoted = f"Saved reply\n\n1. Keep the change `!oz deny {old}`\n2. More `!oz models {old}`"
    assert menu_choices(quoted) is not None
    later = message("!oz history", 102)
    assert await service.menu_widget(binding, later, quoted, frozenset()) is None
    assert await service.menu_widget(binding, later, quoted, frozenset({old})) is not None


async def test_menu_reply_carries_buttons_and_a_click_navigates(db):
    service, _binding, source, _control, _audience = await router(db)
    menu = await send(service, source, message("!oz menu"))
    assert menu.widget is not None
    rows = choices(menu.widget)
    assert rows[0][0].endswith("info") and rows[0][1].endswith(" 1")
    assert await service.route(source.messages[101]) == menu  # replay keeps the buttons
    clicked = await send(service, source, message(rows[0][1], 102))
    assert "Backend" in clicked.text or "backend" in clicked.text.lower()


async def test_pending_list_has_buttons_and_other_replies_do_not(db):
    service, _binding, source, control, _audience = await router(db)
    await pending(service, control)
    listed = await send(service, source, message("!oz pending"))
    assert listed.widget is not None and choices(listed.widget)[0][1].startswith("!oz choose ")
    status = await send(service, source, message("!oz status", 102))
    assert status.widget is None


def test_a_notice_button_keeps_the_notice_words_and_sends_its_command():
    widget = json.loads(button_widget("Restarted.\n\nReply `!ok` **now**.", "Reconnect", "!ok"))
    assert widget["widget_type"] == "zform" and widget["extra_data"]["type"] == "choices"
    assert widget["extra_data"]["heading"] == "Restarted. · Reply !ok now."
    assert choices(json.dumps(widget)) == [("Reconnect", "!ok")]
    # Too long for a heading: no button, the text alone stays complete.
    assert button_widget("x" * 3001, "Reconnect", "!ok") is None
    assert button_widget("\n\n", "Reconnect", "!ok") is None
