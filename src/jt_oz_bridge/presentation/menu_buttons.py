"""Desktop buttons for a numbered chat menu; each click sends a command shown in the menu.

Most untrusted text reaches a reply through `literal()`, which writes `!` as an entity,
and fenced blocks are skipped. That alone is not a guarantee: saved reply pages and code
spans keep Native text raw. The router therefore also requires every button token to
be one minted while this very command ran, for this actor and binding; stored text
cannot contain those. Anything that does not map cleanly gets no buttons.
"""

import html
import json
import re
from collections.abc import Callable

ROW = re.compile(r"^(\d{1,2})\. (.+)$")
TOKEN = r"((?:[A-Za-z0-9_-]|&#45;|&#95;)+)"
COMMAND = re.compile(r"!oz ([a-z-]+) " + TOKEN)
TEMPLATE = re.compile(r"!oz (choose|history) " + TOKEN + r" (?:1|<[^>\n]{1,20}>)")
VALID = re.compile(r"[A-Za-z0-9_-]{32}")
MARKUP = re.compile(r"[*`]")
LIMIT = 3000

Choice = tuple[str, str, str]  # label, reply, token


def _plain(text: str) -> str:
    return " ".join(MARKUP.sub("", html.unescape(text)).split())


def _command(match: re.Match[str]) -> tuple[str, str] | None:
    token = html.unescape(match[2])
    if not VALID.fullmatch(token):
        return None
    return f"!oz {match[1]} {token}", token


def menu_choices(text: str) -> tuple[str, list[Choice]] | None:
    """The menu's heading and one (label, reply, token) per row, or None."""
    found = numbered_menu(text)
    return None if found is None else (found[0], found[1])


def numbered_menu(text: str) -> tuple[str, list[Choice], int] | None:
    """Like menu_choices, plus how many leading choices are the numbered rows."""
    rows: list[tuple[int, str, tuple[str, str] | None]] = []
    extras: list[Choice] = []
    heading: list[str] = []
    template: tuple[str, str] | None = None
    attach = fenced = False
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fenced, attach = not fenced, False
            continue
        if fenced:
            continue
        numbered = ROW.match(stripped)
        shared = TEMPLATE.search(stripped)
        command = None if shared else COMMAND.search(stripped)
        found = _command(command) if command else None
        if command and found is None:
            return None
        if shared:
            if template is not None or (template := _command(shared)) is None:
                return None
            attach = False
        elif numbered:
            label = (
                numbered[2][: command.start() - len(numbered[1]) - 2] if command else numbered[2]
            )
            rows.append((int(numbered[1]), _plain(label), found))
            attach = found is None
        elif found and attach and rows:
            rows[-1] = (*rows[-1][:2], found)
            attach = False
        elif found:
            assert command is not None
            label = _plain(stripped[: command.start()]).rstrip("：: ")
            extras.append((label or found[0].split()[1], *found))
            attach = False
        else:
            attach = False
            if not rows and stripped:
                heading.append(_plain(stripped))
    if not 1 <= len(rows) <= 10 or [row[0] for row in rows] != list(range(1, len(rows) + 1)):
        return None
    choices: list[Choice] = []
    for number, label, found in rows:
        if found is None:
            if template is None:
                return None
            found = (f"{template[0]} {number}", template[1])
        choices.append((label[:200] or str(number), *found))
    choices += [(label[:200], reply, token) for label, reply, token in extras][: 10 - len(choices)]
    title = " · ".join(heading)
    if not title or len(title) > LIMIT:
        return None
    return title, choices, len(rows)


def menu_widget(heading: str, choices: list[Choice]) -> str:
    return json.dumps(
        {
            "widget_type": "zform",
            "extra_data": {
                "type": "choices",
                "heading": heading,
                "choices": [
                    {
                        "type": "multiple_choice",
                        "short_name": str(index),
                        "long_name": label,
                        "reply": reply,
                    }
                    for index, (label, reply, _token) in enumerate(choices, 1)
                ],
            },
        },
        ensure_ascii=False,
    )


def button_widget(text: str, label: str, reply: str) -> str | None:
    """One button under a short Bridge notice; web clients show it in place of the text.

    The heading carries the notice's own words, so nothing is lost on desktop; phones
    show the text, whose typed command does the same thing.
    """
    return buttons_widget(text, [(label, reply)])


def buttons_widget(text: str, buttons: list[tuple[str, str]]) -> str | None:
    """Like button_widget, with one button per (label, reply)."""
    heading = " · ".join(line for line in map(_plain, text.split("\n")) if line)
    if not heading or len(heading) > LIMIT or not 1 <= len(buttons) <= 10:
        return None
    return menu_widget(heading, [(label[:200], reply, "") for label, reply in buttons])


# Short Bridge notices whose typed commands also get desktop buttons: (label key, reply).
NOTICE_BUTTONS: dict[str, tuple[tuple[str, str], ...]] = {
    "router.paused_input": (("button.go", "!go"), ("button.drop", "!no")),
    "router.paused_old": (
        ("button.go_new", "!go new"),
        ("button.go_all", "!go"),
        ("button.drop_all", "!no"),
    ),
    "action.held": (("button.go", "!go"), ("button.drop", "!no")),
    "router.paused_gap": (("reconnect.button", "!ok"), ("button.drop", "!no")),
    "router.paused_gap_stopped": (("reconnect.button", "!ok"), ("button.drop", "!no")),
    "router.gap_go": (("reconnect.button", "!ok"),),
    "action.queue_paused": (("button.go", "!go"),),
    "action.stop_paused": (("button.go", "!go"), ("button.drop", "!no")),
    "transcript.repeat_hint": (("button.stop", "!stop"),),
    "schedule.proposal": (
        ("button.start", "!ok"),
        ("button.once", "!send"),
        ("button.decline", "!no"),
    ),
}


def notice_widget(key: str, text: str, label: Callable[[str], str]) -> str | None:
    """Buttons for the commands a fixed notice names, or None for any other text."""
    buttons = NOTICE_BUTTONS.get(key)
    if buttons is None:
        return None
    return buttons_widget(text, [(label(name), reply) for name, reply in buttons])
