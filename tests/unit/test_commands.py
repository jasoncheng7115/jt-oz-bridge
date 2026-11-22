import pytest

from jt_oz_bridge.presentation.commands import parse_input


@pytest.mark.parametrize(
    "text", ["````\n!oz stop\n````", "> !oz approve TOKEN once", "Agent says !oz stop", " !oz stop"]
)
def test_embedded_commands_never_become_controls(text):
    parsed = parse_input(text, bound=True)
    assert parsed.kind == "prompt"
    assert parsed.arguments == text


def test_bot_output_and_unbound_text_ignored():
    assert parse_input("!oz stop", is_bot=True, bound=True).kind == "ignore"
    assert parse_input("Please edit", bound=False).kind == "ignore"


def test_unknown_command_never_forwarded():
    assert parse_input("!oz rm -rf", bound=True).kind == "unknown"


def test_literal_send_preserves_whitespace_and_commands():
    result = parse_input("!oz send -- !oz stop\n  exact text  ", bound=True)
    assert result.kind == "prompt"
    assert result.arguments == "!oz stop\n  exact text  "


def test_command_prefix_requires_boundary():
    assert parse_input("!ozone", bound=True).kind == "prompt"
    assert parse_input("!oz").command == "help"
    assert parse_input("!oz send something", bound=True).kind == "invalid"


@pytest.mark.parametrize(
    "changes",
    [
        {"author_id": True},
        {"author_id": "7"},
        {"message_id": True},
        {"channel_id": "10"},
        {"revision": False},
        {"is_bot": "false"},
        {"deleted": 0},
    ],
)
def test_source_identity_never_coerces_boolean_or_text_ids(changes):
    from pydantic import ValidationError

    from jt_oz_bridge.domain.execution import HumanMessage

    payload = dict(
        realm_id="realm",
        channel_id=10,
        topic="work",
        message_id=101,
        revision=0,
        author_id=7,
        text="PRIVATE_SOURCE_BODY",
        is_bot=False,
        deleted=False,
    )
    payload.update(changes)
    with pytest.raises(ValidationError) as captured:
        HumanMessage.model_validate(payload)
    assert "PRIVATE_SOURCE_BODY" not in str(captured.value)


@pytest.mark.parametrize("text", ["!help", "!help ", "!help\n"])
@pytest.mark.parametrize("bound", [False, True])
def test_short_help_is_a_control_in_both_bound_and_unbound_topics(text, bound):
    assert parse_input(text, bound=bound).kind == "command"
    assert parse_input(text, bound=bound).command == "help"


@pytest.mark.parametrize("text", [" !help", "> !help", "Agent says !help", "!helper", "!help me"])
def test_short_help_never_captures_embedded_text_or_longer_words(text):
    assert parse_input(text, bound=True).kind == "prompt"
    assert parse_input(text, bound=True).arguments == text


def test_literal_send_can_send_help_text_to_the_original_agent():
    value = parse_input("!oz send -- !help", bound=True)
    assert value.kind == "prompt" and value.arguments == "!help"


@pytest.mark.parametrize("mention", ["@**jt-oz-bridge** ", "@**jt-oz-bridge|11** "])
def test_a_button_click_in_a_channel_is_the_control_after_its_mention(mention):
    # Zulip sends a channel widget reply as "@**Bot** <reply>".
    assert parse_input(mention + "!1") == parse_input("!1")
    assert parse_input(mention + "!ok 1234", bound=True) == parse_input("!ok 1234", bound=True)
    assert parse_input(mention + "!oz menu", bound=True).command == "menu"
    # Ordinary text keeps the mention and reaches the AI exactly as written.
    for text in (mention + "hello", mention + "!hello there"):
        assert parse_input(text, bound=True) == parse_input(text, bound=True)
        assert parse_input(text, bound=True).arguments == text
    assert parse_input(mention + "!oz send -- !x", bound=True).arguments == "!x"
    assert parse_input("say @**jt-oz-bridge** !1", bound=True).kind == "prompt"


@pytest.mark.parametrize(
    ("text", "bound", "expected"),
    [
        # Bridge asked you something: `!ok` / `!no`; a permission notice carries its code.
        ("!ok", True, ("command", "confirm", "")),
        ("!ok", False, ("command", "confirm", "")),
        ("!ok 1234", True, ("command", "approve", "1234 once")),
        ("!ok 1234 always", True, ("command", "approve", "1234 always")),
        ("!ok " + "a" * 32, True, ("command", "confirm", "a" * 32)),
        ("!no", True, ("command", "decline", "")),
        ("!no", False, ("command", "decline", "")),
        ("!no 1234 not now", True, ("command", "deny", "1234 not now")),
        # `!go` continues here once connected and picks a conversation before.
        ("!go", True, ("command", "queue", "resume")),
        ("!go", False, ("command", "go", "")),
        ("!go mail", True, ("command", "go", "mail")),
        ("!stop", False, ("command", "stop", "")),
        ("!new", False, ("command", "new", "")),
        # One word per everyday action, each the canonical command underneath.
        ("!send", True, ("command", "once", "")),
        ("!send !stop now", True, ("prompt", "", "!stop now")),
        ("!model", True, ("command", "models", "")),
        ("!disconnect", True, ("command", "unbind", "")),
        ("!undo", True, ("command", "revert", "")),
        ("!undo files", True, ("command", "revert", "files")),
        ("!redo", True, ("command", "revert", "clear")),
        ("!discard", True, ("command", "revert", "commit")),
        ("!commit fix the build", True, ("command", "git", "commit -m 'fix the build'")),
        ("!push", True, ("command", "git", "push")),
        ("!push origin main", True, ("command", "git", "push origin main")),
        ("!help all", True, ("command", "help", "all")),
        ("!help undo", True, ("command", "help", "undo")),
    ],
)
def test_everyday_words_name_one_canonical_command(text, bound, expected):
    parsed = parse_input(text, bound=bound)
    assert (parsed.kind, parsed.command, parsed.arguments) == expected


@pytest.mark.parametrize("text", ["!redo now", "!discard all", "!commit", "!commit   "])
def test_everyday_words_refuse_what_they_cannot_mean(text):
    assert parse_input(text, bound=True).kind == "invalid"


@pytest.mark.parametrize("text", ["!send", "!model", "!undo", "!commit x", "!disconnect", "!a 1 x"])
def test_everyday_words_need_a_connected_topic(text):
    assert parse_input(text, bound=False).kind == "ignore"


def test_help_names_the_command_an_everyday_word_runs():
    from jt_oz_bridge.presentation.commands import KNOWN, canonical

    words = ["ok", "no", "a", "go", "stop", "send", "model", "disconnect", "undo", "redo"]
    words += ["discard", "commit", "push", "new", "status", "history", "schedule"]
    assert all(canonical(word) in KNOWN for word in words)
