import re
import shlex
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedInput:
    kind: str
    command: str = ""
    arguments: str = ""


KNOWN = frozenset(
    "go help menu backends projects sessions next choose bind info unbind history new rename fork archive unarchive export delete send status usage stop steer queue cancel compact revert confirm models model variants variant agents agent pending approve deny answer skip files file diff checks check git worktrees worktree commands run skills skill mcp output outputs settings lang topic-lang notify sync recovery reconnect schedule once decline".split()
)


# A Zulip widget button in a channel sends its reply as "@**Bot** <reply>", and people
# often address the bot the same way. A mention right before a control is not part of it.
MENTION = re.compile(r"@\*\*[^*\n]{1,200}\*\*[ \t]+(?=[!！])")


def unmentioned(text: str) -> str:
    match = MENTION.match(text)
    return text[match.end() :] if match else text


LEADING_WORD = re.compile(r"!([A-Za-z]+)")
# A whole message that is one command word, perhaps with a permission code, as phone
# keyboards and Chinese input methods type it: `!stop。`, `!ok!`, `! status`, `!ｏｋ　１２３４`.
SHORT = re.compile(r"![ \t]*([A-Za-z]+|[0-9]+)((?:[ \t]+[0-9]+)?)[。.!?~～ \t\r\n]*")


def control_text(text: str) -> str:
    control = unmentioned(text)
    if len(control) <= 64:
        # NFKC reads full-width letters, digits, spaces, `！` and `？` as their ASCII forms.
        short = SHORT.fullmatch(unicodedata.normalize("NFKC", control))
        if short:
            return "!" + short[1].lower() + short[2]
    # A Chinese keyboard types the full-width `！`; leading a message it is the same `!`.
    control = "!" + control[1:] if control.startswith("！") else control
    # Phone keyboards capitalize the first word: `!Status` is `!status`.
    word = LEADING_WORD.match(control)
    return control if word is None else "!" + word[1].lower() + control[word.end() :]


def parse_input(text: str, *, is_bot: bool = False, bound: bool = False) -> ParsedInput:
    if is_bot or not text.strip():
        return ParsedInput("ignore")
    control = control_text(text)
    if control != text:
        parsed = _parse(control, bound)
        # Ordinary text keeps the mention and its `！`: it goes to the AI exactly as written.
        plain = parsed.kind == "prompt" and parsed.arguments == control
        return ParsedInput("prompt", arguments=text) if plain else parsed
    return _parse(text, bound)


WORD = re.compile(r"!([a-z]+)(?:[ \t]+([\s\S]*?))?[ \t\r\n]*")
# Everyday words: `!` and one word. Each maps to the one canonical command that
# does the work, so receipts, checks and replies stay those of that command.
EVERYDAY = {
    "model": "models",
    "disconnect": "unbind",
    "undo": "revert",
}
# Words with no arguments that name one canonical command and its arguments.
FIXED = {
    "redo": ("revert", "clear"),
    "discard": ("revert", "commit"),
}
# Words that also work before a topic is connected; `!stop` and `!go` there pause
# and continue a new conversation that is still being created.
UNBOUND = frozenset({"new", "lang", "stop"})


def canonical(word: str) -> str:
    """The command an everyday word runs, for `!help <word>`."""
    named = {"ok": "confirm", "no": "decline", "a": "answer", "commit": "git", "push": "git"}
    return named.get(word) or EVERYDAY.get(word) or FIXED.get(word, (word,))[0]


def _parse(text: str, bound: bool) -> ParsedInput:
    # Explicit controls only: a bare number remains ordinary agent text.
    shortcut = re.fullmatch(r"!([0-9]+)[ \t\r\n]*", text)
    if shortcut:
        number = shortcut.group(1)
        if number not in {str(value) for value in range(1, 11)}:
            return ParsedInput("invalid", "choose")
        return ParsedInput("command", "choose", number)
    aliases = {
        "!projects": ("projects", ""),
        "!sessions": ("sessions", ""),
        "!backends": ("backends", ""),
        "!recent": ("sessions", "recent"),
        "!next": ("next", ""),
        "!confirm": ("confirm", ""),
        "!reconnect": ("reconnect", ""),
        "!agent": ("agent", ""),
    }
    if text.rstrip(" \t\r\n") in aliases:
        command, arguments = aliases[text.rstrip(" \t\r\n")]
        return ParsedInput("command", command, arguments)
    word = WORD.fullmatch(text)
    if word is None:
        return _oz(text, bound)
    name, rest = word.group(1), word.group(2) or ""
    if name == "help":
        # `!help`, `!help all` or `!help <command>`; "!help me" stays ordinary text.
        if rest and rest != "all" and canonical(rest.removeprefix("!")) not in KNOWN:
            # `!help stauts` explains `!status`; reading help sends nothing anywhere.
            meant = typo_of(rest.removeprefix("!"))
            return ParsedInput("command", "help", meant) if meant else _oz(text, bound)
        return ParsedInput("command", "help", rest)
    if name == "go":
        # Connected: continue what is paused here. Otherwise: pick a conversation.
        if bound and not rest:
            return ParsedInput("command", "queue", "resume")
        if bound and rest.strip().casefold() in GO_NEW:
            # Send only the new messages; this person's old held ones are dropped.
            return ParsedInput("command", "queue", "resume new")
        return ParsedInput("command", "go", rest)
    if name == "ok":
        # `!ok` answers the question Bridge asked you; `!ok 1234` a permission notice.
        words = rest.split(maxsplit=1)
        if words and words[0].isdecimal() and bound:
            # Only a once approval exists; anything after the code fails as a broad request.
            return ParsedInput("command", "approve", " ".join([*words, "once"][:2]))
        return ParsedInput("command", "confirm", rest)
    if name == "no":
        # `!no` declines the question Bridge asked you; `!no 1234 [reason]` a permission.
        if not rest:
            return ParsedInput("command", "decline")
        return ParsedInput("command", "deny", rest) if bound else _oz(text, bound)
    if name in UNBOUND and not bound:
        return ParsedInput("command", name, rest)
    if not bound:
        return _oz(text, bound)
    if name == "a":
        # `!a 1234 <answer>` answers the one-question form whose notice showed that code.
        return ParsedInput("command", "answer", rest)
    if name == "send":
        # `!send` sends a message Bridge read as a repeat once as written; `!send <text>`
        # sends text exactly as written, even text that looks like a command.
        return ParsedInput("command", "once") if not rest else ParsedInput("prompt", "", rest)
    if name == "commit":
        if not rest.strip():
            return ParsedInput("invalid", command="git")
        return ParsedInput("command", "git", "commit -m " + shlex.quote(rest.strip()))
    if name == "push":
        return ParsedInput("command", "git", ("push " + rest).strip())
    if name in FIXED:
        if rest:
            return ParsedInput("invalid", command=FIXED[name][0])
        return ParsedInput("command", *FIXED[name])
    if name == "steer":
        return _literal("steer", text[len("!steer") :].lstrip(" \t"), bound)
    command = EVERYDAY.get(name, name)
    if command in KNOWN and command != "send":
        # In a connected topic `!stop` must stop, not reach the AI as text.
        return ParsedInput("command", command, rest)
    meant = typo_of(name)
    if meant is not None and "\n" not in rest and len(text) <= 200:
        # A mistyped command is not sent to the AI; the reply offers what was meant.
        return ParsedInput("unknown", name, f"!{meant} {rest}".rstrip())
    return _oz(text, bound)


# Everyday words a typo is matched against; shorter words match too much prose.
TYPO_TARGETS = (
    "stop status pending disconnect model agent rename fork compact undo redo discard"
    " history output files file diff schedule commit push send lang help next".split()
)


def typo_of(word: str) -> str | None:
    """The one everyday word `word` is a typo of: two neighbouring letters swapped,
    or, for words of five letters or more, one letter missing, extra or wrong."""
    found = {target for target in TYPO_TARGETS if _one_slip(word, target)}
    return found.pop() if len(found) == 1 else None


def _one_slip(word: str, target: str) -> bool:
    if word == target:
        return False
    if len(word) == len(target):
        diff = [i for i, (a, b) in enumerate(zip(word, target, strict=True)) if a != b]
        if len(diff) == 2 and diff[1] == diff[0] + 1:
            return word[diff[0]] == target[diff[1]] and word[diff[1]] == target[diff[0]]
        return len(target) >= 5 and len(diff) == 1
    if len(target) < 5 or abs(len(word) - len(target)) != 1:
        return False
    short, long = sorted((word, target), key=len)
    return any(long[:i] + long[i + 1 :] == short for i in range(len(long)))


def _oz(text: str, bound: bool) -> ParsedInput:
    # Only the beginning of the original message is a control position.
    match = re.match(r"^!oz(?:\s+([^\s]+))?(?:[ \t]+|\n)?([\s\S]*)$", text)
    if not match or (len(text) > 3 and not text[3].isspace()):
        return ParsedInput("prompt", arguments=text) if bound else ParsedInput("ignore")
    command, arguments = match.group(1) or "help", match.group(2)
    if command not in KNOWN:
        return ParsedInput("unknown", command=command)
    if command in {"send", "steer"}:
        return _literal(command, arguments, bound)
    return ParsedInput("command", command, arguments)


def _literal(command: str, arguments: str, bound: bool) -> ParsedInput:
    """`send -- text` and `steer -- text` carry the exact text after `-- ` as a prompt.

    A steer keeps its command name so the reply can say plainly that it was only queued.
    """
    if not arguments.startswith("-- ") and not arguments.startswith("--\n"):
        return ParsedInput("invalid", command=command)
    literal = arguments[3:]
    return (
        ParsedInput("prompt", "steer" if command == "steer" else "", literal)
        if bound and literal.strip()
        else ParsedInput("invalid", command=command)
    )


# Words people type to answer yes or no without the `!`. Only the whole message counts.
GO_NEW = frozenset({"new", "新的", "只送新的"})
BARE_YES = frozenset({"ok", "okay", "yes", "y", "好", "好的", "好啊", "可以", "確認", "是", "對"})
BARE_NO = frozenset({"no", "n", "不", "不要", "不用", "取消"})
BARE_TRAILING = "。.!！~～ \t"


# A lone 1 or 2 under a notice is someone picking its first or second button by number,
# as the desktop shows them; Bridge asks back instead of passing the digit on.
BARE_BUTTONS = {"1": "ok", "2": "no"}


def bare_answer(text: str) -> str | None:
    """`ok` or `no` for a message that is only such a word, else None."""
    word = unicodedata.normalize("NFKC", text).strip().rstrip(BARE_TRAILING).casefold()
    if word in BARE_BUTTONS:
        return BARE_BUTTONS[word]
    return "ok" if word in BARE_YES else "no" if word in BARE_NO else None


def is_unbound_text(text: str) -> bool:
    """Nonempty plain text may receive static onboarding, never an agent action."""
    return bool(text.strip()) and parse_input(text).kind == "ignore"
