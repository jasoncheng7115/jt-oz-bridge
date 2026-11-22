"""`!N` on a phone: row N of this person's latest menu in this topic.

A desktop button sends a menu row's command as the person's own message. Phones show no
buttons, so `!N` names that same command: a row of the menu this actor's last command in
this binding showed, provided it was posted before `!N` and nothing else was posted there
in between. Anything later (another command, a notice, an AI reply) closes it. The
command keeps every check it has when typed out, including its own token. Handlers that
re-read the Human source compare against the expanded command, never against `!N` alone.
"""

import re
from contextvars import ContextVar

from sqlalchemy import false, or_, select

from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.presentation.commands import ParsedInput, control_text, parse_input
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch

# Replies that are numbered menus; desktop clients get one button per row.
MENU_COMMANDS = frozenset({"menu", "pending", "choose", "models", "variants", "history"})
NUMBER = re.compile(r"!([1-9]|10)[ \t\r\n]*")
# The menu row a `!N` resolved to while that command runs.
EXPANDED: ContextVar[str | None] = ContextVar("menu_shortcut", default=None)


class NoOpenMenu(Conflict):
    pass


def number(text: str) -> int | None:
    match = NUMBER.fullmatch(control_text(text))
    return int(match[1]) if match else None


def expand(text: str, row: str | None) -> ParsedInput:
    """The command a Human source stands for: itself, or the menu row its `!N` named."""
    parsed = parse_input(text, bound=True)
    if row is None:
        return parsed
    expanded = parse_input(row, bound=True)
    if number(text) is None or expanded.kind != "command" or number(row) is not None:
        raise Conflict("menu_shortcut_source_changed")
    return expanded


def current(text: str) -> ParsedInput:
    """The source as this running command sees it (expanded when it came from `!N`)."""
    return expand(text, EXPANDED.get())


async def latest_is_menu(db: Database, binding: Binding, message: HumanMessage) -> bool:
    """`!N` belongs to the numbered menu only when this person's last command here showed one.

    Agent and lifecycle menus keep their own `!N` when they were shown last.
    """
    if number(message.text) is None:
        return False
    async with db.sessions() as session:
        receipt = await session.scalar(
            select(CommandReceipt)
            .where(
                CommandReceipt.realm_id == message.realm_id,
                CommandReceipt.actor_id == message.author_id,
                CommandReceipt.channel_id == message.channel_id,
                CommandReceipt.topic == message.topic,
                CommandReceipt.binding_id == binding.id,
                CommandReceipt.binding_revision == binding.revision,
                CommandReceipt.message_id < message.message_id,
            )
            .order_by(CommandReceipt.message_id.desc())
            .limit(1)
        )
    saved = receipt.response if receipt is not None else None
    return bool(isinstance(saved, dict) and saved.get("shortcuts"))


async def resolve(
    db: Database, binding: Binding, message: HumanMessage, *, routing: bool = True
) -> str:
    """Row N's command. `routing=False` repeats only the checks that cannot change later."""
    chosen = number(message.text)
    if chosen is None:
        raise Conflict("menu_shortcut_requires_number")
    async with db.sessions() as session:
        # This person's last command here must be the menu; any other command,
        # finished or not, closes it.
        receipt = await session.scalar(
            select(CommandReceipt)
            .where(
                CommandReceipt.realm_id == message.realm_id,
                CommandReceipt.actor_id == message.author_id,
                CommandReceipt.channel_id == message.channel_id,
                CommandReceipt.topic == message.topic,
                CommandReceipt.binding_id == binding.id,
                CommandReceipt.binding_revision == binding.revision,
                CommandReceipt.message_id < message.message_id,
            )
            .order_by(CommandReceipt.message_id.desc())
            .limit(1)
        )
        saved = receipt.response if receipt is not None else None
        rows = saved.get("shortcuts") if isinstance(saved, dict) else None
        if receipt is None or receipt.state != "completed" or not rows:
            raise NoOpenMenu("no_open_menu_for_short_choice")
        if not isinstance(rows, list) or not all(isinstance(row, str) for row in rows):
            raise Conflict("menu_shortcut_rows_changed")
        if chosen > len(rows):
            raise ValueError("invalid_navigation_choice")
        dedupe = "reply-batch:" + digest(
            {"key": "command:" + receipt.id, "binding": binding.id, "revision": binding.revision}
        )
        batch = await session.scalar(
            select(DeliveryBatch).where(DeliveryBatch.dedupe_key == dedupe)
        )
        pages = (
            list(
                await session.scalars(
                    select(Delivery).where(Delivery.batch_id == batch.id).limit(101)
                )
            )
            if batch is not None
            else []
        )
        # `!N` answers what the person saw: every page of that menu was posted before
        # it, and nothing else was posted here in between, so it was the last list.
        if (
            batch is None
            or len(pages) != batch.page_count
            or any(
                page.state != "delivered"
                or page.posted_message_id is None
                or page.posted_message_id >= message.message_id
                for page in pages
            )
        ):
            raise NoOpenMenu("menu_shortcut_menu_not_visible_first")
        shown = max(page.posted_message_id or 0 for page in pages)
        later = await session.scalar(
            select(Delivery.id)
            .where(
                Delivery.binding_id == binding.id,
                or_(
                    Delivery.posted_message_id > shown,
                    # Maybe already on screen, its Zulip id not recorded yet. Only
                    # while routing: by dispatch time later posts are in flight too.
                    Delivery.state.in_(["sending", "ambiguous"]) if routing else false(),
                ),
                or_(
                    Delivery.posted_message_id.is_(None),
                    Delivery.posted_message_id < message.message_id,
                ),
            )
            .limit(1)
        )
    if later is not None:
        raise NoOpenMenu("menu_shortcut_menu_not_the_last_post")
    return str(rows[chosen - 1])


async def verify(db: Database, binding: Binding, source: HumanMessage, row: object) -> ParsedInput:
    """A queued action's `!N` still resolves to the row saved with it."""
    if row is None:
        return expand(source.text, None)
    if not isinstance(row, str) or await resolve(db, binding, source, routing=False) != row:
        raise Conflict("menu_shortcut_resolution_changed")
    return expand(source.text, row)
