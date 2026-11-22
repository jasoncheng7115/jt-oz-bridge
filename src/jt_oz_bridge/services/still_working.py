"""One "still working" line when a running turn has shown nothing for a while.

Typing is easy to miss and may be refused, and a long final answer shows no
words until it is finished. After a quiet period this posts one short line for
the turn, saying whether it waits on a tool or on the model when the newest
entry Bridge saw tells, through the ordinary sealed outbox: the same fence,
fresh audience reads and delivery checks as any other post. It never reaches OpenCode, never
authorizes anything and never deletes or edits a message; a line that was not
sent before the turn moved on is retired unsent.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from typing import Any, cast

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.budget import request_lane
from jt_oz_bridge.adapters.zulip.client import ZulipAuthenticationFailed
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import literal
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.runtime import error_label
from jt_oz_bridge.services.transcript_publisher import SUBAGENT_TOOLS
from jt_oz_bridge.services.transcript_records import (
    TranscriptState,
    incomplete,
    read_snapshot,
    read_stream,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch
from jt_oz_bridge.storage.transcript_models import (
    TranscriptMessage,
    TranscriptStream,
    TranscriptVersion,
)

LOG = logging.getLogger(__name__)
RENDERER = "still-working-notice-v1"
# Nothing new in the topic for this long while its turn runs: say it still runs.
QUIET_SECONDS = 120.0
# Ahead of a reply queued after it (80), so it can never land after that reply.
PRIORITY = 70
# A topic whose line was refused is tried again no sooner than this.
RETRY_SECONDS = 60.0
# OpenCode tool states of a call that has not finished yet.
UNFINISHED = frozenset({"pending", "running"})
# At most this many tool names in one line.
SHOWN_TOOLS = 3

type Key = tuple[str, int, int, str]
type Running = Callable[[], Mapping[Key, tuple[Binding, float]]]


def running_tools(content: list[dict[str, Any]]) -> list[str]:
    """Names of the tools an unfinished step is still running, oldest first.

    A code-mode step names the MCP tools it called; the one still running is the
    wait, or the newest call while OpenCode has not marked one yet.
    """
    names: dict[str, None] = {}
    for part in content:
        if part["type"] != "tool" or part["status"] not in UNFINISHED:
            continue
        calls = part.get("calls") or ()
        waiting = [c for c in calls if c["status"] in UNFINISHED] or list(calls[-1:])
        for call in waiting or ({"tool": part["name"]},):
            names[call["tool"]] = None
    return list(names)


async def doing(session: AsyncSession, state: TranscriptState) -> list[str] | None:
    """What the turn waits on, from the newest entry Bridge saw of the session.

    Tool names while a step still runs tools; an empty list while the model
    thinks or writes (after the input, or between and inside steps that run no
    tool); None when the newest entry does not tell.
    """
    record = await session.scalar(
        select(TranscriptMessage)
        .where(TranscriptMessage.scope_key == state.key)
        .order_by(TranscriptMessage.ordinal.desc())
        .limit(1)
    )
    if record is None:
        return None
    row = await session.scalar(
        select(TranscriptVersion).where(
            TranscriptVersion.record_id == record.id,
            TranscriptVersion.version == record.current_version,
        )
    )
    if row is None:
        return None
    try:
        entry = read_snapshot(row, record, state).observation.entry
    except (Conflict, ValueError):
        return None
    if entry.kind == "user":
        return []
    if entry.kind != "assistant":
        return None
    return running_tools(entry.projection()["content"]) if incomplete(entry) else []


async def waits_on(session: AsyncSession, binding: Binding) -> list[str] | None:
    """`doing` for this topic's session; None while its replies are held for a gap."""
    stream = await session.scalar(
        select(TranscriptStream).where(
            TranscriptStream.binding_id == binding.id,
            TranscriptStream.binding_revision == binding.revision,
        )
    )
    try:
        state = read_stream(stream, binding) if stream is not None else None
    except (Conflict, ValueError):
        return None
    return None if state is None or state.status == "gap" else await doing(session, state)


def tool_names(tr: Translator, locale: Locale, names: list[str]) -> str:
    """At most `SHOWN_TOOLS` names as literal text; OpenCode's subagent tool in words."""
    label = tr.render("transcript.tool_label.subagent", locale)
    shown = [label if n in SUBAGENT_TOOLS else literal(n[:80]) for n in names[:SHOWN_TOOLS]]
    return ", ".join(dict.fromkeys(shown))


class StillWorkingNotices:
    def __init__(
        self,
        replies: RoutedOutbox,
        running: Running,
        *,
        waiting: Callable[[Binding], bool] = lambda _binding: False,
        quiet: float = QUIET_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if replies.outbox.fence is None or not 0 < quiet <= 3600:
            raise ValueError("still_working_notice_scope_required")
        self.replies, self.outbox, self.db = replies, replies.outbox, replies.outbox.db
        self.fence = replies.outbox.fence
        self.running, self.waiting, self.quiet, self.clock = running, waiting, quiet, clock
        self.tr = Translator()
        # Busy periods (by their start) this process already settled: one line each.
        self._settled: dict[Key, float] = {}
        self._retry_at: dict[Key, float] = {}

    async def once(self) -> int:
        """One pass; returns how many lines were queued. Never raises for one topic."""
        running = dict(self.running())
        self._settled = {k: v for k, v in self._settled.items() if k in running}
        self._retry_at = {k: v for k, v in self._retry_at.items() if k in running}
        await self.retire({(binding.id, binding.revision) for binding, _ in running.values()})
        queued = 0
        now = self.clock()
        for identity, (binding, since) in running.items():
            if (
                binding.realm_id != self.replies.realm_id
                or now - since < self.quiet
                or self._settled.get(identity) == since
                or now < self._retry_at.get(identity, 0.0)
                or self.waiting(binding)
            ):
                continue
            try:
                if await self.notice(identity, binding, since, now):
                    queued += 1
            except (asyncio.CancelledError, ZulipAuthenticationFailed):
                raise
            except DeliveryRateLimited as error:
                LOG.info("still_working_notice_deferred kind=rate_limited")
                delay = error.retry_after if 0 < error.retry_after < 3600 else RETRY_SECONDS
                self._retry_at[identity] = now + max(RETRY_SECONDS, delay)
                break  # Optional: the budget is for replies first.
            except Exception as error:
                self._retry_at[identity] = now + RETRY_SECONDS
                LOG.warning("still_working_notice_skipped error_type=%s", error_label(error))
        return queued

    async def notice(self, identity: Key, binding: Binding, since: float, now: float) -> bool:
        scope = (
            Delivery.binding_id == binding.id,
            Delivery.binding_revision == binding.revision,
        )
        batches = (
            DeliveryBatch.binding_id == binding.id,
            DeliveryBatch.binding_revision == binding.revision,
        )
        async with self.db.sessions() as session:
            stream = await session.scalar(
                select(TranscriptStream).where(
                    TranscriptStream.binding_id == binding.id,
                    TranscriptStream.binding_revision == binding.revision,
                )
            )
            state = read_stream(stream, binding) if stream is not None else None
            if state is not None and state.status == "gap":
                return False  # Replies are held; "it will appear here" would not be true.
            if await session.scalar(
                select(Delivery.id)
                .where(*scope, Delivery.state.in_(["pending", "sending"]))
                .limit(1)
            ):
                return False  # Something is about to appear anyway.
            shown = await session.scalar(
                select(func.max(Delivery.updated_at)).where(*scope, Delivery.state == "delivered")
            )
            newest = (
                await session.execute(
                    select(
                        DeliveryBatch.id, DeliveryBatch.renderer_version, DeliveryBatch.created_at
                    )
                    .where(*batches)
                    .order_by(DeliveryBatch.created_at.desc(), DeliveryBatch.id.desc())
                    .limit(1)
                )
            ).first()
            if now - max(since, shown or 0.0, newest[2] if newest else 0.0) < self.quiet:
                return False
            if await session.scalar(
                select(DeliveryBatch.id)
                .where(
                    *batches,
                    DeliveryBatch.renderer_version == RENDERER,
                    DeliveryBatch.created_at >= since,
                )
                .limit(1)
            ):
                self._settled[identity] = since  # This turn already has its line.
                return False
            if newest is not None:
                last = await session.scalar(
                    select(Delivery)
                    .where(Delivery.batch_id == newest[0])
                    .order_by(Delivery.batch_index.desc())
                    .limit(1)
                )
                if last is not None and digest(last.payload) == last.payload_hash:
                    if last.payload.get("widget") is not None:
                        # Choice buttons are the newest post: the topic waits on a person.
                        return False
                    if (
                        newest[1] == RENDERER
                        and last.state == "delivered"
                        and not await session.scalar(
                            select(Action.id)
                            .where(
                                Action.binding_id == binding.id,
                                Action.created_at > newest[2],
                            )
                            .limit(1)
                        )
                    ):
                        # Its line is still the newest post and no new input came
                        # since, as after a restart in the middle of the turn.
                        self._settled[identity] = since
                        return False
            waiting_for = await doing(session, state) if state is not None else None
        locale = cast(Locale, binding.locale) if binding.locale in {"en", "zh-TW"} else "en"
        minutes = max(1, int((now - since) // 60))
        if waiting_for:
            text = self.tr.render(
                "runtime.still_working_tool",
                locale,
                minutes=minutes,
                tools=tool_names(self.tr, locale, waiting_for),
            )
        elif waiting_for is not None:
            text = self.tr.render("runtime.still_working_model", locale, minutes=minutes)
        else:
            text = self.tr.render("runtime.still_working", locale, minutes=minutes)
        with request_lane("normal"):
            await self.outbox.queue_batch(
                "still-working:"
                + digest({"binding": binding.id, "revision": binding.revision, "since": since}),
                binding.id,
                binding.revision,
                (text,),
                renderer_version=RENDERER,
                message_limit=self.replies.message_limit,
                topic_limit=self.replies.topic_limit,
                priority=PRIORITY,
            )
        self._settled[identity] = since
        LOG.warning(
            "still_working_notice_queued binding=%s minutes=%d waits_on=%s",
            binding.id,
            minutes,
            "unknown" if waiting_for is None else "tool" if waiting_for else "model",
        )
        return True

    async def retire(self, running: set[tuple[str, int]]) -> int:
        """Cancel an unsent line whose turn ended or already showed something newer."""
        async with self.db.sessions() as session:
            rows = (
                await session.execute(
                    select(Delivery, DeliveryBatch.created_at)
                    .join(DeliveryBatch, DeliveryBatch.id == Delivery.batch_id)
                    .join(Binding, Binding.id == Delivery.binding_id)
                    .where(
                        Binding.realm_id == self.replies.realm_id,
                        DeliveryBatch.renderer_version == RENDERER,
                        Delivery.state.in_(["pending", "held"]),
                        Delivery.posted_message_id.is_(None),
                    )
                    .limit(100)
                )
            ).all()
            stale = []
            for saved, created in rows:
                newer = await session.scalar(
                    select(DeliveryBatch.id)
                    .where(
                        DeliveryBatch.binding_id == saved.binding_id,
                        DeliveryBatch.binding_revision == saved.binding_revision,
                        DeliveryBatch.created_at > created,
                    )
                    .limit(1)
                )
                if (
                    saved.state == "held"  # e.g. held by a restart: it would only be late
                    or (saved.binding_id, saved.binding_revision) not in running
                    or newer is not None
                ):
                    stale.append(saved)
        if not stale:
            return 0
        retired = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            for saved in stale:
                result = await session.execute(
                    update(Delivery)
                    .where(
                        Delivery.id == saved.id,
                        Delivery.state == saved.state,
                        Delivery.version == saved.version,
                        Delivery.state.in_(["pending", "held"]),
                        Delivery.posted_message_id.is_(None),
                    )
                    .values(
                        state="cancelled",
                        version=Delivery.version + 1,
                        status_reason="still_working_superseded",
                        updated_at=time.time(),
                    )
                )
                if result.rowcount == 1:  # type: ignore[attr-defined]
                    retired += 1
                    session.add(
                        AuditEvent(
                            actor="system", event="still_working_notice_retired", object_id=saved.id
                        )
                    )
        return retired
