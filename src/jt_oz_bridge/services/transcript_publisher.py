"""Atomic authorized transcript output plans, with no automatic POST retry."""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.transcript import TranscriptEntry
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.delivery import without_marker
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, literal, sanitize_controls
from jt_oz_bridge.presentation.menu_buttons import notice_widget
from jt_oz_bridge.security.redaction import RedactionError, redact_json, redact_text
from jt_oz_bridge.services.batch_dependencies import validate_dependency
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.outbox import OutboundPayload
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_commands import history_preview, reply_signature
from jt_oz_bridge.services.transcript_records import (
    PublicationMode,
    TranscriptPublicationPlan,
    TranscriptSnapshot,
    TranscriptState,
    incomplete,
    read_snapshot,
    read_stream,
    write_stream,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch
from jt_oz_bridge.storage.transcript_models import (
    TranscriptMessage,
    TranscriptPublication,
    TranscriptStream,
    TranscriptVersion,
)

RENDERER = "native-transcript-output-v2"
# Earlier posted versions searched for the model/Agent line a topic last showed.
SHOWN_SCAN = 100
# Earlier plans searched for the progress message of the turn a tool step is in.
PROGRESS_SCAN = 100
# A progress message is edited only this long after it was posted: under
# Zulip's default 10-minute edit limit, so a long turn starts a new one first.
PROGRESS_EDIT_WINDOW = 540.0
# OpenCode names its subagent tool `task`; 2.0.x builds may also call it `subagent`.
SUBAGENT_TOOLS = frozenset({"task", "subagent"})
# Room kept free below the message limit when a progress message grows.
PROGRESS_MARGIN = 200
REPEATED = re.compile(r"^(?P<line>.*) ×(?P<count>[0-9]+)$")
# The same step (words and tools) this many times in a row: suggest `!stop`, once a turn.
REPEAT_HINT_AT = 5
REPEAT_HINT_RENDERER = "transcript-repeat-hint-v1"
# Ahead of a reply queued after it (80), like the "still working" line.
REPEAT_HINT_PRIORITY = 70
# A reply whose step read this much context (input, cached or not) suggests a new
# conversation, once per binding: each step re-reads all of it and slows down.
LONG_CONTEXT_AT = 60_000
LONG_CONTEXT_RENDERER = "transcript-long-context-hint-v1"
# As a reply (80) and queued after the one it follows, so it never lands before it.
LONG_CONTEXT_PRIORITY = 80


def context_size(tokens: int, locale: Locale) -> str:
    """About how many tokens: 「9.5 萬」 in Chinese, "95k" in English."""
    if locale == "zh-TW":
        return f"{tokens / 10_000:.1f}".removesuffix(".0") + " 萬"
    if tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}".removesuffix(".0") + "M"
    return f"{round(tokens / 1000)}k"


@dataclass(frozen=True)
class Progress:
    """How one finished tool-only step reaches its turn's progress message.

    ``edit`` replaces ``edit_of``'s content with ``body``; ``post`` starts a new
    progress message with ``lines``; ``wait`` plans nothing until the message
    being extended is sent; ``skip`` (a step with words only) posts as usual.
    ``cancel`` is an unsent edit this plan replaces.
    """

    action: Literal["wait", "edit", "post", "skip"]
    edit_of: str | None = None
    body: str = ""
    lines: tuple[str, ...] = ()
    cancel: Delivery | None = None


def tool_step(entry: TranscriptEntry) -> bool:
    """A finished assistant step that only ran tools: progress, not a reply."""
    if entry.kind != "assistant" or incomplete(entry):
        return False
    content = entry.projection()["content"]
    return any(p["type"] == "tool" for p in content) and not any(
        p["type"] == "text" and p["text"] for p in content
    )


def repeat_step(entry: TranscriptEntry) -> bool:
    """A finished assistant step that said something and ran tools: it may repeat."""
    if entry.kind != "assistant" or incomplete(entry):
        return False
    content = entry.projection()["content"]
    return any(p["type"] == "tool" for p in content) and any(
        p["type"] == "text" and p["text"] for p in content
    )


def with_repeat(body: str, block: str) -> str | None:
    """The message once more counting a step it already shows in full, else None.

    A model stuck in a loop says the same words and calls the same tool step after
    step. A message showing exactly that step (whitespace aside) counts up on its
    last line (×2, ×3), as a repeated tool line does, instead of a new post.
    """
    if body.split() == block.split():
        return body + " ×2"
    head, _, tail = body.rpartition("\n")
    last = REPEATED.match(tail)
    if last is None:
        return None
    shown = (head + "\n" if head else "") + last["line"]
    if shown.split() != block.split():
        return None
    return shown + " ×" + str(int(last["count"]) + 1)


def repeats(body: str) -> int:
    """How many times a progress message's last line counted its step or tools."""
    last = REPEATED.match(body.rpartition("\n")[2])
    return int(last["count"]) if last else 1


def with_line(body: str, line: str) -> str:
    """Append one progress line; the same line again only counts up (×2, ×3)."""
    lines = body.split("\n")
    last = REPEATED.match(lines[-1])
    if lines[-1] == line:
        lines[-1] = line + " ×2"
    elif last and last["line"] == line:
        lines[-1] = line + " ×" + str(int(last["count"]) + 1)
    else:
        lines.append(line)
    return "\n".join(lines)


def unshown(body: str, shown: str) -> list[str]:
    """Lines of ``body`` the message showing ``shown`` does not (yet) show."""
    new, old = body.split("\n"), shown.split("\n")
    common = 0
    while common < min(len(new), len(old)) and new[common] == old[common]:
        common += 1
    return new[common:]


class EntryFormatter(Protocol):
    def __call__(
        self, entry: TranscriptEntry, locale: Locale, /, *, footer: bool = True
    ) -> str: ...


def plain_reply(entry: TranscriptEntry) -> bool:
    """A finished assistant step without tools: the only post that ends in the footer."""
    return (
        entry.kind == "assistant"
        and not incomplete(entry)
        and not any(p["type"] == "tool" for p in entry.projection()["content"])
    )


class TranscriptPublisher:
    def __init__(
        self,
        collector: TranscriptCollector,
        replies: RoutedOutbox,
        formatter: EntryFormatter,
        *,
        drafts_enabled: bool = False,
        progress_wait: float = 1.0,
        progress_edit_window: float = PROGRESS_EDIT_WINDOW,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            replies.outbox.bindings is not collector.bindings
            or replies.outbox.fence != collector.fence
        ):
            raise ValueError("transcript_publication_scope_and_fence_required")
        if not 0 <= progress_wait <= 60 or not 0 < progress_edit_window <= 3600:
            raise ValueError("transcript_progress_timing_invalid")
        self.collector, self.replies, self.outbox, self.db, self.fence = (
            collector,
            replies,
            replies.outbox,
            collector.db,
            collector.fence,
        )
        self.formatter, self.tr = formatter, Translator()
        self.drafts_enabled = drafts_enabled
        self.progress_wait, self.progress_edit_window = progress_wait, progress_edit_window
        self.clock = clock
        # Streams whose next tool step waits for its progress message to be
        # sent, until when. Memory only: a restart decides again from SQL.
        self._waiting: dict[str, float] = {}
        # Whether a gap's notice may go now, given (binding, gap reason). The runtime
        # holds an OpenCode restart's notice while its automatic reconnect may still
        # answer it with one line instead.
        self.gap_notice_due: Callable[[Binding, str | None], bool] | None = None
        # Whether `!new` in another topic can start a conversation in this binding's
        # project; the long-context notice names it only then.
        self.creates_here: Callable[[Binding], bool] | None = None

    async def next_pending(self) -> tuple[Literal["bootstrap", "gap", "version"], str] | None:
        async with self.db.sessions() as session:
            streams = (
                await session.execute(
                    select(TranscriptStream, Binding)
                    .join(Binding, Binding.id == TranscriptStream.binding_id)
                    .where(
                        Binding.state == "active",
                        Binding.realm_id == self.replies.realm_id,
                        Binding.revision == TranscriptStream.binding_revision,
                    )
                    .order_by(Binding.created_at, Binding.id)
                    .limit(100)
                )
            ).all()
            states = {}
            for row, binding in streams:
                state = read_stream(row, binding)
                states[row.key] = state
                if state.status == "gap":
                    if state.gap_plan is None and (
                        self.gap_notice_due is None
                        or self.gap_notice_due(binding, state.gap_reason)
                    ):
                        return "gap", row.key
                    continue
                if state.bootstrap_plan is None:
                    return "bootstrap", row.key
            pending = (
                await session.execute(
                    select(TranscriptVersion.id, TranscriptMessage.scope_key)
                    .join(TranscriptMessage, TranscriptMessage.id == TranscriptVersion.record_id)
                    .join(TranscriptStream, TranscriptStream.key == TranscriptMessage.scope_key)
                    .join(Binding, Binding.id == TranscriptStream.binding_id)
                    .outerjoin(
                        TranscriptPublication,
                        TranscriptPublication.version_id == TranscriptVersion.id,
                    )
                    .where(
                        TranscriptPublication.version_id.is_(None),
                        Binding.state == "active",
                        Binding.realm_id == self.replies.realm_id,
                        Binding.revision == TranscriptStream.binding_revision,
                    )
                    .order_by(TranscriptMessage.ordinal, TranscriptVersion.version)
                    .limit(100)
                )
            ).all()
            now = self.clock()
            for identity, key in pending:
                if key in states and states[key].status != "gap":
                    if self._waiting.get(key, 0) > now:
                        continue  # Other topics go on while this one waits.
                    return "version", identity
        return None

    async def source(self, key: str, *, authorize: bool = True) -> tuple[Binding, TranscriptState]:
        async with self.db.sessions() as session:
            row = await session.get(TranscriptStream, key)
            binding = await session.get(Binding, row.binding_id) if row else None
        if row is None or binding is None or binding.realm_id != self.replies.realm_id:
            raise Conflict("transcript_publication_scope_missing")
        state = read_stream(row, binding)
        if authorize:
            await self.collector.preflight(binding)
        return binding, state

    def plan_scope(
        self, plan: TranscriptPublicationPlan, binding: Binding, state: TranscriptState
    ) -> None:
        if (
            plan.scope_key,
            plan.binding_id,
            plan.binding_revision,
            plan.realm_id,
            plan.channel_id,
            plan.topic,
            plan.reference,
            plan.bot_user_id,
        ) != (
            state.key,
            binding.id,
            binding.revision,
            binding.realm_id,
            binding.channel_id,
            binding.topic,
            reference(binding),
            self.outbox.bot_user_id,
        ):
            raise Conflict("transcript_publication_plan_scope_changed")

    async def cached(
        self, plan: TranscriptPublicationPlan, binding: Binding, state: TranscriptState
    ) -> str | None:
        self.plan_scope(plan, binding, state)
        if plan.batch_id is not None:
            batch = await self.outbox.batch_by_id(plan.batch_id, binding.id, binding.revision)
            async with self.db.sessions() as session:
                parent = await session.get(DeliveryBatch, batch.id)
                dependency = await validate_dependency(
                    session, batch.id, binding, self.outbox.bot_user_id
                )
            if (dependency.before_batch_id if dependency else None) != plan.after_batch_id:
                raise Conflict("transcript_publication_dependency_changed")
            if parent is None or (
                parent.plan_hash,
                parent.renderer_version,
                parent.message_limit,
                parent.topic_limit,
            ) != (plan.plan_hash, plan.renderer, plan.message_limit, plan.topic_limit):
                raise Conflict("transcript_publication_batch_changed")
        return plan.batch_id

    async def _committed(
        self, plan: TranscriptPublicationPlan, binding: Binding, state: TranscriptState
    ) -> str | None:
        """Validate the just-written local batch; never supplies POST authority.

        Publication already performed its current remote preflight. Delivery
        independently re-observes the complete remote scope before any POST.
        Cached/replayed publications still use cached() and its original reads.
        """
        self.plan_scope(plan, binding, state)
        if plan.batch_id is not None:
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                await lock_output_scope(self.collector.bindings, session, binding)
                parent = await session.get(DeliveryBatch, plan.batch_id)
                dependency = await validate_dependency(
                    session, plan.batch_id, binding, self.outbox.bot_user_id
                )
                if (dependency.before_batch_id if dependency else None) != plan.after_batch_id:
                    raise Conflict("transcript_publication_dependency_changed")
                if parent is None or (
                    parent.plan_hash,
                    parent.renderer_version,
                    parent.message_limit,
                    parent.topic_limit,
                ) != (plan.plan_hash, plan.renderer, plan.message_limit, plan.topic_limit):
                    raise Conflict("transcript_publication_batch_changed")
            await self.outbox._validated_batch(binding, parent)
        return plan.batch_id

    async def queue_plan(
        self,
        session: AsyncSession,
        binding: Binding,
        state: TranscriptState,
        source_id: str,
        source_hash: str,
        mode: PublicationMode,
        pages: tuple[str, ...],
        locale: Locale,
        *,
        independent: bool = False,
        edit_of: str | None = None,
    ) -> TranscriptPublicationPlan:
        after = None if independent else state.last_batch_id
        batch_id = plan_hash = None
        if pages:
            batch = await self.outbox.queue_batch_in_session(
                session,
                "transcript:" + source_id,
                binding,
                pages,
                renderer_version=RENDERER,
                message_limit=self.replies.message_limit,
                topic_limit=self.replies.topic_limit,
                priority=1
                if mode == "gap"
                else 200
                if mode == "bootstrap"
                else 80
                if mode == "queued"
                else 100,
                after_batch_id=after,
                edit_of=edit_of,
            )
            parent = await session.get(DeliveryBatch, batch.id)
            if parent is None:
                raise Conflict("transcript_queued_batch_missing")
            batch_id, plan_hash = batch.id, parent.plan_hash
        return TranscriptPublicationPlan(
            scope_key=state.key,
            binding_id=binding.id,
            binding_revision=binding.revision,
            realm_id=binding.realm_id,
            channel_id=binding.channel_id,
            topic=binding.topic,
            reference=reference(binding),
            source_id=source_id,
            source_hash=source_hash,
            mode=mode,
            batch_id=batch_id,
            after_batch_id=after if pages else None,
            plan_hash=plan_hash,
            renderer=RENDERER,
            bot_user_id=self.outbox.bot_user_id,
            locale=locale,
            message_limit=self.replies.message_limit,
            topic_limit=self.replies.topic_limit,
        )

    def bootstrap_text(self, values: list[TranscriptSnapshot], locale: Locale) -> tuple[str, ...]:
        if not values:
            return ()
        header = self.tr.render("mirror.history", locale, count=len(values))
        footer = self.tr.render("mirror.history_more", locale)
        omitted = self.tr.render("mirror.history_omitted", locale)
        budget = self.replies.message_limit - FOOTER_SIZE
        maximum = max(
            0,
            min(
                80,
                (self.replies.message_limit - FOOTER_SIZE - len(header) - len(footer) - 60)
                // len(values)
                // 2
                - 16,
            ),
        )
        lines = [header]
        for index, value in enumerate(values, 1):
            entry = value.observation.entry
            key = (
                "input"
                if entry.kind == "user"
                else "reply"
                if entry.kind == "assistant"
                else "state"
                if entry.kind == "idle"
                else "control"
            )
            try:
                body, _ = sanitize_controls(self.formatter(entry, locale))
                preview = history_preview(body, maximum)
            except (ValueError, RedactionError):
                preview = ""
            line = self.tr.render(
                "mirror.history_item",
                locale,
                index=index,
                kind=self.tr.render("mirror.kind." + key, locale),
                preview=preview,
            )
            if len("\n".join([*lines, line, omitted, footer])) > budget:
                lines.append(omitted)
                break
            lines.append(line)
        lines.append(footer)
        body = "\n".join(lines)
        if len(body) > self.replies.message_limit - FOOTER_SIZE:
            raise Conflict("transcript_bootstrap_digest_budget_changed")
        return (body,)

    async def scope_notice(self, key: str, kind: Literal["bootstrap", "gap"]) -> str | None:
        binding, _ = await self.source(key)
        created = False
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.collector.bindings, session, binding)
            row = await session.get(TranscriptStream, key, with_for_update=True)
            if row is None:
                raise Conflict("transcript_publication_stream_missing")
            state = read_stream(row, binding)
            stored = state.bootstrap_plan if kind == "bootstrap" else state.gap_plan
            if stored is not None:
                plan = TranscriptPublicationPlan.model_validate(stored)
            else:
                locale = cast(Locale, binding.locale) if binding.locale in {"en", "zh-TW"} else "en"
                pages: tuple[str, ...]
                if kind == "gap":
                    if state.status != "gap":
                        raise Conflict("transcript_gap_notice_not_current")
                    pages = (self.tr.render("mirror.gap", locale),)
                    source_hash = digest({"scope": state.key, "gap": state.gap_reason})
                else:
                    if state.status == "gap":
                        raise Conflict("transcript_bootstrap_held_for_gap")
                    values = []
                    for identity in state.bootstrap_versions:
                        version = await session.get(TranscriptVersion, identity)
                        record = (
                            await session.get(TranscriptMessage, version.record_id)
                            if version
                            else None
                        )
                        if version is None or record is None:
                            raise Conflict("transcript_bootstrap_version_missing")
                        value = read_snapshot(version, record, state)
                        if not value.historical:
                            raise Conflict("transcript_bootstrap_source_not_history")
                        values.append(value)
                    pages = self.bootstrap_text(values, locale)
                    source_hash = digest(
                        {"scope": state.key, "history": [v.model_dump(mode="json") for v in values]}
                    )
                plan = await self.queue_plan(
                    session,
                    binding,
                    state,
                    state.gap_source() if kind == "gap" else key + ":" + kind,
                    source_hash,
                    kind,
                    pages,
                    locale,
                    independent=kind == "gap",
                )
                if kind == "bootstrap":
                    for value in values:
                        version = await session.get(TranscriptVersion, value.id)
                        assert version is not None
                        history = await self.queue_plan(
                            session,
                            binding,
                            state,
                            value.id,
                            version.payload_hash,
                            "historical",
                            (),
                            locale,
                        )
                        session.add(
                            TranscriptPublication(
                                version_id=value.id,
                                batch_id=None,
                                payload=history.model_dump(mode="json"),
                                payload_hash=digest(history.model_dump(mode="json")),
                            )
                        )
                    state = state.model_copy(
                        update={
                            "bootstrap_plan": plan.model_dump(mode="json"),
                            "last_batch_id": plan.batch_id or state.last_batch_id,
                        }
                    )
                else:
                    state = state.model_copy(update={"gap_plan": plan.model_dump(mode="json")})
                write_stream(row, state)
                created = True
        # As in publish(): a plan this call just wrote is validated locally, since
        # source() read Zulip in full for it and delivery reads it again before any
        # POST. A plan stored earlier still goes through cached() and its reads.
        if created:
            return await self._committed(plan, binding, state)
        return await self.cached(plan, binding, state)

    async def own_locale(
        self, session: AsyncSession, value: TranscriptSnapshot, binding: Binding
    ) -> Locale:
        identity = value.context_action_id
        if identity is not None:
            action = await session.get(Action, identity)
            receipt = native_receipt(action) if action else None
            if (
                action is None
                or receipt is None
                or receipt.admission.status != "admitted"
                or receipt.reference != reference(binding)
                or action.binding_id != binding.id
                or action.binding_revision != binding.revision
            ):
                raise Conflict("transcript_reply_locale_origin_changed")
            locale = action.payload.get("reply_locale", binding.locale)
        else:
            locale = binding.locale
        if locale not in {"en", "zh-TW"}:
            raise Conflict("transcript_reply_locale_invalid")
        return cast(Locale, locale)

    def _tools_line(self, tools: list[dict[str, Any]], locale: Locale) -> str:
        error = " (" + self.tr.render("transcript.tool_status.error", locale) + ")"
        names: dict[str, None] = {}
        for tool in tools:
            for call in tool.get("calls") or ({"tool": tool["name"], "status": tool["status"]},):
                failed = call["status"] in {"error", "failed"}
                name = literal(call["tool"])
                if call["tool"] in SUBAGENT_TOOLS:
                    # OpenCode's subagent tool; the bare name says little on a phone.
                    name = self.tr.render("transcript.tool_label.subagent", locale)
                names[name + (error if failed else "")] = None
        return self.tr.render("transcript.tools_used", locale, names=", ".join(names))

    async def shown_signature(
        self,
        session: AsyncSession,
        state: TranscriptState,
        record: TranscriptMessage,
        row: TranscriptVersion,
    ) -> tuple[str, str] | None:
        """The model/Agent line this topic's posts last showed, from earlier sealed plans.

        A posted plain reply either showed its line or repeated the one before it,
        so the newest one names what the person last saw. Every earlier version is
        already planned, so the answer is fixed when this plan is sealed.
        """
        earlier = (
            await session.execute(
                select(TranscriptVersion, TranscriptMessage, TranscriptPublication)
                .join(TranscriptMessage, TranscriptMessage.id == TranscriptVersion.record_id)
                .join(
                    TranscriptPublication,
                    TranscriptPublication.version_id == TranscriptVersion.id,
                )
                .where(
                    TranscriptMessage.scope_key == state.key,
                    TranscriptPublication.batch_id.is_not(None),
                    or_(
                        TranscriptMessage.ordinal < record.ordinal,
                        and_(
                            TranscriptMessage.ordinal == record.ordinal,
                            TranscriptVersion.version < row.version,
                        ),
                    ),
                )
                .order_by(TranscriptMessage.ordinal.desc(), TranscriptVersion.version.desc())
                .limit(SHOWN_SCAN)
            )
        ).all()
        for version, message, publication in earlier:
            if digest(publication.payload) != publication.payload_hash:
                raise Conflict("transcript_publication_seal_changed")
            if publication.payload.get("mode") != "queued":
                continue
            try:
                entry = read_snapshot(version, message, state).observation.entry
                if plain_reply(entry):
                    return reply_signature(entry)
            except (Conflict, ValueError):
                # Unreadable here means unknown: show the line again.
                return None
        return None

    async def progress_tail(
        self,
        session: AsyncSession,
        state: TranscriptState,
        record: TranscriptMessage,
        row: TranscriptVersion,
        value: TranscriptSnapshot,
    ) -> tuple[Delivery, OutboundPayload, str] | None:
        """The newest delivery of this turn's progress message, from earlier sealed plans.

        A turn's progress message is the post of its first tool step and the
        edits later tool steps sealed onto it. An input (a steer too), an
        outcome or any other posted entry in between ends that message, so each
        input's tool steps show under it. Every earlier version is already
        planned, so the answer is fixed when this plan is sealed.
        """
        earlier = (
            await session.execute(
                select(TranscriptVersion, TranscriptMessage, TranscriptPublication)
                .join(TranscriptMessage, TranscriptMessage.id == TranscriptVersion.record_id)
                .join(
                    TranscriptPublication,
                    TranscriptPublication.version_id == TranscriptVersion.id,
                )
                .where(
                    TranscriptMessage.scope_key == state.key,
                    or_(
                        TranscriptMessage.ordinal < record.ordinal,
                        and_(
                            TranscriptMessage.ordinal == record.ordinal,
                            TranscriptVersion.version < row.version,
                        ),
                    ),
                )
                .order_by(TranscriptMessage.ordinal.desc(), TranscriptVersion.version.desc())
                .limit(PROGRESS_SCAN)
            )
        ).all()
        for version, message, publication in earlier:
            if digest(publication.payload) != publication.payload_hash:
                raise Conflict("transcript_publication_seal_changed")
            mode = publication.payload.get("mode")
            try:
                snapshot = read_snapshot(version, message, state)
            except (Conflict, ValueError):
                return None  # Unknown: start a new progress message.
            entry = snapshot.observation.entry
            if entry.kind in {"user", "idle"} or mode == "historical":
                return None
            if publication.batch_id is None:
                continue  # Nothing shown: an unfinished or empty step.
            if snapshot.owner_generation != value.owner_generation or not (
                mode == "progress"
                or mode == "queued"
                and publication.batch_id == state.last_batch_id
                and entry.kind == "assistant"
                and any(p["type"] == "tool" for p in entry.projection()["content"])
            ):
                return None
            tail = await session.scalar(
                select(Delivery)
                .where(Delivery.batch_id == publication.batch_id)
                .order_by(Delivery.batch_index.desc())
                .limit(1)
            )
            if tail is None or tail.payload_compacted_at is not None:
                return None
            if digest(tail.payload) != tail.payload_hash or (
                tail.binding_id,
                tail.binding_revision,
                tail.destination_id,
            ) != (state.binding_id, state.binding_revision, None):
                raise Conflict("transcript_progress_delivery_changed")
            payload = OutboundPayload.model_validate(tail.payload)
            body = without_marker(payload.content, "jtoz:" + tail.id)
            if body is None:
                raise Conflict("transcript_progress_delivery_changed")
            return tail, payload, body
        return None

    async def progress(
        self,
        session: AsyncSession,
        state: TranscriptState,
        record: TranscriptMessage,
        row: TranscriptVersion,
        value: TranscriptSnapshot,
        line: str,
        *,
        repeat: bool = False,
    ) -> Progress:
        """Edit this turn's progress message, or say why a new one starts.

        Only a delivered message is edited, and delivery GETs it again first.
        An edit not yet sent is replaced by one carrying its lines too; an edit
        that failed, or whose outcome is unknown, never loses its lines: they
        open the next progress message (an unknown one may then show twice).

        With ``repeat``, ``line`` is a whole step with words; only a message
        showing that same step is edited, to count it once more (``skip``
        otherwise). Should it not be edited, the step posts in full again, so
        nothing but the count is ever lost.
        """
        found = await self.progress_tail(session, state, record, row, value)
        if found is None:
            return Progress("skip") if repeat else Progress("post", lines=(line,))
        tail, payload, body = found
        if repeat and with_repeat(body, line) is None:
            return Progress("skip")
        carried: list[str] = []  # Lines no message shows yet.
        cancel = None
        if tail.state == "delivered":
            base = tail
        elif tail.state == "sending" or (
            payload.operation == "post" and tail.state in {"pending", "held"}
        ):
            return Progress("wait")
        elif payload.operation == "post":
            # Later posts wait behind a post that failed, as they always have.
            return Progress("post", lines=(line,))
        else:
            parent = await session.get(Delivery, payload.target_delivery_id)
            shown = (
                without_marker(parent.payload["content"], "jtoz:" + parent.id)
                if parent is not None and digest(parent.payload) == parent.payload_hash
                else None
            )
            if parent is None or shown is None or parent.state != "delivered":
                raise Conflict("transcript_progress_edit_source_changed")
            carried = unshown(body, shown)
            unsent = tail.state == "pending" or (
                tail.state == "held" and tail.attempts == 0 and tail.posted_message_id is None
            )
            cancel = tail if unsent else None
            if not (tail.state == "pending" or unsent and tail.status_reason == "restart_unsent"):
                return Progress("post", lines=(*carried, line), cancel=cancel)
            base = parent
        posted_at = await session.scalar(
            select(Delivery.updated_at)
            .where(
                Delivery.binding_id == base.binding_id,
                Delivery.posted_message_id == base.posted_message_id,
                Delivery.state == "delivered",
            )
            .order_by(Delivery.created_at)
            .limit(1)
        )
        merged = (with_repeat(body, line) or body) if repeat else with_line(body, line)
        if (
            posted_at is None
            or self.clock() - posted_at > self.progress_edit_window
            or len(merged) + FOOTER_SIZE + PROGRESS_MARGIN > self.replies.message_limit
        ):
            return Progress("post", lines=(*carried, line), cancel=cancel)
        return Progress("edit", edit_of=base.id, body=merged, cancel=cancel)

    async def repeat_hinted(
        self,
        session: AsyncSession,
        binding: Binding,
        state: TranscriptState,
        record: TranscriptMessage,
        row: TranscriptVersion,
    ) -> bool:
        """Whether this turn already has its repeat hint, from earlier sealed plans.

        The turn runs back to the nearest input or outcome. A hint is queued with
        a step of its turn, so none older than that turn's first post is its own.
        A turn longer than the scan may get a second hint, minutes later.
        """
        earlier = (
            await session.execute(
                select(TranscriptVersion, TranscriptMessage, TranscriptPublication)
                .join(TranscriptMessage, TranscriptMessage.id == TranscriptVersion.record_id)
                .join(
                    TranscriptPublication,
                    TranscriptPublication.version_id == TranscriptVersion.id,
                )
                .where(
                    TranscriptMessage.scope_key == state.key,
                    or_(
                        TranscriptMessage.ordinal < record.ordinal,
                        and_(
                            TranscriptMessage.ordinal == record.ordinal,
                            TranscriptVersion.version < row.version,
                        ),
                    ),
                )
                .order_by(TranscriptMessage.ordinal.desc(), TranscriptVersion.version.desc())
                .limit(PROGRESS_SCAN)
            )
        ).all()
        first = None
        for version, message, publication in earlier:
            if digest(publication.payload) != publication.payload_hash:
                raise Conflict("transcript_publication_seal_changed")
            if publication.payload.get("mode") == "historical":
                break
            try:
                entry = read_snapshot(version, message, state).observation.entry
            except (Conflict, ValueError):
                break
            if entry.kind in {"user", "idle"}:
                break
            first = publication.batch_id or first
        since = (
            await session.scalar(select(DeliveryBatch.created_at).where(DeliveryBatch.id == first))
            if first
            else None
        )
        if since is None:
            return False
        return (
            await session.scalar(
                select(DeliveryBatch.id)
                .where(
                    DeliveryBatch.binding_id == binding.id,
                    DeliveryBatch.binding_revision == binding.revision,
                    DeliveryBatch.renderer_version == REPEAT_HINT_RENDERER,
                    DeliveryBatch.created_at >= since,
                )
                .limit(1)
            )
            is not None
        )

    async def repeat_hint(
        self, session: AsyncSession, binding: Binding, identity: str, count: int, locale: Locale
    ) -> None:
        """One notice that the AI repeats itself, with a `!stop` button; never stops it.

        Queued in the same transaction that seals the step's plan, so a replay or a
        restart finds that plan and never queues it again.
        """
        text = self.tr.render("transcript.repeat_hint", locale, count=count)
        await self.outbox.queue_batch_in_session(
            session,
            "repeat-hint:" + identity,
            binding,
            (text,),
            renderer_version=REPEAT_HINT_RENDERER,
            message_limit=self.replies.message_limit,
            topic_limit=self.replies.topic_limit,
            priority=REPEAT_HINT_PRIORITY,
            widget=notice_widget(
                "transcript.repeat_hint", text, lambda name: self.tr.render(name, locale)
            ),
        )
        session.add(
            AuditEvent(actor="system", event="transcript_repeat_hint_queued", object_id=binding.id)
        )

    async def retire_repeat_hints(self, session: AsyncSession, binding: Binding) -> None:
        """Cancel an unsent repeat hint once its turn ended: `!stop` would come too late."""
        unsent = (
            await session.scalars(
                select(Delivery)
                .join(DeliveryBatch, DeliveryBatch.id == Delivery.batch_id)
                .where(
                    DeliveryBatch.binding_id == binding.id,
                    DeliveryBatch.renderer_version == REPEAT_HINT_RENDERER,
                    Delivery.state.in_(["pending", "held"]),
                    Delivery.posted_message_id.is_(None),
                )
                .limit(10)
            )
        ).all()
        for saved in unsent:
            await self.cancel_unsent(
                session,
                saved,
                reason="repeat_hint_superseded",
                event="transcript_repeat_hint_retired",
            )

    async def long_context_hinted(self, session: AsyncSession, binding: Binding) -> bool:
        """Whether this binding (one topic and its one session) already had the notice."""
        return (
            await session.scalar(
                select(DeliveryBatch.id)
                .where(
                    DeliveryBatch.binding_id == binding.id,
                    DeliveryBatch.renderer_version == LONG_CONTEXT_RENDERER,
                )
                .limit(1)
            )
            is not None
            or await session.scalar(
                select(AuditEvent.id)
                .where(
                    AuditEvent.event == "transcript_long_context_hint_queued",
                    AuditEvent.object_id == binding.id,
                )
                .limit(1)
            )
            is not None
        )

    async def long_context_hint(
        self,
        session: AsyncSession,
        binding: Binding,
        identity: str,
        after: str,
        tokens: int,
        locale: Locale,
    ) -> None:
        """One notice, after the reply, that a new conversation would be faster.

        It only says how; Bridge never starts a conversation or tells OpenCode
        anything. `!new` works in a topic not yet connected, so it gets no button
        here; a project that cannot create from chat is told so instead.
        """
        how = (
            self.tr.render(
                "transcript.long_context_new",
                locale,
                project=literal(redact_json(binding.project_id).value[:180]),
            )
            if self.creates_here is not None and self.creates_here(binding)
            else self.tr.render("transcript.long_context_no_new", locale)
        )
        text = self.tr.render(
            "transcript.long_context", locale, size=context_size(tokens, locale), how=how
        )
        await self.outbox.queue_batch_in_session(
            session,
            "long-context-hint:" + identity,
            binding,
            (text,),
            renderer_version=LONG_CONTEXT_RENDERER,
            message_limit=self.replies.message_limit,
            topic_limit=self.replies.topic_limit,
            priority=LONG_CONTEXT_PRIORITY,
            after_batch_id=after,
        )
        session.add(
            AuditEvent(
                actor="system", event="transcript_long_context_hint_queued", object_id=binding.id
            )
        )

    def progress_pages(self, lines: tuple[str, ...]) -> tuple[str, ...]:
        """A new progress message for these lines, split only when one is too long."""
        budget = self.replies.message_limit - FOOTER_SIZE - PROGRESS_MARGIN
        pages = [lines[0]]
        for line in lines[1:]:
            joined = with_line(pages[-1], line)
            if len(joined) > budget:
                pages.append(line)
            else:
                pages[-1] = joined
        return tuple(pages)

    async def cancel_unsent(
        self,
        session: AsyncSession,
        saved: Delivery,
        *,
        reason: str = "progress_edit_superseded",
        event: str = "progress_unsent_edit_cancelled",
    ) -> bool:
        """Retire a post or edit nobody sent, unless delivery claimed it meanwhile."""
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
                status_reason=reason,
                updated_at=time.time(),
            )
        )
        if result.rowcount != 1:  # type: ignore[attr-defined]
            return False
        session.add(AuditEvent(actor="system", event=event, object_id=saved.id))
        return True

    async def progress_waits(
        self,
        identity: str,
        binding: Binding,
        state: TranscriptState,
        value: TranscriptSnapshot,
    ) -> bool:
        """Whether an unplanned tool step waits for its progress message to be sent.

        A step with words waits only when it repeats the step that message shows.
        """
        async with self.db.sessions() as session:
            row = await session.get(TranscriptVersion, identity)
            record = await session.get(TranscriptMessage, row.record_id) if row else None
            if (
                row is None
                or record is None
                or record.current_version != row.version
                or value.historical
                or value.recovering
                or await session.get(TranscriptPublication, identity) is not None
            ):
                return False
            line, repeat = "", repeat_step(value.observation.entry)
            if repeat:
                mode, pages = self.pages(value, await self.own_locale(session, value, binding))
                if mode != "queued" or len(pages) != 1:
                    return False
                line = pages[0]
            step = await self.progress(session, state, record, row, value, line, repeat=repeat)
        if step.action == "wait":
            self.wait(state.key)
            return True
        return False

    def wait(self, key: str) -> None:
        now = self.clock()
        self._waiting = {k: v for k, v in self._waiting.items() if v > now}
        self._waiting[key] = now + self.progress_wait

    def pages(
        self,
        value: TranscriptSnapshot,
        locale: Locale,
        *,
        shown: tuple[str, str] | None = None,
    ) -> tuple[PublicationMode, tuple[str, ...]]:
        """``shown`` is the topic's last model/Agent line; an equal one is left out."""
        entry = value.observation.entry
        if entry.kind in {"system", "synthetic", "skill"}:
            return "empty", ()
        if entry.kind == "user" and value.source_action_id:
            return "echo", ()
        if entry.kind == "assistant":
            raw = entry.projection()
            tools = [p for p in raw["content"] if p["type"] == "tool"]
            if incomplete(entry):
                if self.drafts_enabled:
                    return "draft_owned", ()
                # Typing shows a running step; only finished words reach the chat.
                return "empty", ()
            said = [p["text"] for p in raw["content"] if p["type"] == "text" and p["text"]]
            if not said and not tools:
                return "empty", ()
            # A step that called tools is progress: its words and one line of tool names.
            body = (
                "\n\n".join((*said, self._tools_line(tools, locale)))
                if tools
                else self.formatter(entry, locale, footer=shown != reply_signature(entry))
            )
            header = ""
        else:
            # A failure or interruption must be said; success is the reply itself.
            if entry.kind == "idle" and entry.projection()["outcome"] == "succeeded":
                return "empty", ()
            body = self.formatter(entry, locale)
            key = (
                "input"
                if entry.kind == "user"
                else "outcome"
                if entry.kind == "idle"
                else "control"
            )
            header = self.tr.render("mirror." + key, locale)
        if value.recovering:
            header += "\n" + self.tr.render("mirror.recovered", locale)
        maximum = self.tr.render("output.page", locale, index=100, total=100)
        note = ""
        mode: PublicationMode = "queued"
        try:
            body, _ = sanitize_controls(body)
            body, redactions = redact_text(body)
            note = self.tr.render("native.redacted", locale) if redactions else ""
            rendered = MobileMarkdown(locale=locale).render(
                body,
                self.replies.message_limit,
                reserved_characters=FOOTER_SIZE + len(header) + len(maximum) + len(note) + 12,
            )
            if not 1 <= len(rendered.pages) <= 100 or sum(map(len, rendered.pages)) > 900000:
                raise ValueError("transcript_full_output_required")
        except (ValueError, RedactionError):
            mode = "needs_full_output"
            note = ""
            rendered = MobileMarkdown(locale=locale).render(
                self.tr.render("transcript.unpreviewable", locale),
                self.replies.message_limit,
                reserved_characters=FOOTER_SIZE + len(header) + len(maximum) + 12,
            )
        return mode, tuple(
            (header + "\n\n" if header else "")
            + self.tr.page_prefix(locale, i, len(rendered.pages))
            + page
            + ("\n\n" + note if note else "")
            for i, page in enumerate(rendered.pages, 1)
        )

    async def publish(self, identity: str) -> str | None:
        async with self.db.sessions() as session:
            row = await session.get(TranscriptVersion, identity)
            record = await session.get(TranscriptMessage, row.record_id) if row else None
        if row is None or record is None:
            raise Conflict("transcript_publication_version_missing")
        binding, state = await self.source(record.scope_key, authorize=False)
        initial_value = read_snapshot(row, record, state)
        entry = initial_value.observation.entry
        local_only = (
            record.current_version > row.version
            or initial_value.historical
            or entry.kind in {"system", "synthetic", "skill"}
            or entry.kind == "user"
            and initial_value.source_action_id is not None
            or self.drafts_enabled
            and entry.kind == "assistant"
            and incomplete(entry)
        )
        if not local_only:
            if (tool_step(entry) or repeat_step(entry)) and await self.progress_waits(
                identity, binding, state, initial_value
            ):
                return None  # Decided again, without a Zulip read, once it is sent.
            await self.collector.preflight(binding)
        created = False
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.collector.bindings, session, binding)
            stream = await session.get(TranscriptStream, record.scope_key, with_for_update=True)
            row = await session.get(TranscriptVersion, identity)
            record = await session.get(TranscriptMessage, row.record_id) if row else None
            if stream is None or row is None or record is None:
                raise Conflict("transcript_publication_source_missing")
            state = read_stream(stream, binding)
            value = read_snapshot(row, record, state)
            saved = await session.get(TranscriptPublication, identity)
            if saved is not None:
                if digest(saved.payload) != saved.payload_hash:
                    raise Conflict("transcript_publication_seal_changed")
                plan = TranscriptPublicationPlan.model_validate(saved.payload)
                if (
                    plan.source_id != identity
                    or plan.source_hash != row.payload_hash
                    or saved.batch_id != plan.batch_id
                ):
                    raise Conflict("transcript_publication_source_changed")
                if local_only and plan.batch_id is not None:
                    raise Conflict("local_transcript_version_cannot_own_output")
            else:
                if state.bootstrap_plan is None or state.status == "gap":
                    raise Conflict("transcript_publication_continuity_not_ready")
                earlier = await session.scalar(
                    select(TranscriptVersion.id)
                    .join(TranscriptMessage, TranscriptMessage.id == TranscriptVersion.record_id)
                    .outerjoin(
                        TranscriptPublication,
                        TranscriptPublication.version_id == TranscriptVersion.id,
                    )
                    .where(
                        TranscriptMessage.scope_key == state.key,
                        TranscriptPublication.version_id.is_(None),
                        or_(
                            TranscriptMessage.ordinal < record.ordinal,
                            and_(
                                TranscriptMessage.ordinal == record.ordinal,
                                TranscriptVersion.version < row.version,
                            ),
                        ),
                    )
                    .limit(1)
                )
                if earlier is not None:
                    raise Conflict("transcript_earlier_version_not_planned")
                locale = await self.own_locale(session, value, binding)
                shown = (
                    await self.shown_signature(session, state, record, row)
                    if record.current_version == row.version
                    and not value.historical
                    and plain_reply(value.observation.entry)
                    else None
                )
                mode, pages = (
                    ("superseded", ())
                    if record.current_version > row.version
                    else ("historical", ())
                    if value.historical
                    else self.pages(value, locale, shown=shown)
                )
                if value.source_action_id is not None:
                    original = await self.collector.origin(session, binding, value.observation)
                    if original != value.source_action_id:
                        raise Conflict("transcript_phone_origin_changed")
                if local_only and pages:
                    raise Conflict("local_transcript_version_cannot_emit_pages")
                edit_of = None
                repeat = repeat_step(value.observation.entry)
                hint = 0
                if (
                    mode == "queued"
                    and len(pages) == 1
                    and not value.recovering
                    and ("\n" not in pages[0] and tool_step(value.observation.entry) or repeat)
                ):
                    # One line of tool names joins the turn's progress message; a
                    # step with words that only repeats the one shown counts up there.
                    step = await self.progress(
                        session, state, record, row, value, pages[0], repeat=repeat
                    )
                    if step.action == "wait" or (
                        step.cancel is not None
                        and not await self.cancel_unsent(session, step.cancel)
                    ):
                        self.wait(state.key)
                        return None
                    if step.action == "edit":
                        mode, pages, edit_of = "progress", (step.body,), step.edit_of
                        if (
                            repeat
                            and repeats(step.body) >= REPEAT_HINT_AT
                            and not await self.repeat_hinted(session, binding, state, record, row)
                        ):
                            hint = repeats(step.body)
                    elif step.action == "post" and (not repeat or len(step.lines) > 1):
                        # A repeat posts as itself, unless an unsent edit's lines ride along.
                        pages = self.progress_pages(step.lines)
                plan = await self.queue_plan(
                    session,
                    binding,
                    state,
                    identity,
                    row.payload_hash,
                    mode,
                    pages,
                    locale,
                    # An edit changes a message already shown; replies after it
                    # never wait for it, and its failure never holds the topic.
                    independent=edit_of is not None,
                    edit_of=edit_of,
                )
                session.add(
                    TranscriptPublication(
                        version_id=identity,
                        batch_id=plan.batch_id,
                        payload=plan.model_dump(mode="json"),
                        payload_hash=digest(plan.model_dump(mode="json")),
                    )
                )
                created = True
                if hint:
                    await self.repeat_hint(session, binding, identity, hint, locale)
                said = value.observation.entry
                current = record.current_version == row.version and not value.historical
                if current and (said.kind in {"user", "idle"} or plain_reply(said)):
                    # The turn's reply, outcome or next input: its unsent hint is late.
                    await self.retire_repeat_hints(session, binding)
                tokens = said.context_tokens() if current and plain_reply(said) else None
                if (
                    plan.batch_id
                    and edit_of is None
                    and tokens is not None
                    and tokens >= LONG_CONTEXT_AT
                    and not await self.long_context_hinted(session, binding)
                ):
                    await self.long_context_hint(
                        session, binding, identity, plan.batch_id, tokens, locale
                    )
                if plan.batch_id and edit_of is None:
                    state = state.model_copy(update={"last_batch_id": plan.batch_id})
                    write_stream(stream, state)
        if created:
            return await self._committed(plan, binding, state)
        return await self.cached(plan, binding, state)
