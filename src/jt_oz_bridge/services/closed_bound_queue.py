"""One closed Source operation for fresh local queue admission and complete ACK.

No Native operation or cached ACL is introduced. Original standalone queue APIs
retain their fresh guards. Delivery independently reobserves its whole audience.
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Literal, cast

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE, DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.routing import RoutedInput, RoutingRateDeferred
from jt_oz_bridge.domain.schedules import looks_scheduled
from jt_oz_bridge.i18n import Translator, message_locale
from jt_oz_bridge.presentation.commands import bare_answer, parse_input
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.presentation.menu_buttons import notice_widget
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import scope
from jt_oz_bridge.services.bindings import BindingService, topic_key
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.outbox import Outbox, QueuedBatch, batch_digest
from jt_oz_bridge.services.queue import QueueReceipt, QueueService
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.zulip_events import (
    OLD_HELD_SECONDS,
    UNCHOSEN_HOLDS,
    ZulipEventJournal,
)
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import (
    Action,
    AuditEvent,
    DeliveryBatch,
    Grant,
    InputEvent,
    WorkerLease,
)
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex, ZulipQueue

PREFIX = "bound-local:"
RENDERER = "router-mobile-markdown-v2"
UNSETTLED = ("queued", "held", "dispatching", "admitted", "running", "ambiguous")
PERSON_PAUSES = frozenset(
    {"queue_paused", "interrupt_queued", "queue_paused_background_stop_unqualified"}
)
QUEUE_CHOICES = (*PERSON_PAUSES, "queue_resumed")
# `!stop`: it ends the running turn and holds what waited behind it.
STOP_PAUSE = "interrupt_queued"


async def last_queue_choice(session: AsyncSession, binding_id: str) -> str | None:
    choice: str | None = await session.scalar(
        select(AuditEvent.event)
        .where(AuditEvent.object_id == binding_id, AuditEvent.event.in_(QUEUE_CHOICES))
        .order_by(AuditEvent.created_at.desc())
        .limit(1)
    )
    return choice


async def person_paused(session: AsyncSession, binding_id: str) -> bool:
    """True when the latest queue choice on this topic is a person's pause."""
    return await last_queue_choice(session, binding_id) in PERSON_PAUSES


async def old_held(session: AsyncSession, binding_id: str, besides: str | None = None) -> bool:
    """A prompt waits here from an hour or more ago (see `OLD_HELD_SECONDS`)."""
    found = await session.scalar(
        select(Action.id)
        .where(
            Action.binding_id == binding_id,
            Action.id != (besides or ""),
            Action.operation == "prompt",
            Action.state.in_(("queued", "held")),
            Action.created_at <= time.time() - OLD_HELD_SECONDS,
        )
        .limit(1)
    )
    return found is not None


class ClosedBoundReadUnavailable(ZulipReadUnavailable):
    """Only the known preclaim read phase may produce this no-effects signal."""


class SavedBoundQueueReply(ControlModel):
    format: Literal["closed-bound-queue-v1"] = "closed-bound-queue-v1"
    source: HumanMessage
    binding_scope: BindingScope
    text: str
    locale: Locale
    action_id: str | None = None
    queued_batch_id: str | None = None
    # Desktop buttons the reply was queued with; older receipts have none.
    widget: str | None = None


class ClosedBoundQueue:
    def __init__(
        self,
        bindings: BindingService,
        reader: ZulipSourceReader,
        inbox: CommandInbox,
        queue: QueueService,
        outbox: Outbox,
        *,
        message_limit: int,
        topic_limit: int,
        continuity: TranscriptCollector | None,
        journal: ZulipEventJournal,
    ) -> None:
        if (
            not isinstance(reader, ZulipSourceReader)
            or reader.scope is not bindings.audience
            or queue.bindings is not bindings
            or outbox.bindings is not bindings
            or (continuity is not None and continuity.bindings is not bindings)
        ):
            raise ValueError("closed_bound_original_runtime_composition_required")
        if (
            inbox.db is not bindings.db
            or queue.db is not bindings.db
            or outbox.db is not bindings.db
        ):
            raise ValueError("closed_bound_original_database_required")
        if queue.fence != inbox.fence or outbox.fence != inbox.fence:
            raise ValueError("closed_bound_original_fence_required")
        self.bindings, self.reader, self.inbox = bindings, reader, inbox
        self.db, self.queue, self.outbox, self.fence = bindings.db, queue, outbox, inbox.fence
        self.message_limit, self.topic_limit, self.continuity = (
            message_limit,
            topic_limit,
            continuity,
        )
        self.tr = Translator()
        if (
            journal.db is not self.db
            or journal.fence != self.fence
            or getattr(reader.expected_channel, "__self__", None) is not journal
        ):
            raise ValueError("closed_bound_original_capture_issuer_required")
        self.journal = journal
        self._original = (
            bindings,
            reader,
            inbox,
            queue,
            outbox,
            continuity,
            journal,
            bindings.control,
            reader.scope,
        )
        if (
            outbox.bot_user_id != reader.scope.enrolled.bot_user_id
            or journal.realm_id != reader.scope.enrolled.realm_id
            or journal.bot_user_id != outbox.bot_user_id
            or journal.url != reader.scope.client.url.rstrip("/")
            or journal.channel_ids != reader.scope.channel_ids
        ):
            raise ValueError("closed_bound_original_server_scope_required")

    def _composition(self) -> None:
        actual = (
            self.bindings,
            self.reader,
            self.inbox,
            self.queue,
            self.outbox,
            self.continuity,
            self.journal,
            self.bindings.control,
            self.reader.scope,
        )
        if (
            any(a is not b for a, b in zip(actual, self._original, strict=True))
            or self.reader.scope is not self.bindings.audience
            or self.queue.bindings is not self.bindings
            or self.outbox.bindings is not self.bindings
        ):
            raise Conflict("closed_bound_original_composition_changed")

    @staticmethod
    def eligible(message: HumanMessage) -> bool:
        parsed = parse_input(message.text, bound=True)
        return (
            not message.is_bot
            and not message.deleted
            and message.revision == 0
            and (
                # A steer takes the original router, which says where the text goes.
                parsed.kind == "prompt"
                and parsed.command != "steer"
                # A repeat is shown back for `!confirm` by the original router.
                and not looks_scheduled(message.text)
                # So is a bare "ok", which may answer a question Bridge asked.
                and bare_answer(message.text) is None
                or parsed.kind == "command"
                and (
                    parsed.command == "cancel"
                    and 0 < len(parsed.arguments.strip()) <= 36
                    and not any(ch.isspace() for ch in parsed.arguments.strip())
                    or parsed.command == "queue"
                    and parsed.arguments.strip() == "resume"
                )
            )
        )

    def qualified(self) -> bool:
        self._composition()
        guard = self.reader.scope.client.verify_identity
        return callable(getattr(type(guard), "scope_reads", None)) and callable(
            getattr(type(guard), "scope_read", None)
        )

    async def candidate(self, message: HumanMessage) -> Binding | None:
        """SQL selection only. A returned row grants no Source/queue authority."""
        if not self.qualified() or not self.eligible(message):
            return None
        previous = await self.inbox.find(message.realm_id, message.message_id)
        if previous is not None and (
            previous.state != "completed"
            or previous.response.get("format") != "closed-bound-queue-v1"
        ):
            return None  # Legacy/processing/unknown attempts retain the original strict path.
        async with self.db.sessions() as session:
            return cast(
                Binding | None,
                await session.scalar(
                    select(Binding).where(
                        Binding.realm_id == message.realm_id,
                        Binding.topic_key
                        == topic_key(message.realm_id, message.channel_id, message.topic),
                        Binding.state == "active",
                    )
                ),
            )

    async def _sql(
        self,
        session: AsyncSession,
        expected: Binding,
        message: HumanMessage,
        audience: AudienceSnapshot,
        current: Callable[[], None],
        *,
        write: bool = True,
        fresh: bool = True,
    ) -> tuple[Binding, Action | None]:
        self._composition()
        current()
        if write:
            await self.fence.lock(session)
        else:
            import time

            lease = await session.get(WorkerLease, "consumer")
            if (
                lease is None
                or (lease.holder, lease.fencing) != (self.fence.holder, self.fence.fencing)
                or lease.expires_at <= time.time()
            ):
                raise Conflict("closed_bound_current_lease_required")
        current()
        binding = await lock_output_scope(self.bindings, session, expected)
        current()
        if (
            (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != (message.realm_id, message.channel_id, message.topic)
            or (binding.realm_id, binding.channel_id, binding.topic)
            != (message.realm_id, message.channel_id, message.topic)
            or not audience.private
            or audience.untrusted_bot_ids
            or message.author_id not in audience.user_ids
            or audience.revision != binding.audience_revision
            or set(audience.user_ids) != set(binding.audience_user_ids)
        ):
            raise AccessDenied("closed_bound_original_private_audience_required")
        await self._provenance(session, message, current, fresh=fresh)
        parsed = parse_input(message.text, bound=True)
        action = None
        needed = Permission.OPERATE
        if parsed.command == "cancel":
            identity = parsed.arguments.strip()
            if not identity or len(identity) > 36 or any(ch.isspace() for ch in identity):
                raise ValueError("invalid_action_identity")
            action = await session.get(Action, identity, with_for_update=True)
            current()
            if action is None or (action.binding_id, action.binding_revision) != (
                binding.id,
                binding.revision,
            ):
                raise AccessDenied("action_outside_current_topic")
            needed = (
                Permission.OPERATE if action.actor_id == message.author_id else Permission.MANAGE
            )
        roles = list(
            await session.scalars(
                select(Grant.role)
                .where(
                    Grant.realm_id == binding.realm_id,
                    Grant.project_id == binding.project_id,
                    Grant.user_id == message.author_id,
                    Grant.active.is_(True),
                )
                .with_for_update()
            )
        )
        current()
        if not any(needed in ROLES.get(role, set()) for role in roles):
            raise AccessDenied("closed_bound_current_actor_permission_required")
        return binding, action

    async def _provenance(
        self,
        session: AsyncSession,
        message: HumanMessage,
        current: Callable[[], None],
        *,
        fresh: bool,
    ) -> None:
        index = await session.get(ZulipMessageIndex, (message.realm_id, message.message_id))
        current()
        if (
            index is None
            or index.source != self.journal.source
            or index.state != "live"
            or index.channel_id != message.channel_id
        ):
            raise Conflict("closed_bound_original_capture_index_required")
        event = await session.get(InputEvent, index.input_event_id)
        current()
        if event is None:
            raise Conflict("closed_bound_original_capture_required")
        self.journal.validate_receipt(event)
        payload = event.payload
        wire = payload.get("wire", {})
        row = wire.get("message", {})
        if (
            wire.get("type") != "message"
            or row.get("type") != "stream"
            or (
                row.get("id"),
                row.get("stream_id"),
                row.get("subject"),
                row.get("sender_id"),
                row.get("content"),
            )
            != (
                message.message_id,
                message.channel_id,
                message.topic,
                message.author_id,
                message.text,
            )
        ):
            raise Conflict("closed_bound_original_wire_changed")
        if fresh:
            queue = await session.get(ZulipQueue, self.journal.source)
            current()
            # A recent message the previous process captured but never began
            # counts as fresh (the journal's claim decided the same).
            moved = (
                payload.get("capture_fencing") != self.fence.fencing
                or queue is None
                or queue.queue_id != payload.get("queue_id")
            ) and not self.journal.carried_over(payload)
            if (
                event.state != "zulip_processing"
                or moved
                or payload.get("processing_fencing") != self.fence.fencing
                or payload.get("recovery_run_id") is not None
                or payload.get("defer_recovered", False) is not False
                or wire.get("historical", False) is not False
                or row.get("last_edit_timestamp") is not None
                or queue is None
                or queue.state != "active"
            ):
                raise Conflict("closed_bound_recovered_or_historical_input_forbidden")

    def _pages(self, text: str, locale: Locale) -> tuple[str, ...]:
        header = self.tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text,
            self.message_limit,
            reserved_characters=len(header) + MARKER_FOOTER_SIZE,
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise ValueError("closed_bound_reply_capacity")
        return tuple(
            self.tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )

    async def _paused_key(self, session: AsyncSession, binding: Binding) -> str:
        """Point at the reconnect `!ok` when `!go` alone cannot lift this pause."""
        if self.continuity is not None:
            try:
                await self.continuity._require_continuity_in_session(session, binding)
            except Conflict as error:
                if str(error) == "transcript_gap_requires_review_and_rebind":
                    # `!ok` lifts the pause too unless a person chose it.
                    if await person_paused(session, binding.id):
                        return "router.paused_gap_stopped"
                    return "router.paused_gap"
        if await old_held(session, binding.id):
            return "router.paused_old"
        return "router.paused_input"

    async def paused_key(self, binding: Binding) -> str:
        async with self.db.sessions() as session:
            return await self._paused_key(session, binding)

    async def _continue_unchosen_pause(
        self, session: AsyncSession, binding: Binding, message: HumanMessage, action_id: str
    ) -> bool:
        """A new prompt resumes a pause no person chose, when only plain prompts wait.

        Restarts and outages pause without asking anyone; `!oz queue pause` stays
        until a person resumes. Prompts people sent during the pause go along in
        order; anything running, unclear or held for its own reason keeps the pause.
        Recovery review and stream gaps keep their own refusals, raised before any
        write, so a refusal just leaves the message held.

        `!stop` is like Esc: once the stop has settled, a message typed after it is
        new work and goes. Only what `!stop` itself held back waits for `!go` or
        `!no`, so this continues only when nothing else at all is unsettled.
        """
        if await last_queue_choice(session, binding.id) == STOP_PAUSE:
            if await session.scalar(
                select(Action.id)
                .where(
                    Action.binding_id == binding.id,
                    Action.id != action_id,
                    Action.state.in_(UNSETTLED),
                )
                .limit(1)
            ):
                return False
            return await self._resume(session, binding, message)
        waiting = await session.scalar(
            select(Action.id)
            .where(
                Action.binding_id == binding.id,
                Action.id != action_id,
                Action.state.in_(UNSETTLED),
                ~and_(
                    Action.operation == "prompt",
                    # The dispatcher's pause hold is the same unchosen pause.
                    or_(
                        Action.status_reason.is_(None),
                        Action.status_reason.in_(sorted(UNCHOSEN_HOLDS)),
                    ),
                    Action.state.in_(("queued", "held")),
                ),
            )
            .limit(1)
        )
        if (
            waiting is not None
            or await person_paused(session, binding.id)
            or await old_held(session, binding.id, besides=action_id)
        ):
            # An old message keeps the pause: the person picks `!go new`, `!go` or `!no`.
            return False
        return await self._resume(session, binding, message)

    async def _resume(self, session: AsyncSession, binding: Binding, message: HumanMessage) -> bool:
        try:
            if self.continuity is not None:
                await self.continuity._require_continuity_in_session(session, binding)
            await self.queue._resume_in_session(
                session,
                binding,
                message.realm_id,
                message.author_id,
                binding.revision,
                binding.queue_revision,
            )
        except Conflict:
            return False
        return True

    async def continued(
        self, session: AsyncSession, binding: Binding, message: HumanMessage, receipt: QueueReceipt
    ) -> QueueReceipt:
        """The admitted prompt, queued when it may continue a pause no person chose.

        Both message paths call this inside their admission transaction, so a
        `!steer` or any other prompt the original router admits follows the same
        rule as a plain message.
        """
        if (
            receipt.state == "held"
            and receipt.paused_at_admission
            and not receipt.already_dispatched
            and await self._continue_unchosen_pause(session, binding, message, receipt.action_id)
        ):
            return replace(receipt, state="queued")
        return receipt

    def _routed(self, saved: SavedBoundQueueReply, receipt_id: str) -> RoutedInput:
        return RoutedInput(
            "reply" if saved.queued_batch_id is not None else "ignore",
            saved.binding_scope.binding_id,
            saved.binding_scope.revision,
            saved.text,
            PREFIX + receipt_id,
            saved.action_id,
            locale=saved.locale,
            queued_batch_id=saved.queued_batch_id,
        )

    async def route(self, expected: Binding, message: HumanMessage) -> RoutedInput:
        self._composition()
        if not self.eligible(message):
            raise Conflict("closed_bound_fresh_original_input_required")
        previous = await self.inbox.find(message.realm_id, message.message_id)
        replay = previous is not None and previous.state == "completed"
        parsed = parse_input(message.text, bound=True)
        operation = "prompt" if parsed.kind == "prompt" else parsed.command
        locale = await message_locale(
            self.db,
            self.reader,
            message,
            cast(Locale, expected.locale) if expected.locale in {"en", "zh-TW"} else "en",
        )

        async def read_only(
            audience: AudienceSnapshot,
        ) -> tuple[AudienceSnapshot, ZulipLocalWritePermit]:
            permit = self.reader.scope.local_write_permit(self.reader, message, audience)

            def read_current() -> None:
                self._composition()
                self.reader.scope.require_read_permit(permit, self.reader, message, audience)

            async with self.db.sessions.begin() as session:
                await self._sql(
                    session,
                    expected,
                    message,
                    audience,
                    read_current,
                    write=False,
                    fresh=not replay,
                )
                if operation == "queue" and self.continuity is not None:
                    await self.continuity._require_continuity_in_session(session, expected)
                    read_current()
            return audience, permit

        try:
            observation = await self.reader.scope.observe_sources(
                self.reader, (message,), read_only=read_only
            )
        except DeliveryRateLimited as error:
            raise RoutingRateDeferred(error.retry_after) from None
        except ZulipReadUnavailable:
            raise ClosedBoundReadUnavailable(
                "closed_bound_preclaim_source_read_unavailable"
            ) from None
        observed = self.reader.scope.consume_observation(observation, self.reader, (message,))
        audience, permit = observed.value

        def current() -> None:
            self._composition()
            self.reader.scope.require_write_permit(permit, self.reader, message, audience)

        current()
        claim = (
            await self.inbox._claim_bound_prompt(
                message,
                expected.id,
                expected.revision,
                reader=self.reader,
                permit=permit,
                audience=audience,
            )
            if operation == "prompt"
            else await self.inbox.claim(
                message, operation, binding_id=expected.id, binding_revision=expected.revision
            )
        )
        result: RoutedInput | None = None
        try:
            current()
            if claim.status == "replay":
                saved = SavedBoundQueueReply.model_validate(claim.response)
                if saved.source != message or saved.binding_scope != scope(expected):
                    raise Conflict("closed_bound_replay_original_scope_changed")
                routed = self._routed(saved, claim.id)
                if routed.state == "ignore":
                    return routed
                await self.committed(routed)
                current()
                return routed
            if claim.status != "claimed":
                raise Conflict("closed_bound_command_not_owned")

            async def commit(session: AsyncSession) -> None:
                nonlocal result
                binding, action = await self._sql(session, expected, message, audience, current)
                action_id = None
                silent = False
                widget = None
                if operation == "prompt":
                    receipt = await self.queue._receive_in_session(
                        session, binding, message, reply_locale=locale
                    )
                    current()
                    action_id = receipt.action_id
                    receipt = await self.continued(session, binding, message, receipt)
                    current()
                    # Typing and the reply already show an accepted message is moving.
                    silent = not receipt.already_dispatched and receipt.state != "held"
                    key = (
                        "router.not_editable"
                        if receipt.already_dispatched
                        else await self._paused_key(session, binding)
                        if receipt.state == "held" and receipt.paused_at_admission
                        else "action.held"
                        if receipt.state == "held"
                        else "action.received"
                    )
                    text = (
                        self.tr.render(
                            key,
                            locale,
                            state=self.tr.render("queue.state." + receipt.state, locale),
                        )
                        if receipt.already_dispatched
                        else self.tr.render(key, locale)
                    )
                    if not receipt.already_dispatched:
                        widget = notice_widget(key, text, lambda name: self.tr.render(name, locale))
                elif operation == "cancel":
                    assert action is not None
                    changed = await self.queue._cancel_in_session(session, action)
                    current()
                    text = self.tr.render(
                        "router.cancelled" if changed else "router.not_cancelled", locale
                    )
                else:
                    if self.continuity is not None:
                        await self.continuity._require_continuity_in_session(session, binding)
                        current()
                    await self.queue._resume_in_session(
                        session,
                        binding,
                        message.realm_id,
                        message.author_id,
                        expected.revision,
                        expected.queue_revision,
                    )
                    current()
                    text = self.tr.render("router.resumed", locale)
                queued = (
                    None
                    if silent
                    else await self.outbox.queue_batch_in_session(
                        session,
                        PREFIX + claim.id,
                        binding,
                        self._pages(text, locale),
                        renderer_version=RENDERER,
                        message_limit=self.message_limit,
                        topic_limit=self.topic_limit,
                        priority=10,
                        widget=widget,
                    )
                )
                current()
                await self._sql(session, expected, message, audience, current)
                saved = SavedBoundQueueReply(
                    source=message,
                    binding_scope=scope(binding),
                    text=text,
                    locale=locale,
                    action_id=action_id,
                    queued_batch_id=queued.id if queued is not None else None,
                    widget=widget if queued is not None else None,
                )
                receipt_updated = await session.execute(
                    update(CommandReceipt)
                    .where(
                        CommandReceipt.id == claim.id,
                        CommandReceipt.state == "completed",
                        CommandReceipt.version == claim.version + 1,
                        CommandReceipt.holder == self.fence.holder,
                        CommandReceipt.fencing == self.fence.fencing,
                    )
                    # Without buttons the receipt keeps the shape older releases read.
                    .values(
                        response=saved.model_dump(
                            mode="json", exclude={"widget"} if saved.widget is None else None
                        )
                    )
                )
                current()
                if receipt_updated.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("closed_bound_receipt_changed")
                await self.fence.lock(session)
                current()
                result = self._routed(saved, claim.id)

            await self.inbox.finish(claim, {}, commit=commit)
        except BaseException:
            try:
                if claim.status == "claimed":
                    await asyncio.shield(self.inbox.abandon(claim))
            except (Conflict, asyncio.CancelledError):
                pass
            raise
        if result is None:
            raise Conflict("closed_bound_commit_unknown")
        current()
        return result

    async def committed(self, routed: RoutedInput) -> QueuedBatch:
        """Validate only existing full work; no network, output creation or Native call."""
        self._composition()
        if not routed.delivery_key or not routed.delivery_key.startswith(PREFIX):
            raise Conflict("closed_bound_committed_key_required")
        identity = routed.delivery_key.removeprefix(PREFIX)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            row = await session.get(CommandReceipt, identity, with_for_update=True)
            if row is None or row.state != "completed":
                raise Conflict("closed_bound_committed_receipt_required")
            saved = SavedBoundQueueReply.model_validate(row.response)
            parsed = parse_input(saved.source.text, bound=True)
            expected_command = "prompt" if parsed.kind == "prompt" else parsed.command
            if (
                row.source_revision != saved.source.revision
                or row.command != expected_command
                or self._routed(saved, row.id) != routed
                or row.source_hash != digest(saved.source.model_dump(mode="json"))
                or (
                    row.realm_id,
                    row.message_id,
                    row.actor_id,
                    row.channel_id,
                    row.topic,
                    row.binding_id,
                    row.binding_revision,
                )
                != (
                    saved.source.realm_id,
                    saved.source.message_id,
                    saved.source.author_id,
                    saved.source.channel_id,
                    saved.source.topic,
                    saved.binding_scope.binding_id,
                    saved.binding_scope.revision,
                )
            ):
                raise Conflict("closed_bound_committed_source_or_body_changed")
            binding = await session.get(Binding, saved.binding_scope.binding_id)
            if binding is None or scope(binding) != saved.binding_scope:
                raise Conflict("closed_bound_committed_binding_changed")
            audience = AudienceSnapshot(
                realm_id=binding.realm_id,
                channel_id=binding.channel_id,
                canonical_topic=binding.topic,
                user_ids=frozenset(binding.audience_user_ids),
                untrusted_bot_ids=frozenset(),
                private=True,
                revision=binding.audience_revision,
            )
            # Stored audience is data for the existing SQL guards, never remote
            # permission or a fresh write permit. No new output can be queued.
            await self._sql(session, binding, saved.source, audience, lambda: None, fresh=False)
            batch = await session.get(DeliveryBatch, saved.queued_batch_id)
            if batch is None or (
                batch.renderer_version != RENDERER
                or batch.dedupe_key
                != "reply-batch:"
                + digest(
                    {"key": PREFIX + row.id, "binding": binding.id, "revision": binding.revision}
                )
                or (batch.message_limit, batch.topic_limit, batch.priority, batch.page_count)
                != (
                    self.message_limit,
                    self.topic_limit,
                    10,
                    len(self._pages(saved.text, saved.locale)),
                )
            ):
                raise Conflict("closed_bound_committed_batch_required")
            queued = await self.outbox._validated_batch(binding, batch)
            if batch.plan_hash != batch_digest(
                self._pages(saved.text, saved.locale),
                RENDERER,
                self.message_limit,
                self.topic_limit,
                None,
                saved.widget,
            ):
                raise Conflict("closed_bound_committed_pages_changed")
            await self._sql(session, binding, saved.source, audience, lambda: None, fresh=False)
            await self.fence.lock(session)
            return queued
