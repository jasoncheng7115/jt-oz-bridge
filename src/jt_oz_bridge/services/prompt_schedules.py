"""Repeating prompts in a bound topic: propose, one `!confirm`, then timed ordinary prompts.

A message such as "every 30 minutes check my mail until 18:00" is not sent. The bridge
answers with what it understood and opens a ten-minute confirmation for that person
only. `!confirm` records one schedule; `!once` sends the message as written instead.

Each due time re-reads the original message and the person's grant and channel
audience in full, then records one ordinary prompt Action of that person with the
short task as its text. It waits its turn like any prompt. A time that comes while
the previous send is still waiting or running, or while the queue is paused, is
skipped, never piled up. Editing or deleting the original message, losing access, or
unbinding the topic stops the schedule. Native gets nothing but those prompts.
"""

import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, cast
from zoneinfo import ZoneInfo

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.git_publish import CONFIRM_TOKEN as GIT_PUBLISH_TOKEN
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.operations import current_operation
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.domain.schedules import (
    SCHEDULE_TOKEN,
    ScheduleAsk,
    ScheduleFire,
    ScheduleRefused,
    detect,
    ends_at,
    fire_count,
    looks_scheduled,
    scheduled_text,
)
from jt_oz_bridge.domain.session_lifecycle import LIFECYCLE_TOKEN_KINDS
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import literal
from jt_oz_bridge.presentation.menu_buttons import notice_widget
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant
from jt_oz_bridge.storage.schedule_models import PromptSchedule

LOG = logging.getLogger(__name__)
CONFIRM_TTL = 600
# A proposal replaces any other confirmation still open for this person here.
OTHER_TOKENS = (
    *LIFECYCLE_TOKEN_KINDS,
    GIT_PUBLISH_TOKEN,
    "native-agent-menu",
    "native-agent-confirm",
)
OPEN = ("queued", "held", "dispatching", "admitted", "running", "ambiguous")
DUE_BATCH = 16


class ScheduleConfirmation(ControlModel):
    reference: SessionRef
    source: HumanMessage
    ask: ScheduleAsk
    ends_at: float
    locale: Locale


class ScheduleRecord(ControlModel):
    reference: SessionRef
    source: HumanMessage
    ask: ScheduleAsk
    locale: Locale


class PromptSchedules:
    def __init__(
        self,
        bindings: BindingService,
        tokens: TokenService,
        reader: SourceReader,
        queue: QueueService,
        *,
        timezone: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            tokens.db is not bindings.db
            or tokens.fence is None
            or queue.bindings is not bindings
            or queue.fence != tokens.fence
        ):
            raise ValueError("prompt_schedules_require_shared_database_and_consumer_fence")
        self.bindings, self.db, self.tokens = bindings, bindings.db, tokens
        self.reader, self.queue, self.fence = reader, queue, tokens.fence
        self.zone, self.clock, self.tr = ZoneInfo(timezone), clock, Translator()
        # Trusted composition only; None keeps sends working without their notices.
        self.replies: RoutedOutbox | None = None

    # -- formatting

    def _every(self, seconds: int, locale: Locale) -> str:
        hours, minutes = divmod(seconds // 60, 60)
        parts = []
        if hours:
            parts.append(self.tr.render("schedule.hours", locale, count=str(hours)))
        if minutes:
            parts.append(self.tr.render("schedule.minutes", locale, count=str(minutes)))
        return " ".join(parts)

    def _clock(self, when: float, locale: Locale) -> str:
        moment = datetime.fromtimestamp(when, self.zone)
        today = datetime.fromtimestamp(self.clock(), self.zone).date()
        shown = moment.strftime("%H:%M")
        if moment.date() == today:
            return shown
        return self.tr.render("schedule.tomorrow", locale, time=shown)

    def _task(self, ask: ScheduleAsk) -> str:
        return literal(ask.text)

    def _refusal(self, error: ScheduleRefused, locale: Locale) -> str:
        return self.tr.render(error.key, locale, **error.values)

    # -- routing

    def candidate(self, message: HumanMessage) -> bool:
        """A new plain prompt that reads as a repeat (or a refused one)."""
        return not message.is_bot and not message.deleted and looks_scheduled(message.text)

    async def owns_source(self, message: HumanMessage) -> bool:
        """An edit of a message that started a schedule belongs here, not to the AI."""
        if message.revision == 0:
            return False
        async with self.db.sessions() as session:
            found = await session.scalar(
                select(PromptSchedule.id)
                .where(
                    PromptSchedule.realm_id == message.realm_id,
                    PromptSchedule.source_message_id == message.message_id,
                )
                .limit(1)
            )
        return found is not None

    async def _current(self, binding: Binding, message: HumanMessage) -> Binding:
        if (
            message.is_bot
            or message.deleted
            or (message.realm_id, message.channel_id, message.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(message.realm_id, message.message_id) != message
        ):
            raise Conflict("schedule_original_human_source_changed")
        current = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("schedule_binding_changed")
        return current

    async def _lock_operator(
        self, session: AsyncSession, binding: Binding, realm: str, actor: int
    ) -> Binding:
        await self.fence.lock(session)
        current = await lock_output_scope(self.bindings, session, binding)
        grant = await session.scalar(
            select(Grant.id)
            .where(
                Grant.realm_id == realm,
                Grant.user_id == actor,
                Grant.project_id == binding.project_id,
                Grant.active.is_(True),
                Grant.role.in_([r for r, p in ROLES.items() if Permission.OPERATE in p]),
            )
            .with_for_update()
        )
        if grant is None:
            raise AccessDenied("schedule_operate_grant_changed")
        return current

    async def _retire(self, session: AsyncSession, binding: Binding, message: HumanMessage) -> None:
        await session.execute(
            update(ControlToken)
            .where(
                ControlToken.kind.in_([SCHEDULE_TOKEN, *OTHER_TOKENS]),
                ControlToken.realm_id == message.realm_id,
                ControlToken.user_id == message.author_id,
                ControlToken.binding_id == binding.id,
                ControlToken.used.is_(False),
            )
            .values(used=True)
        )

    async def propose(self, binding: Binding, message: HumanMessage, locale: Locale) -> RoutedInput:
        binding = await self._current(binding, message)
        prefix = ""
        if message.revision > 0 and await self._stop_source(binding, message):
            prefix = self.tr.render("schedule.edited", locale) + "\n\n"
        async with self.db.sessions() as session:
            existing = await session.scalar(
                select(PromptSchedule.id).where(
                    PromptSchedule.realm_id == message.realm_id,
                    PromptSchedule.source_message_id == message.message_id,
                    PromptSchedule.state == "active",
                )
            )
        widget = None
        if existing is not None:
            # A replayed event of a confirmed message opens nothing new.
            text = self.tr.render("schedule.already", locale)
        else:
            proposal, proposed = await self._proposal(binding, message, locale)
            text = prefix + proposal
            if proposed:
                widget = notice_widget(
                    "schedule.proposal", text, lambda name: self.tr.render(name, locale)
                )
        return RoutedInput(
            "reply",
            binding.id,
            binding.revision,
            text,
            f"schedule-proposal:{message.realm_id}:{message.message_id}:{message.revision}",
            locale=locale,
            widget=widget,
        )

    async def _proposal(
        self, binding: Binding, message: HumanMessage, locale: Locale
    ) -> tuple[str, bool]:
        """The reply, and whether it opened a question that `!ok` answers."""
        try:
            ask = detect(message.text)
            if ask is None:
                # An edit that no longer asks for a repeat is not sent either.
                return self.tr.render("schedule.edited_plain", locale), False
            end = ends_at(ask, datetime.fromtimestamp(self.clock(), self.zone)).timestamp()
            count = fire_count(ask, self.clock(), end)
        except ScheduleRefused as error:
            return self._refusal(error, locale), False
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(
                session, binding, message.realm_id, message.author_id
            )
            await self._retire(session, current, message)
        if binding.dispatch_paused:
            return self.tr.render("schedule.paused", locale), False
        await self.tokens.issue(
            SCHEDULE_TOKEN,
            message.realm_id,
            message.author_id,
            ScheduleConfirmation(
                reference=reference(binding), source=message, ask=ask, ends_at=end, locale=locale
            ).model_dump(mode="json"),
            ttl=CONFIRM_TTL,
            binding_id=binding.id,
            binding_revision=binding.revision,
        )
        return (
            self.tr.render(
                "schedule.proposal",
                locale,
                every=self._every(ask.interval_seconds, locale),
                task=self._task(ask),
                end=self._clock(end, locale),
                count=str(count),
            ),
            True,
        )

    async def _open(self, binding: Binding, message: HumanMessage) -> ControlToken | None:
        async with self.db.sessions() as session:
            saved: ControlToken | None = await session.scalar(
                select(ControlToken)
                .where(
                    ControlToken.kind == SCHEDULE_TOKEN,
                    ControlToken.realm_id == message.realm_id,
                    ControlToken.user_id == message.author_id,
                    ControlToken.binding_id == binding.id,
                    ControlToken.binding_revision == binding.revision,
                    ControlToken.used.is_(False),
                    ControlToken.expires_at > time.time(),
                )
                .order_by(ControlToken.expires_at.desc())
                .limit(1)
            )
        if saved is not None and saved.context_hash != digest(saved.context):
            raise Conflict("schedule_token_context_changed")
        return saved

    async def owns_confirm(self, binding: Binding, message: HumanMessage) -> bool:
        return await self._open(binding, message) is not None

    async def _confirmation(
        self, binding: Binding, message: HumanMessage
    ) -> tuple[ControlToken, ScheduleConfirmation] | None:
        saved = await self._open(binding, message)
        if saved is None:
            return None
        confirmation = ScheduleConfirmation.model_validate(saved.context)
        source = confirmation.source
        if (
            confirmation.reference != reference(binding)
            or source.message_id == message.message_id
            or source.author_id != message.author_id
            or (source.realm_id, source.channel_id, source.topic)
            != (message.realm_id, message.channel_id, message.topic)
            or await self.reader.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("schedule_proposal_source_changed")
        try:
            ask = detect(source.text)
        except ScheduleRefused:
            ask = None
        if ask != confirmation.ask:
            raise Conflict("schedule_proposal_source_changed")
        return saved, confirmation

    async def confirm(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        binding = await self._current(binding, message)
        found = await self._confirmation(binding, message)
        if found is None:
            return self.tr.render("schedule.nothing_open", locale)
        saved, confirmation = found
        now = self.clock()
        try:
            count = fire_count(confirmation.ask, now, confirmation.ends_at)
        except ScheduleRefused as error:
            return self._refusal(error, locale)
        source = confirmation.source
        record = ScheduleRecord(
            reference=reference(binding),
            source=source,
            ask=confirmation.ask,
            locale=confirmation.locale,
        ).model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(
                session, binding, message.realm_id, message.author_id
            )
            if current.dispatch_paused:
                return self.tr.render("schedule.paused", locale)
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, current, message)
            schedule = PromptSchedule(
                dedupe_key="schedule:" + saved.token_hash,
                binding_id=binding.id,
                binding_revision=binding.revision,
                realm_id=binding.realm_id,
                actor_id=message.author_id,
                source_message_id=source.message_id,
                payload=record,
                payload_hash=digest(record),
                interval_seconds=confirmation.ask.interval_seconds,
                starts_at=now,
                ends_at=confirmation.ends_at,
                next_at=now,
                total=count,
                sent=0,
                skipped=0,
                state="active",
                version=1,
                created_at=now,
                updated_at=now,
            )
            session.add(schedule)
            await session.flush()
            session.add(
                AuditEvent(
                    actor=f"{message.realm_id}:{message.author_id}",
                    event="prompt_schedule_confirmed",
                    object_id=schedule.id,
                )
            )
        return self.tr.render(
            "schedule.set",
            locale,
            every=self._every(confirmation.ask.interval_seconds, locale),
            task=self._task(confirmation.ask),
            end=self._clock(confirmation.ends_at, locale),
            count=str(count),
        )

    async def once(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        """Send the proposed message once, exactly as written, as an ordinary prompt."""
        binding = await self._current(binding, message)
        found = await self._confirmation(binding, message)
        if found is None:
            return self.tr.render("schedule.nothing_open", locale)
        saved, confirmation = found
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(
                session, binding, message.realm_id, message.author_id
            )
            await self.tokens.consume_in_session(session, saved)
            await self._retire(session, current, message)
        receipt = await self.queue.receive(binding.id, confirmation.source, reply_locale=locale)
        return self.tr.render("schedule.once" if receipt.state != "held" else "action.held", locale)

    # -- list / stop

    async def _active(self, binding: Binding) -> list[PromptSchedule]:
        async with self.db.sessions() as session:
            return list(
                (
                    await session.scalars(
                        select(PromptSchedule)
                        .where(
                            PromptSchedule.binding_id == binding.id,
                            PromptSchedule.binding_revision == binding.revision,
                            PromptSchedule.state == "active",
                        )
                        .order_by(PromptSchedule.created_at, PromptSchedule.id)
                    )
                ).all()
            )

    async def route(
        self, binding: Binding, message: HumanMessage, locale: Locale, arguments: str
    ) -> str:
        words = arguments.split()
        if words == ["stop"]:
            return await self.stop(binding, message, locale)
        if words:
            raise ValueError("schedule_takes_stop_only")
        await self.bindings.get(binding.id, message.realm_id, message.author_id)
        rows = await self._active(binding)
        if not rows:
            return self.tr.render("schedule.none", locale)
        lines = [self.tr.render("schedule.list_title", locale)]
        for index, row in enumerate(rows, 1):
            record = ScheduleRecord.model_validate(row.payload)
            lines.append(
                self.tr.render(
                    "schedule.row",
                    locale,
                    number=str(index),
                    every=self._every(row.interval_seconds, locale),
                    task=self._task(record.ask),
                    sent=str(row.sent),
                    total=str(row.total),
                    next=self._clock(row.next_at, locale),
                    end=self._clock(row.ends_at, locale),
                )
            )
        return "\n".join(lines) + "\n\n" + self.tr.render("schedule.stop_hint", locale)

    async def stop(self, binding: Binding, message: HumanMessage, locale: Locale) -> str:
        stopped = await self.halt(binding, message)
        if not stopped:
            return self.tr.render("schedule.none_to_stop", locale)
        return self.tr.render("schedule.stopped", locale, count=str(stopped))

    async def halt(self, binding: Binding, message: HumanMessage) -> int:
        """Stop this person's schedules here; a manager also stops everyone else's."""
        binding = await self.bindings.get(
            binding.id, message.realm_id, message.author_id, Permission.OPERATE
        )
        try:
            await self.bindings.get(
                binding.id, message.realm_id, message.author_id, Permission.MANAGE
            )
            everyone = True
        except AccessDenied:
            everyone = False
        rows = [
            r for r in await self._active(binding) if everyone or r.actor_id == message.author_id
        ]
        stopped = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            for row in rows:
                stopped += await self._cancel_in_session(session, row, "stopped")
            if stopped:
                session.add(
                    AuditEvent(
                        actor=f"{message.realm_id}:{message.author_id}",
                        event="prompt_schedules_stopped",
                        object_id=binding.id,
                    )
                )
        return stopped

    async def _cancel_in_session(
        self, session: AsyncSession, row: PromptSchedule, reason: str
    ) -> int:
        """Stop one schedule and every send of it that has not reached OpenCode."""
        result = await session.execute(
            update(PromptSchedule)
            .where(
                PromptSchedule.id == row.id,
                PromptSchedule.version == row.version,
                PromptSchedule.state == "active",
            )
            .values(
                state="cancelled",
                status_reason=reason,
                version=row.version + 1,
                updated_at=self.clock(),
            )
        )
        if result.rowcount != 1:  # type: ignore[attr-defined]
            return 0
        await session.execute(
            update(Action)
            .where(
                Action.dedupe_key.like(f"schedule:{row.id}:%"),
                Action.state.in_(["queued", "held"]),
            )
            .values(
                state="cancelled", status_reason="schedule_" + reason, version=Action.version + 1
            )
        )
        return 1

    async def _stop_source(self, binding: Binding, message: HumanMessage) -> bool:
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(PromptSchedule).where(
                        PromptSchedule.realm_id == message.realm_id,
                        PromptSchedule.source_message_id == message.message_id,
                        PromptSchedule.state == "active",
                    )
                )
            ).all()
        if not rows:
            return False
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            for row in rows:
                await self._cancel_in_session(session, row, "source_changed")
        return True

    # -- timed sends

    async def fire_once(self) -> int:
        """Record the sends that are due now; returns how many schedules moved."""
        now = self.clock()
        async with self.db.sessions() as session:
            due = list(
                (
                    await session.scalars(
                        select(PromptSchedule.id)
                        .where(PromptSchedule.state == "active", PromptSchedule.next_at <= now)
                        .order_by(PromptSchedule.next_at, PromptSchedule.id)
                        .limit(DUE_BATCH)
                    )
                ).all()
            )
        moved = 0
        for identity in due:
            try:
                moved += await self._fire(str(identity), now)
            except Conflict:
                # Audience under review, a topic changing under us: send nothing this time.
                LOG.warning("schedule_time_skipped_not_current")
                moved += await self._skip(str(identity), now)
        return moved

    async def _skip(self, identity: str, now: float) -> int:
        row = await self._load(identity)
        if row is None or row.state != "active" or row.next_at > now:
            return 0
        slot = min(int((now - row.starts_at) // row.interval_seconds), row.total - 1)
        values: dict[str, Any] = {
            "next_at": row.starts_at + (slot + 1) * row.interval_seconds,
            "skipped": slot + 1 - row.sent,
            "version": row.version + 1,
            "updated_at": now,
        }
        if slot + 1 >= row.total:
            values |= {"state": "completed", "status_reason": "completed"}
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            result = await session.execute(
                update(PromptSchedule)
                .where(
                    PromptSchedule.id == row.id,
                    PromptSchedule.version == row.version,
                    PromptSchedule.state == "active",
                )
                .values(**values)
            )
        return int(result.rowcount == 1)  # type: ignore[attr-defined]

    async def _load(self, identity: str) -> PromptSchedule | None:
        async with self.db.sessions() as session:
            return cast(PromptSchedule | None, await session.get(PromptSchedule, identity))

    async def _stop(self, row: PromptSchedule, reason: str, *, notify: bool) -> int:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            stopped = await self._cancel_in_session(session, row, reason)
        if stopped and notify:
            record = ScheduleRecord.model_validate(row.payload)
            await self._notice(
                row,
                f"schedule-stop:{row.id}",
                self.tr.render("schedule.cancelled." + reason, record.locale),
                record.locale,
            )
        return stopped

    async def _notice(self, row: PromptSchedule, key: str, text: str, locale: Locale) -> None:
        if self.replies is None:
            return
        try:
            await self.replies.publish(
                RoutedInput("reply", row.binding_id, row.binding_revision, text, key, locale=locale)
            )
        except (Conflict, AccessDenied):
            # The topic changed or lost its audience; the schedule state already says why.
            LOG.warning("schedule_notice_not_queued")

    async def _fire(self, identity: str, now: float) -> int:
        row = await self._load(identity)
        if row is None or row.state != "active" or row.next_at > now:
            return 0
        if row.payload_hash != digest(row.payload):
            raise Conflict("schedule_payload_changed")
        record = ScheduleRecord.model_validate(row.payload)
        slot = int((now - row.starts_at) // row.interval_seconds)
        if slot >= row.total or now > row.ends_at + row.interval_seconds:
            return await self._finish(row, "completed")
        try:
            binding = await self.bindings.get(
                row.binding_id, row.realm_id, row.actor_id, Permission.OPERATE
            )
        except AccessDenied:
            async with self.db.sessions() as session:
                stored = await session.get(Binding, row.binding_id)
            changed = (
                stored is None
                or stored.state != "active"
                or stored.revision != row.binding_revision
            )
            return await self._stop(
                row,
                "binding_changed" if changed else "authorization_revoked",
                notify=not changed,
            )
        if binding.revision != row.binding_revision or reference(binding) != record.reference:
            return await self._stop(row, "binding_changed", notify=False)
        source = record.source
        if await self.reader.read(source.realm_id, source.message_id) != source:
            return await self._stop(row, "source_changed", notify=True)
        payload: dict[str, Any] = {
            "operation": "prompt",
            "reference": record.reference.model_dump(mode="json"),
            "text": record.ask.text,
            "source": source.model_dump(mode="json"),
            "reply_locale": record.locale,
            "schedule": ScheduleFire(
                id=row.id, index=slot + 1, total=row.total, ask=record.ask
            ).model_dump(mode="json"),
        }
        sent = False
        async with self.db.sessions.begin() as session:
            current = await self._lock_operator(session, binding, row.realm_id, row.actor_id)
            locked = await session.scalar(
                select(PromptSchedule).where(PromptSchedule.id == row.id).with_for_update()
            )
            if locked is None or locked.version != row.version or locked.state != "active":
                return 0
            busy = await session.scalar(
                select(Action.id)
                .where(
                    Action.dedupe_key.like(f"schedule:{row.id}:%"),
                    Action.state.in_(OPEN),
                )
                .limit(1)
            )
            values: dict[str, Any] = {
                "next_at": row.starts_at + (slot + 1) * row.interval_seconds,
                "version": row.version + 1,
                "updated_at": now,
            }
            # Times that passed while the bridge was down count as skipped.
            missed = slot - (row.sent + row.skipped)
            if current.dispatch_paused or busy is not None:
                values["skipped"] = row.skipped + missed + 1
            else:
                action = Action(
                    dedupe_key=f"schedule:{row.id}:{slot + 1}",
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    actor_id=row.actor_id,
                    payload=payload,
                    operation=current_operation(payload),
                    operation_digest=digest(payload),
                    state="queued",
                )
                session.add(action)
                await session.flush()
                values |= {
                    "sent": row.sent + 1,
                    "skipped": row.skipped + missed,
                    "last_action_id": action.id,
                }
                sent = True
            if slot + 1 >= row.total:
                values |= {"state": "completed", "status_reason": "completed"}
            await session.execute(
                update(PromptSchedule).where(PromptSchedule.id == row.id).values(**values)
            )
        if sent:
            await self._notice(
                row,
                f"schedule-fire:{row.id}:{slot + 1}",
                self.tr.render(
                    "schedule.fire_last" if slot + 1 >= row.total else "schedule.fire",
                    record.locale,
                    index=str(slot + 1),
                    total=str(row.total),
                    task=self._task(record.ask),
                ),
                record.locale,
            )
        return 1

    async def _finish(self, row: PromptSchedule, reason: str) -> int:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            result = await session.execute(
                update(PromptSchedule)
                .where(
                    PromptSchedule.id == row.id,
                    PromptSchedule.version == row.version,
                    PromptSchedule.state == "active",
                )
                .values(
                    state="completed",
                    status_reason=reason,
                    skipped=row.total - row.sent,
                    version=row.version + 1,
                    updated_at=self.clock(),
                )
            )
        return int(result.rowcount == 1)  # type: ignore[attr-defined]

    # -- dispatch

    async def refresh(self, action: Action, binding: Binding, latest: HumanMessage) -> Action:
        """Dispatch-time check of one timed prompt; a changed one is cancelled, not held."""
        fire = ScheduleFire.model_validate(action.payload.get("schedule"))
        if action.dedupe_key != f"schedule:{fire.id}:{fire.index}":
            raise Conflict("scheduled_prompt_identity_changed")
        row = await self._load(fire.id)
        reason = None
        if row is None or row.state == "cancelled":
            reason = "schedule_stopped"
        elif (
            row.binding_id != binding.id
            or row.binding_revision != binding.revision
            or row.actor_id != action.actor_id
        ):
            reason = "schedule_binding_changed"
        elif latest.model_dump(mode="json") != action.payload.get("source"):
            reason = "schedule_source_changed"
        if reason is None:
            try:
                scheduled_text(latest.text, fire.model_dump(mode="json"))
            except ValueError:
                reason = "schedule_source_changed"
        if reason is not None:
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                await session.execute(
                    update(Action)
                    .where(
                        Action.id == action.id,
                        Action.version == action.version,
                        Action.state.in_(["queued", "held"]),
                    )
                    .values(state="cancelled", status_reason=reason, version=action.version + 1)
                )
            if row is not None and row.state == "active" and reason == "schedule_source_changed":
                await self._stop(row, "source_changed", notify=True)
        async with self.db.sessions() as session:
            fresh = await session.get(Action, action.id)
        if fresh is None:
            raise Conflict("scheduled_prompt_missing")
        return fresh
