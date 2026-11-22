"""One explicit qualified Zulip queue attempt into the existing authorized router.

No native writer, reconnect/backfill claim, fabricated human or automatic startup.
After a restart, recent messages a paused topic missed become ordinary receipts
that the normal path reads again; that is a bounded catch-up, not a backfill.
"""

import asyncio
import json
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, cast

from sqlalchemy import func, select

from jt_oz_bridge.adapters.zulip.budget import request_lane
from jt_oz_bridge.adapters.zulip.client import ZulipError, ZulipReadUnavailable
from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader, ZulipSourceReader
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.delivery import DeliveryRateLimited, with_marker
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.routing import RoutedInput, RoutingRateDeferred
from jt_oz_bridge.i18n import Translator, message_locale
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.closed_bound_queue import UNSETTLED
from jt_oz_bridge.services.recovery_quota import RecoveryCapacityExceeded
from jt_oz_bridge.services.router import GUIDED_CONFLICTS, CommandRouter
from jt_oz_bridge.services.zulip_events import ZulipEventJournal, event_number, queue_name
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, InputEvent
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex

EVENT_OPERATIONS = frozenset(
    {"register", "events", "message.create", "message.update", "message.delete"}
)


LOG = logging.getLogger(__name__)

# Held codes that have one fixed thing the person can do next.
GUIDED = GUIDED_CONFLICTS

# How often a restart pause kept for unclear work is looked at again.
UNCLEAR_PAUSE_RECHECK_SECONDS = 30.0


class ZulipCommandConsumer:
    def __init__(
        self,
        scope: ZulipScopeReader,
        source: ZulipSourceReader,
        journal: ZulipEventJournal,
        router: CommandRouter,
        *,
        publish: Callable[[RoutedInput], Awaitable[Any]] | None = None,
        typing_status: bool = False,
        recover_gaps: bool = False,
        recovery_max_epochs: int = 128,
        recovery_max_items: int = 10000,
        recovery_max_bytes: int = 128 * 1024**2,
    ) -> None:
        enrolled = scope.enrolled
        if (
            journal.realm_id != enrolled.realm_id
            or journal.bot_user_id != enrolled.bot_user_id
            or journal.channel_ids != scope.channel_ids
            or journal.url != scope.client.url.rstrip("/")
            or source.expected_channel != journal.expected_channel
            or router.reader is not source
            or router.db is not journal.db
            or router.inbox.fence != journal.fence
            or source.scope is not scope
            or not EVENT_OPERATIONS <= enrolled.verified_event_operations
        ):
            raise ValueError("zulip_consumer_components_must_share_verified_scope")
        self.scope, self.source, self.journal, self.router = scope, source, journal, router
        self.publish = publish
        self.typing_status = typing_status
        self.queue_id: str | None = None
        self._starting = False
        self._polling = False
        # binding id -> the queue revision its restart pause was kept at
        self._unclear_pauses: dict[str, int] = {}
        self._unclear_checked_at = -UNCLEAR_PAUSE_RECHECK_SECONDS
        self.recovery = None
        if recover_gaps:
            from jt_oz_bridge.services.recovery_quota import RecoveryLimits
            from jt_oz_bridge.services.zulip_gap_recovery import ZulipGapRecovery
            from jt_oz_bridge.services.zulip_recovery_review import ZulipRecoveryReview

            self.recovery = ZulipGapRecovery(
                self, RecoveryLimits(recovery_max_epochs, recovery_max_items, recovery_max_bytes)
            )
            self.router.recovery = ZulipRecoveryReview(self.recovery)

    async def check(self) -> None:
        await self.scope.identity()
        if not EVENT_OPERATIONS <= self.scope.enrolled.verified_event_operations:
            raise ZulipError("zulip_events_not_attested")
        for channel in sorted(self.scope.channel_ids):
            metadata = await self.scope.channel(channel)
            if metadata["invite_only"] is not True or metadata["is_web_public"] is not False:
                raise ZulipError("private_channel_required_for_event_consumer")

    async def start(self, *, _existing_recovery_run: str | None = None) -> str:
        if self.queue_id is not None or self._starting:
            raise Conflict("zulip_consumer_already_started")
        self._starting = True
        try:
            await self.check()
            run_id = None
            if self.recovery is not None:
                run_id = _existing_recovery_run or await self.recovery.begin()
            registration = await self.scope.client.register_events(typing_status=self.typing_status)
            queue = queue_name(registration.get("queue_id"))
            watermark = event_number(registration.get("last_event_id"), watermark=True)
            await self.check()
            await self.journal.enroll(queue, watermark, recovery_run_id=run_id)
            self.queue_id = queue
            await self._release_restart_pauses()
            return queue
        finally:
            self._starting = False

    async def _release_restart_pauses(self) -> None:
        """A restart nobody chose does not stop a topic.

        What the restart held, and messages sent here while Bridge was down, go
        out by themselves when they are at most ten minutes old. Older ones wait
        for the person, who gets one reply per topic per restart. A failed read
        keeps the pause, as does any unclear work; that topic is looked at again
        once the work settles.
        """
        assert self.queue_id is not None
        pending, self.journal.restart_paused = self.journal.restart_paused, {}
        # Nothing new is captured before this runs, so this is the newest message the
        # previous process saw; ids only grow, so anything newer was sent while it was down.
        async with self.journal.db.sessions() as session:
            seen_until = await session.scalar(
                select(func.max(ZulipMessageIndex.message_id)).where(
                    ZulipMessageIndex.realm_id == self.journal.realm_id
                )
            )
            already = list(
                await session.scalars(
                    select(Binding.id).where(
                        Binding.realm_id == self.journal.realm_id,
                        Binding.state == "active",
                        Binding.dispatch_paused.is_(True),
                        Binding.channel_id.in_(sorted(self.scope.channel_ids)),
                    )
                )
            )
        for binding_id, queue_revision in pending.items():
            try:
                async with self.journal.db.sessions() as session:
                    binding = await session.get(Binding, binding_id)
                if binding is None:
                    continue
                messages = await self._topic_history(binding)
                now = time.time()
                recent, older = await self.journal.unseen_human_messages(
                    binding_id, messages, now=now
                )
                outcome = await self.journal.release_restart_pause(
                    binding_id, queue_revision, now=now
                )
                if outcome == "kept_unclear":
                    self._unclear_pauses[binding_id] = queue_revision
                captured: tuple[str, ...] = ()
                if outcome == "released" and recent:
                    # They go through the normal path, which reads each one again.
                    try:
                        captured = await self.journal.capture_missed(self.queue_id, recent)
                    except (Conflict, ValueError) as error:
                        LOG.warning(
                            "restart_missed_capture_failed error_type=%s", type(error).__name__
                        )
                        older += len(recent)
                elif recent:
                    older += len(recent)  # A message here now could send older ones too.
                LOG.warning(
                    "restart_pause_%s binding=%s resent_missed=%d not_sent_missed=%d",
                    outcome,
                    binding_id,
                    len(captured),
                    older,
                )
                keys = ["router.restart_waiting"] if outcome == "kept_old" else []
                if older:
                    keys.append("router.restart_missed")
                if keys:
                    await self._topic_notice(binding, keys)
            except Exception as error:
                LOG.warning(
                    "restart_pause_kept binding=%s error_type=%s", binding_id, type(error).__name__
                )
        if self.recovery is not None:
            return  # Gap recovery reads the history and reviews what it finds itself.
        for binding_id in already:
            if binding_id not in pending:
                await self._paused_missed(binding_id, seen_until or 0)

    async def _recheck_unclear_pauses(self) -> None:
        """Look again at restart pauses kept only because some work was unclear.

        Once it settles the restart's own rules apply: recent held work goes out,
        older work waits and the topic is told once, so the topic does not stay
        paused and silent after the work settled. A person's `!go`
        or `!no` changes the queue revision, which ends the recheck.
        """
        now = time.monotonic()
        if not self._unclear_pauses or now - self._unclear_checked_at < (
            UNCLEAR_PAUSE_RECHECK_SECONDS
        ):
            return
        self._unclear_checked_at = now
        for binding_id, queue_revision in list(self._unclear_pauses.items()):
            try:
                outcome = await self.journal.release_restart_pause(binding_id, queue_revision)
                if outcome == "kept_unclear":
                    continue
                del self._unclear_pauses[binding_id]
                LOG.warning("restart_pause_%s binding=%s after=unclear_work", outcome, binding_id)
                if outcome == "kept_old":
                    async with self.journal.db.sessions() as session:
                        binding = await session.get(Binding, binding_id)
                    if binding is not None:
                        await self._topic_notice(
                            binding, ["router.restart_waiting"], kind="restart-settled"
                        )
            except Exception as error:
                LOG.warning(
                    "restart_pause_recheck_failed binding=%s error_type=%s",
                    binding_id,
                    type(error).__name__,
                )

    async def _paused_missed(self, binding_id: str, seen_until: int) -> None:
        """Messages sent while Bridge was down into a topic that was paused already.

        The pause stays. When nothing else waits there, recent ones take the normal
        path, which holds each and says how to continue; otherwise, and for older ones,
        the topic gets one sentence. Without this they went unanswered.
        """
        assert self.queue_id is not None
        try:
            async with self.journal.db.sessions() as session:
                binding = await session.get(Binding, binding_id)
            if binding is None or binding.state != "active" or not binding.dispatch_paused:
                return
            messages = [
                item
                for item in await self._topic_history(binding)
                if isinstance(item, dict)
                and type(item.get("id")) is int
                and item["id"] > seen_until
            ]
            recent, older = await self.journal.unseen_human_messages(binding_id, messages)
            async with self.journal.db.sessions() as session:
                waiting = await session.scalar(
                    select(Action.id)
                    .where(Action.binding_id == binding_id, Action.state.in_(UNSETTLED))
                    .limit(1)
                )
            if recent and waiting is not None:
                # A message admitted now could carry older held work along without
                # anyone's `!go`, as on the restart path: say it was not sent instead.
                older += len(recent)
                recent = []
            captured: tuple[str, ...] = ()
            if recent:
                try:
                    captured = await self.journal.capture_missed(self.queue_id, recent)
                except (Conflict, ValueError) as error:
                    LOG.warning("restart_missed_capture_failed error_type=%s", type(error).__name__)
                    older += len(recent)
            if captured or older:
                LOG.warning(
                    "restart_paused_missed binding=%s held_missed=%d not_sent_missed=%d",
                    binding_id,
                    len(captured),
                    older,
                )
            if older:
                await self._topic_notice(binding, ["router.restart_missed"])
        except Exception as error:
            LOG.warning(
                "restart_paused_missed_failed binding=%s error_type=%s",
                binding_id,
                type(error).__name__,
            )

    async def _topic_history(self, binding: Binding) -> list[Any]:
        """The latest 50 messages of the topic, raw (a proposal only)."""
        with request_lane("control"):
            data = await self.scope.client.request(
                "GET",
                "messages",
                params={
                    "narrow": json.dumps(
                        [
                            {"operator": "channel", "operand": binding.channel_id},
                            {"operator": "topic", "operand": binding.topic},
                        ]
                    ),
                    "anchor": "newest",
                    "num_before": 50,
                    "num_after": 0,
                    "apply_markdown": "false",
                },
            )
        messages = data.get("messages")
        if not isinstance(messages, list):
            raise ZulipError("history_contract_mismatch")
        return messages

    async def _topic_notice(
        self, binding: Binding, keys: list[str], *, kind: str = "restart"
    ) -> None:
        """Best effort: fixed sentences once per topic per restart, never content.

        The marker names this queue and the kind of notice, so a retry finds the
        earlier post instead of posting twice. Nothing is posted into a channel
        that is not private.
        """
        if self.publish is None or self.queue_id is None:
            return
        try:
            channel, topic = binding.channel_id, binding.topic
            if channel not in self.scope.channel_ids:
                return
            metadata = await self.scope.channel(channel)
            if metadata["invite_only"] is not True or metadata["is_web_public"] is not False:
                return
            locale = binding.locale if binding.locale in {"en", "zh-TW"} else "en"
            marker = "jtoz:" + str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"{kind}:{self.journal.realm_id}:{binding.id}:{self.queue_id}",
                )
            )
            gateway = self.scope.gateway
            if await gateway.find(channel, topic, marker):
                return
            tr = Translator()
            text = "\n\n".join(tr.render(key, cast(Locale, locale)) for key in keys)
            await gateway.send(channel, topic, with_marker(text, marker), marker)
        except Exception as error:  # noqa: BLE001 - the notice never changes the outcome
            LOG.warning("zulip_restart_notice_failed error_type=%s", type(error).__name__)

    async def process(self, receipt_id: str) -> str:
        with request_lane("control"):
            return await self.process_receipt(receipt_id)

    async def _check_before_legacy_source(self, receipt_id: str, *, recovered: bool) -> None:
        """Keep pre-Source check errors visible without stranding an owned claim.

        No Source, legacy route or publication has started. A read-only retry
        preserves the original recovered flag; permanent loss holds the event.
        A lost journal fence must reject these writes rather than imply recovery.
        """
        try:
            await self.check()
        except BaseException as error:
            if isinstance(error, (ZulipReadUnavailable, asyncio.CancelledError)):
                await asyncio.shield(self.journal.defer(receipt_id, 1, recovered=recovered))
            elif isinstance(error, DeliveryRateLimited):
                budget = self.scope.client.budget
                delay = (
                    max(error.retry_after, budget.window)
                    if budget is not None
                    else error.retry_after
                )
                await asyncio.shield(self.journal.defer(receipt_id, delay, recovered=recovered))
            else:
                await asyncio.shield(self.journal.finish(receipt_id, state="held"))
            raise

    async def process_receipt(self, receipt_id: str) -> str:
        if await self.journal.waiting(receipt_id):
            return "deferred"  # Scheduling only; no cached permission or skipped later ACL.
        claim = await self.journal.claim(receipt_id)
        if claim is None:
            return "already_claimed_or_settled"
        event = claim.wire
        if event["type"] != "message":
            await self.journal.finish(receipt_id, state="ignored")
            return "ignored"
        m = event["message"]
        if m["sender_id"] == self.journal.bot_user_id:
            await self.journal.finish(receipt_id, state="ignored")
            return "ignored"
        fresh = (
            not claim.recovered
            and event.get("historical", False) is False
            and m.get("last_edit_timestamp") is None
        )
        stage = "source"
        verified = False  # Set once the legacy path has re-read this exact message.
        try:
            if m.get("subject") == "":
                # Topic proofs need a name, so "general chat" never routes. Say
                # so once instead of holding the message without a word.
                await self.journal.finish(receipt_id, state="ignored")
                if fresh:
                    await self._notice(m, "router.empty_topic")
                return "ignored"
            historical = event.get("historical", False)
            if type(historical) is not bool:
                raise ZulipError("invalid_historical_message_flag")
            if self.recovery is not None and await self.recovery.below_checkpoint(
                m["stream_id"], m["id"]
            ):
                historical = True  # Denial only, before any closed-menu callback.
            routed: RoutedInput | None = None
            if (
                claim.routed is None
                and not claim.recovered
                and not historical
                and m.get("last_edit_timestamp") is None
                and isinstance(self.router, CommandRouter)
            ):
                # This DTO is an untrusted proposal, never a Source or approval.
                # The selected closed reader double-verifies the exact original
                # content/author/revision/topic and complete audience before its
                # callback can claim a command or access the Native catalog.
                proposal = HumanMessage(
                    realm_id=self.journal.realm_id,
                    channel_id=m["stream_id"],
                    topic=m["subject"],
                    message_id=m["id"],
                    revision=0,
                    author_id=m["sender_id"],
                    text=m["content"],
                    is_bot=False,
                    deleted=False,
                )
                stage = "routing"
                routed = await self.router.route_closed_menu_event(proposal)
                if routed is not None:
                    await self.journal.record_route(receipt_id, routed)
            if routed is None:
                # Only an effect-free decline reaches the original standalone
                # Source reader/router; selected-operation errors never fall back.
                stage = "fallback-check"
                await self._check_before_legacy_source(receipt_id, recovered=claim.recovered)
                stage = "source"
                message = await self.source.read(self.journal.realm_id, m["id"])
                if message.is_bot:
                    await self.journal.finish(receipt_id, state="ignored")
                    return "ignored"
                # An edit never becomes a new instruction, even when received late.
                if (
                    message.deleted
                    or message.revision != 0
                    or m.get("last_edit_timestamp") is not None
                    or (
                        message.message_id,
                        message.channel_id,
                        message.author_id,
                        message.topic,
                        message.text,
                    )
                    != (m["id"], m["stream_id"], m["sender_id"], m["subject"], m["content"])
                ):
                    await self.journal.finish(receipt_id, state="held")
                    return "held"
                verified = fresh
                if claim.routed is not None:
                    routed = claim.routed  # Output only; never re-execute a completed route.
                else:
                    stage = "routing"
                    recovery_item = None
                    if self.recovery is not None and (claim.recovered or historical):
                        recovery_item = await self.recovery.event_item(
                            receipt_id, message, claim.recovery_run_id
                        )
                        if recovery_item is None:
                            await self.journal.finish(receipt_id, state="held")
                            return "held"
                        from jt_oz_bridge.presentation.commands import parse_input

                        if parse_input(message.text, bound=True).kind != "prompt":
                            await self.recovery.hold_command(recovery_item, message)
                            await self.journal.finish(receipt_id, state="held")
                            return "held"
                    if recovery_item is None:
                        routed = await self.router.route(
                            message, recovered=claim.recovered or historical
                        )
                    else:
                        routed = await self.router.route(
                            message, recovered=True, recovery_item_id=recovery_item
                        )
                    await self.journal.record_route(receipt_id, routed)
            stage = "publication"
            if self.publish is not None:
                await self.publish(routed)
            await self.journal.finish(receipt_id, state="done", routed=routed)
            return routed.state
        except ZulipReadUnavailable as error:
            from jt_oz_bridge.services.closed_bound_queue import ClosedBoundReadUnavailable

            if stage == "fallback-check":
                raise
            if stage == "routing" and not isinstance(error, ClosedBoundReadUnavailable):
                # Reads can fail after local control effects. Only a saved
                # routed reply proves that later retries cannot reroute it.
                await self.journal.finish(receipt_id, state="held")
                await self._held(m, stage, error, verified, fresh)
                return "held"
            await self.journal.defer(receipt_id, 1, recovered=claim.recovered)
            return "deferred"
        except DeliveryRateLimited as error:
            if stage == "fallback-check":
                raise
            if stage == "routing" and not isinstance(error, RoutingRateDeferred):
                # A router can already have created queue/action/control effects.
                # Its own receipt decides recovery; never replay it speculatively.
                await self.journal.finish(receipt_id, state="held")
                await self._held(
                    m, stage, error, False, False
                )  # Posting now would hit the limit too.
                return "held"
            # A retry restarts fresh Source/ACL reads, rather than continuing at
            # the refused HTTP request. Waiting only for the oldest request to
            # expire can consume each newly freed slot before a whole attempt
            # fits, keeping a read-only menu deferred forever. Allow this
            # client's complete rolling window to refill; preserve longer
            # upstream cooldowns and every existing unknown-effect hold above.
            budget = self.scope.client.budget
            delay = (
                max(error.retry_after, budget.window) if budget is not None else error.retry_after
            )
            await self.journal.defer(receipt_id, delay, recovered=claim.recovered)
            return "deferred"
        except RecoveryCapacityExceeded:
            await self.journal.finish(receipt_id, state="held")
            raise  # Durable Source stays held; poll applies local backpressure then stops.
        except (AccessDenied, ZulipError, Conflict, ValueError) as error:
            if stage == "fallback-check":
                raise
            # A held event is not evidence that an already queued/admitted action
            # never ran; the action's own durable receipts remain authoritative.
            await self.journal.finish(receipt_id, state="held")
            await self._held(m, stage, error, verified, fresh)
            return "held"

    async def _held(
        self, m: dict[str, Any], stage: str, error: BaseException, verified: bool, fresh: bool
    ) -> None:
        """Log every held message; tell the person only about a verified new one.

        A closed-menu failure stays silent: its reader owns that Source proof.
        The one exception is a refusal with a fixed next step, such as a
        conversation that must be reconnected; ``_notice`` re-reads it first.
        """
        code = held_code(error)
        LOG.warning(
            "zulip_message_held stage=%s error_type=%s code=%s",
            stage,
            type(error).__name__,
            code,
        )
        if isinstance(error, AccessDenied):
            return  # A refused author gets no reply, as before.
        if fresh and code in GUIDED:
            await self._notice(m, GUIDED[code])
        elif verified:
            await self._notice(m, "router.not_handled", code=code)

    async def _notice(self, m: dict[str, Any], key: str, **fields: str) -> None:
        """Best effort: one fixed sentence in the sender's own topic, never content.

        The event is only a proposal: the message is read again and must be the
        same unedited human message in a still-private channel, or nothing is
        posted. A lost notice changes nothing; a retried one is found by its
        marker instead of posted twice.
        """
        if self.publish is None:
            return
        try:
            if m.get("type") != "stream" or m["stream_id"] not in self.scope.channel_ids:
                return
            message = await self.source.read(self.journal.realm_id, m["id"])
            if (
                message.is_bot
                or message.deleted
                or message.revision != 0
                or (message.channel_id, message.author_id, message.topic, message.text)
                != (m["stream_id"], m["sender_id"], m["subject"], m["content"])
            ):
                return
            channel, topic = message.channel_id, message.topic
            metadata = await self.scope.channel(channel)
            if metadata["invite_only"] is not True or metadata["is_web_public"] is not False:
                return  # Never post into a channel that stopped being private.
            locale = await message_locale(self.journal.db, self.source, message)
            marker = "jtoz:" + str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"notice:{self.journal.realm_id}:{m['id']}")
            )
            gateway = self.scope.gateway
            if await gateway.find(channel, topic, marker):
                return
            text = Translator().render(key, locale, **fields)
            await gateway.send(channel, topic, with_marker(text, marker), marker)
        except Exception as error:  # noqa: BLE001 - the notice never changes the outcome
            LOG.warning("zulip_notice_failed key=%s error_type=%s", key, type(error).__name__)

    async def drain(self, limit: int = 100) -> tuple[str, ...]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid_zulip_drain_limit")
        async with self.journal.db.sessions() as session:
            rows = list(
                (
                    await session.scalars(
                        select(InputEvent.id)
                        .where(
                            InputEvent.source == "zulip:" + self.journal.source,
                            InputEvent.state.in_(
                                ["zulip_received", "zulip_processing", "zulip_deferred"]
                            ),
                        )
                        .order_by(InputEvent.created_at, InputEvent.id)
                        .limit(limit)
                    )
                ).all()
            )
        return await self.process_batch(tuple(rows))

    async def process_batch(self, receipts: tuple[str, ...]) -> tuple[str, ...]:
        states = []
        for receipt_id in receipts:
            state = await self.process(receipt_id)
            states.append(state)
            if state == "deferred":
                break  # Preserve receipt order; do not route a later prompt ahead of it.
        return tuple(states)

    async def poll(self) -> tuple[str, ...]:
        if self.recovery is not None and self.recovery.capacity_blocked:
            raise RecoveryCapacityExceeded("recovery_capacity_requires_operator_review")
        if self.queue_id is None or self._polling:
            raise Conflict("zulip_consumer_not_ready_or_already_polling")
        self._polling = True
        queue = self.queue_id
        try:
            if self.recovery is not None and self.recovery.capturing:
                return await self._recover_poll(queue)
            if self.recovery is not None:
                await self.recovery.process_history_one()
            await self._recheck_unclear_pauses()
            drained = await self.drain()
            if "deferred" in drained:
                return drained
            await self.check()
            last = await self.journal.cursor(queue)
            try:
                response = await self.scope.client.events(queue, last)
            except ZulipError as e:
                if str(e) == "queue_expired":
                    run_id = await self.recovery.begin() if self.recovery is not None else None
                    await self.journal.expire(queue, recovery_run_id=run_id)
                    self.queue_id = None
                    if self.recovery is not None:
                        await self.start(_existing_recovery_run=run_id)
                        return ("recovering",)
                raise
            await self.check()
            events = response.get("events")
            if not isinstance(events, list):
                raise ZulipError("zulip_events_schema_mismatch")
            receipts = await self.journal.capture(queue, events)
            return drained + await self.process_batch(receipts)
        except RecoveryCapacityExceeded as error:
            if self.recovery is not None:
                await self.recovery.backpressure(str(error))
            raise
        finally:
            self._polling = False

    async def _recover_poll(self, queue: str) -> tuple[str, ...]:
        assert self.recovery is not None
        await self.check()
        cursor = await self.journal.cursor(queue)
        try:
            result = await self.scope.client.events(queue, cursor, dont_block=True)
        except ZulipError as error:
            if str(error) != "queue_expired":
                raise
            run_id = await self.recovery.begin()
            await self.journal.expire(queue, recovery_run_id=run_id)
            self.queue_id = None
            await self.start(_existing_recovery_run=run_id)
            return ("recovering",)
        await self.check()
        events = result.get("events")
        if not isinstance(events, list):
            raise ZulipError("zulip_events_schema_mismatch")
        receipts = await self.journal.capture(queue, events, recovery_run_id=self.recovery.run_id)
        await self.recovery.step()
        try:
            receipts += await self.recovery.finish_capture(queue)
        except ZulipError as error:
            if str(error) != "queue_expired":
                raise
            run_id = await self.recovery.begin()
            await self.journal.expire(queue, recovery_run_id=run_id)
            self.queue_id = None
            await self.start(_existing_recovery_run=run_id)
            return ("recovering",)
        states = await self.process_batch(receipts)
        if "deferred" not in states:
            await self.recovery.process_history_one()
        return ("recovering" if self.recovery.capturing else "recovery_captured",) + states

    async def close(self) -> None:
        # Stop the caller's polling task before closing its queue. An expired
        # queue stays expired; a cleanup ACK is not gap reconciliation.
        if self._polling:
            raise Conflict("stop_zulip_poll_before_close")
        if self.queue_id is not None:
            queue, self.queue_id = self.queue_id, None
            await self.check()
            if "cleanup" in self.scope.enrolled.verified_event_operations:
                await self.scope.client.delete_events(queue)


def held_code(error: BaseException) -> str:
    """The error's fixed code such as ``existing_nonempty_topic_required``, else "-"."""
    if isinstance(error, DeliveryRateLimited):
        return "rate_limited"  # Its text can carry server detail.
    text = str(error)
    return text if re.fullmatch(r"[a-z0-9_]{1,80}", text) else "-"
