"""Actual Zulip history capture with an explicit gap epoch; never a Native writer.

History GETs are owned evidence, not invented queue events or Human authority.
Every executable prompt still goes through the original Source, queue and dispatcher.
"""

from __future__ import annotations

import copy
import json
import time
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.client import ZulipSourceUnavailable
from jt_oz_bridge.adapters.zulip.scope import positive
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.services.binding_scope_history import scope
from jt_oz_bridge.services.recovery_quota import RecoveryCapacityExceeded, RecoveryLimits
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, InputEvent, uid
from jt_oz_bridge.storage.retained_payloads import retained_scope
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem

if TYPE_CHECKING:
    from jt_oz_bridge.services.zulip_consumer import ZulipCommandConsumer
    from jt_oz_bridge.services.zulip_events import ZulipEventJournal

PAGE = 100
RUN_FORMAT = "zulip-recovery-run-v1"
HISTORY_FORMAT = "zulip-history-capture-v1"


def run_payload(row: InputEvent | None, source: str) -> dict[str, Any]:
    if row is None:
        raise Conflict("zulip_recovery_run_missing")
    value = row.payload
    if (
        row.source != "zulip-recovery:" + source
        or type(value) is not dict
        or digest(value) != row.payload_hash
        or value.get("format") != RUN_FORMAT
        or value.get("source") != source
        or value.get("id") != row.id
        or type(value.get("fencing")) is not int
        or type(value.get("scopes")) is not dict
        or len(value["scopes"]) > 1000
        or type(value.get("channels")) is not dict
    ):
        raise Conflict("zulip_recovery_run_changed")
    for item in value["scopes"].values():
        BindingScope.model_validate(item["scope"])
        if (
            type(item.get("previous_paused")) is not bool
            or type(item.get("queue_revision")) is not int
            or type(item.get("history_eligible")) is not bool
        ):
            raise Conflict("zulip_recovery_pause_proof_changed")
    return copy.deepcopy(value)


async def require_epoch(
    session: AsyncSession, journal: ZulipEventJournal, run_id: str
) -> dict[str, Any]:
    row = await session.get(InputEvent, run_id)
    if row is None:
        raise Conflict("zulip_recovery_epoch_missing")
    value = run_payload(row, journal.source)
    if (
        value["fencing"] != journal.fence.fencing
        or value["holder"] != journal.fence.holder
        or row.state not in {"zulip_recovery_running", "zulip_recovery_partial"}
    ):
        raise Conflict("zulip_recovery_epoch_not_owned")
    for identity, target in value["scopes"].items():
        binding = await session.get(Binding, identity)
        original = BindingScope.model_validate(target["scope"])
        if (
            binding is None
            or binding.state != "active"
            or scope(binding) != original
            or not binding.dispatch_paused
            or binding.queue_revision != target["queue_revision"]
        ):
            raise Conflict("zulip_recovery_owned_pause_changed")
    return value


async def link_paused_prompt(
    session: AsyncSession, binding: Binding, message: HumanMessage, action_id: str
) -> None:
    """Deny-only tracking for fresh live prompts received during an owned pause."""
    if not binding.dispatch_paused:
        return
    index = await session.get(ZulipMessageIndex, (message.realm_id, message.message_id))
    if index is None or index.state != "live" or index.binding_id != binding.id:
        return
    cp = await session.get(ZulipRecoveryCheckpoint, (index.source, message.channel_id))
    if cp is None or cp.run_id is None or message.message_id <= cp.message_id:
        return
    if binding.id not in cp.binding_scopes or BindingScope.model_validate(
        cp.binding_scopes[binding.id]
    ) != scope(binding):
        return
    row = await session.get(InputEvent, cp.run_id)
    value = run_payload(row, index.source)
    target = value["scopes"].get(binding.id)
    if (
        target is None
        or target["queue_revision"] != binding.queue_revision
        or BindingScope.model_validate(target["scope"]) != scope(binding)
    ):
        return
    with RecoveryLimits.from_run(value).watch(session, index.source):
        session.add(
            ZulipRecoveryItem(
                source=index.source,
                message_id=message.message_id,
                source_revision=message.revision,
                input_event_id=index.input_event_id,
                run_id=cp.run_id,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=message.author_id,
                action_id=action_id,
                state="held",
            )
        )
        await session.flush()


class ZulipGapRecovery:
    def __init__(
        self, consumer: ZulipCommandConsumer, limits: RecoveryLimits | None = None
    ) -> None:
        self.consumer = consumer
        self.limits = limits or RecoveryLimits()
        self.journal, self.db = consumer.journal, consumer.journal.db
        self.scope, self.source, self.router = consumer.scope, consumer.source, consumer.router
        self.fence = self.journal.fence
        self.run_id: str | None = None
        self.capturing = False
        self.capacity_blocked = False

    async def begin(self) -> str:
        try:
            return await self._begin()
        except RecoveryCapacityExceeded as error:
            await self.backpressure(str(error))
            raise

    async def backpressure(self, reason: str) -> None:
        self.capacity_blocked = True
        async with self.limits.transaction(
            self.db, self.fence, self.journal.source, control=True
        ) as session:
            bindings = (
                await session.scalars(
                    select(Binding).where(
                        Binding.realm_id == self.journal.realm_id,
                        Binding.state == "active",
                        Binding.channel_id.in_(self.journal.channel_ids),
                    )
                )
            ).all()
            for binding in bindings:
                if not binding.dispatch_paused:
                    binding.dispatch_paused = True
                    binding.queue_revision += 1
                await session.execute(
                    update(Action)
                    .where(Action.binding_id == binding.id, Action.state == "queued")
                    .values(
                        state="held",
                        version=Action.version + 1,
                        status_reason="zulip_recovery_capacity_hold",
                    )
                )
            for cp in (
                await session.scalars(
                    select(ZulipRecoveryCheckpoint).where(
                        ZulipRecoveryCheckpoint.source == self.journal.source
                    )
                )
            ).all():
                if cp.run_id is not None:
                    row = await session.get(InputEvent, cp.run_id)
                    if row is not None:
                        run_payload(
                            row, self.journal.source
                        )  # Authenticate before deny-only state.
                        # The payload and its original AEAD/hash remain exact,
                        # even when a lowered cap has no control space left.
                        row.state = "zulip_recovery_capacity"
            session.add(
                AuditEvent(
                    actor="system:zulip-recovery",
                    event="zulip_recovery_capacity_blocked",
                    object_id=self.journal.source,
                )
            )
        self.capturing = True

    async def _begin(self) -> str:
        """Hold old queued work and own a new pause before attempting registration."""
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            await self.limits.admission(session, self.journal.source)
            bindings = list(
                (
                    await session.scalars(
                        select(Binding)
                        .where(
                            Binding.realm_id == self.journal.realm_id,
                            Binding.state == "active",
                            Binding.channel_id.in_(self.journal.channel_ids),
                        )
                        .with_for_update()
                    )
                ).all()
            )
            if len(bindings) > 1000:
                raise Conflict("zulip_recovery_binding_capacity")
            checkpoints: dict[int, ZulipRecoveryCheckpoint | None] = {}
            for channel in sorted(self.journal.channel_ids):
                cp = await session.get(ZulipRecoveryCheckpoint, (self.journal.source, channel))
                if cp is not None and (cp.realm_id, cp.bot_user_id) != (
                    self.journal.realm_id,
                    self.journal.bot_user_id,
                ):
                    raise Conflict("zulip_recovery_checkpoint_identity_changed")
                checkpoints[channel] = cp
            identity = uid()
            scopes: dict[str, Any] = {}
            safety_actions: list[Action] = []
            for binding in bindings:
                previous = binding.dispatch_paused
                parent = None
                cp = checkpoints[binding.channel_id]
                if cp is not None and cp.run_id is not None and previous:
                    old = await session.get(InputEvent, cp.run_id)
                    if old is not None:
                        prior = run_payload(old, self.journal.source)
                        target = prior["scopes"].get(binding.id)
                        # Inherit only the exact proven recovery-owned pause. An
                        # intervening user/admin pause increments the revision.
                        if (
                            target is not None
                            and BindingScope.model_validate(target["scope"]) == scope(binding)
                            and target["queue_revision"] == binding.queue_revision
                        ):
                            previous = target["previous_paused"]
                            parent = old.id
                binding.dispatch_paused = True
                binding.queue_revision += 1
                scopes[binding.id] = {
                    "scope": scope(binding).model_dump(mode="json"),
                    "previous_paused": previous,
                    "queue_revision": binding.queue_revision,
                    "parent_run": parent,
                    "history_eligible": cp is not None
                    and type(cp.binding_scopes) is dict
                    and binding.id in cp.binding_scopes
                    and BindingScope.model_validate(cp.binding_scopes[binding.id])
                    == scope(binding),
                }
                safety_actions.extend(
                    (
                        await session.scalars(
                            select(Action)
                            .where(
                                Action.binding_id == binding.id,
                                Action.binding_revision == binding.revision,
                                Action.state == "queued",
                            )
                            .with_for_update()
                        )
                    ).all()
                )
                await session.execute(
                    update(Action)
                    .where(
                        Action.binding_id == binding.id,
                        Action.binding_revision == binding.revision,
                        Action.state == "queued",
                    )
                    .values(
                        state="held",
                        version=Action.version + 1,
                        status_reason="zulip_recovery_safety_hold",
                    )
                )
            payload = {
                "format": RUN_FORMAT,
                "quota": self.limits.dump(),
                "id": identity,
                "source": self.journal.source,
                "realm_id": self.journal.realm_id,
                "bot_user_id": self.journal.bot_user_id,
                "holder": self.fence.holder,
                "fencing": self.fence.fencing,
                "scopes": scopes,
                "channels": {
                    str(c): {
                        "lower": None if cp is None else cp.message_id,
                        "upper": None,
                        "captured": False,
                        "pages": 0,
                        "canonical_bytes": 0,
                        "coverage": "unknown_before_anchor" if cp is None else cp.coverage,
                    }
                    for c, cp in checkpoints.items()
                },
            }
            session.add(
                InputEvent(
                    id=identity,
                    source="zulip-recovery:" + self.journal.source,
                    source_id=identity,
                    revision=0,
                    payload=payload,
                    payload_hash=digest(payload),
                    state="zulip_recovery_running",
                )
            )
            await session.flush()
            for action in safety_actions:
                original = HumanMessage.model_validate(action.payload["source"])
                index = await session.get(
                    ZulipMessageIndex, (original.realm_id, original.message_id)
                )
                target = scopes[action.binding_id]
                old_item = await session.scalar(
                    select(ZulipRecoveryItem.id).where(ZulipRecoveryItem.action_id == action.id)
                )
                if (
                    old_item is None
                    and index is not None
                    and index.state == "live"
                    and index.source == self.journal.source
                    and index.binding_id == action.binding_id
                    and action.operation == "prompt"
                    and not original.is_bot
                    and original.revision == 0
                    and original.author_id == action.actor_id
                    and (original.realm_id, original.channel_id, original.topic)
                    == (
                        target["scope"]["realm_id"],
                        target["scope"]["channel_id"],
                        target["scope"]["topic"],
                    )
                    and action.payload["reference"] == target["scope"]["reference"]
                    and digest(action.payload) == action.operation_digest
                ):
                    session.add(
                        ZulipRecoveryItem(
                            source=self.journal.source,
                            message_id=original.message_id,
                            source_revision=0,
                            input_event_id=index.input_event_id,
                            run_id=identity,
                            binding_id=action.binding_id,
                            binding_revision=action.binding_revision,
                            actor_id=action.actor_id,
                            action_id=action.id,
                            state="held",
                        )
                    )
            for channel, cp in checkpoints.items():
                if cp is None:
                    cp = ZulipRecoveryCheckpoint(
                        source=self.journal.source,
                        channel_id=channel,
                        realm_id=self.journal.realm_id,
                        bot_user_id=self.journal.bot_user_id,
                        message_id=-1,
                        coverage="unknown_before_anchor",
                        binding_scopes={},
                        run_id=identity,
                    )
                    session.add(cp)
                else:
                    cp.run_id = identity
                    cp.version += 1
                    cp.updated_at = time.time()
            session.add(
                AuditEvent(
                    actor="system:zulip-recovery", event="zulip_gap_paused", object_id=identity
                )
            )
        self.run_id, self.capturing = identity, True
        return identity

    async def history(self, channel: int, *, anchor: int | str, after: int) -> dict[str, Any]:
        await self.consumer.check()
        narrow = json.dumps([{"operator": "channel", "operand": str(channel)}])
        raw = await self.scope.client.request(
            "GET",
            "messages",
            params={
                "narrow": narrow,
                "anchor": anchor,
                "include_anchor": "true" if anchor == "newest" else "false",
                "num_before": 1 if anchor == "newest" else 0,
                "num_after": after,
                "apply_markdown": "false",
                "client_gravatar": "false",
                "allow_empty_topic_name": "true",
            },
        )
        await self.consumer.check()
        if (
            len(checked_json(raw)) > 8 * 1024 * 1024
            or raw.get("ignored_parameters_unsupported")
            or type(raw.get("messages")) is not list
            or len(raw["messages"]) > PAGE
            or any(
                type(raw.get(k)) is not bool
                for k in ("found_newest", "found_oldest", "found_anchor", "history_limited")
            )
        ):
            raise Conflict("zulip_recovery_history_contract_changed")
        numbers = []
        for message in raw["messages"]:
            if (
                type(message) is not dict
                or message.get("type") != "stream"
                or message.get("stream_id") != channel
                or type(message.get("stream_id")) is not int
                or message.get("content_type") != "text/x-markdown"
                or type(message.get("subject")) is not str
                or type(message.get("content")) is not str
            ):
                raise Conflict("zulip_recovery_exact_channel_markdown_required")
            positive(message.get("id"))
            positive(message.get("sender_id"))
            numbers.append(message["id"])
        if (
            numbers != sorted(set(numbers))
            or anchor != "newest"
            and any(mid <= anchor for mid in numbers)
        ):
            raise Conflict("zulip_recovery_history_order_changed")
        return raw

    async def step(self) -> None:
        if not self.capturing or self.run_id is None:
            return
        async with self.db.sessions() as session:
            row = await session.get(InputEvent, self.run_id)
            if row is None:
                raise Conflict("zulip_recovery_run_missing")
            value = run_payload(row, self.journal.source)
        if row.state == "zulip_recovery_partial":
            return  # Continue capture-only queue buffering; never claim complete.
        pending = [(int(c), p) for c, p in value["channels"].items() if not p["captured"]]
        if not pending:
            return  # Only the final real queue barrier may open normal routing.
        channel, progress = pending[0]
        async with self.db.sessions() as session:
            cp = await session.get(ZulipRecoveryCheckpoint, (self.journal.source, channel))
            if cp is None:
                raise Conflict("zulip_recovery_checkpoint_missing")
            cursor, version = cp.message_id, cp.version
        raw: dict[str, Any] | None
        if progress["upper"] is None:
            raw = await self.history(channel, anchor="newest", after=0)
            if not raw["found_newest"] or raw["history_limited"]:
                raise Conflict("zulip_recovery_newest_anchor_unproven")
            upper = max([m["id"] for m in raw["messages"]], default=0)
            async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
                await self.fence.lock(session)
                row = await session.get(InputEvent, self.run_id)
                if row is None:
                    raise Conflict("zulip_recovery_run_missing")
                current = run_payload(row, self.journal.source)
                cp = await session.get(ZulipRecoveryCheckpoint, (self.journal.source, channel))
                if (
                    cp is None
                    or cp.run_id != self.run_id
                    or cp.version != version
                    or cp.message_id != cursor
                ):
                    raise Conflict("zulip_recovery_anchor_cas_changed")
                target = current["channels"][str(channel)]
                if cursor == -1:
                    cp.message_id = upper
                    target["lower"] = upper
                    target["captured"] = True
                    target["initial_anchor_sha256"] = digest(raw)
                elif upper < cursor:
                    raise Conflict("zulip_recovery_visible_history_rewound")
                target["upper"] = upper
                cp.version += 1
                row.payload, row.payload_hash = current, digest(current)
            return
        upper = progress["upper"]
        if progress["pages"] >= 100 and cursor != upper:
            async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
                await self.fence.lock(session)
                row = await session.get(InputEvent, self.run_id)
                if row is None:
                    raise Conflict("zulip_recovery_run_missing")
                current = run_payload(row, self.journal.source)
                if current != value:
                    raise Conflict("zulip_recovery_partial_boundary_changed")
                row.state = "zulip_recovery_partial"
            return
        if cursor == upper:
            raw = None
            messages = []
            complete = True
        else:
            raw = await self.history(channel, anchor=cursor, after=PAGE)
            if raw["history_limited"]:
                raise Conflict("zulip_recovery_history_limited_gap")
            if progress["canonical_bytes"] + len(checked_json(raw)) > 32 * 1024 * 1024:
                async with self.limits.transaction(
                    self.db, self.fence, self.journal.source
                ) as session:
                    await self.fence.lock(session)
                    row = await session.get(InputEvent, self.run_id)
                    if row is None:
                        raise Conflict("zulip_recovery_run_missing")
                    if run_payload(row, self.journal.source) != value:
                        raise Conflict("zulip_recovery_partial_byte_boundary_changed")
                    row.state = "zulip_recovery_partial"
                return
            messages = [m for m in raw["messages"] if m["id"] <= upper]
            complete = raw["found_newest"] or any(m["id"] >= upper for m in raw["messages"])
            if not messages and not complete:
                raise Conflict("zulip_recovery_pagination_not_advancing")
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            row = await session.get(InputEvent, self.run_id)
            if row is None:
                raise Conflict("zulip_recovery_run_missing")
            current = run_payload(row, self.journal.source)
            cp = await session.get(ZulipRecoveryCheckpoint, (self.journal.source, channel))
            if (
                cp is None
                or cp.run_id != self.run_id
                or cp.version != version
                or cp.message_id != cursor
            ):
                raise Conflict("zulip_recovery_page_cas_changed")
            for message in messages:
                if raw is None:
                    raise Conflict("zulip_recovery_page_original_response_missing")
                await self.capture_history(session, current, message, digest(raw), cursor, upper)
            cp.message_id = upper if complete else messages[-1]["id"]
            cp.version += 1
            cp.updated_at = time.time()
            current["channels"][str(channel)]["captured"] = complete
            current["channels"][str(channel)]["pages"] += 1
            current["channels"][str(channel)]["canonical_bytes"] += (
                0 if raw is None else len(checked_json(raw))
            )
            row.payload, row.payload_hash = current, digest(current)

    async def below_checkpoint(self, channel: int, message_id: int) -> bool:
        async with self.db.sessions() as session:
            cp = await session.get(ZulipRecoveryCheckpoint, (self.journal.source, channel))
            return cp is not None and message_id <= cp.message_id

    async def finish_capture(self, queue: str) -> tuple[str, ...]:
        if self.run_id is None:
            raise Conflict("zulip_recovery_run_missing")
        async with self.db.sessions() as session:
            row = await session.get(InputEvent, self.run_id)
            value = run_payload(row, self.journal.source)
            if (
                row is None
                or row.state == "zulip_recovery_partial"
                or any(not p["captured"] for p in value["channels"].values())
            ):
                return ()
        # A committed history page is not evidence that the live queue is empty.
        # A final real newest read closes delayed queue-message delivery below
        # these exact per-channel message anchors without inventing event IDs.
        for channel, progress in value["channels"].items():
            actual = await self.history(int(channel), anchor="newest", after=0)
            if not actual["found_newest"] or actual["history_limited"]:
                raise Conflict("zulip_recovery_final_history_unproven")
            upper = max((m["id"] for m in actual["messages"]), default=0)
            if upper < progress["upper"]:
                raise Conflict("zulip_recovery_final_history_rewound")
            if upper > progress["upper"]:
                async with self.limits.transaction(
                    self.db, self.fence, self.journal.source
                ) as session:
                    await self.fence.lock(session)
                    row = await session.get(InputEvent, self.run_id)
                    if row is None or run_payload(row, self.journal.source) != value:
                        raise Conflict("zulip_recovery_final_history_cas_changed")
                    value["channels"][channel].update(
                        upper=upper, captured=False, final_anchor_canonical_sha256=digest(actual)
                    )
                    row.payload, row.payload_hash = value, digest(value)
                return ()
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            row = await session.get(InputEvent, self.run_id)
            if row is None or run_payload(row, self.journal.source) != value:
                raise Conflict("zulip_recovery_barrier_cas_changed")
            value["barrier_attempts"] = value.get("barrier_attempts", 0) + 1
            if value["barrier_attempts"] > 100:
                row.state = "zulip_recovery_partial"
                return ()
            row.payload, row.payload_hash = value, digest(value)
        await self.consumer.check()
        cursor = await self.journal.cursor(queue)
        response = await self.scope.client.events(queue, cursor, dont_block=True)
        await self.consumer.check()
        events = response.get("events")
        if type(events) is not list:
            raise Conflict("zulip_recovery_final_queue_contract_changed")
        receipts = await self.journal.capture(queue, events, recovery_run_id=self.run_id)
        if events:
            return receipts  # All remain recovered; require a genuine empty barrier.
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            row = await session.get(InputEvent, self.run_id)
            if row is None or run_payload(row, self.journal.source) != value:
                raise Conflict("zulip_recovery_final_capture_cas_changed")
            await require_epoch(session, self.journal, self.run_id)
            for channel in value["channels"]:
                cp = await session.get(ZulipRecoveryCheckpoint, (self.journal.source, int(channel)))
                if cp is None or cp.run_id != self.run_id:
                    raise Conflict("zulip_recovery_completed_anchor_changed")
                cp.binding_scopes = {
                    identity: target["scope"]
                    for identity, target in value["scopes"].items()
                    if target["scope"]["channel_id"] == int(channel)
                }
                cp.version += 1
            row.state = "zulip_recovery_captured"
        self.capturing = False
        return receipts

    async def capture_history(
        self,
        session: AsyncSession,
        run: dict[str, Any],
        message: dict[str, Any],
        raw_sha: str,
        lower: int,
        upper: int,
    ) -> None:
        key = digest(
            {"source": self.journal.source, "message_id": message["id"], "format": HISTORY_FORMAT}
        )
        old = await session.scalar(
            select(InputEvent).where(
                InputEvent.source == "zulip-history:" + self.journal.source,
                InputEvent.source_id == key,
                InputEvent.revision == 0,
            )
        )
        if old is not None:
            if old.payload_compacted_at is not None:
                scope = retained_scope(
                    old.payload,
                    kind="recovery_input:payload",
                    identity=old.id,
                    when=old.payload_compacted_at,
                    checksum=old.payload_hash,
                )
                if (
                    scope.get("original_format"),
                    scope.get("source"),
                    scope.get("source_id"),
                    scope.get("message_id"),
                ) != (HISTORY_FORMAT, old.source, key, message["id"]):
                    raise Conflict("zulip_recovery_retired_history_identity_changed")
                return  # A retired Source remains a dedupe barrier, never a new Action.
            if digest(old.payload) != old.payload_hash:
                raise Conflict("zulip_recovery_history_receipt_changed")
            return
        # Keep only original raw-Markdown source fields, never email/profile data.
        frozen = {
            k: message[k]
            for k in ("id", "type", "stream_id", "subject", "sender_id", "content", "content_type")
        }
        if "last_edit_timestamp" in message:
            frozen["last_edit_timestamp"] = message["last_edit_timestamp"]
        payload = {
            "format": HISTORY_FORMAT,
            "source": self.journal.source,
            "run_id": run["id"],
            "realm_id": self.journal.realm_id,
            "bot_user_id": self.journal.bot_user_id,
            "channel_id": message["stream_id"],
            "lower": lower,
            "upper": upper,
            "canonical_response_sha256": raw_sha,
            "message": frozen,
        }
        receipt = InputEvent(
            source="zulip-history:" + self.journal.source,
            source_id=key,
            revision=0,
            payload=payload,
            payload_hash=digest(payload),
            state="zulip_history_received",
        )
        session.add(receipt)
        await session.flush()
        await self.stage_item(session, run, receipt.id, frozen)

    async def stage_item(
        self, session: AsyncSession, run: dict[str, Any], receipt_id: str, message: dict[str, Any]
    ) -> str | None:
        targets = [
            (identity, target)
            for identity, target in run["scopes"].items()
            if target["history_eligible"]
            and target["scope"]["channel_id"] == message["stream_id"]
            and target["scope"]["topic"] == message["subject"]
        ]
        if not targets:
            return None
        if len(targets) != 1:
            raise Conflict("zulip_recovery_ambiguous_original_binding")
        identity, target = targets[0]
        original = BindingScope.model_validate(target["scope"])
        lower = run["channels"][str(message["stream_id"])]["lower"]
        if lower is None or message["id"] <= lower:
            return None
        if original.anchor_message_id is not None and message["id"] <= original.anchor_message_id:
            return None
        item = await session.scalar(
            select(ZulipRecoveryItem).where(
                ZulipRecoveryItem.source == self.journal.source,
                ZulipRecoveryItem.message_id == message["id"],
                ZulipRecoveryItem.source_revision == 0,
            )
        )
        if item is not None:
            if (item.binding_id, item.binding_revision, item.actor_id) != (
                identity,
                original.revision,
                message["sender_id"],
            ):
                raise Conflict("zulip_recovery_existing_message_scope_changed")
            return item.id
        # Existing actions/commands are authoritative, not a new reviewable action.
        action = await session.scalar(
            select(Action.id).where(
                Action.dedupe_key == f"human:{self.journal.realm_id}:{message['id']}"
            )
        )
        if action is not None:
            return None
        index = await session.get(ZulipMessageIndex, (self.journal.realm_id, message["id"]))
        if index is None:
            session.add(
                ZulipMessageIndex(
                    realm_id=self.journal.realm_id,
                    message_id=message["id"],
                    source=self.journal.source,
                    channel_id=message["stream_id"],
                    binding_id=identity,
                    state="live",
                    input_event_id=receipt_id,
                    version=1,
                )
            )
        elif (
            index.source != self.journal.source
            or index.channel_id != message["stream_id"]
            or index.binding_id != identity
            or index.state != "live"
        ):
            return None
        item = ZulipRecoveryItem(
            id=uid(),
            source=self.journal.source,
            message_id=message["id"],
            source_revision=0,
            input_event_id=receipt_id,
            run_id=run["id"],
            binding_id=identity,
            binding_revision=original.revision,
            actor_id=message["sender_id"],
            state="captured",
        )
        session.add(item)
        await session.flush()
        return item.id

    async def event_item(
        self, receipt_id: str, message: HumanMessage, run_id: str | None
    ) -> str | None:
        identity = run_id or self.run_id
        if identity is None:
            raise Conflict("zulip_recovery_event_epoch_missing")
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            row = await session.get(InputEvent, identity)
            run = run_payload(row, self.journal.source)
            return await self.stage_item(
                session,
                run,
                receipt_id,
                {
                    "id": message.message_id,
                    "stream_id": message.channel_id,
                    "subject": message.topic,
                    "sender_id": message.author_id,
                },
            )

    async def hold_command(self, item_id: str, message: HumanMessage) -> None:
        binding = await self.router.bindings.get(
            (await self.item(item_id)).binding_id,
            message.realm_id,
            message.author_id,
            Permission.OPERATE,
        )
        parsed = parse_input(message.text, bound=True)
        command = parsed.command if parsed.kind != "unknown" else "unknown"
        await self.router.inbox.claim(
            message,
            command,
            binding_id=binding.id,
            binding_revision=binding.revision,
            recovered=True,
        )
        await self.set_item(item_id, "command_held")

    async def item(self, identity: str) -> ZulipRecoveryItem:
        async with self.db.sessions() as session:
            row = await session.get(ZulipRecoveryItem, identity)
            if row is None or row.source != self.journal.source:
                raise Conflict("zulip_recovery_item_missing")
            return row

    async def set_item(self, identity: str, state: str) -> None:
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            row = await session.get(ZulipRecoveryItem, identity)
            if row is None or row.source != self.journal.source:
                raise Conflict("zulip_recovery_item_changed")
            row.state, row.version, row.updated_at = state, row.version + 1, time.time()

    async def process_history_one(self) -> str | None:
        async with self.db.sessions() as session:
            row = await session.scalar(
                select(InputEvent)
                .where(
                    InputEvent.source == "zulip-history:" + self.journal.source,
                    InputEvent.state == "zulip_history_received",
                )
                .order_by(InputEvent.created_at, InputEvent.id)
                .limit(1)
            )
            if row is None:
                return None
            payload, identity = copy.deepcopy(row.payload), row.id
            item = await session.scalar(
                select(ZulipRecoveryItem).where(ZulipRecoveryItem.input_event_id == identity)
            )
        if (
            type(payload) is not dict
            or digest(payload) != row.payload_hash
            or payload.get("format") != HISTORY_FORMAT
        ):
            raise Conflict("zulip_history_provenance_changed")
        if item is None:
            state = "unqualified"
        else:
            try:
                message = await self.source.read(self.journal.realm_id, item.message_id)
            except ZulipSourceUnavailable:
                await self.set_item(item.id, "rejected")
                message = None
            original = payload["message"]
            if (
                message is None
                or message.is_bot
                or message.deleted
                or message.revision != 0
                or original.get("last_edit_timestamp") is not None
                or (
                    message.message_id,
                    message.channel_id,
                    message.topic,
                    message.author_id,
                    message.text,
                )
                != (
                    original["id"],
                    original["stream_id"],
                    original["subject"],
                    original["sender_id"],
                    original["content"],
                )
            ):
                await self.set_item(item.id, "rejected")
                state = "held"
            else:
                try:
                    if parse_input(message.text, bound=True).kind != "prompt":
                        await self.hold_command(item.id, message)
                    else:
                        routed = await self.router.route(
                            message, recovered=True, recovery_item_id=item.id
                        )
                        if self.consumer.publish is not None:
                            await self.consumer.publish(routed)
                except AccessDenied:
                    # Per-message grant denial is terminal, not a transient
                    # outage or authority to retry. HTTP 401/403, lost fences
                    # and malformed contracts remain typed failures upstream.
                    await self.set_item(item.id, "rejected")
                state = "held"
        async with self.limits.transaction(self.db, self.fence, self.journal.source) as session:
            await self.fence.lock(session)
            current = await session.get(InputEvent, identity)
            if (
                current is None
                or current.payload_hash != row.payload_hash
                or current.state != "zulip_history_received"
            ):
                raise Conflict("zulip_history_completion_changed")
            current.state = "zulip_history_" + state
        return state
