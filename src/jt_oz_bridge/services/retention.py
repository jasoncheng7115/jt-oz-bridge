"""Bounded fenced local payload compaction; no upstream or filesystem cleanup.

Never remove identity/dedupe rows, checkpoints, bindings or transcript/creation
proofs. Every sweep is one lease-locked transaction, rechecked before commit.
Live-feed receipts of ended Native connections are a separate bounded deletion.
"""

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Retention
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.services.binding_scope_history import EVENT as SCOPE_HISTORY_EVENT
from jt_oz_bridge.services.live_retention import LiveSourceRetention
from jt_oz_bridge.services.recovery_retention import RECOVERY_STATES, RecoveryRetention
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken, PendingInteraction
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch, InputEvent
from jt_oz_bridge.storage.output_models import OutputDestination
from jt_oz_bridge.storage.retained_payloads import retained_scope, tombstone
from jt_oz_bridge.storage.schema import Base
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex

DAY = 86400
PROTECTED_AUDIT_EVENTS = frozenset(
    {SCOPE_HISTORY_EVENT, "database_restored_held", "database_restore_review_completed"}
)
TERMINAL_ACTIONS = frozenset({"completed", "cancelled", "rejected", "failed"})
PROFILES: tuple[tuple[str, Any], ...] = (
    ("input", InputEvent),
    ("recovery_input", InputEvent),
    ("action", Action),
    ("delivery", Delivery),
    ("command", CommandReceipt),
    ("destination", OutputDestination),
    ("token", ControlToken),
)


@dataclass(frozen=True)
class RetentionSweep:
    scanned: int
    observed: int
    compacted: int
    audit_deleted: int


class RetentionExecutor:
    def __init__(
        self,
        db: Database,
        fence: ConsumerFence,
        settings: Retention,
        *,
        batch_size: int = 32,
        interval: float = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            type(batch_size) is not int
            or not 1 <= batch_size <= 1000
            or not 0.01 <= interval <= 3600
        ):
            raise ValueError("retention_batch_and_interval_must_be_bounded")
        self.db, self.fence, self.settings = db, fence, settings
        self.batch_size, self.interval, self.clock = batch_size, interval, clock
        self._cursors: dict[str, tuple[float, str] | None] = {}
        self._start = 0
        self.recovery = RecoveryRetention(self)
        self.live = LiveSourceRetention(db, fence, settings, clock=clock)

    async def _referenced(
        self,
        session: AsyncSession,
        target: str,
        identity: str | Select[tuple[str]],
        *,
        exclude: frozenset[str] = frozenset(),
    ) -> bool:
        # FK metadata is the complete current application schema, not guessed
        # payload keys. Preserve every publication/file/transcript dependency.
        for table in Base.metadata.sorted_tables:
            if table.name in exclude:
                continue
            for column in table.columns:
                if any(fk.target_fullname == target for fk in column.foreign_keys):
                    matches = (
                        column == identity if isinstance(identity, str) else column.in_(identity)
                    )
                    if await session.scalar(select(column).where(matches).limit(1)) is not None:
                        return True
        return False

    async def _source_pending(self, session: AsyncSession, realm: Any, message_id: Any) -> bool:
        if not isinstance(realm, str) or type(message_id) is not int:
            return True
        index = await session.scalar(
            select(ZulipMessageIndex).where(
                ZulipMessageIndex.realm_id == realm, ZulipMessageIndex.message_id == message_id
            )
        )
        if index is not None:
            event = await session.get(InputEvent, index.input_event_id)
            if event is None or (
                event.state not in {"zulip_done", "zulip_ignored"}
                and not self.recovery.terminal_history(event)
            ):
                return True
        return (
            await session.scalar(
                select(CommandReceipt.id)
                .where(
                    CommandReceipt.realm_id == realm,
                    CommandReceipt.message_id == message_id,
                    CommandReceipt.state != "completed",
                )
                .limit(1)
            )
            is not None
        )

    async def _binding_pending(self, session: AsyncSession, identity: str | None) -> bool:
        # An active binding is metadata, not a blanket dependency on every old
        # terminal body. Preserve only in-flight work that may still edit/recover
        # an earlier body; explicit publication/transcript FKs are checked below.
        if identity is None:
            return False
        if await session.get(Binding, identity) is None:
            return True
        for model, condition in (
            (Action, Action.state.not_in(TERMINAL_ACTIONS)),
            (Delivery, Delivery.state != "delivered"),
            (CommandReceipt, CommandReceipt.state != "completed"),
            (
                PendingInteraction,
                PendingInteraction.state.not_in({"resolved", "expired", "rejected", "cancelled"}),
            ),
        ):
            if (
                await session.scalar(
                    select(model.binding_id).where(model.binding_id == identity, condition).limit(1)
                )
                is not None
            ):
                return True
        return (
            await session.scalar(
                select(InputEvent.id)
                .join(ZulipMessageIndex, ZulipMessageIndex.input_event_id == InputEvent.id)
                .where(
                    ZulipMessageIndex.binding_id == identity,
                    InputEvent.state.not_in({"zulip_done", "zulip_ignored"}),
                    ~and_(
                        InputEvent.source.startswith("zulip-history:"),
                        InputEvent.state.in_({"zulip_history_held", "zulip_history_unqualified"}),
                    ),
                )
                .limit(1)
            )
            is not None
        )

    async def _safe(
        self, session: AsyncSession, kind: str, row: Any, now: float, cutoff: float
    ) -> bool:
        if kind == "recovery_input":
            return await self.recovery.safe_input(session, row)
        if kind == "input":
            if not await self.recovery.source_safe(session, row):
                return False
            if (
                row.state not in {"zulip_done", "zulip_ignored"}
                or row.payload.get("format") != "zulip-event-capture-v1"
                or digest(row.payload) != row.payload_hash
            ):
                raise Conflict("retention_input_receipt_changed")
            if await self._referenced(
                session,
                "input_events.id",
                row.id,
                exclude=frozenset({"zulip_message_index", "zulip_recovery_items"}),
            ):
                return False
            index = await session.scalar(
                select(ZulipMessageIndex).where(ZulipMessageIndex.input_event_id == row.id).limit(1)
            )
            if index is not None and index.state == "unresolved":
                return False
            wire = row.payload.get("wire", {})
            if wire.get("type") == "message":
                message = wire.get("message", {})
                if await self._source_pending(
                    session, row.payload.get("realm_id"), message.get("id")
                ):
                    return False
            route = row.payload.get("routed_reply", {})
            if isinstance(route, dict) and route.get("action_id"):
                action = await session.get(Action, route["action_id"])
                if (
                    action is None
                    or action.state not in TERMINAL_ACTIONS
                    or await self._referenced(
                        session,
                        "actions.id",
                        action.id,
                        exclude=frozenset({"zulip_recovery_items"}),
                    )
                ):
                    return False
            return True
        if kind == "action":
            # Even a legacy row whose owner metadata says "bridge" may hold
            # original/unknown Native correlation evidence. No TTL reduction
            # may replace that evidence with a hash-only origin substitute.
            if row.admission or row.native_result or row.upstream_id is not None:
                return False
            if (
                await session.scalar(
                    select(PendingInteraction.id)
                    .where(PendingInteraction.action_id == row.id)
                    .limit(1)
                )
                is not None
            ):
                return False
            from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

            if (
                await session.scalar(
                    select(ZulipRecoveryItem.id)
                    .where(
                        ZulipRecoveryItem.action_id == row.id, ZulipRecoveryItem.state != "retired"
                    )
                    .limit(1)
                )
                is not None
            ):
                return False
            return not await self._referenced(
                session, "actions.id", row.id, exclude=frozenset({"zulip_recovery_items"})
            )
        if kind == "command":
            return not (
                await self._source_pending(session, row.realm_id, row.message_id)
                or await self._referenced(session, "command_receipts.id", row.id)
            )
        if kind == "delivery":
            if digest(row.payload) != row.payload_hash:
                raise Conflict("retention_delivery_payload_changed")
            if await self._binding_pending(session, row.binding_id):
                return False
            if row.batch_id is not None:
                batch = await session.get(DeliveryBatch, row.batch_id)
                if batch is None or await self._referenced(
                    session, "delivery_batches.id", row.batch_id
                ):
                    return False
                if (
                    await session.scalar(
                        select(Delivery.id)
                        .where(Delivery.batch_id == row.batch_id, Delivery.state != "delivered")
                        .limit(1)
                    )
                    is not None
                ):
                    return False
            if row.destination_id is not None:
                dest = await session.get(OutputDestination, row.destination_id)
                if (
                    dest is None
                    or dest.expires_at > cutoff
                    or not await self._destination_safe(session, dest)
                ):
                    return False
            return not await self._referenced(session, "deliveries.id", row.id)
        if kind == "destination":
            return await self._destination_safe(session, row)
        # Expired tokens retain identity/hash/expiry/used. A pending interaction
        # is an explicit recovery dependency, not a reason to retire evidence.
        if digest(row.context) != row.context_hash:
            raise Conflict("retention_control_token_changed")
        if not await self.recovery.token_safe(session, row):
            return False
        if row.binding_id and await self._binding_pending(session, row.binding_id):
            return False
        interaction = row.context.get("interaction_id")
        if interaction and await session.get(PendingInteraction, interaction) is not None:
            return False
        source = row.context.get("source")
        if isinstance(source, dict):
            return not await self._source_pending(session, row.realm_id, source.get("message_id"))
        return True

    async def _destination_safe(self, session: AsyncSession, row: OutputDestination) -> bool:
        if row.payload_compacted_at is not None:
            retained_scope(
                row.authorization,
                kind="destination:authorization",
                identity=row.id,
                when=row.payload_compacted_at,
                checksum=row.authorization_hash,
            )
        else:
            if digest(row.authorization) != row.authorization_hash:
                raise Conflict("retention_output_authorization_changed")
            target = DiscoveryTarget.model_validate(row.authorization)
            if (
                row.state != "active"
                or str(target.id) != row.id
                or row.realm_id != target.source.realm_id
                or row.expires_at != target.expires_at
            ):
                raise Conflict("retention_output_destination_metadata_changed")
            if await self._source_pending(
                session, target.source.realm_id, target.source.message_id
            ):
                return False
        if (
            await session.scalar(
                select(Delivery.id)
                .where(Delivery.destination_id == row.id, Delivery.state != "delivered")
                .limit(1)
            )
            is not None
        ):
            return False
        batches = select(DeliveryBatch.id).where(DeliveryBatch.destination_id == row.id)
        return not await self._referenced(session, "delivery_batches.id", batches)

    @staticmethod
    def _fields(kind: str) -> tuple[str, ...]:
        return {
            "input": ("payload",),
            "recovery_input": ("payload",),
            "action": ("payload", "admission", "native_result"),
            "delivery": ("payload",),
            "command": ("response",),
            "destination": ("authorization",),
            "token": ("context",),
        }[kind]

    @staticmethod
    def _stamp(kind: str, row: Any) -> str:
        return digest(
            {
                "state": row.state,
                "version": getattr(row, "version", None),
                "binding": getattr(row, "binding_id", None),
                "fields": {
                    name: digest(getattr(row, name)) for name in RetentionExecutor._fields(kind)
                },
            }
        )

    @staticmethod
    def _compact(kind: str, row: Any, now: float) -> None:
        identity = row.token_hash if kind == "token" else row.id
        scope: dict[str, Any] = {}
        if kind == "input":
            scope = {
                key: row.payload[key]
                for key in (
                    "realm_id",
                    "bot_user_id",
                    "source",
                    "queue_id",
                    "event_id",
                    "capture_fencing",
                    "raw_sha256",
                )
            }
        if kind == "recovery_input":
            scope = RecoveryRetention.scope(row)
        if kind == "destination":
            target = DiscoveryTarget.model_validate(row.authorization)
            scope = {
                "realm_id": target.source.realm_id,
                "channel_id": target.source.channel_id,
                "topic": target.source.topic,
            }
        if kind == "action" and isinstance(row.payload.get("source"), dict):
            source = row.payload["source"]
            scope = {"source_revision": source.get("revision"), "source_sha256": digest(source)}
        for name in RetentionExecutor._fields(kind):
            old = getattr(row, name)
            setattr(row, name, tombstone(kind + ":" + name, identity, digest(old), now, scope))
        row.payload_compacted_at = now
        # Original hashes/dedupe IDs, final state and message IDs never change.
        if hasattr(row, "version"):
            row.version += 1

    async def _audit_protected(self, session: AsyncSession, identity: str) -> bool:
        if (
            await session.scalar(select(FileTransfer.id).where(FileTransfer.id == identity))
            is not None
        ):
            return True  # Keep file/provenance metadata while its journal exists.
        for model, condition in (
            (Action, Action.state.not_in(TERMINAL_ACTIONS)),
            (Delivery, Delivery.state != "delivered"),
            (CommandReceipt, CommandReceipt.state != "completed"),
            (InputEvent, InputEvent.state.not_in({"zulip_done", "zulip_ignored"})),
            (
                PendingInteraction,
                PendingInteraction.state.not_in({"resolved", "expired", "rejected", "cancelled"}),
            ),
        ):
            if (
                await session.scalar(select(model.id).where(model.id == identity, condition))
                is not None
            ):
                return True
        return False

    async def sweep(self) -> RetentionSweep:
        now = float(self.clock())
        if not math.isfinite(now) or now <= 0:
            raise ValueError("retention_clock_invalid")
        delay = self.settings.finalized_payload_days * DAY
        cutoff, audit_cutoff = now - delay, now - self.settings.audit_metadata_days * DAY
        cursors = dict(self._cursors)
        scanned = observed = compacted = purged = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            categories = (*PROFILES, ("audit", AuditEvent))
            for offset in range(len(categories)):
                if scanned >= self.batch_size:
                    break
                kind, model = categories[(self._start + offset) % len(categories)]
                key = model.token_hash if kind == "token" else model.id
                age = model.expires_at if kind == "token" else model.created_at
                # Fetch bounded identity metadata first. Decrypt just one row
                # at a time, never materialize N * maximum-size JSON bodies.
                query = select(key, age)
                if kind == "audit":
                    query = query.where(
                        AuditEvent.created_at <= audit_cutoff,
                        AuditEvent.event.not_in(PROTECTED_AUDIT_EVENTS),
                    )
                else:
                    query = query.where(model.payload_compacted_at.is_(None))
                if kind == "input":
                    query = query.where(
                        model.state.in_({"zulip_done", "zulip_ignored"}),
                        model.source.startswith("zulip:"),
                    )
                elif kind == "recovery_input":
                    query = query.where(
                        model.state.in_(RECOVERY_STATES),
                        or_(
                            model.source.startswith("zulip-history:"),
                            model.source.startswith("zulip-recovery:"),
                            model.source.startswith("zulip-recovery-review:"),
                        ),
                    )
                elif kind == "action":
                    query = query.where(model.state.in_(TERMINAL_ACTIONS), model.owner == "bridge")
                elif kind == "delivery":
                    query = query.where(
                        model.state == "delivered",
                        model.posted_message_id > 0,
                        model.updated_at > 0,
                        model.updated_at <= cutoff,
                    )
                elif kind == "command":
                    query = query.where(
                        model.state == "completed", model.updated_at > 0, model.updated_at <= cutoff
                    )
                elif kind != "audit":
                    query = query.where(model.expires_at > 0, model.expires_at <= cutoff)
                    if kind == "destination":
                        query = query.where(model.state == "active")
                cursor = cursors.get(kind)
                if cursor is not None:
                    query = query.where(
                        or_(age > cursor[0], and_(age == cursor[0], key > cursor[1]))
                    )
                candidates = list(
                    (
                        await session.execute(
                            query.order_by(age, key).limit(self.batch_size - scanned)
                        )
                    ).all()
                )
                cursors[kind] = None if not candidates else (candidates[-1][1], candidates[-1][0])
                for identity, _age in candidates:
                    row: Any = await session.get(model, identity, with_for_update=True)
                    if row is None:
                        raise Conflict("retention_candidate_disappeared")
                    scanned += 1
                    if kind == "audit":
                        if not await self._audit_protected(session, row.object_id):
                            await session.delete(row)
                            purged += 1
                            await session.flush()
                        continue
                    if not await self._safe(session, kind, row, now, cutoff):
                        continue
                    if kind in {"input", "recovery_input", "action"}:
                        fingerprint = self._stamp(kind, row)
                        stamp = row.retention_observed_at
                        if (
                            stamp is None
                            or not math.isfinite(stamp)
                            or stamp > now
                            or stamp <= 0
                            or row.retention_fingerprint != fingerprint
                        ):
                            row.retention_observed_at, row.retention_fingerprint = now, fingerprint
                            observed += 1
                            await session.flush()
                            continue
                        if now - stamp < delay:
                            continue
                    if kind == "recovery_input" and not await self.recovery.fits_storage(
                        session, row, now
                    ):
                        continue  # Retain small metadata rather than grow the byte quota.
                    self._compact(kind, row, now)
                    if kind in {"input", "recovery_input"}:
                        await self.recovery.retire_items(session, row.id)
                    compacted += 1
                    await session.flush()  # release old ORM JSON history, still no commit
            await session.flush()
            await self.fence.lock(session)  # expiry/cancellation rolls back the WHOLE sweep
        self._cursors = cursors
        self._start = (self._start + 1) % len(categories)
        return RetentionSweep(scanned, observed, compacted, purged)

    async def run(self) -> None:
        while True:
            await self.sweep()
            await self.live.sweep()
            await asyncio.sleep(self.interval)
