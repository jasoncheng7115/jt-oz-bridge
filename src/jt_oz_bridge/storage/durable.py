"""Transactional receipts, CAS actions, outbox holds and fenced consumer leases."""

import hashlib
import json
import time
from typing import Any

from sqlalchemy import case, select, update
from sqlalchemy.exc import IntegrityError

from jt_oz_bridge.domain.models import TRANSITIONS, ActionState
from jt_oz_bridge.domain.operations import current_operation
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import Action, Checkpoint, Delivery, InputEvent, WorkerLease
from jt_oz_bridge.storage.statements import insert


class Conflict(ValueError):
    pass


def digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


class DurableStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def ingest(
        self,
        source: str,
        queue_id: str,
        event_id: int,
        source_id: str,
        revision: int,
        payload: dict[str, Any],
    ) -> tuple[str, bool]:
        """Commit receipt and queue checkpoint together; queue rotation is explicit."""
        async with self.db.sessions.begin() as session:
            # A checkpoint is enrolled before event consumption, never implicitly reset here.
            checkpoint = (
                await session.execute(
                    update(Checkpoint)
                    .where(Checkpoint.source == source, Checkpoint.queue_id == queue_id)
                    .values(
                        event_id=case(
                            (Checkpoint.event_id < event_id, event_id), else_=Checkpoint.event_id
                        ),
                        updated_at=time.time(),
                    )
                    .returning(Checkpoint.source)
                )
            ).scalar_one_or_none()
            if checkpoint is None:
                raise Conflict("queue must be enrolled before ingestion")
            existing = await session.scalar(
                select(InputEvent).where(
                    InputEvent.source == source,
                    InputEvent.source_id == source_id,
                    InputEvent.revision == revision,
                )
            )
            if existing:
                if existing.payload_hash != digest(payload):
                    raise Conflict("source revision reused with different content")
                receipt_id, inserted = existing.id, False
            else:
                receipt = InputEvent(
                    source=source,
                    source_id=source_id,
                    revision=revision,
                    payload=payload,
                    payload_hash=digest(payload),
                )
                session.add(receipt)
                await session.flush()
                receipt_id, inserted = receipt.id, True
            return receipt_id, inserted

    async def enroll_queue(self, source: str, queue_id: str, initial_event_id: int) -> None:
        async with self.db.sessions.begin() as session:
            current = await session.get(Checkpoint, source)
            if current:
                current.queue_id, current.event_id = queue_id, initial_event_id
                current.updated_at = time.time()
            else:
                session.add(Checkpoint(source=source, queue_id=queue_id, event_id=initial_event_id))

    async def enqueue(
        self,
        key: str,
        binding_id: str,
        binding_revision: int,
        actor_id: int,
        payload: dict[str, Any],
        recovered: bool = False,
    ) -> str:
        """Persistence primitive only. A caller must authorize before and again at dispatch."""
        async with self.db.sessions.begin() as session:
            checksum = digest(
                {
                    "binding": binding_id,
                    "revision": binding_revision,
                    "actor": actor_id,
                    "payload": payload,
                }
            )
            action_id = (
                await session.execute(
                    insert(self.db, Action)
                    .values(
                        dedupe_key=key,
                        binding_id=binding_id,
                        binding_revision=binding_revision,
                        actor_id=actor_id,
                        operation_digest=checksum,
                        payload=payload,
                        operation=current_operation(payload),
                        state=ActionState.HELD if recovered else ActionState.QUEUED,
                    )
                    .on_conflict_do_nothing(index_elements=["dedupe_key"])
                    .returning(Action.id)
                )
            ).scalar_one_or_none()
            if action_id:
                return str(action_id)
            existing = (await session.scalars(select(Action).where(Action.dedupe_key == key))).one()
            if existing.operation_digest != checksum:
                raise Conflict("action ID reused with different operation")
            return existing.id

    async def transition(
        self, action_id: str, expected: ActionState, target: ActionState, version: int
    ) -> bool:
        if target not in TRANSITIONS[expected]:
            raise Conflict("unsafe action transition")
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(Action)
                .where(Action.id == action_id, Action.state == expected, Action.version == version)
                .values(state=target, version=version + 1)
            )
            return result.rowcount == 1  # type: ignore[attr-defined,no-any-return]

    async def queue_delivery(
        self, key: str, binding_id: str, binding_revision: int, payload: dict[str, Any]
    ) -> str:
        async with self.db.sessions.begin() as session:
            delivery_id = (
                await session.execute(
                    insert(self.db, Delivery)
                    .values(
                        dedupe_key=key,
                        binding_id=binding_id,
                        binding_revision=binding_revision,
                        payload=payload,
                        payload_hash=digest(payload),
                    )
                    .on_conflict_do_nothing(index_elements=["dedupe_key"])
                    .returning(Delivery.id)
                )
            ).scalar_one_or_none()
            if delivery_id:
                return str(delivery_id)
            existing = (
                await session.scalars(select(Delivery).where(Delivery.dedupe_key == key))
            ).one()
            if (
                existing.payload_hash != digest(payload)
                or existing.binding_id != binding_id
                or existing.binding_revision != binding_revision
            ):
                raise Conflict("delivery ID reused with different target/content")
            return existing.id

    async def recover(self) -> None:
        """No networking here: uncertain sends never become eligible for blind retry."""
        async with self.db.sessions.begin() as session:
            for before, after in [
                (ActionState.QUEUED, ActionState.HELD),
                (ActionState.DISPATCHING, ActionState.AMBIGUOUS),
            ]:
                # An Agent attempt moves only together with its configuration head;
                # its dedicated GET-only restore performs the same conservative move.
                await session.execute(
                    update(Action)
                    .where(Action.state == before, Action.operation != "agent.switch")
                    .values(state=after, version=Action.version + 1)
                )
            await session.execute(
                update(Delivery)
                .where(Delivery.state == "sending")
                .values(
                    state="ambiguous",
                    version=Delivery.version + 1,
                    updated_at=time.time(),
                    status_reason="restart_during_send",
                )
            )
            await session.execute(
                update(Delivery)
                .where(Delivery.state == "pending")
                .values(
                    state="held",
                    version=Delivery.version + 1,
                    updated_at=time.time(),
                    status_reason="restart_unsent",
                )
            )

    async def acquire_lease(self, holder: str, ttl: float = 30) -> int | None:
        if not await self.db.ready():
            return None
        now = time.time()
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(WorkerLease)
                .where(WorkerLease.role == "consumer", WorkerLease.expires_at <= now)
                .values(holder=holder, expires_at=now + ttl, fencing=WorkerLease.fencing + 1)
                .returning(WorkerLease.fencing)
            )
            fencing = result.scalar_one_or_none()
            if fencing is not None:
                return fencing
        try:
            async with self.db.sessions.begin() as session:
                session.add(WorkerLease(role="consumer", holder=holder, expires_at=now + ttl))
            return 1
        except IntegrityError:
            return None

    async def renew_lease(self, holder: str, fencing: int, ttl: float = 30) -> bool:
        now = time.time()
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(WorkerLease)
                .where(
                    WorkerLease.role == "consumer",
                    WorkerLease.holder == holder,
                    WorkerLease.fencing == fencing,
                    WorkerLease.expires_at > now,
                )
                .values(expires_at=now + ttl)
            )
            return result.rowcount == 1  # type: ignore[attr-defined,no-any-return]

    async def release_lease(self, holder: str, fencing: int) -> None:
        async with self.db.sessions.begin() as session:
            await session.execute(
                update(WorkerLease)
                .where(
                    WorkerLease.role == "consumer",
                    WorkerLease.holder == holder,
                    WorkerLease.fencing == fencing,
                )
                .values(expires_at=0)
            )
