"""Fenced own dedup journal and coalesced visible-source archival persistence."""

import time
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.live import FeedEventReceipt, V2PublicFeed, event_receipt_key
from jt_oz_bridge.adapters.opencode.live_text import VisibleTextSnapshot
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.live_models import NativeFeedReceipt, NativeLiveCapture


class LiveEventJournal:
    def __init__(self, db: Database, fence: ConsumerFence) -> None:
        self.db, self.fence = db, fence

    async def record_many(self, values: tuple[FeedEventReceipt, ...]) -> tuple[bool, ...]:
        if not values or len(values) > 128:
            raise ValueError("bounded_nonempty_receipt_batch_required")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            existing = {
                row.key: row
                for row in (
                    await session.scalars(
                        select(NativeFeedReceipt).where(
                            NativeFeedReceipt.key.in_([v.key for v in values])
                        )
                    )
                ).all()
            }
            result = []
            for value in values:
                payload = value.model_dump(mode="json")
                row = existing.get(value.key)
                if row is not None:
                    if (
                        digest(row.payload) != row.payload_hash
                        or row.connection_epoch != value.connection_epoch
                        or row.payload != payload
                    ):
                        raise Conflict("native_feed_receipt_identity_changed")
                    result.append(False)
                else:
                    row = NativeFeedReceipt(
                        key=value.key,
                        connection_epoch=value.connection_epoch,
                        payload=payload,
                        payload_hash=digest(payload),
                        recorded_at=time.time(),
                    )
                    session.add(row)
                    existing[value.key] = row
                    result.append(True)
        return tuple(result)


def read_live_capture(row: NativeLiveCapture) -> VisibleTextSnapshot:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("visible_text_capture_seal_changed")
    value = VisibleTextSnapshot.model_validate(row.payload)
    if (value.id, value.source_key, value.revision) != (row.id, row.source_key, row.revision):
        raise Conflict("visible_text_capture_scope_changed")
    # Unset (pre-schema37) retention copies are backfilled, never trusted blank.
    if (row.connection_epoch is not None and row.connection_epoch != value.connection_epoch) or (
        row.receipt_key is not None and row.receipt_key != capture_receipt_key(value)
    ):
        raise Conflict("visible_text_capture_scope_changed")
    return value


def capture_receipt_key(value: VisibleTextSnapshot) -> str:
    return event_receipt_key(
        value.reference, value.owner_epoch, value.connection_epoch, value.last_event_id
    )


async def validate_capture_receipt(session: AsyncSession, value: VisibleTextSnapshot) -> None:
    key = capture_receipt_key(value)
    receipt = await session.get(NativeFeedReceipt, key)
    if receipt is None or digest(receipt.payload) != receipt.payload_hash:
        raise Conflict("visible_text_capture_receipt_missing")
    metadata = FeedEventReceipt.model_validate(receipt.payload)
    if (
        metadata.key != receipt.key
        or metadata.reference != value.reference
        or metadata.event_sha256 != value.last_event_sha256
        or metadata.connection_epoch != receipt.connection_epoch
        or metadata.contract_sha256 != value.contract_sha256
        or metadata.event_type
        not in {"session.text.started", "session.text.delta", "session.text.ended"}
    ):
        raise Conflict("visible_text_capture_receipt_changed")


class LiveTextSource(Protocol):
    async def available(self, reference: SessionRef) -> tuple[str, ...]: ...
    def current(self, reference: SessionRef, identity: str) -> bool: ...


class LiveTextCollector:
    def __init__(self, db: Database, fence: ConsumerFence, feed: V2PublicFeed) -> None:
        self.db, self.fence, self.feed = db, fence, feed
        self._saved: dict[str, str] = {}

    async def collect(self) -> int:
        await self.feed.current_owner()
        capture = self.feed.visible_text
        if capture is None:
            return 0
        values = capture.snapshots()
        pending = tuple(v for v in values if self._saved.get(v.source_key) != v.id)
        if not pending:
            return 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            # A racing text revision is safe to retain as a historical capture.
            # A dead/replaced original generation is not silently accepted.
            epoch = capture.index.require_live()
            for value in pending:
                if (
                    value.connection_epoch != epoch
                    or value.owner_epoch != capture.index.owner_epoch
                    or capture.index.references.get(value.reference.upstream_session_id)
                    != value.reference
                ):
                    raise Conflict("visible_text_capture_generation_changed")
                await validate_capture_receipt(session, value)
                row = await session.get(NativeLiveCapture, value.id)
                if row is not None:
                    if read_live_capture(row) != value:
                        raise Conflict("visible_text_capture_identity_changed")
                else:
                    payload = value.model_dump(mode="json")
                    session.add(
                        NativeLiveCapture(
                            id=value.id,
                            source_key=value.source_key,
                            revision=value.revision,
                            payload=payload,
                            payload_hash=digest(payload),
                            connection_epoch=value.connection_epoch,
                            receipt_key=capture_receipt_key(value),
                            recorded_at=time.time(),
                        )
                    )
            capture.index.require_live()
        # Bounded by the capture window, never one entry per token or generation.
        self._saved = {v.source_key: v.id for v in values}
        return len(pending)

    async def available(self, reference: SessionRef) -> tuple[str, ...]:
        await self.feed.current_owner()
        capture = self.feed.visible_text
        if capture is None:
            return ()
        return tuple(
            self._saved[value.source_key]
            for value in capture.snapshots()
            if value.reference == reference and value.source_key in self._saved
        )

    def current(self, reference: SessionRef, identity: str) -> bool:
        self.feed.check_contract()
        capture = self.feed.visible_text
        if capture is None:
            return False
        return any(
            value.reference == reference and self._saved.get(value.source_key) == identity
            for value in capture.snapshots()
        )
