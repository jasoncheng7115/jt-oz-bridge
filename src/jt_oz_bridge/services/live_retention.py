"""Bounded deletion of own live-feed receipts and captures from ended connections.

A receipt deduplicates only inside its own Native connection generation: its key
includes that connection epoch and an ended feed never reconnects. A capture is
read only while its generation is current or through an explicit foreign key.
Neither is a replay cursor, Zulip dedupe key, checkpoint or Native history, so
rows of an ended generation are deleted after the finalized-payload horizon.
Every generation this process opened stays protected, as does any receipt that a
retained capture verifies and any capture another table references.
"""

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import Column, delete, exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Retention
from jt_oz_bridge.services.live_capture import capture_receipt_key, read_live_capture
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.live_models import NativeFeedReceipt, NativeLiveCapture
from jt_oz_bridge.storage.schema import Base

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed

DAY = 86400
TABLES = ("native_feed_receipts", "native_live_captures")


@dataclass(frozen=True)
class LiveSweep:
    stamped: int
    backfilled: int
    captures_deleted: int
    receipts_deleted: int


class FeedGenerations:
    """Connection epochs opened by this process's original feeds, never reset."""

    def __init__(self, feeds: tuple["V2PublicFeed", ...]) -> None:
        self.feeds = feeds

    def epochs(self) -> frozenset[str]:
        # A closed index keeps its epoch: an in-flight receipt batch or collector
        # may still name it. A restart opens new epochs and ends these for good.
        return frozenset(
            feed.index.connection_epoch
            for feed in self.feeds
            if feed.index is not None and feed.index.connection_epoch is not None
        )

    def connected(self) -> int:
        return sum(
            1
            for feed in self.feeds
            if feed.index is not None
            and not feed.index.closed
            and feed.index.connection_epoch is not None
        )


def _dependents(target: str) -> tuple[Column[Any], ...]:
    # Complete current FK metadata, like payload retention: a draft publication
    # (or any future table) pins its capture regardless of the capture's age.
    return tuple(
        column
        for table in Base.metadata.sorted_tables
        for column in table.columns
        if any(fk.target_fullname == target for fk in column.foreign_keys)
    )


class LiveSourceRetention:
    def __init__(
        self,
        db: Database,
        fence: ConsumerFence,
        settings: Retention,
        *,
        batch_size: int = 256,
        max_batches: int = 16,
        backfill_size: int = 32,
        pause: float = 0.05,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            any(
                type(value) is not int or not 1 <= value <= limit
                for value, limit in ((batch_size, 1000), (max_batches, 64), (backfill_size, 128))
            )
            or not 0 <= pause <= 1
        ):
            raise ValueError("live_retention_batches_must_be_bounded")
        self.db, self.fence, self.settings = db, fence, settings
        self.batch_size, self.max_batches, self.backfill_size = (
            batch_size,
            max_batches,
            backfill_size,
        )
        self.pause, self.clock = pause, clock
        # Unknown live generations retain everything. Only the composition that
        # owns the feeds may supply them; a standalone executor deletes nothing.
        self.generations: FeedGenerations | None = None
        self.deleted = dict.fromkeys(TABLES, 0)

    def _protected(self) -> frozenset[str]:
        assert self.generations is not None
        values = self.generations.epochs()
        if any(
            type(v) is not str or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
            for v in values
        ):
            raise ValueError("live_retention_connection_epoch_invalid")
        return values

    async def sweep(self) -> LiveSweep:
        if self.generations is None:
            return LiveSweep(0, 0, 0, 0)
        now = float(self.clock())
        if not math.isfinite(now) or now <= 0:
            raise ValueError("retention_clock_invalid")
        cutoff = now - self.settings.finalized_payload_days * DAY
        total = LiveSweep(0, 0, 0, 0)
        # Several short fenced transactions instead of one long one: each holds
        # the SQLite write lock for at most one bounded batch per table, and the
        # pause lets a waiting writer's busy handler take the lock in between.
        for index in range(self.max_batches):
            if index:
                await asyncio.sleep(self.pause)
            step = await self._step(now, cutoff)
            total = LiveSweep(
                total.stamped + step.stamped,
                total.backfilled + step.backfilled,
                total.captures_deleted + step.captures_deleted,
                total.receipts_deleted + step.receipts_deleted,
            )
            if step.backfilled < self.backfill_size and all(
                count < self.batch_size
                for count in (step.stamped, step.captures_deleted, step.receipts_deleted)
            ):
                break  # Nothing else is currently eligible.
        return total

    async def _step(self, now: float, cutoff: float) -> LiveSweep:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            protected = self._protected()
            stamped = await self._stamp(session, now)
            backfilled = await self._backfill(session, now)
            captures = await self._delete_captures(session, cutoff, protected)
            receipts = await self._delete_receipts(session, cutoff, protected)
            await self.fence.lock(session)  # expiry/cancellation rolls back this batch
        self.deleted["native_live_captures"] += captures
        self.deleted["native_feed_receipts"] += receipts
        return LiveSweep(stamped, backfilled, captures, receipts)

    async def _stamp(self, session: AsyncSession, now: float) -> int:
        # A pre-schema37 receipt has no own time. Its horizon starts when first
        # observed here, like the payload retention fingerprint stamp.
        legacy = (
            select(NativeFeedReceipt.key)
            .where(NativeFeedReceipt.recorded_at.is_(None))
            .limit(self.batch_size)
        )
        result = await session.execute(
            update(NativeFeedReceipt)
            .where(NativeFeedReceipt.key.in_(legacy.scalar_subquery()))
            .values(recorded_at=now)
            .execution_options(synchronize_session=False)
        )
        return int(result.rowcount)  # type: ignore[attr-defined]

    async def _backfill(self, session: AsyncSession, now: float) -> int:
        identities = (
            await session.scalars(
                select(NativeLiveCapture.id)
                .where(NativeLiveCapture.receipt_key.is_(None))
                .order_by(NativeLiveCapture.id)
                .limit(self.backfill_size)
            )
        ).all()
        for identity in identities:
            row = await session.get(NativeLiveCapture, identity, with_for_update=True)
            if row is None:
                continue
            value = read_live_capture(row)  # A broken seal stops the worker, never deletes.
            row.connection_epoch = value.connection_epoch
            row.receipt_key = capture_receipt_key(value)
            if row.recorded_at is None:
                row.recorded_at = now
            await session.flush()
            session.expunge(row)  # Decrypt and hold one capture at a time.
        return len(identities)

    async def _delete_captures(
        self, session: AsyncSession, cutoff: float, protected: frozenset[str]
    ) -> int:
        query = select(NativeLiveCapture.id).where(
            NativeLiveCapture.recorded_at.is_not(None),
            NativeLiveCapture.recorded_at <= cutoff,
            NativeLiveCapture.receipt_key.is_not(None),
            NativeLiveCapture.connection_epoch.is_not(None),
            NativeLiveCapture.connection_epoch.not_in(protected),
        )
        for column in _dependents("native_live_captures.id"):
            query = query.where(~exists().where(column == NativeLiveCapture.id))
        doomed = query.order_by(NativeLiveCapture.recorded_at).limit(self.batch_size)
        result = await session.execute(
            delete(NativeLiveCapture)
            .where(NativeLiveCapture.id.in_(doomed.scalar_subquery()))
            .execution_options(synchronize_session=False)
        )
        return int(result.rowcount)  # type: ignore[attr-defined]

    async def _delete_receipts(
        self, session: AsyncSession, cutoff: float, protected: frozenset[str]
    ) -> int:
        # A capture not yet backfilled could verify any receipt; keep them all.
        if (
            await session.scalar(
                select(NativeLiveCapture.id).where(NativeLiveCapture.receipt_key.is_(None)).limit(1)
            )
            is not None
        ):
            return 0
        query = select(NativeFeedReceipt.key).where(
            NativeFeedReceipt.recorded_at.is_not(None),
            NativeFeedReceipt.recorded_at <= cutoff,
            NativeFeedReceipt.connection_epoch.not_in(protected),
            ~exists().where(NativeLiveCapture.receipt_key == NativeFeedReceipt.key),
        )
        for column in _dependents("native_feed_receipts.key"):
            query = query.where(~exists().where(column == NativeFeedReceipt.key))
        doomed = query.order_by(NativeFeedReceipt.recorded_at).limit(self.batch_size)
        result = await session.execute(
            delete(NativeFeedReceipt)
            .where(NativeFeedReceipt.key.in_(doomed.scalar_subquery()))
            .execution_options(synchronize_session=False)
        )
        return int(result.rowcount)  # type: ignore[attr-defined]
