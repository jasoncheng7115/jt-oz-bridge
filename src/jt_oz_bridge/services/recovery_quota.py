"""Per-source SQL metadata quotas; no cleanup or execution authority is issued."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import event, func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from jt_oz_bridge.storage.cipher_types import EncryptedJSON
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import InputEvent
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryItem

RESERVE = 4096
HARD_BYTES = 128 * 1024**2


class RecoveryCapacityExceeded(Conflict):
    pass


@dataclass(frozen=True)
class RecoveryLimits:
    epochs: int = 128
    items: int = 10000
    bytes: int = HARD_BYTES

    def __post_init__(self) -> None:
        if any(type(v) is not int for v in (self.epochs, self.items, self.bytes)) or not (
            1 <= self.epochs <= 128
            and 1 <= self.items <= 10000
            and 8192 <= self.bytes <= HARD_BYTES
        ):
            raise ValueError("invalid_recovery_capacity_limits")

    def dump(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_run(cls, run: dict[str, Any]) -> RecoveryLimits:
        value = run.get("quota", cls().dump())  # Old schema34 epochs retain fixed safe defaults.
        if type(value) is not dict or set(value) != {"epochs", "items", "bytes"}:
            raise Conflict("recovery_quota_policy_changed")
        return cls(**value)

    async def admission(self, session: AsyncSession, source: str) -> None:
        names = tuple(
            p + source for p in ("zulip-recovery:", "zulip-history:", "zulip-recovery-review:")
        )
        for model, condition, maximum in (
            (InputEvent, InputEvent.source == names[0], self.epochs),
            (InputEvent, InputEvent.source == names[1], self.items),
            (ZulipRecoveryItem, ZulipRecoveryItem.source == source, self.items),
        ):
            if (
                int(
                    await session.scalar(select(func.count()).select_from(model).where(condition))
                    or 0
                )
                >= maximum
            ):
                raise RecoveryCapacityExceeded("recovery_metadata_quota_requires_operator_review")
        size = int(
            await session.scalar(
                select(func.coalesce(func.sum(func.length(InputEvent.payload)), 0)).where(
                    InputEvent.source.in_(names)
                )
            )
            or 0
        )
        if size >= self.bytes - RESERVE:
            raise RecoveryCapacityExceeded("recovery_ciphertext_byte_quota_exceeded")

    @contextmanager
    def watch(self, session: AsyncSession, source: str, *, control: bool = False) -> Iterator[None]:
        """Only this owned session; listeners are removed on every exit/failure.

        Before SQL, measure actual AEAD encoder output (including its header,
        salt, nonce, tag and key ID). After SQL, re-read the actual BLOB length.
        No alternate ciphertext is stored and no plaintext-size estimate grants
        capacity. All SQL runs inside the caller's original fenced transaction.
        """
        sync = session.sync_session
        names = tuple(
            prefix + source
            for prefix in ("zulip-recovery:", "zulip-history:", "zulip-recovery-review:")
        )
        ceiling = self.bytes if control else self.bytes - RESERVE
        before_bytes = before_epochs = before_items = 0
        touched = False

        def metadata() -> tuple[int, int, int]:
            connection = sync.connection()
            payload_bytes = int(
                connection.scalar(
                    select(func.coalesce(func.sum(func.length(InputEvent.payload)), 0)).where(
                        InputEvent.source.in_(names)
                    )
                )
                or 0
            )
            epochs = int(
                connection.scalar(
                    select(func.count())
                    .select_from(InputEvent)
                    .where(InputEvent.source == names[0])
                )
            )
            items = int(
                connection.scalar(
                    select(func.count())
                    .select_from(ZulipRecoveryItem)
                    .where(ZulipRecoveryItem.source == source)
                )
            )
            histories = int(
                connection.scalar(
                    select(func.count())
                    .select_from(InputEvent)
                    .where(InputEvent.source == names[1])
                )
            )
            return payload_bytes, epochs, max(items, histories)

        def before_flush(_session: Session, _context: Any, _instances: Any) -> None:
            nonlocal touched, before_bytes, before_epochs, before_items
            changed = [
                row
                for row in (*sync.new, *sync.dirty)
                if isinstance(row, InputEvent) and row.source in names
            ]
            new_items = [
                row
                for row in sync.new
                if isinstance(row, ZulipRecoveryItem) and row.source == source
            ]
            if not changed and not new_items:
                touched = False
                return
            touched = True
            connection = sync.connection()
            before_bytes, epochs, _items = metadata()
            before_epochs, before_items = epochs, _items
            item_count = int(
                connection.scalar(
                    select(func.count())
                    .select_from(ZulipRecoveryItem)
                    .where(ZulipRecoveryItem.source == source)
                )
            )
            history_count = int(
                connection.scalar(
                    select(func.count())
                    .select_from(InputEvent)
                    .where(InputEvent.source == names[1])
                )
            )
            added_epochs = sum(row in sync.new and row.source == names[0] for row in changed)
            added_history = sum(row in sync.new and row.source == names[1] for row in changed)
            if added_epochs and epochs + added_epochs > self.epochs:
                raise RecoveryCapacityExceeded("recovery_epoch_quota_exceeded")
            if (new_items and item_count + len(new_items) > self.items) or (
                added_history and history_count + added_history > self.items
            ):
                raise RecoveryCapacityExceeded("recovery_item_or_history_quota_exceeded")
            proposed = before_bytes
            for row in changed:
                if row not in sync.new and not inspect(row).attrs.payload.history.has_changes():
                    continue  # State-only denial does not rewrite/re-encrypt the BLOB.
                original = (
                    0
                    if row in sync.new
                    else int(
                        connection.scalar(
                            select(func.length(InputEvent.payload)).where(InputEvent.id == row.id)
                        )
                        or 0
                    )
                )
                encoded = EncryptedJSON("input_events", "payload").process_bind_param(
                    row.payload, connection.dialect
                )
                if encoded is None:
                    raise Conflict("recovery_quota_encrypted_payload_required")
                proposed += len(encoded) - original
            if proposed > ceiling and proposed > before_bytes:
                raise RecoveryCapacityExceeded("recovery_ciphertext_byte_quota_exceeded")

        def after_flush(_session: Session, _context: Any) -> None:
            if touched:
                actual, epochs, items = metadata()
                if (
                    (epochs > self.epochs and epochs > before_epochs)
                    or (items > self.items and items > before_items)
                    or (actual > ceiling and actual > before_bytes)
                ):
                    raise RecoveryCapacityExceeded("recovery_stored_ciphertext_quota_exceeded")

        event.listen(sync, "before_flush", before_flush)
        event.listen(sync, "after_flush_postexec", after_flush)
        try:
            yield
        finally:
            event.remove(sync, "before_flush", before_flush)
            event.remove(sync, "after_flush_postexec", after_flush)

    @asynccontextmanager
    async def transaction(
        self, db: Database, fence: ConsumerFence, source: str, *, control: bool = False
    ) -> AsyncIterator[AsyncSession]:
        async with db.sessions.begin() as session:
            await fence.lock(session)
            with self.watch(session, source, control=control):
                yield session
                await session.flush()
                await fence.lock(session)
