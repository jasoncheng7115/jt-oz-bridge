"""Lock the current consumer lease before a local write transaction."""

import time
from dataclasses import dataclass

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import WorkerLease


@dataclass(frozen=True)
class ConsumerFence:
    holder: str
    fencing: int

    async def lock(self, session: AsyncSession) -> None:
        locked = await session.execute(
            update(WorkerLease)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == self.holder,
                WorkerLease.fencing == self.fencing,
                WorkerLease.expires_at > time.time(),
            )
            .values(expires_at=WorkerLease.expires_at)
        )
        if locked.rowcount != 1:  # type: ignore[attr-defined]
            raise Conflict("consumer_lease_unavailable")
