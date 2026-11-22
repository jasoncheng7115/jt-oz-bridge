"""Isolated Main diagnostics: current local lease plus controller observations.

No Native I/O or mutation authority. Publication failure invalidates diagnostics
without joining the supervised business-worker failure group.
"""

import asyncio
import math
import os
import time
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import select

from jt_oz_bridge.domain.runtime_readiness import (
    ConsumerLeaseObservation,
    RootModeFact,
    RuntimeModeSnapshot,
    lease_fingerprint,
)
from jt_oz_bridge.services.runtime_status import MAX_AGE, RuntimeStatusWriter
from jt_oz_bridge.storage.backup_files import component, directory_fd
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import WorkerLease


class RuntimeModePublisher:
    def __init__(
        self,
        db: Database,
        fence: ConsumerFence,
        directory: Path,
        facts: Callable[[], tuple[RootModeFact, ...]],
        scope_current: Callable[[], bool],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db, self.fence, self.directory = db, fence, directory
        self.facts, self.scope_current, self.clock = facts, scope_current, clock
        self.fingerprint = lease_fingerprint(fence.holder, fence.fencing)
        self._healthy: Callable[[], bool] = lambda: False
        self._writer: RuntimeStatusWriter | None = None
        self._task: asyncio.Task[None] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._snapshot: RuntimeModeSnapshot | None = None
        self._lease: ConsumerLeaseObservation | None = None
        self._used = self._closed = self._failed = False

    def _now(self) -> float:
        now = self.clock()
        if type(now) is not float or not math.isfinite(now) or now < 0:
            raise ValueError("runtime_mode_clock_invalid")
        return now

    def invalidate(self) -> None:
        self._snapshot = self._lease = None

    async def collect(self) -> RuntimeModeSnapshot | None:
        self.invalidate()
        if self._closed or self._failed or not self._healthy() or not self.scope_current():
            return None
        started = self._now()
        async with self.db.sessions() as session:
            lease = await session.scalar(select(WorkerLease).where(WorkerLease.role == "consumer"))
        now = self._now()
        if (
            lease is None
            or (lease.holder, lease.fencing) != (self.fence.holder, self.fence.fencing)
            or not started <= now < min(started + MAX_AGE, lease.expires_at)
            or not self._healthy()
            or not self.scope_current()
        ):
            return None
        facts = self.facts()
        generated = self._now()
        snapshot = RuntimeModeSnapshot.create(
            generated_at=generated, lease_fingerprint=self.fingerprint, roots=facts
        )
        checked = self._now()
        if not now <= generated <= checked < min(started + MAX_AGE, lease.expires_at):
            return None
        self._lease = ConsumerLeaseObservation(
            lease_fingerprint=self.fingerprint,
            observed_at=started,
            expires_at=float(lease.expires_at),
        )
        self._snapshot = snapshot
        return self.snapshot()

    def snapshot(self) -> RuntimeModeSnapshot | None:
        try:
            snapshot, lease = self._snapshot, self._lease
            now = self._now()
            if (
                self._closed
                or self._failed
                or snapshot is None
                or lease is None
                or not self._healthy()
                or not self.scope_current()
                or not lease.observed_at <= now < min(lease.observed_at + 1.0, lease.expires_at)
                or not snapshot.generated_at <= now < snapshot.generated_at + MAX_AGE
                or snapshot.lease_fingerprint != self.fingerprint
                or snapshot.roots != tuple(sorted(self.facts(), key=lambda root: root.scope_key))
            ):
                return None
            return snapshot
        except Exception:
            # An optional projection error cannot disable or authorize business.
            return None

    async def start(self, healthy: Callable[[], bool]) -> None:
        if self._used or self._closed:
            raise ValueError("runtime_mode_publisher_single_use")
        self._used, self._healthy = True, healthy
        try:
            # Do not follow a replaced/symlink parent even for initial mkdir.
            parent = directory_fd(self.directory.parent)
            try:
                try:
                    os.mkdir(component(self.directory.name), mode=0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass  # The writer independently checks the existing path.
            finally:
                os.close(parent)
            self._writer = RuntimeStatusWriter(self.directory, self.fingerprint, clock=self.clock)
        except Exception:
            self._failed = True
            self.invalidate()
            return
        self._task = asyncio.create_task(self.run(), name="jtoz:runtime-modes")

    async def run(self) -> None:
        try:
            while not self._closed:
                # SQLAlchemy shields its own session-close child. Keep this
                # complete observation owned and uncancelled until that child
                # has returned its connection, before ending our lifecycle.
                observation = asyncio.create_task(self.collect(), name="jtoz:runtime-mode-lease")
                try:
                    snapshot = await asyncio.shield(observation)
                except asyncio.CancelledError:
                    await asyncio.shield(observation)
                    raise
                if snapshot is not None:
                    assert self._writer is not None
                    write = asyncio.create_task(asyncio.to_thread(self._writer.publish, snapshot))
                    try:
                        await asyncio.shield(write)
                    except asyncio.CancelledError:
                        # Join descriptor-using I/O before closing its pinned FD.
                        await asyncio.shield(write)
                        raise
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._failed = True
        finally:
            self.invalidate()
            self._close_writer()

    def _close_writer(self) -> None:
        writer, self._writer = self._writer, None
        if writer is not None:
            try:
                writer.close()
            except Exception:
                # Diagnostic cleanup must not bypass business-worker cleanup.
                self._failed = True

    async def close(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close(), name="jtoz:runtime-mode-cleanup")
        await asyncio.shield(self._close_task)

    async def _close(self) -> None:
        self._closed = True
        self.invalidate()
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._close_writer()
