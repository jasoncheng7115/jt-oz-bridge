"""Read snapshots and explicit write intent, sharing the same engine/pool."""

import asyncio
import logging
import sqlite3
import time
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any
from weakref import WeakKeyDictionary, WeakSet

from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

LOG = logging.getLogger(__name__)


async def join_cleanup(operation: Coroutine[Any, Any, None]) -> None:
    """Propagate cancellation only after the real SQL cleanup/commit has ended.

    SQLAlchemy shields its close task but can return before that task finishes
    if the caller is cancelled. The runtime must join every cleanup before it
    closes the engine/event loop or releases its consumer lease. Joining an
    already started commit does not claim that cancellation rolled it back.
    """
    task = asyncio.create_task(operation)
    cancelled: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            cancelled = error
    task.result()
    if cancelled is not None:
        raise cancelled


class JoinedAsyncSession(AsyncSession):
    async def __aexit__(
        self,
        type_: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await join_cleanup(self.close())


class WriteGateExpired(OperationalError):
    """The in-process write queue did not reach this writer within its budget.

    It is the same ``database is locked`` failure SQLite's busy handler gives,
    raised before any connection or ``BEGIN IMMEDIATE``; nothing was written.
    """

    def __init__(self, waited: float) -> None:
        super().__init__(
            "BEGIN IMMEDIATE (queued)",
            None,
            sqlite3.OperationalError("database is locked"),
        )
        self.waited = waited


class WriteGate:
    """First-come order for this process's SQLite write transactions.

    SQLite's busy handler polls with growing sleeps, so a waiting writer can
    lose the released lock to newer writers again and again until its busy
    timeout expires. Here each writer waits its turn in FIFO order before it
    opens a connection; SQLite's own busy timeout still covers writers in other
    processes. A task that already holds the gate and opens a second write
    session is not queued again: it keeps exactly the earlier SQLite behaviour
    (the inner ``BEGIN IMMEDIATE`` waits on the outer one, then fails).
    """

    def __init__(self, timeout_seconds: float) -> None:
        if not timeout_seconds > 0:
            raise ValueError("write_gate_timeout_must_be_positive")
        self.timeout_seconds = timeout_seconds
        # asyncio locks belong to one event loop; tests and tools may use several.
        self._locks: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
            WeakKeyDictionary()
        )
        self._holders: WeakSet[asyncio.Task[Any]] = WeakSet()
        self.waiting = 0

    @asynccontextmanager
    async def hold(self) -> AsyncIterator[Callable[[], None]]:
        """Wait for this writer's turn; yields an idempotent early ``release``."""
        task = asyncio.current_task()
        if task is None or task in self._holders:
            yield lambda: None
            return
        loop = asyncio.get_running_loop()
        lock = self._locks.get(loop)
        if lock is None:
            lock = self._locks[loop] = asyncio.Lock()
        started = time.monotonic()
        self.waiting += 1
        try:
            async with asyncio.timeout(self.timeout_seconds):
                await lock.acquire()
        except TimeoutError:
            waited = time.monotonic() - started
            LOG.warning("sqlite_write_queue_expired waited_seconds=%.2f", waited)
            raise WriteGateExpired(waited) from None
        finally:
            self.waiting -= 1
        self._holders.add(task)
        held = True

        def release() -> None:
            nonlocal held
            if held:
                held = False
                self._holders.discard(task)
                lock.release()

        try:
            yield release
        finally:
            release()


class SessionFactory:
    def __init__(self, engine: AsyncEngine, *, write_gate: WriteGate | None = None) -> None:
        self._read = async_sessionmaker(engine, class_=JoinedAsyncSession, expire_on_commit=False)
        self._write = async_sessionmaker(
            engine.execution_options(jtoz_begin_immediate=True),
            class_=JoinedAsyncSession,
            expire_on_commit=False,
        )
        self.write_gate = write_gate

    def __call__(self) -> AsyncSession:
        return self._read()

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[AsyncSession]:
        if self.write_gate is None:
            async with self._begin() as session:
                yield session
            return
        # After a COMMIT has returned SQLite holds no write lock, so the next
        # writer's turn starts before this connection goes back to the pool. Any
        # failure keeps the turn until the session (and its rollback) is closed.
        async with self.write_gate.hold() as release, self._begin(release) as session:
            yield session

    @asynccontextmanager
    async def _begin(self, ended: Callable[[], None] | None = None) -> AsyncIterator[AsyncSession]:
        async with self._write() as session:
            transaction = session.begin()
            await transaction.__aenter__()
            try:
                yield session
            except BaseException as error:
                await join_cleanup(transaction.__aexit__(type(error), error, error.__traceback__))
                raise
            else:
                await join_cleanup(transaction.__aexit__(None, None, None))
                if ended is not None:
                    ended()
