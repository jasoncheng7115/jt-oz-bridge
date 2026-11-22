"""One-use supervised worker group sharing the web process's consumer fence.

This lifecycle does not invent qualified adapters, start an OpenCode backend or
retry failed workers. The explicit composition supplies resources and workers.
"""

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from jt_oz_bridge.domain.runtime_readiness import RuntimeModeSnapshot
from jt_oz_bridge.services.runtime_modes import RuntimeModePublisher
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.fencing import ConsumerFence

Operation = Callable[[], Awaitable[None]]
LOG = logging.getLogger(__name__)
WORKER_LABELS = frozenset(
    {
        "zulip-input",
        "zulip-typing",
        "bridge-retention",
        "native-owner-feed",
        "native-session-graphs",
        "native-dispatch",
        "native-results",
        "native-interactions",
        "result-publications",
        "zulip-delivery",
        "file-transfers",
        "native-session-creation",
    }
)
ERROR_LABELS = frozenset(
    {
        "ValueError",
        "RuntimeError",
        "TypeError",
        "AttributeError",
        "KeyError",
        "TimeoutError",
        "ValidationError",
        "OSError",
        "PermissionError",
        "FileNotFoundError",
        "ConnectionError",
        "ConnectError",
        "ConnectTimeout",
        "ReadTimeout",
        "RemoteProtocolError",
        "OperationalError",
        "WriteGateExpired",
        "IntegrityError",
        "DBAPIError",
        "SQLAlchemyError",
        "Conflict",
        "HostOwnerError",
        "SecretUnavailable",
        "AccessDenied",
        "ContractError",
        "SnapshotBoundaryChanged",
        "TransportError",
        "TransportNotSent",
        "ZulipError",
        "ZulipReadUnavailable",
        "ZulipAuthenticationFailed",
        "DeliveryRateLimited",
        "RequestBudgetDeferred",
    }
)


@dataclass(frozen=True)
class RuntimeFailure:
    stage: Literal["startup", "worker", "cleanup"]
    component: str
    index: int
    kind: Literal["raised", "returned", "cancelled"]
    error_type: str


def error_label(error: BaseException | None) -> str:
    if error is None:
        return "none"
    if isinstance(error, asyncio.CancelledError):
        return "CancelledError"
    name = type(error).__name__
    return name if name in ERROR_LABELS else "OtherError"


# Classes raised with fixed codes, whose code tells one stop from another.
CODED_ERRORS = frozenset(
    {
        "Conflict",
        "AccessDenied",
        "ContractError",
        "SnapshotBoundaryChanged",
        "TransportError",
        "TransportNotSent",
    }
)


def error_code(error: BaseException | None) -> str:
    """A coded error's fixed code such as ``upstream_rejected_request``, else "-".

    Other classes are never stringified, and free text never passes the pattern.
    """
    if error is None or error_label(error) not in CODED_ERRORS:
        return "-"
    text = str(error)
    return text if re.fullmatch(r"[a-z0-9_]{1,80}", text) else "-"


def resource_label(name: str) -> str:
    if name.startswith("native:"):
        return "native"
    if name.startswith("native-graph-activation:"):
        return "native-graph-activation"
    if name.startswith("workspace-catalog:"):
        return "workspace-catalog"
    return (
        name
        if name
        in {
            "zulip-client",
            "zulip-consumer",
            "zulip-typing-cleanup",
            "file-returns",
            "workspace-inputs",
            "session-restoration",
            "original-session-restoration",
        }
        else "other"
    )


@dataclass(frozen=True)
class RuntimeResource:
    name: str
    start: Operation
    close: Operation


@dataclass(frozen=True)
class RuntimeWorker:
    name: str
    run: Operation


class BridgeRuntime(Protocol):
    db: Database
    fence: ConsumerFence

    @property
    def healthy(self) -> bool: ...

    async def start(self) -> None: ...

    async def wait_stopped(self) -> None: ...

    async def close(self) -> None: ...


RuntimeFactory = Callable[[Database, ConsumerFence], BridgeRuntime]


class SupervisedRuntime:
    def __init__(
        self,
        db: Database,
        fence: ConsumerFence,
        resources: tuple[RuntimeResource, ...],
        workers: tuple[RuntimeWorker, ...],
        *,
        mode_publisher: RuntimeModePublisher | None = None,
        metrics: Callable[[], Mapping[str, int]] | None = None,
    ) -> None:
        names = [item.name for item in resources] + [item.name for item in workers]
        if not workers or any(not name for name in names) or len(set(names)) != len(names):
            raise ValueError("runtime_components_require_unique_names_and_workers")
        self.db, self.fence = db, fence
        self.resources, self.workers = resources, workers
        self.failure_code: str | None = None
        self.failure_detail: RuntimeFailure | None = None
        self._attempted: list[RuntimeResource] = []
        self._tasks: list[asyncio.Task[None]] = []
        self._monitor: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._close_task: asyncio.Task[None] | None = None
        self._cancel_requests: dict[asyncio.Task[None], asyncio.Task[None]] = {}
        self._used = False
        self._started = False
        self._closed = False
        self.mode_publisher = mode_publisher
        self.metrics = metrics

    def process_metrics(self) -> dict[str, int]:
        # Synchronous in-process counters for /metrics; never upstream or DB reads.
        return dict(self.metrics()) if self.metrics is not None else {}

    def runtime_mode_snapshot(self) -> RuntimeModeSnapshot | None:
        if not self.healthy or self.mode_publisher is None:
            return None
        return self.mode_publisher.snapshot()

    @property
    def healthy(self) -> bool:
        return (
            self._started
            and not self._stopped.is_set()
            and not self._closed
            and bool(self._tasks)
            and all(not task.done() for task in self._tasks)
        )

    async def start(self) -> None:
        if self._used or self._closed:
            raise RuntimeError("runtime_is_single_use")
        self._used = True
        try:
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
            for index, resource in enumerate(self.resources):
                # Include a partially opened resource in reverse-order cleanup.
                self._attempted.append(resource)
                try:
                    await resource.start()
                except BaseException as error:
                    self.record_failure("startup", resource_label(resource.name), index, error)
                    raise
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
            self._tasks = [
                asyncio.create_task(self._run(worker, index), name="jtoz:" + worker.name)
                for index, worker in enumerate(self.workers)
            ]
            await asyncio.sleep(0)
            if any(task.done() for task in self._tasks):
                raise RuntimeError("worker_stopped_during_startup")
            self._started = True
            self._monitor = asyncio.create_task(self._watch(), name="jtoz:runtime-monitor")
            if self.mode_publisher is not None:
                await self.mode_publisher.start(lambda: self.healthy)
        except asyncio.CancelledError as error:
            self.record_failure("startup", "runtime", -1, error)
            self.failure_code = "runtime_start_cancelled"
            await self.close()
            raise
        except Exception as error:
            self.record_failure("startup", "runtime", -1, error)
            self.failure_code = "runtime_start_failed"
            await self.close()
            raise RuntimeError("runtime_start_failed") from None

    def record_failure(
        self,
        stage: Literal["startup", "worker", "cleanup"],
        component: str,
        index: int,
        error: BaseException | None,
    ) -> None:
        if self.failure_detail is not None:
            return
        cancelled = isinstance(error, asyncio.CancelledError)
        detail = RuntimeFailure(
            stage,
            component
            if component
            in WORKER_LABELS
            | {
                "native",
                "zulip-client",
                "zulip-consumer",
                "file-returns",
                "workspace-inputs",
                "workspace-catalog",
                "native-graph-activation",
                "session-restoration",
                "runtime",
            }
            else "other",
            index,
            "cancelled" if cancelled else "returned" if error is None else "raised",
            error_label(error),
        )
        self.failure_detail = detail
        # All values are fixed labels/indices/codes. Never stringify unknown
        # exceptions, resources/tasks, upstream payloads, references or names.
        LOG.warning(
            "runtime_component_failed stage=%s component=%s index=%d kind=%s error_type=%s code=%s",
            detail.stage,
            detail.component,
            detail.index,
            detail.kind,
            detail.error_type,
            error_code(error),
        )

    async def _run(self, worker: RuntimeWorker, index: int) -> None:
        component = worker.name if worker.name in WORKER_LABELS else "other"
        try:
            await worker.run()
        except BaseException as error:
            if not self._closed and not self._stopped.is_set():
                self.record_failure("worker", component, index, error)
            raise
        else:
            if not self._closed and not self._stopped.is_set():
                self.record_failure("worker", component, index, None)

    async def _watch(self) -> None:
        await asyncio.wait(self._tasks, return_when=asyncio.FIRST_COMPLETED)
        self.failure_code = "runtime_worker_stopped"
        self._stopped.set()
        # Stop peers immediately; the lifecycle owner then joins and closes all
        # resources. Dispatcher/delivery preserve uncertain in-flight attempts.
        for task in self._tasks:
            self._request_cancel(task)

    def _request_cancel(self, task: asyncio.Task[None]) -> None:
        if not task.done() and task not in self._cancel_requests:
            self._cancel_requests[task] = asyncio.create_task(
                self._cancel_after_pending_cleanup(task), name="jtoz:worker-stop"
            )

    @staticmethod
    async def _cancel_after_pending_cleanup(task: asyncio.Task[None]) -> None:
        # cancelling() may describe a worker's own asyncio.timeout(), not a
        # supervisor stop. Do not interrupt its SQL/uncertainty cleanup, but
        # recheck after that temporary cancellation is consumed. A one-time
        # skip would let the worker resume forever while shutdown joins it.
        while not task.done() and task.cancelling():  # noqa: ASYNC110 - cancellation count has no event
            await asyncio.sleep(0.01)
        if not task.done():
            task.cancel()

    async def wait_stopped(self) -> None:
        await self._stopped.wait()

    async def close(self) -> None:
        # A cancelled web guard must not cancel cleanup midway and release the
        # lease while a shielded uncertainty receipt is still being committed.
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close(), name="jtoz:runtime-cleanup")
        await asyncio.shield(self._close_task)

    async def _close(self) -> None:
        self._closed = True
        self._stopped.set()
        if self.mode_publisher is not None:
            await self.mode_publisher.close()
        tasks = [*self._tasks]
        if self._monitor is not None:
            tasks.append(self._monitor)
        for task in tasks:
            # Monitor/close share one request per task. A pending internal
            # timeout is observed until it finishes or becomes cancellable.
            self._request_cancel(task)
        if self._cancel_requests:
            await asyncio.gather(*self._cancel_requests.values(), return_exceptions=True)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for index in reversed(range(len(self._attempted))):
            resource = self._attempted[index]
            try:
                await resource.close()
            except Exception as error:
                # Cleanup every resource without logging exception payloads
                # containing upstream content, credentials or private paths.
                self.failure_code = "runtime_cleanup_failed"
                self.record_failure("cleanup", resource_label(resource.name), index, error)
        self._attempted.clear()
