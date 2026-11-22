"""Ephemeral, best-effort typing for actual processing and original running work.

Typing never admits an Action or supplies authorization to another operation.
Only the supervised worker performs HTTP; the dispatch context cannot fail a turn.
"""

import asyncio
import logging
import math
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, request_lane
from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.adapters.zulip.scope import ZulipLocalWritePermit, ZulipSourceReader
from jt_oz_bridge.adapters.zulip.typing import ZulipTyping, typing_write
from jt_oz_bridge.domain.control import AudienceSnapshot, ExecutionState
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import BindingService, reference, topic_key
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.runtime import error_label
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Delivery, Grant, WorkerLease
from jt_oz_bridge.storage.transcript_models import TranscriptStream

LOG = logging.getLogger(__name__)
# A Root seen not running, with no Native arrival in its directory since, is
# snapshotted again only this often.
IDLE_RECHECK_SECONDS = 15.0
# A running Root not confirmed running again within this long is no longer
# reported by running(); one failed snapshot alone does not end its turn.
RUNNING_FRESH_SECONDS = 30.0


type Key = tuple[str, int, int, str]


def retry_delay(error: DeliveryRateLimited | ZulipReadUnavailable | TimeoutError) -> float:
    """Scheduling only; a later attempt must observe fresh original authority."""
    delay = 2.0
    if isinstance(error, DeliveryRateLimited):
        delay = max(1, min(3600, error.retry_after)) if math.isfinite(error.retry_after) else 60
        if isinstance(error, RequestBudgetDeferred) and error.refill_window is not None:
            delay = max(delay, error.refill_window)
    return max(2, delay)


def retry_kind(error: DeliveryRateLimited | ZulipReadUnavailable) -> str:
    if isinstance(error, RequestBudgetDeferred):
        return "local_budget"
    if isinstance(error, DeliveryRateLimited):
        return "upstream_rate"
    return "get_unavailable"


def key(binding: Binding) -> Key:
    return binding.id, binding.revision, binding.channel_id, binding.topic


class TypingStatus:
    def __init__(
        self, bindings: BindingService, fence: ConsumerFence, adapter: ZulipTyping, realm: str
    ) -> None:
        self.bindings, self.fence, self.adapter, self.realm = bindings, fence, adapter, realm
        self._control, self._audience = bindings.control, bindings.audience
        self._adapter = adapter
        self._processing: dict[Key, tuple[Binding, int]] = {}
        self._sent: dict[Key, tuple[Binding, float]] = {}
        self._retry_at: dict[Key, float] = {}
        self._wake = asyncio.Event()
        self._closed = False
        self._syncing = False
        self._source: ZulipSourceReader | None = None
        self._discovery: DiscoveryService | None = None
        self._routes: dict[str, tuple[HumanMessage, int]] = {}
        self._route_sent: dict[tuple[str, int, str], tuple[HumanMessage, float]] = {}
        self._route_failed: set[tuple[str, int, str]] = set()
        self._route_retry_at: dict[tuple[str, int, str], float] = {}
        self._processing_changed = True
        # Directory arrivals of a Root last seen not running, and when. With no
        # new arrival the snapshot is repeated only every IDLE_RECHECK_SECONDS;
        # starting work from the TUI is itself an arrival there.
        self.quiet_fence: Callable[[SessionRef], str | None] = lambda _ref: None
        self._idle_seen: dict[Key, tuple[str, float]] = {}
        # Work counted as running: (binding, since, last confirmed), wall clock.
        self._running: dict[Key, tuple[Binding, float, float]] = {}

    def running(self) -> dict[Key, tuple[Binding, float]]:
        """Bindings whose work typing counts as running now, and since when.

        Wall-clock times, for comparing with stored output times. Scheduling
        only: never output, Native or admission authority.
        """
        now = time.time()
        return {
            identity: (binding, since)
            for identity, (binding, since, seen) in self._running.items()
            if 0 <= now - seen < RUNNING_FRESH_SECONDS
        }

    @asynccontextmanager
    async def processing(self, binding: Binding) -> AsyncIterator[None]:
        """Real authorized Bridge work, never a queued/held Action state claim."""
        identity = key(binding)
        enabled = not self._closed and self.adapter.parameters is not None
        if enabled:
            previous = self._processing.get(identity)
            self._processing[identity] = (binding, previous[1] + 1 if previous else 1)
            self._processing_changed = True
            self._wake.set()
        try:
            yield
        finally:
            if enabled:
                previous = self._processing.get(identity)
                if previous is not None and previous[1] > 1:
                    self._processing[identity] = (previous[0], previous[1] - 1)
                else:
                    self._processing.pop(identity, None)
                self._processing_changed = True
                self._wake.set()

    def configure_routing(self, source: SourceReader, discovery: DiscoveryService | None) -> None:
        if (
            self._source is not None
            or not isinstance(source, ZulipSourceReader)
            or source.scope is not self.bindings.audience
            or source.scope.client is not self.adapter.client
            or discovery is not None
            and discovery.bindings is not self.bindings
        ):
            raise ValueError("typing_original_router_scope_required")
        self._source, self._discovery = source, discovery

    @staticmethod
    def _topic(source: HumanMessage) -> tuple[str, int, str]:
        return source.realm_id, source.channel_id, source.topic

    @asynccontextmanager
    async def routing(self, source: HumanMessage) -> AsyncIterator[None]:
        """Activity proposal only. The worker independently re-observes Source/ACL.

        No remote call, Native proof or awaited cosmetic operation on the route.
        The indicator describes Bridge work, never Native admission/RUNNING.
        """
        identity = digest(source.model_dump(mode="json"))
        enabled = (
            not self._closed
            and self._source is not None
            and self.adapter.parameters is not None
            and source.realm_id == self.realm
            and not source.is_bot
            and not source.deleted
            and source.revision == 0
            and (identity in self._routes or len(self._routes) < 100)
        )
        if enabled:
            previous = self._routes.get(identity)
            self._routes[identity] = (source, previous[1] + 1 if previous else 1)
            self._wake.set()
        try:
            yield
        finally:
            if enabled:
                previous = self._routes.get(identity)
                if previous is not None and previous[1] > 1:
                    self._routes[identity] = (previous[0], previous[1] - 1)
                else:
                    self._routes.pop(identity, None)
                self._wake.set()

    async def _route_scope(
        self, session: AsyncSession, source: HumanMessage, audience: AudienceSnapshot
    ) -> tuple[str, int] | tuple[None, str]:
        if (
            not audience.private
            or audience.untrusted_bot_ids
            or source.author_id not in audience.user_ids
            or (audience.realm_id, audience.channel_id, audience.canonical_topic)
            != self._topic(source)
        ):
            raise AccessDenied("typing_route_private_human_audience_required")
        binding = await session.scalar(
            select(Binding).where(
                Binding.topic_key == topic_key(*self._topic(source)),
                Binding.realm_id == source.realm_id,
                Binding.state == "active",
            )
        )
        if binding is not None:
            locked = await lock_output_scope(self.bindings, session, binding)
            if (
                locked.channel_id,
                locked.topic,
                locked.audience_revision,
                set(locked.audience_user_ids),
            ) != (source.channel_id, source.topic, audience.revision, set(audience.user_ids)):
                raise Conflict("typing_route_bound_audience_changed")
            # VIEW for read-only processing is not Native OPERATE or admission.
            roles = await session.scalars(
                select(Grant.role).where(
                    Grant.realm_id == source.realm_id,
                    Grant.project_id == locked.project_id,
                    Grant.user_id == source.author_id,
                    Grant.active.is_(True),
                )
            )
            if not any(Permission.VIEW in ROLES.get(role, set()) for role in roles):
                raise AccessDenied("typing_route_actor_revoked")
            return (locked.id, locked.revision)
        if self._discovery is None:
            raise AccessDenied("typing_unbound_discovery_not_configured")
        # Same deny-only complete-audience project query as discovery; no catalog
        # or Native call and no returned project data becomes router authority.
        project = await session.scalar(
            self._discovery.candidate_projects(source, audience)
            .order_by(EnrolledProject.id)
            .limit(1)
        )
        if project is None:
            raise AccessDenied("typing_unbound_audience_has_no_visible_project")
        enrolled = await session.scalar(
            select(EnrolledProject).where(EnrolledProject.id == project).with_for_update()
        )
        backend = (
            await session.scalar(
                select(EnrolledBackend)
                .where(EnrolledBackend.id == enrolled.backend_id)
                .with_for_update()
            )
            if enrolled
            else None
        )
        grants = list(
            await session.scalars(
                select(Grant)
                .where(
                    Grant.realm_id == source.realm_id,
                    Grant.project_id == project,
                    Grant.user_id.in_(audience.user_ids),
                    Grant.active.is_(True),
                )
                .with_for_update()
            )
        )
        if (
            enrolled is None
            or backend is None
            or not enrolled.enabled
            or not backend.enabled
            or not backend.verified
            or enrolled.realm_id != source.realm_id
            or {g.user_id for g in grants if Permission.VIEW in ROLES.get(g.role, set())}
            != set(audience.user_ids)
        ):
            raise AccessDenied("typing_unbound_project_or_grants_changed")
        return (None, project)

    async def _send_route(self, source: HumanMessage, operation: str) -> bool:
        phase, attempted = "source_observation", False
        try:
            async with asyncio.timeout(2):
                with request_lane("normal"):
                    reader, discovery = self._source, self._discovery
                    parameters = self.adapter.parameters
                    if reader is None or parameters is None:
                        return False
                    scope, started = reader.scope, time.monotonic()
                    identity = digest(source.model_dump(mode="json"))

                    async def observed(
                        audience: AudienceSnapshot,
                    ) -> tuple[
                        tuple[str, int] | tuple[None, str], ZulipLocalWritePermit, AudienceSnapshot
                    ]:
                        async with self.bindings.db.sessions() as session:
                            selected = await self._route_scope(session, source, audience)
                        return (
                            selected,
                            scope.local_write_permit(reader, source, audience),
                            audience,
                        )

                    observation = await scope.observe_sources(reader, (source,), read_only=observed)
                    closed = scope.consume_observation(observation, reader, (source,))
                    selected, permit, issued_audience = closed.value
                    phase = "sql_scope"
                    async with self.bindings.db.sessions.begin() as session:
                        if operation == "start":
                            await self.fence.lock(session)
                        if await self._route_scope(session, source, closed.audience) != selected:
                            raise Conflict("typing_route_scope_changed_after_source")
                        lease = await session.get(WorkerLease, "consumer")
                        expires = lease.expires_at if lease else 0

                        def current() -> bool:
                            try:
                                scope.require_write_permit(permit, reader, source, issued_audience)
                                return (
                                    time.monotonic() - started < 5
                                    and self._source is reader
                                    and self._discovery is discovery
                                    and self.adapter is self._adapter
                                    and self.adapter.parameters is parameters
                                    and self.bindings.audience is self._audience
                                    and self.bindings.control is self._control
                                    and (
                                        operation == "stop"
                                        or (
                                            not self._closed
                                            and identity in self._routes
                                            and self._routes[identity][0] == source
                                            and lease is not None
                                            and lease.holder == self.fence.holder
                                            and lease.fencing == self.fence.fencing
                                            and expires > time.time()
                                        )
                                    )
                                )
                            except Exception:
                                return False

                        if not current():
                            return False
                        with typing_write(current):
                            phase, attempted = "typing_http", True
                            await self.adapter.send(
                                source.channel_id,
                                source.topic,
                                "start" if operation == "start" else "stop",
                            )
            return True
        except asyncio.CancelledError:
            raise
        except TimeoutError as error:
            if operation == "start":
                if attempted:
                    # Only the ephemeral indicator may have been sent. Clear it
                    # once under a new Source/ACL observation before scheduling
                    # a later fresh indicator; no Action/Native input is retried.
                    await self._send_route(source, "stop")
                self._route_retry_at[self._topic(source)] = time.monotonic() + retry_delay(error)
            LOG.warning(
                "typing_send_deferred scope=route kind=attempt_timeout phase=%s error_type=TimeoutError",
                phase,
            )
            return False
        except (DeliveryRateLimited, ZulipReadUnavailable) as error:
            if operation == "start":
                self._route_retry_at[self._topic(source)] = time.monotonic() + retry_delay(error)
            LOG.warning("typing_send_deferred scope=route kind=%s", retry_kind(error))
            return False
        except Exception as error:
            LOG.warning(
                "typing_send_refused scope=route kind=uncertain_or_denied phase=%s error_type=%s",
                phase,
                error_label(error),
            )
            return False  # Optional cosmetic failure never reaches the router.

    async def _sync_routes(self, native_topics: set[tuple[str, int, str]] | None = None) -> None:
        native_topics = native_topics or {
            (binding.realm_id, binding.channel_id, binding.topic)
            for binding, _ in self._sent.values()
        }
        try:
            async with self.bindings.db.sessions() as session:
                lease = await session.get(WorkerLease, "consumer")
            live = (
                lease is not None
                and lease.holder == self.fence.holder
                and lease.fencing == self.fence.fencing
                and lease.expires_at > time.time()
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            live = False  # Optional activity cannot turn a read failure into authority.
        desired = (
            {self._topic(source): source for source, _ in self._routes.values()} if live else {}
        )
        for topic in tuple(self._route_sent):
            if topic not in desired or topic in native_topics:
                previous = self._route_sent.pop(topic, None)
                if previous is None:
                    continue
                source, _ = previous
                if topic not in native_topics:
                    await self._send_route(source, "stop")
        self._route_failed.intersection_update(desired)
        self._route_retry_at = {k: v for k, v in self._route_retry_at.items() if k in desired}
        parameters = self.adapter.parameters
        if parameters is None:
            return
        for topic, source in desired.items():
            previous = self._route_sent.get(topic)
            if (
                topic in native_topics
                or topic in self._route_failed
                or time.monotonic() < self._route_retry_at.get(topic, 0)
                or previous is not None
                and time.monotonic() - previous[1] < parameters.refresh
            ):
                continue
            budget = self.adapter.client.budget
            if budget is not None and budget.normal_headroom < (40 if previous else 64):
                continue
            self._route_retry_at.pop(topic, None)
            self._route_sent[topic] = (source, time.monotonic())
            if not await self._send_route(source, "start"):
                self._route_sent.pop(topic, None)
                if topic in self._route_retry_at:
                    if previous is not None:
                        # A deferred refresh does not erase our responsibility
                        # to clear the earlier indicator when its work ends.
                        self._route_sent[topic] = previous
                else:
                    self._route_failed.add(topic)
                    await self._send_route(source, "stop")

    async def _send(self, binding: Binding, operation: str) -> bool:
        """One attempt, normal budget lane, bounded HTTP and fresh output scope."""
        phase, attempted = "preflight", False
        try:
            async with asyncio.timeout(2):
                budget = self.adapter.client.budget
                if (
                    operation == "stop"
                    and budget is not None
                    and budget.normal_headroom < 64
                    and await self._core_output_pending(binding)
                ):
                    # Optional cleanup cannot displace original output still
                    # to be captured/sent. No POST was attempted; original
                    # server expiry remains the bounded cleanup fallback.
                    return False
                with request_lane("normal"):
                    parameters = self.adapter.parameters
                    if parameters is None:
                        return False
                    # Resolve current channel/topic audience before locking SQL.
                    phase = "audience"
                    await self.bindings.audience_for_output(binding)
                    started = time.monotonic()
                    processing = self._processing.get(key(binding))
                    if operation == "start" and processing is None:
                        phase = "native_observation"
                        snapshot = await self.bindings.control.snapshot(reference(binding))
                        if (
                            snapshot.reference != reference(binding)
                            or not snapshot.reconciled
                            or snapshot.state != ExecutionState.RUNNING
                        ):
                            return False
                    phase = "sql_scope"
                    async with self.bindings.db.sessions.begin() as session:
                        if operation == "start":
                            await self.fence.lock(session)
                        locked = await lock_output_scope(self.bindings, session, binding)
                        if locked.owner_id != binding.owner_id:
                            raise AccessDenied("typing_binding_owner_changed")
                        roles = list(
                            await session.scalars(
                                select(Grant.role).where(
                                    Grant.realm_id == binding.realm_id,
                                    Grant.project_id == binding.project_id,
                                    Grant.user_id == binding.owner_id,
                                    Grant.active.is_(True),
                                )
                            )
                        )
                        if not any(Permission.OPERATE in ROLES.get(role, set()) for role in roles):
                            raise AccessDenied("typing_operator_revoked")
                        lease = await session.get(WorkerLease, "consumer")
                        # Clearing our already-sent indicator is allowed after lease
                        # loss, but still requires current identity/audience/scope.
                        expires = lease.expires_at if lease is not None else 0

                        def current() -> bool:
                            return (
                                time.monotonic() - started < 5
                                and self.adapter is self._adapter
                                and self.adapter.parameters is parameters
                                and self.bindings.control is self._control
                                and self.bindings.audience is self._audience
                                and key(binding) == expected
                                and (
                                    operation == "stop"
                                    or processing is None
                                    or key(binding) in self._processing
                                )
                                and (
                                    operation == "stop"
                                    or (
                                        not self._closed
                                        and lease is not None
                                        and lease.holder == self.fence.holder
                                        and lease.fencing == self.fence.fencing
                                        and expires > time.time()
                                    )
                                )
                            )

                        expected = key(binding)
                        with typing_write(current):
                            phase, attempted = "typing_http", True
                            await self.adapter.send(
                                binding.channel_id,
                                binding.topic,
                                "start" if operation == "start" else "stop",
                            )
            return True
        except asyncio.CancelledError:
            raise
        except TimeoutError as error:
            if operation == "start":
                if attempted:
                    await self._send(binding, "stop")
                self._retry_at[key(binding)] = time.monotonic() + retry_delay(error)
            LOG.warning(
                "typing_send_deferred scope=native kind=attempt_timeout phase=%s error_type=TimeoutError",
                phase,
            )
            return False
        except (DeliveryRateLimited, ZulipReadUnavailable) as error:
            if operation == "start":
                self._retry_at[key(binding)] = time.monotonic() + retry_delay(error)
            LOG.warning("typing_send_deferred scope=native kind=%s", retry_kind(error))
            return False
        except Exception as error:
            LOG.warning(
                "typing_send_refused scope=native kind=uncertain_or_denied phase=%s error_type=%s",
                phase,
                error_label(error),
            )
            # No raw exception/body/metadata output and no retry of an uncertain
            # POST. Server expiry is the final cleanup if stop cannot be sent.
            return False

    async def _core_output_pending(self, binding: Binding) -> bool:
        """SQL-only scheduling hint; never supplies output/Native authority."""
        async with self.bindings.db.sessions() as session:
            if await session.scalar(
                select(TranscriptStream.key)
                .where(
                    TranscriptStream.binding_id == binding.id,
                    TranscriptStream.binding_revision == binding.revision,
                )
                .limit(1)
            ):
                # A mirrored Root may become idle just before the independent
                # collector captures its final version, including TUI work.
                return True
            if await session.scalar(
                select(Action.id)
                .where(
                    Action.binding_id == binding.id,
                    Action.binding_revision == binding.revision,
                    Action.state.in_(["queued", "dispatching", "admitted", "running"]),
                )
                .limit(1)
            ):
                return True
            return bool(
                await session.scalar(
                    select(Delivery.id)
                    .where(
                        Delivery.binding_id == binding.id,
                        Delivery.binding_revision == binding.revision,
                        Delivery.state.in_(["pending", "sending"]),
                    )
                    .limit(1)
                )
            )

    async def sync_once(self) -> None:
        if self._closed or self._syncing or self.adapter.parameters is None:
            return
        self._syncing = True
        try:
            async with self.bindings.db.sessions() as session:
                bindings = list(
                    await session.scalars(
                        select(Binding)
                        .where(Binding.realm_id == self.realm, Binding.state == "active")
                        .order_by(Binding.id)
                        .limit(100)
                    )
                )
            desired: dict[Key, Binding] = {}
            native_cleanup: list[Binding] = []
            route_topics = {self._topic(source) for source, _ in self._routes.values()}
            listed = {key(binding) for binding in bindings}
            for identity in tuple(self._running):
                if identity not in listed:
                    del self._running[identity]
            for binding in bindings:
                identity = key(binding)
                if (
                    binding.realm_id,
                    binding.channel_id,
                    binding.topic,
                ) in route_topics and identity not in self._sent:
                    continue  # New Source work adds no Native qualification.
                # An already-sent original Native indicator retains its normal
                # independent poll; a Source proposal cannot replace its authority.
                # Explicit processing context is refcounted. Otherwise only a
                # reconciled original RUNNING snapshot, including TUI work, counts.
                processing = self._processing.get(identity)
                busy = known = processing is not None
                quiet = None if busy else self.quiet_fence(reference(binding))
                seen = self._idle_seen.pop(identity, None)
                if (
                    quiet is not None
                    and seen is not None
                    and seen[0] == quiet
                    and 0 <= time.monotonic() - seen[1] < IDLE_RECHECK_SECONDS
                ):
                    self._idle_seen[identity] = seen
                    continue  # Still not running: nothing arrived to change that.
                if not busy:
                    try:
                        snapshot = await self.bindings.control.snapshot(reference(binding))
                        busy = (
                            snapshot.reference == reference(binding)
                            and snapshot.reconciled
                            and snapshot.state == ExecutionState.RUNNING
                        )
                        known = True
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        busy = False
                    if not busy and quiet is not None and identity not in self._sent:
                        self._idle_seen[identity] = (quiet, time.monotonic())
                if busy:
                    desired[identity] = binding
                    now, previous_run = time.time(), self._running.get(identity)
                    self._running[identity] = (
                        binding,
                        previous_run[1] if previous_run is not None else now,
                        now,
                    )
                elif known:
                    self._running.pop(identity, None)  # Unknown is not idle.
            for identity in tuple(self._sent):
                if identity not in desired:
                    binding, _ = self._sent.pop(identity)
                    if (binding.realm_id, binding.channel_id, binding.topic) not in route_topics:
                        await self._send(binding, "stop")
                    else:
                        native_cleanup.append(binding)
            self._retry_at = {k: v for k, v in self._retry_at.items() if k in desired}
            parameters = self.adapter.parameters
            if parameters is None:
                return
            for identity, binding in desired.items():
                previous = self._sent.get(identity)
                if (
                    time.monotonic() < self._retry_at.get(identity, 0)
                    or previous is not None
                    and time.monotonic() - previous[1] < parameters.refresh
                ):
                    continue
                budget = self.adapter.client.budget
                if budget is not None:
                    # One current scope costs12+2*Human-members requests on
                    # this protocol. Leave four such scopes plus final POST
                    # for original result/mirror/publication/delivery, after
                    # this refresh's scope+POST. This is scheduling only;
                    # no cached audience substitutes for any actual check.
                    reply_headroom = 5 * (12 + 2 * len(binding.audience_user_ids)) + 2
                    if (
                        budget.normal_headroom < (40 if previous else 64)
                        or budget.capacity - budget.retained_requests < reply_headroom
                    ):
                        # Scheduling only: optional typing must leave normal
                        # headroom for core work. Confirmed indicators refresh
                        # with40 normal requests available; new starts retain64.
                        # The actual admission and final/control reserves do not
                        # change. No ACL is cached and this
                        # unsent activity may be reconsidered after refill.
                        continue
                # Record before HTTP: an uncertain start still gets one stop.
                self._retry_at.pop(identity, None)
                self._sent[identity] = (binding, time.monotonic())
                if not await self._send(binding, "start"):
                    self._sent.pop(identity, None)
                    if identity in self._retry_at:
                        if previous is not None:
                            self._sent[identity] = previous
                    else:
                        # Typing is the only progress signal, so one failed attempt
                        # must not silence the rest of the turn. Try at the next refresh.
                        self._retry_at[identity] = time.monotonic() + parameters.refresh
                        await self._send(binding, "stop")
            await self._sync_routes({(b.realm_id, b.channel_id, b.topic) for b in desired.values()})
            for binding in native_cleanup:
                if (binding.realm_id, binding.channel_id, binding.topic) not in self._route_sent:
                    await self._send(binding, "stop")
        finally:
            self._syncing = False

    async def run(self) -> None:
        try:
            next_native = 0.0
            while not self._closed:
                self._wake.clear()
                if self._processing_changed or time.monotonic() >= next_native:
                    self._processing_changed = False
                    await self.sync_once()
                    parameters = self.adapter.parameters
                    delay = min(2.0, parameters.refresh) if parameters else 2.0
                    next_native = time.monotonic() + delay
                else:
                    # Route wakeups must not add unrelated original Native GETs.
                    await self._sync_routes()
                try:
                    await asyncio.wait_for(
                        self._wake.wait(), max(0.001, next_native - time.monotonic())
                    )
                except TimeoutError:
                    pass
        finally:
            await self.close()

    async def close(self) -> None:
        self._closed = True
        self._retry_at.clear()
        self._route_retry_at.clear()
        self._processing.clear()
        self._routes.clear()
        self._running.clear()
        self._wake.set()
        sent, self._sent = self._sent, {}
        # Independent bounded best-effort stops; no persistent recovery replay.
        native_topics = {
            (binding.realm_id, binding.channel_id, binding.topic) for binding, _ in sent.values()
        }
        routed, self._route_sent = self._route_sent, {}
        await asyncio.gather(
            *(self._send(binding, "stop") for binding, _ in sent.values()),
            *(
                self._send_route(source, "stop")
                for topic, (source, _) in routed.items()
                if topic not in native_topics
            ),
        )
