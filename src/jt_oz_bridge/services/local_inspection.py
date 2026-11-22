"""Read-only Native observations joined to safe Bridge metadata/counts."""

import asyncio
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal

from sqlalchemy import func, select

from jt_oz_bridge.adapters.opencode.inspection import V2SessionInspection
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.inspection import (
    InspectionBinding,
    InspectionClock,
    InspectionCounts,
    InspectionCoverage,
    InspectionIssue,
    InspectionProtocolQuery,
    InspectionProtocolResponse,
    InspectionQuery,
    InspectionQueryV2,
    InspectionResponse,
    InspectionResponseV2,
    InspectionRuntimeMode,
    InspectionSession,
    InspectionSessionV2,
    bounded_inspection_issues,
    fresh_inspection_response,
    unknown_inspection_row,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.runtime_readiness import (
    ConsumerLeaseObservation,
    RuntimeModeSnapshot,
    lease_fingerprint,
    scope_key,
)
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.models import Action, Delivery, WorkerLease

BUSY = frozenset(
    {
        ExecutionState.QUEUED,
        ExecutionState.RUNNING,
        ExecutionState.WAITING_PERMISSION,
        ExecutionState.WAITING_INPUT,
        ExecutionState.INTERRUPTING,
    }
)


@dataclass(frozen=True)
class InspectionRuntimeScope:
    backend_id: str
    workspace_root: str
    realm_id: str
    allowed_channels: frozenset[int]

    @staticmethod
    def canonical(value: str) -> bool:
        return (
            isinstance(value, str)
            and value.startswith("/")
            and not value.startswith("//")
            and str(PurePosixPath(value)) == value
            and not any(part in {".", ".."} for part in value.split("/"))
        )

    def contains(self, backend_id: str, directory: str) -> bool:
        # Lexical configured scope only, not a physical/symlink or mutation proof.
        return (
            self.canonical(self.workspace_root)
            and self.canonical(directory)
            and backend_id == self.backend_id
            and PurePosixPath(directory).is_relative_to(PurePosixPath(self.workspace_root))
        )


class LocalSessionInspector:
    def __init__(
        self,
        db: Database,
        backends: Mapping[str, V2SessionInspection],
        projects: Mapping[str, tuple[str, str, str]],
        enrolled: frozenset[tuple[str, str, str, str]],
        realm_origins: Mapping[str, str],
        bridge_ready: Callable[[], Awaitable[bool]],
        *,
        runtime_references: frozenset[SessionRef] = frozenset(),
        runtime_scopes: Mapping[str, InspectionRuntimeScope] | None = None,
        runtime_snapshot: Callable[[ConsumerLeaseObservation, bool], Awaitable[RuntimeModeSnapshot]]
        | None = None,
    ) -> None:
        if (
            not backends
            or len(backends) > 20
            or any(key != b.backend_id for key, b in backends.items())
        ):
            raise ValueError("explicit_observer_backend_scope_required")
        self.db, self.backends, self.projects = (
            db,
            MappingProxyType(dict(backends)),
            MappingProxyType(dict(projects)),
        )
        self.enrolled, self.realm_origins, self.bridge_ready = (
            enrolled,
            MappingProxyType(dict(realm_origins)),
            bridge_ready,
        )
        self.runtime_references = runtime_references
        self.runtime_scopes = MappingProxyType(dict(runtime_scopes or {}))
        self.runtime_snapshot = runtime_snapshot
        self._gate = asyncio.Lock()

    async def local_metadata(
        self, rows: list[InspectionSession]
    ) -> tuple[list[InspectionSession], bool]:
        async with self.db.sessions() as session:
            lease = await session.get(WorkerLease, "consumer")
            current = lease is not None and lease.expires_at > time.time()
            if not rows:
                return rows, current
            bindings = list(
                (
                    await session.scalars(
                        select(Binding)
                        .where(
                            Binding.backend_id.in_(self.backends),
                            Binding.session_id.in_([r.session_id for r in rows]),
                        )
                        .order_by(Binding.id)
                        .limit(1001)
                    )
                ).all()
            )
            if len(bindings) > 1000:
                raise ValueError("inspection_binding_capacity")
            projects = {
                p.id: p
                for p in (
                    await session.scalars(
                        select(EnrolledProject).where(
                            EnrolledProject.id.in_({b.project_id for b in bindings})
                        )
                    )
                ).all()
            }
            backends = {
                b.id: b
                for b in (
                    await session.scalars(
                        select(EnrolledBackend).where(EnrolledBackend.id.in_(self.backends))
                    )
                ).all()
            }
            ids = [b.id for b in bindings]
            actions = (
                (
                    await session.execute(
                        select(Action.binding_id, Action.state, func.count())
                        .where(Action.binding_id.in_(ids))
                        .group_by(Action.binding_id, Action.state)
                    )
                ).all()
                if ids
                else []
            )
            deliveries = (
                (
                    await session.execute(
                        select(Delivery.binding_id, Delivery.state, func.count())
                        .where(Delivery.binding_id.in_(ids))
                        .group_by(Delivery.binding_id, Delivery.state)
                    )
                ).all()
                if ids
                else []
            )
        counts: dict[str, dict[str, int]] = {}
        for identity, state, count in actions:
            key = (
                state
                if state in {"queued", "held", "ambiguous"}
                else "active"
                if state in {"dispatching", "admitted", "running"}
                else "failed"
                if state in {"failed", "rejected"}
                else None
            )
            if key is not None:
                counts.setdefault(identity, {})[key] = counts.get(identity, {}).get(key, 0) + count
        for identity, state, count in deliveries:
            key = (
                "pending_delivery"
                if state in {"pending", "held", "sending", "ambiguous"}
                else "failed_delivery"
                if state in {"failed", "rejected"}
                else None
            )
            if key is not None:
                counts.setdefault(identity, {})[key] = counts.get(identity, {}).get(key, 0) + count
        result = []
        for row in rows:
            associated = []
            for binding in bindings:
                if (
                    binding.backend_id,
                    binding.backend_identity,
                    binding.session_id,
                    binding.canonical_directory,
                ) != (row.backend_id, row.backend_identity, row.session_id, row.directory):
                    continue
                project, backend = (
                    projects.get(binding.project_id),
                    backends.get(binding.backend_id),
                )
                expected = self.projects.get(binding.project_id)
                valid = bool(
                    project
                    and project.enabled
                    and backend
                    and backend.enabled
                    and backend.verified
                    and backend.identity == row.backend_identity
                    and backend.contract_hash == self.backends[row.backend_id].contract_sha256
                    and project.backend_id == row.backend_id
                    and project.realm_id == binding.realm_id
                    and project.canonical_directory == row.directory
                    and expected == (row.backend_id, row.native_project_id, row.directory)
                )
                binding_state: Literal["active_record", "creating", "stale", "inactive"] = (
                    "active_record"
                    if binding.state == "active" and valid
                    else "creating"
                    if binding.state == "creating" and valid
                    else "inactive"
                    if binding.state not in {"active", "creating"}
                    else "stale"
                )
                origin = self.realm_origins.get(binding.realm_id)
                link = (
                    (
                        origin
                        + "/#narrow/channel/"
                        + str(binding.channel_id)
                        + "/near/"
                        + str(binding.anchor_message_id)
                    )
                    if origin and binding.anchor_message_id and binding.anchor_message_id > 0
                    else None
                )
                associated.append(
                    InspectionBinding(
                        binding_id=binding.id,
                        project_id=binding.project_id,
                        realm_id=binding.realm_id,
                        channel_id=binding.channel_id,
                        topic=binding.topic,
                        revision=binding.revision,
                        state=binding_state,
                        paused=binding.dispatch_paused,
                        conversation_url=link,
                        counts=InspectionCounts(**counts.get(binding.id, {})),
                    )
                )
            result.append(
                row.model_copy(
                    update={
                        "bindings": tuple(associated),
                        "binding_coverage": "complete",
                        "execution_registration": "enrolled"
                        if (row.backend_id, row.backend_identity, row.session_id, row.directory)
                        in self.enrolled
                        else "catalog_only",
                    }
                )
            )
        return result, current

    async def query(self, query: InspectionProtocolQuery) -> InspectionProtocolResponse:
        # Concurrent local processes share one bounded observer workload. A
        # socket deadline bounds waiting clients and cancels abandoned reads.
        async with self._gate:
            started = InspectionClock.capture(time.time, time.monotonic)
            try:
                initial_lease = await asyncio.wait_for(self._lease_identity(), 1)
            except Exception:
                initial_lease = None
            if isinstance(query, InspectionQueryV2):
                legacy = InspectionQuery.model_validate(query.model_dump(exclude={"version"}))
                response: InspectionProtocolResponse = await self._runtime_modes(
                    await self._query(legacy)
                )
            else:
                response = await self._query(query)
            return await self._finish(response, started, initial_lease)

    async def _lease_identity(self) -> tuple[str, int, float] | None:
        async with self.db.sessions() as session:
            lease = await session.get(WorkerLease, "consumer")
            return (lease.holder, lease.fencing, float(lease.expires_at)) if lease else None

    async def _finish(
        self,
        response: InspectionProtocolResponse,
        started: InspectionClock,
        initial_lease: tuple[str, int, float] | None,
    ) -> InspectionProtocolResponse:
        """Close each used owner/lease after all Native, SQL and v2 awaits.

        At most one owner read per configured backend (max20), concurrency2,
        under one two-second budget. Completed good backends survive timeout.
        """
        owners: dict[str, tuple[str, float]] = {}
        final_lease: tuple[str, int, float] | None = None
        health: tuple[bool, float] | None = None
        semaphore = asyncio.Semaphore(2)
        needed = {
            row.backend_id
            for row in response.rows
            if row.state != ExecutionState.UNKNOWN or row.owner_epoch is not None
        } | {item.backend_id for item in response.coverage if item.owner_epoch is not None}

        async def owner(backend_id: str) -> None:
            try:
                async with semaphore:
                    value = await self.backends[backend_id].original_owner()
                    owners[backend_id] = (value.owner_epoch, value.observed_at)
            except asyncio.CancelledError:
                raise
            except Exception:
                return

        async def lease() -> None:
            nonlocal final_lease
            try:
                final_lease = await self._lease_identity()
            except asyncio.CancelledError:
                raise
            except Exception:
                return

        async def ready() -> None:
            nonlocal health
            try:
                healthy = await self.bridge_ready() is True
                health = (healthy, time.time())
            except asyncio.CancelledError:
                raise
            except Exception:
                return

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    lease(), ready(), *(owner(key) for key in sorted(needed & self.backends.keys()))
                ),
                2,
            )
        except TimeoutError:
            pass
        ended = InspectionClock.capture(time.time, time.monotonic)
        uncertainty = ended.uncertainty_since(started)
        current_lease = bool(
            initial_lease is not None
            and final_lease is not None
            and initial_lease[:2] == final_lease[:2]
            and math.isfinite(initial_lease[2])
            and math.isfinite(final_lease[2])
            and ended.after + uncertainty < min(initial_lease[2], final_lease[2])
        )
        healthy = bool(health is not None and health[0] and ended.fresh(health[1], uncertainty))

        def current_owner(backend_id: str, epoch: str | None) -> bool:
            return (
                backend_id in owners
                and epoch == owners[backend_id][0]
                and ended.fresh(owners[backend_id][1], uncertainty)
            )

        bad_backends = {
            row.backend_id
            for row in response.rows
            if (row.state != ExecutionState.UNKNOWN or row.owner_epoch is not None)
            and not current_owner(row.backend_id, row.owner_epoch)
        } | {
            item.backend_id
            for item in response.coverage
            if item.owner_epoch is not None and not current_owner(item.backend_id, item.owner_epoch)
        }
        additions: list[InspectionIssue] = []
        if bad_backends:
            additions.append(InspectionIssue(code="stale_observation"))
        if (not current_lease or not healthy) and response.status != "error":
            additions.append(InspectionIssue(code="bridge_unavailable"))
        rows: list[InspectionSession] = []
        for row in response.rows:
            owner_changed = (
                row.state != ExecutionState.UNKNOWN or row.owner_epoch is not None
            ) and not current_owner(row.backend_id, row.owner_epoch)
            if owner_changed:
                row = unknown_inspection_row(row)
            if isinstance(row, InspectionSessionV2) and (not current_lease or owner_changed):
                row = row.model_copy(
                    update={
                        "runtime_mode": InspectionRuntimeMode(
                            mode="unavailable", reason="diagnostics-unavailable"
                        )
                    }
                )
                additions.append(InspectionIssue(code="runtime_modes_unavailable"))
            rows.append(row)
        issues = bounded_inspection_issues(response.issues, additions)
        result = response.model_copy(
            update={
                # This is the closing summary time, never a refreshed row fact.
                "observed_at": ended.before
                if math.isfinite(ended.before) and ended.before >= 0
                else response.observed_at,
                "rows": tuple(rows),
                "coverage": tuple(
                    item.model_copy(
                        update={
                            "complete": False,
                            "reason": "state_unknown",
                            "owner_epoch": None,
                            "native_pid": None,
                        }
                    )
                    if item.backend_id in bad_backends
                    else item
                    for item in response.coverage
                ),
                "bridge_ready": healthy and current_lease,
                "bridge_lease_current": response.bridge_lease_current and current_lease,
                "status": "error"
                if response.status == "error"
                else "partial"
                if response.status == "partial" or issues
                else "ok",
                "issues": issues,
            }
        )
        return fresh_inspection_response(
            result, started, InspectionClock.capture(time.time, time.monotonic)
        )

    def _runtime_reference(self, row: InspectionSession) -> SessionRef | None:
        # Neither a catalog title nor a shared directory identifies the Bridge
        # project. Static full references and already-qualified Binding joins only.
        references = {
            ref
            for ref in self.runtime_references
            if (
                ref.backend_id,
                ref.backend_identity,
                ref.upstream_session_id,
                ref.canonical_directory,
            )
            == (row.backend_id, row.backend_identity, row.session_id, row.directory)
            and self.projects.get(ref.project_id)
            == (row.backend_id, row.native_project_id, row.directory)
            and ref.project_id in self.runtime_scopes
            and self.runtime_scopes[ref.project_id].contains(row.backend_id, row.directory)
        }
        for binding in row.bindings:
            if (
                binding.state == "active_record"
                and row.binding_coverage == "complete"
                and self.projects.get(binding.project_id)
                == (row.backend_id, row.native_project_id, row.directory)
                and binding.project_id in self.runtime_scopes
                and self.runtime_scopes[binding.project_id].contains(row.backend_id, row.directory)
                and self.runtime_scopes[binding.project_id].realm_id == binding.realm_id
                and binding.channel_id in self.runtime_scopes[binding.project_id].allowed_channels
            ):
                references.add(
                    SessionRef(
                        backend_id=row.backend_id,
                        backend_identity=row.backend_identity,
                        upstream_session_id=row.session_id,
                        project_id=binding.project_id,
                        canonical_directory=row.directory,
                    )
                )
        return next(iter(references)) if len(references) == 1 else None

    def _runtime_config_unavailable(self, row: InspectionSession) -> bool:
        candidates = {
            ref.project_id
            for ref in self.runtime_references
            if (
                ref.backend_id,
                ref.backend_identity,
                ref.upstream_session_id,
                ref.canonical_directory,
            )
            == (row.backend_id, row.backend_identity, row.session_id, row.directory)
        } | {
            binding.project_id
            for binding in row.bindings
            if binding.state == "active_record" and row.binding_coverage == "complete"
        }
        return any(
            project_id not in self.runtime_scopes
            or not self.runtime_scopes[project_id].canonical(
                self.runtime_scopes[project_id].workspace_root
            )
            for project_id in candidates
        )

    async def _runtime_modes(self, response: InspectionResponse) -> InspectionResponseV2:
        snapshot = None
        observation = None
        effective_expiry = 0.0
        healthy = current = False
        try:
            # This read is independent of the publisher's snapshot and obtains no
            # payload key or consumer fence. Observed_at is after SQL completion.
            async with self.db.sessions() as session:
                lease = (
                    await session.execute(
                        select(
                            WorkerLease.holder, WorkerLease.fencing, WorkerLease.expires_at
                        ).where(WorkerLease.role == "consumer")
                    )
                ).one_or_none()
            if lease is None:
                raise ValueError("diagnostic_lease_unavailable")
            observation = ConsumerLeaseObservation(
                lease_fingerprint=lease_fingerprint(lease.holder, lease.fencing),
                observed_at=time.time(),
                expires_at=float(lease.expires_at),
            )
            healthy = await asyncio.wait_for(self.bridge_ready(), 2) is True
            current = (
                observation.observed_at
                <= time.time()
                < min(observation.observed_at + 5.0, observation.expires_at)
            )
            if self.runtime_snapshot is not None:
                snapshot = await asyncio.wait_for(self.runtime_snapshot(observation, healthy), 2)
                # Revalidate injected readers too; callbacks are not proof providers.
                snapshot = RuntimeModeSnapshot.model_validate(snapshot.model_dump(mode="json"))
                now = time.time()
                if (
                    not healthy
                    or snapshot.lease_fingerprint != observation.lease_fingerprint
                    or not observation.observed_at
                    <= now
                    < min(observation.observed_at + 5.0, observation.expires_at)
                    or not snapshot.generated_at <= now < snapshot.generated_at + 5.0
                ):
                    raise ValueError("diagnostic_snapshot_unavailable")
        except asyncio.CancelledError:
            raise
        except Exception:
            snapshot = None
        qualified_rows = list(response.rows)
        if snapshot is not None:
            try:
                # Dynamic Binding joins must still be qualified after the file
                # callback/health awaits; an earlier valid row is not a grant.
                qualified_rows, _ = await self.local_metadata(qualified_rows)
            except asyncio.CancelledError:
                raise
            except Exception:
                snapshot = None
        facts = {fact.scope_key: fact for fact in snapshot.roots} if snapshot else {}
        rows = []
        for row in qualified_rows:
            reference = self._runtime_reference(row)
            fact = facts.get(scope_key(reference)) if reference is not None else None
            mode = (
                InspectionRuntimeMode(
                    mode=fact.mode,
                    reason=fact.reason,
                    transition_at=fact.transition_at,
                    observed_at=snapshot.generated_at,
                )
                if fact is not None and snapshot is not None
                else InspectionRuntimeMode(mode="unavailable", reason="diagnostics-unavailable")
                if snapshot is None or self._runtime_config_unavailable(row)
                else InspectionRuntimeMode(mode="not-observed", reason="not-observed")
            )
            rows.append(
                InspectionSessionV2.model_validate(
                    row.model_dump(mode="json") | {"runtime_mode": mode.model_dump(mode="json")}
                )
            )
        # All Native/page work precedes the file read. Recheck the independent
        # lease after projection, then gate the final response clock after this
        # last await; a slow filesystem/SQL step cannot extend five-second facts.
        if snapshot is not None and observation is not None:
            try:
                async with self.db.sessions() as session:
                    final_lease = (
                        await session.execute(
                            select(
                                WorkerLease.holder, WorkerLease.fencing, WorkerLease.expires_at
                            ).where(WorkerLease.role == "consumer")
                        )
                    ).one_or_none()
                now = time.time()
                effective_expiry = (
                    min(observation.expires_at, float(final_lease.expires_at))
                    if final_lease is not None
                    else 0.0
                )
                current = bool(
                    final_lease is not None
                    and lease_fingerprint(final_lease.holder, final_lease.fencing)
                    == observation.lease_fingerprint
                    and observation.observed_at
                    <= now
                    < min(
                        observation.observed_at + 5.0,
                        observation.expires_at,
                        final_lease.expires_at,
                    )
                )
                if not current or not snapshot.generated_at <= now < snapshot.generated_at + 5.0:
                    raise ValueError("diagnostic_snapshot_expired")
            except asyncio.CancelledError:
                raise
            except Exception:
                snapshot = None
                rows = [
                    InspectionSessionV2.model_validate(
                        row.model_dump(mode="json")
                        | {
                            "runtime_mode": {
                                "mode": "unavailable",
                                "reason": "diagnostics-unavailable",
                            }
                        }
                    )
                    for row in response.rows
                ]
        issues = response.issues
        if snapshot is None or any(
            row.runtime_mode.mode in {"not-observed", "unavailable"} for row in rows
        ):
            issues = bounded_inspection_issues(
                issues, (InspectionIssue(code="runtime_modes_unavailable"),)
            )
        data = response.model_dump(mode="json", exclude={"version", "rows"})
        result = InspectionResponseV2.model_validate(
            data
            | {
                "rows": [row.model_dump(mode="json") for row in rows],
                "bridge_ready": healthy,
                "bridge_lease_current": current,
                "issues": [issue.model_dump(mode="json") for issue in issues],
                "status": "error"
                if response.status == "error"
                else "partial"
                if response.status == "partial" or issues
                else "ok",
            }
        )
        # DTO assembly is synchronous but bounded work can still cross expiry.
        # This last clock read follows every await and valid-mode serialization.
        if snapshot is not None and observation is not None:
            now = time.time()
            if not (
                snapshot.generated_at <= now < snapshot.generated_at + 5.0
                and observation.observed_at
                <= now
                < min(observation.observed_at + 5.0, effective_expiry)
            ):
                unavailable = InspectionRuntimeMode(
                    mode="unavailable", reason="diagnostics-unavailable"
                )
                result = result.model_copy(
                    update={
                        "rows": tuple(
                            row.model_copy(update={"runtime_mode": unavailable})
                            for row in result.rows
                        ),
                        "bridge_lease_current": False,
                        "status": "error" if result.status == "error" else "partial",
                        "issues": bounded_inspection_issues(
                            result.issues, (InspectionIssue(code="runtime_modes_unavailable"),)
                        ),
                    }
                )
        return result

    async def _query(self, query: InspectionQuery) -> InspectionResponse:
        observed = time.time()
        issues: list[InspectionIssue] = []
        coverage: list[InspectionCoverage] = []
        rows: list[InspectionSession] = []
        selected = {
            key: value
            for key, value in self.backends.items()
            if query.backend_id is None or query.backend_id == key
        }
        project = self.projects.get(query.project_id) if query.project_id else None
        if not selected or query.project_id and project is None:
            return InspectionResponse(
                status="error",
                observed_at=observed,
                issues=(InspectionIssue(code="scope_unavailable"),),
            )
        if project:
            selected = {key: value for key, value in selected.items() if key == project[0]}
            if not selected:
                return InspectionResponse(
                    status="error",
                    observed_at=observed,
                    issues=(InspectionIssue(code="scope_unavailable"),),
                )
        try:
            ready = await asyncio.wait_for(self.bridge_ready(), 2)
        except Exception:
            ready = False
        try:
            _, lease = await self.local_metadata([])
        except Exception:
            lease = False
            issues.append(InspectionIssue(code="bridge_unavailable"))
        if (not ready or not lease) and not issues:
            issues.append(InspectionIssue(code="bridge_unavailable"))
        if query.command == "doctor":
            for backend_id, backend in selected.items():
                try:
                    owner = await backend.original_owner()
                    coverage.append(
                        InspectionCoverage(
                            backend_id=backend_id,
                            complete=True,
                            scanned=0,
                            reason="exhausted",
                            owner_epoch=owner.owner_epoch,
                            native_pid=owner.pid,
                        )
                    )
                except Exception:
                    coverage.append(
                        InspectionCoverage(
                            backend_id=backend_id,
                            complete=False,
                            scanned=0,
                            reason="backend_unavailable",
                        )
                    )
                    issues.append(InspectionIssue(code="native_unavailable", backend_id=backend_id))
            return InspectionResponse(
                status="partial" if issues else "ok",
                observed_at=observed,
                bridge_ready=ready,
                bridge_lease_current=lease,
                coverage=tuple(coverage),
                issues=tuple(issues),
            )
        deadline = time.monotonic() + 24
        for backend_index, (backend_id, backend) in enumerate(selected.items()):
            backend_deadline = time.monotonic() + min(
                12, max(0.1, (deadline - time.monotonic()) / (len(selected) - backend_index))
            )
            cursor = query.cursor
            seen: set[str] = set()
            seen_cursors = {cursor} if cursor is not None else set()
            scanned = 0
            matched = 0
            try:
                pages = (
                    1
                    if query.command == "session"
                    else query.max_pages
                    if query.active or query.association != "all"
                    else 1
                )
                next_cursor = cursor
                batch: tuple[InspectionSession, ...]
                for _page_index in range(pages):
                    if query.command == "session":
                        assert query.session_id is not None
                        batch = (
                            await asyncio.wait_for(
                                backend.detail(query.session_id),
                                max(0.001, backend_deadline - time.monotonic()),
                            ),
                        )
                        next_cursor = None
                    else:
                        batch, next_cursor = await asyncio.wait_for(
                            backend.page(
                                query.limit,
                                cursor,
                                project=(project[1], project[2]) if project else None,
                            ),
                            max(0.001, backend_deadline - time.monotonic()),
                        )
                        try:
                            batch = tuple(
                                await asyncio.wait_for(
                                    asyncio.gather(*(backend.state(row) for row in batch)),
                                    max(0.001, backend_deadline - time.monotonic()),
                                )
                            )
                        except TimeoutError:
                            batch = tuple(
                                row.model_copy(
                                    update={
                                        "state": ExecutionState.UNKNOWN,
                                        "state_reason": "resource_unavailable",
                                        "owner_epoch": None,
                                    }
                                )
                                for row in batch
                            )
                    ids = {r.session_id for r in batch}
                    if ids & seen:
                        raise ValueError("inspection_catalog_duplicate_across_pages")
                    seen.update(ids)
                    scanned += len(batch)
                    try:
                        attached, lease = await self.local_metadata(list(batch))
                    except Exception:
                        attached = list(batch)
                        if not any(i.code == "bridge_unavailable" for i in issues):
                            issues.append(InspectionIssue(code="bridge_unavailable"))
                    if any(r.state == ExecutionState.UNKNOWN for r in attached):
                        if not any(
                            i.code == "partial_state" and i.backend_id == backend_id for i in issues
                        ):
                            issues.append(
                                InspectionIssue(code="partial_state", backend_id=backend_id)
                            )
                    filtered = [
                        r
                        for r in attached
                        if (
                            not query.active
                            or r.state in BUSY
                            or any(
                                b.counts.queued
                                or b.counts.held
                                or b.counts.active
                                or b.counts.ambiguous
                                for b in r.bindings
                            )
                        )
                        and (
                            query.association == "all"
                            or query.association == "bound"
                            and r.bound
                            or query.association == "unbound"
                            and r.binding_coverage == "complete"
                            and not r.bound
                        )
                    ]
                    rows.extend(filtered)
                    matched += len(filtered)
                    if len(rows) > 1000:
                        raise ValueError("inspection_response_capacity")
                    if next_cursor is None or filtered:
                        break
                    if next_cursor == cursor or next_cursor in seen_cursors:
                        raise ValueError("inspection_cursor_cycle")
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
                complete = next_cursor is None
                reason: Literal["exhausted", "page", "scan_limit"] = (
                    "exhausted"
                    if complete
                    else "scan_limit"
                    if not filtered
                    and _page_index + 1 == pages
                    and (query.active or query.association != "all")
                    else "page"
                )
                coverage.append(
                    InspectionCoverage(
                        backend_id=backend_id,
                        complete=complete,
                        scanned=scanned,
                        next_cursor=next_cursor,
                        reason=reason,
                    )
                )
                if reason == "scan_limit":
                    issues.append(InspectionIssue(code="capacity", backend_id=backend_id))
            except asyncio.CancelledError:
                raise
            except Exception:
                coverage.append(
                    InspectionCoverage(
                        backend_id=backend_id,
                        complete=False,
                        scanned=scanned,
                        next_cursor=cursor,
                        reason="backend_unavailable",
                    )
                )
                issues.append(InspectionIssue(code="native_unavailable", backend_id=backend_id))
        return InspectionResponse(
            status="partial" if issues else "ok",
            observed_at=observed,
            bridge_ready=ready,
            bridge_lease_current=lease,
            rows=tuple(rows),
            coverage=tuple(coverage),
            issues=tuple(issues),
        )
