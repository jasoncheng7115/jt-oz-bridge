"""Exact original-session routing inside one explicitly enrolled backend.

Each session keeps its own execution/policy/proof/result objects. Routing never
creates, forks or guesses a session, or promotes an advertised catalog entry.
"""

from __future__ import annotations

import asyncio
import re
import weakref
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from jt_oz_bridge.adapters.opencode.turn_resources import NativeResourceTurn, TurnCorrelation
from jt_oz_bridge.domain.checks import CheckAuthority
from jt_oz_bridge.domain.control import ExecutionState, InteractionSnapshot, SessionSnapshot
from jt_oz_bridge.domain.enrollment_views import EnrollmentView, enrollment_projection
from jt_oz_bridge.domain.execution import (
    Admission,
    ExecutionClient,
    MutationNotSent,
    SteerNotReady,
)
from jt_oz_bridge.domain.model_catalog import ModelCatalog, NativeModelCatalog
from jt_oz_bridge.domain.models import Capability, SessionRef
from jt_oz_bridge.domain.operations import CURRENT_OPERATIONS
from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.resource_execution_results import ResourceTurnReader
from jt_oz_bridge.services.session_graph_generations import (
    BackendGraphCell,
    PreparedGraphGeneration,
    SessionGraphGeneration,
)
from jt_oz_bridge.storage.durable import Conflict

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.opencode.agent_configuration import AgentConfigurationCell
    from jt_oz_bridge.adapters.opencode.files import V2NativeFileReader
    from jt_oz_bridge.adapters.opencode.transcript import TranscriptReader
    from jt_oz_bridge.adapters.opencode.workspace_catalog import V2WorkspaceCatalog
    from jt_oz_bridge.domain.native_metadata import NativeMetadataReader
    from jt_oz_bridge.services.live_capture import LiveTextSource


@dataclass(frozen=True)
class RegisteredSession:
    reference: SessionRef
    contract_sha256: str
    execution: ExecutionClient
    models: ModelCatalog
    results: ResourceTurnReader
    pending: Callable[[SessionRef], Awaitable[tuple[str, ...]]]
    transcript: TranscriptReader | None = None
    metadata: NativeMetadataReader | None = None
    live_text: LiveTextSource | None = None
    # A created Root gets its project's file read only when its rules match the source.
    files: V2NativeFileReader | None = None
    catalog: V2WorkspaceCatalog | None = None

    def __post_init__(self) -> None:
        if (
            not all(self.reference.model_dump().values())
            or not re.fullmatch(r"[0-9a-f]{64}", self.contract_sha256)
            or (
                self.execution.contract_for(self.reference) != self.contract_sha256
                or self.models.contract_for(self.reference) != self.contract_sha256
            )
        ):
            raise ValueError("qualified_session_contract_required")
        for reader in (self.transcript, self.metadata):
            if reader is not None and reader.contract_for(self.reference) != self.contract_sha256:
                raise ValueError("qualified_session_resource_contract_required")
        if self.live_text is not None and self.transcript is None:
            raise ValueError("qualified_session_live_text_requires_transcript")
        if self.catalog is not None and (
            self.files is None or self.catalog.client is not self.files.client
        ):
            raise ValueError("qualified_session_catalog_requires_its_file_reader")


@dataclass(frozen=True)
class _StagedRegistryGraph:
    root: SessionRef
    base: object
    next_state: object
    generation: SessionGraphGeneration
    snapshots: Mapping[SessionRef, SessionSnapshot]


@dataclass(frozen=True, init=False)
class SessionRegistry:
    sessions: Mapping[SessionRef, RegisteredSession]
    projects: Mapping[str, str]
    models: SessionModelCatalog
    results: SessionResultReader
    publication: BackendGraphCell = field(repr=False, compare=False)
    configuration: AgentConfigurationCell | None = field(repr=False, compare=False)
    _identity: tuple[str, str, str] = field(repr=False, compare=False)
    _adoption_gate: asyncio.Lock = field(repr=False, compare=False)
    _transcripts: EnrollmentView[SessionRef, TranscriptReader] = field(repr=False, compare=False)
    _metadata: EnrollmentView[SessionRef, NativeMetadataReader] = field(repr=False, compare=False)
    _live_text: EnrollmentView[SessionRef, LiveTextSource] = field(repr=False, compare=False)
    _files: EnrollmentView[SessionRef, V2NativeFileReader] = field(repr=False, compare=False)
    _catalogs: EnrollmentView[SessionRef, V2WorkspaceCatalog] = field(repr=False, compare=False)
    _staged_graphs: weakref.WeakKeyDictionary[PreparedGraphGeneration, _StagedRegistryGraph] = (
        field(repr=False, compare=False)
    )

    def __init__(self, sessions: Mapping[SessionRef, RegisteredSession]) -> None:
        object.__setattr__(self, "_staged_graphs", weakref.WeakKeyDictionary())
        if (
            not sessions
            or len(sessions) > 1000
            or any(ref != item.reference for ref, item in sessions.items())
        ):
            raise ValueError("explicit_session_registration_required")
        entries = tuple(sessions.values())
        first = entries[0]
        identity = (
            first.reference.backend_id,
            first.reference.backend_identity,
            first.contract_sha256,
        )
        ids = [e.reference.upstream_session_id for e in entries]
        projects: dict[str, str] = {}
        for entry in entries:
            ref = entry.reference
            if (ref.backend_id, ref.backend_identity, entry.contract_sha256) != identity:
                raise ValueError("session_registry_cannot_mix_backend_instances_or_contracts")
            if ref.project_id in projects and projects[ref.project_id] != ref.canonical_directory:
                raise ValueError("session_registry_project_directory_conflict")
            projects[ref.project_id] = ref.canonical_directory
        if len(set(ids)) != len(ids):
            raise ValueError("native_session_cannot_have_multiple_project_aliases")
        publication = BackendGraphCell(sessions)
        object.__setattr__(self, "publication", publication)
        object.__setattr__(self, "configuration", None)
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "_adoption_gate", asyncio.Lock())
        object.__setattr__(self, "sessions", publication.sessions)
        object.__setattr__(self, "projects", publication.projects)
        object.__setattr__(self, "models", SessionModelCatalog(self))
        object.__setattr__(self, "results", SessionResultReader(self))
        object.__setattr__(
            self,
            "_transcripts",
            enrollment_projection(self.sessions, lambda entry: entry.transcript),
        )
        object.__setattr__(
            self, "_metadata", enrollment_projection(self.sessions, lambda entry: entry.metadata)
        )
        object.__setattr__(
            self, "_live_text", enrollment_projection(self.sessions, lambda entry: entry.live_text)
        )
        object.__setattr__(
            self, "_files", enrollment_projection(self.sessions, lambda entry: entry.files)
        )
        object.__setattr__(
            self, "_catalogs", enrollment_projection(self.sessions, lambda entry: entry.catalog)
        )

    def attach_configuration(self, cell: AgentConfigurationCell) -> None:
        """Trusted one-time composition; reads, not mutations, stay independent of it."""
        if self.configuration is not None:
            raise ValueError("session_registry_configuration_already_composed")
        object.__setattr__(self, "configuration", cell)

    def _configuration_pin(self, reference: SessionRef) -> str | None:
        """Approved policy pointer; a repeated restore or first enrollment is not a change."""
        saved = self.configuration.readiness(reference) if self.configuration is not None else None
        return saved.policy_sha256 if saved is not None else None

    def _require_configuration(self, reference: SessionRef, pinned: str | None) -> None:
        # A new policy after POST stays uncertain at the dispatcher, like a new graph.
        if pinned is not None and self._configuration_pin(reference) != pinned:
            raise Conflict("original_session_configuration_changed")

    @property
    def transcripts(self) -> EnrollmentView[SessionRef, TranscriptReader]:
        return self._transcripts

    def reference_snapshot(self) -> tuple[SessionRef, ...]:
        return tuple(self.sessions)

    @property
    def metadata(self) -> EnrollmentView[SessionRef, NativeMetadataReader]:
        return self._metadata

    @property
    def live_text(self) -> EnrollmentView[SessionRef, LiveTextSource]:
        return self._live_text

    @property
    def files(self) -> EnrollmentView[SessionRef, V2NativeFileReader]:
        """File readers of Roots registered after startup; enrolled Roots have their own."""
        return self._files

    @property
    def catalogs(self) -> EnrollmentView[SessionRef, V2WorkspaceCatalog]:
        return self._catalogs

    def adoption_scope(self, entry: RegisteredSession) -> None:
        ref = entry.reference
        if (
            (ref.backend_id, ref.backend_identity, entry.contract_sha256) != self._identity
            or self.projects.get(ref.project_id) != ref.canonical_directory
            or entry.execution.contract_for(ref) != entry.contract_sha256
            or entry.models.contract_for(ref) != entry.contract_sha256
            or any(
                reader is not None and reader.contract_for(ref) != entry.contract_sha256
                for reader in (entry.transcript, entry.metadata)
            )
            or (entry.live_text is not None and entry.transcript is None)
            or any(
                other.upstream_session_id == ref.upstream_session_id and other != ref
                for other in self.sessions
            )
        ):
            raise AccessDenied("new_session_registration_outside_enrolled_project")
        previous = self.sessions.get(ref)
        if previous is not None and previous is not entry:
            raise Conflict("original_session_registration_cannot_be_replaced")
        if previous is None and len(self.sessions) >= 1000:
            raise Conflict("session_registration_capacity_reached")

    async def adopt(
        self, entry: RegisteredSession, *, authorize: Callable[[], Awaitable[bool]]
    ) -> None:
        """Append one fully assembled, originally proven resource set atomically.

        The enrollment controller must verify its own source/authority/candidate
        seal before and after Native reads. This is not a catalog-listing API.
        Existing original registrations are never replaced or removed.
        """
        async with self._adoption_gate:
            self.adoption_scope(entry)
            existing = self.publication.generation(entry.reference)
            prepared = (
                self.publication.prepare_legacy(existing.root, existing.entries, existing.parents)
                if existing is not None
                else self.publication.prepare_legacy(
                    entry.reference, {entry.reference: entry}, {entry.reference: None}
                )
            )
            if await authorize() is not True:
                raise AccessDenied("new_session_registration_authority_changed")
            snapshot = await entry.execution.snapshot(entry.reference)
            if (
                snapshot.reference != entry.reference
                or not snapshot.reconciled
                or snapshot.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED}
                or snapshot.descendants
            ):
                raise Conflict("new_session_registration_original_snapshot_required")
            if await authorize() is not True:
                raise AccessDenied("new_session_registration_authority_changed")
            self.adoption_scope(entry)
            self.publication.publish(prepared)

    async def adopt_graph(
        self,
        root: SessionRef,
        entries: Mapping[SessionRef, RegisteredSession],
        parents: Mapping[SessionRef, SessionRef | None],
        *,
        authorize: Callable[[], Awaitable[bool]],
        current: Callable[[], bool],
        before_commit: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        """Append a complete originally proven graph with one visible commit.

        Trusted composition must supply qualified per-node execution readers,
        verified original parent edges, current Source authority and a final
        synchronous check of every original resource proof. Metadata/catalog
        DTOs alone cannot assemble an execution graph. Durable journaling and
        activation are the controller's responsibility, not this registry's.
        """
        selected, lineage = dict(entries), dict(parents)
        if (
            not selected
            or len(selected) > 1000
            or root not in selected
            or selected.keys() != lineage.keys()
            or lineage[root] is not None
            or any(ref != item.reference for ref, item in selected.items())
        ):
            raise Conflict("original_session_complete_graph_required")
        scope = root.model_dump(exclude={"upstream_session_id"})
        descendants: dict[SessionRef, set[SessionRef]] = {ref: set() for ref in selected}
        for ref in selected:
            if ref.model_dump(exclude={"upstream_session_id"}) != scope:
                raise AccessDenied("original_session_graph_outside_project")
            parent = lineage[ref]
            if ref != root and parent is None:
                raise Conflict("original_session_graph_single_root_required")
            visited = {ref}
            while parent is not None:
                if parent not in selected or parent in visited:
                    raise Conflict("original_session_graph_parent_missing_or_cyclic")
                visited.add(parent)
                descendants[parent].add(ref)
                parent = lineage[parent]

        def scope_current() -> None:
            if len(set(selected) | set(self.sessions)) > 1000:
                raise Conflict("session_registration_capacity_reached")
            for item in selected.values():
                self.adoption_scope(item)

        async with self._adoption_gate:
            scope_current()
            prepared = self.publication.prepare_legacy(root, selected, lineage)
            # Existing entries may only be reused by exact object identity.
            # No registry visibility changes until all awaits and fences pass.
            for ref, entry in selected.items():
                if await authorize() is not True:
                    raise AccessDenied("original_session_graph_authority_changed")
                snapshot = await entry.execution.snapshot(ref)
                if (
                    snapshot.reference != ref
                    or not snapshot.reconciled
                    or snapshot.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED}
                    or len(snapshot.descendants) != len(set(snapshot.descendants))
                    or set(snapshot.descendants) != descendants[ref]
                ):
                    raise Conflict("original_session_graph_snapshot_not_complete")
            if await authorize() is not True:
                raise AccessDenied("original_session_graph_authority_changed")
            if before_commit is not None:
                # The controller may durably prepare the original identity
                # journal here. A crash leaves a prepared record for GET-only
                # recovery, never proof of a Native mutation or a Binding.
                await before_commit()
                if await authorize() is not True:
                    raise AccessDenied("original_session_graph_authority_changed")
            scope_current()
            # Final source checks above can yield to Native arrivals. Require
            # the controller's original proof checks without another await.
            if current() is not True:
                raise Conflict("original_session_graph_resource_fence_changed")
            scope_current()
            self.publication.publish(prepared)

    async def stage_adopt_graph(
        self,
        root: SessionRef,
        entries: Mapping[SessionRef, RegisteredSession],
        parents: Mapping[SessionRef, SessionRef | None],
        *,
        authorize: Callable[[], Awaitable[bool]],
        current: Callable[[], bool],
        qualify: Callable[[], Awaitable[None]],
    ) -> PreparedGraphGeneration:
        """Perform original graph GET qualification without making it visible.

        The returned cell candidate is issuer-owned and still pins the original
        whole-backend CAS. The closed Source owner must finish its second side
        before the controller calls commit_staged_graph with SQL-only hooks.
        The public adopt_graph path above retains its independent checks.
        """
        selected, lineage = dict(entries), dict(parents)
        if (
            not selected
            or len(selected) > 1000
            or root not in selected
            or selected.keys() != lineage.keys()
            or lineage[root] is not None
            or any(ref != entry.reference for ref, entry in selected.items())
        ):
            raise Conflict("original_session_complete_graph_required")
        scope = root.model_dump(exclude={"upstream_session_id"})
        descendants: dict[SessionRef, set[SessionRef]] = {ref: set() for ref in selected}
        for ref in selected:
            if ref.model_dump(exclude={"upstream_session_id"}) != scope:
                raise AccessDenied("original_session_graph_outside_project")
            parent, visited = lineage[ref], {ref}
            if ref != root and parent is None:
                raise Conflict("original_session_graph_single_root_required")
            while parent is not None:
                if parent not in selected or parent in visited:
                    raise Conflict("original_session_graph_parent_missing_or_cyclic")
                visited.add(parent)
                descendants[parent].add(ref)
                parent = lineage[parent]
        async with self._adoption_gate:
            if len(set(selected) | set(self.sessions)) > 1000:
                raise Conflict("session_registration_capacity_reached")
            for entry in selected.values():
                self.adoption_scope(entry)
            prepared = self.publication.prepare_legacy(root, selected, lineage)
            snapshots = {}
            for ref, entry in selected.items():
                if await authorize() is not True:
                    raise AccessDenied("original_session_graph_authority_changed")
                snapshot = await entry.execution.snapshot(ref)
                if (
                    snapshot.reference != ref
                    or not snapshot.reconciled
                    or snapshot.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED}
                    or len(snapshot.descendants) != len(set(snapshot.descendants))
                    or set(snapshot.descendants) != descendants[ref]
                ):
                    raise Conflict("original_session_graph_snapshot_not_complete")
                snapshots[ref] = snapshot
            if await authorize() is not True:
                raise AccessDenied("original_session_graph_authority_changed")
            await qualify()
            if await authorize() is not True:
                raise AccessDenied("original_session_graph_authority_changed")
            if current() is not True or self.publication.snapshot() is not prepared._base:
                raise Conflict("original_session_graph_resource_fence_changed")
            if len(self._staged_graphs) >= 1000:
                raise Conflict("original_session_generation_candidate_capacity")
            self._staged_graphs[prepared] = _StagedRegistryGraph(
                root,
                prepared._base,
                prepared._next,
                prepared.generation,
                MappingProxyType(snapshots),
            )
            return prepared

    def require_staged_graph(self, candidate: PreparedGraphGeneration) -> _StagedRegistryGraph:
        staged = self._staged_graphs.get(candidate)
        if (
            staged is None
            or candidate._base is not staged.base
            or candidate._next is not staged.next_state
            or candidate.generation is not staged.generation
            or self.publication.snapshot() is not staged.base
        ):
            raise Conflict("original_session_staged_graph_changed")
        if len(set(candidate.generation.entries) | set(self.sessions)) > 1000:
            raise Conflict("session_registration_capacity_reached")
        for entry in candidate.generation.entries.values():
            self.adoption_scope(entry)
        return staged

    def staged_snapshot(
        self, candidate: PreparedGraphGeneration, reference: SessionRef
    ) -> SessionSnapshot:
        staged = self.require_staged_graph(candidate)
        try:
            return staged.snapshots[reference]
        except KeyError:
            raise Conflict("original_session_staged_snapshot_missing") from None

    async def commit_staged_graph(
        self,
        candidate: PreparedGraphGeneration,
        *,
        authorize: Callable[[], Awaitable[bool]],
        current: Callable[[], bool],
        before_commit: Callable[[], Awaitable[None]],
    ) -> SessionGraphGeneration:
        """SQL-only continuation; no execution snapshot or Native read occurs."""
        async with self._adoption_gate:
            self.require_staged_graph(candidate)
            if current() is not True or await authorize() is not True:
                raise AccessDenied("original_session_graph_authority_changed")
            self.require_staged_graph(candidate)
            if current() is not True:
                raise Conflict("original_session_graph_resource_fence_changed")
            await before_commit()
            self.require_staged_graph(candidate)
            if current() is not True or await authorize() is not True:
                raise AccessDenied("original_session_graph_authority_changed")
            self.require_staged_graph(candidate)
            if current() is not True:
                raise Conflict("original_session_graph_resource_fence_changed")
            self._staged_graphs.pop(candidate)
            return self.publication.publish(candidate)

    @property
    def generation_lock(self) -> asyncio.Lock:
        """Controller lock order: this gate before durable journal fencing."""
        return self._adoption_gate

    def prepare_generation(
        self,
        record: SessionAdoptionRecord,
        entries: Mapping[SessionRef, RegisteredSession],
        *,
        expected: SessionGraphGeneration | None,
        enrollments: Mapping[SessionRef, object],
        context: object | None = None,
        receipt: object | None = None,
    ) -> PreparedGraphGeneration:
        for entry in entries.values():
            self.adoption_scope(entry)
        return self.publication.prepare(
            record,
            entries,
            expected=expected,
            enrollments=enrollments,
            context=context,
            receipt=receipt,
        )

    def prepare_refresh_generation(
        self,
        record: SessionAdoptionRecord,
        entries: Mapping[SessionRef, RegisteredSession],
        *,
        expected: SessionGraphGeneration,
        enrollments: Mapping[SessionRef, object],
        context: object | None = None,
        receipt: object | None = None,
    ) -> PreparedGraphGeneration:
        for entry in entries.values():
            self.adoption_scope(entry)
        return self.publication.prepare_refresh(
            record,
            entries,
            expected=expected,
            enrollments=enrollments,
            context=context,
            receipt=receipt,
        )

    def prepare_bootstrap_generation(
        self,
        record: SessionAdoptionRecord,
        entries: Mapping[SessionRef, RegisteredSession],
        *,
        expected: SessionGraphGeneration,
        original_nodes: Mapping[SessionRef, OriginalSessionNode],
        baseline_current: Callable[[], bool],
        enrollments: Mapping[SessionRef, object],
        context: object | None = None,
        receipt: object | None = None,
    ) -> PreparedGraphGeneration:
        for entry in entries.values():
            self.adoption_scope(entry)
        candidate = self.publication.prepare_bootstrap(
            record,
            entries,
            expected=expected,
            original_nodes=original_nodes,
            baseline_current=baseline_current,
            enrollments=enrollments,
            context=context,
            receipt=receipt,
        )
        for entry in candidate.generation.entries.values():
            self.adoption_scope(entry)
        return candidate

    def bind_receipt(
        self, candidate: PreparedGraphGeneration, receipt: object
    ) -> PreparedGraphGeneration:
        return self.publication.bind_receipt(candidate, receipt)

    def publish_generation(self, candidate: PreparedGraphGeneration) -> SessionGraphGeneration:
        return self.publication.publish(candidate)

    def selected(self, ref: SessionRef) -> RegisteredSession:
        item = self.sessions.get(ref)
        if item is None:
            raise AccessDenied("original_session_not_registered")
        if item.execution.contract_for(ref) != item.contract_sha256:
            raise Conflict("original_session_contract_changed")
        return item

    def contract_for(self, reference: SessionRef) -> str:
        return self.selected(reference).contract_sha256

    def capabilities(self, reference: SessionRef) -> dict[str, Capability]:
        entry = self.selected(reference)
        result = {
            key: value.model_copy(deep=True)
            for key, value in entry.execution.capabilities(reference).items()
            if key in CURRENT_OPERATIONS
        }
        if self.configuration is not None and not self.configuration.mutation_ready(reference):
            # Read continuity stays; only an emergency interrupt remains available.
            return {
                key: value
                if key in {"interrupt", "agent.switch"}
                else value.model_copy(
                    update={
                        "supported": False,
                        "reason": "original_root_configuration_not_ready",
                    }
                )
                for key, value in result.items()
            }
        return result

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot:
        entry = self.selected(reference)
        generation = self.publication.generation(reference)
        value = await entry.execution.snapshot(reference)
        self.publication.require_current(reference, generation)
        self.selected(reference)
        if (
            value.reference != reference
            or len(set(value.descendants)) != len(value.descendants)
            or reference in value.descendants
        ):
            raise Conflict("original_session_snapshot_scope_changed")
        for descendant in value.descendants:
            if (
                descendant.project_id != reference.project_id
                or descendant.canonical_directory != reference.canonical_directory
            ):
                raise AccessDenied("original_session_descendant_outside_project")
            self.selected(descendant)
        return value

    async def _lifecycle_read(self, name: str, reference: SessionRef) -> Any:
        entry = self.selected(reference)
        read = getattr(entry.execution, name, None)
        if not callable(read):
            raise Conflict("session_lifecycle_read_unavailable")
        generation = self.publication.generation(reference)
        value = await read(reference)
        self.publication.require_current(reference, generation)
        self.selected(reference)
        return value

    async def pending_revert(self, reference: SessionRef) -> str | None:
        return cast("str | None", await self._lifecycle_read("pending_revert", reference))

    async def recent_user_messages(self, reference: SessionRef) -> tuple[Any, ...]:
        return cast(
            "tuple[Any, ...]", await self._lifecycle_read("recent_user_messages", reference)
        )

    async def prompt_readback(
        self, reference: SessionRef, action_id: str, operation_digest: str, text: str
    ) -> str | None:
        entry = self.selected(reference)
        read = getattr(entry.execution, "prompt_readback", None)
        if not callable(read):
            raise Conflict("prompt_readback_unavailable")
        generation = self.publication.generation(reference)
        value = await read(reference, action_id, operation_digest, text)
        self.publication.require_current(reference, generation)
        self.selected(reference)
        return cast("str | None", value)

    async def prompt_never_arrived(
        self, reference: SessionRef, action_id: str, operation_digest: str, sent_after: float
    ) -> bool:
        entry = self.selected(reference)
        read = getattr(entry.execution, "prompt_never_arrived", None)
        if not callable(read):
            return False
        generation = self.publication.generation(reference)
        value = await read(reference, action_id, operation_digest, sent_after)
        self.publication.require_current(reference, generation)
        self.selected(reference)
        return value is True

    async def interaction(self, reference: SessionRef, request_id: str) -> InteractionSnapshot:
        if not request_id:
            raise ValueError("native_request_identity_required")
        entry = self.selected(reference)
        generation = self.publication.generation(reference)
        value = await entry.execution.interaction(reference, request_id)
        self.publication.require_current(reference, generation)
        self.selected(reference)
        if value.reference != reference or value.upstream_request_id != request_id:
            raise Conflict("original_session_interaction_scope_changed")
        return value

    def steer_supported(self, reference: SessionRef) -> bool:
        try:
            supported = getattr(self.selected(reference).execution, "steer_supported", None)
            return callable(supported) and supported(reference) is True
        except Exception:
            return False

    async def submit(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        *,
        steer: bool = False,
    ) -> Admission:
        entry = self.selected(reference)
        generation = self.publication.generation(reference)
        configuration = self._configuration_pin(reference)
        if steer:
            # Only the original adapter that can read the pending inbox may steer.
            if not self.steer_supported(reference):
                raise SteerNotReady("session_steer_not_supported")
            submit_steer: Any = entry.execution.submit
            result = cast(Admission, await submit_steer(reference, payload, action_id, steer=True))
        else:
            result = await entry.execution.submit(reference, payload, action_id)
        self.publication.require_current(reference, generation)
        self._require_configuration(reference, configuration)
        # A change after POST remains uncertain at the dispatcher. Never reroute
        # or retry on another session to manufacture a successful receipt.
        self.selected(reference)
        return result

    async def submit_check(
        self,
        reference: SessionRef,
        payload: dict[str, Any],
        action_id: str,
        authority: CheckAuthority,
    ) -> Admission:
        entry = self.selected(reference)
        submit_check = getattr(entry.execution, "submit_check", None)
        if payload.get("operation") != "check.run" or not callable(submit_check):
            raise MutationNotSent("session_check_final_authority_not_supported")
        generation = self.publication.generation(reference)
        configuration = self._configuration_pin(reference)
        result = await submit_check(reference, payload, action_id, authority)
        self.publication.require_current(reference, generation)
        self._require_configuration(reference, configuration)
        self.selected(reference)
        return Admission.model_validate(result.model_dump(mode="python"))

    async def pending(self, reference: SessionRef) -> tuple[str, ...]:
        entry = self.selected(reference)
        generation = self.publication.generation(reference)
        value = await entry.pending(reference)
        self.publication.require_current(reference, generation)
        self.selected(reference)
        if (
            type(value) is not tuple
            or len(value) > 1000
            or any(not isinstance(x, str) or not 1 <= len(x) <= 255 for x in value)
            or len(set(value)) != len(value)
        ):
            raise ValueError("bounded_scoped_native_pending_ids_required")
        return value


class SessionModelCatalog:
    def __init__(self, registry: SessionRegistry) -> None:
        self.registry = registry

    def contract_for(self, reference: SessionRef) -> str:
        entry = self.registry.selected(reference)
        if entry.models.contract_for(reference) != entry.contract_sha256:
            raise Conflict("original_session_model_contract_changed")
        return entry.contract_sha256

    async def read(self, reference: SessionRef) -> NativeModelCatalog:
        entry = self.registry.selected(reference)
        self.contract_for(reference)
        generation = self.registry.publication.generation(reference)
        value = await entry.models.read(reference)
        self.registry.publication.require_current(reference, generation)
        self.contract_for(reference)
        if value.reference != reference or value.contract_sha256 != entry.contract_sha256:
            raise Conflict("original_session_model_scope_changed")
        return value


class SessionResultReader:
    def __init__(self, registry: SessionRegistry) -> None:
        self.registry = registry
        self._generations: dict[
            int, tuple[weakref.ReferenceType[NativeResourceTurn], SessionGraphGeneration | None]
        ] = {}

    def _remember(
        self, evidence: NativeResourceTurn, generation: SessionGraphGeneration | None
    ) -> None:
        key = id(evidence)

        def forget(reference: weakref.ReferenceType[NativeResourceTurn]) -> None:
            if self._generations.get(key, (None, None))[0] is reference:
                self._generations.pop(key, None)

        if len(self._generations) >= 1000:
            self._generations.pop(next(iter(self._generations)))
        self._generations[key] = (weakref.ref(evidence, forget), generation)

    async def capture(
        self, correlation: TurnCorrelation, *, allow_later_steer: bool = False
    ) -> NativeResourceTurn:
        entry = self.registry.selected(correlation.reference)
        generation = self.registry.publication.generation(correlation.reference)
        if allow_later_steer:
            capture: Any = entry.results.capture
            evidence = cast(NativeResourceTurn, await capture(correlation, allow_later_steer=True))
        else:
            evidence = await entry.results.capture(correlation)
        self.registry.publication.require_current(correlation.reference, generation)
        self.registry.selected(correlation.reference)
        if (
            evidence.correlation != correlation
            or evidence.contract_sha256 != entry.contract_sha256
            or not entry.results.current(evidence)
        ):
            raise Conflict("original_session_result_scope_or_witness_changed")
        self._remember(evidence, generation)
        return evidence

    def current(self, evidence: NativeResourceTurn) -> bool:
        try:
            entry = self.registry.selected(evidence.correlation.reference)
            saved = self._generations.get(id(evidence))
            return (
                saved is not None
                and saved[0]() is evidence
                and self.registry.publication.current(evidence.correlation.reference, saved[1])
                and entry.results.current(evidence)
            )
        except (ValueError, KeyError):
            return False
