"""Fresh GET-only graph extension with original facades and journal-before-publish.

Only trusted runtime composition supplies this controller and its current SQL /
Native authority hooks. Historical identities and detached probes never grant
execution or synthesize a Human, Binding, create/fork or Native input.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.graph_generation import (
    GraphResourceContext,
    attach_graph_generation,
)
from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs
from jt_oz_bridge.adapters.opencode.model_settings import ModelSettingsAttestation
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.project_policy import (
    PERMISSION_SOURCE,
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, V2LeafResourceProofs
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.turn_resources import V2TurnResourceReader
from jt_oz_bridge.domain.control import ExecutionState, SessionSnapshot
from jt_oz_bridge.domain.existing_sessions import ExistingSessionGraphObservation
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import (
    OriginalSessionNode,
    SessionAdoptionRecord,
    same_original_graph,
)
from jt_oz_bridge.domain.session_graph_extension import require_original_extension
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.existing_session_factory import V2ExistingSessionFactory
from jt_oz_bridge.services.session_graph_generations import (
    BackendGraphState,
    PreparedGraphGeneration,
    SessionGraphGeneration,
)
from jt_oz_bridge.services.session_registration_journal import (
    RegistrationReceipt,
    SavedSessionRegistration,
    SessionRegistrationJournal,
    registration_identity,
    registration_key,
)
from jt_oz_bridge.services.session_registry import RegisteredSession
from jt_oz_bridge.storage.durable import Conflict, digest

Authority = Callable[[], Awaitable[bool]]
JournalUpdate = Callable[[SessionAdoptionRecord], Awaitable[RegistrationReceipt]]


@dataclass(frozen=True, eq=False)
class PreparedSessionGraphUpdate:
    root: SessionRef
    previous: SavedSessionRegistration | None
    record: SessionAdoptionRecord
    context: GraphResourceContext
    entries: Mapping[SessionRef, RegisteredSession]
    prepared: PreparedGraphGeneration
    expires_at: float


@dataclass
class _Issued:
    original: ReferenceType[PreparedSessionGraphUpdate]
    seal: tuple[object, ...]
    base: BackendGraphState
    old_entries: Mapping[SessionRef, RegisteredSession]
    assemblies: tuple[tuple[object, ...], ...]
    index: object
    task: object
    attestation: object
    published: SessionGraphGeneration | None = None
    consumed: bool = False
    committing: bool = False
    qualified_snapshots: Mapping[SessionRef, SessionSnapshot] | None = None


class OriginalSessionGraphUpdates:
    def __init__(self, factory: V2ExistingSessionFactory) -> None:
        self.factory = factory
        self._factory = factory
        self.registry = factory.registry
        self._registry = self.registry
        self._issued: OrderedDict[int, _Issued] = OrderedDict()
        self._gate = asyncio.Lock()
        self.attach_registered()

    def attach_registered(self, *, only: SessionRef | None = None) -> None:
        """Tree-opt-in existing facades before future Native watch/proof calls.

        This installs no context and registers no new reference. A complete
        trusted tree pin fences unknown child events even before first growth.
        """
        qualification = self.factory.lineage
        if qualification is None or qualification.qualification_scope != "tree":
            return
        for root, generation in self.registry.publication.snapshot().roots.items():
            if only is not None and root != only:
                continue
            if root.project_id != self.factory.policy.anchor.project_id:
                continue
            entry = generation.entries[root]
            execution = entry.execution
            if (
                not isinstance(execution, V2ExecutionClient)
                or not isinstance(execution.proofs, V2LeafResourceProofs)
                or not isinstance(execution.scope_guard, V2ProjectPolicyGuard)
                or execution.transport is not self.factory._transport
                or execution.proofs.feed is not self.factory._feed
            ):
                raise Conflict("original_graph_update_original_facade_required")
            attached = getattr(execution.proofs, "_graph_publication", None)
            if attached is None:
                attach_graph_generation(
                    execution.proofs,
                    execution.scope_guard,
                    self.registry.publication,
                    root,
                    qualification,
                )
            elif (
                attached.cell is not self.registry.publication
                or attached.root != root
                or attached.guard is not execution.scope_guard
                or attached.attestation is not qualification
            ):
                raise Conflict("original_graph_update_original_facade_changed")

    @staticmethod
    def _assembly(entry: RegisteredSession) -> tuple[object, ...]:
        execution = entry.execution
        if not isinstance(execution, V2ExecutionClient):
            raise Conflict("original_graph_update_native_entry_required")
        return (
            entry,
            execution,
            execution.transport,
            execution.proofs,
            execution.scope_guard,
            getattr(execution.scope_guard, "enrollments", None),
            getattr(execution.proofs, "feed", None),
            getattr(execution.proofs, "model_settings", None),
            entry.models,
            execution.models,
            entry.results,
            getattr(entry.results, "client", None),
            getattr(entry.results, "attestation", None),
            getattr(entry.results, "attachments", None),
            entry.pending,
            entry.transcript,
            getattr(entry.transcript, "qualified", None),
            entry.metadata,
            getattr(entry.metadata, "client", None),
            entry.live_text,
            execution.attachments,
            execution.workspace_attachments,
        )

    def _selected(self, root: SessionRef) -> None:
        if (
            self.factory is not self._factory
            or self.registry is not self._registry
            or self.factory.registry is not self.registry
        ):
            raise Conflict("original_graph_update_factory_replaced")
        self.factory.selected(root)
        self.registry.selected(root)
        if self.factory.lineage is None or self.factory.lineage.qualification_scope != "tree":
            raise Conflict("original_graph_update_tree_qualification_required")

    @staticmethod
    def _seal(candidate: PreparedSessionGraphUpdate) -> tuple[object, ...]:
        return (
            candidate.root,
            candidate.previous,
            candidate.record,
            candidate.context,
            candidate.entries,
            candidate.prepared,
            candidate.expires_at,
        )

    def current(self, candidate: PreparedSessionGraphUpdate) -> bool:
        try:
            self.require(candidate)
            return True
        except (ValueError, TypeError, AttributeError, KeyError):
            return False

    def require(self, candidate: PreparedSessionGraphUpdate) -> _Issued:
        self._selected(candidate.root)
        issued = self._issued.get(id(candidate))
        if (
            issued is None
            or issued.original() is not candidate
            or issued.consumed
            or any(a is not b for a, b in zip(self._seal(candidate), issued.seal, strict=True))
            or not candidate.record.observed_at <= time.time() < candidate.expires_at
            or self.factory._feed.index is not issued.index
            or self.factory._feed.task is not issued.task
            or self.factory._transport.attestation is not issued.attestation
            or not self.factory.observer.current(candidate.context.proofs.observation)
            or candidate.record.qualification_sha256 != self.factory.qualification_sha256()
        ):
            raise Conflict("original_graph_update_expired_or_replaced")
        if issued.published is None:
            if self.registry.publication.snapshot() is not issued.base:
                raise Conflict("original_graph_update_publication_head_changed")
        elif self.registry.publication.generation(candidate.root) is not issued.published:
            raise Conflict("original_graph_update_publication_head_changed")
        candidate.context.require()
        for ref, entry in issued.old_entries.items():
            if self.registry.sessions.get(ref) is not entry:
                raise Conflict("original_graph_update_original_entry_replaced")
        for entry, expected in zip(candidate.entries.values(), issued.assemblies, strict=True):
            if any(a is not b for a, b in zip(self._assembly(entry), expected, strict=True)):
                raise Conflict("original_graph_update_reader_assembly_changed")
        if any(candidate.context.proofs.current_proof(ref) is None for ref in candidate.entries):
            raise Conflict("original_graph_update_original_resource_proof_changed")
        return issued

    async def _authorize(self, authorize: Authority) -> None:
        if await authorize() is not True:
            raise AccessDenied("original_graph_update_current_authority_required")

    @staticmethod
    def _record(factory: V2ExistingSessionFactory, observation: object) -> SessionAdoptionRecord:
        # The observer returns its independently sealed, complete Native graph.
        if not isinstance(observation, ExistingSessionGraphObservation):
            raise Conflict("original_graph_update_observation_required")
        return SessionAdoptionRecord(
            root=observation.reference,
            native_project_id=observation.nodes[0].native_project_id,
            contract_sha256=INSTALLED_SCHEMA,
            qualification_sha256=factory.qualification_sha256(),
            graph_sha256=observation.graph_sha256,
            nodes=tuple(
                OriginalSessionNode.model_validate(
                    node.model_dump(
                        include={
                            "reference",
                            "native_created_at",
                            "parent_reference",
                            "parent_created_at",
                            "policy_sha256",
                        }
                    )
                )
                for node in observation.nodes
            ),
            observed_owner_epoch=observation.owner_epoch,
            observed_at=observation.observed_at,
        )

    def _legacy(self, previous: SavedSessionRegistration) -> bool:
        # Only an unextended head: every extension delta seals its qualification.
        return previous.extension_count == 0 and self.factory.legacy_qualified(previous.record)

    def _historical(
        self, root: SessionRef, previous: SavedSessionRegistration
    ) -> SessionGraphGeneration:
        previous = SessionRegistrationJournal.expected(previous)
        if previous.record.root != root or (
            previous.record.qualification_sha256 != self.factory.qualification_sha256()
            and not self._legacy(previous)
        ):
            raise Conflict("original_graph_update_historical_scope_changed")
        generation = self.registry.publication.generation(root)
        if generation is None or generation.root != root:
            raise Conflict("original_graph_update_registered_root_required")
        known = generation.record
        if known is not None and registration_identity(known) != registration_identity(
            previous.record
        ):
            # A committed SQL extension may precede publication when current
            # authority changes or the caller is cancelled. Only a prepared,
            # strictly additive original head can be re-proved against these
            # unchanged live entries. The journal is not itself live authority.
            if previous.state != "prepared":
                raise Conflict("original_graph_update_historical_generation_changed")
            try:
                require_original_extension(known, previous.record)
            except ValueError:
                raise Conflict("original_graph_update_historical_generation_changed") from None
        historical = {node.reference: node for node in previous.record.nodes}
        if not set(generation.entries) <= set(historical):
            raise Conflict("original_graph_update_historical_nodes_missing")
        if any(
            historical[ref].parent_reference != parent for ref, parent in generation.parents.items()
        ):
            raise Conflict("original_graph_update_historical_parent_changed")
        saved = self.factory._registered.get(root)
        if saved is not None and registration_identity(saved.record) != registration_identity(
            previous.record
        ):
            try:
                require_original_extension(saved.record, previous.record)
            except ValueError:
                raise Conflict("original_graph_update_original_factory_identity_changed") from None
        return generation

    def _enrollments(
        self, generation: SessionGraphGeneration, record: SessionAdoptionRecord
    ) -> dict[SessionRef, NativePolicyEnrollment]:
        policies: dict[SessionRef, NativePolicyEnrollment] = {}
        for node in record.nodes:
            old_entry = generation.entries.get(node.reference)
            old = generation.enrollments.get(node.reference)
            if old_entry is not None:
                guard = getattr(old_entry.execution, "scope_guard", None)
                if not isinstance(guard, V2ProjectPolicyGuard):
                    raise Conflict("original_graph_update_original_policy_guard_required")
                policy = guard.enrollments.get(node.reference)
                if old is not None and policy is not old:
                    raise Conflict("original_graph_update_original_enrollment_changed")
                if not isinstance(policy, NativePolicyEnrollment):
                    raise Conflict("original_graph_update_original_policy_required")
            else:
                policy = NativePolicyEnrollment.model_validate(
                    {
                        "format": "native-project-policy-v1",
                        "reference": node.reference,
                        "native_project_id": record.native_project_id,
                        "contract_sha256": INSTALLED_SCHEMA,
                        "permission_source_sha256": PERMISSION_SOURCE,
                        "fingerprint_sha256": node.policy_sha256,
                        "operations": self.factory.policy.operations,
                    }
                )
            if (
                policy.reference != node.reference
                or policy.native_project_id != record.native_project_id
                or policy.contract_sha256 != record.contract_sha256
                or policy.fingerprint_sha256 != node.policy_sha256
            ):
                raise Conflict("original_graph_update_original_policy_changed")
            policies[node.reference] = policy
        return policies

    def _facades(
        self,
        root: SessionRef,
        entries: dict[SessionRef, RegisteredSession],
        policies: Mapping[SessionRef, NativePolicyEnrollment],
        settings: Mapping[SessionRef, ModelSettingsAttestation | None],
    ) -> None:
        root_entry = entries[root]
        execution = root_entry.execution
        if (
            not isinstance(execution, V2ExecutionClient)
            or not isinstance(execution.proofs, V2LeafResourceProofs)
            or not isinstance(execution.scope_guard, V2ProjectPolicyGuard)
        ):
            raise Conflict("original_graph_update_original_facade_required")
        proofs, guard = execution.proofs, execution.scope_guard
        attestation = self.factory.lineage
        assert attestation is not None
        attached = getattr(proofs, "_graph_publication", None)
        if attached is None:
            attach_graph_generation(proofs, guard, self.registry.publication, root, attestation)
        elif (
            attached.cell is not self.registry.publication
            or attached.root != root
            or attached.guard is not guard
            or attached.attestation is not attestation
        ):
            raise Conflict("original_graph_update_original_facade_changed")
        for ref in policies:
            if ref in entries:
                continue
            shared = (
                proofs.model_settings is not None
                and proofs.model_settings.qualification_scope == "backend"
                and settings[ref] is proofs.model_settings
            )
            if shared:
                selected_proofs, selected_guard = proofs, guard
            else:
                selected_proofs = V2LeafResourceProofs(
                    self.factory._feed, self.factory._proofs.projects, model_settings=settings[ref]
                )
                selected_guard = V2ProjectPolicyGuard(selected_proofs, policies)
                attach_graph_generation(
                    selected_proofs, selected_guard, self.registry.publication, root, attestation
                )
            client = V2ExecutionClient(
                self.factory._transport,
                self.factory._proofs.projects,
                proofs=selected_proofs,
                scope_guard=selected_guard,
            )
            reader = V2TurnResourceReader(client, attestation=self.factory._semantics)
            reader.qualify(ref)

            async def pending(
                selected: SessionRef,
                *,
                expected: SessionRef = ref,
                provider: V2LeafResourceProofs = selected_proofs,
            ) -> tuple[str, ...]:
                if selected != expected:
                    raise AccessDenied("original_graph_update_pending_reference_changed")
                return tuple(key for key, _ in (await provider.capture(selected)).pending)

            entries[ref] = RegisteredSession(
                ref,
                INSTALLED_SCHEMA,
                client,
                client.models,
                reader,
                pending,
                transcript=V2TranscriptReader(reader),
                metadata=V2NativeMetadataReader(client, ref),
                live_text=root_entry.live_text,
            )

    async def prepare(
        self, root: SessionRef, previous: SavedSessionRegistration, *, authorize: Authority
    ) -> PreparedSessionGraphUpdate | None:
        try:
            async with asyncio.timeout(5), self._gate:
                self._selected(root)
                generation = self._historical(root, previous)
                base = self.registry.publication.snapshot()
                await self._authorize(authorize)
                observation = await self.factory.observer.observe(root, authorize=authorize)
                record = self._record(self.factory, observation)
                same = registration_identity(record) == registration_identity(previous.record)
                if record.qualification_sha256 != previous.record.qualification_sha256:
                    # _historical admitted a legacy head. Re-seal exactly this
                    # live graph; a grown or changed one keeps failing.
                    if not same_original_graph(previous.record, record):
                        raise Conflict("original_graph_update_legacy_identity_changed")
                    return await self._build(
                        root, previous, generation, base, observation, record, False, authorize
                    )
                if not same:
                    try:
                        require_original_extension(previous.record, record)
                    except ValueError:
                        raise Conflict("original_graph_update_original_identity_changed") from None
                if (
                    same
                    and generation.record is not None
                    and isinstance(generation.context, GraphResourceContext)
                    and previous.state == "active"
                    and all(
                        generation.context.proofs.certified_epoch(ref, INSTALLED_SCHEMA) is not None
                        for ref in generation.entries
                    )
                ):
                    generation.context.require()
                    if registration_identity(generation.context.record) != registration_identity(
                        previous.record
                    ):
                        raise Conflict("original_graph_update_active_context_changed")
                    await self._authorize(authorize)
                    if (
                        self.registry.publication.snapshot() is not base
                        or not self.factory.observer.current(observation)
                    ):
                        raise Conflict("original_graph_update_publication_head_changed")
                    return None
                return await self._build(
                    root, previous, generation, base, observation, record, same, authorize
                )
        except TimeoutError:
            raise Conflict("original_graph_update_preparation_deadline_expired") from None

    async def prepare_initial(
        self, root: SessionRef, *, authorize: Authority
    ) -> PreparedSessionGraphUpdate:
        """Establish a first real baseline from original registered resource proof.

        No Saved record is invented. Existing refs/parents must already be the
        complete live graph; a leaf which has grown an unqualified child fails.
        The commit hook must insert the actual journal head under its SQL fence.
        """
        try:
            async with asyncio.timeout(5), self._gate:
                self._selected(root)
                generation = self.registry.publication.generation(root)
                if generation is None or generation.root != root or generation.record is not None:
                    raise Conflict("original_graph_initial_unrecorded_registered_root_required")
                base = self.registry.publication.snapshot()
                await self._authorize(authorize)
                # Roots created after this controller was composed were absent
                # from its constructor attach. Attach the existing stable reader
                # before any original watch/proof; no context or ref is added.
                self.attach_registered(only=root)
                witnesses = {}
                policies = {}
                assemblies = {}
                watched: set[int] = set()
                for ref, entry in generation.entries.items():
                    provider = getattr(entry.execution, "proofs", None)
                    if not isinstance(provider, V2LeafResourceProofs):
                        raise Conflict("original_graph_initial_original_resources_required")
                    # Reconcile the original registered provider; never a staged
                    # new reference. Unknown descendants still fail its codec.
                    if isinstance(provider, V2LineageResourceProofs):
                        if id(provider) not in watched:
                            await provider.watch_graph(authorize=authorize)
                            watched.add(id(provider))
                    else:
                        await self._authorize(authorize)
                        await provider.watch(ref)
                        await self._authorize(authorize)
                for ref, entry in generation.entries.items():
                    execution = entry.execution
                    if not isinstance(execution, V2ExecutionClient) or not isinstance(
                        execution.scope_guard, V2ProjectPolicyGuard
                    ):
                        raise Conflict("original_graph_initial_original_resources_required")
                    snapshot, proof = await execution.qualified_snapshot(ref)
                    if (
                        not snapshot.reconciled
                        or snapshot.state in {ExecutionState.UNKNOWN, ExecutionState.DISCONNECTED}
                        or set(snapshot.descendants) != set(generation.descendants[ref])
                    ):
                        raise Conflict("original_graph_initial_complete_registered_graph_required")
                    first = await execution.scope_guard.bundle(ref)
                    second = await execution.scope_guard.bundle(ref)
                    policy = execution.scope_guard.enrollments[ref]
                    if first != second or first != (
                        policy.fingerprint_sha256,
                        proof.session_info_sha256,
                    ):
                        raise Conflict("original_graph_initial_original_policy_changed")
                    witnesses[ref], policies[ref], assemblies[ref] = (
                        proof,
                        policy,
                        self._assembly(entry),
                    )
                observation = await self.factory.observer.observe(root, authorize=authorize)
                record = self._record(self.factory, observation)
                observed = {node.reference: node for node in observation.nodes}
                if set(observed) != set(generation.entries) or any(
                    node.parent_reference != generation.parents[ref]
                    for ref, node in observed.items()
                ):
                    raise Conflict("original_graph_initial_complete_registered_graph_required")
                original_nodes = {}
                for ref, entry in generation.entries.items():
                    execution = entry.execution
                    assert isinstance(execution, V2ExecutionClient)
                    node = observed[ref]
                    provider = execution.proofs
                    expected_info = (
                        node.progress_info_sha256
                        if isinstance(provider, V2LineageResourceProofs)
                        else node.session_info_sha256
                    )
                    if (
                        witnesses[ref].session_info_sha256 != expected_info
                        or policies[ref].fingerprint_sha256 != node.policy_sha256
                    ):
                        raise Conflict("original_graph_initial_original_metadata_changed")
                    original = OriginalSessionNode.model_validate(
                        node.model_dump(
                            include={
                                "reference",
                                "native_created_at",
                                "parent_reference",
                                "parent_created_at",
                                "policy_sha256",
                            }
                        )
                    )
                    if isinstance(provider, V2LineageResourceProofs):
                        known = provider.original_node(ref)
                        if (
                            OriginalSessionNode.model_validate(
                                known.model_dump(
                                    include={
                                        "reference",
                                        "native_created_at",
                                        "parent_reference",
                                        "parent_created_at",
                                        "policy_sha256",
                                    }
                                )
                            )
                            != original
                        ):
                            raise Conflict("original_graph_initial_original_identity_changed")
                    original_nodes[ref] = original

                def initial_current() -> bool:
                    try:
                        if (
                            self.registry.publication.snapshot() is not base
                            or not self.factory.observer.current(observation)
                        ):
                            return False
                        for ref, entry in generation.entries.items():
                            execution = entry.execution
                            assert isinstance(execution, V2ExecutionClient)
                            assert isinstance(execution.scope_guard, V2ProjectPolicyGuard)
                            if (
                                any(
                                    a is not b
                                    for a, b in zip(
                                        self._assembly(entry), assemblies[ref], strict=True
                                    )
                                )
                                or execution.scope_guard.enrollments.get(ref) is not policies[ref]
                            ):
                                return False
                            execution.current(ref, witnesses[ref])
                        return True
                    except (ValueError, AttributeError, KeyError):
                        return False

                if initial_current() is not True:
                    raise Conflict("original_graph_initial_original_proof_changed")
                return await self._build(
                    root,
                    None,
                    generation,
                    base,
                    observation,
                    record,
                    True,
                    authorize,
                    original_nodes=original_nodes,
                    initial_current=initial_current,
                )
        except TimeoutError:
            raise Conflict("original_graph_initial_deadline_expired") from None

    async def _build(
        self,
        root: SessionRef,
        previous: SavedSessionRegistration | None,
        generation: SessionGraphGeneration,
        base: BackendGraphState,
        observation: ExistingSessionGraphObservation,
        record: SessionAdoptionRecord,
        same: bool,
        authorize: Authority,
        *,
        original_nodes: Mapping[SessionRef, OriginalSessionNode] | None = None,
        initial_current: Callable[[], bool] | None = None,
    ) -> PreparedSessionGraphUpdate:
        for node in observation.nodes:
            await self.factory._feed.enroll_reference(node.reference, authorize=authorize)
        policies = self._enrollments(generation, record)
        entries = dict(generation.entries)
        root_proofs = getattr(entries[root].execution, "proofs", None)
        if not isinstance(root_proofs, V2LeafResourceProofs):
            raise Conflict("original_graph_update_original_facade_required")
        root_settings = root_proofs.model_settings
        settings: dict[SessionRef, ModelSettingsAttestation | None] = {}
        backend_settings = (
            root_settings
            if root_settings is not None and root_settings.qualification_scope == "backend"
            else self.factory._settings
        )
        if backend_settings is not None and backend_settings.qualification_scope != "backend":
            backend_settings = None
        for node in observation.nodes:
            ref = node.reference
            old = entries.get(ref)
            configured = (
                getattr(getattr(old.execution, "proofs", None), "model_settings", None)
                if old is not None
                else backend_settings
            )
            if configured is not None:
                configured.require(ref, INSTALLED_SCHEMA)
            settings[ref] = configured
        settings[root] = root_settings
        attestation = self.factory.lineage
        assert attestation is not None
        probe = V2LineageResourceProofs(
            self.factory._feed,
            self.factory._proofs.projects,
            observation,
            attestation,
            current=self.factory.observer.current,
            model_settings=root_settings,
            model_settings_by_reference=settings,
        )
        guard = V2LineagePolicyGuard(probe, policies)
        await probe.watch_graph(authorize=authorize)
        client = V2ExecutionClient(
            self.factory._transport,
            self.factory._proofs.projects,
            proofs=probe,
            scope_guard=guard,
        )
        for node in observation.nodes:
            snapshot, _ = await client.qualified_snapshot(node.reference)
            if not snapshot.reconciled or snapshot.state in {
                ExecutionState.UNKNOWN,
                ExecutionState.DISCONNECTED,
            }:
                raise Conflict("original_graph_update_complete_current_resources_required")
        context = GraphResourceContext(probe, guard, record)
        self._facades(root, entries, policies, settings)
        if self.registry.publication.snapshot() is not base:
            raise Conflict("original_graph_update_publication_head_changed")
        if generation.record is None:
            historical = (
                original_nodes
                if previous is None
                else {
                    node.reference: node
                    for node in previous.record.nodes
                    if node.reference in generation.entries
                }
            )
            if historical is None:
                raise Conflict("original_graph_update_historical_baseline_required")

            def baseline_current() -> bool:
                return bool(
                    self.registry.publication.snapshot() is base
                    and (initial_current is None or initial_current() is True)
                    and self.factory.observer.current(observation)
                    and all(
                        self.registry.sessions.get(ref) is entry
                        for ref, entry in generation.entries.items()
                    )
                    and all(probe.current_proof(ref) is not None for ref in entries)
                )

            prepared = self.registry.prepare_bootstrap_generation(
                record,
                entries,
                expected=generation,
                original_nodes=historical,
                baseline_current=baseline_current,
                enrollments=policies,
                context=context,
            )
        elif same and registration_identity(generation.record) == registration_identity(record):
            prepared = self.registry.prepare_refresh_generation(
                record, entries, expected=generation, enrollments=policies, context=context
            )
        else:
            prepared = self.registry.prepare_generation(
                record, entries, expected=generation, enrollments=policies, context=context
            )
        deadlines = [observation.expires_at]
        for ref in entries:
            proof = probe.current_proof(ref)
            if proof is None:
                raise Conflict("original_graph_update_original_resource_proof_changed")
            deadlines.append(proof.expires_at)
        expires = min(deadlines)
        candidate = PreparedSessionGraphUpdate(
            root, previous, record, context, MappingProxyType(entries), prepared, expires
        )
        while len(self._issued) >= 32:
            self._issued.popitem(last=False)
        self._issued[id(candidate)] = _Issued(
            weakref(candidate),
            self._seal(candidate),
            base,
            generation.entries,
            tuple(self._assembly(entry) for entry in candidate.entries.values()),
            self.factory._feed.index,
            self.factory._feed.task,
            self.factory._transport.attestation,
        )
        self.require(candidate)
        await self._authorize(authorize)
        self.require(candidate)
        return candidate

    async def qualify_publication(
        self, candidate: PreparedSessionGraphUpdate, *, authorize: Authority
    ) -> SessionSnapshot:
        """Run all remaining original commit GETs without publishing or journaling."""
        async with self.registry.generation_lock:
            issued = self.require(candidate)
            if issued.committing or issued.published is not None or issued.qualified_snapshots:
                raise Conflict("original_graph_update_already_qualified")
            await self._authorize(authorize)
            self.require(candidate)
            client = V2ExecutionClient(
                self.factory._transport,
                self.factory._proofs.projects,
                proofs=candidate.context.proofs,
                scope_guard=candidate.context.guard,
            )
            snapshots = {}
            for ref in candidate.entries:
                await self._authorize(authorize)
                self.require(candidate)
                snapshot, _ = await client.qualified_snapshot(ref)
                first = await candidate.context.guard.bundle(ref)
                second = await candidate.context.guard.bundle(ref)
                proof = candidate.context.proofs.current_proof(ref)
                if (
                    proof is None
                    or first != second
                    or first
                    != (
                        candidate.context.guard.enrollments[ref].fingerprint_sha256,
                        proof.session_info_sha256,
                    )
                ):
                    raise Conflict("original_graph_update_original_policy_or_resource_changed")
                self.require(candidate)
                snapshots[ref] = snapshot
            await self._authorize(authorize)
            self.require(candidate)
            issued.qualified_snapshots = MappingProxyType(snapshots)
            return snapshots[candidate.root]

    async def commit_publication(
        self,
        candidate: PreparedSessionGraphUpdate,
        *,
        authorize: Authority,
        before_commit: JournalUpdate,
    ) -> Mapping[SessionRef, RegisteredSession]:
        """SQL-only continuation of qualify_publication, retaining original CAS."""
        async with self.registry.generation_lock:
            issued = self.require(candidate)
            if (
                issued.committing
                or issued.published is not None
                or issued.qualified_snapshots is None
            ):
                raise Conflict("original_graph_update_publication_not_qualified")
            issued.committing = True
            try:
                await self._authorize(authorize)
                self.require(candidate)
                receipt = await before_commit(candidate.record)
                self.require(candidate)
                if (
                    not isinstance(receipt, RegistrationReceipt)
                    or receipt.key != registration_key(receipt.realm_id, candidate.root)
                    or receipt.project_id != candidate.root.project_id
                    or receipt.revision < 1
                    or receipt.identity_hash != registration_identity(candidate.record)
                    or receipt.payload_hash != digest(candidate.record.model_dump(mode="json"))
                    or candidate.previous is not None
                    and (
                        receipt.key != candidate.previous.receipt.key
                        or receipt.realm_id != candidate.previous.receipt.realm_id
                        or receipt.revision < candidate.previous.receipt.revision
                    )
                ):
                    raise Conflict("original_graph_update_journal_receipt_changed")
                bound = self.registry.bind_receipt(candidate.prepared, receipt)
                await self._authorize(authorize)
                self.require(candidate)
                if bound.baseline_current is not None and bound.baseline_current() is not True:
                    raise Conflict("original_graph_update_baseline_changed")
                self.require(candidate)
                published = self.registry.publish_generation(bound)
                issued.published = published
                return candidate.entries
            except BaseException:
                issued.consumed = True
                raise
            finally:
                issued.committing = False

    async def commit(
        self,
        candidate: PreparedSessionGraphUpdate,
        *,
        authorize: Authority,
        before_commit: JournalUpdate,
    ) -> Mapping[SessionRef, RegisteredSession]:
        async with self.registry.generation_lock:
            issued = self.require(candidate)
            if issued.committing or issued.published is not None:
                raise Conflict("original_graph_update_already_committed")
            issued.committing = True
            try:
                await self._authorize(authorize)
                self.require(candidate)
                client = V2ExecutionClient(
                    self.factory._transport,
                    self.factory._proofs.projects,
                    proofs=candidate.context.proofs,
                    scope_guard=candidate.context.guard,
                )
                for ref in candidate.entries:
                    await self._authorize(authorize)
                    self.require(candidate)
                    await client.qualified_snapshot(ref)
                    first = await candidate.context.guard.bundle(ref)
                    second = await candidate.context.guard.bundle(ref)
                    proof = candidate.context.proofs.current_proof(ref)
                    if (
                        proof is None
                        or first != second
                        or first
                        != (
                            candidate.context.guard.enrollments[ref].fingerprint_sha256,
                            proof.session_info_sha256,
                        )
                    ):
                        raise Conflict("original_graph_update_original_policy_or_resource_changed")
                    self.require(candidate)
                await self._authorize(authorize)
                self.require(candidate)
                receipt = await before_commit(candidate.record)
                self.require(candidate)
                if (
                    not isinstance(receipt, RegistrationReceipt)
                    or receipt.key != registration_key(receipt.realm_id, candidate.root)
                    or receipt.project_id != candidate.root.project_id
                    or receipt.revision < 1
                    or receipt.identity_hash != registration_identity(candidate.record)
                    or receipt.payload_hash != digest(candidate.record.model_dump(mode="json"))
                    or candidate.previous is not None
                    and (
                        receipt.key != candidate.previous.receipt.key
                        or receipt.realm_id != candidate.previous.receipt.realm_id
                        or receipt.revision < candidate.previous.receipt.revision
                    )
                ):
                    raise Conflict("original_graph_update_journal_receipt_changed")
                bound = self.registry.bind_receipt(candidate.prepared, receipt)
                await self._authorize(authorize)
                self.require(candidate)
                if bound.baseline_current is not None and bound.baseline_current() is not True:
                    raise Conflict("original_graph_update_baseline_changed")
                self.require(candidate)
                # Publication itself performs no await, I/O or external callback.
                published = self.registry.publish_generation(bound)
                issued.published = published
                return candidate.entries
            except BaseException:
                issued.consumed = True
                raise
            finally:
                issued.committing = False
