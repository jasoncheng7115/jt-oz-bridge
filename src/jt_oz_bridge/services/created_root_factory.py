"""Qualified new/used Root assembly on the original feed, outside chat routing.

Only trusted composition supplies the creation/policy anchors and authority
callback. Assembly never creates Native sessions, starts turns, grants users or
activates bindings. The durable coordinator must do the latter separately.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace

from jt_oz_bridge.adapters.opencode.creation_policy import DerivedCreationPolicy, V2CreationPolicy
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof, V2ExecutionClient
from jt_oz_bridge.adapters.opencode.files import V2NativeFileReader
from jt_oz_bridge.adapters.opencode.graph_generation import (
    GraphResourceContext,
    attach_graph_generation,
)
from jt_oz_bridge.adapters.opencode.lineage_resources import (
    LINEAGE_SEMANTICS,
    LineageResourceAttestation,
)
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.project_policy import (
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
)
from jt_oz_bridge.adapters.opencode.resources import READS, V2LeafResourceProofs
from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
from jt_oz_bridge.adapters.opencode.turn_resources import V2TurnResourceReader
from jt_oz_bridge.adapters.opencode.workspace_catalog import V2WorkspaceCatalog
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_creation import (
    CreatedRootObservation,
    NewSessionCandidate,
    SessionCreationIntent,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.live_capture import LiveTextCollector
from jt_oz_bridge.services.session_graph_generations import (
    BackendGraphState,
    PreparedGraphGeneration,
)
from jt_oz_bridge.services.session_registration_journal import (
    RegistrationReceipt,
    registration_identity,
    registration_key,
)
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.durable import Conflict, digest

Authority = Callable[[], Awaitable[bool]]


@dataclass(frozen=True)
class _Registration:
    entry: RegisteredSession
    intent_sha256: str
    native_created_at: int
    execution: V2ExecutionClient
    proofs: V2LeafResourceProofs
    guard: V2ProjectPolicyGuard
    policy: NativePolicyEnrollment
    attestation: ContractAttestation | None


@dataclass(frozen=True, eq=False)
class PreparedCreatedRestore:
    """Unpublished issuer-owned creation data, not route or graph authority."""

    entry: RegisteredSession
    policy: NativePolicyEnrollment
    origin: CreatedRootObservation


@dataclass(frozen=True)
class _RestoreStage:
    registration: _Registration
    intent: SessionCreationIntent
    receipt: NewSessionCandidate
    derived: DerivedCreationPolicy
    origin: CreatedRootObservation
    base: BackendGraphState
    task: object
    index: object
    feed_task: asyncio.Task[None] | None
    owner: object
    expires_at: float
    lineage: LineageResourceAttestation
    assembly: tuple[object, ...]


@dataclass(frozen=True)
class CreatedRootPolicyProof:
    """Original, short-lived read-only observation; not a Native mutation grant."""

    reference: SessionRef
    execution_proof: OriginalExecutionProof
    fingerprint_sha256: str
    checked_at: float
    expires_at: float


class V2CreatedRootFactory:
    def __init__(
        self,
        creator: V2SessionCreation,
        policies: V2CreationPolicy,
        registry: SessionRegistry,
        *,
        files: V2NativeFileReader | None = None,
        catalog: V2WorkspaceCatalog | None = None,
    ) -> None:
        self.creator, self.policies, self.registry = creator, policies, registry
        ref = policies.template.source.reference
        self.anchor = registry.selected(ref)
        # The source Root's own file read, reused only for Roots with the same rules.
        if (
            files is not None
            and (
                files.client is not self.anchor.execution
                or files.attestation is None
                or files.attestation.reference != ref
            )
            or catalog is not None
            and (
                files is None
                or catalog.client is not self.anchor.execution
                or set(catalog.attestations) != {ref}
                or catalog.directories is None
            )
        ):
            raise ValueError("created_root_file_read_must_be_the_source_roots")
        self._files, self._catalog = files, catalog
        if (
            not isinstance(self.anchor.execution, V2ExecutionClient)
            or self.anchor.execution.scope_guard is not policies.anchor
            or not isinstance(policies.anchor.proofs, V2LeafResourceProofs)
            or self.anchor.execution.proofs is not policies.anchor.proofs
            or creator.transport is not self.anchor.execution.transport
            or creator.transport is not policies.anchor.proofs.feed.transport
            or creator.owner is not policies.anchor.proofs.feed.owner
            or not isinstance(self.anchor.results, V2TurnResourceReader)
            or self.anchor.results.client is not self.anchor.execution
            or self.anchor.results.attestation is None
            or creator.templates.get(ref.project_id) != policies.template.creation
            or registry.projects.get(ref.project_id) != ref.canonical_directory
            or self.anchor.live_text is not None
            and (
                not isinstance(self.anchor.live_text, LiveTextCollector)
                or self.anchor.live_text.feed is not policies.anchor.proofs.feed
            )
        ):
            raise ValueError("created_root_original_runtime_graph_required")
        self.feed = policies.anchor.proofs.feed
        self._template = policies.template
        self._semantics = self.anchor.results.attestation
        self._model_settings = policies.anchor.proofs.model_settings
        self._lock = asyncio.Lock()
        self._records: dict[SessionRef, _Registration] = {}
        self._restore_stages: dict[PreparedCreatedRestore, _RestoreStage] = {}
        self._policies: dict[SessionRef, CreatedRootPolicyProof] = {}
        self.anchor.results.qualify(ref)

    def selected(self, intent: SessionCreationIntent) -> SessionRef:
        ref = SessionRef(**intent.scope.model_dump(), upstream_session_id=intent.native_session_id)
        # Keep explicit pointer checks: equivalent copied graphs are not the
        # original registered execution/transport/feed or semantic authority.
        execution = self.anchor.execution
        if (
            not isinstance(execution, V2ExecutionClient)
            or self.policies.template != self._template
            or self.registry.sessions.get(self._template.source.reference) is not self.anchor
            or execution.scope_guard is not self.policies.anchor
            or execution.proofs is not self.policies.anchor.proofs
            or execution.transport is not self.creator.transport
            or self.policies.anchor.proofs.feed is not self.feed
            or self.creator.owner is not self.feed.owner
            or self.creator.transport is not self.feed.transport
            or not isinstance(self.anchor.results, V2TurnResourceReader)
            or self.anchor.results.client is not execution
            or self.anchor.results.attestation is not self._semantics
            or self.policies.anchor.proofs.model_settings is not self._model_settings
            or self.creator.templates.get(ref.project_id) != self._template.creation
            or intent.scope != self._template.creation.scope
            or self.anchor.live_text is not None
            and (
                not isinstance(self.anchor.live_text, LiveTextCollector)
                or self.anchor.live_text.feed is not self.feed
            )
        ):
            raise Conflict("created_root_factory_anchor_changed")
        self.creator.selected(intent)
        return ref

    def watched_roots(self) -> tuple[tuple[SessionRef, V2LeafResourceProofs], ...]:
        """Registered created Roots and their own leaf proofs, for the watch keeper."""
        return tuple((ref, saved.proofs) for ref, saved in self._records.items())

    def registered(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        entry: RegisteredSession,
    ) -> None:
        """Synchronous original-record check; this does not refresh authority."""
        ref = self.selected(intent)
        saved = self._records.get(ref)
        if (
            saved is None
            or saved.entry is not entry
            or self.registry.sessions.get(ref) is not entry
            or saved.intent_sha256 != digest(intent.model_dump(mode="json"))
            or saved.native_created_at != receipt.native_created_at
            or receipt.reference != ref
            or receipt.intent_sha256 != saved.intent_sha256
            or entry.execution is not saved.execution
            or saved.execution.transport is not self.creator.transport
            or saved.execution.proofs is not saved.proofs
            or saved.execution.scope_guard is not saved.guard
            or saved.proofs.feed is not self.feed
            or saved.guard.proofs is not saved.proofs
            or saved.guard.enrollments.get(ref) != saved.policy
            or not isinstance(entry.results, V2TurnResourceReader)
            or entry.results.client is not saved.execution
            or entry.results.attestation is not self._semantics
            or self.creator.transport.attestation is not saved.attestation
        ):
            raise Conflict("created_root_original_registration_changed")

    async def observe_policy(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        entry: RegisteredSession,
        proof: OriginalExecutionProof,
    ) -> CreatedRootPolicyProof:
        """Double-read original policy with qualified idle or active resources.

        Native mutation guards keep their existing stricter contract. This
        observation can only support registration/restore, never submit a turn.
        """
        self.registered(intent, receipt, entry)
        saved = self._records[entry.reference]
        self._policies.pop(entry.reference, None)
        owner = await self.creator.original_owner(intent, same_process=False)
        first = await saved.guard.bundle(entry.reference)
        second = await saved.guard.bundle(entry.reference)
        await self.creator.original_owner(intent, same_process=False, epoch=owner.owner_epoch)
        self.registered(intent, receipt, entry)
        saved.execution.current(entry.reference, proof)
        if first != second or first != (saved.policy.fingerprint_sha256, proof.session_info_sha256):
            raise Conflict("created_root_current_policy_changed")
        now = time.time()
        observed = CreatedRootPolicyProof(entry.reference, proof, first[0], now, now + 5)
        self._policies[entry.reference] = observed
        return observed

    def policy_current(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        entry: RegisteredSession,
        proof: OriginalExecutionProof,
        observed: CreatedRootPolicyProof,
    ) -> None:
        self.registered(intent, receipt, entry)
        saved = self._records[entry.reference]
        saved.execution.current(entry.reference, proof)
        if (
            self._policies.get(entry.reference) is not observed
            or observed.reference != entry.reference
            or observed.execution_proof is not proof
            or observed.fingerprint_sha256 != saved.policy.fingerprint_sha256
            or not observed.checked_at <= time.time() < observed.expires_at
            or not 0 < observed.expires_at - observed.checked_at <= 5
        ):
            raise Conflict("created_root_original_policy_observation_changed")

    async def prepare_restore(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        *,
        authorize: Authority,
        lineage: LineageResourceAttestation | None = None,
    ) -> PreparedCreatedRestore:
        """Stage the original created Root without a leaf watch or publication.

        Trusted activation must authenticate its real creation ledger first.
        This handle supplies creation provenance, never graph/SQL authority.
        """
        async with asyncio.timeout(5), self._lock:
            ref = self.selected(intent)
            self._require_restore_lineage(ref, lineage)
            assert lineage is not None
            if ref in self.registry.sessions or ref in self._records:
                raise Conflict("created_restore_absent_original_registration_required")
            if await authorize() is not True:
                raise AccessDenied("created_restore_current_authority_required")
            NewSessionCandidate.model_validate(receipt.model_dump(mode="json"))
            base = self.registry.publication.snapshot()
            derived = await self.policies.derive(intent)
            origin = await self.creator.observe_existing(intent, receipt)

            async def current() -> bool:
                self.selected(intent)
                return bool(
                    self.registry.publication.snapshot() is base
                    and ref not in self.registry.sessions
                    and await authorize() is True
                    and await self.policies.current(intent, derived)
                    and await self.creator.existing_current(intent, receipt, origin)
                    and await authorize() is True
                )

            settings = self._model_settings
            if settings is not None:
                # Preserve existing creation behavior, including refusal of an
                # anchor-session-only codec which does not qualify this Root.
                settings.require(ref, self.creator.transport.profile.sha256)
            await self.feed.enroll_reference(ref, authorize=current)
            if not await current():
                raise Conflict("created_restore_original_provenance_changed")
            source_proofs = self.policies.anchor.proofs
            proofs = V2LeafResourceProofs(
                self.feed, source_proofs.projects, model_settings=settings
            )
            guard = V2ProjectPolicyGuard(proofs, {ref: derived.enrollment})
            execution = V2ExecutionClient(
                self.creator.transport, source_proofs.projects, proofs=proofs, scope_guard=guard
            )
            reader = V2TurnResourceReader(execution, attestation=self._semantics)
            reader.qualify(ref)
            files, catalog = self._reads(ref, derived, execution)

            async def pending(selected: SessionRef) -> tuple[str, ...]:
                if selected != ref:
                    raise AccessDenied("created_restore_pending_scope_changed")
                return tuple(identity for identity, _ in (await proofs.capture(ref)).pending)

            entry = RegisteredSession(
                ref,
                self.creator.transport.profile.sha256,
                execution,
                execution.models,
                reader,
                pending,
                transcript=V2TranscriptReader(reader),
                metadata=V2NativeMetadataReader(execution, ref),
                live_text=self.anchor.live_text,
                files=files,
                catalog=catalog,
            )
            registration = _Registration(
                entry,
                digest(intent.model_dump(mode="json")),
                receipt.native_created_at,
                execution,
                proofs,
                guard,
                derived.enrollment,
                self.creator.transport.attestation,
            )
            # Attach only this still-unpublished facade, once, before sealing
            # its complete assembly. No later arbitrary rebaseline is allowed.
            attach_graph_generation(proofs, guard, self.registry.publication, ref, lineage)
            stage = PreparedCreatedRestore(entry, derived.enrollment, origin)
            while len(self._restore_stages) >= 32:
                self._restore_stages.pop(next(iter(self._restore_stages)))
            self._restore_stages[stage] = _RestoreStage(
                registration,
                intent,
                receipt,
                derived,
                origin,
                base,
                asyncio.current_task(),
                self.feed.index,
                self.feed.task,
                self.feed.owner,
                min(origin.observed_at + 5, derived.observed_at + 5),
                lineage,
                self._restore_assembly(entry),
            )
            self.require_restore(stage)
            return stage

    def _require_restore_lineage(
        self, ref: SessionRef, lineage: LineageResourceAttestation | None
    ) -> None:
        captured = self.creator.transport.attestation
        if (
            not isinstance(lineage, LineageResourceAttestation)
            or lineage.qualification_scope != "tree"
            or (lineage.backend_id, lineage.backend_identity)
            != (ref.backend_id, ref.backend_identity)
            or lineage.contract_sha256 != self.creator.transport.profile.sha256
            or lineage.semantics != LINEAGE_SEMANTICS
            or len(lineage.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in lineage.installed_evidence_sha256)
            or type(lineage.operations) is not frozenset
            or not READS <= lineage.operations
            or captured is None
            or not lineage.operations <= captured.verified_operations
        ):
            raise Conflict("created_restore_independent_tree_qualification_required")

    @staticmethod
    def _restore_assembly(entry: RegisteredSession) -> tuple[object, ...]:
        execution = entry.execution
        if not isinstance(execution, V2ExecutionClient):
            raise Conflict("created_restore_original_execution_required")
        proofs, guard = execution.proofs, execution.scope_guard
        return (
            entry,
            execution,
            execution.transport,
            execution.transport.client,
            execution.transport.profile,
            execution.transport.attestation,
            proofs,
            guard,
            getattr(guard, "enrollments", None),
            getattr(proofs, "feed", None),
            getattr(proofs, "model_settings", None),
            getattr(proofs, "_graph_publication", None),
            getattr(guard, "_graph_publication", None),
            entry.models,
            execution.models,
            getattr(entry.models, "transport", None),
            getattr(entry.models, "projects", None),
            entry.results,
            getattr(entry.results, "client", None),
            getattr(entry.results, "proofs", None),
            getattr(entry.results, "attestation", None),
            getattr(entry.results, "attachments", None),
            entry.pending,
            entry.transcript,
            getattr(entry.transcript, "qualified", None),
            getattr(entry.transcript, "client", None),
            entry.metadata,
            getattr(entry.metadata, "client", None),
            getattr(entry.metadata, "reference", None),
            entry.live_text,
            getattr(entry.live_text, "feed", None),
            execution.attachments,
            execution.workspace_attachments,
            entry.files,
            getattr(entry.files, "client", None),
            getattr(entry.files, "attestation", None),
            entry.catalog,
            getattr(entry.catalog, "client", None),
            getattr(entry.catalog, "attestations", None),
            getattr(entry.catalog, "directories", None),
        )

    def _reads(
        self, ref: SessionRef, derived: DerivedCreationPolicy, execution: V2ExecutionClient
    ) -> tuple[V2NativeFileReader | None, V2WorkspaceCatalog | None]:
        """The source Root's file read, re-keyed to this Root, when the rules match.

        The evidence describes how this OpenCode serves files for that project and
        policy. Each read still checks this Root's own live policy and owner.
        """
        if not derived.same_as_source or self._files is None:
            return None, None
        assert self._files.attestation is not None
        policy = derived.enrollment.fingerprint_sha256
        files = V2NativeFileReader(
            execution,
            attestation=replace(
                self._files.attestation, reference=ref, native_policy_sha256=policy
            ),
        )
        if self._catalog is None:
            return files, None
        source = self._catalog.attestations[self.policies.template.source.reference]
        catalog = V2WorkspaceCatalog(
            execution,
            {ref: replace(source, reference=ref, native_policy_sha256=policy)},
            directories=self._catalog.directories,
        )
        return files, catalog

    def require_restore(self, stage: PreparedCreatedRestore) -> _Registration:
        """Issuer/scope/age pins only; graph proof and current SQL are additional.

        No origin timestamp, observation, record or resource proof is refreshed.
        The actual graph controller must also recheck its complete detached
        Native graph and journal/current authority immediately before publish.
        """
        owned = self._restore_stages.get(stage)
        if owned is None or type(stage) is not PreparedCreatedRestore:
            raise Conflict("created_restore_stage_not_issued")
        saved = owned.registration
        ref = self.selected(owned.intent)
        self._require_restore_lineage(ref, owned.lineage)
        binding = getattr(saved.proofs, "_graph_publication", None)
        if (
            owned.task is None
            or asyncio.current_task() is not owned.task
            or self.registry.publication.snapshot() is not owned.base
            or ref in self.registry.sessions
            or ref in self._records
            or stage.entry is not saved.entry
            or stage.policy is not saved.policy
            or stage.origin is not owned.origin
            or stage.origin.reference != ref
            or stage.origin.intent_sha256 != saved.intent_sha256
            or stage.origin.creation_receipt_sha256 != digest(owned.receipt.model_dump(mode="json"))
            or stage.origin.native_created_at != saved.native_created_at
            or owned.derived.enrollment is not saved.policy
            or owned.derived.intent_sha256 != saved.intent_sha256
            or digest(owned.intent.model_dump(mode="json")) != saved.intent_sha256
            or self.feed.index is not owned.index
            or self.feed.task is not owned.feed_task
            or self.feed.owner is not owned.owner
            or owned.feed_task is None
            or owned.feed_task.done()
            or owned.feed_task.cancelling()
            or binding is None
            or binding.cell is not self.registry.publication
            or binding.root != ref
            or binding.proofs is not saved.proofs
            or binding.guard is not saved.guard
            or binding.attestation is not owned.lineage
            or getattr(saved.guard, "_graph_publication", None) is not binding
            or any(
                actual is not expected
                for actual, expected in zip(
                    self._restore_assembly(saved.entry), owned.assembly, strict=True
                )
            )
            or self.creator.transport.attestation is not saved.attestation
            or saved.entry.execution is not saved.execution
            or saved.execution.transport is not self.creator.transport
            or saved.execution.proofs is not saved.proofs
            or saved.proofs.model_settings is not self._model_settings
            or not isinstance(saved.entry.results, V2TurnResourceReader)
            or saved.entry.results.client is not saved.execution
            or saved.entry.results.attestation is not self._semantics
            or saved.execution.scope_guard is not saved.guard
            or saved.proofs.feed is not self.feed
            or saved.guard.proofs is not saved.proofs
            or saved.guard.enrollments.get(ref) is not saved.policy
            or not 0 <= time.time() - owned.origin.observed_at < 5
            or not 0 <= time.time() - owned.derived.observed_at < 5
            or not time.time() < owned.expires_at
        ):
            raise Conflict("created_restore_original_stage_changed")
        return saved

    def publish_restore(
        self, stage: PreparedCreatedRestore, candidate: PreparedGraphGeneration
    ) -> RegisteredSession:
        """Trusted controller's final no-await cell+creation-provenance append.

        The caller must finish actual ledger/grants/graph CAS and Native checks
        first. A detached graph candidate, not a fake registered singleton,
        supplies complete entries and an actual returned journal receipt.
        """
        saved = self.require_restore(stage)
        ref = saved.entry.reference
        owned = self._restore_stages[stage]
        generation = candidate.generation
        record, context, receipt = generation.record, generation.context, generation.receipt
        root_node = (
            next((node for node in record.nodes if node.reference == ref), None)
            if record is not None
            else None
        )
        if (
            candidate._base is not owned.base
            or candidate._base is not self.registry.publication.snapshot()
            or generation.root != ref
            or generation.entries.get(ref) is not saved.entry
            or generation.enrollments.get(ref) is not saved.policy
            or record is None
            or record.root != ref
            or root_node is None
            or root_node.native_created_at != saved.native_created_at
            or root_node.policy_sha256 != saved.policy.fingerprint_sha256
            or not isinstance(context, GraphResourceContext)
            or context.record != record
            or context.guard.enrollments.get(ref) is not saved.policy
            or context.proofs.feed is not self.feed
            or context.proofs.lineage_attestation is not owned.lineage
            or set(context.guard.enrollments) != set(generation.enrollments)
            or any(
                context.guard.enrollments[ref] is not policy
                for ref, policy in generation.enrollments.items()
            )
            or not isinstance(receipt, RegistrationReceipt)
            or receipt.key != registration_key(receipt.realm_id, ref)
            or receipt.identity_hash != registration_identity(record)
            or receipt.payload_hash != digest(record.model_dump(mode="json"))
            or receipt.project_id != ref.project_id
            or receipt.revision < 1
        ):
            raise Conflict("created_restore_complete_qualified_graph_required")
        context.require()
        deadlines = [owned.expires_at]
        for item in record.nodes:
            proof = context.proofs.current_proof(item.reference)
            if proof is None:
                raise Conflict("created_restore_complete_native_proof_not_current")
            deadlines.append(proof.expires_at)
        # Synchronous validation can itself consume the remaining time. Later
        # graph proofs never renew the earlier creation provenance deadline.
        context.require()
        self.require_restore(stage)
        if not time.time() < min(deadlines):
            raise Conflict("created_restore_earliest_proof_deadline_expired")
        # Never pass any callback or perform I/O after these checks. The cell
        # independently authenticates issuance and its entire early-base CAS.
        self._restore_stages.pop(stage)
        self.registry.publish_generation(candidate)
        self._records[ref] = saved
        return saved.entry

    async def register(
        self,
        intent: SessionCreationIntent,
        receipt: NewSessionCandidate,
        *,
        authorize: Authority,
        restore: bool = False,
    ) -> RegisteredSession:
        """Append one complete Root; restoration reads only the same Native ID.

        A historical receipt must come from the owned durable coordinator. It
        is not itself live authority. Repeated registration returns this exact
        factory's original record only after fresh origin/policy/authority reads.
        """
        async with self._lock:
            ref = self.selected(intent)
            if await authorize() is not True:
                raise AccessDenied("created_root_current_authority_required")
            NewSessionCandidate.model_validate(receipt.model_dump(mode="json"))
            derived = await self.policies.derive(intent)
            observed: CreatedRootObservation | None = None
            if restore:
                observed = await self.creator.observe_existing(intent, receipt)
            elif not await self.creator.current(intent, receipt):
                raise Conflict("created_root_original_pristine_candidate_required")

            async def current() -> bool:
                self.selected(intent)
                if await authorize() is not True or not await self.policies.current(
                    intent, derived
                ):
                    return False
                valid = (
                    await self.creator.existing_current(intent, receipt, observed)
                    if observed is not None
                    else await self.creator.current(intent, receipt)
                )
                return valid and await authorize() is True

            previous = self.registry.sessions.get(ref)
            if previous is not None:
                saved = self._records.get(ref)
                if (
                    saved is None
                    or saved.entry is not previous
                    or saved.intent_sha256 != digest(intent.model_dump(mode="json"))
                    or saved.native_created_at != receipt.native_created_at
                    or not await current()
                ):
                    raise Conflict("created_root_existing_registration_cannot_be_replaced")
                execution = previous.execution
                self.registered(intent, receipt, previous)
                if not isinstance(execution, V2ExecutionClient):
                    raise Conflict("created_root_existing_graph_changed")
                snapshot, proof = await execution.qualified_snapshot(ref)
                if (
                    not snapshot.reconciled
                    or not restore
                    and snapshot.state != ExecutionState.IDLE
                    or not await current()
                ):
                    raise Conflict("created_root_existing_resources_not_current")
                execution.current(ref, proof)
                return previous
            source_proofs = self.policies.anchor.proofs
            settings = self._model_settings
            if settings is not None:
                settings.require(ref, self.creator.transport.profile.sha256)
            await self.feed.enroll_reference(ref, authorize=current)
            proofs = V2LeafResourceProofs(
                self.feed, source_proofs.projects, model_settings=settings
            )
            guard = V2ProjectPolicyGuard(proofs, {ref: derived.enrollment})
            execution = V2ExecutionClient(
                self.creator.transport, source_proofs.projects, proofs=proofs, scope_guard=guard
            )
            await proofs.watch(ref)
            reader = V2TurnResourceReader(execution, attestation=self._semantics)
            reader.qualify(ref)
            files, catalog = self._reads(ref, derived, execution)

            async def pending(selected: SessionRef) -> tuple[str, ...]:
                if selected != ref:
                    raise AccessDenied("created_root_pending_scope_changed")
                return tuple(identity for identity, _ in (await proofs.capture(ref)).pending)

            entry = RegisteredSession(
                ref,
                self.creator.transport.profile.sha256,
                execution,
                execution.models,
                reader,
                pending,
                transcript=V2TranscriptReader(reader),
                metadata=V2NativeMetadataReader(execution, ref),
                live_text=self.anchor.live_text,
                files=files,
                catalog=catalog,
            )

            async def adopt_authority() -> bool:
                if not await current():
                    return False
                fingerprint, _ = await guard.bundle(ref)
                if fingerprint != derived.enrollment.fingerprint_sha256:
                    return False
                snapshot, proof = await execution.qualified_snapshot(ref)
                if not restore and snapshot.state != ExecutionState.IDLE:
                    return False
                if not await current():
                    return False
                # The final authority checks above may have yielded to a new
                # Native arrival. Validate the original resource fence/age
                # synchronously before the registry's no-await insertion.
                execution.current(ref, proof)
                return True

            await self.registry.adopt(entry, authorize=adopt_authority)
            # No await after registry insertion: a cancellation cannot leave an
            # adopted entry without its matching factory recovery identity.
            self._records[ref] = _Registration(
                entry,
                digest(intent.model_dump(mode="json")),
                receipt.native_created_at,
                execution,
                proofs,
                guard,
                derived.enrollment,
                self.creator.transport.attestation,
            )
            return entry
