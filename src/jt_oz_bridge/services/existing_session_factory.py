"""Prepare/commit the same original existing session graph without Native writes.

Trusted composition supplies backend-scope codecs and explicit operation policy.
The durable controller supplies current Human/project/source/audience authority
and its prepared-journal hook. This factory never creates/forks sessions, starts
turns, creates bindings or silently grants optional file/check/Git capabilities.
"""

import asyncio
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType
from weakref import ReferenceType, WeakKeyDictionary
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.existing_session_graph import V2ExistingSessionGraphObserver
from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
from jt_oz_bridge.adapters.opencode.lineage_resources import (
    LINEAGE_SEMANTICS,
    LineageResourceAttestation,
    V2LineageResourceProofs,
)
from jt_oz_bridge.adapters.opencode.model_catalog import READS as MODEL_READS
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.project_policy import PERMISSION_SOURCE, NativePolicyEnrollment
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, READS
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.turn_resources import V2TurnResourceReader
from jt_oz_bridge.domain.existing_sessions import ExistingSessionGraphObservation
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.runtime_readiness import RootModeFact, scope_key
from jt_oz_bridge.domain.session_adoption import (
    LEGACY_RECORD_FORMAT,
    RECORD_FORMAT,
    OriginalSessionNode,
    SessionAdoptionPolicy,
    SessionAdoptionRecord,
    same_original_graph,
)
from jt_oz_bridge.domain.session_graph_extension import require_original_extension
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.live_capture import LiveTextCollector
from jt_oz_bridge.services.session_graph_generations import PreparedGraphGeneration
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.durable import Conflict, digest

Authority = Callable[[], Awaitable[bool]]
JournalPrepare = Callable[[SessionAdoptionRecord], Awaitable[None]]


@dataclass(frozen=True)
class PreparedExistingGraph:
    observation: ExistingSessionGraphObservation
    entries: Mapping[SessionRef, RegisteredSession]
    parents: Mapping[SessionRef, SessionRef | None]
    proofs: V2LineageResourceProofs
    guard: V2LineagePolicyGuard
    record: SessionAdoptionRecord
    expires_at: float


@dataclass(frozen=True)
class _Prepared:
    original: ReferenceType[PreparedExistingGraph]
    entries: object
    parents: object
    proofs: object
    guard: object
    record: object
    attestation: object


class V2ExistingSessionFactory:
    def __init__(
        self,
        observer: V2ExistingSessionGraphObserver,
        registry: SessionRegistry,
        policy: SessionAdoptionPolicy,
        *,
        lineage: LineageResourceAttestation | None = None,
    ) -> None:
        self.observer, self.registry, self.policy, self.lineage = (
            observer,
            registry,
            policy,
            lineage,
        )
        self._observer, self._registry, self._policy, self._lineage = (
            observer,
            registry,
            policy,
            lineage,
        )
        self.anchor = registry.selected(policy.anchor)
        self._anchor = self.anchor
        execution = self.anchor.execution
        if not isinstance(execution, V2ExecutionClient):
            raise ValueError("existing_session_original_native_anchor_required")
        self._execution = execution
        self._proofs = observer.observer.anchor.proofs
        self._feed = self._proofs.feed
        self._transport = execution.transport
        self._settings = self._proofs.model_settings
        if (
            not isinstance(self.anchor.results, V2TurnResourceReader)
            or self.anchor.results.attestation is None
        ):
            raise ValueError("existing_session_original_turn_semantics_required")
        self._semantics = self.anchor.results.attestation
        self._prepared: OrderedDict[int, _Prepared] = OrderedDict()
        self._registered: dict[SessionRef, PreparedExistingGraph] = {}
        self._publications: WeakKeyDictionary[PreparedGraphGeneration, PreparedExistingGraph] = (
            WeakKeyDictionary()
        )
        self._mode_facts: dict[SessionRef, tuple[tuple[object, ...], RootModeFact]] = {}
        self._gate = asyncio.Lock()
        self.selected(policy.anchor)

    def owns(self, target: SessionRef) -> bool:
        original = self._registered.get(target)
        return original is not None and all(
            self.registry.sessions.get(ref) is entry for ref, entry in original.entries.items()
        )

    def mode_facts(self) -> tuple[RootModeFact, ...]:
        """Controller diagnostics only; no Native reads or mutation membership changes."""
        result = []
        for root, candidate in self._registered.items():
            for ref, entry in candidate.entries.items():
                epoch = None
                try:
                    self.selected(root)
                    if self.owns(root) and self.registry.sessions.get(ref) is entry:
                        epoch = candidate.proofs.diagnostic_epoch(ref)
                except (ValueError, TypeError):
                    pass
                context = (
                    self._feed.index,
                    self._feed.task,
                    self._transport.attestation,
                    epoch,
                    candidate.record.graph_sha256,
                )
                previous = self._mode_facts.get(ref)
                transition = (
                    previous[1].transition_at
                    if previous is not None and previous[0] == context
                    else time.time()
                )
                fact = RootModeFact(
                    scope_key=scope_key(ref),
                    mode="strict" if epoch is not None else "unavailable",
                    reason="strict-observation" if epoch is not None else "feed-unavailable",
                    transition_at=float(transition),
                )
                self._mode_facts[ref] = context, fact
                result.append(fact)
        return tuple(result)

    def selected(self, target: SessionRef) -> None:
        self.observer.require(target)
        source = self.observer.observer.anchor.enrollments.get(self.policy.anchor)
        native = self._transport.attestation
        if (
            self.observer is not self._observer
            or self.registry is not self._registry
            or self.policy is not self._policy
            or self.lineage is not self._lineage
            or self.anchor is not self._anchor
            or self.registry.sessions.get(self.policy.anchor) is not self.anchor
            or self.anchor.execution is not self._execution
            or self._execution.proofs is not self._proofs
            or self._execution.scope_guard is not self.observer.observer.anchor
            or self._execution.transport is not self._transport
            or self._proofs.feed is not self._feed
            or self._feed.transport is not self._transport
            or self._proofs.model_settings is not self._settings
            or self.observer.observer.reference != self.policy.anchor
            or source is None
            or not self.policy.operations <= source.operations
            or "check.run" in self.policy.operations
            or self.policy.installed_protocol_evidence_sha256
            != self.observer.observer.protocol.installed_evidence_sha256
            or self.lineage is not None
            and (
                (self.lineage.backend_id, self.lineage.backend_identity)
                != (target.backend_id, target.backend_identity)
                or self.lineage.contract_sha256 != INSTALLED_SCHEMA
                or self.lineage.semantics != LINEAGE_SEMANTICS
                or self.lineage.qualification_scope not in {"leaf", "tree"}
                or re.fullmatch(r"[0-9a-f]{64}", self.lineage.installed_evidence_sha256) is None
                or type(self.lineage.operations) is not frozenset
                or not READS <= self.lineage.operations
                or native is None
                or not self.lineage.operations <= native.verified_operations
            )
            or self.policy.contract_sha256 != INSTALLED_SCHEMA
            or source.contract_sha256 != self.policy.contract_sha256
            or self.registry.projects.get(target.project_id) != target.canonical_directory
            or native is None
            or not (READS | MODEL_READS) <= native.verified_operations
            or not isinstance(self.anchor.results, V2TurnResourceReader)
            or self.anchor.results.client is not self._execution
            or self.anchor.results.attestation is not self._semantics
            or self._semantics is None
            or self.anchor.live_text is not None
            and (
                not isinstance(self.anchor.live_text, LiveTextCollector)
                or self.anchor.live_text.feed is not self._feed
            )
        ):
            raise Conflict("existing_session_original_backend_assembly_changed")
        self.anchor.results.qualify(self.policy.anchor)

    def _qualification(self) -> dict[str, object]:
        self.selected(self.policy.anchor)
        policy = self.policy.model_dump(mode="json")
        policy["operations"] = sorted(self.policy.operations)
        lineage = None
        if self.lineage is not None:
            lineage = asdict(self.lineage)
            lineage["operations"] = sorted(self.lineage.operations)
        return {
            "policy": policy,
            "lineage": lineage,
            "model_settings": self._settings.enrollment_sha256
            if self._settings is not None
            else None,
            "turn_semantics": asdict(self._semantics)
            | {
                "verified_types": sorted(self._semantics.verified_types),
                "verified_outcomes": sorted(self._semantics.verified_outcomes),
            },
        }

    def qualification_sha256(self) -> str:
        """Durable identity of this project's tree semantics, nothing wider.

        The turn attestation's installed evidence is the whole runtime manifest,
        so adding another project changed it. Short-lived turn witnesses keep
        that digest; this identity outlives restarts and must not.
        """
        value = self._qualification()
        semantics = value["turn_semantics"]
        assert isinstance(semantics, dict)
        del semantics["installed_evidence_sha256"]
        return digest({"format": "original-session-qualification-v2"} | value)

    def legacy_qualified(self, record: SessionAdoptionRecord) -> bool:
        """A record whose qualification the caller may re-seal under these pins.

        Either a v1 record that is exactly the v1 digest of these pins, or a
        graph that is just its root (v1 or current), whose identity, creation
        time and policy the caller re-proves against a fresh live read. A
        childless root carries no descendant semantics of the old lineage
        observation, so re-pinning a project equals a fresh first baseline.
        The caller must then find the identical live graph and re-seal it
        through the journal; never a grown or changed one.
        """
        if (
            record.format not in {LEGACY_RECORD_FORMAT, RECORD_FORMAT}
            or record.contract_sha256 != INSTALLED_SCHEMA
            or record.qualification_sha256 == self.qualification_sha256()
        ):
            return False
        if record.format == LEGACY_RECORD_FORMAT and record.qualification_sha256 == digest(
            self._qualification()
        ):
            return True
        return len(record.nodes) == 1 and record.nodes[0].reference == record.root

    def require(self, candidate: PreparedExistingGraph) -> None:
        self.selected(candidate.record.root)
        saved = self._prepared.get(id(candidate))
        if (
            saved is None
            or saved.original() is not candidate
            or candidate.entries is not saved.entries
            or candidate.parents is not saved.parents
            or candidate.proofs is not saved.proofs
            or candidate.guard is not saved.guard
            or candidate.record is not saved.record
            or self._transport.attestation is not saved.attestation
            or not self.observer.current(candidate.observation)
            or candidate.record.qualification_sha256 != self.qualification_sha256()
            or not candidate.observation.observed_at <= time.time() < candidate.expires_at
        ):
            raise Conflict("existing_session_original_prepared_graph_expired_or_replaced")
        for ref, entry in candidate.entries.items():
            execution = entry.execution
            if (
                not isinstance(execution, V2ExecutionClient)
                or entry.reference != ref
                or execution.proofs is not candidate.proofs
                or execution.scope_guard is not candidate.guard
                or execution.transport is not self._transport
                or execution.models is not entry.models
                or execution.attachments is not None
                or execution.workspace_attachments is not None
                or not isinstance(entry.results, V2TurnResourceReader)
                or entry.results.client is not execution
                or entry.results.attestation is not self._semantics
                or entry.results.attachments is not None
                or not isinstance(entry.transcript, V2TranscriptReader)
                or entry.transcript.qualified is not entry.results
                or not isinstance(entry.metadata, V2NativeMetadataReader)
                or entry.metadata.client is not execution
                or entry.live_text is not self.anchor.live_text
            ):
                raise Conflict("existing_session_original_prepared_readers_changed")

    async def prepare(self, target: SessionRef, *, authorize: Authority) -> PreparedExistingGraph:
        try:
            async with asyncio.timeout(5), self._gate:
                self.selected(target)
                if await authorize() is not True:
                    raise AccessDenied("existing_session_current_authority_required")
                observed = await self.observer.observe(target, authorize=authorize)
                previous = self._registered.get(target)
                if previous is not None:
                    if previous.record.graph_sha256 != observed.graph_sha256 or any(
                        self.registry.sessions.get(r) is not e for r, e in previous.entries.items()
                    ):
                        raise Conflict("existing_session_original_registration_changed")
                    entries, proofs, guard = previous.entries, previous.proofs, previous.guard
                else:
                    if any(node.reference in self.registry.sessions for node in observed.nodes):
                        raise Conflict("existing_session_original_registration_cannot_be_replaced")
                    if len(observed.nodes) > 1 and (
                        self.lineage is None or self.lineage.qualification_scope != "tree"
                    ):
                        raise Conflict("existing_session_descendant_semantics_required")
                    for node in observed.nodes:
                        await self._feed.enroll_reference(node.reference, authorize=authorize)
                    settings = (
                        self._settings
                        if self._settings is not None
                        and self._settings.qualification_scope == "backend"
                        else None
                    )
                    if settings is not None:
                        for node in observed.nodes:
                            settings.require(node.reference, INSTALLED_SCHEMA)
                    qualification = self.lineage or LineageResourceAttestation(
                        target.backend_id,
                        target.backend_identity,
                        INSTALLED_SCHEMA,
                        LINEAGE_SEMANTICS,
                        self.policy.installed_protocol_evidence_sha256,
                        READS,
                        qualification_scope="leaf",
                    )
                    proofs = V2LineageResourceProofs(
                        self._feed,
                        self._proofs.projects,
                        observed,
                        qualification,
                        current=self.observer.current,
                        model_settings=settings,
                    )
                    enrollments = {
                        node.reference: NativePolicyEnrollment.model_validate(
                            {
                                "format": "native-project-policy-v1",
                                "reference": node.reference,
                                "native_project_id": node.native_project_id,
                                "contract_sha256": INSTALLED_SCHEMA,
                                "permission_source_sha256": PERMISSION_SOURCE,
                                "fingerprint_sha256": node.policy_sha256,
                                "operations": self.policy.operations,
                            }
                        )
                        for node in observed.nodes
                    }
                    guard = V2LineagePolicyGuard(proofs, enrollments)
                    built = {}
                    for node in observed.nodes:
                        ref = node.reference
                        execution = V2ExecutionClient(
                            self._transport, self._proofs.projects, proofs=proofs, scope_guard=guard
                        )
                        reader = V2TurnResourceReader(execution, attestation=self._semantics)
                        reader.qualify(ref)

                        async def pending(
                            selected: SessionRef, *, expected: SessionRef = ref
                        ) -> tuple[str, ...]:
                            if selected != expected:
                                raise AccessDenied("existing_session_pending_reference_changed")
                            return tuple(key for key, _ in (await proofs.capture(selected)).pending)

                        built[ref] = RegisteredSession(
                            ref,
                            INSTALLED_SCHEMA,
                            execution,
                            execution.models,
                            reader,
                            pending,
                            transcript=V2TranscriptReader(reader),
                            metadata=V2NativeMetadataReader(execution, ref),
                            live_text=self.anchor.live_text,
                        )
                    entries = MappingProxyType(built)
                if previous is None:
                    await proofs.watch_graph(authorize=authorize)
                elif any(proofs.certified_epoch(ref, INSTALLED_SCHEMA) is None for ref in entries):
                    raise Conflict("existing_session_original_registration_generation_changed")
                for ref, entry in entries.items():
                    await entry.execution.snapshot(ref)
                record = SessionAdoptionRecord(
                    root=target,
                    native_project_id=observed.nodes[0].native_project_id,
                    contract_sha256=INSTALLED_SCHEMA,
                    qualification_sha256=self.qualification_sha256(),
                    graph_sha256=observed.graph_sha256,
                    nodes=tuple(
                        OriginalSessionNode(
                            **node.model_dump(
                                include={
                                    "reference",
                                    "native_created_at",
                                    "parent_reference",
                                    "parent_created_at",
                                    "policy_sha256",
                                }
                            )
                        )
                        for node in observed.nodes
                    ),
                    observed_owner_epoch=observed.owner_epoch,
                    observed_at=observed.observed_at,
                )
                deadlines = [observed.expires_at]
                for ref in entries:
                    proof = proofs.current_proof(ref)
                    if proof is None:
                        raise Conflict("existing_session_original_preparation_proof_lost")
                    deadlines.append(proof.expires_at)
                candidate = PreparedExistingGraph(
                    observed,
                    entries,
                    MappingProxyType({n.reference: n.parent_reference for n in observed.nodes}),
                    proofs,
                    guard,
                    record,
                    min(deadlines),
                )
                while len(self._prepared) >= 32:
                    self._prepared.popitem(last=False)
                self._prepared[id(candidate)] = _Prepared(
                    weakref(candidate),
                    entries,
                    candidate.parents,
                    proofs,
                    guard,
                    record,
                    self._transport.attestation,
                )
                self.require(candidate)
                if await authorize() is not True:
                    raise AccessDenied("existing_session_current_authority_required")
                self.require(candidate)
                return candidate
        except TimeoutError:
            raise Conflict("existing_session_preparation_deadline_expired") from None

    async def commit(
        self,
        candidate: PreparedExistingGraph,
        *,
        authorize: Authority,
        before_commit: JournalPrepare | None = None,
    ) -> Mapping[SessionRef, RegisteredSession]:
        async with self._gate:
            self.require(candidate)

            async def authority() -> bool:
                self.require(candidate)
                allowed = await authorize()
                self.require(candidate)
                return allowed is True

            async def policies_and_journal() -> None:
                self.require(candidate)
                for ref in candidate.entries:
                    first = await candidate.guard.bundle(ref)
                    second = await candidate.guard.bundle(ref)
                    proof = candidate.proofs.current_proof(ref)
                    if (
                        proof is None
                        or first != second
                        or first
                        != (
                            candidate.guard.enrollments[ref].fingerprint_sha256,
                            proof.session_info_sha256,
                        )
                    ):
                        raise Conflict("existing_session_original_policy_or_resource_changed")
                if before_commit is not None:
                    await before_commit(candidate.record)
                self.require(candidate)

            def current() -> bool:
                self.require(candidate)
                return all(
                    candidate.proofs.current_proof(ref) is not None for ref in candidate.entries
                )

            await self.registry.adopt_graph(
                candidate.record.root,
                candidate.entries,
                candidate.parents,
                authorize=authority,
                current=current,
                before_commit=policies_and_journal,
            )
            self._registered[candidate.record.root] = candidate
            return candidate.entries

    async def prepare_publication(
        self, candidate: PreparedExistingGraph, *, authorize: Authority
    ) -> PreparedGraphGeneration:
        """Stage every original commit GET before a closed Source's final side."""
        async with self._gate:
            self.require(candidate)

            async def authority() -> bool:
                self.require(candidate)
                allowed = await authorize()
                self.require(candidate)
                return allowed is True

            async def qualify() -> None:
                self.require(candidate)
                for ref in candidate.entries:
                    first = await candidate.guard.bundle(ref)
                    second = await candidate.guard.bundle(ref)
                    proof = candidate.proofs.current_proof(ref)
                    if (
                        proof is None
                        or first != second
                        or first
                        != (
                            candidate.guard.enrollments[ref].fingerprint_sha256,
                            proof.session_info_sha256,
                        )
                    ):
                        raise Conflict("existing_session_original_policy_or_resource_changed")
                    self.require(candidate)

            def current() -> bool:
                self.require(candidate)
                return all(
                    candidate.proofs.current_proof(ref) is not None for ref in candidate.entries
                )

            publication = await self.registry.stage_adopt_graph(
                candidate.record.root,
                candidate.entries,
                candidate.parents,
                authorize=authority,
                current=current,
                qualify=qualify,
            )
            self.require(candidate)
            self._publications[publication] = candidate
            return publication

    async def commit_publication(
        self,
        candidate: PreparedExistingGraph,
        publication: PreparedGraphGeneration,
        *,
        authorize: Authority,
        before_commit: JournalPrepare,
    ) -> Mapping[SessionRef, RegisteredSession]:
        """Consume a qualified publication using local SQL hooks only."""
        async with self._gate:
            if self._publications.pop(publication, None) is not candidate:
                raise Conflict("existing_session_publication_not_issued")
            self.require(candidate)

            def current() -> bool:
                self.require(candidate)
                return all(
                    candidate.proofs.current_proof(ref) is not None for ref in candidate.entries
                )

            async def journal() -> None:
                self.require(candidate)
                await before_commit(candidate.record)
                self.require(candidate)

            await self.registry.commit_staged_graph(
                publication, authorize=authorize, current=current, before_commit=journal
            )
            self._registered[candidate.record.root] = candidate
            return candidate.entries

    async def prepare_record(
        self, record: SessionAdoptionRecord, *, authorize: Authority
    ) -> PreparedExistingGraph:
        """Re-observe a historical original graph; never replay its authority.

        The owner epoch/time in a durable record are historical observations.
        Fresh current owner/resources and current controller authority replace
        those observations; original IDs, creation times, parents and policies
        must still match exactly. Newly observed descendants may only be a
        strict extension; the controller must extend the saved journal with
        its complete expected-head CAS. No Native create/fork or input occurs.
        A legacy_qualified record must find the identical graph; the controller
        re-seals it under the current identity instead of extending it.
        """
        original = SessionAdoptionRecord.model_validate(record.model_dump(mode="python"))
        self.selected(original.root)
        legacy = self.legacy_qualified(original)
        if original.contract_sha256 != INSTALLED_SCHEMA or (
            original.qualification_sha256 != self.qualification_sha256() and not legacy
        ):
            raise Conflict("existing_session_historical_qualification_changed")
        candidate = await self.prepare(original.root, authorize=authorize)
        current = candidate.record
        if legacy:
            if not same_original_graph(original, current):
                raise Conflict("existing_session_historical_original_identity_changed")
            self.require(candidate)
            return candidate
        identical = not (
            current.root != original.root
            or current.native_project_id != original.native_project_id
            or current.graph_sha256 != original.graph_sha256
            or {node.reference: node for node in current.nodes}
            != {node.reference: node for node in original.nodes}
            or current.contract_sha256 != original.contract_sha256
            or current.qualification_sha256 != original.qualification_sha256
        )
        if not identical:
            try:
                require_original_extension(original, current)
            except ValueError:
                raise Conflict("existing_session_historical_original_identity_changed") from None
        self.require(candidate)
        return candidate
