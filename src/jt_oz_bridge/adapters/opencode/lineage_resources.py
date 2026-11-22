"""Opt-in original-session tree resource proofs; no default runtime activation.

Metadata observations establish identities only. Trusted composition must also
supply separately qualified backend lineage/resource semantics and current Human
scope. No Native sessions, policies, inputs or file grants are created here.
"""

import asyncio
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Literal

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.graph_generation import generation_bound
from jt_oz_bridge.adapters.opencode.info_projection import progress_info
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
from jt_oz_bridge.adapters.opencode.model_settings import ModelSettingsAttestation
from jt_oz_bridge.adapters.opencode.resources import (
    ACTIVE_STATES,
    INSTALLED_SCHEMA,
    READS,
    LeafResourceWitness,
    ReadOnlyRootScope,
    V2LeafResourceProofs,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.existing_sessions import (
    ExistingSessionGraphObservation,
    ExistingSessionObservation,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

LINEAGE_SEMANTICS = "original-session-lineage-resources-v2"
# Each record still expires 5 s after issue; this only bounds concurrent readers.
GRAPH_PROOFS_KEPT = 8


@dataclass(frozen=True)
class LineageResourceAttestation:
    """Trusted backend-scope semantic evidence, never a catalog/chat assertion."""

    backend_id: str
    backend_identity: str
    contract_sha256: str
    semantics: str
    installed_evidence_sha256: str
    operations: frozenset[str]
    qualification_scope: Literal["leaf", "tree"] = "tree"


@dataclass(frozen=True)
class _GraphProof:
    proof: OriginalExecutionProof
    witnesses: tuple[LeafResourceWitness, ...]
    index: object
    task: object
    attestation: object
    owner_epoch: str


class V2LineageResourceProofs(V2LeafResourceProofs):
    def __init__(
        self,
        feed: V2PublicFeed,
        projects: Mapping[str, V2CatalogProject],
        observation: ExistingSessionGraphObservation,
        attestation: LineageResourceAttestation,
        *,
        current: Callable[[ExistingSessionGraphObservation], bool],
        model_settings: ModelSettingsAttestation | None = None,
        model_settings_by_reference: Mapping[SessionRef, ModelSettingsAttestation | None]
        | None = None,
    ) -> None:
        if current(observation) is not True:
            raise ContractError("lineage_original_metadata_observation_required")
        super().__init__(feed, projects, model_settings=model_settings)
        self.observation, self.lineage_attestation = observation, attestation
        self._observation, self._lineage_attestation, self._lineage_feed = (
            observation,
            attestation,
            feed,
        )
        self._nodes = MappingProxyType({node.reference: node for node in observation.nodes})
        self._original_nodes = self._nodes
        if model_settings_by_reference is not None:
            if (
                set(model_settings_by_reference) != set(self._nodes)
                or model_settings_by_reference[observation.reference] is not model_settings
            ):
                raise ContractError("lineage_complete_node_model_qualifications_required")
            for reference, qualification in model_settings_by_reference.items():
                if qualification is not None:
                    qualification.require(reference, INSTALLED_SCHEMA)
        self._node_model_settings = (
            MappingProxyType(dict(model_settings_by_reference))
            if model_settings_by_reference is not None
            else None
        )
        self._original_node_model_settings = self._node_model_settings
        descendants: dict[SessionRef, set[SessionRef]] = {ref: set() for ref in self._nodes}
        for reference, node in self._nodes.items():
            parent = node.parent_reference
            while parent is not None:
                descendants[parent].add(reference)
                parent = self._nodes[parent].parent_reference
        self._descendants = MappingProxyType(
            {
                ref: tuple(sorted(children, key=lambda child: child.upstream_session_id))
                for ref, children in descendants.items()
            }
        )
        self._original_descendants = self._descendants
        # Recent proofs per Root, newest last. Several readers prove one Root
        # concurrently; a new proof must not withdraw one another reader holds.
        self._graph_proofs: dict[SessionRef, tuple[_GraphProof, ...]] = {}
        self._graph_gate = asyncio.Lock()
        self.select(observation.reference)

    @generation_bound()
    def select(self, ref: SessionRef) -> V2CatalogProject:
        p = super().select(ref)
        a, native = self.lineage_attestation, self.feed.transport.attestation
        if (
            self.feed is not self._lineage_feed
            or self.observation is not self._observation
            or self.lineage_attestation is not self._lineage_attestation
            or self._nodes is not self._original_nodes
            or self._node_model_settings is not self._original_node_model_settings
            or self._descendants is not self._original_descendants
            or ref not in self._nodes
            or p.upstream_project_id != self._nodes[ref].native_project_id
            or (a.backend_id, a.backend_identity) != (ref.backend_id, ref.backend_identity)
            or a.contract_sha256 != INSTALLED_SCHEMA
            or a.semantics != LINEAGE_SEMANTICS
            or a.qualification_scope not in {"leaf", "tree"}
            or a.qualification_scope == "leaf"
            and len(self.observation.nodes) != 1
            or re.fullmatch(r"[0-9a-f]{64}", a.installed_evidence_sha256) is None
            or type(a.operations) is not frozenset
            or not READS <= a.operations
            or native is None
            or not a.operations <= native.verified_operations
        ):
            raise ContractError("lineage_explicit_original_backend_semantics_required")
        return p

    @generation_bound()
    def model_settings_for(self, reference: SessionRef) -> ModelSettingsAttestation | None:
        self.select(reference)
        return (
            self._node_model_settings[reference]
            if self._node_model_settings is not None
            else self.model_settings
        )

    @generation_bound()
    def descendants(self, ref: SessionRef) -> tuple[SessionRef, ...]:
        self.select(ref)
        return self._descendants[ref]

    @generation_bound()
    def project_info(self, reference: SessionRef, info: dict[str, Any]) -> dict[str, Any]:
        self.select(reference)
        return progress_info(info)

    @generation_bound()
    def original_node(self, ref: SessionRef) -> ExistingSessionObservation:
        """Sealed enrollment identity, never a fresh state or operation grant."""
        self.select(ref)
        return self._nodes[ref]

    @generation_bound()
    async def ancestor_origins(self, ref: SessionRef) -> str:
        self.select(ref)
        origins = []
        parent = self._nodes[ref].parent_reference
        while parent is not None:
            info = (
                await self.feed.transport.request(
                    "session.get", path={"sessionID": parent.upstream_session_id}
                )
            )["data"]
            self.validate_native_info(parent, info)
            node = self._nodes[parent]
            origins.append(
                {
                    "reference": parent.model_dump(mode="json"),
                    "created_at": node.native_created_at,
                    "parent": node.parent_reference.model_dump(mode="json")
                    if node.parent_reference
                    else None,
                }
            )
            parent = node.parent_reference
        return digest({"ancestors": origins})

    @generation_bound()
    async def read_scope(self, ref: SessionRef) -> ReadOnlyRootScope:
        """Original node plus ancestor origins, with the earliest read deadline."""
        self._read_watched.pop(ref, None)
        try:
            async with asyncio.timeout(5):
                started = time.time()
                before = await self.ancestor_origins(ref)
                scope = await super().read_scope(ref)
                if await self.ancestor_origins(ref) != before:
                    raise ContractError("lineage_read_original_parent_changed")
                owner = await self.feed.current_owner()
                verify = self.feed.transport.verify_identity
                if (
                    verify is None
                    or await verify() is not True
                    or owner.owner_epoch != scope.owner_epoch
                    or self.read_epoch(ref, INSTALLED_SCHEMA) != scope.connection_epoch
                    or not started <= time.time() < started + 5
                ):
                    raise ContractError("lineage_read_original_scope_changed")
                saved = self._read_watched.get(ref)
                if saved is None or saved[0] is not scope:
                    raise ContractError("lineage_read_original_scope_replaced")
                # Shorten the inherited metadata witness; never renew an earlier
                # ancestor observation by starting its TTL at the last Node GET.
                result = replace(scope, issued_at=started, expires_at=started + 5)
                self._read_watched[ref] = (result, saved[1], saved[2], saved[3])
                return result
        except BaseException as exc:
            self._read_watched.pop(ref, None)
            if isinstance(exc, TimeoutError):
                raise ContractError("lineage_read_original_deadline_expired") from None
            raise

    @generation_bound()
    def validate_native_info(
        self, ref: SessionRef, info: dict[str, Any], *, read_only: bool = False
    ) -> None:
        self.select(ref)
        node = self._nodes[ref]
        parent = node.parent_reference
        if (
            info.get("id") != ref.upstream_session_id
            or info.get("projectID") != node.native_project_id
            or info.get("location") != {"directory": ref.canonical_directory}
            or type(info.get("time", {}).get("created")) is not int
            or info["time"]["created"] != node.native_created_at
            or info.get("time", {}).get("archived") is not None
            or (
                "parentID" in info
                if parent is None
                else info.get("parentID") != parent.upstream_session_id
            )
        ):
            raise ContractError("lineage_original_session_origin_changed")

    @generation_bound()
    async def children_response(self, ref: SessionRef) -> dict[str, Any]:
        self.select(ref)
        rows, seen, cursors = [], set(), set()
        cursor: str | None = None
        for _ in range(1000):
            query = {"parentID": ref.upstream_session_id, "limit": "100", "order": "asc"}
            if cursor is not None:
                query["cursor"] = cursor
            value = await self.feed.transport.request("session.list", query=query)
            self.select(ref)
            if len(value["data"]) > 100:
                raise ContractError("lineage_children_page_capacity_exceeded")
            for row in value["data"]:
                child = ref.model_copy(update={"upstream_session_id": row["id"]})
                if child not in self._nodes:
                    # A subagent this tree has not connected yet: nothing is read
                    # or sent for it, and the graph worker connects it shortly.
                    raise SnapshotBoundaryChanged("lineage_original_child_not_yet_connected")
                self.validate_native_info(child, row)
                if child in seen or self._nodes[child].parent_reference != ref:
                    raise ContractError("lineage_child_duplicate_or_parent_changed")
                seen.add(child)
                rows.append(row)
                if len(rows) > 999:
                    raise ContractError("lineage_children_capacity_exceeded")
            cursor = value["cursor"].get("next")
            if cursor is None:
                return {"data": rows, "cursor": {}}
            if not cursor or len(cursor) > 8192 or cursor in cursors:
                raise ContractError("lineage_children_cursor_not_progressing")
            cursors.add(cursor)
        raise ContractError("lineage_children_page_capacity_exceeded")

    @generation_bound()
    def validate_children(self, ref: SessionRef, response: dict[str, Any]) -> dict[str, Any]:
        expected = {r for r, n in self._nodes.items() if n.parent_reference == ref}
        actual = {
            ref.model_copy(update={"upstream_session_id": row["id"]}) for row in response["data"]
        }
        if response["cursor"].get("next") is None and actual > expected:
            raise SnapshotBoundaryChanged("lineage_original_child_not_yet_connected")
        if actual != expected or response["cursor"].get("next") is not None:
            raise ContractError("lineage_original_children_changed")
        return {
            "lineage_children": [
                {
                    "reference": r.model_dump(mode="json"),
                    "created_at": self._nodes[r].native_created_at,
                    "parent_created_at": self._nodes[r].parent_created_at,
                }
                for r in sorted(actual, key=lambda r: r.upstream_session_id)
            ]
        }

    @generation_bound()
    def fence(self, ref: SessionRef, *, state_only: bool = False) -> str:
        self.select(ref)
        index = self.feed.index
        if index is None:
            raise ContractError("lineage_original_feed_required")
        nodes = (ref, *self.descendants(ref))
        # State arrivals in this tree's directory cover previously unknown
        # children; another project's activity cannot be one. The caller's
        # positive-active qualification applies only to this actual node; each
        # descendant needs its own current authenticated resource witness. An
        # idle ancestor must neither freeze a running child's ephemeral text
        # nor lend its child's qualification to an idle sibling.
        return digest(
            {
                "lineage": self.observation.graph_sha256,
                "directory_stream_state": index.directory_fence(
                    ref.canonical_directory, state_only=True
                ),
                "nodes": [
                    {
                        "reference": r.model_dump(mode="json"),
                        "fence": super(V2LineageResourceProofs, self).fence(
                            r,
                            state_only=state_only
                            if r == ref
                            else self._qualified_active_descendant(r),
                        ),
                    }
                    for r in nodes
                ],
            }
        )

    def _qualified_active_descendant(self, ref: SessionRef) -> bool:
        witness, context = self.witnesses.get(ref), self._watched.get(ref)
        now = time.time()
        return bool(
            witness is not None
            and context is not None
            and witness.reference == ref
            and witness.state in ACTIVE_STATES
            and witness.state_only_fence
            and witness.issued_at <= now < witness.issued_at + 5
            and witness.connection_epoch == context.connection_epoch
            and witness.owner_epoch == context.owner_epoch
            and self.current_generation(ref, context)
        )

    def _capture_order(self, nodes: tuple[SessionRef, ...]) -> tuple[SessionRef, ...]:
        # Establish actual descendants' positive-active/strict qualifications
        # before capturing an ancestor's aggregate fence, even on first watch.
        return tuple(sorted(nodes, key=lambda ref: len(self._descendants[ref])))

    @generation_bound()
    def certified_epoch(self, reference: SessionRef, contract_sha256: str) -> str | None:
        try:
            epoch = super().certified_epoch(reference, contract_sha256)
            if epoch is None or any(
                super(V2LineageResourceProofs, self).certified_epoch(child, contract_sha256)
                != epoch
                for child in self.descendants(reference)
            ):
                return None
            return epoch
        except (ValueError, TypeError):
            return None

    @generation_bound()
    def diagnostic_epoch(self, reference: SessionRef) -> str | None:
        """Inspect watch generation without revoking, renewing or proving resources."""
        try:
            self.select(reference)
            result = None
            for node in (reference, *self.descendants(reference)):
                context = self._watched.get(node)
                if context is None or not self.current_generation(node, context):
                    return None
                if result is not None and context.connection_epoch != result:
                    return None
                result = context.connection_epoch
            return result
        except (ValueError, TypeError):
            return None

    @generation_bound()
    async def watch_graph(self, *, authorize: Callable[[], Awaitable[bool]]) -> None:
        nodes = tuple(self._nodes)
        try:
            async with asyncio.timeout(5), self._graph_gate:
                before = self.feed.index, self.feed.task, self.feed.transport.attestation
                for ref in self._capture_order(nodes):
                    if await authorize() is not True:
                        raise ContractError("lineage_current_authority_required")
                    await super().watch(ref)
                if (
                    await authorize() is not True
                    or before != (self.feed.index, self.feed.task, self.feed.transport.attestation)
                    or any(self.certified_epoch(r, INSTALLED_SCHEMA) is None for r in nodes)
                ):
                    raise ContractError("lineage_original_graph_watch_changed")
        except BaseException as exc:
            for ref in nodes:
                self.revoke_watch(ref)
            self._graph_proofs.clear()
            if isinstance(exc, TimeoutError):
                raise ContractError("lineage_original_watch_deadline_expired") from None
            raise

    @generation_bound()
    async def prove(
        self, reference: SessionRef, contract_sha256: str, session_info_sha256: str
    ) -> OriginalExecutionProof:
        try:
            async with asyncio.timeout(5), self._graph_gate:
                epoch = self.certified_epoch(reference, contract_sha256)
                if epoch is None:
                    raise ContractError("lineage_original_complete_graph_not_watched")
                started = time.time()
                index, task, attestation = (
                    self.feed.index,
                    self.feed.task,
                    self.feed.transport.attestation,
                )
                before = await self.feed.current_owner()
                ancestors = await self.ancestor_origins(reference)
                nodes = (reference, *self.descendants(reference))
                captured = {}
                for ref in self._capture_order(nodes):
                    captured[ref] = await self.capture(
                        ref, session_info_sha256 if ref == reference else None
                    )
                witnesses = [captured[ref] for ref in nodes]
                if await self.ancestor_origins(reference) != ancestors:
                    raise ContractError("lineage_original_parent_origin_changed")
                after = await self.feed.current_owner()
                root = witnesses[0]
                proof = OriginalExecutionProof(
                    reference=reference,
                    contract_sha256=contract_sha256,
                    session_info_sha256=root.session_info_sha256,
                    ownership_evidence_sha256=root.ownership_evidence_sha256,
                    connection_epoch=epoch,
                    issued_at=started,
                    expires_at=started + 5,
                    state=root.state,
                    descendants=self.descendants(reference),
                    resource_fence=root.resource_fence,
                    cursor="resource-sha256:"
                    + digest(
                        {
                            "nodes": [
                                {
                                    "reference": w.reference.model_dump(mode="json"),
                                    "resources_sha256": w.resources_sha256,
                                }
                                for w in witnesses
                            ]
                        }
                    ),
                )
                record = _GraphProof(
                    proof, tuple(witnesses), index, task, attestation, after.owner_epoch
                )
                if before.owner_epoch != after.owner_epoch or not self.record_current(record):
                    raise ContractError("lineage_original_resource_graph_changed")
                kept = tuple(
                    r
                    for r in self._graph_proofs.get(reference, ())
                    if r.proof.expires_at > time.time()
                )
                self._graph_proofs[reference] = (*kept, record)[-GRAPH_PROOFS_KEPT:]
                return proof
        except TimeoutError:
            self._graph_proofs.pop(reference, None)
            raise ContractError("lineage_original_resource_deadline_expired") from None
        except Exception:
            # A proof that fails has seen something change: none issued before it
            # stays current. One still running withdraws nothing.
            self._graph_proofs.pop(reference, None)
            raise

    @generation_bound()
    def record_current(self, saved: _GraphProof) -> bool:
        try:
            proof, index, task = saved.proof, self.feed.index, self.feed.task
            self.select(proof.reference)
            now = time.time()
            return bool(
                index is saved.index
                and index is not None
                and task is saved.task
                and task is not None
                and not task.done()
                and not task.cancelling()
                and self.feed.transport.attestation is saved.attestation
                and index.owner_epoch == saved.owner_epoch
                and self.certified_epoch(proof.reference, INSTALLED_SCHEMA)
                == proof.connection_epoch
                and proof.issued_at <= now < proof.expires_at
                and proof.expires_at == proof.issued_at + 5
                and proof.descendants == self.descendants(proof.reference)
                and all(
                    w.owner_epoch == saved.owner_epoch
                    and w.connection_epoch == proof.connection_epoch
                    and w.state_only_fence == (w.state in ACTIVE_STATES)
                    and proof.issued_at <= w.issued_at <= now < w.issued_at + 5
                    and w.resource_fence == self.fence(w.reference, state_only=w.state_only_fence)
                    for w in saved.witnesses
                )
            )
        except (ValueError, TypeError):
            return False

    @generation_bound()
    def valid_fence(self, ref: SessionRef, resource_fence: str) -> bool:
        return any(
            saved.proof.resource_fence == resource_fence and self.record_current(saved)
            for saved in self._graph_proofs.get(ref, ())
        )

    def _issued_record(self, ref: SessionRef, proof: OriginalExecutionProof) -> _GraphProof | None:
        """The still-current record this exact proof came from, if any."""
        if not isinstance(proof, OriginalExecutionProof) or proof.reference != ref:
            return None
        value = proof.model_dump(mode="python")
        return next(
            (
                saved
                for saved in self._graph_proofs.get(ref, ())
                if saved.proof.model_dump(mode="python") == value and self.record_current(saved)
            ),
            None,
        )

    @generation_bound()
    def proof_current(self, ref: SessionRef, proof: OriginalExecutionProof) -> bool:
        return self._issued_record(ref, proof) is not None

    @generation_bound()
    def current_proof(self, ref: SessionRef) -> OriginalExecutionProof | None:
        """Return only this provider's latest still-current original proof."""
        saved = self._graph_proofs.get(ref, ())
        return saved[-1].proof if saved and self.record_current(saved[-1]) else None

    @generation_bound()
    def dispatch_owner_epoch(self, ref: SessionRef, proof: OriginalExecutionProof) -> str:
        saved = self._issued_record(ref, proof)
        if saved is None or any(
            w.state != ExecutionState.IDLE or w.pending or w.state_only_fence
            for w in saved.witnesses
        ):
            raise ContractError("lineage_dispatch_original_quiescent_graph_required")
        return saved.owner_epoch
