"""Original-owner resource reconciliation for explicitly watched leaf roots.

This narrow qualified path rejects descendants and unresolved background shells.
It never converts the volatile feed into replay or fabricates native positions.
Full lineage/background qualification remains required for those session shapes.
"""

import asyncio
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head, reconcile_aborted_turn_tail
from jt_oz_bridge.adapters.opencode.agent_settings import (
    AgentSettingsAttestation,
    reconcile_agent_settings_tail,
)
from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.checks import V2CheckTailReader
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.graph_generation import (
    generation_bound,
    publication_generation,
)
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.adapters.opencode.model_settings import (
    ModelSettingsAttestation,
    reconcile_model_tail,
)
from jt_oz_bridge.domain.check_idle_anchor import (
    CheckHeadBoundary,
    CheckIdleAnchor,
    CheckPositiveIdle,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

# Actual installed schema and source/interaction observations, not a version range.
INSTALLED_SCHEMA = "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"
READS = frozenset(
    {
        "event.subscribe",
        "session.get",
        "session.active",
        "session.inbox.list",
        "session.permission.list",
        "session.form.list",
        "session.message.list",
        "session.list",
        "shell.list",
    }
)
ACTIVE_STATES = frozenset(
    {ExecutionState.RUNNING, ExecutionState.WAITING_PERMISSION, ExecutionState.WAITING_INPUT}
)


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReadOnlyRootScope:
    """Short-lived original-owner scope for reads, never an execution proof.

    This witness carries neither an execution state nor a mutation cursor. Its
    independent cache must never enroll a Root in ``_watched``.
    """

    reference: SessionRef
    contract_sha256: str
    native_project_id: str
    connection_epoch: str
    owner_epoch: str
    ownership_evidence_sha256: str
    session_info_sha256: str
    issued_at: float
    expires_at: float


class _BackgroundRootState(ContractError):
    """Unvalidated classification, never sufficient for startup degradation."""


class BackgroundRootWork(ContractError):
    """Complete stable resource evidence requiring separate ownership checks.

    Only V2LeafResourceProofs.capture issues this after validating both resource
    bundles and the strict event fence. It proves neither Idle nor shell stop.
    """

    def __init__(
        self,
        reference: SessionRef,
        contract_sha256: str,
        owner_epoch: str,
        connection_epoch: str,
        ownership_evidence_sha256: str,
        session_info_sha256: str,
        resources_sha256: str,
        resource_fence: str,
        issued_at: float,
        running_shell_ids: tuple[str, ...],
    ) -> None:
        super().__init__("leaf_background_work_requires_qualification")
        self.reference = reference
        self.contract_sha256 = contract_sha256
        self.owner_epoch = owner_epoch
        self.connection_epoch = connection_epoch
        self.ownership_evidence_sha256 = ownership_evidence_sha256
        self.session_info_sha256 = session_info_sha256
        self.resources_sha256 = resources_sha256
        self.resource_fence = resource_fence
        self.issued_at = issued_at
        self.running_shell_ids = running_shell_ids

    @property
    def expires_at(self) -> float:
        return self.issued_at + 5

    def evidence_sha256(self) -> str:
        return digest(
            {
                "reference": self.reference.model_dump(mode="json"),
                "contract_sha256": self.contract_sha256,
                "owner_epoch": self.owner_epoch,
                "connection_epoch": self.connection_epoch,
                "ownership_evidence_sha256": self.ownership_evidence_sha256,
                "session_info_sha256": self.session_info_sha256,
                "resources_sha256": self.resources_sha256,
                "resource_fence": self.resource_fence,
                "issued_at": self.issued_at,
                "running_shell_ids": self.running_shell_ids,
            }
        )


@dataclass(frozen=True)
class _RootGeneration:
    connection_epoch: str
    owner_epoch: str
    index: object
    task: object
    attestation: object
    publication_generation: object | None = None


@dataclass(frozen=True)
class LeafResourceWitness:
    reference: SessionRef
    connection_epoch: str
    owner_epoch: str
    ownership_evidence_sha256: str
    session_info_sha256: str
    resources_sha256: str
    resource_fence: str
    issued_at: float
    state: ExecutionState
    pending: tuple[tuple[str, Literal["permission", "form"]], ...]
    last_outcome: str | None
    state_only_fence: bool = False


class PositiveIdleRequired(ContractError):
    """Fresh verified non-idle resources, without committing a mutation watch."""

    def __init__(self, witness: LeafResourceWitness) -> None:
        super().__init__("leaf_idle_required_for_watch")
        self.witness = witness


def aborted_turn(bundle: dict[str, Any]) -> dict[str, Any] | None:
    """The reconciled declined-permission turn behind the current idle, if any."""
    if bundle.get("aborted_turn") is not None:
        turn: dict[str, Any] = bundle["aborted_turn"]
        return turn
    for key in ("agent_settings", "model_settings"):
        tail = bundle.get(key)
        if tail and tail.get("aborted_turn") is not None:
            turn = tail["aborted_turn"]
            return turn
    return None


def last_outcome(bundle: dict[str, Any]) -> str | None:
    """Retained Native outcome, except after a reconciled aborted turn.

    Native keeps the previous turn's outcome there. Its own ``terminal()``
    classifies the aborted turn's interrupt cause as interrupted.
    """
    return "interrupted" if aborted_turn(bundle) is not None else bundle["info"].get("outcome")


def root_state(bundle: dict[str, Any]) -> ExecutionState:
    """Only current authoritative resources and positive idle projection evidence.

    Retained outcome alone and absence from active alone are never sufficient.
    The caller must already validate the installed RPC responses and exact scope.
    """
    if bundle["active"]:
        if bundle["permissions"]:
            return ExecutionState.WAITING_PERMISSION
        if bundle["forms"]:
            return ExecutionState.WAITING_INPUT
        return ExecutionState.RUNNING
    if bundle["permissions"] or bundle["forms"]:
        raise ContractError("leaf_pending_without_active_owner")
    if bundle["inbox_ids"]:
        return ExecutionState.QUEUED
    if bundle["running_shell_ids"]:
        raise _BackgroundRootState("leaf_background_work_requires_qualification")
    info, latest = bundle["info"], bundle["latest"]
    if latest is None:
        if "outcome" not in info and "idle" not in info["time"]:
            return ExecutionState.IDLE  # Stable pristine resources, not active absence alone.
    elif (
        latest["type"] == "idle"
        and latest["outcome"] == info.get("outcome")
        and latest["time"]["created"] == info["time"].get("idle")
    ):
        return ExecutionState.IDLE  # Current root idle; last outcome is separate witness data.
    elif latest["type"] in {"agent-switched", "model-switched"} and (
        tail := bundle.get("agent_settings")
    ):
        # Separately attested mixed tail: a chain of settings behind a positive idle.
        boundary = tail["idle"]
        if boundary["outcome"] == info.get("outcome") and boundary["time"]["created"] == info[
            "time"
        ].get("idle"):
            return ExecutionState.IDLE
    elif latest["type"] == "model-switched" and (tail := bundle.get("model_settings")) is not None:
        # This entry can only be produced by the separately qualified tail
        # reader below, never from active absence or a retained outcome alone.
        boundary = tail["idle"]
        if boundary is not None and (
            boundary["outcome"] == info.get("outcome")
            and boundary["time"]["created"] == info["time"].get("idle")
        ):
            return ExecutionState.IDLE
        if tail["pristine"] and "outcome" not in info and "idle" not in info["time"]:
            return ExecutionState.IDLE
    elif latest["type"] == "assistant" and (tail := bundle.get("aborted_turn")) is not None:
        # A declined permission ends its turn without projecting an idle. Only
        # the separately reconciled exact tail reaches the previous boundary.
        boundary = tail["idle"]
        if tail["aborted"]["id"] == latest["id"]:
            if boundary is not None and (
                boundary["outcome"] == info.get("outcome")
                and boundary["time"]["created"] == info["time"].get("idle")
            ):
                return ExecutionState.IDLE
            if tail["pristine"] and "outcome" not in info and "idle" not in info["time"]:
                return ExecutionState.IDLE
    if (tail := bundle.get("check_tail")) is not None:
        boundary = tail["idle"]
        if (
            boundary is not None
            and boundary["outcome"] == info.get("outcome")
            and boundary["time"]["created"] == info["time"].get("idle")
        ):
            return ExecutionState.IDLE
        if tail["pristine"] and "outcome" not in info and "idle" not in info["time"]:
            return ExecutionState.IDLE
    raise ContractError("leaf_current_idle_not_positively_reconciled")


class V2LeafResourceProofs:
    """Explicitly enrolled experimental leaf-root provider; no default consumer.

    watch() establishes exact scope with resources before exposing an epoch.
    prove() repeats all resource reads with fresh original-owner evidence. Events
    fence individual state proofs without changing the connection epoch or
    request generation. Neither fence nor resource digest is a native cursor.
    """

    requires_project_policy = True
    _graph_publication: object | None = None

    @generation_bound()
    def model_settings_for(self, reference: SessionRef) -> ModelSettingsAttestation | None:
        """Exact per-node codec qualification; default leaf behavior is unchanged."""
        self.select(reference)
        return self.model_settings

    def agent_settings_for(self, reference: SessionRef) -> AgentSettingsAttestation | None:
        configuration = self.feed.agent_configuration
        if configuration is None:
            return None
        attestation: AgentSettingsAttestation | None = configuration.attestation(reference)
        return attestation

    @generation_bound()
    def project_info(self, reference: SessionRef, info: dict[str, Any]) -> dict[str, Any]:
        self.select(reference)
        return info

    @generation_bound()
    def resource_boundary(self, reference: SessionRef, bundle: dict[str, Any]) -> str:
        self.select(reference)
        return digest({**bundle, "info": self.project_info(reference, bundle["info"])})

    def __init__(
        self,
        feed: V2PublicFeed,
        projects: Mapping[str, V2CatalogProject],
        *,
        model_settings: ModelSettingsAttestation | None = None,
    ) -> None:
        if not projects or any(k != p.scope.project_id for k, p in projects.items()):
            raise ValueError("invalid_leaf_project_enrollment")
        self.feed, self.projects = feed, MappingProxyType(dict(projects))
        self.model_settings = model_settings
        self.check_tail: V2CheckTailReader | None = None
        self.witnesses: dict[SessionRef, LeafResourceWitness] = {}
        self._idle_anchors: dict[SessionRef, tuple[LeafResourceWitness, CheckIdleAnchor]] = {}
        self._watched: dict[SessionRef, _RootGeneration] = {}
        self._background_work: dict[
            SessionRef, tuple[BackgroundRootWork, _RootGeneration, str]
        ] = {}
        self._read_watched: dict[SessionRef, tuple[ReadOnlyRootScope, object, object, object]] = {}
        self._read_generations: dict[SessionRef, object | None] = {}

    @generation_bound()
    def select(self, ref: SessionRef) -> V2CatalogProject:
        self.feed.check_contract()
        p = self.projects.get(ref.project_id)
        t = self.feed.transport
        a = t.attestation
        if (
            p is None
            or not p.scope.contains(ref)
            or ref not in self.feed.references
            or t.profile.sha256 != INSTALLED_SCHEMA
            or a is None
            or a.upstream_version != "2.0.32"
            or not READS <= a.verified_operations
        ):
            raise ContractError("leaf_resources_scope_or_contract_unqualified")
        return p

    @generation_bound()
    def generation(self, ref: SessionRef) -> str:
        self.select(ref)
        i = self.feed.index
        if i is None:
            raise ContractError("leaf_public_feed_not_started")
        return i.require_live()

    @generation_bound()
    def validate_native_info(
        self, ref: SessionRef, info: dict[str, Any], *, read_only: bool = False
    ) -> None:
        p = self.select(ref)
        if (
            info.get("id") != ref.upstream_session_id
            or info.get("projectID") != p.upstream_project_id
            or info.get("location") != {"directory": ref.canonical_directory}
            or "parentID" in info
            or info.get("time", {}).get("archived") is not None
        ):
            raise ContractError(
                "leaf_read_only_root_scope_changed"
                if read_only
                else "leaf_native_root_scope_changed"
            )

    @generation_bound()
    async def children_response(self, ref: SessionRef) -> dict[str, Any]:
        # No project/directory filter: cross-workspace children must not hide.
        response: dict[str, Any] = await self.feed.transport.request(
            "session.list",
            query={"parentID": ref.upstream_session_id, "limit": "1", "order": "desc"},
        )
        return response

    @generation_bound()
    def validate_children(self, ref: SessionRef, response: dict[str, Any]) -> dict[str, Any]:
        if response["data"] or response["cursor"].get("next") is not None:
            raise ContractError("leaf_descendants_require_qualification")
        return {}

    @generation_bound()
    def read_epoch(self, ref: SessionRef, contract_sha256: str) -> str | None:
        """Return only a current read generation; never mutate certification."""
        try:
            p = self.select(ref)
            saved = self._read_watched.get(ref)
            if saved is None:
                return None
            scope, index, task, attestation = saved
            now = time.time()
            if (
                scope.reference != ref
                or contract_sha256 != INSTALLED_SCHEMA
                or scope.contract_sha256 != contract_sha256
                or scope.native_project_id != p.upstream_project_id
                or not scope.issued_at <= now < scope.expires_at
                or scope.expires_at - scope.issued_at != 5
                or self.feed.transport.attestation is not attestation
                or self.feed.index is not index
                or self.feed.task is not task
                or self.feed.task is None
                or self.feed.task.done()
                or self.feed.task.cancelling()
                or self.feed.index is None
                or scope.owner_epoch != self.feed.index.owner_epoch
                or scope.connection_epoch != self.generation(ref)
                or self._read_generations.get(ref) is not publication_generation(self, ref)
            ):
                return None
            return scope.connection_epoch
        except (ValueError, TypeError):
            return None

    @generation_bound()
    async def read_scope(self, ref: SessionRef) -> ReadOnlyRootScope:
        """Establish exact owner/Root read scope without claiming Idle or stop.

        Two authenticated metadata reads and peer/owner checks are required.
        Failure cannot borrow a previous mutation watch or read-only witness.
        """
        p = self.select(ref)
        t = self.feed.transport
        attestation = t.attestation
        index, task = self.feed.index, self.feed.task
        epoch = self.generation(ref)
        if index is None or task is None:
            raise ContractError("leaf_read_only_feed_unavailable")
        owner_epoch = index.owner_epoch
        started = time.time()
        published = publication_generation(self, ref)
        self._read_watched.pop(ref, None)

        async def peer() -> None:
            if t.verify_identity is None or not await t.verify_identity():
                raise ContractError("leaf_read_only_backend_identity_unverified")

        async def metadata() -> dict[str, Any]:
            info: dict[str, Any] = (
                await t.request("session.get", path={"sessionID": ref.upstream_session_id})
            )["data"]
            self.validate_native_info(ref, info, read_only=True)
            return info

        first_owner = await self.feed.current_owner()
        await peer()
        first, second = await metadata(), await metadata()
        await peer()
        last_owner = await self.feed.current_owner()
        now = time.time()
        if (
            self.select(ref) is not p
            or t.attestation is not attestation
            or self.feed.index is not index
            or self.feed.task is not task
            or task is None
            or task.done()
            or task.cancelling()
            or index.owner_epoch != owner_epoch
            or first_owner.owner_epoch != owner_epoch
            or last_owner.owner_epoch != owner_epoch
            or epoch != self.generation(ref)
            or not started <= now < started + 5
        ):
            raise ContractError("leaf_read_only_owner_or_feed_boundary_changed")
        if digest(self.project_info(ref, first)) != digest(self.project_info(ref, second)):
            raise SnapshotBoundaryChanged("leaf_read_only_metadata_boundary_changed")
        scope = ReadOnlyRootScope(
            ref,
            INSTALLED_SCHEMA,
            p.upstream_project_id,
            epoch,
            last_owner.owner_epoch,
            digest(last_owner.model_dump(mode="json")),
            digest(self.project_info(ref, second)),
            started,
            started + 5,
        )
        self._read_watched[ref] = (scope, index, task, attestation)
        self._read_generations[ref] = published
        return scope

    @generation_bound()
    def fence(self, ref: SessionRef, *, state_only: bool = False) -> str:
        epoch = self.generation(ref)
        assert self.feed.index is not None
        qualification = self.model_settings_for(ref)
        value = {
            "feed_epoch": epoch,
            "reference": ref.model_dump(),
            "local_revision": self.feed.index.state_revision_for(ref)
            if state_only
            else self.feed.index.revision_for(ref),
            "model_setting_enrollment": qualification.enrollment_sha256
            if qualification is not None
            else None,
        }
        if self.check_tail is not None:
            value["check_tail_enrollment"] = self.check_tail.enrollment_sha256
        configuration = self.feed.agent_configuration
        selected = configuration.fence_value(ref) if configuration is not None else None
        if selected is not None:
            # Published configuration pins every short-lived witness across awaits.
            value["agent_configuration"] = selected
        published = publication_generation(self, ref)
        if published is not None:
            value["graph_generation"] = id(published)
            # The explicitly tree-qualified facade must fence previously
            # unknown children even before its first non-leaf publication.
            value["directory_stream_state"] = self.feed.index.directory_fence(
                ref.canonical_directory, state_only=True
            )
        if state_only:
            value["revision_kind"] = "positive-active-state"
        return digest(value)

    @generation_bound()
    def current_generation(self, ref: SessionRef, context: _RootGeneration) -> bool:
        """A mutation watch or background report cannot survive a new feed."""
        try:
            return (
                self.feed.index is context.index
                and self.feed.task is context.task
                and self.feed.transport.attestation is context.attestation
                and self.feed.index is not None
                and self.feed.index.owner_epoch == context.owner_epoch
                and self.feed.task is not None
                and not self.feed.task.done()
                and not self.feed.task.cancelling()
                and self.generation(ref) == context.connection_epoch
                and publication_generation(self, ref) is context.publication_generation
            )
        except (ValueError, TypeError):
            return False

    def holds_watch(self, ref: SessionRef) -> bool:
        """This Root's own current watch, held by the provider that issued it.

        Diagnostic only, for the watch keeper: it neither revokes nor renews.
        A graph-published facade's watch() and certified_epoch() run on its
        active generation's provider, so the facade's own map is never read
        here. Reading it reported a healthy tree Root as lost forever.
        """
        try:
            return self._holds_own_watch(ref)
        except (ValueError, TypeError):
            return False

    @generation_bound()
    def _holds_own_watch(self, ref: SessionRef) -> bool:
        context = self._watched.get(ref)
        return context is not None and self.current_generation(ref, context)

    @generation_bound()
    def current_witness(self, ref: SessionRef) -> LeafResourceWitness | None:
        """This Root's latest witness, from the provider that holds its watch.

        A graph-published facade keeps no witnesses of its own; reading its map
        refused every finished turn of a chat-created tree Root as unwatched.
        """
        return self.witnesses.get(ref)

    def revoke_watch(self, ref: SessionRef) -> None:
        """Revoke one Root's mutation membership, preserving other Roots/reads."""
        self._watched.pop(ref, None)
        self.witnesses.pop(ref, None)
        self._idle_anchors.pop(ref, None)

    @generation_bound()
    def is_current_background(self, work: BackgroundRootWork) -> bool:
        """Recognize this provider's complete short-lived report, not a claim."""
        try:
            saved = self._background_work.get(work.reference)
            if saved is None:
                return False
            issued, context, evidence_sha = saved
            now = time.time()
            return (
                issued is work
                and work.contract_sha256 == INSTALLED_SCHEMA
                and work.issued_at <= now < work.expires_at
                and work.evidence_sha256() == evidence_sha
                and bool(work.running_shell_ids)
                and len(set(work.running_shell_ids)) == len(work.running_shell_ids)
                and self.current_generation(work.reference, context)
                and work.resource_fence == self.fence(work.reference)
            )
        except (ValueError, TypeError, AttributeError):
            return False

    @generation_bound()
    def valid_fence(self, ref: SessionRef, resource_fence: str) -> bool:
        try:
            if self.certified_epoch(ref, INSTALLED_SCHEMA) is None:
                return False
            if self.fence(ref) == resource_fence:
                return True
            witness = self.witnesses.get(ref)
            return bool(
                witness is not None
                and witness.state_only_fence
                and witness.state in ACTIVE_STATES
                and witness.resource_fence == resource_fence
                and self.fence(ref, state_only=True) == resource_fence
            )
        except (ValueError, TypeError):
            return False

    @generation_bound()
    def certified_epoch(self, reference: SessionRef, contract_sha256: str) -> str | None:
        try:
            context = self._watched.get(reference)
            if context is None or contract_sha256 != INSTALLED_SCHEMA:
                return None
            if not self.current_generation(reference, context):
                LOG.warning(
                    "root_watch_revoked cause=generation session=%s",
                    reference.upstream_session_id,
                )
                self.revoke_watch(reference)
                return None
            return context.connection_epoch
        except (ValueError, TypeError):
            return None

    @generation_bound()
    def dispatch_owner_epoch(self, ref: SessionRef, proof: OriginalExecutionProof) -> str:
        """Extract only the owner of this exact current Idle dispatch proof.

        This synchronous consistency check supplies a pre-send journal field.
        It performs no I/O, enrolls no scope and grants no mutation authority.
        In particular, a read-only witness cannot provide a dispatch owner.
        """
        witness = self.witnesses.get(ref)
        epoch = self.certified_epoch(ref, INSTALLED_SCHEMA)
        index = self.feed.index
        now = time.time()
        if (
            not isinstance(proof, OriginalExecutionProof)
            or witness is None
            or epoch is None
            or index is None
            or proof.reference != ref
            or witness.reference != ref
            or proof.contract_sha256 != INSTALLED_SCHEMA
            or proof.connection_epoch != epoch
            or witness.connection_epoch != epoch
            or witness.owner_epoch != index.owner_epoch
            or proof.ownership_evidence_sha256 != witness.ownership_evidence_sha256
            or proof.session_info_sha256 != witness.session_info_sha256
            or proof.resource_fence != witness.resource_fence
            or witness.resource_fence != self.fence(ref)
            or proof.cursor != "resource-sha256:" + witness.resources_sha256
            or proof.issued_at != witness.issued_at
            or proof.expires_at != witness.issued_at + 5
            or not proof.issued_at <= now < proof.expires_at
            or proof.state != ExecutionState.IDLE
            or witness.state != ExecutionState.IDLE
            or witness.state_only_fence
            or witness.pending
            or proof.descendants
        ):
            raise ContractError("leaf_dispatch_owner_epoch_unqualified")
        return witness.owner_epoch

    @generation_bound()
    def dispatch_idle_anchor(
        self, ref: SessionRef, proof: OriginalExecutionProof
    ) -> CheckIdleAnchor:
        """Extract only a positive boundary from this exact current Idle proof."""
        self.dispatch_owner_epoch(ref, proof)
        saved = self._idle_anchors.get(ref)
        if saved is None or saved[0] is not self.witnesses.get(ref):
            raise ContractError("leaf_dispatch_positive_idle_anchor_unavailable")
        return saved[1]

    @generation_bound()
    def idle_anchor(self, ref: SessionRef, bundle: dict[str, Any]) -> CheckIdleAnchor:
        """Project already validated resources, never infer Idle from absence."""
        latest = bundle["latest"]
        idle = latest if latest is not None and latest["type"] == "idle" else None
        if idle is None:
            for key in ("check_tail", "agent_settings", "model_settings"):
                tail = bundle.get(key)
                if tail is not None and tail["idle"] is not None:
                    idle = tail["idle"]
                    break
        pristine = (
            idle is None
            and "outcome" not in bundle["info"]
            and "idle" not in bundle["info"]["time"]
            and (
                latest is None
                or any(
                    bundle.get(key) is not None and bundle[key]["pristine"]
                    for key in ("check_tail", "model_settings")
                )
            )
        )
        qualification = self.model_settings_for(ref)
        return CheckIdleAnchor(
            reference=ref,
            head=CheckHeadBoundary(
                id=latest["id"],
                type=latest["type"],
                created_at=latest["time"]["created"],
                sha256=bundle["latest_sha256"],
            )
            if latest is not None
            else None,
            idle=CheckPositiveIdle(
                id=idle["id"],
                created_at=idle["time"]["created"],
                outcome=idle["outcome"],
            )
            if idle is not None
            else None,
            pristine=pristine,
            selected_model=native_ref(bundle["info"]["model"])
            if "model" in bundle["info"]
            else None,
            model_settings_sha256=qualification.enrollment_sha256
            if qualification is not None
            else None,
        )

    @generation_bound()
    async def bundle(self, ref: SessionRef) -> dict[str, Any]:
        self.select(ref)
        sid = {"sessionID": ref.upstream_session_id}
        t = self.feed.transport
        # Independent authenticated reads. A second identical bundle and event
        # fence are required; this is not an atomic cross-system transaction.
        info, active, inbox, permissions, forms, messages, children, shells = await asyncio.gather(
            t.request("session.get", path=sid),
            t.request("session.active"),
            t.request("session.inbox.list", path=sid),
            t.request("session.permission.list", path=sid),
            t.request("session.form.list", path=sid),
            t.request("session.message.list", path=sid, query={"limit": "1", "order": "desc"}),
            self.children_response(ref),
            t.request("shell.list", query={"location": {"directory": ref.canonical_directory}}),
        )
        raw = info["data"]
        self.validate_native_info(ref, raw)
        child_projection = self.validate_children(ref, children)
        if shells["location"]["directory"] != ref.canonical_directory:
            raise ContractError("leaf_shell_location_changed")
        catalogs = [inbox["data"], permissions["data"], forms["data"], shells["data"]]
        if any(len(c) > 1000 for c in catalogs):
            raise ContractError("leaf_resources_capacity_exceeded")
        for catalog in catalogs:
            if len({x["id"] for x in catalog}) != len(catalog):
                raise ContractError("leaf_resource_duplicate_identity")
        for catalog in catalogs[:3]:
            if any(x["sessionID"] != ref.upstream_session_id for x in catalog):
                raise ContractError("leaf_pending_scope_changed")
        # Pending catalogs identify request kinds even when their answer fields
        # cannot be previewed. Full normalization remains in the reply adapter;
        # an unsupported form must not hide that root is waiting or block stop.
        if any(f.get("state", {"status": "pending"})["status"] != "pending" for f in forms["data"]):
            raise ContractError("leaf_settled_form_in_pending_catalog")
        pids, fids = (
            sorted(x["id"] for x in permissions["data"]),
            sorted(x["id"] for x in forms["data"]),
        )
        if set(pids) & set(fids):
            raise ContractError("leaf_interaction_kind_conflict")
        if any(s["status"] != "running" for s in shells["data"]):
            raise ContractError("leaf_running_shell_catalog_inconsistent")
        if (
            len(messages["data"]) > 1
            or not messages["data"]
            and messages["cursor"].get("next") is not None
        ):
            raise ContractError("leaf_latest_message_boundary_inconsistent")
        # Raw texts/commands/reasoning are not retained in the witness.
        latest = messages["data"][0] if messages["data"] else None
        latest_fields = (
            {k: latest[k] for k in ("id", "type", "time", "outcome") if k in latest}
            if latest is not None
            else None
        )
        model_settings = None
        agent_tail = None
        agent_qualification = self.agent_settings_for(ref)
        if (
            agent_qualification is not None
            and self.check_tail is None
            and latest is not None
            and latest["type"] in {"agent-switched", "model-switched"}
            and ref.upstream_session_id not in active["data"]
            and not any((inbox["data"], permissions["data"], forms["data"], shells["data"]))
        ):
            agent_page = await t.request(
                "session.message.list", path=sid, query={"limit": "51", "order": "desc"}
            )
            if not agent_page["data"] or agent_page["data"][0] != latest:
                raise ContractError("leaf_agent_setting_tail_changed")
            settings = []
            for row in agent_page["data"]:
                if row["type"] == "idle":
                    break
                settings.append(row["type"])
            if "agent-switched" in settings:
                agent_tail = reconcile_agent_settings_tail(
                    t.profile, ref, raw, agent_page, agent_qualification
                )
            if self.agent_settings_for(ref) is not agent_qualification:
                raise ContractError("leaf_agent_setting_attestation_changed")
        if (
            agent_tail is None
            and latest is not None
            and latest["type"] == "model-switched"
            and self.check_tail is None
        ):
            qualification = self.model_settings_for(ref)
            if qualification is not None:
                qualification.require(ref, t.profile.sha256)
                # Positive running/pending/inbox resources already establish a
                # non-idle state. In particular, a model control during a
                # waiting form must not demand an Idle behind that active User
                # or prevent replying to its existing request.
                if (
                    ref.upstream_session_id not in active["data"]
                    and not inbox["data"]
                    and not permissions["data"]
                    and not forms["data"]
                    and not shells["data"]
                ):
                    tail = await t.request(
                        "session.message.list", path=sid, query={"limit": "51", "order": "desc"}
                    )
                    if not tail["data"] or tail["data"][0] != latest:
                        raise ContractError("leaf_model_setting_tail_changed")
                    model_settings = reconcile_model_tail(raw, tail)
                if self.model_settings_for(ref) is not qualification:
                    raise ContractError("leaf_model_setting_attestation_changed")
        aborted = None
        if (
            latest is not None
            and aborted_head(latest)
            and ref.upstream_session_id not in active["data"]
            and not any((inbox["data"], permissions["data"], forms["data"], shells["data"]))
        ):
            aborted_page = await t.request(
                "session.message.list", path=sid, query={"limit": "51", "order": "desc"}
            )
            if not aborted_page["data"] or aborted_page["data"][0] != latest:
                raise ContractError("leaf_aborted_turn_tail_changed")
            aborted = reconcile_aborted_turn_tail(raw, aborted_page)
        check_tail = None
        tail_reader = self.check_tail
        if (
            tail_reader is not None
            and latest is not None
            and latest["type"]
            in (
                {"shell", "synthetic", "model-switched", "agent-switched"}
                if agent_qualification is not None
                else {"shell", "synthetic", "model-switched"}
            )
            and ref.upstream_session_id not in active["data"]
            and not any((inbox["data"], permissions["data"], forms["data"], shells["data"]))
        ):
            if tail_reader.model_settings is not self.model_settings_for(ref):
                raise ContractError("leaf_check_tail_model_qualification_changed")
            check_tail = await tail_reader.read(ref, raw, latest)
            if self.check_tail is not tail_reader:
                raise ContractError("leaf_check_tail_qualification_changed")
        return {
            **child_projection,
            "info": raw,
            "active": ref.upstream_session_id in active["data"],
            "inbox_ids": sorted(x["id"] for x in inbox["data"]),
            "inbox_sha256": digest(inbox["data"]),
            "permissions": pids,
            "permissions_sha256": digest(permissions["data"]),
            "forms": fids,
            "forms_sha256": digest(forms["data"]),
            "latest": latest_fields,
            "latest_sha256": digest({"latest": latest}),
            "model_settings": model_settings,
            **({"aborted_turn": aborted} if aborted is not None else {}),
            **({"agent_settings": agent_tail} if agent_qualification is not None else {}),
            **({"check_tail": check_tail} if self.check_tail is not None else {}),
            "running_shell_ids": sorted(x["id"] for x in shells["data"]),
            "running_shells_sha256": digest(shells["data"]),
        }

    @generation_bound()
    async def capture(
        self, ref: SessionRef, expected_info_sha: str | None = None
    ) -> LeafResourceWitness:
        self.select(ref)
        self._background_work.pop(ref, None)
        epoch = self.generation(ref)
        index, task = self.feed.index, self.feed.task
        if index is None or task is None:
            raise ContractError("leaf_public_feed_not_started")
        context = _RootGeneration(
            epoch,
            index.owner_epoch,
            index,
            task,
            self.feed.transport.attestation,
            publication_generation(self, ref),
        )
        started = time.time()
        fence = self.fence(ref)
        state_fence = self.fence(ref, state_only=True)
        model_settings = self.model_settings_for(ref)
        check_tail = self.check_tail
        first_owner = await self.feed.current_owner()
        a = await self.bundle(ref)
        b = await self.bundle(ref)
        last_owner = await self.feed.current_owner()
        sha = digest(self.project_info(ref, b["info"]))
        background = False
        try:
            state: ExecutionState | None = root_state(b)
        except _BackgroundRootState:
            # Do not expose the typed report until every complete boundary
            # below has passed. Early classification alone is not authority.
            state, background = None, True
        active = state in ACTIVE_STATES
        # Both complete authenticated resource bundles must still be identical.
        # Only a positively active execution may tolerate schema-qualified
        # ephemeral text deltas. Final/idle evidence keeps the strict fence.
        selected_fence = state_fence if active else fence
        if (
            first_owner.owner_epoch != context.owner_epoch
            or last_owner.owner_epoch != context.owner_epoch
            or not self.current_generation(ref, context)
            or self.model_settings_for(ref) is not model_settings
            or self.check_tail is not check_tail
        ):
            raise ContractError("leaf_resource_or_feed_boundary_changed")
        if (
            selected_fence != self.fence(ref, state_only=active)
            or self.resource_boundary(ref, a) != self.resource_boundary(ref, b)
            or expected_info_sha is not None
            and sha != expected_info_sha
        ):
            raise SnapshotBoundaryChanged("leaf_resource_or_feed_boundary_changed")
        ownership_sha = digest(last_owner.model_dump(mode="json"))
        resources_sha = self.resource_boundary(ref, b)
        # A check anchor's idle bounds a suffix of check entries only. Turn
        # entries of an aborted turn are not, so no check starts from there.
        idle_anchor = (
            self.idle_anchor(ref, b)
            if state == ExecutionState.IDLE and aborted_turn(b) is None
            else None
        )
        # Every witness starts with the first capture boundary, including a
        # positive Idle. Slow owner/bundle reads cannot mint a fresh five
        # seconds for resources whose observation already began earlier.
        now = time.time()
        if not started <= now < started + 5:
            raise ContractError("leaf_resource_boundary_expired")
        if background:
            work = BackgroundRootWork(
                ref,
                INSTALLED_SCHEMA,
                last_owner.owner_epoch,
                epoch,
                ownership_sha,
                sha,
                resources_sha,
                fence,
                started,
                tuple(b["running_shell_ids"]),
            )
            self._background_work[ref] = (work, context, work.evidence_sha256())
            raise work
        assert state is not None
        pending: list[tuple[str, Literal["permission", "form"]]] = [
            (x, "permission") for x in b["permissions"]
        ]
        pending.extend((x, "form") for x in b["forms"])
        result = LeafResourceWitness(
            ref,
            epoch,
            last_owner.owner_epoch,
            ownership_sha,
            sha,
            resources_sha,
            selected_fence,
            started,
            state,
            tuple(pending),
            last_outcome(b),
            active,
        )
        self.witnesses[ref] = result
        if idle_anchor is not None:
            self._idle_anchors[ref] = (result, idle_anchor)
        else:
            self._idle_anchors.pop(ref, None)
        return result

    @generation_bound()
    async def watch(self, ref: SessionRef, *, require_idle: bool = False) -> LeafResourceWitness:
        self.revoke_watch(ref)
        try:
            result = await self.capture(ref)
            if require_idle and result.state != ExecutionState.IDLE:
                raise PositiveIdleRequired(result)
            context = _RootGeneration(
                result.connection_epoch,
                result.owner_epoch,
                self.feed.index,
                self.feed.task,
                self.feed.transport.attestation,
                publication_generation(self, ref),
            )
            if not self.current_generation(ref, context):
                raise ContractError("leaf_watch_generation_changed")
            self._watched[ref] = context
            return result
        except BaseException as error:
            LOG.warning(
                "root_watch_revoked cause=watch_failed session=%s error_type=%s",
                ref.upstream_session_id,
                type(error).__name__,
            )
            self.revoke_watch(ref)
            raise

    @generation_bound()
    async def prove(
        self, reference: SessionRef, contract_sha256: str, session_info_sha256: str
    ) -> OriginalExecutionProof:
        if self.certified_epoch(reference, contract_sha256) is None:
            raise ContractError("leaf_original_scope_not_watched")
        w = await self.capture(reference, session_info_sha256)
        return OriginalExecutionProof(
            reference=reference,
            contract_sha256=contract_sha256,
            session_info_sha256=w.session_info_sha256,
            ownership_evidence_sha256=w.ownership_evidence_sha256,
            connection_epoch=w.connection_epoch,
            issued_at=w.issued_at,
            expires_at=w.issued_at + 5,
            state=w.state,
            descendants=(),
            resource_fence=w.resource_fence,
            cursor="resource-sha256:" + w.resources_sha256,
        )

    @generation_bound()
    async def interaction_kind(
        self, reference: SessionRef, request_id: str, connection_epoch: str
    ) -> Literal["permission", "form"] | None:
        if self.certified_epoch(reference, INSTALLED_SCHEMA) != connection_epoch:
            return None
        w = await self.capture(reference)
        if w.connection_epoch != connection_epoch:
            return None
        return next((kind for key, kind in w.pending if key == request_id), None)
