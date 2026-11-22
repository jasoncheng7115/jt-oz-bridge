"""Qualified Native worktree creation, never a session move or implicit enrollment."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import PurePosixPath

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.git_review import V2NativeGitReview
from jt_oz_bridge.adapters.opencode.project_policy import NativePolicyWitness
from jt_oz_bridge.adapters.opencode.resources import ReadOnlyRootScope
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, TransportNotSent
from jt_oz_bridge.domain.directory_scope import DirectoryScopeSnapshot
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.git_review import NativeGitReview
from jt_oz_bridge.domain.worktrees import (
    WorktreeIntent,
    WorktreeObservation,
    WorktreePreflight,
    WorktreeTemplate,
    native_setup_command,
)
from jt_oz_bridge.storage.durable import digest

WORKTREE_OPERATIONS = frozenset(
    {"worktree.create", "worktree.list", "location.get", "project.list"}
)


@dataclass(frozen=True)
class _Prepared:
    intent: WorktreeIntent
    proof: WorktreePreflight
    native: OriginalExecutionProof
    policy: NativePolicyWitness
    review: NativeGitReview
    parent: DirectoryScopeSnapshot
    attestation: ContractAttestation
    task: object


class V2WorktreeCreation:
    def __init__(self, review: V2NativeGitReview, template: WorktreeTemplate) -> None:
        self.review, self.template = review, template
        self.client, self.transport = review.client, review.client.transport
        self._composition = (
            review.proofs,
            review.guard,
            review.directories,
            self.client.proofs,
            self.client.scope_guard,
        )
        self._entry = self.client.selected(template.reference)
        self._prepared: dict[str, _Prepared] = {}
        self._attempted: set[str] = set()
        self._observed: dict[
            int,
            tuple[
                WorktreeObservation,
                ContractAttestation | None,
                ReadOnlyRootScope,
                DirectoryScopeSnapshot,
                object,
                str,
            ],
        ] = {}

    def selected(self) -> None:
        ref, t = self.template.reference, self.transport.attestation
        policy = self.review.guard.enrollments.get(ref)
        if (
            self.review.client is not self.client
            or self.client.transport is not self.transport
            or any(
                a is not b
                for a, b in zip(
                    self._composition,
                    (
                        self.review.proofs,
                        self.review.guard,
                        self.review.directories,
                        self.client.proofs,
                        self.client.scope_guard,
                    ),
                    strict=True,
                )
            )
            or self.client.selected(ref) is not self._entry
            or policy is None
            or not self.review.guard.enrolled(ref, "worktree.create")
            or policy.native_project_id != self.template.native_project_id
            or policy.fingerprint_sha256 != self.template.native_policy_sha256
            or self.client.selected(ref).upstream_project_id != self.template.native_project_id
            or self.client.contract_for(ref) != self.template.contract_sha256
            or t is None
            or t.schema_sha256 != self.template.contract_sha256
            or t.backend_identity != ref.backend_identity
            or t.upstream_version != "2.0.32"
            or not WORKTREE_OPERATIONS <= t.verified_operations
            or self.review.directories is None
            or not self.review.directories.qualified(ref)
        ):
            raise ContractError("worktree_execution_not_explicitly_qualified")
        self.review.require(ref)

    async def project_facts(self) -> dict[str, object]:
        self.selected()
        rows = await self.transport.request("project.list")
        if not isinstance(rows, list) or len(rows) > 1000:
            raise ContractError("worktree_project_inventory_capacity")
        found = [r for r in rows if r["id"] == self.template.native_project_id]
        if len(found) != 1:
            raise ContractError("worktree_original_project_missing_or_duplicate")
        row = found[0]
        facts = {k: row.get(k) for k in ("id", "canonical", "vcs", "commands")}
        if (
            row["canonical"] != self.template.reference.canonical_directory
            or native_setup_command(row.get("commands", {}).get("start", ""))
            != self.template.setup_command
            or digest(facts) != self.template.project_facts_sha256
        ):
            raise ContractError("worktree_setup_or_original_project_changed")
        return facts

    def _relative(self, directory: str) -> str:
        root, path = (
            PurePosixPath(self.template.reference.canonical_directory),
            PurePosixPath(directory),
        )
        if str(path) != directory or not path.is_relative_to(root) or ".." in path.parts:
            raise ContractError("worktree_readback_outside_reviewed_root")
        return str(path.relative_to(root))

    async def inventory(self) -> tuple[dict[str, str], ...]:
        rows = await self.transport.request(
            "worktree.list", query={"projectID": self.template.native_project_id}
        )
        if (
            not isinstance(rows, list)
            or len(rows) > 128
            or len({r["directory"] for r in rows}) != len(rows)
        ):
            raise ContractError("worktree_bounded_unique_inventory_required")
        return tuple(sorted(rows, key=lambda r: r["directory"]))

    async def prepare(self, intent: WorktreeIntent) -> WorktreePreflight:
        if intent.template != self.template:
            raise ContractError("worktree_intent_template_changed")
        self.selected()
        ref = self.template.reference
        captured = self.transport.attestation
        first = await self.project_facts()
        view = await self.review.read(ref)
        inventory = await self.inventory()
        if any(
            r["directory"] == intent.directory or r["directory"].startswith(intent.directory + "-")
            for r in inventory
        ):
            raise ContractError("worktree_intent_destination_already_registered")
        assert self.review.directories is not None
        parent = await self.review.directories.observe(
            ref, (self._relative(self.template.destination_parent),)
        )
        snapshot, native = await self.client.qualified_snapshot(ref)
        if not snapshot.reconciled:
            raise ContractError("worktree_original_complete_scope_required")
        policy = await self.review.guard.authorize_worktree(
            ref, native, self.template.setup_command
        )
        second = await self.project_facts()
        if first != second or inventory != await self.inventory():
            raise ContractError("worktree_preflight_native_facts_changed")
        issued = time.time()
        proof = WorktreePreflight(
            intent_sha256=digest(intent.model_dump(mode="json")),
            comparison_sha256=digest(
                {
                    "project": first,
                    "review": view.model_dump(mode="json"),
                    "inventory": inventory,
                    "parent": parent.fingerprint,
                }
            ),
            issued_at=issued,
            expires_at=min(native.expires_at, policy.expires_at, issued + 5),
            dirty_workspace=bool(view.files or view.hidden_files),
        )
        assert captured is not None
        self._prepared = {
            key: value for key, value in self._prepared.items() if value.proof.expires_at > issued
        }
        if len(self._prepared) >= 32:
            self._prepared.pop(next(iter(self._prepared)))
        self._prepared[intent.intent_id] = _Prepared(
            intent, proof, native, policy, view, parent, captured, asyncio.current_task()
        )
        if not self.current(intent, proof):
            raise ContractError("worktree_preflight_original_proof_expired")
        return proof

    def current(self, intent: WorktreeIntent, proof: WorktreePreflight) -> bool:
        value = self._prepared.get(intent.intent_id)
        try:
            self.selected()
            if (
                value is None
                or value.intent != intent
                or value.proof is not proof
                or value.task is not asyncio.current_task()
            ):
                return False
            self.client.current(self.template.reference, value.native)
            return bool(
                value.attestation is self.transport.attestation
                and proof.issued_at <= time.time() < proof.expires_at
                and proof.intent_sha256 == digest(intent.model_dump(mode="json"))
                and self.review.current(value.review)
                and self.review.guard.worktree_current(
                    self.template.reference, value.native, value.policy
                )
                and self.review.directories is not None
                and self.review.directories.current(self.template.reference, value.parent)
            )
        except ValueError:
            return False

    async def create(
        self,
        intent: WorktreeIntent,
        proof: WorktreePreflight,
        *,
        authorize: Callable[[], Awaitable[None]],
    ) -> WorktreeObservation:
        def ready() -> None:
            if not self.current(intent, proof):
                raise ContractError("worktree_original_proof_changed_before_send")

        if intent.intent_id in self._attempted:
            raise MutationNotSent("worktree_adapter_intent_already_attempted")
        if len(self._attempted) >= 1024:
            raise MutationNotSent("worktree_adapter_attempt_capacity")
        # Reserve before any awaited transport work; never undo on uncertainty.
        self._attempted.add(intent.intent_id)

        async def boundary_authority() -> None:
            await authorize()
            await self.project_facts()
            value = self._prepared.get(intent.intent_id)
            policy = await self.review.guard.bundle(self.template.reference)
            if value is None or policy != (
                self.template.native_policy_sha256,
                value.native.session_info_sha256,
            ):
                raise ContractError("worktree_setup_policy_changed_at_send_boundary")
            # SQL grants / original Source can change during Native read awaits.
            await authorize()
            ready()

        try:
            ready()
        except ValueError:
            raise MutationNotSent("worktree_preflight_proved_not_sent") from None
        try:
            result = await self.transport.request(
                "worktree.create",
                body={
                    "projectID": self.template.native_project_id,
                    "from": self.template.reference.canonical_directory,
                    "directory": self.template.destination_parent,
                    "name": intent.name,
                    "branch": intent.branch,
                },
                before_send=ready,
                authorize_send=boundary_authority,
            )
        except TransportNotSent:
            raise MutationNotSent("worktree_transport_proved_not_sent") from None
        # Native may add a suffix on destination collision. Never silently accept it.
        if result != {"directory": intent.directory}:
            raise ContractError("worktree_created_destination_not_exact_intent")
        return await self._observe(intent, acknowledged=True)

    async def reconcile(self, intent: WorktreeIntent) -> WorktreeObservation:
        return await self._observe(intent, acknowledged=False)

    async def _observe(self, intent: WorktreeIntent, *, acknowledged: bool) -> WorktreeObservation:
        if intent.template != self.template:
            raise ContractError("worktree_readback_template_changed")
        self.selected()
        ref, captured = self.template.reference, self.transport.attestation
        first_scope = await self.review.proofs.read_scope(ref)
        fence = self.review.proofs.fence(ref)
        first_project = await self.project_facts()
        first = await self.inventory()
        if (
            sum(row["directory"] == intent.directory and bool(row.get("strategy")) for row in first)
            != 1
        ):
            raise ContractError("worktree_created_target_not_registered")
        location = await self.transport.request(
            "location.get", query={"location": {"directory": intent.directory}}
        )
        if location != {
            "directory": intent.directory,
            "project": {
                "id": self.template.native_project_id,
                "directory": intent.directory,
                "canonical": ref.canonical_directory,
            },
        }:
            raise ContractError("worktree_readback_original_project_or_location_changed")
        assert self.review.directories is not None
        physical = await self.review.directories.observe(ref, (self._relative(intent.directory),))
        repeated = await self.inventory()
        location_after = await self.transport.request(
            "location.get", query={"location": {"directory": intent.directory}}
        )
        physical_after = await self.review.directories.observe(
            ref, (self._relative(intent.directory),)
        )
        policy = await self.review.guard.bundle(ref)
        second_project = await self.project_facts()
        after_scope = await self.review.proofs.read_scope(ref)
        if (
            self.transport.attestation is not captured
            or first != repeated
            or location != location_after
            or physical.fingerprint != physical_after.fingerprint
            or not self.review.directories.current(ref, physical_after)
            or first_project != second_project
            or policy != (self.template.native_policy_sha256, first_scope.session_info_sha256)
            or (
                first_scope.owner_epoch,
                first_scope.connection_epoch,
                first_scope.session_info_sha256,
            )
            != (
                after_scope.owner_epoch,
                after_scope.connection_epoch,
                after_scope.session_info_sha256,
            )
            or self.review.proofs.fence(ref) != fence
            or not first_scope.issued_at <= time.time() < first_scope.expires_at
        ):
            raise ContractError("worktree_readback_current_original_boundary_changed")
        self.selected()
        observed = WorktreeObservation(
            intent_sha256=digest(intent.model_dump(mode="json")),
            directory=intent.directory,
            native_project_id=self.template.native_project_id,
            physical_sha256=physical_after.fingerprint,
            directory_identity_sha256=digest(
                {
                    k: getattr(
                        next(
                            r
                            for r in physical_after.records
                            if r.path == self._relative(intent.directory)
                        ),
                        k,
                    )
                    for k in ("path", "device", "inode", "uid", "gid", "mode")
                }
            ),
            inventory_sha256=digest({"worktrees": first}),
            observed_at=time.time(),
            status="completed" if acknowledged else "registered_setup_unknown",
        )

        if len(self._observed) >= 32:
            self._observed.pop(next(iter(self._observed)))
        self._observed[id(observed)] = (
            observed,
            captured,
            first_scope,
            physical_after,
            asyncio.current_task(),
            fence,
        )
        if not self.observation_current(intent, observed):
            raise ContractError("worktree_readback_expired_before_return")
        return observed

    def observation_current(self, intent: WorktreeIntent, observed: WorktreeObservation) -> bool:
        value = self._observed.get(id(observed))
        if value is None or value[0] is not observed or value[4] is not asyncio.current_task():
            return False
        _, attestation, scope, physical, _, fence = value
        try:
            self.selected()
            ref = self.template.reference
            return bool(
                intent.template == self.template
                and observed.intent_sha256 == digest(intent.model_dump(mode="json"))
                and observed.directory == intent.directory
                and self.transport.attestation is attestation
                and scope.issued_at <= time.time() < scope.expires_at
                and time.time() < observed.observed_at + 5
                and self.review.proofs.read_epoch(ref, self.template.contract_sha256)
                == scope.connection_epoch
                and self.review.proofs.fence(ref) == fence
                and self.review.directories is not None
                and self.review.directories.current(ref, physical)
            )
        except ValueError:
            return False
