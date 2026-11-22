"""Qualified, bounded original-Root GET review metadata, with no mutation watch.

This internal adapter does not replace Human/Binding authorization. It has no
runtime consumer, no installed default enrollment, no raw patch renderer and no
active worktree selection. A caller must still authorize disclosure to its viewer.
"""

import hashlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Literal
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.resources import (
    INSTALLED_SCHEMA,
    ReadOnlyRootScope,
    V2LeafResourceProofs,
)
from jt_oz_bridge.domain.directory_scope import DirectoryScopeGuard, DirectoryScopeSnapshot
from jt_oz_bridge.domain.git_review import (
    NativeDiffSummary,
    NativeGitPatch,
    NativeGitReview,
    NativeReviewBase,
    SavedWorktree,
    inert_text,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.workspace_paths import canonical_relative, disclosed_path
from jt_oz_bridge.storage.durable import digest

REVIEW_OPERATIONS = frozenset(
    {"location.get", "worktree.list", "vcs.get", "vcs.branch.list", "vcs.base", "vcs.diff"}
)
REVIEW_SEMANTICS = digest(
    {
        "schema": INSTALLED_SCHEMA,
        "projection": "native-review-metadata-v1",
        "saved_worktrees": "saved-only-relative-enrolled-root-descendants-with-physical-proof",
        "diff": "summary-only-no-raw-patch-branch-and-committed-explicit-base",
        "branch_limit_probe": 51,
        "worktree_capacity": 128,
        "physical_directory_capacity": 32,
        "diff_capacity": 1000,
        "patch_bytes_capacity": 1024**2,
        "scope": "read-only-root-never-idle-or-mutation-proof",
    }
)


PATCH_SEMANTICS = digest(
    {
        "schema": INSTALLED_SCHEMA,
        "projection": "native-review-single-patch-v1",
        "summary_semantics": REVIEW_SEMANTICS,
        "selection": "one-disclosed-canonical-relative-path-in-exact-comparison",
        "content": "original-native-utf8-text-with-exact-sha256-and-byte-count",
        "boundary": "same-original-root-double-six-get-bundle-and-read-scope",
        "patch_bytes_capacity_including_hidden": 1024**2,
        "authority": "outer-human-view-source-actor-audience-fence-still-required",
        "comparison": "only-independently-observed-comparison-modes",
        "not_proven": "index-head-remote-clean-worktree-switch-mutation",
    }
)


# An added line only Git's merge writes: `<<<<<<< ours` or `>>>>>>> theirs`.
CONFLICT_MARKER = re.compile(r"^\+(?:<{7}|>{7}) ", re.MULTILINE)


def explicit_base(value: str) -> str:
    # This conservative first batch deliberately has no rev-expression parser.
    # Native receives one inert query value; it is never joined into a shell.
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) is None
        or value.endswith(("/", ".", ".lock"))
        or any(not part or part.startswith(".") for part in value.split("/"))
        or ".." in value
    ):
        raise ContractError("git_review_explicit_inert_base_required")
    return value


def absolute_directory(value: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 4096
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ContractError("git_review_canonical_absolute_directory_required")
    path = PurePosixPath(value)
    if str(path) != value or ".." in path.parts:
        raise ContractError("git_review_canonical_absolute_directory_required")
    return path


@dataclass(frozen=True)
class GitReviewAttestation:
    reference: SessionRef
    schema_sha256: str
    native_policy_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    operations: frozenset[str]


def review_attestation_sha256(value: GitReviewAttestation) -> str:
    """Bind a patch opt-in to the complete existing summary enrollment."""
    return digest(
        {
            "reference": value.reference.model_dump(mode="json"),
            "schema_sha256": value.schema_sha256,
            "native_policy_sha256": value.native_policy_sha256,
            "semantics_sha256": value.semantics_sha256,
            "installed_evidence_sha256": value.installed_evidence_sha256,
            "operations": sorted(value.operations),
        }
    )


@dataclass(frozen=True)
class GitPatchAttestation:
    """Explicit raw-projection qualification, not Human disclosure authority."""

    reference: SessionRef
    review_attestation_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    verified_modes: frozenset[str]


@dataclass(frozen=True)
class _Context:
    original: ReferenceType[NativeGitReview | NativeGitPatch]
    scope: ReadOnlyRootScope
    attestation: GitReviewAttestation
    transport_attestation: object
    fence: str
    deadline: float
    physical: DirectoryScopeSnapshot
    patch_attestation: GitPatchAttestation | None = None


class V2NativeGitReview:
    def __init__(
        self,
        client: V2ExecutionClient,
        attestations: Mapping[SessionRef, GitReviewAttestation],
        *,
        directories: DirectoryScopeGuard | None = None,
        patch_attestations: Mapping[SessionRef, GitPatchAttestation] | None = None,
    ) -> None:
        if (
            not isinstance(client.proofs, V2LeafResourceProofs)
            or not isinstance(client.scope_guard, V2ProjectPolicyGuard)
            or client.scope_guard.proofs is not client.proofs
            or client.transport is not client.proofs.feed.transport
            or any(r != a.reference for r, a in attestations.items())
        ):
            raise ValueError("git_review_original_owner_policy_required")
        self.client, self.proofs, self.guard = client, client.proofs, client.scope_guard
        self.attestations = MappingProxyType(dict(attestations))
        self.directories = directories
        self.patch_attestations = MappingProxyType(dict(patch_attestations or {}))
        self._observed: dict[int, _Context] = {}

    def require(self, ref: SessionRef) -> GitReviewAttestation:
        project = self.client.selected(ref)
        self.proofs.select(ref)
        a = self.attestations.get(ref)
        policy = self.guard.enrollments.get(ref)
        transport = self.client.transport
        t = transport.attestation
        if (
            a is None
            or policy is None
            or self.directories is None
            or not self.directories.qualified(ref)
            or policy.native_project_id != project.upstream_project_id
            or a.schema_sha256 != INSTALLED_SCHEMA
            or transport.profile.sha256 != INSTALLED_SCHEMA
            or a.native_policy_sha256 != policy.fingerprint_sha256
            or a.semantics_sha256 != REVIEW_SEMANTICS
            or re.fullmatch(r"[0-9a-f]{64}", a.installed_evidence_sha256) is None
            or not REVIEW_OPERATIONS <= a.operations
            or t is None
            or t.backend_identity != ref.backend_identity
            or t.schema_sha256 != INSTALLED_SCHEMA
            or t.upstream_version != "2.0.32"
            or not REVIEW_OPERATIONS <= t.verified_operations
        ):
            raise ContractError("git_review_original_read_contract_not_qualified")
        return a

    def contract_for(self, ref: SessionRef) -> str:
        self.require(ref)
        return self.client.contract_for(ref)

    def qualified(self, ref: SessionRef) -> bool:
        try:
            self.require(ref)
            return True
        except ValueError:
            return False

    def require_patch(self, ref: SessionRef) -> GitPatchAttestation:
        review = self.require(ref)
        selected = self.patch_attestations.get(ref)
        if (
            not isinstance(selected, GitPatchAttestation)
            or selected.reference != ref
            or selected.review_attestation_sha256 != review_attestation_sha256(review)
            or selected.semantics_sha256 != PATCH_SEMANTICS
            or not isinstance(selected.installed_evidence_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", selected.installed_evidence_sha256) is None
            or not selected.verified_modes
            or not selected.verified_modes <= {"working", "branch", "committed"}
        ):
            raise ContractError("git_patch_projection_not_qualified")
        return selected

    def qualified_patch(self, ref: SessionRef) -> bool:
        try:
            self.require_patch(ref)
            return True
        except ValueError:
            return False

    def patch_contract_for(self, ref: SessionRef) -> str:
        self.require_patch(ref)
        return self.client.contract_for(ref)

    async def _bundle(
        self,
        ref: SessionRef,
        *,
        mode: Literal["working", "branch", "committed"],
        base: str | None,
        search: str,
        limit: int,
    ) -> dict[str, Any]:
        t = self.client.transport
        query = {"location": {"directory": ref.canonical_directory}}
        location = await t.request("location.get", query=query)
        if (
            location["directory"] != ref.canonical_directory
            or location["project"]["directory"] != ref.canonical_directory
            or location["project"]["id"] != self.client.selected(ref).upstream_project_id
        ):
            raise ContractError("git_review_original_project_location_changed")
        absolute_directory(location["project"]["canonical"])
        result: dict[str, Any] = {"location": location}
        result["worktrees"] = await t.request(
            "worktree.list", query={"projectID": self.client.selected(ref).upstream_project_id}
        )
        for operation, name, extra in (
            ("vcs.get", "info", {}),
            ("vcs.branch.list", "branches", {"search": search, "limit": str(limit + 1)}),
            ("vcs.base", "base", {}),
            ("vcs.diff", "diff", {"mode": mode, **({"base": base} if base else {})}),
        ):
            response = await t.request(operation, query={**query, **extra})
            if response["location"] != {"directory": ref.canonical_directory}:
                raise ContractError("git_review_original_location_changed")
            result[name] = response["data"]
        return result

    def _project(
        self,
        ref: SessionRef,
        raw: dict[str, Any],
        *,
        mode: Literal["working", "branch", "committed"],
        base: str | None,
        limit: int,
    ) -> tuple[NativeGitReview, tuple[str, ...]]:
        worktrees, branches, rows = raw["worktrees"], raw["branches"], raw["diff"]
        if (
            not isinstance(worktrees, list)
            or len(worktrees) > 128
            or not isinstance(branches, list)
            or len(branches) > limit + 1
            or not isinstance(rows, list)
            or len(rows) > 1000
        ):
            raise ContractError("git_review_response_capacity")
        root = absolute_directory(ref.canonical_directory)
        seen_worktrees: set[str] = set()
        visible = []
        hidden_worktrees = 0
        parents = {""}
        for row in worktrees:
            path = absolute_directory(row["directory"])
            if str(path) in seen_worktrees:
                raise ContractError("git_review_duplicate_saved_worktree")
            seen_worktrees.add(str(path))
            if not path.is_relative_to(root):
                hidden_worktrees += 1
                continue
            relative = str(path.relative_to(root)) if path != root else ""
            try:
                if relative:
                    disclosed_path(relative)
            except AccessDenied:
                hidden_worktrees += 1
                continue
            visible.append(SavedWorktree(relative_directory=relative))
            parents.add(relative)
        files = []
        hidden_files = patch_bytes = conflict_files = 0
        seen_files: set[str] = set()
        for row in rows:
            relative = canonical_relative(row["file"])
            if relative in seen_files:
                raise ContractError("git_review_duplicate_diff_path")
            seen_files.add(relative)
            patch = row["patch"].encode("utf-8")
            patch_bytes += len(patch)
            # Include hidden paths in the limit; a secret name cannot bypass it.
            if patch_bytes > 1024**2:
                raise ContractError("git_review_patch_capacity")
            conflict_files += CONFLICT_MARKER.search(row["patch"]) is not None
            try:
                disclosed_path(relative)
            except AccessDenied:
                hidden_files += 1
                continue
            files.append(
                NativeDiffSummary(
                    path=relative,
                    additions=row["additions"],
                    deletions=row["deletions"],
                    status=row["status"],
                    patch_sha256=hashlib.sha256(patch).hexdigest(),
                    patch_bytes=len(patch),
                )
            )
            parents.add(relative.rpartition("/")[0])
        if len(parents) > 32:
            raise ContractError("git_review_physical_directory_capacity")
        if len(set(branches)) != len(branches):
            raise ContractError("git_review_duplicate_branch")
        for name in branches:
            inert_text(name)
        info = raw["info"]
        view = NativeGitReview(
            reference=ref,
            provider=info.get("provider"),
            current_branch=info["branch"].get("current"),
            default_branch=info["branch"].get("default"),
            saved_worktrees=tuple(sorted(visible, key=lambda e: e.relative_directory)),
            hidden_worktrees=hidden_worktrees,
            branches=tuple(branches[:limit]),
            branches_complete=len(branches) <= limit,
            inferred_base=NativeReviewBase.model_validate(raw["base"]) if raw["base"] else None,
            mode=mode,
            requested_base=base,
            files=tuple(sorted(files, key=lambda e: e.path)),
            hidden_files=hidden_files,
            conflict_files=conflict_files,
        )
        return view, tuple(sorted(parents))

    async def read(
        self,
        ref: SessionRef,
        *,
        mode: Literal["working", "branch", "committed"] = "working",
        base: str | None = None,
        search: str = "",
        limit: int = 50,
    ) -> NativeGitReview:
        value = await self._read(ref, mode=mode, base=base, search=search, limit=limit)
        assert isinstance(value, NativeGitReview)
        return value

    async def read_patch(
        self,
        ref: SessionRef,
        *,
        path: str,
        mode: Literal["working", "branch", "committed"] = "working",
        base: str | None = None,
    ) -> NativeGitPatch:
        disclosed_path(path)
        qualification = self.require_patch(ref)
        if mode not in qualification.verified_modes:
            raise ContractError("git_patch_comparison_mode_not_qualified")
        value = await self._read(
            ref,
            mode=mode,
            base=base,
            patch_path=path,
            patch_attestation=qualification,
        )
        assert isinstance(value, NativeGitPatch)
        return value

    async def _read(
        self,
        ref: SessionRef,
        *,
        mode: Literal["working", "branch", "committed"] = "working",
        base: str | None = None,
        search: str = "",
        limit: int = 50,
        patch_path: str | None = None,
        patch_attestation: GitPatchAttestation | None = None,
    ) -> NativeGitReview | NativeGitPatch:
        # Validate before owner, policy or Native RPCs.
        if (
            mode not in {"working", "branch", "committed"}
            or (mode == "working") != (base is None)
            or type(limit) is not int
            or not 1 <= limit <= 50
            or not isinstance(search, str)
            or len(search.encode("utf-8")) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in search)
        ):
            raise ContractError("git_review_bounded_explicit_query_required")
        if base is not None:
            explicit_base(base)
        if patch_path is not None:
            # Before any RPC; direct path selection cannot bypass disclosure policy.
            disclosed_path(patch_path)
            if self.require_patch(ref) is not patch_attestation:
                raise ContractError("git_patch_projection_changed_before_read")
        elif patch_attestation is not None:
            raise ContractError("git_patch_projection_without_selected_path")
        a = self.require(ref)
        transport_attestation = self.client.transport.attestation
        scope = await self.proofs.read_scope(ref)
        deadline = scope.expires_at
        fence = self.proofs.fence(ref)
        policy_before = await self.guard.bundle(ref)
        if policy_before != (a.native_policy_sha256, scope.session_info_sha256):
            raise ContractError("git_review_original_policy_changed")
        assert self.directories is not None
        root_before = await self.directories.observe(ref, ("",))
        raw = await self._bundle(ref, mode=mode, base=base, search=search, limit=limit)
        summary, paths = self._project(ref, raw, mode=mode, base=base, limit=limit)
        view: NativeGitReview | NativeGitPatch = summary
        if patch_path is not None:
            selected = next((f for f in summary.files if f.path == patch_path), None)
            if selected is None:
                # Neither an absent nor a hidden file may disclose its name/content.
                raise ContractError("git_patch_selected_file_not_available")
            row = next(r for r in raw["diff"] if r["file"] == patch_path)
            view = NativeGitPatch(
                reference=ref,
                mode=mode,
                requested_base=base,
                file=selected,
                patch=row["patch"],
                hidden_files=summary.hidden_files,
            )
        physical = await self.directories.observe(ref, paths)
        if (
            not self.directories.current(ref, physical)
            or physical.records[0] != root_before.records[0]
        ):
            raise ContractError("git_review_physical_root_changed")
        repeated = await self._bundle(ref, mode=mode, base=base, search=search, limit=limit)
        # Exact bounded Native bundle repeated; no repository transaction claim.
        self._project(ref, repeated, mode=mode, base=base, limit=limit)
        if digest(raw) != digest(repeated):
            raise ContractError("git_review_native_review_changed")
        physical_after = await self.directories.observe(ref, paths)
        policy_after = await self.guard.bundle(ref)
        after = await self.proofs.read_scope(ref)
        now = time.time()
        if (
            self.require(ref) is not a
            or patch_path is not None
            and self.require_patch(ref) is not patch_attestation
            or self.client.transport.attestation is not transport_attestation
            or policy_after != policy_before
            or after.owner_epoch != scope.owner_epoch
            or after.connection_epoch != scope.connection_epoch
            or after.session_info_sha256 != scope.session_info_sha256
            or self.proofs.read_epoch(ref, INSTALLED_SCHEMA) != scope.connection_epoch
            or self.proofs.fence(ref) != fence
            or not scope.issued_at <= now < deadline
            or not self.directories.current(ref, root_before)
            or not self.directories.current(ref, physical)
            or not self.directories.current(ref, physical_after)
            or physical_after.fingerprint != physical.fingerprint
        ):
            raise ContractError("git_review_original_read_boundary_changed")
        self._observed = {
            key: item
            for key, item in self._observed.items()
            if item.original() is not None and item.deadline > now
        }
        if len(self._observed) >= 32:
            self._observed.pop(next(iter(self._observed)))
        self._observed[id(view)] = _Context(
            weakref(view),
            after,
            a,
            transport_attestation,
            fence,
            deadline,
            physical_after,
            patch_attestation,
        )
        if not self._current(view):
            self._observed.pop(id(view), None)
            raise ContractError("git_review_response_boundary_expired")
        return view

    def current(self, view: NativeGitReview) -> bool:
        return isinstance(view, NativeGitReview) and self._current(view)

    def current_patch(self, view: NativeGitPatch) -> bool:
        return isinstance(view, NativeGitPatch) and self._current(view)

    def _current(self, view: NativeGitReview | NativeGitPatch) -> bool:
        context = self._observed.get(id(view))
        if context is None or context.original() is not view:
            return False
        try:
            return (
                self.require(view.reference) is context.attestation
                and (
                    context.patch_attestation is None
                    if isinstance(view, NativeGitReview)
                    else self.require_patch(view.reference) is context.patch_attestation
                )
                and self.client.transport.attestation is context.transport_attestation
                and self.proofs.read_epoch(view.reference, INSTALLED_SCHEMA)
                == context.scope.connection_epoch
                and self.proofs.fence(view.reference) == context.fence
                and self.directories is not None
                and self.directories.current(view.reference, context.physical)
                and context.scope.issued_at <= time.time() < context.deadline
            )
        except ValueError:
            return False
