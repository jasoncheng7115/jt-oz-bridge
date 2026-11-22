"""GET-only qualification for two already registered, physically enrolled Roots."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.git_review import V2NativeGitReview, absolute_directory
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.worktree_switch import (
    ObservedWorktreeSwitch,
    WorktreeSwitchSelection,
)
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.storage.durable import Conflict, digest


@dataclass(frozen=True)
class WorktreeSwitchEnrollment:
    original: SessionRef
    target: SessionRef
    strategy: str
    canonical_repository_directory: str
    installed_evidence_sha256: str


class V2WorktreeSwitchObserver:
    def __init__(
        self,
        registry: SessionRegistry,
        original_review: V2NativeGitReview,
        target_review: V2NativeGitReview,
        enrollment: WorktreeSwitchEnrollment,
    ) -> None:
        self.registry, self.reviews, self.enrollment = (
            registry,
            (original_review, target_review),
            enrollment,
        )
        self.original, self.target = enrollment.original, enrollment.target
        if (
            self.original.backend_id != self.target.backend_id
            or self.original.backend_identity != self.target.backend_identity
            or self.original.upstream_session_id == self.target.upstream_session_id
            or self.original.canonical_directory == self.target.canonical_directory
            or not enrollment.strategy
            or len(enrollment.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in enrollment.installed_evidence_sha256)
        ):
            raise ValueError("worktree_switch_explicit_distinct_roots_required")
        absolute_directory(enrollment.canonical_repository_directory)
        self._entries = tuple(registry.sessions.get(ref) for ref in (self.original, self.target))
        self._assembly()

    def _assembly(self) -> None:
        projects = []
        for ref, review, entry in zip(
            (self.original, self.target), self.reviews, self._entries, strict=True
        ):
            if (
                entry is None
                or self.registry.sessions.get(ref) is not entry
                or type(entry.execution) is not V2ExecutionClient
                or review.client is not entry.execution
                or review.directories is None
            ):
                raise Conflict("worktree_switch_registered_original_assembly_required")
            generation = self.registry.publication.generation(ref)
            if generation is None or generation.root != ref:
                raise Conflict("worktree_switch_original_root_required")
            review.require(ref)
            projects.append(review.client.selected(ref).upstream_project_id)
        if projects[0] != projects[1]:
            raise Conflict("worktree_switch_native_project_changed")

    async def observe(self, *, authorize: Callable[[], Awaitable[None]]) -> ObservedWorktreeSwitch:
        self._assembly()
        task, deadline = asyncio.current_task(), time.monotonic() + 5
        registry, reviews, enrollment = self.registry, self.reviews, self.enrollment
        entries = self._entries
        generations = tuple(
            registry.publication.generation(r) for r in (self.original, self.target)
        )
        assemblies = tuple(
            (
                r.client.proofs,
                r.client.scope_guard,
                r.client.transport,
                r.client.transport.attestation,
                r.client.transport.verify_identity,
                r.directories,
                r.attestations,
                r.client.projects,
                r.client.selected(ref),
                r.proofs.model_settings,
                r.proofs.feed.transport,
                r.guard.proofs,
                r.guard.enrollments,
                r.guard.enrollments.get(ref),
                r.proofs.feed,
                getattr(r.proofs.feed, "owner", None),
            )
            for ref, r in zip((self.original, self.target), reviews, strict=True)
        )

        def assembly() -> None:
            if (
                asyncio.current_task() is not task
                or time.monotonic() >= deadline
                or self.registry is not registry
                or self.reviews is not reviews
                or self.enrollment is not enrollment
                or self._entries is not entries
            ):
                raise Conflict("worktree_switch_observation_not_current")
            self._assembly()
            for ref, review, generation, old in zip(
                (self.original, self.target), reviews, generations, assemblies, strict=True
            ):
                registry.publication.require_current(ref, generation)
                now = (
                    review.client.proofs,
                    review.client.scope_guard,
                    review.client.transport,
                    review.client.transport.attestation,
                    review.client.transport.verify_identity,
                    review.directories,
                    review.attestations,
                    review.client.projects,
                    review.client.selected(ref),
                    review.proofs.model_settings,
                    review.proofs.feed.transport,
                    review.guard.proofs,
                    review.guard.enrollments,
                    review.guard.enrollments.get(ref),
                    review.proofs.feed,
                    getattr(review.proofs.feed, "owner", None),
                )
                if any(a is not b for a, b in zip(old, now, strict=True)):
                    raise Conflict("worktree_switch_original_assembly_changed")

        async def admitted() -> None:
            assembly()
            await authorize()
            assembly()

        proofs, snapshots, physical, policies = [], [], [], []
        for ref, review in zip((self.original, self.target), reviews, strict=True):
            await admitted()
            await review.proofs.watch(ref)
            await admitted()
            snapshot, proof = await review.client.qualified_snapshot(ref)
            await admitted()
            assert review.directories is not None
            directory = await review.directories.observe(ref, ("",))
            await admitted()
            policy = await review.guard.bundle(ref)
            await admitted()
            if policy != (
                review.guard.expected_fingerprint(ref, "worktree.switch"),
                proof.session_info_sha256,
            ):
                raise Conflict("worktree_switch_original_policy_changed")
            policies.append(policy)
            snapshots.append(snapshot)
            proofs.append(proof)
            physical.append(directory)
        roots = [next(r for r in p.records if r.path == "") for p in physical]
        if (roots[0].device, roots[0].inode) == (roots[1].device, roots[1].inode):
            raise Conflict("worktree_switch_requires_distinct_physical_worktrees")
        project_id = reviews[0].client.selected(self.original).upstream_project_id

        async def bundle() -> dict[str, Any]:
            await admitted()
            rows = await reviews[0].client.transport.request(
                "worktree.list", query={"projectID": project_id}
            )
            await admitted()
            if not isinstance(rows, list) or len(rows) > 128:
                raise Conflict("worktree_switch_inventory_not_bounded")
            matches = [r for r in rows if r.get("directory") == self.target.canonical_directory]
            if len(matches) != 1 or matches[0].get("strategy") != enrollment.strategy:
                raise Conflict("worktree_switch_target_not_original_saved_worktree")
            locations, dirty = [], []
            for reference, review in zip((self.original, self.target), reviews, strict=True):
                location = await review.client.transport.request(
                    "location.get", query={"location": {"directory": reference.canonical_directory}}
                )
                await admitted()
                if (
                    location["directory"] != reference.canonical_directory
                    or location["project"]["directory"] != reference.canonical_directory
                    or location["project"]["id"] != project_id
                    or location["project"]["canonical"] != enrollment.canonical_repository_directory
                ):
                    raise Conflict("worktree_switch_target_location_changed")
                locations.append(location)
                diff = await review.client.transport.request(
                    "vcs.diff",
                    query={
                        "location": {"directory": reference.canonical_directory},
                        "mode": "working",
                    },
                )
                await admitted()
                if (
                    diff["location"] != {"directory": reference.canonical_directory}
                    or not isinstance(diff["data"], list)
                    or len(diff["data"]) > 1000
                ):
                    raise Conflict("worktree_switch_original_diff_not_bounded")
                dirty.append(
                    {"dirty": bool(diff["data"]), "sha256": digest({"diff": diff["data"]})}
                )
            return {"worktree": matches[0], "locations": locations, "dirty": dirty}

        first = await bundle()
        if first != await bundle():
            raise Conflict("worktree_switch_inventory_changed")

        for ref, review, policy in zip(
            (self.original, self.target), reviews, policies, strict=True
        ):
            if await review.guard.bundle(ref) != policy:
                raise Conflict("worktree_switch_original_policy_changed")
            await admitted()

        def current() -> None:
            assembly()
            for ref, review, proof, directory in zip(
                (self.original, self.target), reviews, proofs, physical, strict=True
            ):
                review.client.current(ref, proof)
                assert review.directories is not None
                if not review.directories.current(ref, directory):
                    raise Conflict("worktree_switch_physical_root_changed")

        current()
        selection = WorktreeSwitchSelection(
            original=self.original,
            target=self.target,
            native_project_id=project_id,
            strategy=enrollment.strategy,
            original_physical_sha256=digest(roots[0].model_dump(mode="json")),
            target_physical_sha256=digest(roots[1].model_dump(mode="json")),
            metadata_sha256=digest(first),
            dirty_workspace=any(v["dirty"] for v in first["dirty"]),
        )
        return ObservedWorktreeSwitch(selection, snapshots[1], current)
