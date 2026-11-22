"""Stable original reader facades over atomically published graph generations.

Detached GET-only probes never become active through this module. Only the
registry's current publication cell can select a probe. Historical graph DTOs
and feed membership alone confer no resource or mutation authority.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar, cast
from weakref import WeakKeyDictionary

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.domain.enrollment_views import EnrollmentView
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LineageResourceAttestation,
        V2LineageResourceProofs,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
    from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs
    from jt_oz_bridge.services.session_graph_generations import (
        BackendGraphCell,
        SessionGraphGeneration,
    )

Function = TypeVar("Function", bound=Callable[..., Any])


@dataclass(frozen=True, eq=False)
class GraphResourceContext:
    """A sealed complete original probe, requiring fresh proofs on every use."""

    proofs: V2LineageResourceProofs
    guard: V2LineagePolicyGuard
    record: SessionAdoptionRecord
    _sealed: tuple[object, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
        from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs

        if (
            not isinstance(self.proofs, V2LineageResourceProofs)
            or not isinstance(self.guard, V2LineagePolicyGuard)
            or self.guard.proofs is not self.proofs
            or self.guard.lineage is not self.proofs
            or getattr(self.proofs, "_graph_publication", None) is not None
            or getattr(self.guard, "_graph_publication", None) is not None
        ):
            raise ContractError("original_graph_detached_probe_required")
        try:
            validated = SessionAdoptionRecord.model_validate(self.record.model_dump(mode="python"))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("original_graph_probe_record_invalid") from None
        observation = self.proofs.observation
        nodes = tuple(
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
        )
        if (
            validated.root != observation.reference
            or validated.graph_sha256 != observation.graph_sha256
            or validated.observed_owner_epoch != observation.owner_epoch
            or validated.observed_at != observation.observed_at
            or {n.reference: n for n in validated.nodes} != {n.reference: n for n in nodes}
            or set(self.guard.enrollments) != {n.reference for n in nodes}
            or validated.contract_sha256 != self.proofs.lineage_attestation.contract_sha256
        ):
            raise ContractError("original_graph_probe_record_mismatch")
        self.proofs.select(validated.root)
        object.__setattr__(
            self,
            "_sealed",
            (
                self.proofs,
                self.guard,
                self.record,
                observation,
                self.proofs.feed,
                self.proofs.lineage_attestation,
                self.guard.enrollments,
            ),
        )

    def require(self) -> None:
        if (
            getattr(self.proofs, "_graph_publication", None) is not None
            or getattr(self.guard, "_graph_publication", None) is not None
        ) or any(
            actual is not expected
            for actual, expected in zip(
                (
                    self.proofs,
                    self.guard,
                    self.record,
                    self.proofs.observation,
                    self.proofs.feed,
                    self.proofs.lineage_attestation,
                    self.guard.enrollments,
                ),
                self._sealed,
                strict=True,
            )
        ):
            raise ContractError("original_graph_probe_assembly_changed")
        self.proofs.select(self.record.root)


@dataclass(frozen=True)
class _Publication:
    cell: BackendGraphCell
    root: SessionRef
    proofs: V2LeafResourceProofs
    guard: V2ProjectPolicyGuard
    attestation: LineageResourceAttestation
    original_policies: object
    policy_view: object
    original_feed: object
    _validated: WeakKeyDictionary[SessionGraphGeneration, tuple[object, ...]] = field(
        default_factory=WeakKeyDictionary, repr=False, compare=False
    )

    def select(
        self, reference: SessionRef
    ) -> tuple[SessionGraphGeneration | None, GraphResourceContext | None]:
        generation = self.cell.generation(reference)
        if generation is None:
            if reference == self.root:
                return None, None
            raise ContractError("original_graph_active_reference_required")
        if generation.root != self.root:
            raise ContractError("original_graph_active_reference_required")
        if (
            self.guard.proofs is not self.proofs
            or self.guard.enrollments is not self.policy_view
            or self.proofs.feed is not self.original_feed
        ):
            raise ContractError("original_graph_facade_assembly_changed")
        context = generation.context
        signature = (
            context,
            generation.record,
            generation.entries,
            generation.enrollments,
            generation.parents,
            generation.descendants,
        )
        # Only frozen publication structure is memoized. Native owner, stream,
        # policies and short-lived resource witnesses still run on every call.
        previous = self._validated.get(generation)
        unchanged = previous is not None and all(
            a is b for a, b in zip(signature, previous, strict=True)
        )
        if (
            not unchanged
            and generation.enrollments
            and any(
                generation.enrollments.get(ref) is not enrollment
                for ref, enrollment in self.original_policies.items()  # type: ignore[attr-defined]
            )
        ):
            raise ContractError("original_graph_original_enrollment_changed")
        if context is None:
            # Initial composition may attach before authenticated baseline is
            # published. It retains the old exact leaf/tree behavior only.
            return generation, None
        if not isinstance(context, GraphResourceContext):
            raise ContractError("original_graph_qualified_context_required")
        context.require()
        if not unchanged and (
            generation.record != context.record
            or context.proofs.feed is not self.proofs.feed
            or context.proofs.lineage_attestation is not self.attestation
            or set(generation.entries) != {n.reference for n in context.record.nodes}
            or set(generation.enrollments) != set(context.guard.enrollments)
            or any(
                generation.enrollments[ref] is not context.guard.enrollments[ref]
                for ref in generation.enrollments
            )
        ):
            raise ContractError("original_graph_active_context_changed")
        self._validated[generation] = signature
        return generation, context


def attach_graph_generation(
    proofs: V2LeafResourceProofs,
    guard: V2ProjectPolicyGuard,
    publication: BackendGraphCell,
    root: SessionRef,
    attestation: LineageResourceAttestation,
) -> None:
    """One-time trusted composition; never publishes or reads Native resources."""
    from jt_oz_bridge.adapters.opencode.lineage_resources import LINEAGE_SEMANTICS
    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, READS

    if (
        getattr(proofs, "_graph_publication", None) is not None
        or getattr(guard, "_graph_publication", None) is not None
        or guard.proofs is not proofs
        or root not in guard.enrollments
        or publication.projects.get(root.project_id) != root.canonical_directory
        or (publication.generation(root) is not None and publication.generation(root).root != root)  # type: ignore[union-attr]
        or attestation.qualification_scope != "tree"
        or attestation.semantics != LINEAGE_SEMANTICS
        or attestation.contract_sha256 != INSTALLED_SCHEMA
        or (attestation.backend_id, attestation.backend_identity)
        != (root.backend_id, root.backend_identity)
        or not READS <= attestation.operations
    ):
        raise ContractError("original_graph_once_qualified_facade_required")
    policies = guard.enrollments

    # Do not change execution.proofs/scope_guard or any policy DTO. The view
    # itself is installed once, before the factory captures composition pins.
    def active_policies() -> Any:
        generation = publication.generation(root)
        if generation is None or not generation.enrollments:
            return policies
        return generation.enrollments

    view = EnrollmentView(active_policies)
    binding = _Publication(
        publication, root, proofs, guard, attestation, policies, view, proofs.feed
    )
    guard.enrollments = view
    if hasattr(guard, "_original_enrollments"):
        guard._original_enrollments = guard.enrollments
    proofs._graph_publication = binding
    guard._graph_publication = binding


def publication_generation(provider: Any, reference: SessionRef) -> object | None:
    binding = getattr(provider, "_graph_publication", None)
    return binding.select(reference)[0] if isinstance(binding, _Publication) else None


def generation_bound(*, policy: bool = False) -> Callable[[Function], Function]:
    """Pin the active generation around one public read/proof operation."""

    def decorate(method: Function) -> Function:
        def target(owner: Any, args: tuple[Any, ...]) -> tuple[Any, _Publication | None, Any]:
            binding = getattr(owner, "_graph_publication", None)
            if not isinstance(binding, _Publication):
                return owner, None, None
            reference = args[0] if args and isinstance(args[0], SessionRef) else binding.root
            generation, context = binding.select(reference)
            if generation is None and method.__name__ not in {
                "select",
                "project_info",
                "resource_boundary",
            }:
                raise ContractError("original_graph_active_generation_required")
            delegate = (context.guard if policy else context.proofs) if context else owner
            return delegate, binding, generation

        if inspect.iscoroutinefunction(method):

            @functools.wraps(method)
            async def asynchronous(owner: Any, *args: Any, **kwargs: Any) -> Any:
                delegate, binding, generation = target(owner, args)
                selected = method if delegate is owner else getattr(delegate, method.__name__)
                result = await (
                    selected(owner, *args, **kwargs)
                    if delegate is owner
                    else selected(*args, **kwargs)
                )
                if (
                    binding is not None
                    and generation is not None
                    and not binding.cell.current(binding.root, generation)
                ):
                    raise ContractError("original_graph_generation_changed_during_read")
                return result

            return cast(Function, asynchronous)

        @functools.wraps(method)
        def synchronous(owner: Any, *args: Any, **kwargs: Any) -> Any:
            binding = getattr(owner, "_graph_publication", None)
            if (
                method.__name__ == "select"
                and isinstance(binding, _Publication)
                and args
                and isinstance(args[0], SessionRef)
                and binding.cell.generation(args[0]) is None
            ):
                # Contract construction is metadata only. A detached new entry
                # may name a same-project, already feed-enrolled reference;
                # watch/prove/current still require its published generation.
                from jt_oz_bridge.adapters.opencode.resources import V2LeafResourceProofs

                reference = args[0]
                if reference.model_dump(exclude={"upstream_session_id"}) != binding.root.model_dump(
                    exclude={"upstream_session_id"}
                ):
                    raise ContractError("original_graph_contract_outside_project")
                return V2LeafResourceProofs.select.__wrapped__(owner, reference)  # type: ignore[attr-defined]
            delegate, binding, generation = target(owner, args)
            selected = method if delegate is owner else getattr(delegate, method.__name__)
            result = (
                selected(owner, *args, **kwargs) if delegate is owner else selected(*args, **kwargs)
            )
            if (
                binding is not None
                and generation is not None
                and not binding.cell.current(binding.root, generation)
            ):
                raise ContractError("original_graph_generation_changed_during_read")
            return result

        return cast(Function, synchronous)

    return decorate
