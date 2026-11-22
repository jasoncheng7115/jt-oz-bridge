"""One backend publication pointer; graph identity metadata is never authority.

Trusted controllers acquire current Native/SQL authority before publishing. A
prepared generation is detached and cannot route or mutate any Native session.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING
from weakref import WeakSet

from jt_oz_bridge.domain.enrollment_views import EnrollmentView
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord
from jt_oz_bridge.domain.session_graph_extension import require_original_extension
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.storage.durable import Conflict

if TYPE_CHECKING:
    from jt_oz_bridge.services.session_registry import RegisteredSession


@dataclass(frozen=True, eq=False)
class SessionGraphGeneration:
    root: SessionRef
    record: SessionAdoptionRecord | None
    entries: Mapping[SessionRef, RegisteredSession]
    parents: Mapping[SessionRef, SessionRef | None]
    descendants: Mapping[SessionRef, tuple[SessionRef, ...]]
    enrollments: Mapping[SessionRef, object]
    context: object | None = None
    receipt: object | None = None


@dataclass(frozen=True, eq=False)
class BackendGraphState:
    sessions: Mapping[SessionRef, RegisteredSession]
    projects: Mapping[str, str]
    roots: Mapping[SessionRef, SessionGraphGeneration]
    membership: Mapping[SessionRef, SessionRef]
    enrollments: Mapping[SessionRef, object]


@dataclass(frozen=True, eq=False)
class PreparedGraphGeneration:
    generation: SessionGraphGeneration
    _base: BackendGraphState
    _next: BackendGraphState
    baseline_current: Callable[[], bool] | None = None


class BackendGraphCell:
    """Loop-owned cell with stable views and identity-based sealed issuance/CAS."""

    def __init__(self, sessions: Mapping[SessionRef, RegisteredSession]) -> None:
        self._issued: WeakSet[PreparedGraphGeneration] = WeakSet()
        roots = {
            ref: SessionGraphGeneration(
                ref,
                None,
                MappingProxyType({ref: item}),
                MappingProxyType({ref: None}),
                MappingProxyType({ref: ()}),
                MappingProxyType({}),
            )
            for ref, item in sessions.items()
        }
        self._state = self._state_for(dict(sessions), roots)
        self.sessions: EnrollmentView[SessionRef, RegisteredSession] = EnrollmentView(
            lambda: self._state.sessions
        )
        self.projects: EnrollmentView[str, str] = EnrollmentView(lambda: self._state.projects)
        self.enrollments: EnrollmentView[SessionRef, object] = EnrollmentView(
            lambda: self._state.enrollments
        )

    def snapshot(self) -> BackendGraphState:
        return self._state

    def generation(self, reference: SessionRef) -> SessionGraphGeneration | None:
        state = self._state
        root = state.membership.get(reference)
        return state.roots.get(root) if root is not None else None

    def current(self, reference: SessionRef, generation: SessionGraphGeneration | None) -> bool:
        return generation is not None and self.generation(reference) is generation

    def require_current(
        self, reference: SessionRef, generation: SessionGraphGeneration | None
    ) -> None:
        if not self.current(reference, generation):
            raise Conflict("original_session_graph_generation_changed")

    @staticmethod
    def _state_for(
        sessions: dict[SessionRef, RegisteredSession],
        roots: dict[SessionRef, SessionGraphGeneration],
    ) -> BackendGraphState:
        if not sessions or len(sessions) > 1000:
            raise Conflict("session_registration_capacity_reached")
        identity = None
        ids = set()
        projects: dict[str, str] = {}
        for ref, entry in sessions.items():
            item_identity = (ref.backend_id, ref.backend_identity, entry.contract_sha256)
            if identity is None:
                identity = item_identity
            if ref != entry.reference or item_identity != identity:
                raise AccessDenied("original_session_graph_backend_or_contract_changed")
            if ref.upstream_session_id in ids:
                raise AccessDenied("native_session_cannot_have_multiple_project_aliases")
            ids.add(ref.upstream_session_id)
            if ref.project_id in projects and projects[ref.project_id] != ref.canonical_directory:
                raise AccessDenied("session_registry_project_directory_conflict")
            projects[ref.project_id] = ref.canonical_directory
        membership = {}
        enrollments: dict[SessionRef, object] = {}
        for root, generation in roots.items():
            for ref, entry in generation.entries.items():
                if ref in membership or sessions.get(ref) is not entry:
                    raise Conflict("original_session_graph_roots_overlap")
                membership[ref] = root
            enrollments.update(generation.enrollments)
        if set(membership) != set(sessions):
            raise Conflict("original_session_graph_membership_incomplete")
        return BackendGraphState(
            MappingProxyType(sessions),
            MappingProxyType(projects),
            MappingProxyType(roots),
            MappingProxyType(membership),
            MappingProxyType(enrollments),
        )

    def prepare(
        self,
        record: SessionAdoptionRecord,
        entries: Mapping[SessionRef, RegisteredSession],
        *,
        expected: SessionGraphGeneration | None,
        enrollments: Mapping[SessionRef, object],
        context: object | None = None,
        receipt: object | None = None,
    ) -> PreparedGraphGeneration:
        record = SessionAdoptionRecord.model_validate(record.model_dump(mode="python"))
        if self._state.roots.get(record.root) is not expected:
            raise Conflict("original_session_generation_predecessor_changed")
        parents = {node.reference: node.parent_reference for node in record.nodes}
        if set(entries) != set(parents) or set(enrollments) != set(parents):
            raise Conflict("original_session_generation_complete_resources_required")
        if any(entry.contract_sha256 != record.contract_sha256 for entry in entries.values()):
            raise AccessDenied("original_session_generation_record_contract_changed")
        if expected is not None:
            if expected.record is None:
                if set(parents) != set(expected.parents) or parents != expected.parents:
                    raise Conflict("original_session_generation_baseline_required")
            else:
                try:
                    require_original_extension(expected.record, record)
                except (ValueError, TypeError):
                    raise Conflict("original_session_generation_not_strict_extension") from None
        return self._prepare(
            record.root,
            entries,
            parents,
            expected=expected,
            record=record,
            enrollments=enrollments,
            context=context,
            receipt=receipt,
        )

    def prepare_refresh(
        self,
        record: SessionAdoptionRecord,
        entries: Mapping[SessionRef, RegisteredSession],
        *,
        expected: SessionGraphGeneration,
        enrollments: Mapping[SessionRef, object],
        context: object | None = None,
        receipt: object | None = None,
    ) -> PreparedGraphGeneration:
        from jt_oz_bridge.services.session_registration_journal import registration_identity

        record = SessionAdoptionRecord.model_validate(record.model_dump(mode="python"))
        if (
            expected.record is None
            or set(entries) != set(expected.entries)
            or set(enrollments) != set(expected.entries)
            or registration_identity(record) != registration_identity(expected.record)
        ):
            raise Conflict("original_session_generation_refresh_identity_changed")
        return self._prepare(
            record.root,
            entries,
            {node.reference: node.parent_reference for node in record.nodes},
            expected=expected,
            record=record,
            enrollments=enrollments,
            context=context,
            receipt=receipt,
        )

    def prepare_bootstrap(
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
        """Trusted legacy opt-in, requiring independently proven original nodes.

        The callback is an original live guard, never inferred from the supplied
        observation. Publication does not call it: the controller must recheck
        this same guard alongside SQL/Native authority immediately before CAS.
        """
        base = self._state
        record = SessionAdoptionRecord.model_validate(record.model_dump(mode="python"))
        if base.roots.get(record.root) is not expected:
            raise Conflict("original_session_generation_predecessor_changed")
        nodes = {node.reference: node for node in record.nodes}
        try:
            original_nodes = {
                ref: OriginalSessionNode.model_validate(node.model_dump(mode="python"))
                for ref, node in original_nodes.items()
            }
        except (ValueError, TypeError, AttributeError):
            raise Conflict("original_session_generation_original_baseline_required") from None
        if (
            expected.record is not None
            or record.root != expected.root
            or set(original_nodes) != set(expected.entries)
            or any(nodes.get(ref) != node for ref, node in original_nodes.items())
            or any(
                node.reference != ref or node.parent_reference != expected.parents[ref]
                for ref, node in original_nodes.items()
            )
            or set(entries) != set(nodes)
            or set(enrollments) != set(nodes)
            or any(entry.contract_sha256 != record.contract_sha256 for entry in entries.values())
            or not callable(baseline_current)
        ):
            raise Conflict("original_session_generation_original_baseline_required")
        answer = baseline_current()
        if inspect.iscoroutine(answer):
            answer.close()
        if answer is not True:
            raise Conflict("original_session_generation_baseline_not_current")
        if self._state is not base:
            raise Conflict("original_session_generation_predecessor_changed")
        return self._prepare(
            record.root,
            entries,
            {ref: node.parent_reference for ref, node in nodes.items()},
            expected=expected,
            record=record,
            enrollments=enrollments,
            context=context,
            receipt=receipt,
            baseline_current=baseline_current,
        )

    def prepare_legacy(
        self,
        root: SessionRef,
        entries: Mapping[SessionRef, RegisteredSession],
        parents: Mapping[SessionRef, SessionRef | None],
    ) -> PreparedGraphGeneration:
        expected = self._state.roots.get(root)
        # Legacy adoption may never change an already identified graph.
        if expected is not None and expected.record is not None:
            if dict(entries) != dict(expected.entries) or dict(parents) != dict(expected.parents):
                raise Conflict("original_session_generation_record_required")
            return self._issue(expected, self._state)
        return self._prepare(root, entries, parents, expected=expected)

    def _issue(
        self,
        generation: SessionGraphGeneration,
        state: BackendGraphState,
        baseline_current: Callable[[], bool] | None = None,
    ) -> PreparedGraphGeneration:
        if len(self._issued) >= 1000:
            raise Conflict("original_session_generation_candidate_capacity")
        candidate = PreparedGraphGeneration(generation, self._state, state, baseline_current)
        self._issued.add(candidate)
        return candidate

    def _prepare(
        self,
        root: SessionRef,
        entries: Mapping[SessionRef, RegisteredSession],
        parents: Mapping[SessionRef, SessionRef | None],
        *,
        expected: SessionGraphGeneration | None,
        record: SessionAdoptionRecord | None = None,
        enrollments: Mapping[SessionRef, object] | None = None,
        context: object | None = None,
        receipt: object | None = None,
        baseline_current: Callable[[], bool] | None = None,
    ) -> PreparedGraphGeneration:
        state = self._state
        if state.roots.get(root) is not expected:
            raise Conflict("original_session_generation_predecessor_changed")
        selected, lineage, policies = dict(entries), dict(parents), dict(enrollments or {})
        if (
            not selected
            or root not in selected
            or set(selected) != set(lineage)
            or lineage[root] is not None
        ):
            raise Conflict("original_session_complete_graph_required")
        scope = root.model_dump(exclude={"upstream_session_id"})
        descendants: dict[SessionRef, list[SessionRef]] = {ref: [] for ref in selected}
        for ref, entry in selected.items():
            if ref != entry.reference or ref.model_dump(exclude={"upstream_session_id"}) != scope:
                raise AccessDenied("original_session_graph_outside_project")
            owner = state.membership.get(ref)
            if owner is not None and owner != root:
                raise Conflict("original_session_graph_roots_overlap")
            if ref in state.sessions and state.sessions[ref] is not entry:
                raise Conflict("original_session_registration_cannot_be_replaced")
            parent, visited = lineage[ref], {ref}
            if ref != root and parent is None:
                raise Conflict("original_session_graph_single_root_required")
            while parent is not None:
                if parent not in selected or parent in visited:
                    raise Conflict("original_session_graph_parent_missing_or_cyclic")
                visited.add(parent)
                descendants[parent].append(ref)
                parent = lineage[parent]
        if expected is not None:
            if any(selected.get(ref) is not item for ref, item in expected.entries.items()):
                raise Conflict("original_session_registration_cannot_be_replaced")
            if any(lineage.get(ref) != parent for ref, parent in expected.parents.items()):
                raise Conflict("original_session_generation_parent_changed")
            if any(policies.get(ref) is not item for ref, item in expected.enrollments.items()):
                raise Conflict("original_session_generation_enrollment_changed")
            if record is None and set(selected) == set(expected.entries):
                return self._issue(expected, state)
        if any(ref not in selected for ref in policies):
            raise Conflict("original_session_generation_enrollment_scope_changed")
        generation = SessionGraphGeneration(
            root,
            record,
            MappingProxyType(selected),
            MappingProxyType(lineage),
            MappingProxyType({ref: tuple(children) for ref, children in descendants.items()}),
            MappingProxyType(policies),
            context,
            receipt,
        )
        roots = dict(state.roots) | {root: generation}
        combined = dict(state.sessions) | selected
        # New roots may only use an already enrolled project's exact directory.
        if any(state.projects.get(ref.project_id) != ref.canonical_directory for ref in selected):
            raise AccessDenied("new_session_registration_outside_enrolled_project")
        return self._issue(generation, self._state_for(combined, roots), baseline_current)

    def bind_receipt(
        self, candidate: PreparedGraphGeneration, receipt: object
    ) -> PreparedGraphGeneration:
        """Consume a detached candidate and bind durable metadata, never authority.

        Preserve the original early backend CAS and all resource/context objects.
        The only replacement is the immutable root-generation envelope/receipt.
        """
        if candidate not in self._issued:
            raise Conflict("original_session_generation_candidate_not_issued")
        self._issued.discard(candidate)
        if self._state is not candidate._base:
            raise Conflict("original_session_generation_predecessor_changed")
        old = candidate.generation
        generation = SessionGraphGeneration(
            old.root,
            old.record,
            old.entries,
            old.parents,
            old.descendants,
            old.enrollments,
            old.context,
            receipt,
        )
        next_state = candidate._next
        roots = dict(next_state.roots) | {old.root: generation}
        state = BackendGraphState(
            next_state.sessions,
            next_state.projects,
            MappingProxyType(roots),
            next_state.membership,
            next_state.enrollments,
        )
        return self._issue(generation, state, candidate.baseline_current)

    def publish(self, candidate: PreparedGraphGeneration) -> SessionGraphGeneration:
        """Single pointer CAS: no await, user callback, DTO authority or I/O.

        The controller must finish its current authorization and durable journal
        CAS first. Sealed issuance is composition integrity, not Native authority.
        """
        if candidate not in self._issued:
            raise Conflict("original_session_generation_candidate_not_issued")
        self._issued.discard(candidate)
        if self._state is not candidate._base:
            raise Conflict("original_session_generation_predecessor_changed")
        self._state = candidate._next
        return candidate.generation
