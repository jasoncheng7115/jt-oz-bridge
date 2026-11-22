"""Original-session adoption policy/identity records, distinct from creation."""

from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.existing_sessions import ExistingSessionObservation
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest


class SessionAdoptionPolicy(ControlModel):
    format: Literal["original-session-adoption-policy-v1"] = "original-session-adoption-policy-v1"
    anchor: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_protocol_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_scope: Literal["backend"]
    operations: frozenset[str] = Field(min_length=1)


class OriginalSessionNode(ControlModel):
    reference: SessionRef
    native_created_at: StrictInt = Field(ge=0)
    parent_reference: SessionRef | None = None
    parent_created_at: StrictInt | None = Field(default=None, ge=0)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExistingSessionSelection(ControlModel):
    """Historical menu identity, never a live observation or execution grant."""

    format: Literal["original-session-selection-v1"] = "original-session-selection-v1"
    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    native_created_at: StrictInt = Field(ge=0)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_observation(
        cls,
        observed: ExistingSessionObservation,
        *,
        contract_sha256: str,
        qualification_sha256: str,
    ) -> "ExistingSessionSelection":
        if observed.parent_reference is not None or observed.parent_created_at is not None:
            raise ValueError("original_session_menu_root_required")
        return cls(
            reference=observed.reference,
            native_project_id=observed.native_project_id,
            native_created_at=observed.native_created_at,
            policy_sha256=observed.policy_sha256,
            contract_sha256=contract_sha256,
            qualification_sha256=qualification_sha256,
        )

    def matches(self, record: "SessionAdoptionRecord") -> bool:
        root = next((node for node in record.nodes if node.reference == record.root), None)
        return (
            root is not None
            and self.reference == record.root
            and self.native_project_id == record.native_project_id
            and self.native_created_at == root.native_created_at
            and self.policy_sha256 == root.policy_sha256
            and self.contract_sha256 == record.contract_sha256
            and self.qualification_sha256 == record.qualification_sha256
        )


RECORD_FORMAT = "original-session-adoption-record-v2"
# v1 qualifications also digested the whole runtime manifest; see legacy_qualified.
LEGACY_RECORD_FORMAT = "original-session-adoption-record-v1"


class SessionAdoptionRecord(ControlModel):
    """Durable identity material; not live authority, a Binding or a create receipt."""

    format: Literal[
        "original-session-adoption-record-v1", "original-session-adoption-record-v2"
    ] = "original-session-adoption-record-v2"
    root: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    nodes: tuple[OriginalSessionNode, ...] = Field(min_length=1, max_length=1000)
    observed_owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    starts_execution: Literal[False] = False
    creates_binding: Literal[False] = False

    @model_validator(mode="after")
    def original_connected_tree(self) -> Self:
        entries = {node.reference: node for node in self.nodes}
        root = entries.get(self.root)
        if len(entries) != len(self.nodes) or root is None or root.parent_reference is not None:
            raise ValueError("adoption_record_unique_original_root_required")
        scope = self.root.model_dump(exclude={"upstream_session_id"})
        for node in self.nodes:
            if node.reference.model_dump(exclude={"upstream_session_id"}) != scope:
                raise ValueError("adoption_record_original_project_required")
            parent = node.parent_reference
            if parent is None:
                if node.reference != self.root or node.parent_created_at is not None:
                    raise ValueError("adoption_record_single_original_root_required")
            elif (
                parent not in entries or node.parent_created_at != entries[parent].native_created_at
            ):
                raise ValueError("adoption_record_original_parent_origin_required")
        complete = {self.root}
        for node in self.nodes:
            trail: set[SessionRef] = set()
            cursor = node.reference
            while cursor not in complete:
                if cursor in trail or cursor not in entries:
                    raise ValueError("adoption_record_original_tree_cycle")
                trail.add(cursor)
                parent = entries[cursor].parent_reference
                if parent is None:
                    raise ValueError("adoption_record_original_tree_disconnected")
                cursor = parent
            complete.update(trail)

        def origin(node: OriginalSessionNode) -> dict[str, object]:
            return {
                "reference": node.reference.model_dump(mode="json"),
                "native_project_id": self.native_project_id,
                "created_at": node.native_created_at,
                "parent_id": node.parent_reference.upstream_session_id
                if node.parent_reference
                else None,
            }

        identities = []
        for node in sorted(self.nodes, key=lambda node: node.reference.upstream_session_id):
            observed = origin(node)
            if node.parent_reference is not None:
                observed["parent_origin_sha256"] = digest(origin(entries[node.parent_reference]))
                observed["parent_created_at"] = node.parent_created_at
            identities.append(
                {
                    "reference": node.reference.model_dump(mode="json"),
                    "origin_sha256": digest(observed),
                    "policy_sha256": node.policy_sha256,
                }
            )
        if digest({"nodes": identities}) != self.graph_sha256:
            raise ValueError("adoption_record_original_graph_digest_required")
        return self


def same_original_graph(saved: SessionAdoptionRecord, current: SessionAdoptionRecord) -> bool:
    """Same root, project, contract and every node, whatever the qualification says."""
    return (
        saved.root == current.root
        and saved.native_project_id == current.native_project_id
        and saved.contract_sha256 == current.contract_sha256
        and saved.graph_sha256 == current.graph_sha256
        and {node.reference: node for node in saved.nodes}
        == {node.reference: node for node in current.nodes}
    )
