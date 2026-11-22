"""Original existing-session observations, separate from Native create receipts."""

from typing import Literal

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef


class ExistingSessionObservation(ControlModel):
    """Fresh metadata/policy observation; not execution, adoption or Human approval."""

    format: Literal["original-existing-session-observation-v1"] = (
        "original-existing-session-observation-v1"
    )
    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    native_created_at: StrictInt = Field(ge=0)
    parent_reference: SessionRef | None = None
    parent_created_at: StrictInt | None = Field(default=None, ge=0)
    origin_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    progress_info_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)
    starts_execution: Literal[False] = False
    registered_for_execution: Literal[False] = False

    @model_validator(mode="after")
    def coherent(self) -> "ExistingSessionObservation":
        if not 0 < self.expires_at - self.observed_at <= 5:
            raise ValueError("existing_session_original_five_second_bound_required")
        parent = self.parent_reference
        if (parent is None) != (self.parent_created_at is None):
            raise ValueError("existing_session_parent_origin_required")
        if parent is not None and (
            parent == self.reference
            or parent.model_dump(exclude={"upstream_session_id"})
            != self.reference.model_dump(exclude={"upstream_session_id"})
        ):
            raise ValueError("existing_session_parent_must_be_same_original_project")
        return self


class ExistingSessionGraphObservation(ControlModel):
    """Complete observed Root tree; still no resource/execution qualification."""

    format: Literal["original-existing-session-graph-v1"] = "original-existing-session-graph-v1"
    reference: SessionRef
    nodes: tuple[ExistingSessionObservation, ...] = Field(min_length=1, max_length=1000)
    graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)
    starts_execution: Literal[False] = False
    registered_for_execution: Literal[False] = False

    @model_validator(mode="after")
    def coherent_graph(self) -> "ExistingSessionGraphObservation":
        if not 0 < self.expires_at - self.observed_at <= 5:
            raise ValueError("existing_session_graph_original_five_second_bound_required")
        entries = {node.reference: node for node in self.nodes}
        root = entries.get(self.reference)
        if len(entries) != len(self.nodes) or root is None or root.parent_reference is not None:
            raise ValueError("existing_session_graph_unique_original_root_required")
        scope = self.reference.model_dump(exclude={"upstream_session_id"})
        for node in self.nodes:
            if (
                node.reference.model_dump(exclude={"upstream_session_id"}) != scope
                or node.native_project_id != root.native_project_id
                or node.owner_epoch != self.owner_epoch
                or node.observed_at < self.observed_at
                or node.expires_at < self.expires_at
            ):
                raise ValueError("existing_session_graph_original_scope_or_deadline_changed")
            parent = node.parent_reference
            if node is not root and (
                parent not in entries or node.parent_created_at != entries[parent].native_created_at
            ):
                raise ValueError("existing_session_graph_complete_parent_origins_required")
        # Iterative marking is bounded even for a deep 1000-node tree. Every
        # node must reach this Root, not another component or an ancestor cycle.
        complete = {self.reference}
        for node in self.nodes:
            trail: set[SessionRef] = set()
            current = node.reference
            while current not in complete:
                if current in trail or current not in entries:
                    raise ValueError("existing_session_graph_cycle_or_disconnected_node")
                trail.add(current)
                parent = entries[current].parent_reference
                if parent is None:
                    raise ValueError("existing_session_graph_single_root_required")
                current = parent
            complete.update(trail)
        return self
