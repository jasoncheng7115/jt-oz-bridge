from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class SessionRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    backend_id: str
    backend_identity: str
    upstream_session_id: str
    project_id: str
    canonical_directory: str


# Why an operation is unavailable while the Root has no current watch: a Root that just
# connected, or whose watch is being restored, is watched again within seconds.
WATCH_PENDING = "session_watch_pending"


class Capability(BaseModel):
    supported: bool = False
    scope: str
    reason: str
    upstream_version: str | None = None
    verification: str = "not_run"


class ActionState(StrEnum):
    RECEIVED = "received"
    VALIDATED = "validated"
    QUEUED = "queued"
    HELD = "held"
    DISPATCHING = "dispatching"
    ADMITTED = "admitted"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


TRANSITIONS: dict[ActionState, set[ActionState]] = {
    ActionState.RECEIVED: {ActionState.VALIDATED, ActionState.REJECTED},
    ActionState.VALIDATED: {ActionState.QUEUED, ActionState.HELD, ActionState.REJECTED},
    ActionState.QUEUED: {
        ActionState.DISPATCHING,
        ActionState.CANCELLED,
        ActionState.HELD,
        ActionState.REJECTED,
    },
    ActionState.HELD: {ActionState.QUEUED, ActionState.CANCELLED, ActionState.REJECTED},
    ActionState.DISPATCHING: {ActionState.ADMITTED, ActionState.AMBIGUOUS, ActionState.REJECTED},
    ActionState.ADMITTED: {
        ActionState.RUNNING,
        ActionState.COMPLETED,
        ActionState.FAILED,
        ActionState.CANCELLED,
    },
    ActionState.RUNNING: {ActionState.COMPLETED, ActionState.FAILED, ActionState.CANCELLED},
    ActionState.AMBIGUOUS: {ActionState.ADMITTED, ActionState.REJECTED},
    ActionState.COMPLETED: set(),
    ActionState.CANCELLED: set(),
    ActionState.REJECTED: set(),
    ActionState.FAILED: set(),
}
