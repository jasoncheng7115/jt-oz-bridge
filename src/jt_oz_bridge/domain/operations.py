"""Current operation index; frozen migrations retain storage.operations v1."""

from collections.abc import Callable
from typing import Any

from jt_oz_bridge.domain.models import Capability, SessionRef
from jt_oz_bridge.domain.session_lifecycle import LIFECYCLE_OPERATIONS
from jt_oz_bridge.storage.operations import OPERATIONS

type CapabilityLookup = Callable[[SessionRef], dict[str, Capability]]

CURRENT_OPERATIONS = (
    OPERATIONS
    | LIFECYCLE_OPERATIONS
    | {
        "form.cancel",
        "model.switch",
        "session.rename",
        "check.run",
        "worktree.create",
        "agent.switch",
        "agent.adopt",
        "git.publish",
    }
)


def current_operation(payload: dict[str, Any]) -> str:
    value = payload.get("operation")
    return value if isinstance(value, str) and value in CURRENT_OPERATIONS else "unknown"
