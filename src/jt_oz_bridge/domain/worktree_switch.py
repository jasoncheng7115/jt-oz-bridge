"""Existing-original worktree selection, never new directory enrollment."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import Field, StrictBool, StrictInt

from jt_oz_bridge.domain.control import ControlModel, SessionSnapshot
from jt_oz_bridge.domain.models import SessionRef


class WorktreeSwitchSelection(ControlModel):
    original: SessionRef
    target: SessionRef
    native_project_id: str
    strategy: str
    original_physical_sha256: str
    target_physical_sha256: str
    metadata_sha256: str
    dirty_workspace: StrictBool


@dataclass(frozen=True)
class ObservedWorktreeSwitch:
    selection: WorktreeSwitchSelection
    snapshot: SessionSnapshot
    require_current: Callable[[], None]


class WorktreeSwitchObserver(Protocol):
    original: SessionRef
    target: SessionRef

    async def observe(
        self, *, authorize: Callable[[], Awaitable[None]]
    ) -> ObservedWorktreeSwitch: ...


class WorkspaceConcurrencyPolicy(ControlModel):
    """Explicit administrator policy; does not lock external Native/TUI work."""

    backend_id: str
    backend_identity: str
    canonical_directory: str
    mode: Literal["warn", "exclusive"]
    device: StrictInt = Field(ge=0)
    inode: StrictInt = Field(gt=0)
