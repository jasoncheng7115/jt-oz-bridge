"""Bounded file/diff projections; names do not attest any current file bytes."""

from typing import Literal, Protocol

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.storage.durable import digest


class WorkspaceEntry(ControlModel):
    path: str = Field(min_length=1, max_length=4096)
    kind: Literal["file", "directory"]

    @field_validator("path")
    @classmethod
    def safe(cls, value: str) -> str:
        return disclosed_path(value)


class WorkspaceListing(ControlModel):
    reference: SessionRef
    directory: str = Field(default="", max_length=4096)
    query: str = Field(default="", max_length=255)
    entries: tuple[WorkspaceEntry, ...] = Field(max_length=1000)
    complete: StrictBool
    hidden_count: StrictInt = Field(ge=0, le=10000)

    @field_validator("directory")
    @classmethod
    def safe_dir(cls, value: str) -> str:
        return disclosed_path(value) if value else ""

    @model_validator(mode="after")
    def unique(self) -> "WorkspaceListing":
        if len({entry.path for entry in self.entries}) != len(self.entries):
            raise ValueError("workspace_listing_duplicate_path")
        return self

    @property
    def sha256(self) -> str:
        return digest(self.model_dump(mode="json"))


class WorkspaceDiff(ControlModel):
    path: str = Field(min_length=1, max_length=4096)
    patch: str = Field(max_length=1000000)
    additions: StrictInt = Field(ge=0)
    deletions: StrictInt = Field(ge=0)
    status: Literal["added", "deleted", "modified"]

    @field_validator("path")
    @classmethod
    def safe(cls, value: str) -> str:
        return disclosed_path(value)


class WorkspaceTurn(ControlModel):
    native_id: str = Field(pattern=r"^msg_[A-Za-z0-9_-]+$", max_length=255)
    created: float = Field(ge=0, allow_inf_nan=False)
    message_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkspaceTurns(ControlModel):
    reference: SessionRef
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    next_cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    entries: tuple[WorkspaceTurn, ...] = Field(max_length=10)

    @model_validator(mode="after")
    def unique(self) -> "WorkspaceTurns":
        if len({e.native_id for e in self.entries}) != len(self.entries):
            raise ValueError("workspace_turn_duplicate_id")
        return self


class WorkspaceChanges(ControlModel):
    reference: SessionRef
    from_message: str | None = Field(default=None, pattern=r"^msg_[A-Za-z0-9_-]+$", max_length=255)
    turn_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    files: tuple[WorkspaceDiff, ...] = Field(max_length=1000)
    hidden_count: StrictInt = Field(ge=0, le=10000)

    @model_validator(mode="after")
    def bounded(self) -> "WorkspaceChanges":
        if (self.from_message is None) != (self.turn_sha256 is None):
            raise ValueError("workspace_diff_original_turn_pair_required")
        if (
            len({f.path for f in self.files}) != len(self.files)
            or sum(len(f.patch.encode("utf-8")) for f in self.files) > 1024**2
        ):
            raise ValueError("workspace_diff_duplicate_or_byte_capacity")
        return self


class WorkspaceCatalogReader(Protocol):
    def qualified(
        self, reference: SessionRef, kind: Literal["list", "find", "diff", "turns", "turn-diff"]
    ) -> bool: ...
    async def listing(
        self, reference: SessionRef, *, directory: str = "", query: str = ""
    ) -> WorkspaceListing: ...
    async def turns(
        self, reference: SessionRef, *, cursor: str | None = None
    ) -> WorkspaceTurns: ...
    async def diff(
        self,
        reference: SessionRef,
        *,
        from_message: str | None = None,
        turn_sha256: str | None = None,
    ) -> WorkspaceChanges: ...
    def current(self, value: WorkspaceListing | WorkspaceChanges | WorkspaceTurns) -> bool: ...
