"""Safe Native catalogs and reported usage, never credential/configuration DTOs."""

import hashlib
import math
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import Field, StrictFloat, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.git import NativeGitContext
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.security.workspace_paths import disclosed_path

type MetadataKind = Literal["agents", "commands", "skills", "mcp", "usage", "git"]
type ReportedNumber = Annotated[StrictInt | StrictFloat, Field(ge=0, allow_inf_nan=False)]


class NamedMetadata(ControlModel):
    native_id: str = Field(min_length=1, max_length=4096)
    name: str = Field(max_length=4096)

    @field_validator("native_id")
    @classmethod
    def identifier_is_inert(cls, value: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("native_metadata_identity_contains_control_character")
        return value


class AgentMetadata(NamedMetadata):
    kind: Literal["agents"] = "agents"
    mode: Literal["primary", "subagent", "all"]


class CommandMetadata(NamedMetadata):
    kind: Literal["commands"] = "commands"


class SkillMetadata(NamedMetadata):
    kind: Literal["skills"] = "skills"
    autoinvoke: bool | None = Field(default=None, strict=True)


class McpMetadata(NamedMetadata):
    kind: Literal["mcp"] = "mcp"
    status: Literal["connected", "pending", "disabled", "failed", "needs_auth"]


class GitFileMetadata(NamedMetadata):
    kind: Literal["git"] = "git"
    change: Literal["added", "deleted", "modified"]
    additions: StrictInt = Field(ge=0, le=10**12)
    deletions: StrictInt = Field(ge=0, le=10**12)

    @model_validator(mode="after")
    def original_relative_file_identity(self) -> Self:
        try:
            disclosed_path(self.name)
        except (ValueError, AccessDenied):
            raise ValueError("native_git_file_disclosure_policy_rejected") from None
        if (
            not self.name
            or "\x00" in self.name
            or len(self.name.encode()) > 4096
            or self.name.startswith("/")
            or any(p in {"", ".", ".."} for p in self.name.split("/"))
            or self.native_id != hashlib.sha256(self.name.encode()).hexdigest()
        ):
            raise ValueError("native_git_file_identity_invalid")
        return self


type MetadataItem = Annotated[
    AgentMetadata | CommandMetadata | SkillMetadata | McpMetadata | GitFileMetadata,
    Field(discriminator="kind"),
]


class NativeUsage(ControlModel):
    # All values are supplied by Native. Do not add cache/reasoning fields into
    # an invented total, or treat a missing measurement as zero.
    cost_usd: ReportedNumber
    input: ReportedNumber
    output: ReportedNumber
    reasoning: ReportedNumber
    cache_read: ReportedNumber
    cache_write: ReportedNumber

    @field_validator("*", mode="before")
    @classmethod
    def bounded_native_number(cls, value: Any) -> Any:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= value <= 10**18
            or isinstance(value, float)
            and not math.isfinite(value)
        ):
            raise ValueError("native_usage_measurement_invalid_or_capacity_exceeded")
        return value


class NativeMetadataSnapshot(ControlModel):
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: MetadataKind
    items: tuple[MetadataItem, ...] = Field(default=(), max_length=4096)
    usage: NativeUsage | None = None
    git: NativeGitContext | None = None

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.kind == "git":
            if (
                self.git is None
                or self.git.reported_files != len(self.items) + self.git.hidden_files
            ):
                raise ValueError("native_git_context_required")
        elif self.git is not None:
            raise ValueError("foreign_native_git_context")
        if self.kind == "usage":
            if self.usage is None or self.items:
                raise ValueError("usage_requires_original_measurements_without_catalog_items")
        elif self.usage is not None or any(item.kind != self.kind for item in self.items):
            raise ValueError("native_metadata_kind_mismatch")
        ids = [item.native_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_native_metadata_identity")
        return self


class NativeMetadataReader(Protocol):
    def contract_for(self, reference: SessionRef) -> str: ...
    def available_kinds(self, reference: SessionRef) -> frozenset[MetadataKind]: ...
    async def read(self, reference: SessionRef, kind: MetadataKind) -> NativeMetadataSnapshot: ...
    def current(self, snapshot: NativeMetadataSnapshot) -> bool: ...
