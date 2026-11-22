"""Read-only Native review metadata; not full diff display or Git mutation proof."""

import hashlib
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.workspace_paths import disclosed_path


def inert_text(value: str) -> str:
    if not 1 <= len(value.encode("utf-8")) <= 4096 or any(
        ord(c) < 32 or ord(c) == 127 for c in value
    ):
        raise ValueError("git_review_bounded_inert_text_required")
    return value


class SavedWorktree(ControlModel):
    # Empty means the already enrolled root, never an unspecified/new directory.
    relative_directory: str = Field(max_length=4096)

    @field_validator("relative_directory")
    @classmethod
    def disclosed(cls, value: str) -> str:
        return disclosed_path(value) if value else value


class NativeReviewBase(ControlModel):
    name: str = Field(min_length=1, max_length=4096)
    ref: str = Field(min_length=1, max_length=4096)
    source: Literal["reflog", "default"]

    @field_validator("name", "ref")
    @classmethod
    def inert(cls, value: str) -> str:
        return inert_text(value)


class NativeDiffSummary(ControlModel):
    path: str = Field(min_length=1, max_length=4096)
    additions: StrictInt = Field(ge=0)
    deletions: StrictInt = Field(ge=0)
    status: Literal["added", "deleted", "modified"]
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_bytes: StrictInt = Field(ge=0, le=1024**2)

    @field_validator("path")
    @classmethod
    def disclosed(cls, value: str) -> str:
        return disclosed_path(value)


class NativeGitReview(ControlModel):
    reference: SessionRef
    provider: str | None = Field(default=None, max_length=4096)
    current_branch: str | None = Field(default=None, max_length=4096)
    default_branch: str | None = Field(default=None, max_length=4096)
    saved_worktrees: tuple[SavedWorktree, ...] = Field(max_length=128)
    hidden_worktrees: StrictInt = Field(ge=0, le=128)
    branches: tuple[str, ...] = Field(max_length=50)
    branches_complete: StrictBool
    inferred_base: NativeReviewBase | None
    mode: Literal["working", "branch", "committed"]
    requested_base: str | None = Field(default=None, max_length=255)
    files: tuple[NativeDiffSummary, ...] = Field(max_length=1000)
    hidden_files: StrictInt = Field(ge=0, le=1000)
    # Files (shown or hidden) whose patch adds a merge conflict marker line.
    conflict_files: StrictInt = Field(default=0, ge=0, le=1000)
    projection: Literal["native-review-metadata-v1"] = "native-review-metadata-v1"
    saved_inventory_only: Literal[True] = True
    full_diff_display: Literal[False] = False
    index_verified: Literal[False] = False
    head_verified: Literal[False] = False
    remote_verified: Literal[False] = False
    clean_verified: Literal[False] = False
    worktree_switch_usable: Literal[False] = False
    mutation_confirmation_usable: Literal[False] = False

    @field_validator("provider", "current_branch", "default_branch", "requested_base")
    @classmethod
    def inert_optional(cls, value: str | None) -> str | None:
        return inert_text(value) if value is not None else None

    @field_validator("branches")
    @classmethod
    def bounded_branches(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for branch in value:
            inert_text(branch)
        if len(set(value)) != len(value):
            raise ValueError("git_review_duplicate_branch")
        return value

    @model_validator(mode="after")
    def coherent(self) -> "NativeGitReview":
        if (self.mode == "working") != (self.requested_base is None):
            raise ValueError("git_review_explicit_comparison_base_required")
        if len(self.saved_worktrees) + self.hidden_worktrees > 128:
            raise ValueError("git_review_worktree_capacity")
        if len(self.files) + self.hidden_files > 1000:
            raise ValueError("git_review_diff_capacity")
        if len({e.relative_directory for e in self.saved_worktrees}) != len(self.saved_worktrees):
            raise ValueError("git_review_duplicate_worktree")
        if len({e.path for e in self.files}) != len(self.files):
            raise ValueError("git_review_duplicate_diff_path")
        return self


class NativeGitReviewReader(Protocol):
    def qualified(self, ref: SessionRef) -> bool: ...
    def contract_for(self, ref: SessionRef) -> str: ...
    async def read(
        self,
        ref: SessionRef,
        *,
        mode: Literal["working", "branch", "committed"] = "working",
        base: str | None = None,
        search: str = "",
        limit: int = 50,
    ) -> NativeGitReview: ...
    def current(self, view: NativeGitReview) -> bool: ...


class NativeGitPatch(ControlModel):
    """One Native-returned textual patch; never an index or publication proof.

    Patch text is sensitive workspace content. Callers must independently retain
    VIEW/audience/Source authorization and render through the file-menu redaction
    and bounded literal-page mechanisms. Do not serialize this DTO to a topic.
    """

    reference: SessionRef
    mode: Literal["working", "branch", "committed"]
    requested_base: str | None = Field(default=None, max_length=255)
    file: NativeDiffSummary
    patch: str = Field(max_length=1024**2)
    hidden_files: StrictInt = Field(ge=0, le=1000)
    projection: Literal["native-review-single-patch-v1"] = "native-review-single-patch-v1"
    full_diff_display: Literal[False] = False
    index_verified: Literal[False] = False
    head_verified: Literal[False] = False
    remote_verified: Literal[False] = False
    clean_verified: Literal[False] = False
    mutation_confirmation_usable: Literal[False] = False

    @field_validator("requested_base")
    @classmethod
    def inert_base(cls, value: str | None) -> str | None:
        return inert_text(value) if value is not None else None

    @model_validator(mode="after")
    def exact_text(self) -> "NativeGitPatch":
        if (self.mode == "working") != (self.requested_base is None):
            raise ValueError("git_patch_explicit_comparison_required")
        NativeDiffSummary.model_validate(self.file.model_dump(mode="python"))
        data = self.patch.encode("utf-8")
        if (
            len(data) > 1024**2
            or len(data) != self.file.patch_bytes
            or hashlib.sha256(data).hexdigest() != self.file.patch_sha256
        ):
            raise ValueError("git_patch_original_text_hash_or_bytes_changed")
        return self


@runtime_checkable
class NativeGitPatchReader(Protocol):
    """Separate opt-in contract; legacy summary readers remain unchanged."""

    def qualified_patch(self, ref: SessionRef) -> bool: ...
    def patch_contract_for(self, ref: SessionRef) -> str: ...
    async def read_patch(
        self,
        ref: SessionRef,
        *,
        path: str,
        mode: Literal["working", "branch", "committed"] = "working",
        base: str | None = None,
    ) -> NativeGitPatch: ...
    def current_patch(self, view: NativeGitPatch) -> bool: ...
