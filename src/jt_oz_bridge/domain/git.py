"""Reported Native VCS state is not a staged-index or mutation confirmation proof."""

from typing import Literal

from pydantic import Field, StrictInt, field_validator

from jt_oz_bridge.domain.control import ControlModel


class NativeGitContext(ControlModel):
    provider: str | None = Field(default=None, max_length=4096)
    branch: str | None = Field(default=None, max_length=4096)
    default_branch: str | None = Field(default=None, max_length=4096)
    native_project_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reported_files: StrictInt = Field(ge=0, le=4096)
    hidden_files: StrictInt = Field(default=0, ge=0, le=4096)
    status_scope: Literal["native_combined_status"] = "native_combined_status"
    staged_index_verified: Literal[False] = False
    head_and_remote_verified: Literal[False] = False
    clean_verified: Literal[False] = False
    checks_verified: Literal[False] = False
    mutation_confirmation_usable: Literal[False] = False

    @field_validator("branch", "default_branch", "provider")
    @classmethod
    def no_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("native_vcs_context_contains_controls")
        return value
