"""Explicit worktree creation data; never a replacement SessionRef or enrollment."""

from collections.abc import Awaitable, Callable
from pathlib import PurePosixPath
from typing import Literal, Protocol, Self
from uuid import UUID

from pydantic import Field, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef


def native_setup_command(value: str) -> str:
    """ECMAScript trim: match Native's String.trim, including BOM, excluding NEL."""
    return value.strip(
        "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
    )


class WorktreeTemplate(ControlModel):
    """Reviewed execution-capable configuration, never supplied by chat."""

    reference: SessionRef
    native_project_id: str = Field(min_length=1, max_length=255)
    destination_parent: str = Field(min_length=1, max_length=4096)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_facts_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    strategy_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    setup_command: str = Field(max_length=8192)

    @model_validator(mode="after")
    def root_descendant_parent(self) -> Self:
        root, parent = (
            PurePosixPath(self.reference.canonical_directory),
            PurePosixPath(self.destination_parent),
        )
        if (
            not root.is_absolute()
            or not parent.is_absolute()
            or str(parent) != self.destination_parent
            or ".." in parent.parts
            or not parent.is_relative_to(root)
            or parent == root
            or any(ord(c) < 32 or ord(c) == 127 for c in self.destination_parent)
            or self.setup_command != native_setup_command(self.setup_command)
        ):
            raise ValueError("worktree_reviewed_descendant_parent_required")
        return self


class WorktreeIntent(ControlModel):
    intent_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    template: WorktreeTemplate
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def name(self) -> str:
        return "jtoz-" + self.intent_id

    @property
    def directory(self) -> str:
        return str(PurePosixPath(self.template.destination_parent) / self.name)

    @property
    def branch(self) -> str:
        return "jtoz/" + self.intent_id

    @property
    def receipt_id(self) -> str:
        return str(UUID(hex=self.intent_id))


class WorktreePreflight(ControlModel):
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    comparison_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: float = Field(gt=0, allow_inf_nan=False)
    expires_at: float = Field(gt=0, allow_inf_nan=False)
    dirty_workspace: bool


class WorktreeObservation(ControlModel):
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory: str = Field(min_length=1, max_length=4096)
    native_project_id: str = Field(min_length=1, max_length=255)
    physical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    directory_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(gt=0, allow_inf_nan=False)
    status: Literal["completed", "registered_setup_unknown"]
    changes_original_session: Literal[False] = False
    grants_execution: Literal[False] = False


class WorktreeProducer(Protocol):
    template: WorktreeTemplate

    async def prepare(self, intent: WorktreeIntent) -> WorktreePreflight: ...
    def current(self, intent: WorktreeIntent, proof: WorktreePreflight) -> bool: ...
    async def create(
        self,
        intent: WorktreeIntent,
        proof: WorktreePreflight,
        *,
        authorize: Callable[[], Awaitable[None]],
    ) -> WorktreeObservation: ...
    async def reconcile(self, intent: WorktreeIntent) -> WorktreeObservation: ...
    def observation_current(
        self, intent: WorktreeIntent, observed: WorktreeObservation
    ) -> bool: ...
