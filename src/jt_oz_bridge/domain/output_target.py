"""An unbound discovery output target is authorization, never a session binding."""

from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.catalog import CatalogProject
from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef


class DiscoveryTarget(ControlModel):
    id: UUID
    source: HumanMessage
    audience: AudienceSnapshot
    projects: tuple[CatalogProject, ...] = Field(max_length=10)
    purpose: Literal["static", "catalog"]
    issued_at: float = Field(gt=0, allow_inf_nan=False, strict=True)
    expires_at: float = Field(gt=0, allow_inf_nan=False, strict=True)

    @model_validator(mode="after")
    def exact_target(self) -> Self:
        if (
            self.source.is_bot
            or self.source.deleted
            or self.source.revision != 0
            and self.purpose != "static"
            or not self.audience.private
            or self.audience.untrusted_bot_ids
            or self.source.author_id not in self.audience.user_ids
            or (self.source.realm_id, self.source.channel_id, self.source.topic)
            != (self.audience.realm_id, self.audience.channel_id, self.audience.canonical_topic)
        ):
            raise ValueError("invalid_discovery_output_audience")
        if not 0 < self.expires_at - self.issued_at <= 900:
            raise ValueError("invalid_discovery_output_lifetime")
        if len({project.scope.project_id for project in self.projects}) != len(self.projects):
            raise ValueError("duplicate_discovery_output_project")
        if (self.purpose == "static") != (not self.projects):
            raise ValueError("discovery_output_purpose_mismatch")
        return self


class WorktreeSwitchPreviewTarget(DiscoveryTarget):
    """Data requiring its dedicated issuer; construction grants no authority."""

    format: Literal["bound-worktree-switch-preview-v1"] = "bound-worktree-switch-preview-v1"
    original_scope: BindingScope
    target_reference: SessionRef
    operation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bound_switch(self) -> Self:
        old, target, source = self.original_scope, self.target_reference, self.source
        if (
            self.purpose != "catalog"
            or source.revision != 0
            or len(self.projects) != 2
            or (old.realm_id, old.channel_id, old.topic)
            != (source.realm_id, source.channel_id, source.topic)
            or (old.audience_revision, old.audience_user_ids)
            != (self.audience.revision, self.audience.user_ids)
            or not self.projects[0].scope.contains(old.reference)
            or not self.projects[1].scope.contains(target)
            or old.reference.backend_id != target.backend_id
            or old.reference.backend_identity != target.backend_identity
            or old.reference.canonical_directory == target.canonical_directory
            or old.reference.upstream_session_id == target.upstream_session_id
            or self.expires_at - self.issued_at > 300
        ):
            raise ValueError("invalid_bound_worktree_preview_scope")
        return self


def output_target(value: dict[str, Any]) -> DiscoveryTarget | WorktreeSwitchPreviewTarget:
    if value.get("format") == "bound-worktree-switch-preview-v1":
        return WorktreeSwitchPreviewTarget.model_validate(value)
    return DiscoveryTarget.model_validate(value)
