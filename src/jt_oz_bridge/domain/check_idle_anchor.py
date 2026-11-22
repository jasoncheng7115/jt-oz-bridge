"""Positive original idle boundary retained before a check, never a send receipt."""

from typing import Literal, Self

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.model_catalog import NativeModelRef
from jt_oz_bridge.domain.models import SessionRef


class CheckHeadBoundary(ControlModel):
    id: str = Field(min_length=1, max_length=255)
    type: Literal["idle", "model-switched", "agent-switched", "shell", "synthetic"]
    created_at: StrictInt = Field(ge=0)
    # Hash of {"latest": complete Native message}, not a stripped projection.
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("id")
    @classmethod
    def inert_identity(cls, value: str) -> str:
        if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value):
            raise ValueError("check_idle_anchor_message_identity_invalid")
        return value


class CheckPositiveIdle(ControlModel):
    id: str = Field(min_length=1, max_length=255)
    created_at: StrictInt = Field(ge=0)
    outcome: Literal["succeeded", "failed", "interrupted"]

    @field_validator("id")
    @classmethod
    def inert_identity(cls, value: str) -> str:
        return CheckHeadBoundary.inert_identity(value)

    def wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": "idle",
            "time": {"created": self.created_at},
            "outcome": self.outcome,
        }


class CheckIdleAnchor(ControlModel):
    """A qualified pre-send boundary; current observations must still prove it.

    The surrounding immutable CheckDispatchPreflight pins original owner,
    action, Root, contract and qualification. This DTO alone grants nothing.
    """

    format: Literal["native-check-positive-idle-anchor-v1"] = "native-check-positive-idle-anchor-v1"
    reference: SessionRef
    head: CheckHeadBoundary | None
    idle: CheckPositiveIdle | None
    pristine: StrictBool
    selected_model: NativeModelRef | None = None
    model_settings_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def positive_boundary_required(self) -> Self:
        if self.pristine == (self.idle is not None):
            raise ValueError("check_idle_anchor_positive_boundary_required")
        if self.head is None and not self.pristine:
            raise ValueError("check_idle_anchor_head_required")
        if self.head is not None and self.idle is not None:
            if self.head.created_at < self.idle.created_at:
                raise ValueError("check_idle_anchor_head_precedes_idle")
            if self.head.type == "idle" and (
                self.head.id != self.idle.id or self.head.created_at != self.idle.created_at
            ):
                raise ValueError("check_idle_anchor_idle_head_changed")
        if self.pristine and self.head is not None and self.head.type == "idle":
            raise ValueError("check_idle_anchor_pristine_has_idle")
        return self
