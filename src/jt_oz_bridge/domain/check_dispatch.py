"""Sealed historical original-owner preflight, never proof of a Native send."""

from typing import Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.check_idle_anchor import CheckIdleAnchor
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef


class CheckDispatchPreflight(ControlModel):
    """Trusted dispatch provider output; persistence does not qualify its provider.

    Historical expiry is retained for audit. Re-reading this DTO never renews
    mutation authority and does not prove sent, admitted, completed or passed.
    """

    format: Literal["native-check-dispatch-preflight-v1"] = "native-check-dispatch-preflight-v1"
    action_id: str = Field(min_length=1, max_length=36)
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: SessionRef
    binding_id: str = Field(min_length=1, max_length=36)
    binding_revision: StrictInt = Field(ge=1)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    message_id: str = Field(pattern=r"^msg_[0-9a-f]{64}$")
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    connection_epoch: str = Field(min_length=1, max_length=255)
    ownership_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: float = Field(strict=True, ge=0, allow_inf_nan=False)
    expires_at: float = Field(strict=True, ge=0, allow_inf_nan=False)
    state: Literal["idle"] = "idle"
    idle_anchor: CheckIdleAnchor | None = None

    @field_validator("connection_epoch")
    @classmethod
    def epoch_is_metadata(cls, value: str) -> str:
        if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value):
            raise ValueError("check_dispatch_connection_epoch_invalid")
        return value

    @model_validator(mode="after")
    def original_identity_and_window(self) -> Self:
        # checks imports this DTO for typed authority; keep the import local.
        from jt_oz_bridge.domain.checks import check_message_id

        if self.message_id != check_message_id(self.action_id):
            raise ValueError("check_dispatch_original_message_identity_changed")
        if self.idle_anchor is not None and self.idle_anchor.reference != self.reference:
            raise ValueError("check_dispatch_original_idle_anchor_scope_changed")
        if not 0 < self.expires_at - self.issued_at <= 30:
            raise ValueError("check_dispatch_original_proof_window_invalid")
        return self
