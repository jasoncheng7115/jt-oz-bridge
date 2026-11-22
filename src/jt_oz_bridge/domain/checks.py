"""Administrator-approved exact checks and original-session shell observations."""

import hashlib
from collections.abc import Awaitable, Callable
from typing import Literal, Protocol, Self

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef

type CheckAuthority = Callable[[CheckDispatchPreflight], Awaitable[None]]


class ApprovedCheck(ControlModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,47}$")
    title: str = Field(min_length=1, max_length=120)
    command: str = Field(min_length=1, max_length=8192)

    @field_validator("command", "title")
    @classmethod
    def bounded_original_text(cls, value: str) -> str:
        if not value.strip() or any(
            ord(c) < 32 and c not in "\n\t" or 127 <= ord(c) < 160 for c in value
        ):
            raise ValueError("approved_check_control_or_blank_text")
        return value


class CheckCatalog(ControlModel):
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checks: tuple[ApprovedCheck, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def unique_checks(self) -> Self:
        if len({c.id for c in self.checks}) != len(self.checks):
            raise ValueError("duplicate_approved_check_id")
        return self


class CheckSelection(ControlModel):
    reference: SessionRef
    check: ApprovedCheck
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def check_message_id(action_id: str) -> str:
    if not isinstance(action_id, str) or not 1 <= len(action_id) <= 255:
        raise ValueError("check_action_identity_required")
    return "msg_" + hashlib.sha256(("jt-oz-check:" + action_id).encode()).hexdigest()


class CheckObservation(ControlModel):
    reference: SessionRef
    action_id: str = Field(min_length=1, max_length=255)
    check: ApprovedCheck
    message_id: str
    shell_id: str = Field(min_length=1, max_length=255)
    status: Literal["running", "exited", "timeout", "killed"]
    exit_code: StrictInt | None = None
    started_at: StrictInt = Field(ge=0)
    completed_at: StrictInt | None = Field(default=None, ge=0)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output: str = Field(default="", max_length=1048576)
    output_truncated: StrictBool = False

    @model_validator(mode="after")
    def original_identity_and_terminal(self) -> Self:
        if self.message_id != check_message_id(self.action_id):
            raise ValueError("check_original_message_identity_changed")
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("check_time_order_invalid")
        if self.status == "running" and (
            self.completed_at is not None or self.exit_code is not None
        ):
            raise ValueError("running_check_has_terminal_data")
        if self.status != "running" and self.completed_at is None:
            raise ValueError("terminal_check_has_no_completion_time")
        return self

    @property
    def outcome(self) -> Literal["running", "passed", "failed", "timeout", "killed", "unknown"]:
        if self.status != "exited":
            return self.status
        return (
            "unknown" if self.exit_code is None else "passed" if self.exit_code == 0 else "failed"
        )


class CheckReader(Protocol):
    def contract_for(self, reference: SessionRef) -> str: ...
    def catalog(self, reference: SessionRef) -> CheckCatalog: ...
    def qualification_for(self, reference: SessionRef) -> str: ...
    async def observe(
        self, reference: SessionRef, action_id: str, check: ApprovedCheck
    ) -> CheckObservation | None: ...
