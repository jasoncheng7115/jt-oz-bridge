"""Normalized backend/control contracts. Transport DTOs stay version-specific."""

import json
import math
from enum import StrEnum
from typing import Literal, Protocol, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    field_validator,
    model_validator,
)

from jt_oz_bridge.domain.models import SessionRef


class ExecutionState(StrEnum):
    UNKNOWN = "unknown"
    IDLE = "idle"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_PERMISSION = "waiting_permission"
    WAITING_INPUT = "waiting_input"
    INTERRUPTING = "interrupting"
    FAILED = "failed"
    DISCONNECTED = "disconnected"


class ControlModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class SessionSnapshot(ControlModel):
    reference: SessionRef
    title: str
    state: ExecutionState
    cursor: str
    reconciled: bool = False
    descendants: tuple[SessionRef, ...] = ()


class AudienceSnapshot(ControlModel):
    realm_id: str
    channel_id: int = Field(gt=0)
    canonical_topic: str = Field(min_length=1)
    user_ids: frozenset[int]
    untrusted_bot_ids: frozenset[int] = frozenset()
    private: bool
    revision: str


class Choice(ControlModel):
    id: str = Field(min_length=1)
    label: str


class FieldCondition(ControlModel):
    key: str
    op: Literal["eq", "neq"]
    value: StrictBool | StrictInt | StrictFloat | str

    @field_validator("value")
    @classmethod
    def finite_value(cls, value: bool | int | float | str) -> bool | int | float | str:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("condition must be finite")
        return value


class QuestionField(ControlModel):
    id: str = Field(min_length=1)
    label: str
    description: str = ""
    kind: Literal["single", "multi", "text", "boolean", "integer", "number", "external"]
    required: bool = True
    choices: tuple[Choice, ...] = ()
    allow_custom_text: bool = False
    min_length: int = Field(default=0, ge=0)
    max_length: int = Field(default=10000, ge=0, le=100000)
    minimum: float | None = Field(default=None, allow_inf_nan=False)
    maximum: float | None = Field(default=None, allow_inf_nan=False)
    min_items: int = Field(default=0, ge=0)
    max_items: int = Field(default=1000, ge=0)
    when: tuple[FieldCondition, ...] = ()
    pattern: str | None = None
    format: str | None = None
    hidden: bool = False
    external_url: str | None = None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.min_length > self.max_length:
            raise ValueError("invalid text bounds")
        if self.min_items > self.max_items or (
            self.minimum is not None and self.maximum is not None and self.minimum > self.maximum
        ):
            raise ValueError("invalid field bounds")
        if len({choice.id for choice in self.choices}) != len(self.choices):
            raise ValueError("duplicate option identity")
        if self.kind not in {"single", "multi"} and self.choices:
            raise ValueError("non-choice field cannot contain choices")
        if self.kind in {"single", "multi"} and not self.choices and not self.allow_custom_text:
            raise ValueError("choice field requires options")
        return self


class FieldAnswer(ControlModel):
    selected: tuple[str, ...] = ()
    text: str | None = None
    value: StrictBool | StrictInt | StrictFloat | None = Field(default=None, allow_inf_nan=False)


class PermissionDetails(ControlModel):
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata_json: str | None = Field(default=None, max_length=262144)
    requester_json: str | None = Field(default=None, max_length=8192)
    redactions: StrictInt = Field(default=0, ge=0)
    control_escapes: StrictInt = Field(default=0, ge=0)

    @field_validator("metadata_json", "requester_json")
    @classmethod
    def object_json(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            decoded = json.loads(value)
            if not isinstance(decoded, dict):
                raise ValueError("object required")
            json.dumps(decoded, allow_nan=False)
            return value
        except (ValueError, TypeError, RecursionError):
            raise ValueError("invalid_permission_details_json") from None


class InteractionSnapshot(ControlModel):
    reference: SessionRef
    upstream_request_id: str = Field(min_length=1)
    generation: str = Field(min_length=1)
    kind: Literal["permission", "form"]
    pending: bool
    description: str
    operation: str | None = None
    resources: tuple[str, ...] = ()
    requested_scope: tuple[str, ...] = ()
    permission_details: PermissionDetails | None = None
    fields: tuple[QuestionField, ...] = ()

    @model_validator(mode="after")
    def unique_fields(self) -> Self:
        if len({field.id for field in self.fields}) != len(self.fields):
            raise ValueError("duplicate field identity")
        if self.kind == "permission" and self.fields:
            raise ValueError("permission cannot contain form fields")
        if self.kind != "permission" and self.permission_details is not None:
            raise ValueError("permission details cannot describe a form")
        earlier: dict[str, QuestionField] = {}
        for field in self.fields:
            for condition in field.when:
                if condition.key not in earlier:
                    raise ValueError("condition must reference an earlier field")
                source = earlier[condition.key]
                if source.kind == "external":
                    raise ValueError("condition cannot reference an external acknowledgement")
                if source.kind == "boolean" and not isinstance(condition.value, bool):
                    raise ValueError("condition type mismatch")
                if source.kind in {"integer", "number"} and (
                    isinstance(condition.value, bool)
                    or not isinstance(condition.value, int | float)
                ):
                    raise ValueError("condition type mismatch")
                if source.kind in {"single", "multi", "text"} and not isinstance(
                    condition.value, str
                ):
                    raise ValueError("condition type mismatch")
                if (
                    source.kind in {"single", "multi"}
                    and not source.allow_custom_text
                    and condition.value not in {choice.id for choice in source.choices}
                ):
                    raise ValueError("condition references an unknown option")
            earlier[field.id] = field
        return self


class SessionControl(Protocol):
    """Injected connector must prove these semantics against its installed contract.

    snapshot closes subscription/snapshot races. It must never create, fork or wake
    a session. A concrete mapper still needs a separately qualified proof provider.
    """

    def contract_for(self, reference: SessionRef) -> str: ...

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot: ...
    async def interaction(self, reference: SessionRef, request_id: str) -> InteractionSnapshot: ...


class AudienceProvider(Protocol):
    async def inspect(self, realm_id: str, channel_id: int, topic: str) -> AudienceSnapshot: ...


def answer_value(
    field: QuestionField, answer: FieldAnswer
) -> str | list[str] | bool | int | float | None:
    if field.kind in {"boolean", "integer", "number", "external"}:
        return answer.value
    if field.kind == "multi":
        return [*answer.selected, *([answer.text] if answer.text is not None else [])]
    if field.kind == "single" and answer.selected:
        return answer.selected[0]
    return answer.text


def condition_equal(left: object, right: object) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def active_field(
    field: QuestionField, fields: tuple[QuestionField, ...], answers: dict[str, FieldAnswer]
) -> bool:
    by_id = {item.id: item for item in fields}
    for condition in field.when:
        if condition.key not in answers or condition.key not in by_id:
            return False
        value = answer_value(by_id[condition.key], answers[condition.key])
        matched = (
            any(condition_equal(item, condition.value) for item in value)
            if isinstance(value, list)
            else condition_equal(value, condition.value)
        )
        if (condition.op == "eq") != matched:
            return False
    return True


def validate_answers(
    fields: tuple[QuestionField, ...], answers: dict[str, FieldAnswer], *, complete: bool = True
) -> None:
    known = {field.id for field in fields}
    if not answers.keys() <= known:
        raise ValueError("unknown form field")
    for field in fields:
        answer = answers.get(field.id)
        active = active_field(field, fields, answers)
        if not active:
            if answer is not None:
                raise ValueError("form field is inactive")
            continue
        if answer is None:
            if complete and field.required:
                raise ValueError("required form field missing")
            continue
        if field.kind in {"boolean", "integer", "number", "external"}:
            if answer.selected or answer.text is not None:
                raise ValueError("scalar field requires a typed value")
            value = answer.value
            if field.kind in {"boolean", "external"}:
                if not isinstance(value, bool):
                    raise ValueError("boolean value required")
                if field.kind == "external" and value is not True:
                    raise ValueError("external field requires explicit acknowledgement")
            else:
                if isinstance(value, bool) or not isinstance(value, int | float):
                    raise ValueError("numeric value required")
                if field.kind == "integer" and isinstance(value, float) and not value.is_integer():
                    raise ValueError("integer value required")
                if (field.minimum is not None and value < field.minimum) or (
                    field.maximum is not None and value > field.maximum
                ):
                    raise ValueError("numeric value outside bounds")
            continue
        if answer.value is not None:
            raise ValueError("text/choice field cannot contain a scalar")
        if len(set(answer.selected)) != len(answer.selected):
            raise ValueError("duplicate selected option")
        if not field.allow_custom_text and not set(answer.selected) <= {
            choice.id for choice in field.choices
        }:
            raise ValueError("unknown option identity")
        if field.kind == "text" and answer.selected:
            raise ValueError("text field cannot select options")
        if field.kind == "single" and len(answer.selected) > 1:
            raise ValueError("single choice has multiple selections")
        if (
            field.kind == "single"
            and answer.selected
            and not field.min_length <= len(answer.selected[0]) <= field.max_length
        ):
            raise ValueError("text length outside bounds")
        if answer.text is not None:
            if field.kind != "text" and not field.allow_custom_text:
                raise ValueError("custom text unavailable")
            if not field.min_length <= len(answer.text) <= field.max_length:
                raise ValueError("text length outside bounds")
            if field.kind == "single" and answer.selected:
                raise ValueError("single choice cannot combine option and custom text")
        if field.kind == "multi":
            selected_count = len(answer.selected) + (answer.text is not None)
            if not field.min_items <= selected_count <= field.max_items:
                raise ValueError("selection count outside bounds")
        if field.required and not answer.selected and not (answer.text or ""):
            raise ValueError("required answer is empty")


def draft_answers(
    fields: tuple[QuestionField, ...],
    previous: dict[str, FieldAnswer],
    field_id: str,
    answer: FieldAnswer,
) -> dict[str, FieldAnswer]:
    candidates = {**previous, field_id: answer}
    if not candidates.keys() <= {field.id for field in fields}:
        raise ValueError("unknown form field")
    active: dict[str, FieldAnswer] = {}
    for field in fields:
        if active_field(field, fields, active) and field.id in candidates:
            active[field.id] = candidates[field.id]
    if field_id not in active:
        raise ValueError("cannot answer an inactive field")
    validate_answers(fields, active, complete=False)
    return active


def wire_answers(
    fields: tuple[QuestionField, ...], answers: dict[str, FieldAnswer]
) -> dict[str, str | list[str] | bool | int | float]:
    validate_answers(fields, answers)
    result: dict[str, str | list[str] | bool | int | float] = {}
    for field in fields:
        if field.id in answers:
            value = answer_value(field, answers[field.id])
            if value is not None:
                result[field.id] = value
    return result
