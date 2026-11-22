"""Typed phone answers and optional-field progress; no defaults or regex execution."""

import json
import math
import re
from typing import Any

from jt_oz_bridge.domain.control import FieldAnswer, QuestionField, active_field, validate_answers


class FormInputError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


VALIDATION_CODES = {
    "numeric value outside bounds": "form.numeric_bounds",
    "text length outside bounds": "form.text_bounds",
    "selection count outside bounds": "form.selection_bounds",
    "required answer is empty": "form.required_answer",
    "duplicate selected option": "form.duplicate_selection",
    "custom text unavailable": "form.custom_unavailable",
    "unknown option identity": "form.expected_choice",
}


def literal_text(raw: str) -> tuple[str, bool]:
    if raw == "--":
        return "", True
    if raw.startswith(("-- ", "--\n")):
        return raw[3:], True
    return raw, False


def selected_indices(raw: str, field: QuestionField) -> tuple[str, ...]:
    if not re.fullmatch(r"[0-9]{1,10}(?:\s*,\s*[0-9]{1,10})*", raw, flags=re.ASCII):
        raise FormInputError("form.expected_choice")
    numbers = [int(part.strip()) for part in raw.split(",")]
    if len(numbers) > 10000 or any(number < 1 or number > len(field.choices) for number in numbers):
        raise FormInputError("form.expected_choice")
    if len(set(numbers)) != len(numbers):
        raise FormInputError("form.duplicate_selection")
    return tuple(field.choices[number - 1].id for number in numbers)


def decode_answer(field: QuestionField, raw: str) -> FieldAnswer:
    if len(raw) > 1000000:
        raise FormInputError("form.answer_too_large")
    text, literal = literal_text(raw)
    scalar = raw.strip()
    if field.kind == "text":
        answer = FieldAnswer(text=text)
    elif field.kind == "boolean":
        if scalar in {"yes", "true", "是"}:
            answer = FieldAnswer(value=True)
        elif scalar in {"no", "false", "否"}:
            answer = FieldAnswer(value=False)
        else:
            raise FormInputError("form.expected_boolean")
    elif field.kind == "integer":
        if len(scalar) > 64 or not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", scalar, flags=re.ASCII):
            raise FormInputError("form.expected_integer")
        answer = FieldAnswer(value=int(scalar))
    elif field.kind == "number":
        try:
            if len(scalar) > 64:
                raise ValueError("oversized")
            value = json.loads(scalar)
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or isinstance(value, float)
                and not math.isfinite(value)
            ):
                raise ValueError("not a finite number")
        except (ValueError, TypeError, RecursionError):
            raise FormInputError("form.expected_number") from None
        answer = FieldAnswer(value=value)
    elif field.kind in {"single", "multi"}:
        if literal:
            if not field.allow_custom_text:
                raise FormInputError("form.custom_unavailable")
            answer = FieldAnswer(text=text)
        else:
            before, separator, custom = raw.partition(" -- ")
            if separator and (field.kind != "multi" or not field.allow_custom_text):
                raise FormInputError("form.custom_unavailable")
            selected = (
                ()
                if before.strip() == "none" and field.kind == "multi"
                else selected_indices(before.strip(), field)
            )
            if field.kind == "single" and len(selected) != 1:
                raise FormInputError("form.expected_single_choice")
            answer = FieldAnswer(selected=selected, text=custom if separator else None)
    elif field.kind == "external":
        if scalar != "ack":
            raise FormInputError("form.expected_ack")
        answer = FieldAnswer(value=True)
    else:
        raise FormInputError("form.unsupported_field")
    if (
        isinstance(answer.value, int)
        and not isinstance(answer.value, bool)
        and int(float(answer.value)) != answer.value
    ):
        raise FormInputError("form.number_precision")
    try:
        # Validate the field in isolation; its activation was already verified
        # against the complete draft by the caller, not guessed from this answer.
        independent = field.model_copy(update={"when": ()})
        validate_answers((independent,), {field.id: answer}, complete=False)
    except ValueError as error:
        raise FormInputError(VALIDATION_CODES.get(str(error), "form.invalid_answer")) from None
    return answer


def skipped_fields(
    progress: dict[str, Any], fields: tuple[QuestionField, ...], answers: dict[str, FieldAnswer]
) -> frozenset[str]:
    raw = progress.get("skipped", [])
    if (
        progress.keys() - {"skipped"}
        or not isinstance(raw, list)
        or any(not isinstance(item, str) for item in raw)
        or len(set(raw)) != len(raw)
    ):
        raise ValueError("invalid_form_progress")
    by_id = {field.id: field for field in fields}
    if any(identity not in by_id or by_id[identity].required for identity in raw):
        raise ValueError("invalid_form_progress")
    return frozenset(
        identity
        for identity in raw
        if identity not in answers and active_field(by_id[identity], fields, answers)
    )
