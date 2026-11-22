import pytest

from jt_oz_bridge.domain.control import Choice, FieldAnswer, FieldCondition, QuestionField
from jt_oz_bridge.domain.form_input import FormInputError, decode_answer, skipped_fields


@pytest.mark.parametrize(
    "raw,value",
    [("no", False), ("false", False), ("否", False), ("yes", True), ("true", True), ("是", True)],
)
def test_boolean_inputs_are_explicit_and_never_defaults(raw, value):
    field = QuestionField(id="enabled", label="Enabled", kind="boolean")
    answer = decode_answer(field, raw)
    assert answer.value is value and answer.text is None and answer.selected == ()


@pytest.mark.parametrize(
    "kind,raw,expected",
    [
        ("integer", "0", 0),
        ("integer", "-3", -3),
        ("number", "0", 0),
        ("number", "0.25", 0.25),
        ("number", "1e3", 1000.0),
        ("integer", str(2**60), 2**60),
    ],
)
def test_numeric_values_keep_types_zero_and_exact_large_values(kind, raw, expected):
    answer = decode_answer(QuestionField(id="number", label="Number", kind=kind), raw)
    assert answer.value == expected and type(answer.value) is type(expected)


@pytest.mark.parametrize(
    "kind,raw,code",
    [
        ("boolean", "0", "form.expected_boolean"),
        ("boolean", "maybe", "form.expected_boolean"),
        ("integer", "1.5", "form.expected_integer"),
        ("integer", "true", "form.expected_integer"),
        ("number", "true", "form.expected_number"),
        ("number", "NaN", "form.expected_number"),
        ("number", "1e999", "form.expected_number"),
        ("integer", str(2**53 + 1), "form.number_precision"),
    ],
)
def test_invalid_scalars_never_become_text_or_coerced_answers(kind, raw, code):
    with pytest.raises(FormInputError) as captured:
        decode_answer(QuestionField(id="value", label="Value", kind=kind), raw)
    assert captured.value.code == code


def test_text_literal_retains_whitespace_newlines_and_control_looking_content():
    field = QuestionField(id="note", label="Note", kind="text")
    literal = "  !oz stop\n```python\nprint(0)\n```\n "
    assert decode_answer(field, "-- " + literal).text == literal
    assert decode_answer(field, "ordinary text").text == "ordinary text"
    optional = field.model_copy(update={"required": False})
    assert decode_answer(optional, "--").text == ""


def test_choices_use_exact_option_ids_and_support_multiselect_custom_text():
    choices = (
        Choice(id="opaque-red", label="Red"),
        Choice(id="opaque-blue", label="Blue"),
        Choice(id="opaque-green", label="Green"),
    )
    single = QuestionField(id="mode", label="Mode", kind="single", choices=choices)
    assert decode_answer(single, "2").selected == ("opaque-blue",)
    multi = single.model_copy(update={"kind": "multi", "allow_custom_text": True})
    answer = decode_answer(multi, "1,3 --   exact custom\ntext ")
    assert (
        answer.selected == ("opaque-red", "opaque-green") and answer.text == "  exact custom\ntext "
    )
    assert decode_answer(multi, "-- custom value").text == "custom value"
    with pytest.raises(FormInputError, match="duplicate"):
        decode_answer(multi, "1,1")
    with pytest.raises(FormInputError, match="expected_choice"):
        decode_answer(single, "Blue")
    with pytest.raises(FormInputError, match="expected_single"):
        decode_answer(single, "1,2")
    with pytest.raises(FormInputError, match="custom_unavailable"):
        decode_answer(single, "-- custom")


def test_local_constraints_reject_before_any_submit_and_return_stable_codes():
    number = QuestionField(id="number", label="Number", kind="integer", minimum=0, maximum=10)
    with pytest.raises(FormInputError, match="numeric_bounds"):
        decode_answer(number, "11")
    text = QuestionField(id="text", label="Text", kind="text", min_length=3, max_length=4)
    with pytest.raises(FormInputError, match="text_bounds"):
        decode_answer(text, "-- x")
    with pytest.raises(FormInputError, match="required_answer"):
        decode_answer(text.model_copy(update={"min_length": 0}), "--")
    external = QuestionField(
        id="external",
        label="External action",
        kind="external",
        external_url="https://example.test/confirm",
    )
    with pytest.raises(FormInputError, match="expected_ack"):
        decode_answer(external, "yes")
    assert decode_answer(external, "ack").value is True


def test_skips_are_only_optional_and_are_dropped_when_conditions_change():
    fields = (
        QuestionField(id="enabled", label="Enabled", kind="boolean"),
        QuestionField(
            id="details",
            label="Details",
            kind="text",
            required=False,
            when=(FieldCondition(key="enabled", op="eq", value=True),),
        ),
    )
    assert skipped_fields(
        {"skipped": ["details"]}, fields, {"enabled": FieldAnswer(value=True)}
    ) == frozenset({"details"})
    assert (
        skipped_fields({"skipped": ["details"]}, fields, {"enabled": FieldAnswer(value=False)})
        == frozenset()
    )
    assert (
        skipped_fields(
            {"skipped": ["details"]},
            fields,
            {"enabled": FieldAnswer(value=True), "details": FieldAnswer(text="explicit")},
        )
        == frozenset()
    )
    for progress in [
        {"skipped": ["enabled"]},
        {"skipped": ["missing"]},
        {"skipped": ["details", "details"]},
        {"skipped": "details"},
        {"unknown": []},
    ]:
        with pytest.raises(ValueError, match="invalid_form_progress"):
            skipped_fields(progress, fields, {})
