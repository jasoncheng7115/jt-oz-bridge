"""Actual benign native tool/question traces, without fabricating phone evidence."""

import hashlib
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.forms import normalize_form, normalize_permission
from jt_oz_bridge.domain.control import FieldAnswer, validate_answers, wire_answers
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_installed_opencode_evidence import REF

ROOT = Path("tests/fixtures/installed/opencode-v2.0.32")
PROFILE = OpenAPIProfile.from_file(Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json"))
INTERACTIVE = json.loads((ROOT / "parsed-interactive.json").read_text())
STOP = json.loads((ROOT / "parsed-background-stop.json").read_text())


def test_scoped_capture_and_exact_tag_interaction_sources_match_recorded_hashes():
    m = json.loads((ROOT / "manifest.json").read_text())
    for f in m["interactive_captures"] + m["interaction_source_files"]:
        b = (ROOT / f["path"]).read_bytes()
        assert hashlib.sha256(b).hexdigest() == f["sha256"]
    assert INTERACTIVE["genuine_permission_and_form_pass"] and STOP["passed"]
    assert INTERACTIVE["session_id"] == STOP["session_id"] == REF.upstream_session_id
    assert INTERACTIVE["initial_owner_epoch"] == STOP["owner_epoch"]


@pytest.mark.parametrize("event", INTERACTIVE["events"] + STOP["events"], ids=lambda e: e["type"])
def test_actual_permission_question_and_stop_frames_validate_against_installed_schema(event):
    PROFILE.sse_frame("event.subscribe", event="message", data=json.dumps(event), event_id=None)
    if event["type"].startswith(("form.", "permission.")):
        assert "durable" not in event  # Native ephemeral state is not a replay checkpoint.


def test_genuine_permission_normalizes_source_and_matches_the_one_actual_once_reply():
    raw = next(e["data"] for e in INTERACTIVE["events"] if e["type"] == "permission.asked")
    p = normalize_permission(
        PROFILE, REF, raw, INTERACTIVE["initial_owner_epoch"], pending_catalog=True
    )
    assert p.pending and p.kind == "permission" and p.operation == "read"
    assert p.resources == ("README.md",) and p.permission_details is not None
    assert p.permission_details.source_digest
    attempt = next(
        a for a in INTERACTIVE["attempts"] if a["operation"] == "session.permission.reply"
    )
    assert attempt["request_id"] == p.upstream_request_id and attempt["phase"] == "acknowledged"
    assert attempt["body_sha256"] == digest({"decision": "once"})


def test_real_question_maps_choices_and_wire_body_matches_the_acknowledged_native_reply():
    raw = next(e["data"]["form"] for e in INTERACTIVE["events"] if e["type"] == "form.created")
    form = normalize_form(
        PROFILE, REF, raw, INTERACTIVE["initial_owner_epoch"], pending_catalog=True
    )
    field = form.fields[0]
    assert form.pending and field.kind == "single" and field.id == "q0"
    answers = {field.id: FieldAnswer(selected=(field.choices[0].id,))}
    validate_answers(form.fields, answers)
    wire = {"answer": wire_answers(form.fields, answers)}
    assert wire["answer"] == INTERACTIVE["genuine_form"]["selected"]
    attempt = next(a for a in INTERACTIVE["attempts"] if a["operation"] == "session.form.reply")
    assert attempt["body_sha256"] == digest(wire) and attempt["phase"] == "acknowledged"


def test_retained_idle_outcome_is_demonstrably_not_current_execution_state():
    before, waiting, background = STOP["before"], STOP["while_waiting"], STOP["after_background"]
    assert not before["selected_active"]
    assert waiting["selected_active"] and background["selected_active"]
    assert (
        before["retained_outcome"]
        == waiting["retained_outcome"]
        == background["retained_outcome"]
        == "succeeded"
    )
    assert (
        before["retained_idle_time"]
        == waiting["retained_idle_time"]
        == background["retained_idle_time"]
    )
    assert waiting["pending_form_ids"] == background["pending_form_ids"]


def test_interrupt_ack_and_final_cancelled_form_are_distinct_positive_facts():
    assert STOP["interrupt_ack"] == {"interrupted": True}
    attempt = next(a for a in STOP["attempts"] if a["operation"] == "session.interrupt")
    assert attempt["query"] == {"resume": "false"} and attempt["state"] == "acknowledged"
    terminal = next(
        e for e in STOP["events"] if e["id"] == STOP["native_user_interrupted_event_id"]
    )
    assert (
        terminal["type"] == "session.execution.interrupted" and terminal["data"]["reason"] == "user"
    )
    assert (
        STOP["after"]["retained_outcome"] == "interrupted" and not STOP["after"]["selected_active"]
    )
    assert STOP["form_state_after_interrupt"] == {"status": "cancelled"}
    assert any(e["type"] == "session.step.failed" for e in STOP["events"])
    assert not any(e["type"] == "session.execution.failed" for e in STOP["events"])
