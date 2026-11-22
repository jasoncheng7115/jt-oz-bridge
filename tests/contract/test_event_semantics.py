import hashlib
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.event_semantics import (
    SEMANTICS_SHA256,
    ProjectionState,
    completion,
    normalize,
    reduce,
)
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.native_events import LogProvenance, QualifiedLogRecord
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from tests.contract.test_v2_execution import REF

CONTEXT = LogProvenance(
    binding_id="binding",
    binding_revision=1,
    realm_id="realm",
    reference=REF,
    contract_sha256="a" * 64,
    execution_epoch="qualified-fixture-epoch",
    ownership_evidence_sha256="b" * 64,
    session_info_sha256="c" * 64,
)


def event(kind, seq, *, context=CONTEXT, capture="capture-1", **data):
    native = {
        "id": "evt_" + str(seq),
        "type": kind,
        "created": 123,
        "durable": {"aggregateID": REF.upstream_session_id, "seq": seq, "version": 1},
        "data": {"sessionID": REF.upstream_session_id, **data},
    }
    if kind == "log.synced":
        native = {
            "type": kind,
            "aggregateID": REF.upstream_session_id,
            **({"seq": seq} if seq is not None else {}),
        }
    return normalize(QualifiedLogRecord(provenance=context, capture_epoch=capture, native=native))


def receipt(**changes):
    return ExecutionReceipt(
        action_id="original-action",
        operation_digest="d" * 64,
        reference=REF,
        contract_sha256="a" * 64,
        admission=Admission(
            status="admitted",
            upstream_id="msg_bridge",
            details={"operation": "prompt", "delivery": "queue", "turn_completed": False},
        ),
        **changes,
    )


def facts(outcome="succeeded", reason=None):
    state = ProjectionState(provenance=CONTEXT)
    state = reduce(state, event("session.execution.started", 1)).state
    delivered = reduce(state, event("session.inbox.delivered", 3, inboxID="msg_bridge"))
    terminal = reduce(
        delivered.state,
        event(
            "session.execution." + outcome,
            7,
            **(
                {"reason": reason}
                if outcome == "interrupted"
                else {"error": {"_tag": "FixtureFailure"}}
                if outcome == "failed"
                else {}
            ),
        ),
    )
    return delivered, terminal


def test_preserved_official_sources_license_and_semantics_profile_hash():
    root = Path("tests/fixtures/native-v2.0.30")
    manifest = json.loads((root / "manifest.json").read_text())
    assert manifest["tag"] == "v2.0.30"
    for item in manifest["files"]:
        data = (root / item["path"]).read_bytes()
        assert len(data) == item["bytes"] and hashlib.sha256(data).hexdigest() == item["sha256"]
        assert item["verification"] == "source_tag_static_not_installed"
    assert b"MIT License" in (root / "LICENSE").read_bytes()
    mapping = {item["path"]: item["sha256"] for item in manifest["files"]}
    assert (
        hashlib.sha256(
            json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == SEMANTICS_SHA256
    )


@pytest.mark.parametrize(
    "outcome,reason,result",
    [
        ("succeeded", None, "completed"),
        ("failed", None, "failed"),
        ("interrupted", "user", "cancelled"),
        ("interrupted", "inactivity", "cancelled"),
        ("interrupted", "superseded", "cancelled"),
        ("interrupted", "shutdown", None),
    ],
)
def test_only_exact_delivered_inbox_in_qualified_busy_period_has_terminal_candidate(
    outcome, reason, result
):
    delivered, terminal = facts(outcome, reason)
    assert completion(receipt(), delivered.delivery, terminal.terminal) == result
    assert terminal.state.active is None
    assert terminal.terminal.window.native_start_id == "evt_1"


@pytest.mark.parametrize(
    "change",
    [
        "message",
        "reference",
        "contract",
        "owner",
        "status",
        "kind",
        "binding",
        "revision",
        "realm",
        "epoch",
        "window",
        "order",
    ],
)
def test_terminal_never_completes_unrelated_or_unadmitted_prompt(change):
    delivered, terminal = facts()
    admission = receipt()
    delivery, ending = delivered.delivery, terminal.terminal
    if change in {"message", "owner", "status", "kind"}:
        update = {
            "message": {"upstream_id": "msg_other"},
            "owner": {"owner": "bridge"},
            "status": {"status": "completed"},
            "kind": {"details": {"operation": "interrupt"}},
        }[change]
        admission = admission.model_copy(
            update={"admission": admission.admission.model_copy(update=update)}
        )
    elif change == "reference":
        admission = admission.model_copy(
            update={"reference": REF.model_copy(update={"upstream_session_id": "ses_other"})}
        )
    elif change == "contract":
        admission = admission.model_copy(update={"contract_sha256": "e" * 64})
    elif change == "window":
        ending = ending.model_copy(
            update={"window": ending.window.model_copy(update={"native_start_id": "evt_other"})}
        )
    elif change == "order":
        ending = ending.model_copy(update={"terminal_sequence": 2})
    else:
        update = {
            "binding": {"binding_id": "other"},
            "revision": {"binding_revision": 2},
            "realm": {"realm_id": "other"},
            "epoch": {"execution_epoch": "other"},
        }[change]
        ending = ending.model_copy(update={"provenance": CONTEXT.model_copy(update=update)})
    assert completion(admission, delivery, ending) is None


def test_native_tui_input_and_later_queue_admission_are_not_completed_by_another_turn():
    state = reduce(ProjectionState(provenance=CONTEXT), event("session.execution.started", 1)).state
    delivered = reduce(state, event("session.inbox.delivered", 3, inboxID="msg_tui"))
    terminal = reduce(delivered.state, event("session.execution.succeeded", 7))
    assert completion(receipt(), delivered.delivery, terminal.terminal) is None
    # The bridge input delivered later cannot be attached to the older busy period.
    later = reduce(terminal.state, event("session.inbox.delivered", 9, inboxID="msg_bridge"))
    assert later.delivery.window is None
    assert completion(receipt(), later.delivery, terminal.terminal) is None


def test_missing_start_or_second_start_never_guesses_completion_for_old_delivery():
    no_start = reduce(
        ProjectionState(provenance=CONTEXT),
        event("session.inbox.delivered", 0, inboxID="msg_bridge"),
    )
    terminal = reduce(no_start.state, event("session.execution.succeeded", 1))
    assert completion(receipt(), no_start.delivery, terminal.terminal) is None
    delivered, terminal = facts()
    restarted = reduce(delivered.state, event("session.execution.started", 5))
    assert restarted.continuity_gap
    ending = reduce(restarted.state, event("session.execution.succeeded", 7))
    assert completion(receipt(), delivered.delivery, ending.terminal) is None


def test_coalesced_native_inputs_can_share_one_busy_period_without_id_guessing():
    state = reduce(ProjectionState(provenance=CONTEXT), event("session.execution.started", 1)).state
    tui = reduce(state, event("session.inbox.delivered", 2, inboxID="msg_tui"))
    bridge = reduce(tui.state, event("session.inbox.delivered", 4, inboxID="msg_bridge"))
    terminal = reduce(bridge.state, event("session.execution.succeeded", 8))
    assert completion(receipt(), bridge.delivery, terminal.terminal) == "completed"
    assert completion(receipt(), tui.delivery, terminal.terminal) is None


def test_final_text_parts_preserve_original_text_and_replay_is_distinct_from_live():
    state = ProjectionState(provenance=CONTEXT)
    source = "  ```python\nprint('!oz stop')\n```\n"
    part = reduce(
        state,
        event("session.text.ended", 0, assistantMessageID="msg_assistant", ordinal=0, text=source),
    )
    assert part.text.text == source and part.text.historical
    synced = reduce(part.state, event("log.synced", 3))
    live = reduce(
        synced.state,
        event(
            "session.text.ended",
            4,
            assistantMessageID="msg_assistant",
            ordinal=1,
            text="Native TUI text",
        ),
    )
    assert not live.text.historical and live.text.ordinal == 1
    # A new capture has its own catch-up boundary, preserving known busy state.
    fresh = CONTEXT.model_copy(
        update={"session_info_sha256": "e" * 64, "ownership_evidence_sha256": "f" * 64}
    )
    resumed = reduce(
        live.state,
        event(
            "session.text.ended",
            5,
            context=fresh,
            capture="capture-2",
            assistantMessageID="msg_other",
            ordinal=0,
            text="Catch-up",
        ),
    )
    assert resumed.text.historical
    marker = reduce(resumed.state, event("log.synced", 5, context=fresh, capture="capture-2"))
    assert marker.state.replay_synced


def test_reconnect_keeps_busy_period_across_new_snapshot_digests_in_same_certified_epoch():
    delivered, terminal = facts()
    fresh = CONTEXT.model_copy(
        update={"session_info_sha256": "e" * 64, "ownership_evidence_sha256": "f" * 64}
    )
    ending = reduce(
        delivered.state, event("session.execution.succeeded", 7, context=fresh, capture="capture-2")
    )
    assert completion(receipt(), delivered.delivery, ending.terminal) == "completed"


@pytest.mark.parametrize(
    "change",
    [
        {"execution_epoch": "other"},
        {"binding_revision": 2},
        {"binding_id": "other"},
        {"realm_id": "other"},
        {"contract_sha256": "e" * 64},
    ],
)
def test_changed_authorization_or_owner_epoch_requires_explicit_reconciliation(change):
    state = ProjectionState(provenance=CONTEXT)
    with pytest.raises(ContractError, match="requires_reconciliation"):
        reduce(
            state, event("session.execution.started", 1, context=CONTEXT.model_copy(update=change))
        )


@pytest.mark.parametrize("seq", [1, 0, None])
def test_regression_duplicate_and_missing_event_positions_refuse(seq):
    state = reduce(ProjectionState(provenance=CONTEXT), event("session.execution.started", 1)).state
    if seq is None:
        malformed = event("session.renamed", 2, title="Changed").model_copy(
            update={"sequence": None}
        )
        with pytest.raises(ValueError):
            reduce(state, malformed)
    else:
        with pytest.raises(ContractError):
            reduce(state, event("session.renamed", seq, title="Changed"))


def test_empty_watermark_and_later_same_position_new_capture_are_not_fake_event_zero():
    state = ProjectionState(provenance=CONTEXT)
    first = reduce(state, event("log.synced", None))
    assert first.state.sequence is None and first.state.replay_synced
    with pytest.raises(ContractError):
        reduce(first.state, event("log.synced", None))
    second = reduce(first.state, event("log.synced", None, capture="capture-2"))
    assert second.state.sequence is None


@pytest.mark.parametrize(
    "change", ["version", "extra", "foreign", "unknown-execution", "invalid-interruption"]
)
def test_known_native_event_shape_or_version_changes_cannot_be_silently_interpreted(change):
    native = {
        "id": "evt_bad",
        "type": "session.execution.started",
        "created": 123,
        "durable": {"aggregateID": REF.upstream_session_id, "seq": 2, "version": 1},
        "data": {"sessionID": REF.upstream_session_id},
    }
    if change == "version":
        native["durable"]["version"] = 2
    elif change == "extra":
        native["data"]["PRIVATE_INPUT"] = "PRIVATE_SECRET"
    elif change == "foreign":
        native["data"]["sessionID"] = "ses_other"
    elif change == "unknown-execution":
        native["type"] = "session.execution.new-semantics"
    else:
        native.update(
            type="session.execution.interrupted",
            data={"sessionID": REF.upstream_session_id, "reason": "unknown"},
        )
    with pytest.raises(ContractError) as error:
        normalize(QualifiedLogRecord(provenance=CONTEXT, capture_epoch="capture", native=native))
    assert "PRIVATE_SECRET" not in str(error.value)


def test_ordinary_unhandled_durable_events_advance_without_invented_effect_or_action():
    state = ProjectionState(provenance=CONTEXT)
    output = reduce(
        state, event("session.tool.progress", 4, toolCallID="tool_original", message="Progress")
    )
    assert output.state.sequence == 4
    assert (
        output.delivery is output.terminal is output.text is None
        and output.state.status == state.status
    )


def steer_receipt(upstream_id="msg_steer", delivery="steer"):
    admitted = receipt()
    return admitted.model_copy(
        update={
            "action_id": "steered-action",
            "admission": admitted.admission.model_copy(
                update={
                    "upstream_id": upstream_id,
                    "details": {
                        "operation": "prompt",
                        "delivery": delivery,
                        "turn_completed": False,
                    },
                }
            ),
        }
    )


def test_a_steer_delivered_into_the_running_period_completes_with_that_period():
    state = reduce(ProjectionState(provenance=CONTEXT), event("session.execution.started", 1)).state
    head = reduce(state, event("session.inbox.delivered", 2, inboxID="msg_bridge"))
    steered = reduce(head.state, event("session.inbox.delivered", 4, inboxID="msg_steer"))
    terminal = reduce(steered.state, event("session.execution.succeeded", 8))
    assert completion(receipt(), head.delivery, terminal.terminal) == "completed"
    assert completion(steer_receipt(), steered.delivery, terminal.terminal) == "completed"
    # Each receipt matches only its own inbox ID, and only known deliveries count.
    assert completion(steer_receipt(), head.delivery, terminal.terminal) is None
    assert completion(steer_receipt(delivery="later"), steered.delivery, terminal.terminal) is None


def test_a_steer_parked_by_a_stop_completes_only_with_the_period_that_delivers_it():
    state = reduce(ProjectionState(provenance=CONTEXT), event("session.execution.started", 1)).state
    head = reduce(state, event("session.inbox.delivered", 2, inboxID="msg_bridge"))
    stopped = reduce(head.state, event("session.execution.interrupted", 5, reason="user"))
    assert completion(receipt(), head.delivery, stopped.terminal) == "cancelled"
    # The undelivered steer is not completed or cancelled by the stopped period.
    restarted = reduce(stopped.state, event("session.execution.started", 7)).state
    steered = reduce(restarted, event("session.inbox.delivered", 8, inboxID="msg_steer"))
    assert completion(steer_receipt(), steered.delivery, stopped.terminal) is None
    ending = reduce(steered.state, event("session.execution.succeeded", 9))
    assert completion(steer_receipt(), steered.delivery, ending.terminal) == "completed"
