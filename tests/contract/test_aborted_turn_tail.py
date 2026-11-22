"""A declined permission's aborted tail; synthetic and reconstructed, not live evidence."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from jt_oz_bridge.adapters.opencode.aborted_turn import (
    ABORTED_TURN_SEMANTICS,
    ABORTED_TURN_SOURCES,
    STEP_ABORTED,
    reconcile_aborted_turn_tail,
)
from jt_oz_bridge.adapters.opencode.agent_settings import reconcile_agent_settings_tail
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
    reconcile_model_tail,
)
from jt_oz_bridge.adapters.opencode.resources import (
    INSTALLED_SCHEMA,
    BackgroundRootWork,
    PositiveIdleRequired,
    root_state,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_leaf_resources import (
    REF,
    background_shell,
    finish,
    fixture_data,
    setup,
)
from tests.contract.test_public_live_feed import PROFILE, REAL

ROOT = Path("tests/fixtures/installed/opencode-v2.0.32")
OBSERVED = ROOT / "reconstructed-permission-reject-tail-20261104.json"
MODEL = {"providerID": "synthetic-provider", "id": "original-model", "variant": "none"}
HIGH = {**MODEL, "variant": "high"}


def observed():
    return json.loads(OBSERVED.read_text())


def rows():
    return copy.deepcopy(observed()["messages_desc"])


def info():
    row = fixture_data()["session.get"]["data"]
    row.update(copy.deepcopy(observed()["session"]))
    return row


def page(data=None, *, more=True):
    return {"data": rows() if data is None else data, "cursor": {"next": "older" if more else None}}


def serve(transport, native, tail):
    """Answer the one-latest read and the bounded 51-entry read from one store page."""
    original = transport.request
    reads = []

    async def request(operation, **kwargs):
        if operation == "session.message.list":
            reads.append(kwargs["query"]["limit"])
            current = tail()
            if kwargs["query"]["limit"] == "1":
                return {"data": current["data"][:1], "cursor": {"next": "older"}}
            return current
        return await original(operation, **kwargs)

    transport.request = request
    return reads


async def watched(tail=page, change=None, **setup_options):
    data = fixture_data()
    data["session.get"]["data"] = info()
    if change is not None:
        change(data)
    proofs, transport, data, _calls = await setup(data, **setup_options)
    reads = serve(transport, data, tail)
    return proofs, transport, data, reads


def test_preserved_native_sources_pin_the_aborted_turn_semantics():
    files = {
        "permission.ts": ROOT / "source" / "packages_core_src_permission.ts",
        "projector.ts": ROOT / "source" / "packages_core_src_session_projector.ts",
        "message-updater.ts": ROOT / "source" / "packages_core_src_session_message-updater.ts",
        "execution.ts": Path(
            "tests/fixtures/native-v2.0.30/packages_core_src_session_execution.ts"
        ),
        "run-coordinator.ts": Path(
            "tests/fixtures/native-v2.0.30/packages_core_src_session_run-coordinator.ts"
        ),
    }
    for key, path in files.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == ABORTED_TURN_SOURCES[key]
    # 2.0.32 retained these two coordinator files byte-identical to 2.0.30.
    manifest = json.loads((ROOT / "manifest.json").read_text())
    tagged = {f["path"]: f["sha256"] for f in manifest["source_tag_comparison"]}
    assert tagged["packages_core_src_session_execution.ts"] == ABORTED_TURN_SOURCES["execution.ts"]
    assert (
        tagged["packages_core_src_session_run-coordinator.ts"]
        == ABORTED_TURN_SOURCES["run-coordinator.ts"]
    )
    assert ABORTED_TURN_SEMANTICS == digest({"version": "2.0.32", "sources": ABORTED_TURN_SOURCES})
    updater = files["message-updater.ts"].read_text()
    assert 'event.data.reason === "shutdown" ? clearCurrentRetry : idle("interrupted")' in updater


def test_reconstructed_readback_keeps_no_text_and_records_the_observed_relations():
    e = observed()
    assert e["date"] == "2026-11-04" and e["version"] == "2.0.32"
    assert "GET-only" in e["scope"] and "Reconstructed" in e["scope"]
    head, user, idle, previous = e["messages_desc"]
    assert head["error"] == STEP_ABORTED and head["finish"] == "error"
    assert e["session"]["time"]["updated"] == head["time"]["completed"]
    assert e["session"]["time"]["idle"] == idle["time"]["created"]
    assert e["session"]["outcome"] == idle["outcome"] == "succeeded"
    assert user["type"] == "user" and previous["finish"] == "stop"
    assert not any("text" in row or "content" in row for row in e["messages_desc"])
    assert not any(e[k] for k in ("active", "inbox", "permissions", "forms", "shells"))


async def test_reconstructed_reject_tail_is_idle_with_an_honest_interrupted_outcome():
    proofs, transport, data, reads = await watched()
    try:
        witness = await proofs.watch(REF, require_idle=True)
        assert witness.state == ExecutionState.IDLE and not witness.pending
        # Native still retains the previous turn's success; this turn was not one.
        assert data["session.get"]["data"]["outcome"] == "succeeded"
        assert witness.last_outcome == "interrupted"
        assert "51" in reads
        proof = await proofs.prove(REF, INSTALLED_SCHEMA, digest(info()))
        assert proof.state == ExecutionState.IDLE
        assert proofs.dispatch_owner_epoch(REF, proof) == witness.owner_epoch
        # No check suffix may start from the turn entries of an aborted turn.
        with pytest.raises(ContractError, match="positive_idle_anchor_unavailable"):
            proofs.dispatch_idle_anchor(REF, proof)
    finally:
        await finish(proofs, transport)


def test_assistant_latest_without_the_reconciled_tail_is_still_unresolved():
    e = observed()
    bundle = {
        "active": False,
        "permissions": [],
        "forms": [],
        "inbox_ids": [],
        "running_shell_ids": [],
        "info": e["session"],
        "latest": {k: e["messages_desc"][0][k] for k in ("id", "type", "time")},
    }
    with pytest.raises(ContractError, match="not_positively_reconciled"):
        root_state(bundle)
    tail = reconcile_aborted_turn_tail(info(), page())
    with pytest.raises(ContractError, match="not_positively_reconciled"):
        root_state({**bundle, "aborted_turn": {**tail, "aborted": {**tail["aborted"], "id": "x"}}})
    assert root_state({**bundle, "aborted_turn": tail}) == ExecutionState.IDLE


@pytest.mark.parametrize("kind", ["running", "permission", "form"])
async def test_active_or_pending_root_keeps_its_positive_state_without_reading_the_tail(kind):
    def change(data):
        data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
        if kind != "running":
            event = next(
                e
                for e in REAL
                if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
            )
            data["session." + kind + ".list"]["data"] = [
                copy.deepcopy(event["data"] if kind == "permission" else event["data"]["form"])
            ]

    proofs, transport, _data, reads = await watched(change=change)
    try:
        with pytest.raises(PositiveIdleRequired) as raised:
            await proofs.watch(REF, require_idle=True)
        assert (
            raised.value.witness.state
            == {
                "running": ExecutionState.RUNNING,
                "permission": ExecutionState.WAITING_PERMISSION,
                "form": ExecutionState.WAITING_INPUT,
            }[kind]
        )
        assert raised.value.witness.last_outcome == "succeeded"
        assert "51" not in reads
    finally:
        await finish(proofs, transport)


async def test_queued_inbox_or_running_shell_is_never_this_idle():
    def queued(data):
        data["session.inbox.list"]["data"] = [
            {
                "id": "msg_queued",
                "sessionID": REF.upstream_session_id,
                "type": "user",
                "payload": {"text": "queued"},
                "delivery": "queue",
                "time": {"created": 1793761300000},
            }
        ]

    def shell(data):
        data["shell.list"]["data"] = [background_shell()]

    proofs, transport, _data, reads = await watched(change=queued)
    try:
        with pytest.raises(PositiveIdleRequired) as raised:
            await proofs.watch(REF, require_idle=True)
        assert raised.value.witness.state == ExecutionState.QUEUED and "51" not in reads
    finally:
        await finish(proofs, transport)
    proofs, transport, _data, reads = await watched(change=shell)
    try:
        with pytest.raises(BackgroundRootWork):
            await proofs.watch(REF, require_idle=True)
        assert "51" not in reads
    finally:
        await finish(proofs, transport)


def changed(kind):
    data = rows()
    current = info()
    more = True
    if kind == "error-type":
        data[0]["error"] = {"type": "provider", "message": "Step interrupted"}
    elif kind == "error-message":
        data[0]["error"] = {"type": "aborted", "message": "Tool execution interrupted"}
    elif kind == "error-extra-field":
        data[0]["error"] = {**STEP_ABORTED, "cause": "other"}
    elif kind == "finish":
        data[0]["finish"] = "stop"
    elif kind == "retry":
        data[0]["retry"] = {"attempt": 1}
    elif kind == "unfinished":
        del data[0]["time"]["completed"]
    elif kind == "completed-after-session-update":
        current["time"]["updated"] = data[0]["time"]["completed"] - 1
    elif kind == "unrelated-entry":
        data.insert(
            2, {"id": "msg_synthetic", "type": "synthetic", "time": {"created": 1793761200000}}
        )
    elif kind == "setting-inside-turn":
        data.insert(
            2,
            {
                "id": "msg_model",
                "type": "model-switched",
                "model": MODEL,
                "time": {"created": 1793761200000},
            },
        )
    elif kind == "other-failed-step":
        data.insert(
            1,
            {
                "id": "msg_failed_step",
                "type": "assistant",
                "time": {"created": 1793761210200, "completed": 1793761210250},
                "error": {"type": "provider", "message": "upstream failed"},
                "finish": "error",
            },
        )
    elif kind == "unfinished-earlier-step":
        data.insert(1, {"id": "msg_step", "type": "assistant", "time": {"created": 1793761210200}})
    elif kind == "missing-user":
        del data[1]
    elif kind == "idle-outcome":
        current["outcome"] = "failed"
    elif kind == "idle-time":
        current["time"]["idle"] += 1
    elif kind == "time-order":
        data[1]["time"]["created"] = data[0]["time"]["created"] + 1
    elif kind == "duplicate":
        data[1]["id"] = data[0]["id"]
    elif kind == "page-boundary":
        filler = [
            {"id": f"msg_user_{i}", "type": "user", "time": {"created": 1793761210000 - i}}
            for i in range(49)
        ]
        data = data[:2] + filler
    elif kind == "more-history-without-idle":
        data = data[:2]
    elif kind == "pristine-with-retained-outcome":
        data, more = data[:2], False
    return current, {"data": data, "cursor": {"next": "older" if more else None}}


NEGATIVE = [
    "error-type",
    "error-message",
    "error-extra-field",
    "finish",
    "retry",
    "unfinished",
    "completed-after-session-update",
    "unrelated-entry",
    "setting-inside-turn",
    "other-failed-step",
    "unfinished-earlier-step",
    "missing-user",
    "idle-outcome",
    "idle-time",
    "time-order",
    "duplicate",
    "page-boundary",
    "more-history-without-idle",
    "pristine-with-retained-outcome",
]


@pytest.mark.parametrize("kind", NEGATIVE)
def test_only_the_exact_aborted_turn_shape_reaches_the_previous_idle(kind):
    current, tail = changed(kind)
    with pytest.raises(ContractError):
        reconcile_aborted_turn_tail(current, tail)


@pytest.mark.parametrize("kind", ["error-type", "unrelated-entry", "idle-time", "page-boundary"])
async def test_leaf_watch_fails_closed_on_any_unexpected_tail(kind):
    current, tail = changed(kind)

    def change(data):
        data["session.get"]["data"] = current

    proofs, transport, _data, _reads = await watched(lambda: copy.deepcopy(tail), change)
    try:
        with pytest.raises(ContractError):
            await proofs.watch(REF, require_idle=True)
        assert not proofs.holds_watch(REF)
    finally:
        await finish(proofs, transport)


async def test_newer_user_message_after_the_aborted_turn_is_not_idle():
    newer = [{"id": "msg_newer_user", "type": "user", "time": {"created": 1793761295000}}] + rows()

    def change(data):
        data["session.get"]["data"]["time"]["updated"] = 1793761295000

    proofs, transport, _data, reads = await watched(lambda: page(newer), change)
    try:
        with pytest.raises(ContractError, match="not_positively_reconciled"):
            await proofs.watch(REF, require_idle=True)
        assert "51" not in reads
    finally:
        await finish(proofs, transport)


async def test_a_newer_native_idle_keeps_the_normal_path_and_its_outcome():
    newer = [
        {
            "id": "msg_newer_idle",
            "type": "idle",
            "time": {"created": 1793761291000},
            "outcome": "interrupted",
        }
    ] + rows()

    def change(data):
        data["session.get"]["data"].update(outcome="interrupted")
        data["session.get"]["data"]["time"].update(idle=1793761291000)

    proofs, transport, _data, reads = await watched(lambda: page(newer), change)
    try:
        witness = await proofs.watch(REF, require_idle=True)
        assert witness.state == ExecutionState.IDLE and witness.last_outcome == "interrupted"
        assert "51" not in reads
        proof = await proofs.prove(REF, INSTALLED_SCHEMA, witness.session_info_sha256)
        assert proofs.dispatch_idle_anchor(REF, proof).idle.id == "msg_newer_idle"
    finally:
        await finish(proofs, transport)


def test_consecutive_declines_multi_step_turns_and_later_session_touches_stay_idle():
    first, user, idle, previous = rows()
    second = copy.deepcopy(first)
    second.update(id="msg_second_aborted")
    second["time"] = {"created": 1793761400000, "completed": 1793761410000}
    step = {
        "id": "msg_first_step",
        "type": "assistant",
        "time": {"created": 1793761210200, "completed": 1793761210250},
        "finish": "tool-calls",
    }
    current = info()
    current["time"]["updated"] = 1793761500000  # e.g. a later rename, never execution
    tail = reconcile_aborted_turn_tail(
        current,
        page(
            [
                second,
                {"id": "msg_second_user", "type": "user", "time": {"created": 1793761300000}},
                first,
                step,
                user,
                idle,
                previous,
            ]
        ),
    )
    assert tail["aborted"]["id"] == "msg_second_aborted" and tail["idle"]["id"] == idle["id"]
    assert [row["id"] for row in tail["turn"]][-2:] == ["msg_first_step", user["id"]]
    assert not any("text" in row or "content" in row for row in tail["turn"])


def test_first_turn_of_a_new_session_declined_needs_the_complete_history():
    current = info()
    current.pop("outcome")
    current["time"].pop("idle")
    tail = reconcile_aborted_turn_tail(current, page(rows()[:2], more=False))
    assert tail["pristine"] and tail["idle"] is None
    with pytest.raises(ContractError):
        reconcile_aborted_turn_tail(current, page(rows()[:2], more=True))


def attestation():
    return ModelSettingsAttestation(REF, INSTALLED_SCHEMA, MODEL_SETTING_SEMANTICS, "a" * 64)


def switched():
    return [
        {
            "id": "msg_model_after_reject",
            "type": "model-switched",
            "model": MODEL,
            "previous": HIGH,
            "time": {"created": 1793761300000},
        }
    ] + rows()


async def test_model_change_after_a_decline_still_reaches_the_previous_idle():
    def change(data):
        data["session.get"]["data"].update(model=dict(MODEL))
        data["session.get"]["data"]["time"]["updated"] = 1793761300000

    proofs, transport, _data, reads = await watched(lambda: page(switched()), change)
    proofs.model_settings = attestation()
    try:
        witness = await proofs.watch(REF, require_idle=True)
        assert witness.state == ExecutionState.IDLE and witness.last_outcome == "interrupted"
        proof = await proofs.prove(REF, INSTALLED_SCHEMA, witness.session_info_sha256)
        with pytest.raises(ContractError, match="positive_idle_anchor_unavailable"):
            proofs.dispatch_idle_anchor(REF, proof)
    finally:
        await finish(proofs, transport)


def test_model_tail_composes_only_with_a_reconciled_non_pristine_aborted_turn():
    current = info()
    current.update(model=dict(MODEL))
    current["time"]["updated"] = 1793761300000
    tail = reconcile_model_tail(current, page(switched()))
    assert tail["idle"]["id"] == "msg_reconstructed_previous_idle"
    assert tail["aborted_turn"]["aborted"]["id"] == "msg_reconstructed_reject_assistant"
    broken = switched()
    broken[1]["error"] = {"type": "provider", "message": "Step interrupted"}
    with pytest.raises(ContractError):
        reconcile_model_tail(current, page(broken))
    late = switched()
    late[0]["time"]["created"] = late[1]["time"]["completed"] - 1  # switched mid-turn
    with pytest.raises(ContractError):
        reconcile_model_tail(current, page(late))
    pristine = info()
    pristine.update(model=dict(MODEL))
    pristine.pop("outcome")
    pristine["time"].pop("idle")
    with pytest.raises(ContractError):
        reconcile_model_tail(pristine, page(switched()[:3], more=False))


@pytest.mark.parametrize("shape", ["declined", "other-error"])
async def test_local_inspection_classifies_the_same_tail_and_never_borrows_the_old_success(shape):
    from tests.contract.test_local_inspection_native import setup as inspection_setup

    inspector, proofs, transport, data, _pages, _page_calls, writes = await inspection_setup()
    data["session.get"]["data"].update(copy.deepcopy(observed()["session"]))
    tail = rows()
    if shape == "other-error":
        tail[0]["error"] = {"type": "provider", "message": "Step interrupted"}
    reads = serve(transport, data, lambda: page(copy.deepcopy(tail)))
    try:
        row = await inspector.detail(REF.upstream_session_id)
        if shape == "declined":
            assert row.state == ExecutionState.IDLE and row.last_outcome == "interrupted"
            assert row.state_reason == "repeated_resources" and "51" in reads
        else:
            assert row.state == ExecutionState.UNKNOWN
            assert row.state_reason == "resource_unavailable" and "51" not in reads
        assert not writes
    finally:
        await finish(proofs, transport)


def installed(row, text="synthetic"):
    """Installed-schema fields the readback omits; synthetic, never live content."""
    row = copy.deepcopy(row)
    if row["type"] == "assistant":
        row.update(agent="build", model=dict(MODEL), content=[])
    elif row["type"] == "user":
        row["text"] = text
    return row


def test_reconstructed_rows_are_legal_installed_schema_entries_once_completed():
    PROFILE.response(
        "session.message.list", 200, {"data": [installed(r) for r in rows()], "cursor": {}}
    )


def test_agent_tail_composes_only_behind_an_agent_change_with_a_positive_idle():
    from tests.contract.test_native_agent_settings import qualification

    current = info()
    current.update(agent="review", model=dict(MODEL))
    current["time"]["updated"] = 1793761300000
    switch = {
        "id": "msg_agent_after_reject",
        "type": "agent-switched",
        "agent": "review",
        "previous": "build",
        "time": {"created": 1793761300000},
    }
    raw = {"data": [switch] + [installed(r) for r in rows()], "cursor": {"next": "older"}}
    result = reconcile_agent_settings_tail(PROFILE, REF, current, raw, qualification())
    assert result["idle"]["id"] == "msg_reconstructed_previous_idle"
    assert result["aborted_turn"]["aborted"]["error"] == STEP_ABORTED
    model_only = copy.deepcopy(raw)
    model_only["data"][0] = {
        "id": "msg_model_after_reject",
        "type": "model-switched",
        "model": MODEL,
        "time": {"created": 1793761300000},
    }
    with pytest.raises(ContractError):
        reconcile_agent_settings_tail(PROFILE, REF, current, model_only, qualification())
    other = copy.deepcopy(raw)
    other["data"][1]["error"] = {"type": "provider", "message": "Step interrupted"}
    with pytest.raises(ContractError):
        reconcile_agent_settings_tail(PROFILE, REF, current, other, qualification())


@pytest.mark.parametrize(
    "kind, ready",
    [("declined", True), ("behind-setting", True), ("other-error", False), ("pristine", False)],
)
def test_agent_switch_readiness_predicts_the_same_composed_tail(kind, ready):
    from jt_oz_bridge.adapters.opencode.agent_switch import V2AgentSettings

    current, tail = info(), page()
    if kind == "behind-setting":
        current["time"]["updated"] = 1793761300000
        tail["data"].insert(
            0,
            {
                "id": "msg_model_after_reject",
                "type": "model-switched",
                "model": MODEL,
                "time": {"created": 1793761300000},
            },
        )
    elif kind == "other-error":
        tail["data"][0]["error"] = {"type": "provider", "message": "Step interrupted"}
    elif kind == "pristine":
        current.pop("outcome")
        current["time"].pop("idle")
        tail = page(rows()[:2], more=False)
    assert V2AgentSettings._settings_tail_ready(current, tail) is ready
