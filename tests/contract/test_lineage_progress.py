"""Actual GET adapters with changing synthetic progress; not Native qualification."""

import copy
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs
from jt_oz_bridge.domain.control import ExecutionState
from tests.contract.test_leaf_resources import finish
from tests.contract.test_leaf_resources import setup as leaf_setup
from tests.contract.test_lineage_resources import TARGET, setup
from tests.contract.test_public_live_feed import REF


def changing_info(transport, reference, edit):
    old, count = transport.client._transport, [0]

    def handle(request):
        response = old.handler(request)
        if request.url.path == "/api/session/" + reference.upstream_session_id:
            count[0] += 1
            body = copy.deepcopy(response.json())
            edit(body["data"], count[0])
            return httpx.Response(200, json=body)
        return response

    transport.client._transport = httpx.MockTransport(handle)
    return count


def assistant():
    return {
        "id": "msg_streaming_original",
        "type": "assistant",
        "time": {"created": 101, "streamed": 102},
        "agent": "build",
        "model": {"id": "synthetic-model", "providerID": "synthetic"},
        "content": [
            {"type": "text", "text": "first"},
            {"type": "reasoning", "text": "not retained", "time": {"created": 101}},
        ],
    }


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("field", ["cost", "tokens", "title", "updated", "viewed"])
async def test_original_info_identity_survives_progress_without_renewing_resource_deadline(
    active, field
):
    anchor, t, proofs, client, tree, state, writes, _ = await setup()

    def edit(info, count):
        if field in {"updated", "viewed"}:
            info["time"][field] = 100 + count
        elif field == "tokens":
            info["tokens"]["output"] = count
        else:
            info[field] = count / 100 if field == "cost" else "Progress " + str(count)

    calls = changing_info(t, TARGET, edit)
    try:
        if active:
            state["active"][TARGET.upstream_session_id] = {"type": "running"}
        await proofs.watch_graph(authorize=AsyncMock(return_value=True))
        snapshot, proof = await client.qualified_snapshot(TARGET)
        assert snapshot.reconciled and snapshot.state == (
            ExecutionState.RUNNING if active else ExecutionState.IDLE
        )
        client.current(TARGET, proof)
        assert proof.expires_at - proof.issued_at == 5 and calls[0] > 4
        scope = await proofs.read_scope(TARGET)
        assert scope.expires_at - scope.issued_at == 5
        assert proofs.read_epoch(TARGET, t.profile.sha256) == scope.connection_epoch
        if active:
            with pytest.raises(ContractError):
                proofs.dispatch_owner_epoch(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_active_text_deltas_do_not_change_exact_durable_message_or_renew_proof():
    from tests.contract.test_public_live_feed import frame, text_delta

    anchor, t, proofs, client, tree, state, writes, _ = await setup()
    count = 0
    durable = assistant()

    def hook(request, current):
        nonlocal count
        if request.url.path == "/api/session/" + TARGET.upstream_session_id + "/message":
            count += 1
            raw = text_delta("evt_synthetic_stream_" + str(count))
            raw["data"]["sessionID"] = TARGET.upstream_session_id
            anchor.feed.index.accept(frame(raw))
            return httpx.Response(200, json={"data": [copy.deepcopy(durable)], "cursor": {}})
        return None

    try:
        state["hook"] = hook
        state["active"][TARGET.upstream_session_id] = {"type": "running"}
        await proofs.watch_graph(authorize=AsyncMock(return_value=True))
        snapshot, proof = await client.qualified_snapshot(TARGET)
        assert snapshot.state == ExecutionState.RUNNING and count >= 4
        client.current(TARGET, proof)
        assert proof.expires_at - proof.issued_at == 5
        assert durable == assistant() and not writes
        witness = proofs.witnesses[TARGET]
        assert not hasattr(witness, "text") and not hasattr(witness, "reasoning")
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "field",
    [
        "created",
        "parent",
        "id",
        "project",
        "directory",
        "agent",
        "model",
        "permissions",
        "metadata",
        "idle",
        "archived",
        "outcome",
    ],
)
async def test_identity_policy_and_settled_info_are_never_masked_as_presentation(field):
    anchor, t, proofs, client, tree, state, writes, _ = await setup()

    def edit(info, count):
        if field in {"created", "idle", "archived"}:
            info["time"][field] = 100 + count
        elif field == "parent":
            info["parentID"] = "ses_foreign_parent"
        elif field == "directory":
            info["location"]["directory"] = "/foreign/" + str(count)
        elif field == "permissions":
            info["permissions"] = [
                {"action": "*", "resource": "*", "effect": "allow" if count % 2 else "deny"}
            ]
        elif field == "model":
            info["model"] = {"id": "model-" + str(count), "providerID": "synthetic"}
        elif field == "metadata":
            info["metadata"] = {"owner-change": count}
        elif field == "outcome":
            info["outcome"] = "failed" if count % 2 else "succeeded"
        else:
            info[{"id": "id", "project": "projectID", "agent": "agent"}[field]] = "changed-" + str(
                count
            )

    changing_info(t, TARGET, edit)
    try:
        state["active"][TARGET.upstream_session_id] = {"type": "running"}
        with pytest.raises(ContractError):
            await proofs.watch_graph(authorize=AsyncMock(return_value=True))
        assert TARGET not in proofs._watched and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "created",
        "model",
        "agent",
        "metadata",
        "tool_id",
        "tool_input",
        "tool_status",
        "tool_metadata",
        "completed",
        "finish",
        "error",
        "retry",
        "rawFinish",
        "providerState",
        "snapshot",
        "settled_reasoning",
        "prior_text_with_running_tool",
        "text",
        "reasoning",
        "cost",
        "tokens",
        "streamed",
    ],
)
async def test_message_identity_tools_and_settled_content_changes_still_break_boundary(field):
    anchor, t, proofs, client, tree, state, writes, _ = await setup()
    counter = 0

    def hook(request, current):
        nonlocal counter
        if request.url.path != "/api/session/" + TARGET.upstream_session_id + "/message":
            return None
        counter += 1
        value = assistant()
        if field.startswith("tool_"):
            value["content"] = [
                {
                    "type": "tool",
                    "id": "call_original",
                    "name": "synthetic-tool",
                    "state": {
                        "status": "running",
                        "input": {"command": "original"},
                        "metadata": {},
                    },
                    "time": {"created": 101, "ran": 102},
                }
            ]
            tool = value["content"][0]
            if field == "tool_id":
                tool["id"] += str(counter)
            elif field == "tool_input":
                tool["state"]["input"]["command"] = "changed " + str(counter)
            elif field == "tool_metadata":
                tool["state"]["metadata"] = {"owner": counter}
            else:
                tool["state"] = (
                    {"status": "streaming", "input": "new " + str(counter)}
                    if counter % 2
                    else tool["state"]
                )
        elif field == "created":
            value["time"]["created"] += counter
        elif field == "model":
            value["model"]["id"] += str(counter)
        elif field == "metadata":
            value["metadata"] = {"owner": counter}
        elif field == "prior_text_with_running_tool":
            value["content"] = [
                {"type": "text", "text": "Settled earlier text " + str(counter)},
                {
                    "type": "tool",
                    "id": "call_original",
                    "name": "synthetic-tool",
                    "state": {
                        "status": "running",
                        "input": {"command": "original"},
                        "metadata": {},
                    },
                    "time": {"created": 102, "ran": 103},
                },
            ]
        elif field in {"text", "reasoning"}:
            value["content"][0 if field == "text" else 1]["text"] += str(counter)
        elif field == "cost":
            value["cost"] = counter / 100
        elif field == "tokens":
            value["tokens"] = {
                "input": 0,
                "output": counter,
                "reasoning": 0,
                "cache": {"read": 0, "write": 0},
            }
        elif field == "streamed":
            value["time"]["streamed"] += counter
        elif field == "settled_reasoning":
            value["content"][1]["time"]["completed"] = 102
            value["content"][1]["text"] += str(counter)
        elif field == "providerState":
            value["providerState"] = {"opaque-owner": counter}
        elif field == "snapshot":
            value["snapshot"] = {"start": str(counter)}
        elif field in {"completed", "finish", "error", "retry", "rawFinish"}:
            value["content"][0]["text"] += str(counter)
            if field == "completed":
                value["time"]["completed"] = 103
            elif field == "finish":
                value["finish"] = "stop"
            elif field == "rawFinish":
                value["rawFinish"] = "stop"
            elif field == "error":
                value["error"] = {"type": "synthetic-error", "message": "not Native"}
            else:
                value["retry"] = {
                    "attempt": 1,
                    "at": 104,
                    "error": {"type": "synthetic-error", "message": "not Native"},
                }
        else:
            value[field] += str(counter)
        return httpx.Response(200, json={"data": [value], "cursor": {}})

    try:
        state["active"][TARGET.upstream_session_id] = {"type": "running"}
        state["hook"] = hook
        with pytest.raises(SnapshotBoundaryChanged):
            await proofs.watch_graph(authorize=AsyncMock(return_value=True))
        assert not writes
    finally:
        await finish(anchor, t)


async def test_legacy_leaf_keeps_exact_info_and_does_not_borrow_progress_semantics():
    anchor, t, data, calls = await leaf_setup()
    try:
        await anchor.watch(REF)
        changing_info(t, REF, lambda info, count: info.update(cost=count / 100))
        with pytest.raises(SnapshotBoundaryChanged):
            await anchor.capture(REF)
        assert all(operation != "session.interrupt" for operation, _ in calls)
    finally:
        await finish(anchor, t)


async def test_old_lineage_semantic_pin_cannot_enable_new_projection():
    anchor, t, proofs, client, tree, state, writes, metadata = await setup()
    try:
        with pytest.raises(ContractError, match="semantics"):
            V2LineageResourceProofs(
                anchor.feed,
                anchor.projects,
                proofs.observation,
                replace(
                    proofs.lineage_attestation, semantics="original-session-lineage-resources-v1"
                ),
                current=metadata.current,
            )
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("state_kind", ["idle", "queued"])
async def test_nonactive_message_text_is_exact_even_with_unfinished_assistant(state_kind):
    anchor, t, proofs, client, tree, state, writes, _ = await setup()
    counter = 0

    def hook(request, current):
        nonlocal counter
        if request.url.path == "/api/session/" + TARGET.upstream_session_id + "/message":
            counter += 1
            value = assistant()
            value["content"][0]["text"] += str(counter)
            return httpx.Response(200, json={"data": [value], "cursor": {}})
        return None

    try:
        if state_kind == "queued":
            state["resources"][TARGET]["inbox"] = [
                {
                    "id": "msg_queued",
                    "sessionID": TARGET.upstream_session_id,
                    "type": "user",
                    "payload": {"text": "queued"},
                    "delivery": "queue",
                    "time": {"created": 101},
                }
            ]
        state["hook"] = hook
        with pytest.raises(ContractError):
            await proofs.watch_graph(authorize=AsyncMock(return_value=True))
        assert not writes
    finally:
        await finish(anchor, t)


async def test_a_refused_proof_names_the_failing_check_at_most_once_per_window(caplog):
    # A refusal such as "owner or snapshot evidence changed" must say which
    # condition held, without repeating itself on every retry.
    anchor, t, proofs, client, tree, state, writes, _ = await setup()
    try:
        await proofs.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await client.qualified_snapshot(TARGET)
        stale = proof.model_copy(update={"expires_at": proof.issued_at + 0.001})
        for _ in range(2):
            with pytest.raises(ContractError, match="owner_or_snapshot_evidence_changed"):
                client.current(TARGET, stale)
        lines = [x for x in caplog.messages if "native_execution_proof_detail" in x]
        assert len(lines) == 1 and lines[0].endswith("check=expired")
    finally:
        await finish(anchor, t)
