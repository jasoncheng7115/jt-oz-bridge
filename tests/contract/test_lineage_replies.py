"""Replies to a waiting original descendant through its own explicit policy guard.

Synthetic GET/POST peers only; no installed descendant evidence, Human or Native approval.
"""

import copy
import json
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
from jt_oz_bridge.adapters.opencode.project_policy import (
    GUARDED_OPERATIONS,
    PERMISSION_SOURCE,
    WAITING_REPLY_OPERATIONS,
    WAITING_STATES,
    NativePolicyEnrollment,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import CHILD, GRANDCHILD, SIBLING, TARGET, setup
from tests.contract.test_public_live_feed import REAL, frame
from tests.integration.test_dispatch import message

REPLY_OPERATIONS = frozenset(
    {
        "session.permission.reply",
        "session.form.get",
        "session.form.reply",
        "session.form.cancel",
    }
)
SOURCES = {
    "permission.reply": "!no 1234",
    "form.reply": "!a 1234 PASS",
    "form.cancel": "!oz confirm opaque",
}


def policies(proofs):
    return {
        node.reference: NativePolicyEnrollment(
            format="native-project-policy-v1",
            reference=node.reference,
            native_project_id=node.native_project_id,
            contract_sha256=proofs.feed.transport.profile.sha256,
            permission_source_sha256=PERMISSION_SOURCE,
            fingerprint_sha256=node.policy_sha256,
            operations=frozenset({"prompt", "permission.reply", "form.reply", "form.cancel"}),
        )
        for node in proofs.observation.nodes
    }


async def waiting(kind, node=GRANDCHILD):
    """One original descendant positively waiting on a real-shape request."""
    anchor, t, p, _bare, tree, state, writes, _metadata = await setup()
    event = next(
        e
        for e in REAL
        if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
    )
    request = copy.deepcopy(event["data"] if kind == "permission" else event["data"]["form"])
    request["sessionID"] = node.upstream_session_id
    state["active"][node.upstream_session_id] = {"type": "running"}
    state["resources"][node][kind] = [request]
    sent = []
    inner = t.client._transport

    def handler(r):
        if (
            kind == "form"
            and r.method == "GET"
            and r.url.path == "/api/session/" + node.upstream_session_id + "/form/" + request["id"]
        ):
            return httpx.Response(
                200, json={"data": {**copy.deepcopy(request), "state": {"status": "pending"}}}
            )
        if r.method in {"POST", "DELETE"} and (
            "/permission/" in r.url.path or "/form/" in r.url.path
        ):
            sent.append((r.method, r.url.path, r.content))
            return httpx.Response(204)
        return inner.handler(r)

    t.client._transport = httpx.MockTransport(handler)
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | REPLY_OPERATIONS
    )
    guard = V2LineagePolicyGuard(p, policies(p))
    client = V2ExecutionClient(t, anchor.projects, proofs=p, scope_guard=guard)
    await p.watch_graph(authorize=AsyncMock(return_value=True))
    return anchor, t, p, guard, client, request, sent, writes, tree


def payload(operation, reference, request_id, generation):
    body = {
        "operation": operation,
        "reference": reference.model_dump(),
        "source": message(text=SOURCES[operation], revision=0).model_dump(mode="json"),
        "interaction_id": "local-interaction",
        "request_id": request_id,
        "generation": generation,
    }
    if operation == "permission.reply":
        body["decision"] = "reject"
    elif operation == "form.reply":
        body["answers"] = {"q0": {"selected": ["PASS"]}}
    return body


@pytest.mark.parametrize("operation", ["permission.reply", "form.reply", "form.cancel"])
@pytest.mark.parametrize("node", [CHILD, GRANDCHILD])
async def test_reply_reaches_exactly_the_waiting_descendant_under_its_own_policy(operation, node):
    kind = "permission" if operation == "permission.reply" else "form"
    anchor, t, p, guard, client, request, sent, writes, tree = await waiting(kind, node)
    try:
        snapshot, proof = await client.qualified_snapshot(node)
        assert snapshot.reference == node and snapshot.state in WAITING_STATES
        assert proof.resource_fence != p.fence(node)  # The waiting witness's state-only fence.
        root, _ = await client.qualified_snapshot(TARGET)
        assert root.state == ExecutionState.IDLE and node in root.descendants
        current = await client.interaction(node, request["id"])
        assert current.reference == node and current.pending
        result = await client.submit(
            node, payload(operation, node, request["id"], current.generation), "reply-action"
        )
        assert result.status == "completed" and len(sent) == 1 and not writes
        method, path, content = sent[0]
        assert method == ("DELETE" if operation == "form.cancel" else "POST")
        assert path.startswith("/api/session/" + node.upstream_session_id + "/")
        assert request["id"] in path
        if operation == "permission.reply":
            assert json.loads(content) == {"decision": "reject"}
        witness = guard.witnesses[node]
        assert witness.fingerprint_sha256 == p.original_node(node).policy_sha256
        assert witness.fingerprint_sha256 != p.original_node(TARGET).policy_sha256
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("kind", ["permission", "form"])
async def test_request_cannot_be_answered_through_its_parent_sibling_or_root(kind):
    operation = "permission.reply" if kind == "permission" else "form.reply"
    anchor, t, p, guard, client, request, sent, writes, tree = await waiting(kind)
    try:
        for other in (TARGET, CHILD, SIBLING):
            with pytest.raises((ContractError, MutationNotSent)):
                current = await client.interaction(other, request["id"])
                await client.submit(
                    other, payload(operation, other, request["id"], current.generation), "wrong"
                )
        # A payload naming the waiting node may not travel through another node.
        with pytest.raises(MutationNotSent):
            await client.submit(
                CHILD, payload(operation, GRANDCHILD, request["id"], "x"), "retargeted"
            )
        assert not sent and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("kind", ["permission", "form"])
async def test_waiting_descendant_state_fence_never_authorizes_a_prompt_or_other_mutation(kind):
    anchor, t, p, guard, client, request, sent, writes, tree = await waiting(kind)
    try:
        _, proof = await client.qualified_snapshot(GRANDCHILD)
        for operation in sorted(GUARDED_OPERATIONS - WAITING_REPLY_OPERATIONS):
            assert not guard.fence_current(GRANDCHILD, operation, proof)
        with pytest.raises(ContractError):
            await guard.authorize(GRANDCHILD, "prompt", proof)
        running = proof.model_copy(update={"state": ExecutionState.RUNNING})
        reply = "permission.reply" if kind == "permission" else "form.reply"
        assert not guard.fence_current(GRANDCHILD, reply, running)
        assert not sent and not writes
    finally:
        await finish(anchor, t)


async def test_descendant_reply_is_refused_after_the_request_is_answered_elsewhere():
    anchor, t, p, guard, client, request, sent, writes, tree = await waiting("permission")
    try:
        _, proof = await client.qualified_snapshot(GRANDCHILD)
        witness = await guard.authorize(GRANDCHILD, "permission.reply", proof)
        replied = copy.deepcopy(next(e for e in REAL if e["type"] == "permission.replied"))
        replied["data"]["sessionID"] = GRANDCHILD.upstream_session_id
        p.feed.index.accept(frame(replied))
        assert not guard.current(GRANDCHILD, "permission.reply", proof, witness)
        with pytest.raises(ContractError):
            await guard.authorize(GRANDCHILD, "permission.reply", proof)
        assert not sent and not writes
    finally:
        await finish(anchor, t)


async def test_unenrolled_session_event_invalidates_an_issued_descendant_witness():
    anchor, t, p, guard, client, request, sent, writes, tree = await waiting("permission")
    try:
        _, proof = await client.qualified_snapshot(GRANDCHILD)
        witness = await guard.authorize(GRANDCHILD, "permission.reply", proof)
        raw = json.loads(
            json.dumps(next(e for e in REAL if e["type"] == "permission.asked")).replace(
                request["sessionID"], "ses_unenrolled_new_child"
            )
        )
        raw["data"]["sessionID"] = "ses_unenrolled_new_child"
        assert p.feed.index.accept(frame(raw)) is None
        assert not guard.current(GRANDCHILD, "permission.reply", proof, witness)
        assert not sent and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("parent", [GRANDCHILD, TARGET])
async def test_new_unregistered_child_fails_closed_until_the_graph_is_extended(parent):
    anchor, t, p, guard, client, request, sent, writes, tree = await waiting("permission")
    try:
        current = await client.interaction(GRANDCHILD, request["id"])
        new = TARGET.model_copy(update={"upstream_session_id": "ses_unregistered_new_child"})
        info = copy.deepcopy(tree["rows"][GRANDCHILD])
        info.update(id=new.upstream_session_id, parentID=parent.upstream_session_id)
        info["time"]["created"] = 40
        tree["rows"][new] = info
        tree["edges"].setdefault(parent, []).append(new)
        # The Root's own complete tree no longer matches its sealed enrollment.
        with pytest.raises(ContractError):
            await client.qualified_snapshot(TARGET)
        reply = payload("permission.reply", GRANDCHILD, request["id"], current.generation)
        if parent == GRANDCHILD:
            # The waiting node's own subtree changed: nothing is sent to it.
            with pytest.raises(MutationNotSent):
                await client.submit(GRANDCHILD, reply, "after-new-child")
            assert not sent
        else:
            # A sibling subagent elsewhere does not change the waiting node's
            # own subtree, ancestors or policy; the Bridge's Root lineage check
            # (InteractionService.lineage) still refuses until re-enrollment.
            result = await client.submit(GRANDCHILD, reply, "new-sibling")
            assert result.status == "completed" and len(sent) == 1
        assert not writes
    finally:
        await finish(anchor, t)
