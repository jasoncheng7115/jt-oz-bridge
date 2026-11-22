"""Synthetic policy-drift failures; no installed tool containment certificate."""

import copy
import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.project_policy import (
    GUARDED_OPERATIONS,
    PERMISSION_SOURCE,
    POLICY_READS,
    WAITING_REPLY_OPERATIONS,
    WAITING_STATES,
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
    _policy_facts,
    policy_fingerprint,
    root_policy_enrollment,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_leaf_resources import setup as leaf_setup
from tests.contract.test_public_live_feed import REAL, frame
from tests.integration.test_dispatch import message


def fingerprint(data):
    return policy_fingerprint(
        REF,
        "global",
        data["session.get"]["data"],
        data["agent.get"],
        data["plugin.list"],
        data["permission.saved.list"],
        data["mcp.list"],
    )


async def setup(hook=None, *, mcp_status=None):
    p, t, d, calls = await leaf_setup()
    d["session.get"]["data"].update(
        agent="build", permissions=[{"action": "*", "resource": "*", "effect": "deny"}]
    )
    location = {"directory": REF.canonical_directory}
    d.update(
        {
            "agent.get": {
                "location": location,
                "data": {
                    "id": "build",
                    "name": "Build",
                    "request": {"settings": {}, "headers": {}, "body": {}},
                    "mode": "primary",
                    "hidden": False,
                    "permissions": [{"action": "*", "resource": "*", "effect": "allow"}],
                },
            },
            "plugin.list": {
                "location": location,
                "data": [
                    {
                        "id": "opencode.tool.read",
                        "source": {"type": "builtin"},
                        "features": {"server": True},
                        "state": {"status": "active"},
                    }
                ],
            },
            "permission.saved.list": {"data": []},
            "mcp.list": {
                "location": location,
                "data": [
                    {
                        "name": "fixture-mcp",
                        **(
                            {"integrationID": "integration_fixture"}
                            if mcp_status is not None
                            else {}
                        ),
                        "status": copy.deepcopy(mcp_status)
                        if mcp_status is not None
                        else {"status": "disabled"},
                    }
                ],
            },
        }
    )
    original = t.client._transport
    routes = {
        "/api/agent/build": "agent.get",
        "/api/plugin": "plugin.list",
        "/api/permission/saved": "permission.saved.list",
        "/api/mcp": "mcp.list",
    }
    policy_calls = []
    writes = []

    def handler(request):
        if request.method != "GET":
            writes.append(request)
            if request.url.path.endswith("/interrupt"):
                return httpx.Response(200, json={"interrupted": False})
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "msg_fixture",
                        "sessionID": REF.upstream_session_id,
                        "time": {"created": 1},
                        "type": "user",
                        "payload": {"text": body["text"]},
                        "delivery": "queue",
                    }
                },
            )
        op = routes.get(request.url.path)
        if op:
            policy_calls.append(op)
            if hook:
                hook(op, len(policy_calls), d, p)
            if op == "permission.saved.list":
                assert request.url.params["projectID"] == "global"
            else:
                assert request.url.params["location[directory]"] == REF.canonical_directory
            return httpx.Response(200, json=copy.deepcopy(d[op]))
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    t.attestation = replace(
        t.attestation,
        verified_operations=t.attestation.verified_operations
        | POLICY_READS
        | {"session.prompt", "session.interrupt"},
    )
    await p.watch(REF)
    e = NativePolicyEnrollment(
        format="native-project-policy-v1",
        reference=REF,
        native_project_id="global",
        contract_sha256=t.profile.sha256,
        permission_source_sha256=PERMISSION_SOURCE,
        fingerprint_sha256=fingerprint(d),
        operations=GUARDED_OPERATIONS,
    )
    guard = V2ProjectPolicyGuard(p, {REF: e})
    client = V2ExecutionClient(t, p.projects, proofs=p, scope_guard=guard)
    return p, t, d, guard, client, policy_calls, writes


async def test_readonly_leaf_owner_proof_alone_never_enables_tool_granting_operations():
    p, t, d, g, c, calls, writes = await setup()
    try:
        bare = V2ExecutionClient(t, p.projects, proofs=p)
        assert not bare.capabilities(REF)["prompt"].supported
        assert bare.capabilities(REF)["interrupt"].supported
        assert c.capabilities(REF)["prompt"].supported
    finally:
        await finish(p, t)


async def test_exact_root_policy_double_read_witness_ignores_agent_system_and_secret_request():
    p, t, d, g, c, calls, writes = await setup()
    try:
        _, proof = await c.qualified_snapshot(REF)
        witness = await g.authorize(REF, "prompt", proof)
        assert g.current(REF, "prompt", proof, witness) is True
        assert len(calls) == 8 and not writes
        assert not g.current(REF, "form.reply", proof, witness)
        assert not g.current(REF, "prompt", proof, witness.model_copy())
        before = fingerprint(d)
        d["agent.get"]["data"]["system"] = "Do not retain this prompt"
        d["agent.get"]["data"]["request"]["headers"]["Authorization"] = "TEST_PRIVATE_HEADER"
        assert fingerprint(d) == before
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change",
    [
        "session_rules",
        "agent_rules",
        "agent_id",
        "saved_grant",
        "mcp",
        "plugin",
        "location",
        "foreign_saved",
        "duplicate_plugin",
        "missing_agent",
    ],
)
async def test_changed_or_foreign_policy_is_not_self_enrolled(change):
    p, t, d, g, c, calls, writes = await setup()
    try:
        _, proof = await c.qualified_snapshot(REF)
        if change == "session_rules":
            d["session.get"]["data"]["permissions"].append(
                {"action": "*", "resource": "*", "effect": "allow"}
            )
        elif change == "agent_rules":
            d["agent.get"]["data"]["permissions"] = []
        elif change == "agent_id":
            d["agent.get"]["data"]["id"] = "other"
        elif change in {"saved_grant", "foreign_saved"}:
            d["permission.saved.list"]["data"] = [
                {
                    "id": "perm_fixture",
                    "projectID": "foreign" if change == "foreign_saved" else "global",
                    "action": "read",
                    "resource": "*",
                    "time": {"created": 1, "updated": 1},
                }
            ]
        elif change == "mcp":
            d["mcp.list"]["data"] = []
        elif change == "plugin":
            d["plugin.list"]["data"][0]["source"] = {
                "type": "local",
                "path": "/unapproved/plugin.ts",
            }
        elif change == "location":
            d["mcp.list"]["location"] = {"directory": "/foreign"}
        elif change == "duplicate_plugin":
            d["plugin.list"]["data"] *= 2
        elif change == "missing_agent":
            d["session.get"]["data"].pop("agent")
        with pytest.raises((ContractError, ValueError)):
            await g.authorize(REF, "prompt", proof)
        assert REF not in g.witnesses and not writes
    finally:
        await finish(p, t)


async def test_policy_change_between_two_reads_is_not_accepted_even_if_second_is_enrolled():
    def hook(op, n, d, p):
        if op == "agent.get" and n == 1:
            d[op]["data"]["permissions"] = []
        elif op == "agent.get" and n == 5:
            d[op]["data"]["permissions"] = [{"action": "*", "resource": "*", "effect": "allow"}]

    p, t, d, g, c, calls, writes = await setup(hook)
    try:
        _, proof = await c.qualified_snapshot(REF)
        with pytest.raises(ContractError):
            await g.authorize(REF, "prompt", proof)
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change", ["expired", "future", "feed", "owner", "attestation", "revoked_operation"]
)
async def test_witness_stops_being_current_after_its_boundary_changes(change, monkeypatch):
    p, t, d, g, c, calls, writes = await setup()
    try:
        _, proof = await c.qualified_snapshot(REF)
        w = await g.authorize(REF, "prompt", proof)
        if change == "expired":
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.project_policy.time.time",
                lambda: w.expires_at + 0.01,
            )
        elif change == "future":
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.project_policy.time.time", lambda: w.checked_at - 1
            )
        elif change == "feed":
            p.feed.index.accept(frame(REAL[0]))
        elif change == "owner":
            p.feed.index.invalidate("operator_changed_owner")
        elif change == "attestation":
            t.attestation = replace(
                t.attestation,
                verified_operations=t.attestation.verified_operations - {"plugin.list"},
            )
        else:
            g.enrollments = MappingProxyType(
                {
                    REF: g.enrollments[REF].model_copy(
                        update={"operations": frozenset({"form.reply"})}
                    )
                }
            )
        assert not g.current(REF, "prompt", proof, w) and not writes
    finally:
        await finish(p, t)


def prompt_payload():
    return {
        "operation": "prompt",
        "reference": REF.model_dump(),
        "text": "exact fixture prompt",
        "source": message(text="!oz send -- exact fixture prompt", revision=0).model_dump(
            mode="json"
        ),
    }


async def test_actual_client_pre_send_guard_prevents_post_after_identity_await_changes_feed():
    p, t, d, g, c, calls, writes = await setup()
    original = t.verify_identity

    async def changed():
        if g.witnesses:
            p.feed.index.accept(frame(REAL[0]))
        return await original()

    t.verify_identity = changed
    try:
        with pytest.raises(MutationNotSent):
            await c.submit(REF, prompt_payload(), "action_fixture")
        assert not writes
    finally:
        await finish(p, t)


async def test_unchanged_guarded_client_sends_exactly_one_prompt():
    p, t, d, g, c, calls, writes = await setup()
    try:
        result = await c.submit(REF, prompt_payload(), "action_fixture")
        assert result.status == "admitted" and len(writes) == 1
        assert json.loads(writes[0].content)["text"] == "exact fixture prompt"
    finally:
        await finish(p, t)


@pytest.mark.parametrize("initial", ["connected", "failed"])
async def test_transport_health_changes_between_policy_reads_and_send_preserve_authority(initial):
    reads = []

    def hook(op, n, d, p):
        if op == "mcp.list":
            status = (
                {"status": "connected"}
                if len(reads) % 2
                else {"status": "failed", "error": f"fixture transport error {len(reads)}"}
            )
            d[op]["data"][0]["status"] = status
            reads.append(copy.deepcopy(status))

    status = {"status": initial}
    if initial == "failed":
        status["error"] = "initial fixture transport error"
    p, t, d, g, c, calls, writes = await setup(hook, mcp_status=status)
    try:
        enrolled = g.enrollments[REF].fingerprint_sha256
        result = await c.submit(REF, prompt_payload(), "action_health_fixture")
        assert result.status == "admitted" and len(writes) == 1
        assert len(reads) == 2 and reads[0] != reads[1]
        assert fingerprint(d) == enrolled
        assert d["mcp.list"]["data"][0]["status"] == reads[-1]
        assert d["session.get"]["data"]["permissions"] == [
            {"action": "*", "resource": "*", "effect": "deny"}
        ]
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change",
    [
        "disabled",
        "needs_auth",
        "needs_client_registration",
        "unknown_status",
        "unknown_status_field",
        "invalid_error",
        "connected_error",
        "projection_collision",
        "name",
        "integration",
        "extra_configuration",
    ],
)
async def test_mcp_identity_auth_and_unknown_changes_still_reject_before_post(change):
    p, t, d, g, c, calls, writes = await setup(mcp_status={"status": "connected"})
    try:
        record = d["mcp.list"]["data"][0]
        if change in {"disabled", "needs_auth", "needs_client_registration", "unknown_status"}:
            record["status"] = {"status": change}
        elif change == "unknown_status_field":
            record["status"] = {"status": "failed", "error": "fixture", "scope": "changed"}
        elif change == "invalid_error":
            record["status"] = {"status": "failed", "error": {"scope": "changed"}}
        elif change == "connected_error":
            record["status"] = {"status": "connected", "error": "unexpected"}
        elif change == "projection_collision":
            record["status"] = {"projection": "transport-v1"}
        elif change == "name":
            record["name"] = "other-mcp"
        elif change == "integration":
            record["integrationID"] = "other-integration"
        else:
            record["configuration"] = {"scope": "changed"}
        with pytest.raises((ContractError, MutationNotSent)):
            await c.submit(REF, prompt_payload(), "action_changed_health_fixture")
        assert not writes and REF not in g.witnesses
    finally:
        await finish(p, t)


async def test_v1_policy_pin_requires_explicit_requalification_even_without_mcp_health_change():
    p, t, d, g, c, calls, writes = await setup()
    try:
        facts = _policy_facts(
            REF,
            "global",
            d["session.get"]["data"],
            d["agent.get"],
            d["plugin.list"],
            d["permission.saved.list"],
            d["mcp.list"],
        )
        assert facts["format"] == "native-project-policy-fingerprint-v2"
        legacy = copy.deepcopy(facts)
        legacy["format"] = "native-project-policy-fingerprint-v1"
        legacy["mcp"] = copy.deepcopy(d["mcp.list"]["data"])
        old_pin = digest(legacy)
        assert old_pin != fingerprint(d)
        g.enrollments = MappingProxyType(
            {REF: g.enrollments[REF].model_copy(update={"fingerprint_sha256": old_pin})}
        )
        with pytest.raises((ContractError, MutationNotSent)):
            await c.submit(REF, prompt_payload(), "action_v1_fixture")
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["needs_auth", "integration", "extra_field"])
async def test_non_health_drift_between_policy_bundles_rejects_before_post(change):
    reads = 0

    def hook(op, n, d, p):
        nonlocal reads
        if op == "mcp.list":
            reads += 1
            if reads == 2:
                record = d[op]["data"][0]
                if change == "needs_auth":
                    record["status"] = {"status": "needs_auth"}
                elif change == "integration":
                    record["integrationID"] = "changed-between-reads"
                else:
                    record["status"]["unknown"] = "unreviewed"

    p, t, d, g, c, calls, writes = await setup(hook, mcp_status={"status": "connected"})
    try:
        with pytest.raises((ContractError, MutationNotSent)):
            await c.submit(REF, prompt_payload(), "action_between_bundles_fixture")
        assert reads == 2 and not writes and REF not in g.witnesses
    finally:
        await finish(p, t)


async def test_policy_drift_does_not_disable_original_scoped_interrupt():
    p, t, d, g, c, calls, writes = await setup()
    try:
        g.enrollments = MappingProxyType({})
        assert not c.capabilities(REF)["prompt"].supported
        source = message(text="!oz stop", revision=0)
        result = await c.submit(
            REF,
            {
                "operation": "interrupt",
                "reference": REF.model_dump(),
                "source": source.model_dump(mode="json"),
            },
            "stop_fixture",
        )
        assert (
            result.status == "completed"
            and len(writes) == 1
            and writes[0].url.path.endswith("/interrupt")
        )
    finally:
        await finish(p, t)


def test_non_root_enrollment_path_is_rejected_without_reading_contents(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text("{}")
    with pytest.raises(ContractError):
        root_policy_enrollment(p)
    with pytest.raises(ContractError):
        root_policy_enrollment(Path("relative.json"))


@pytest.mark.parametrize("which", ["expired", "future", "schema"])
async def test_unissued_or_expired_execution_proof_cannot_authorize_policy(which):
    p, t, d, g, c, calls, writes = await setup()
    try:
        _, proof = await c.qualified_snapshot(REF)
        if which == "expired":
            proof = proof.model_copy(update={"expires_at": time.time() - 1})
        elif which == "future":
            proof = proof.model_copy(update={"issued_at": time.time() + 1})
        else:
            proof = proof.model_copy(update={"contract_sha256": "f" * 64})
        with pytest.raises(ContractError):
            await g.authorize(REF, "prompt", proof)
        assert not calls and not writes
    finally:
        await finish(p, t)


async def test_last_matching_permission_rule_order_is_part_of_operator_enrollment():
    p, t, d, g, c, calls, writes = await setup()
    try:
        r = d["session.get"]["data"]["permissions"]
        r.append({"action": "read", "resource": "*", "effect": "ask"})
        a = fingerprint(d)
        r.reverse()
        assert fingerprint(d) != a
    finally:
        await finish(p, t)


async def test_failed_policy_recheck_invalidates_previous_token_instead_of_reusing_it():
    p, t, d, g, c, calls, writes = await setup()
    try:
        _, proof = await c.qualified_snapshot(REF)
        w = await g.authorize(REF, "prompt", proof)
        d["permission.saved.list"]["data"] = [
            {
                "id": "grant_fixture",
                "projectID": "global",
                "action": "read",
                "resource": "*",
                "time": {"created": 1, "updated": 1},
            }
        ]
        with pytest.raises(ContractError):
            await g.authorize(REF, "prompt", proof)
        assert not g.current(REF, "prompt", proof, w) and not writes
    finally:
        await finish(p, t)


REPLY_READS = frozenset(
    {
        "session.permission.reply",
        "session.form.get",
        "session.form.reply",
        "session.form.cancel",
    }
)
REPLY_SOURCES = {
    "permission.reply": "!no 1234",
    "form.reply": "!oz answer opaque submit",
    "form.cancel": "!oz confirm opaque",
}


async def waiting(kind):
    """A guarded Root positively waiting on one real-shape permission or question."""
    p, t, d, g, c, calls, writes = await setup()
    event = next(
        e
        for e in REAL
        if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
    )
    request = copy.deepcopy(event["data"] if kind == "permission" else event["data"]["form"])
    d["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
    d["session." + kind + ".list"]["data"] = [request]
    sent = []
    inner = t.client._transport

    def handler(r):
        if kind == "form" and r.method == "GET" and r.url.path.endswith("/form/" + request["id"]):
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
        t.attestation, verified_operations=t.attestation.verified_operations | REPLY_READS
    )
    await p.watch(REF)
    return p, t, d, g, c, request, sent, writes


def reply_payload(operation, request_id, generation):
    body = {
        "operation": operation,
        "reference": REF.model_dump(),
        "source": message(text=REPLY_SOURCES[operation], revision=0).model_dump(mode="json"),
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
async def test_guarded_reply_on_a_waiting_root_is_authorized_and_sent_exactly_once(operation):
    kind = "permission" if operation == "permission.reply" else "form"
    p, t, d, g, c, request, sent, writes = await waiting(kind)
    try:
        snapshot, proof = await c.qualified_snapshot(REF)
        assert snapshot.state in WAITING_STATES and p.witnesses[REF].state_only_fence
        assert proof.resource_fence != p.fence(REF)  # The active proof's state-only fence.
        current = await c.interaction(REF, request["id"])
        result = await c.submit(
            REF, reply_payload(operation, request["id"], current.generation), "reply-action"
        )
        assert result.status == "completed" and len(sent) == 1 and not writes
        method, path, content = sent[0]
        assert method == ("DELETE" if operation == "form.cancel" else "POST")
        assert request["id"] in path
        if operation == "permission.reply":
            assert json.loads(content) == {"decision": "reject"}
    finally:
        await finish(p, t)


@pytest.mark.parametrize("kind", ["permission", "form"])
async def test_state_only_fence_never_authorizes_a_prompt_or_any_non_reply_mutation(kind):
    p, t, d, g, c, request, sent, writes = await waiting(kind)
    try:
        _, proof = await c.qualified_snapshot(REF)
        for operation in sorted(GUARDED_OPERATIONS - WAITING_REPLY_OPERATIONS):
            assert not g.fence_current(REF, operation, proof)
            with pytest.raises(ContractError):
                await g.authorize(REF, operation, proof)
        reply = "permission.reply" if kind == "permission" else "form.reply"
        witness = await g.authorize(REF, reply, proof)
        assert g.current(REF, reply, proof, witness)
        for operation in GUARDED_OPERATIONS - WAITING_REPLY_OPERATIONS:
            assert not g.current(REF, operation, proof, witness)
        # Even a reply-shaped operation needs a proof that is positively waiting.
        running = proof.model_copy(update={"state": ExecutionState.RUNNING})
        assert not g.fence_current(REF, reply, running)
        with pytest.raises(MutationNotSent):
            await c.submit(REF, prompt_payload(), "prompt-while-waiting")
        assert not sent and not writes
    finally:
        await finish(p, t)


async def test_stale_state_only_fence_is_refused_after_the_state_changes():
    p, t, d, g, c, request, sent, writes = await waiting("permission")
    try:
        _, proof = await c.qualified_snapshot(REF)
        witness = await g.authorize(REF, "permission.reply", proof)
        replied = next(e for e in REAL if e["type"] == "permission.replied")
        p.feed.index.accept(frame(replied))
        assert not p.valid_fence(REF, proof.resource_fence)
        assert not g.fence_current(REF, "permission.reply", proof)
        assert not g.current(REF, "permission.reply", proof, witness)
        with pytest.raises(ContractError):
            await g.authorize(REF, "permission.reply", proof)
        assert not sent and not writes
    finally:
        await finish(p, t)


async def test_idle_root_prompt_still_requires_the_strict_fence():
    p, t, d, g, c, calls, writes = await setup()
    try:
        _, proof = await c.qualified_snapshot(REF)
        assert proof.state == ExecutionState.IDLE and proof.resource_fence == p.fence(REF)
        assert g.fence_current(REF, "prompt", proof)
        state_only = proof.model_copy(update={"resource_fence": p.fence(REF, state_only=True)})
        for operation in GUARDED_OPERATIONS:
            assert not g.fence_current(REF, operation, state_only)
        with pytest.raises(ContractError):
            await g.authorize(REF, "prompt", state_only)
    finally:
        await finish(p, t)


def observer_record(path):
    return {
        "id": "jt-audit",
        "source": {"type": "local", "path": str(path)},
        "features": {"server": True},
        "state": {"status": "active"},
    }


@pytest.fixture
def observer_plugin(tmp_path, monkeypatch):
    from jt_oz_bridge.adapters.opencode import project_policy

    monkeypatch.setattr(project_policy, "_OBSERVERS", {})
    plugin = tmp_path / "jt-audit.js"
    plugin.write_bytes(b"export default { id: 'jt-audit' }\n")
    sha = hashlib.sha256(plugin.read_bytes()).hexdigest()
    project_policy.approve_observer_plugins(REF.backend_id, (("jt-audit", str(plugin), sha),))
    return plugin


async def test_an_approved_observer_plugin_keeps_every_enrolled_fingerprint(observer_plugin):
    # A passive audit plugin added to OpenCode must not stop every Root at once.
    p, t, d, g, c, calls, writes = await setup()
    try:
        enrolled = fingerprint(d)
        d["plugin.list"]["data"].append(observer_record(observer_plugin))
        assert fingerprint(d) == enrolled
        result = await c.submit(REF, prompt_payload(), "action_observer_fixture")
        assert result.status == "admitted" and len(writes) == 1
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "change", ["bytes", "symlink", "features", "state", "other_backend", "unapproved"]
)
async def test_any_other_or_changed_plugin_is_still_policy_drift(
    observer_plugin, monkeypatch, change
):
    from jt_oz_bridge.adapters.opencode import project_policy

    p, t, d, g, c, calls, writes = await setup()
    try:
        enrolled = fingerprint(d)
        record = observer_record(observer_plugin)
        if change == "bytes":
            observer_plugin.write_bytes(b"export default { id: 'jt-audit', block: true }\n")
        elif change == "symlink":
            link = observer_plugin.with_name("link.js")
            link.symlink_to(observer_plugin)
            ((_, _, sha),) = project_policy._OBSERVERS[REF.backend_id]
            project_policy.approve_observer_plugins(REF.backend_id, (("jt-audit", str(link), sha),))
            record = observer_record(link)
        elif change == "features":
            record["features"] = {"server": True, "tui": True}
        elif change == "state":
            record["state"] = {"status": "failed"}
        elif change == "other_backend":
            monkeypatch.setattr(
                project_policy, "_OBSERVERS", {"other": project_policy._OBSERVERS[REF.backend_id]}
            )
        else:
            record["id"] = "jt-other"
        d["plugin.list"]["data"].append(record)
        if change == "state":
            with pytest.raises(ContractError):  # An inactive plugin is refused outright.
                fingerprint(d)
        else:
            assert fingerprint(d) != enrolled
        with pytest.raises((ContractError, MutationNotSent)):
            await c.submit(REF, prompt_payload(), "action_observer_drift_fixture")
        assert not writes
    finally:
        await finish(p, t)
