"""Installed2.0.32 OpenAPI with synthetic HTTP/owner/policy, never live certification."""

import asyncio
import copy
import json
import time
from dataclasses import replace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.checks import (
    CHECK_READS,
    CHECK_SEMANTICS,
    CheckExecutionAttestation,
    V2CheckRunner,
    require_shell_allow,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.transport import TransportError
from jt_oz_bridge.domain.checks import ApprovedCheck, CheckCatalog, CheckSelection, check_message_id
from jt_oz_bridge.domain.execution import HumanMessage, MutationNotSent
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_session_lifecycle import setup as original_setup
from tests.contract.test_v2_model_catalog import REF

CHECK = ApprovedCheck(id="unit", title="Operator-approved suite", command="python -m pytest tests")


class Policy:
    def __init__(self):
        self.allowed = True
        self.hook = None

    def enrolled(self, ref, operation):
        return operation == "check.run"

    async def authorize_check(self, ref, proof, command):
        require_shell_allow(
            {
                "agent": {
                    "permissions": [
                        {
                            "action": "*",
                            "resource": "*",
                            "effect": "allow" if self.allowed else "deny",
                        }
                    ]
                },
                "session_permissions": [],
            },
            command,
        )
        if self.hook:
            await self.hook()
        return self

    def current(self, ref, operation, proof, witness):
        return witness is self and self.allowed


def setup(mode="success", hook=None):
    client, t, data, _, _ = original_setup()
    guard = Policy()
    client.scope_guard = guard
    catalog = CheckCatalog(reference=REF, contract_sha256=t.profile.sha256, checks=(CHECK,))
    qualification = CheckExecutionAttestation(catalog, CHECK_SEMANTICS, "a" * 64)
    client.checks = V2CheckRunner(client, {REF: qualification})
    t.attestation = replace(
        t.attestation,
        verified_operations=t.attestation.verified_operations | CHECK_READS | {"session.shell"},
    )
    selection = CheckSelection(
        reference=REF,
        check=CHECK,
        catalog_sha256=digest(catalog.model_dump(mode="json")),
        qualification_sha256=qualification.enrollment_sha256,
    )
    source = HumanMessage(
        realm_id="realm",
        channel_id=4,
        topic="original",
        message_id=12,
        revision=0,
        author_id=9,
        text="!oz check " + "x" * 32,
    )
    payload = {
        "operation": "check.run",
        "binding_id": "synthetic-original-binding",
        "binding_revision": 1,
        "reference": REF.model_dump(mode="json"),
        "source": source.model_dump(mode="json"),
        "selection": selection.model_dump(mode="json"),
        "selection_token_sha256": token_hash("x" * 32),
        "choice_expires_at": time.time() + 300,
        "reply_locale": "en",
    }
    state = {
        "location": {
            "directory": REF.canonical_directory,
            "project": {
                "id": "native-project",
                "directory": REF.canonical_directory,
                "canonical": REF.canonical_directory,
            },
        }
    }
    seen = []
    counts = {}

    def handle(request):
        seen.append(request)
        path = request.url.path
        counts[path] = counts.get(path, 0) + 1
        if request.method == "POST":
            assert path == "/api/session/ses_original/shell"
            body = json.loads(request.content)
            assert body == {"id": check_message_id("a"), "command": CHECK.command}
            state["message"] = {
                "id": body["id"],
                "type": "shell",
                "command": body["command"],
                "shellID": "sh_original",
                "status": "exited",
                "exit": 0,
                "time": {"created": 101, "completed": 201},
                "output": {"output": "2 passed", "cursor": 8, "size": 8, "truncated": False},
            }
            state["shell"] = {
                "id": "sh_original",
                "command": body["command"],
                "cwd": REF.canonical_directory,
                "shell": "/bin/bash",
                "file": "/private/output-not-read",
                "metadata": {"sessionID": REF.upstream_session_id, "background": True},
                "status": "exited",
                "exit": 0,
                "time": {"started": 100, "completed": 200},
            }
            if mode == "lost-ack":
                raise httpx.ReadTimeout("synthetic ACK lost after original shell", request=request)
            return httpx.Response(204)
        if path == "/api/location":
            value = copy.deepcopy(state["location"])
        elif "/message/" in path:
            value = {"data": copy.deepcopy(state["message"])}
        elif path == "/api/shell/sh_original":
            value = {
                "location": {"directory": REF.canonical_directory},
                "data": copy.deepcopy(state["shell"]),
            }
        else:
            value = {"data": copy.deepcopy(data)}
        if hook:
            hook(path, counts[path], value, client, state)
        return httpx.Response(200, json=value)

    def synthetic_owner(reference, proof):
        assert reference == REF and proof.reference == REF
        assert proof.state.value == "idle" and proof.connection_epoch == client.proofs.epoch
        assert proof.issued_at <= time.time() < proof.expires_at
        return "e" * 64  # Explicit synthetic original-owner hook, never installed qualification.

    client.proofs.dispatch_owner_epoch = synthetic_owner
    t.client._transport = httpx.MockTransport(handle)
    return client, t, payload, guard, seen, state


async def submit(client, payload):
    async def synthetic_authority(context):
        return None  # Explicit mock, never live Human/lease qualification.

    return await client.submit_check(REF, payload, "a", synthetic_authority)


async def test_exact_original_session_shell_one_post_and_actual_exit_readback():
    client, t, payload, guard, seen, state = setup()
    try:
        assert client.capabilities(REF)["check.run"].supported
        admitted = await submit(client, payload)
        assert (
            admitted.status == "admitted"
            and not admitted.details["check_passed"]
            and not admitted.details["turn_completed"]
        )
        result = await client.checks.observe(REF, "a", CHECK)
        assert result.outcome == "passed" and result.exit_code == 0 and result.output == "2 passed"
        assert len([r for r in seen if r.method == "POST"]) == 1
        assert not any("/prompt" in r.url.path for r in seen)
    finally:
        await t.close()


async def test_lost_http_ack_can_read_original_result_without_post_retry():
    client, t, payload, guard, seen, state = setup("lost-ack")
    try:
        with pytest.raises(TransportError):
            await submit(client, payload)
        assert (await client.checks.observe(REF, "a", CHECK)).outcome == "passed"
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await t.close()


@pytest.mark.parametrize(
    "failure",
    [
        "policy-deny",
        "missing-policy",
        "no-qualification",
        "unqualified-operation",
        "expired",
        "changed-command",
        "changed-reference",
        "edited-source",
    ],
)
async def test_unqualified_or_stale_check_never_posts(failure):
    client, t, payload, guard, seen, state = setup()
    try:
        if failure == "policy-deny":
            guard.allowed = False
        if failure == "missing-policy":
            client.scope_guard = None
        if failure == "no-qualification":
            client.checks = V2CheckRunner(client, {})
        if failure == "unqualified-operation":
            t.attestation = replace(
                t.attestation,
                verified_operations=t.attestation.verified_operations - {"session.shell"},
            )
        if failure == "expired":
            payload["choice_expires_at"] = time.time() - 1
        if failure == "changed-command":
            payload["selection"]["check"]["command"] = "echo forged"
        if failure == "changed-reference":
            payload["selection"]["reference"]["upstream_session_id"] = "ses_other"
        if failure == "edited-source":
            payload["source"]["revision"] = 1
        with pytest.raises(MutationNotSent):
            await submit(client, payload)
        assert not any(r.method == "POST" for r in seen)
    finally:
        await t.close()


@pytest.mark.parametrize("failure", ["deadline", "attestation", "guard"])
async def test_policy_await_cannot_cross_expiry_or_replace_the_qualified_send(failure):
    client, t, payload, guard, seen, state = setup()
    try:
        if failure == "deadline":
            payload["choice_expires_at"] = time.time() + 0.05

        async def change():
            if failure == "deadline":
                await asyncio.sleep(0.1)
            if failure == "attestation":
                t.attestation = replace(t.attestation)
            if failure == "guard":
                guard.allowed = False

        guard.hook = change
        with pytest.raises(MutationNotSent):
            await submit(client, payload)
        assert not any(r.method == "POST" for r in seen)
    finally:
        await t.close()


@pytest.mark.parametrize(
    "failure",
    [
        "message-command",
        "shell-session",
        "shell-cwd",
        "message-id",
        "root",
        "changed-second-read",
        "owner",
        "attestation",
    ],
)
async def test_foreign_drifting_or_changed_original_result_is_rejected(failure):
    armed = False

    def hook(path, count, value, client, state):
        if not armed:
            return
        if "/message/" in path:
            if failure == "message-command":
                value["data"]["command"] = "echo pass"
            if failure == "message-id":
                value["data"]["id"] = "msg_foreign"
            if failure == "changed-second-read" and count == 2:
                value["data"]["output"]["output"] = "changed"
        if path.startswith("/api/shell/"):
            if failure == "shell-session":
                value["data"]["metadata"]["sessionID"] = "ses_other"
            if failure == "shell-cwd":
                value["data"]["cwd"] = "/foreign"
            if failure == "owner":
                client.proofs.epoch = "other-owner"
            if failure == "attestation":
                client.transport.attestation = replace(client.transport.attestation)
        if path == "/api/location" and failure == "root":
            value["project"]["directory"] = "/parent"

    client, t, payload, guard, seen, state = setup(hook=hook)
    try:
        await submit(client, payload)
        armed = True
        with pytest.raises((ContractError, TransportError)):
            await client.checks.observe(REF, "a", CHECK)
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await t.close()


async def test_real_native_policy_guard_deny_all_still_refuses_an_approved_shell():
    from tests.contract.test_leaf_resources import REF as root
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_native_project_policy import setup as policy_setup

    provider, transport, data, guard, client, calls, writes = await policy_setup()
    try:
        _, proof = await client.qualified_snapshot(root)
        with pytest.raises(ContractError, match="not_allowed"):
            await guard.authorize_check(root, proof, CHECK.command)
        assert not writes
    finally:
        await finish(provider, transport)


def test_check_semantics_pin_actual_retained_tag_sources():
    import hashlib
    from pathlib import Path

    from jt_oz_bridge.adapters.opencode.checks import CHECK_SOURCES

    directory = Path("tests/fixtures/installed/opencode-v2.0.32/source")
    files = {
        "session.ts": "packages_core_src_session_session.ts",
        "message-updater.ts": "packages_core_src_session_message-updater.ts",
        "session-shell.ts": "packages_core_src_session_shell.ts",
        "shell.ts": "packages_core_src_shell.ts",
        "wildcard.ts": "packages_core_src_util_wildcard.ts",
    }
    assert set(files) == set(CHECK_SOURCES)
    for name, path in files.items():
        assert hashlib.sha256((directory / path).read_bytes()).hexdigest() == CHECK_SOURCES[name]


async def leaf_tail_fixture(failure=None, *, running=False, watched=True):
    from jt_oz_bridge.adapters.opencode.checks import KnownCheck, V2CheckTailReader
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from tests.contract.test_leaf_resources import REF as root
    from tests.contract.test_leaf_resources import setup as leaf_setup

    provider, transport, data, calls = await leaf_setup()
    catalog = CheckCatalog(
        reference=root, contract_sha256=transport.profile.sha256, checks=(CHECK,)
    )
    qualification = CheckExecutionAttestation(catalog, CHECK_SEMANTICS, "a" * 64)
    transport.attestation = replace(
        transport.attestation,
        verified_operations=transport.attestation.verified_operations
        | CHECK_READS
        | {"session.shell"},
    )

    async def known(ref, identity):
        if failure == "missing-action":
            raise ContractError("no durable owned Action")
        assert ref == root and identity == check_message_id("a")
        return KnownCheck("a", "b" * 64, CHECK, qualification.enrollment_sha256)

    provider.check_tail = V2CheckTailReader(
        transport, qualification, known, model_settings=provider.model_settings
    )
    original_idle = data["session.message.list"]["data"][0]
    shell = {
        "id": check_message_id("a"),
        "type": "shell",
        "command": CHECK.command,
        "shellID": "sh_owned",
        "status": "exited",
        "exit": 0,
        "time": {"created": 10, "completed": 20},
        "output": {"output": "2 passed", "cursor": 8, "size": 8, "truncated": False},
    }
    notice = {
        "id": "msg_check_notice",
        "type": "synthetic",
        "text": "Arbitrary text is ignored",
        "metadata": {"source": "shell", "shellID": "sh_owned", "state": "completed", "exit": 0},
        "time": {"created": 21},
    }
    record = {
        "id": "sh_owned",
        "status": "exited",
        "command": CHECK.command,
        "cwd": root.canonical_directory,
        "shell": "/bin/bash",
        "file": "/private/not-read",
        "metadata": {"sessionID": root.upstream_session_id, "background": True},
        "exit": 0,
        "time": {"started": 9, "completed": 19},
    }
    tail = [notice, shell, original_idle]
    data["check_tail_rows"] = tail
    if failure == "command":
        shell["command"] = "echo forged"
    if failure == "notice-source":
        notice["metadata"]["source"] = "tool"
    if failure == "notice-shell":
        notice["metadata"]["shellID"] = "sh_other"
    if failure == "notice-exit":
        notice["metadata"]["exit"] = 1
    if failure == "boundary":
        tail.pop()
    if failure == "unowned-input":
        tail[1] = {
            "id": "msg_unowned",
            "type": "synthetic",
            "text": "tests passed",
            "time": {"created": 10},
        }
    delegate = transport.client._transport

    def handler(request):
        path = request.url.path
        if path.endswith("/message") and request.url.params.get("limit") == "51":
            return httpx.Response(200, json={"data": copy.deepcopy(tail), "cursor": {}})
        if "/message/" in path:
            return httpx.Response(200, json={"data": copy.deepcopy(shell)})
        if path == "/api/shell/sh_owned":
            return httpx.Response(
                200,
                json={
                    "location": {"directory": root.canonical_directory},
                    "data": copy.deepcopy(record),
                },
            )
        if path == "/api/location":
            return httpx.Response(
                200,
                json={
                    "directory": root.canonical_directory,
                    "project": {
                        "id": "global",
                        "directory": root.canonical_directory,
                        "canonical": root.canonical_directory,
                    },
                },
            )
        return delegate.handler(request)

    transport.client._transport = httpx.MockTransport(handler)
    client = V2ExecutionClient(transport, provider.projects, proofs=provider)
    client.checks = V2CheckRunner(client, {root: qualification})
    if running and watched:
        await provider.watch(root)
    data["session.get"]["data"]["time"]["updated"] = 21
    data["session.message.list"]["data"] = [notice]
    if running:
        shell["status"] = record["status"] = "running"
        shell.pop("exit")
        record.pop("exit")
        shell["time"].pop("completed")
        record["time"].pop("completed")
        shell.pop("output")
        data["session.message.list"]["data"] = [shell]
        data["shell.list"]["data"] = [record]
    return provider, transport, data, client, root


async def test_actual_leaf_resource_proof_recognizes_owned_terminal_check_tail_and_original_idle():
    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture()
    try:
        witness = await provider.watch(root)
        assert witness.state.value == "idle"
        assert (await client.checks.observe(root, "a", CHECK)).outcome == "passed"
        assert (await client.qualified_snapshot(root))[0].state.value == "idle"
    finally:
        await finish(provider, transport)


@pytest.mark.parametrize(
    "failure",
    [
        "missing-action",
        "command",
        "notice-source",
        "notice-shell",
        "notice-exit",
        "boundary",
        "unowned-input",
    ],
)
async def test_actual_leaf_never_calls_unowned_or_inconsistent_shell_tail_idle(failure):
    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture(failure)
    try:
        with pytest.raises((ContractError, AssertionError)):
            await provider.watch(root)
    finally:
        await finish(provider, transport)


async def test_running_check_result_read_does_not_require_a_fabricated_idle_or_background_mutation_proof():
    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture(running=True)
    try:
        with pytest.raises(ContractError, match="background"):
            await client.qualified_snapshot(root)
        assert (await client.checks.observe(root, "a", CHECK)).outcome == "running"
    finally:
        await finish(provider, transport)


@pytest.mark.parametrize("position", ["before", "after"])
@pytest.mark.parametrize("changed", [False, True])
async def test_owned_check_tail_composes_qualified_model_controls_and_refuses_changed_chain(
    position, changed
):
    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )
    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture()
    try:
        model_qualification = ModelSettingsAttestation(
            root, transport.profile.sha256, MODEL_SETTING_SEMANTICS, "f" * 64
        )
        provider.model_settings = model_qualification
        provider.check_tail.model_settings = model_qualification
        target = {"providerID": "synthetic-provider", "id": "after"}
        previous = {"providerID": "synthetic-provider", "id": "before"}
        row = {
            "id": "msg_model_control",
            "type": "model-switched",
            "model": dict(target),
            "previous": previous,
            "time": {"created": 22 if position == "after" else 4},
        }
        data["session.get"]["data"]["model"] = target
        if changed:
            row["model"]["id"] = "foreign"
        if position == "after":
            data["check_tail_rows"].insert(0, row)
            data["session.message.list"]["data"] = [row]
            data["session.get"]["data"]["time"]["updated"] = 22
        else:
            data["check_tail_rows"].insert(2, row)
        if changed:
            with pytest.raises(ContractError):
                await provider.watch(root)
        else:
            assert (await provider.watch(root)).state.value == "idle"
    finally:
        await finish(provider, transport)


async def test_shell_transport_requires_explicit_final_authority_and_runs_it_after_native_identity():
    client, transport, payload, guard, seen, state = setup()
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload, "a")
        order = []
        contexts = []
        original = transport.verify_identity

        async def identity():
            order.append("identity")
            return await original()

        transport.verify_identity = identity

        class Auth(httpx.Auth):
            def auth_flow(self, request):
                order.append("auth")
                yield request

        transport.client.auth = Auth()

        async def authority(context):
            order.append("authority")
            contexts.append(context)

        await client.submit_check(REF, payload, "a", authority)
        assert (
            order[-4:] == ["identity", "authority", "auth", "authority"]
            and len(contexts) == 2
            and contexts[0] == contexts[1]
            and len([r for r in seen if r.method == "POST"]) == 1
        )
    finally:
        await transport.close()


async def test_final_native_human_authority_rejection_cannot_send_a_shell():
    client, transport, payload, guard, seen, state = setup()
    try:

        async def denied(context):
            raise PermissionError("synthetic final authorization revoked")

        with pytest.raises(MutationNotSent):
            await client.submit_check(REF, payload, "a", denied)
        assert not any(r.method == "POST" for r in seen)
    finally:
        await transport.close()


async def test_running_check_before_any_mutation_watch_reads_only_original_shell():
    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture(running=True, watched=False)
    requests = []
    delegate = transport.client._transport

    def observe(request):
        requests.append(request)
        return delegate.handler(request)

    transport.client._transport = httpx.MockTransport(observe)
    try:
        assert not provider._watched
        assert provider.certified_epoch(root, transport.profile.sha256) is None
        with pytest.raises(ContractError, match="background"):
            await provider.watch(root)
        result = await client.checks.observe(root, "a", CHECK)
        assert result.outcome == "running" and result.message_id == check_message_id("a")
        assert provider.read_epoch(root, transport.profile.sha256)
        assert provider.certified_epoch(root, transport.profile.sha256) is None
        assert not provider._watched and not provider.witnesses
        assert not client.capabilities(root)["check.run"].supported
        assert requests and all(r.method == "GET" for r in requests)
        with pytest.raises(ContractError, match="unavailable"):
            client.epoch(root)
    finally:
        await finish(provider, transport)


@pytest.mark.parametrize(
    "fault",
    [
        "owner",
        "feed",
        "scope",
        "shell-second",
        "message-second",
        "qualification",
        "provider",
        "timeout",
    ],
)
async def test_readonly_running_result_strict_readback_rejects_drift_before_watch(
    fault, monkeypatch
):
    from types import SimpleNamespace

    import jt_oz_bridge.adapters.opencode.checks as module
    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture(running=True, watched=False)
    delegate = transport.client._transport
    calls = {"shell": 0, "message": 0}
    clock = [1000.0]
    if fault == "timeout":
        monkeypatch.setattr(module.time, "time", lambda: clock[0])

    def changing(request):
        response = delegate.handler(request)
        if request.url.path == "/api/shell/sh_owned":
            calls["shell"] += 1
            if calls["shell"] == 1:
                if fault == "owner":
                    provider.feed.owner.read.return_value = SimpleNamespace(owner_epoch="b" * 64)
                elif fault == "feed":
                    provider.feed.index.invalidate("synthetic feed lost")
                elif fault == "scope":
                    data["session.get"]["data"]["location"]["directory"] = "/foreign"
                elif fault == "qualification":
                    client.checks.attestations = {}
                elif fault == "provider":
                    client.proofs = None
                elif fault == "timeout":
                    clock[0] += 5
            if calls["shell"] == 2 and fault == "shell-second":
                raw = response.json()
                raw["data"]["time"]["started"] -= 1
                return httpx.Response(200, json=raw)
        if "/message/" in request.url.path:
            calls["message"] += 1
            if calls["message"] == 2 and fault == "message-second":
                raw = response.json()
                raw["data"]["command"] = "echo forged pass"
                return httpx.Response(200, json=raw)
        return response

    transport.client._transport = httpx.MockTransport(changing)
    try:
        with pytest.raises(ContractError):
            await client.checks.observe(root, "a", CHECK)
        assert not provider._watched and not provider.witnesses
    finally:
        await finish(provider, transport)


async def test_readonly_rejection_never_falls_back_to_an_existing_mutation_watch():
    from unittest.mock import AsyncMock

    from tests.contract.test_leaf_resources import finish

    provider, transport, data, client, root = await leaf_tail_fixture()
    try:
        await provider.watch(root)
        assert client.epoch(root)
        provider.read_scope = AsyncMock(side_effect=ContractError("synthetic read scope revoked"))
        with pytest.raises(ContractError, match="read scope revoked"):
            await client.checks.observe(root, "a", CHECK)
        provider.read_scope.assert_awaited_once_with(root)
    finally:
        await finish(provider, transport)


async def test_incomplete_readonly_provider_interface_cannot_borrow_mutation_epoch():
    client, transport, payload, guard, seen, state = setup()
    try:
        await submit(client, payload)
        client.proofs.read_epoch = lambda *_: client.proofs.epoch
        with pytest.raises(ContractError, match="provider_incomplete"):
            await client.checks.observe(REF, "a", CHECK)
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "failure",
    ["missing-owner-hook", "bad-owner", "binding-id", "binding-revision", "owner-hook-error"],
)
async def test_missing_or_invalid_internal_dispatch_owner_context_never_posts(failure):
    client, transport, payload, guard, seen, state = setup()
    if failure == "missing-owner-hook":
        del client.proofs.dispatch_owner_epoch
    elif failure == "bad-owner":
        client.proofs.dispatch_owner_epoch = lambda ref, proof: "not-an-owner-epoch"
    elif failure == "owner-hook-error":

        def fail(ref, proof):
            raise ValueError("synthetic owner evidence unavailable")

        client.proofs.dispatch_owner_epoch = fail
    elif failure == "binding-id":
        payload.pop("binding_id")
    else:
        payload["binding_revision"] = True
    contexts = []

    async def authority(context):
        contexts.append(context)

    try:
        with pytest.raises(MutationNotSent):
            await client.submit_check(REF, payload, "a", authority)
        assert not contexts and not any(request.method == "POST" for request in seen)
    finally:
        await transport.close()


async def test_final_context_contains_original_owner_and_never_changes_native_body():
    from jt_oz_bridge.storage.durable import digest

    client, transport, payload, guard, seen, state = setup()
    contexts = []

    async def authority(context):
        contexts.append(context)

    try:
        await client.submit_check(REF, payload, "a", authority)
        context = contexts[0]
        assert context.owner_epoch == "e" * 64 and context.state == "idle"
        assert context.reference == REF and context.action_id == "a"
        assert context.operation_digest == digest(payload)
        assert context.binding_id == payload["binding_id"]
        assert context.binding_revision == payload["binding_revision"]
        assert context.connection_epoch == client.proofs.epoch
        assert context.ownership_evidence_sha256 == "b" * 64
        posts = [request for request in seen if request.method == "POST"]
        assert len(posts) == 1
        assert json.loads(posts[0].content) == {
            "id": check_message_id("a"),
            "command": CHECK.command,
        }
    finally:
        await transport.close()


async def test_owner_change_during_final_human_callback_is_rechecked_before_post():
    client, transport, payload, guard, seen, state = setup()
    owner = ["e" * 64]
    client.proofs.dispatch_owner_epoch = lambda ref, proof: owner[0]
    contexts = []

    async def authority(context):
        contexts.append(context)
        owner[0] = "f" * 64

    try:
        with pytest.raises(MutationNotSent):
            await client.submit_check(REF, payload, "a", authority)
        assert len(contexts) == 1
        assert not any(request.method == "POST" for request in seen)
    finally:
        await transport.close()
