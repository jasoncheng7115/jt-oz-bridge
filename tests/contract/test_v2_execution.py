"""Synthetic providers are explicit mocks, never installed-owner certification."""

import json
import time
from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.execution import (
    OPERATIONS,
    OriginalExecutionProof,
    V2ExecutionClient,
)
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.control import ExecutionState, FieldAnswer
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.models import SessionRef
from tests.contract.test_v2_catalog import SCOPE, native
from tests.integration.test_dispatch import message

REF = SessionRef(**SCOPE.model_dump(), upstream_session_id="ses_original")
ALL_OPERATIONS = frozenset(
    {"session.get"} | {operation for required in OPERATIONS.values() for operation in required}
)


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


class SyntheticProofs:
    def __init__(self):
        self.epoch = "qualified-fixture-epoch"
        self.changes = {}
        self.kind = "form"
        self.state = ExecutionState.IDLE

    def certified_epoch(self, reference, contract):
        return self.epoch

    async def prove(self, reference, contract, info_sha):
        now = time.time()
        return OriginalExecutionProof(
            reference=reference,
            contract_sha256=contract,
            session_info_sha256=info_sha,
            ownership_evidence_sha256="b" * 64,
            connection_epoch=self.epoch,
            issued_at=now,
            expires_at=now + 20,
            state=self.state,
            cursor="stream:fixture:42",
            descendants=(),
        ).model_copy(update=self.changes)

    async def interaction_kind(self, reference, request_id, epoch):
        return self.kind


def setup(profile, *, proofs=True, change=None):
    seen = []
    provider = SyntheticProofs() if proofs else None
    data = {
        "native": native(),
        "permission": [
            {
                "id": "per_original",
                "sessionID": REF.upstream_session_id,
                "action": "write",
                "resources": ["file.txt"],
                "message": "Write original",
            }
        ],
        "form": {
            "id": "frm_original",
            "sessionID": REF.upstream_session_id,
            "title": "Original form",
            "fields": [
                {"key": "enabled", "type": "boolean", "required": True},
                {"key": "count", "type": "integer", "required": True},
            ],
            "state": {"status": "pending"},
        },
        "interrupted": False,
    }

    def handle(request):
        seen.append(request)
        if change:
            response = change(request, data, provider)
            if response is not None:
                return response
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "data": data["permission"]
                    if request.url.path.endswith("/permission")
                    else data["form"]
                    if "/form/" in request.url.path
                    else data["native"]
                },
            )
        if request.url.path.endswith("/prompt"):
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "msg_original",
                        "sessionID": REF.upstream_session_id,
                        "time": {"created": 0},
                        "type": "user",
                        "payload": {"text": body["text"]},
                        "delivery": body["delivery"],
                    }
                },
            )
        if request.url.path.endswith("/interrupt"):
            return httpx.Response(200, json={"interrupted": data["interrupted"]})
        return httpx.Response(204)

    async def verify():
        return True

    transport = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, SCOPE.backend_identity, "synthetic-fixture", ALL_OPERATIONS
        ),
        verify_identity=verify,
        transport=httpx.MockTransport(handle),
    )
    return (
        V2ExecutionClient(
            transport,
            {SCOPE.project_id: V2CatalogProject(SCOPE, "native-project-id")},
            proofs=provider,
        ),
        transport,
        provider,
        data,
        seen,
    )


def payload(operation="prompt", **changes):
    command = {
        "prompt": "!oz send --   exact\n!oz stop\n",
        "interrupt": "!oz stop",
        "permission.reply": "!oz approve opaque once",
        "form.reply": "!oz answer opaque submit",
        "form.cancel": "!oz confirm opaque",
    }[operation]
    result = {
        "operation": operation,
        "reference": REF.model_dump(),
        "source": message(text=command, revision=0).model_dump(mode="json"),
    }
    if operation == "prompt":
        result["text"] = "  exact\n!oz stop\n"
    return {**result, **changes}


async def decision_payload(client, operation):
    request_id = "per_original" if operation == "permission.reply" else "frm_original"
    current = await client.interaction(REF, request_id)
    return payload(
        operation,
        interaction_id="local-interaction",
        request_id=request_id,
        generation=current.generation,
    )


async def test_no_default_provider_enables_nothing_or_native_read(profile):
    client, transport, provider, data, seen = setup(profile, proofs=False)
    try:
        assert not any(cap.supported for cap in client.capabilities(REF).values())
        with pytest.raises(ContractError):
            await client.snapshot(REF)
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload(), "action")
        assert not seen
    finally:
        await transport.close()


async def test_qualified_snapshot_uses_exact_get_without_active_guessing(profile):
    client, transport, proof, data, seen = setup(profile)
    proof.state = ExecutionState.RUNNING
    try:
        snapshot = await client.snapshot(REF)
        assert (
            snapshot.reference == REF
            and snapshot.reconciled
            and snapshot.state == ExecutionState.RUNNING
        )
        assert snapshot.title == data["native"]["title"] and snapshot.cursor == "stream:fixture:42"
        assert [(request.method, request.url.path) for request in seen] == [
            ("GET", "/api/session/ses_original")
        ]
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change",
    [
        "ref",
        "hash",
        "contract",
        "epoch",
        "expired",
        "future",
        "long",
        "unknown",
        "foreign-child",
        "duplicate-child",
    ],
)
async def test_snapshot_proof_mismatch_never_enables_mutation(profile, change):
    client, transport, proof, data, seen = setup(profile)
    child = REF.model_copy(update={"upstream_session_id": "ses_child"})
    proof.changes = {
        "ref": {"reference": child},
        "hash": {"session_info_sha256": "c" * 64},
        "contract": {"contract_sha256": "d" * 64},
        "epoch": {"connection_epoch": "other"},
        "expired": {"issued_at": 0, "expires_at": 1},
        "future": {"issued_at": time.time() + 100, "expires_at": time.time() + 110},
        "long": {"expires_at": time.time() + 100},
        "unknown": {"state": ExecutionState.UNKNOWN},
        "foreign-child": {
            "descendants": (child.model_copy(update={"canonical_directory": "/outside"}),)
        },
        "duplicate-child": {"descendants": (child, child)},
    }[change]
    try:
        with pytest.raises(ContractError):
            await client.snapshot(REF)
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload(), "action")
        assert all(request.method == "GET" for request in seen)
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change",
    [{"id": "ses_other"}, {"projectID": "foreign"}, {"location": {"directory": "/outside"}}],
)
async def test_native_get_must_match_session_project_and_workspace(profile, change):
    client, transport, proof, data, seen = setup(profile)
    data["native"].update(change)
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload(), "action")
        assert all(request.method == "GET" for request in seen)
    finally:
        await transport.close()


async def test_prompt_wire_preserves_literal_and_records_admission_only(profile):
    client, transport, proof, data, seen = setup(profile)
    original = payload()
    try:
        result = await client.submit(REF, original, "action-original")
        assert (
            result.status == "admitted"
            and result.owner == "opencode"
            and result.upstream_id == "msg_original"
        )
        assert result.details["turn_completed"] is False
        sent = [request for request in seen if request.method == "POST"]
        assert len(sent) == 1 and sent[0].url.path == "/api/session/ses_original/prompt"
        wire = json.loads(sent[0].content)
        assert wire["text"] == original["text"] and wire["delivery"] == "queue"
        assert wire["metadata"]["jt_oz_bridge"]["action_id"] == "action-original"
        assert set(wire) == {"text", "delivery", "metadata"}  # No model/agent/clone/wake override.
    finally:
        await transport.close()


@pytest.mark.parametrize("decision", ["once", "reject"])
async def test_permission_exact_native_request_and_reason_wire(profile, decision):
    client, transport, proof, data, seen = setup(profile)
    proof.kind = "permission"
    try:
        request = await decision_payload(client, "permission.reply")
        request.update(decision=decision, answers={})
        if decision == "reject":
            request["source"]["text"] = "!oz deny opaque exact reason"
            request["reason"] = "  exact reason\n"
        result = await client.submit(REF, request, "action")
        assert result.status == "completed" and result.upstream_id == "per_original"
        sent = [request for request in seen if request.method == "POST"]
        assert len(sent) == 1 and sent[0].url.path.endswith("/permission/per_original/reply")
        assert json.loads(sent[0].content) == (
            {"decision": "once"}
            if decision == "once"
            else {"decision": "reject", "message": "  exact reason\n"}
        )
        assert result.details["turn_completed"] is False
    finally:
        await transport.close()


async def test_form_wire_preserves_false_and_zero_and_cancel_is_bodyless(profile):
    client, transport, proof, data, seen = setup(profile)
    try:
        request = await decision_payload(client, "form.reply")
        request.update(
            decision=None,
            answers={
                "enabled": FieldAnswer(value=False).model_dump(),
                "count": FieldAnswer(value=0).model_dump(),
            },
        )
        assert (await client.submit(REF, request, "answer-action")).status == "completed"
        sent = [request for request in seen if request.method == "POST"]
        assert json.loads(sent[0].content) == {"answer": {"enabled": False, "count": 0}}
        cancel = await decision_payload(client, "form.cancel")
        assert (await client.submit(REF, cancel, "cancel-action")).status == "completed"
        sent = [request for request in seen if request.method == "DELETE"]
        assert (
            len(sent) == 1
            and sent[0].url.path.endswith("/form/frm_original")
            and sent[0].content == b""
            and not sent[0].url.query
        )
    finally:
        await transport.close()


@pytest.mark.parametrize("interrupted", [False, True])
async def test_interrupt_never_resumes_and_reports_only_actual_native_result(profile, interrupted):
    client, transport, proof, data, seen = setup(profile)
    data["interrupted"] = interrupted
    try:
        result = await client.submit(REF, payload("interrupt"), "stop-action")
        sent = [request for request in seen if request.method == "POST"]
        assert (
            len(sent) == 1
            and sent[0].content == b""
            and dict(sent[0].url.params) == {"resume": "false"}
        )
        assert result.details["interrupted"] is interrupted
        assert (
            result.details["children_verified_stopped"] is False
            and result.details["turn_completed"] is False
        )
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change", ["busy", "bot", "deleted", "text", "control", "files", "reference"]
)
async def test_invalid_prompt_cannot_mutate_or_override_native_configuration(profile, change):
    client, transport, proof, data, seen = setup(profile)
    original = payload()
    if change == "busy":
        proof.state = ExecutionState.RUNNING
    elif change == "bot":
        original["source"]["is_bot"] = True
    elif change == "deleted":
        original["source"]["deleted"] = True
    elif change == "text":
        original["text"] = "different text"
    elif change == "control":
        original["source"]["text"] = "!oz stop"
    elif change == "files":
        original["files"] = [{"uri": "file:///etc/private"}]
    else:
        original["reference"]["upstream_session_id"] = "ses_other"
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, original, "action")
        assert all(request.method == "GET" for request in seen)
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["missing-op", "missing-get", "identity"])
async def test_missing_installed_operation_or_peer_verifier_disables_capability(profile, change):
    client, transport, proof, data, seen = setup(profile)
    if change == "identity":
        transport.verify_identity = None
    else:
        removed = "session.prompt" if change == "missing-op" else "session.get"
        transport.attestation = ContractAttestation(
            profile.sha256, SCOPE.backend_identity, "fixture", ALL_OPERATIONS - {removed}
        )
    try:
        assert not client.capabilities(REF)["prompt"].supported
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload(), "action")
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["timeout", "session", "text", "delivery", "invalid-json"])
async def test_post_attempt_failure_is_uncertain_without_second_attempt_or_fallback(
    profile, change
):
    def altered(request, data, proof):
        if request.method != "POST":
            return None
        if change == "timeout":
            raise httpx.ReadTimeout("response lost", request=request)
        if change == "invalid-json":
            return httpx.Response(200, content=b'{"data":')
        body = json.loads(request.content)
        raw = {
            "id": "msg_original",
            "sessionID": "ses_other" if change == "session" else REF.upstream_session_id,
            "time": {"created": 0},
            "type": "user",
            "payload": {"text": "different" if change == "text" else body["text"]},
            "delivery": "steer" if change == "delivery" else "queue",
        }
        return httpx.Response(200, json={"data": raw})

    client, transport, proof, data, seen = setup(profile, change=altered)
    try:
        with pytest.raises((ContractError, TransportError)) as error:
            await client.submit(REF, payload(), "action")
        assert not isinstance(error.value, MutationNotSent)
        assert len([request for request in seen if request.method == "POST"]) == 1
        assert all(request.url.path.startswith("/api/session/ses_original") for request in seen)
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["epoch", "expiry", "attestation"])
async def test_final_guard_after_async_identity_check_prevents_stale_owner_post(
    profile, change, monkeypatch
):
    client, transport, proof, data, seen = setup(profile)
    calls = 0
    observed_time = [time.time()]
    monkeypatch.setattr(time, "time", lambda: observed_time[0])

    async def verify():
        nonlocal calls
        calls += 1
        # Prompt: before GET, after proof, then the transport's final check.
        if calls == 3:
            if change == "epoch":
                proof.epoch = "revoked-fixture-epoch"
            elif change == "expiry":
                observed_time[0] += 31
            else:
                transport.attestation = ContractAttestation(
                    profile.sha256,
                    SCOPE.backend_identity,
                    "fixture",
                    ALL_OPERATIONS - {"session.prompt"},
                )
        return True

    transport.verify_identity = verify
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload(), "action")
        assert calls == 3 and all(request.method == "GET" for request in seen)
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change",
    [
        "absent",
        "duplicate",
        "foreign",
        "unknown-kind",
        "generation",
        "always",
        "source",
        "read-revoked",
    ],
)
async def test_permission_requires_exact_pending_kind_generation_and_limited_decision(
    profile, change
):
    client, transport, proof, data, seen = setup(profile)
    proof.kind = "permission"
    try:
        original = await decision_payload(client, "permission.reply")
        original.update(decision="once", answers={})
        if change == "absent":
            data["permission"] = []
        elif change == "duplicate":
            data["permission"] *= 2
        elif change == "foreign":
            data["permission"][0]["sessionID"] = "ses_other"
        elif change == "unknown-kind":
            proof.kind = None
        elif change == "generation":
            original["generation"] = "changed"
        elif change == "always":
            original["decision"] = "always"
        elif change == "source":
            original["source"]["text"] = "!oz deny opaque"
        else:
            transport.attestation = ContractAttestation(
                profile.sha256,
                SCOPE.backend_identity,
                "fixture",
                ALL_OPERATIONS - {"session.permission.list"},
            )
        with pytest.raises(MutationNotSent):
            await client.submit(REF, original, "action")
        assert all(request.method == "GET" for request in seen)
        if change in {"absent", "unknown-kind"}:
            with pytest.raises(ContractError):
                await client.interaction(REF, "per_original")
            assert not any("/form" in request.url.path for request in seen)
    finally:
        await transport.close()


async def test_async_preflight_cannot_change_frozen_requested_text(profile):
    original = payload()

    def altered(request, data, proof):
        if request.method == "GET":
            original["text"] = "CHANGED_DURING_READ"
            original["source"]["text"] = "CHANGED_DURING_READ"
        return None

    client, transport, proof, data, seen = setup(profile, change=altered)
    try:
        result = await client.submit(REF, original, "action")
        assert result.status == "admitted"
        sent = next(request for request in seen if request.method == "POST")
        assert json.loads(sent.content)["text"] == "  exact\n!oz stop\n"
    finally:
        await transport.close()
