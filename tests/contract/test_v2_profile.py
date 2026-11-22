import copy
import json
from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile, append_query
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)


@pytest.fixture
def profile():
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts/opencode-v2-openapi.json"))


def test_prompt_body_matches_public_v2_contract_and_rejects_v1_shape(profile):
    prepared = profile.prepare(
        "session.prompt",
        path={"sessionID": "ses_original"},
        body={"text": "literal text", "id": "msg_client", "delivery": "queue"},
    )
    assert prepared.path == "/api/session/ses_original/prompt" and prepared.method == "POST"
    with pytest.raises(ContractError, match="schema_mismatch"):
        profile.prepare(
            "session.prompt",
            path={"sessionID": "ses_original"},
            body={"parts": [{"type": "text", "text": "PRIVATE-MARKER"}]},
        )
    with pytest.raises(ContractError) as error:
        profile.prepare(
            "session.permission.reply",
            path={"sessionID": "ses_original", "requestID": "per_request"},
            body={"response": "PRIVATE-MARKER"},
        )
    assert "PRIVATE-MARKER" not in str(error.value)


def test_query_object_matches_official_generated_client(profile):
    prepared = profile.prepare(
        "model.list", query={"location": {"directory": "/workspace/project"}}
    )
    assert prepared.query == (("location[directory]", "/workspace/project"),)
    pairs = []
    append_query(pairs, "test", {"values": ["a", "b"], "optional": None, "flag": True})
    assert pairs == [
        ("test[values]", "a"),
        ("test[values]", "b"),
        ("test[optional]", "null"),
        ("test[flag]", "true"),
    ]
    with pytest.raises(ContractError, match="undeclared"):
        profile.prepare("model.list", query={"cwd": "/workspace"})


def test_opaque_ids_cannot_escape_a_route(profile):
    with pytest.raises(ContractError, match="unsafe"):
        profile.prepare("session.get", path={"sessionID": "ses_a/../../credential"})


def test_external_schema_references_never_fetch_network(profile):
    document = copy.deepcopy(profile.document)
    document["components"]["schemas"]["ServerInfo"] = {"$ref": "http://169.254.169.254/credentials"}
    with pytest.raises(ContractError, match="external"):
        OpenAPIProfile(json.dumps(document).encode())


async def test_public_schema_alone_cannot_enable_mutations(profile):
    def no_request(request):
        pytest.fail("unattested mutation reached HTTP transport")

    client = V2HTTPTransport(
        "http://127.0.0.1:4096", profile, transport=httpx.MockTransport(no_request)
    )
    try:
        with pytest.raises(TransportError, match="not_attested"):
            await client.request(
                "session.prompt", path={"sessionID": "ses_original"}, body={"text": "hello"}
            )
    finally:
        await client.close()


async def test_attestation_also_requires_a_fresh_identity_guard(profile):
    attestation = ContractAttestation(
        profile.sha256, "synthetic-identity", "synthetic-version", frozenset({"session.interrupt"})
    )

    def no_request(request):
        pytest.fail("unverified identity reached HTTP transport")

    client = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=attestation,
        transport=httpx.MockTransport(no_request),
    )
    try:
        with pytest.raises(TransportError, match="identity_not_verified"):
            await client.request("session.interrupt", path={"sessionID": "ses_original"})
    finally:
        await client.close()


async def test_known_contract_response_and_no_credential_catalog_access(profile):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "version": "2.0.30",
                "pid": 123,
                "urls": ["http://127.0.0.1:4096"],
                "paths": {"tmp": "/tmp/opencode"},
            },
        )

    client = V2HTTPTransport(
        "http://127.0.0.1:4096", profile, transport=httpx.MockTransport(handle)
    )
    try:
        assert (await client.request("server.info"))["version"] == "2.0.30"
        operation = next(
            key
            for key in profile.operations
            if "credential" in key and profile.operations[key][0] == "GET"
        )
        with pytest.raises(TransportError, match="not_allowed"):
            await client.request(operation)
        assert len(seen) == 1
    finally:
        await client.close()


async def test_contract_mismatch_does_not_echo_upstream_sensitive_values(profile):
    def handle(request):
        return httpx.Response(200, json={"version": "PRIVATE-MARKER"})

    client = V2HTTPTransport(
        "http://127.0.0.1:4096", profile, transport=httpx.MockTransport(handle)
    )
    try:
        with pytest.raises(ContractError) as error:
            await client.request("server.info")
        assert "PRIVATE-MARKER" not in str(error.value)
    finally:
        await client.close()


async def test_request_body_is_frozen_before_async_identity_checks(profile):
    original = {"decision": "once"}
    captured = []

    async def guard():
        original["decision"] = "always"
        return True

    def handle(request):
        captured.append(json.loads(request.content))
        return httpx.Response(204)

    attestation = ContractAttestation(
        profile.sha256,
        "synthetic-identity",
        "synthetic-version",
        frozenset({"session.permission.reply"}),
    )
    client = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=attestation,
        verify_identity=guard,
        transport=httpx.MockTransport(handle),
    )
    try:
        await client.request(
            "session.permission.reply",
            path={"sessionID": "ses_original", "requestID": "per_request"},
            body=original,
        )
        assert captured == [{"decision": "once"}]
        assert original["decision"] == "always"
    finally:
        await client.close()


def test_permission_denial_reason_uses_native_optional_message_field(profile):
    prepared = profile.prepare(
        "session.permission.reply",
        path={"sessionID": "ses_original", "requestID": "per_request"},
        body={"decision": "reject", "message": "A human rejection reason"},
    )
    assert prepared.method == "POST"
    assert prepared.body == {"decision": "reject", "message": "A human rejection reason"}
    # The domain stores `reason`; a concrete adapter must map it to `message`,
    # not guess an extra JSON field or inject it as an agent prompt.
    with pytest.raises(ContractError):
        profile.prepare(
            "session.permission.reply",
            path={"sessionID": "ses_original", "requestID": "per_request"},
            body={"decision": "reject", "reason": "wrong wire field"},
        )
