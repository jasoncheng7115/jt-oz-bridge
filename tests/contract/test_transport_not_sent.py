from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportNotSent,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.execution import MutationRejected


@pytest.mark.parametrize("change", ["missing", "false", "error", "replace"])
async def test_pre_http_identity_failure_is_typed_and_has_no_mutation_attempt(change):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.30-openapi.json")
    )
    attestation = ContractAttestation(
        profile.sha256, "fixture", "fixture-only", frozenset({"session.interrupt"})
    )
    attempts = []

    def handle(request):
        attempts.append(request)
        return httpx.Response(200, json={"interrupted": False})

    async def verify():
        if change == "error":
            raise RuntimeError("PRIVATE_VERIFIER_DATA")
        if change == "replace":
            client.attestation = ContractAttestation(
                profile.sha256, "other", "fixture-only", attestation.verified_operations
            )
        return change != "false"

    client = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=attestation,
        verify_identity=None if change == "missing" else verify,
        transport=httpx.MockTransport(handle),
    )
    try:
        with pytest.raises(TransportNotSent) as error:
            await client.request(
                "session.interrupt", path={"sessionID": "ses_original"}, query={"resume": "false"}
            )
        assert "PRIVATE" not in str(error.value) and not attempts
    finally:
        await client.close()


async def test_timeout_after_http_attempt_is_never_reported_as_not_sent():
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.30-openapi.json")
    )
    attempts = []

    async def verify():
        return True

    def handle(request):
        attempts.append(request)
        raise httpx.ReadTimeout("fixture response lost", request=request)

    client = V2HTTPTransport(
        "http://127.0.0.1:4096",
        profile,
        attestation=ContractAttestation(
            profile.sha256, "fixture", "fixture-only", frozenset({"session.interrupt"})
        ),
        verify_identity=verify,
        transport=httpx.MockTransport(handle),
    )
    try:
        with pytest.raises(ValueError) as error:
            await client.request("session.interrupt", path={"sessionID": "ses_original"})
        assert not isinstance(error.value, (TransportNotSent, MutationRejected))
        assert len(attempts) == 1
    finally:
        await client.close()
