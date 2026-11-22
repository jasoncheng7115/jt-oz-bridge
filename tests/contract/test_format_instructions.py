"""Zulip formatting instruction entry against the pinned installed v2.0.32 contract.

Synthetic Native through httpx.MockTransport; not a live qualification.
"""

import json
from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.instructions import LIST, PUT, V2SessionInstructions
from jt_oz_bridge.adapters.opencode.transport import (
    MUTATION_OPERATIONS,
    READ_OPERATIONS,
    ContractAttestation,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.services.format_instructions import (
    GUIDANCE,
    KEY,
    FormattedExecution,
    ZulipFormatInstructions,
)
from tests.contract.test_v2_model_catalog import REF

CONTRACT = Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
ENTRIES = "/api/experimental/session/ses_original/instructions/entries"


def native(entries=None, *, put_status=204, attested=True):
    profile = OpenAPIProfile.from_file(CONTRACT)
    stored = dict(entries or {})
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body))
        if request.method == "GET" and request.url.path == ENTRIES:
            data = [{"key": k, "value": v} for k, v in stored.items()]
            return httpx.Response(200, json={"data": data})
        if request.method == "PUT" and request.url.path == f"{ENTRIES}/{KEY}":
            if put_status == 204:
                stored[KEY] = body["value"]
                return httpx.Response(204)
            return httpx.Response(put_status, json={"unexpected": True})
        raise AssertionError(f"unexpected Native request {request.method} {request.url.path}")

    async def identity():
        return True

    operations = {LIST, PUT} if attested else {LIST}
    transport = V2HTTPTransport(
        "https://native.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, REF.backend_identity, "2.0.32", frozenset(operations)
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handler),
    )
    return V2SessionInstructions(transport), stored, seen


class Inner:
    """Stands in for the dispatcher's registry; records what reached it."""

    def __init__(self):
        self.submitted: list[str] = []

    def contract_for(self, reference):
        return "c" * 64

    async def submit(self, reference, payload, action_id):
        self.submitted.append(payload["operation"])
        return Admission(status="admitted", upstream_id="msg_native")

    def custom(self):
        return "delegated"


def test_both_operations_are_in_the_pinned_contract_and_allowlisted():
    profile = OpenAPIProfile.from_file(CONTRACT)
    assert LIST in READ_OPERATIONS and PUT in MUTATION_OPERATIONS
    prepared = profile.prepare(
        PUT, path={"sessionID": "ses_original", "key": KEY}, body={"value": GUIDANCE}
    )
    assert prepared.method == "PUT" and prepared.path == f"{ENTRIES}/{KEY}"
    assert profile.prepare(LIST, path={"sessionID": "ses_original"}).method == "GET"
    with pytest.raises(ContractError):
        profile.prepare(PUT, path={"sessionID": "ses_original", "key": "Upper Case"}, body={})


async def test_absent_entry_is_put_once_then_left_alone():
    client, stored, seen = native()
    instructions = ZulipFormatInstructions({REF.backend_id: client})
    await instructions.ensure(REF)
    assert [(m, p) for m, p, _ in seen] == [("GET", ENTRIES), ("PUT", f"{ENTRIES}/{KEY}")]
    assert seen[1][2] == {"value": GUIDANCE} and stored[KEY] == GUIDANCE
    await instructions.ensure(REF)
    assert len(seen) == 2


async def test_present_entry_is_only_read_and_a_changed_one_is_replaced():
    client, _, seen = native({KEY: GUIDANCE, "other.key": "kept"})
    await ZulipFormatInstructions({REF.backend_id: client}).ensure(REF)
    assert [m for m, _, _ in seen] == ["GET"]
    client, stored, seen = native({KEY: "older wording"})
    await ZulipFormatInstructions({REF.backend_id: client}).ensure(REF)
    assert [m for m, _, _ in seen] == ["GET", "PUT"] and stored[KEY] == GUIDANCE


async def test_entry_is_checked_again_after_an_hour_and_put_if_removed():
    now = [1000.0]
    client, stored, seen = native()
    instructions = ZulipFormatInstructions({REF.backend_id: client}, clock=lambda: now[0])
    await instructions.ensure(REF)
    stored.clear()
    now[0] += 3601
    await instructions.ensure(REF)
    assert [m for m, _, _ in seen] == ["GET", "PUT", "GET", "PUT"]


@pytest.mark.parametrize("status", [404, 413, 500])
async def test_put_failure_never_blocks_the_prompt(status, caplog):
    client, _, seen = native(put_status=status)
    inner = Inner()
    execution = FormattedExecution(inner, ZulipFormatInstructions({REF.backend_id: client}))
    admitted = await execution.submit(REF, {"operation": "prompt"}, "action")
    assert admitted.status == "admitted" and inner.submitted == ["prompt"]
    assert [m for m, _, _ in seen] == ["GET", "PUT"]
    assert "zulip_format_instructions_failed" in caplog.text
    assert GUIDANCE not in caplog.text


async def test_unreachable_native_or_slow_read_never_blocks_the_prompt():
    class Slow:
        def writable(self):
            return True

        async def entries(self, session_id):
            import asyncio

            await asyncio.sleep(10)

        async def put(self, *args):
            raise AssertionError("not reached")

    inner = Inner()
    execution = FormattedExecution(
        inner, ZulipFormatInstructions({REF.backend_id: Slow()}, timeout=0.05)
    )
    await execution.submit(REF, {"operation": "prompt"}, "action")
    assert inner.submitted == ["prompt"]


async def test_unattested_put_and_other_operations_send_nothing():
    client, _, seen = native(attested=False)
    inner = Inner()
    execution = FormattedExecution(inner, ZulipFormatInstructions({REF.backend_id: client}))
    await execution.submit(REF, {"operation": "prompt"}, "action")
    assert inner.submitted == ["prompt"] and not seen
    client, _, seen = native()
    inner = Inner()
    execution = FormattedExecution(inner, ZulipFormatInstructions({REF.backend_id: client}))
    await execution.submit(REF, {"operation": "interrupt"}, "action")
    assert inner.submitted == ["interrupt"] and not seen
    # Everything else is the wrapped client's own.
    assert execution.contract_for(REF) == "c" * 64 and execution.custom() == "delegated"
    assert ZulipFormatInstructions({}).clients == {}
