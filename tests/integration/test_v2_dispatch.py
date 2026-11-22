"""Real SQL dispatcher + V2 HTTP mock; injected owner proof is synthetic only."""

from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.execution_receipts import read_receipt
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject, PendingInteraction
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Grant
from tests.contract.test_v2_execution import REF, SCOPE, setup
from tests.integration.test_dispatch import SyntheticReader, message
from tests.support import SyntheticAudience


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


async def worker(db, profile, change=None):
    client, transport, proof, data, seen = setup(profile, change=change)
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=SCOPE.backend_id,
                identity=SCOPE.backend_identity,
                contract_hash=profile.sha256,
                version="synthetic-fixture",
                enabled=True,
                verified=True,
            )
        )
        session.add(
            EnrolledProject(
                id=SCOPE.project_id,
                backend_id=SCOPE.backend_id,
                realm_id="realm",
                canonical_directory=SCOPE.canonical_directory,
                enabled=True,
            )
        )
        for user in (7, 8):
            for role in ("operator", "approver", "administrator"):
                session.add(
                    Grant(realm_id="realm", user_id=user, project_id=SCOPE.project_id, role=role)
                )
    bindings = BindingService(db, client, SyntheticAudience())
    binding = await bindings.bind("realm", 7, 10, "Original work", REF)
    reader = SyntheticReader()
    fencing = await DurableStore(db).acquire_lease("fixture-v2-dispatch", ttl=30)
    assert fencing
    return (
        Dispatcher(bindings, client, reader, "fixture-v2-dispatch", fencing),
        binding,
        transport,
        proof,
        data,
        seen,
        reader,
    )


@pytest.mark.parametrize("mode", ["success", "timeout", "malformed"])
async def test_v2_prompt_one_attempt_transitions_and_encrypted_receipt_survive_recovery(
    db, profile, mode
):
    def altered(request, data, proof):
        if request.method == "POST":
            if mode == "timeout":
                raise httpx.ReadTimeout("fixture lost acknowledgement", request=request)
            if mode == "malformed":
                return httpx.Response(200, json={"unknown": "PRIVATE_BAD_ACK"})
        return None

    dispatcher, binding, transport, proof, data, seen, reader = await worker(db, profile, altered)
    try:
        source = message(text="Continue original native work", revision=0)
        reader.messages[source.message_id] = source
        queued = await dispatcher.queue.receive(binding.id, source)
        result = "admitted" if mode == "success" else "ambiguous"
        assert await dispatcher.advance(queued.action_id) == result
        assert await dispatcher.advance(queued.action_id) == result
        receipt = await read_receipt(dispatcher.bindings, queued.action_id, "realm", 7)
        if mode == "success":
            assert receipt.reference == REF and receipt.contract_sha256 == profile.sha256
            assert (
                receipt.admission.upstream_id == "msg_original"
                and receipt.admission.status == "admitted"
            )
            assert receipt.admission.details["turn_completed"] is False
        else:
            assert receipt is None
            await DurableStore(db).recover()
            assert (await dispatcher.load(queued.action_id)).state == "ambiguous"
        assert len([request for request in seen if request.method == "POST"]) == 1
    finally:
        await transport.close()


async def test_native_permission_reply_requires_real_fresh_human_source_and_resolves_only_on_204(
    db, profile
):
    dispatcher, binding, transport, proof, data, seen, reader = await worker(db, profile)
    proof.kind = "permission"
    try:
        snapshot = await dispatcher.client.interaction(REF, "per_original")
        interactions = InteractionService(dispatcher.bindings)
        identity = await interactions.observe(binding, snapshot)
        token = await interactions.issue(identity, "realm", 7)
        source = message(text="!oz approve " + token + " once", revision=0)
        reader.messages[source.message_id] = source
        action = await interactions.reply(token, "realm", 7, decision="once", source=source)
        assert await dispatcher.advance(action) == "completed"
        receipt = await read_receipt(dispatcher.bindings, action, "realm", 7)
        assert (
            receipt.admission.upstream_id == "per_original"
            and receipt.admission.details["request_settled"] is True
        )
        async with db.sessions() as session:
            assert (await session.get(PendingInteraction, identity)).state == "resolved"
        assert len([request for request in seen if request.method == "POST"]) == 1
    finally:
        await transport.close()


async def test_false_interrupt_ack_does_not_complete_the_original_admitted_prompt(db, profile):
    dispatcher, binding, transport, proof, data, seen, reader = await worker(db, profile)
    try:
        source = message(text="Original prompt", revision=0)
        reader.messages[source.message_id] = source
        queued = await dispatcher.queue.receive(binding.id, source)
        assert await dispatcher.advance(queued.action_id) == "admitted"
        proof.state = ExecutionState.RUNNING
        stop_source = message(message_id=102, text="!oz stop", revision=0)
        reader.messages[stop_source.message_id] = stop_source
        stop = await dispatcher.queue.stop(
            binding.id, "realm", 7, "native-stop", source=stop_source
        )
        assert await dispatcher.advance(stop) == "completed"
        receipt = await read_receipt(dispatcher.bindings, stop, "realm", 7)
        assert receipt.admission.details["interrupted"] is False
        assert receipt.admission.details["children_verified_stopped"] is False
        assert (await dispatcher.load(queued.action_id)).state == "admitted"
        assert len([request for request in seen if request.url.path.endswith("/interrupt")]) == 1
    finally:
        await transport.close()
