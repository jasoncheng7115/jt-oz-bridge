from dataclasses import FrozenInstanceError

import pytest

from jt_oz_bridge.domain.control import InteractionSnapshot
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.backend_registry import BackendRegistry, RegisteredBackend
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Grant
from tests.integration.test_dispatch import SyntheticExecution, SyntheticReader, message
from tests.support import REF, SyntheticAudience, service

OTHER = REF.model_copy(
    update={
        "backend_id": "second",
        "backend_identity": "second-installation",
        "upstream_session_id": "second-original",
        "project_id": "second-project",
        "canonical_directory": "/workspace/second",
    }
)


def registration(client, ref):
    return RegisteredBackend(
        ref.backend_identity,
        client.contract_for(ref),
        {ref.project_id: ref.canonical_directory},
        client,
    )


async def registered(db):
    first, second = SyntheticExecution(), SyntheticExecution()
    second.ref = OTHER
    second.contract_hash = "b" * 64
    _bindings, _control, _audience = await service(db, first)
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=OTHER.backend_id,
                identity=OTHER.backend_identity,
                contract_hash=second.contract_hash,
                enabled=True,
                verified=True,
                version="synthetic-second",
            )
        )
        session.add(
            EnrolledProject(
                id=OTHER.project_id,
                backend_id=OTHER.backend_id,
                realm_id="realm",
                canonical_directory=OTHER.canonical_directory,
                enabled=True,
            )
        )
        for user in (7, 8):
            session.add(
                Grant(
                    realm_id="realm",
                    user_id=user,
                    project_id=OTHER.project_id,
                    role="administrator",
                )
            )
    registry = BackendRegistry(
        {REF.backend_id: registration(first, REF), OTHER.backend_id: registration(second, OTHER)}
    )
    bindings = BindingService(db, registry, SyntheticAudience())
    return registry, bindings, first, second


async def test_two_contracts_bind_and_dispatch_to_exact_original_backend(db):
    registry, bindings, first, second = await registered(db)
    a = await bindings.bind("realm", 7, 10, "Original work", REF)
    b = await bindings.bind("realm", 7, 10, "Second work", OTHER)
    reader = SyntheticReader()
    reader.messages[101] = message(revision=0)
    reader.messages[102] = message(message_id=102, revision=0, text="second prompt").model_copy(
        update={"topic": "Second work"}
    )
    one = await QueueService(bindings).receive(a.id, reader.messages[101])
    two = await QueueService(bindings).receive(b.id, reader.messages[102])
    fence = await DurableStore(db).acquire_lease("registry-test")
    worker = Dispatcher(bindings, registry, reader, "registry-test", fence)
    assert await worker.advance(one.action_id) == "admitted"
    assert await worker.advance(two.action_id) == "admitted"
    assert first.submitted[0][0] == REF and second.submitted[0][0] == OTHER
    assert len(first.submitted) == len(second.submitted) == 1
    assert registry.contract_for(REF) == "a" * 64 and registry.contract_for(OTHER) == "b" * 64


@pytest.mark.parametrize(
    "change",
    [
        {"backend_id": "missing"},
        {"backend_identity": "other"},
        {"project_id": "other"},
        {"canonical_directory": "/workspace/second/../project"},
        {"upstream_session_id": ""},
    ],
)
async def test_mismatched_scope_never_reaches_a_backend(db, change):
    registry, _bindings, first, second = await registered(db)
    with pytest.raises(AccessDenied):
        await registry.snapshot(REF.model_copy(update=change))
    assert first.calls == second.calls == []


async def test_backend_contract_replacement_does_not_affect_other_enrollment(db):
    registry, bindings, first, second = await registered(db)
    first.contract_hash = "c" * 64
    with pytest.raises(Conflict, match="contract_changed"):
        await bindings.bind("realm", 7, 10, "Original work", REF)
    bound = await bindings.bind("realm", 7, 10, "Second work", OTHER)
    assert bound.backend_id == OTHER.backend_id and not first.calls


async def test_contract_change_during_snapshot_refuses_result_without_relabeling_it(db):
    registry, _bindings, first, _second = await registered(db)
    original = first.snapshot

    async def changing(ref):
        result = await original(ref)
        first.contract_hash = "c" * 64
        return result

    first.snapshot = changing
    with pytest.raises(Conflict, match="contract_changed"):
        await registry.snapshot(REF)


@pytest.mark.parametrize("mode", ["reference", "child", "duplicate"])
async def test_injected_response_cannot_cross_backend_or_duplicate_lineage(db, mode):
    registry, _bindings, first, _second = await registered(db)
    if mode == "reference":
        original = first.snapshot

        async def wrong_reference(ref):
            return (await original(ref)).model_copy(update={"reference": OTHER})

        first.snapshot = wrong_reference
    elif mode == "child":
        first.descendants = (OTHER,)
    else:
        child = REF.model_copy(update={"upstream_session_id": "child"})
        first.descendants = (child, child)
    with pytest.raises((Conflict, AccessDenied)):
        await registry.snapshot(REF)


async def test_interaction_native_request_and_reference_must_match_selected_backend(db):
    registry, _bindings, first, _second = await registered(db)
    first.requests["request"] = InteractionSnapshot(
        reference=OTHER,
        upstream_request_id="request",
        generation="g",
        kind="permission",
        pending=True,
        description="wrong backend",
    )
    with pytest.raises(Conflict, match="reference_mismatch"):
        await registry.interaction(REF, "request")
    first.requests["request"] = first.requests["request"].model_copy(
        update={"reference": REF, "upstream_request_id": "different"}
    )
    with pytest.raises(Conflict, match="reference_mismatch"):
        await registry.interaction(REF, "request")


async def test_capabilities_are_selected_per_reference_and_defensively_copied(db):
    registry, _bindings, first, second = await registered(db)
    capability = Capability(supported=True, scope="form", reason="synthetic")
    first.capabilities = lambda ref: {"form.cancel": capability}
    second.capabilities = lambda ref: {}
    assert registry.capabilities(REF)["form.cancel"].supported
    assert registry.capabilities(OTHER) == {}
    registry.capabilities(REF)["form.cancel"].supported = False
    assert capability.supported
    with pytest.raises(AccessDenied, match="not_supported"):
        await registry.submit(OTHER, {"operation": "form.cancel"}, "action")
    assert second.submitted == []


async def test_registry_submission_freezes_payload_and_does_not_retry_timeout(db):
    registry, _bindings, first, _second = await registered(db)
    payload = {"operation": "prompt", "text": "exact"}

    async def submit(ref, body, action):
        payload["text"] = "changed outside"
        assert body["text"] == "exact"
        first.submitted.append((ref, body, action))
        raise TimeoutError("synthetic accepted/lost response")

    first.submit = submit
    with pytest.raises(TimeoutError):
        await registry.submit(REF, payload, "action")
    assert len(first.submitted) == 1
    with pytest.raises(AccessDenied, match="reference_mismatch"):
        await registry.submit(
            REF, {"operation": "prompt", "reference": OTHER.model_dump()}, "another"
        )
    assert len(first.submitted) == 1


def test_registry_and_registration_copy_and_freeze_input_mappings():
    client = SyntheticExecution()
    projects = {REF.project_id: REF.canonical_directory}
    entry = RegisteredBackend(REF.backend_identity, "a" * 64, projects, client)
    inputs = {REF.backend_id: entry}
    registry = BackendRegistry(inputs)
    inputs.clear()
    projects.clear()
    assert registry.contract_for(REF) == "a" * 64
    with pytest.raises(TypeError):
        registry.backends["replacement"] = entry
    with pytest.raises(FrozenInstanceError):
        registry.backends = {}


async def test_second_contract_guards_work_for_artifacts_delivery_and_log_capture(db, tmp_path):
    import os

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.services.artifacts import ArtifactService, FileDescriptor
    from jt_oz_bridge.services.delivery import DeliveryWorker
    from jt_oz_bridge.services.log_ingestion import LogCapture
    from jt_oz_bridge.services.outbox import Outbox
    from jt_oz_bridge.storage.artifact_files import LocalArtifactFiles
    from jt_oz_bridge.storage.artifact_models import Artifact
    from tests.contract.test_sse_log import event, frame
    from tests.integration.test_artifacts import chunks
    from tests.integration.test_delivery import SyntheticChat

    registry, bindings, first, _second = await registered(db)
    binding = await bindings.bind("realm", 7, 10, "Second work", OTHER)
    # An unrelated backend changing cannot poison or authorize these scoped guards.
    first.contract_hash = "c" * 64
    files = LocalArtifactFiles(tmp_path / "registry-artifacts")
    store = ArtifactService(
        bindings, files, EnvelopeCipher({"v1": os.urandom(32)}, "v1"), reserve_free_bytes=0
    )
    try:
        identity = await store.create(
            binding.id,
            "realm",
            7,
            FileDescriptor(filename="exact.txt", mime_type="text/plain"),
            chunks(b"exact second backend"),
        )
        assert (await store.read(identity, "realm", 8)).content == b"exact second backend"
        async with db.sessions() as session:
            saved = await session.get(Artifact, identity)
        await store.pin(identity, "realm", 7, saved.version, True)
    finally:
        files.close()
    fence = await DurableStore(db).acquire_lease("registry-io")
    chat = SyntheticChat()
    outbox = Outbox(bindings, chat.bot_user_id)
    delivery = await outbox.queue("registry-second", binding.id, binding.revision, "Second output")
    sender = DeliveryWorker(outbox, chat, "registry-io", fence, minimum_interval=0)
    assert await sender.advance(delivery) == "delivered" and len(chat.calls) == 1
    capture = await LogCapture.open(bindings, binding.id, "registry-io", fence)
    await capture.accept(
        frame(
            event(
                0,
                location={"directory": OTHER.canonical_directory},
                durable={"aggregateID": OTHER.upstream_session_id, "seq": 0, "version": 1},
                data={"sessionID": OTHER.upstream_session_id, "title": "Second"},
            )
        )
    )
    assert capture.read.position == 0


async def test_unknown_mutation_is_not_enabled_by_an_overbroad_client_catalog(db):
    registry, _bindings, first, _second = await registered(db)
    first.capabilities = lambda ref: {
        "unsafe.operation": Capability(supported=True, scope="backend", reason="overbroad test")
    }
    assert registry.capabilities(REF) == {}
    with pytest.raises(AccessDenied, match="not_supported"):
        await registry.submit(REF, {"operation": "unsafe.operation"}, "action")
    assert not first.submitted


async def test_uncertain_prompt_reads_route_to_the_exact_original_backend(db):
    """The live client is this registry; without these two routes the
    readback of an uncertain prompt would silently never run."""
    registry, _bindings, first, second = await registered(db)
    calls = []

    async def readback(reference, action_id, operation_digest, text):
        calls.append(("readback", reference, action_id))
        return "msg_landed"

    async def never_arrived(reference, action_id, operation_digest, sent_after):
        calls.append(("absent", reference, action_id))
        return True

    second.prompt_readback, second.prompt_never_arrived = readback, never_arrived
    assert await registry.prompt_readback(OTHER, "a1", "d" * 64, "t") == "msg_landed"
    assert await registry.prompt_never_arrived(OTHER, "a1", "d" * 64, 0.0) is True
    assert calls == [("readback", OTHER, "a1"), ("absent", OTHER, "a1")]
    with pytest.raises(Conflict):
        await registry.prompt_readback(REF, "a1", "d" * 64, "t")
    assert await registry.prompt_never_arrived(REF, "a1", "d" * 64, 0.0) is False
