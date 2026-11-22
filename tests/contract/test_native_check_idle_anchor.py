"""Synthetic original Native/owner plus installed schemas; no live qualification."""

import copy
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.check_idle_anchor import (
    TAIL_PAGE_SIZE,
    V2AnchoredCheckTailReader,
)
from jt_oz_bridge.adapters.opencode.checks import (
    CHECK_READS,
    CHECK_SEMANTICS,
    CheckExecutionAttestation,
    KnownCheck,
    V2CheckRunner,
    V2CheckTailReader,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.live import VolatileFeedIndex
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, V2LeafResourceProofs
from jt_oz_bridge.adapters.opencode.transport import TransportError
from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
from jt_oz_bridge.domain.check_idle_anchor import CheckIdleAnchor
from jt_oz_bridge.domain.checks import ApprovedCheck, CheckCatalog, check_message_id
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.storage.durable import Conflict, digest
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_leaf_resources import setup as leaf_setup
from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, frame, text_delta

CHECK = ApprovedCheck(id="unit", title="Approved synthetic check", command="python -m pytest tests")


async def setup(*, pristine=False):
    proofs, transport, data, calls = await leaf_setup()
    if pristine:
        data["session.get"]["data"].pop("outcome")
        data["session.get"]["data"]["time"].pop("idle")
        data["session.message.list"]["data"] = []
    history = copy.deepcopy(data["session.message.list"]["data"])
    shells, records, known_values, requests = {}, {}, {}, []
    qualification = CheckExecutionAttestation(
        CheckCatalog(reference=REF, contract_sha256=PROFILE.sha256, checks=(CHECK,)),
        CHECK_SEMANTICS,
        "a" * 64,
    )
    transport.attestation = replace(
        transport.attestation,
        verified_operations=transport.attestation.verified_operations
        | CHECK_READS
        | {"session.shell"},
    )
    delegate = transport.client._transport

    def handler(request):
        requests.append(request)
        assert request.method == "GET"  # Fixtures never submit a Native mutation.
        path = request.url.path
        prefix = "/api/session/" + REF.upstream_session_id
        if path == prefix + "/message":
            parameters = dict(request.url.params)
            assert "type" not in parameters
            if "cursor" in parameters:
                assert "order" not in parameters
                offset = int(parameters["cursor"].removeprefix("opaque-native-next-"))
            else:
                assert parameters.get("order") == "desc"
                offset = 0
            limit = int(parameters["limit"])
            rows = copy.deepcopy(history[offset : offset + limit])
            end = offset + len(rows)
            return httpx.Response(
                200,
                json={
                    "data": rows,
                    "cursor": {"next": "opaque-native-next-" + str(end)}
                    if end < len(history)
                    else {},
                },
            )
        if path.startswith(prefix + "/message/"):
            identity = path.rsplit("/", 1)[-1]
            row = next((r for r in history if r["id"] == identity), None)
            if row is None:
                return httpx.Response(
                    404,
                    json={
                        "_tag": "MessageNotFoundError",
                        "sessionID": REF.upstream_session_id,
                        "messageID": identity,
                        "message": "Synthetic missing retained message",
                    },
                )
            return httpx.Response(200, json={"data": copy.deepcopy(row)})
        if path.startswith("/api/shell/"):
            identity = path.rsplit("/", 1)[-1]
            if identity not in shells:
                return httpx.Response(
                    404,
                    json={
                        "_tag": "ShellNotFoundError",
                        "id": identity,
                        "message": "Synthetic evicted shell",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "location": {"directory": REF.canonical_directory},
                    "data": copy.deepcopy(shells[identity]),
                },
            )
        if path == "/api/location":
            return httpx.Response(
                200,
                json={
                    "directory": REF.canonical_directory,
                    "project": {
                        "id": "global",
                        "directory": REF.canonical_directory,
                        "canonical": REF.canonical_directory,
                    },
                },
            )
        return delegate.handler(request)

    transport.client._transport = httpx.MockTransport(handler)

    async def known(ref, message_id):
        assert ref == REF
        if message_id not in known_values:
            raise Conflict("synthetic original owned Action missing")
        return known_values[message_id]

    async def original(action_id, operation_digest, ref, qualifier):
        value = records.get(action_id)
        if value is None or (
            value.operation_digest,
            value.reference,
            value.qualification_sha256,
        ) != (operation_digest, ref, qualifier):
            raise Conflict("synthetic original journal missing")
        return value

    def attach(provider):
        client = V2ExecutionClient(transport, provider.projects, proofs=provider)
        reader = V2CheckRunner(client, {REF: qualification})
        client.checks = reader
        provider.check_tail = V2AnchoredCheckTailReader(
            transport,
            qualification,
            known,
            model_settings=provider.model_settings,
            proofs=provider,
            reader=reader,
            original=original,
        )
        return client

    client = attach(proofs)
    result = SimpleNamespace(
        proofs=proofs,
        transport=transport,
        data=data,
        history=history,
        shells=shells,
        records=records,
        known=known_values,
        requests=requests,
        qualification=qualification,
        client=client,
        attach=attach,
        original=original,
    )
    return result


async def complete(f, number, *, output="passed", legacy=False):
    p = f.proofs
    await p.watch(REF, require_idle=True)
    proof = await p.prove(REF, INSTALLED_SCHEMA, digest(f.data["session.get"]["data"]))
    identity = "synthetic-check-" + str(number)
    message_id = check_message_id(identity)
    op = digest({"synthetic_action": identity})
    record = CheckDispatchPreflight(
        action_id=identity,
        operation_digest=op,
        reference=REF,
        binding_id="synthetic-binding",
        binding_revision=1,
        contract_sha256=INSTALLED_SCHEMA,
        qualification_sha256=f.qualification.enrollment_sha256,
        message_id=message_id,
        owner_epoch=p.dispatch_owner_epoch(REF, proof),
        connection_epoch=proof.connection_epoch,
        ownership_evidence_sha256=proof.ownership_evidence_sha256,
        issued_at=proof.issued_at,
        expires_at=proof.expires_at,
        idle_anchor=None if legacy else p.dispatch_idle_anchor(REF, proof),
    )
    f.records[identity] = record
    f.known[message_id] = KnownCheck(identity, op, CHECK, f.qualification.enrollment_sha256)
    clock = number * 10 + 10
    shell_id = "sh_synthetic_" + str(number)
    shell = {
        "id": shell_id,
        "status": "exited",
        "exit": 0,
        "command": CHECK.command,
        "cwd": REF.canonical_directory,
        "shell": "/bin/bash",
        "file": "/private/not-read",
        "metadata": {"sessionID": REF.upstream_session_id, "background": True},
        "time": {"started": clock, "completed": clock + 2},
    }
    f.shells[shell_id] = shell
    # Model the retained installed cap of25 exited processes. Native message
    # projections remain; evicted shell output is not invented or queried.
    if len(f.shells) > 25:
        del f.shells[next(iter(f.shells))]
    row = {
        "id": message_id,
        "type": "shell",
        "command": CHECK.command,
        "shellID": shell_id,
        "status": "exited",
        "exit": 0,
        "time": {"created": clock + 1, "completed": clock + 3},
        "output": {
            "output": output,
            "cursor": len(output),
            "size": len(output),
            "truncated": False,
        },
    }
    notice = {
        "id": "msg_synthetic_notice_" + str(number),
        "type": "synthetic",
        "text": "No Agent prose trusted",
        "metadata": {"source": "shell", "shellID": shell_id, "state": "completed", "exit": 0},
        "time": {"created": clock + 4},
    }
    f.history[:0] = [notice, row]
    f.data["session.get"]["data"]["time"]["updated"] = clock + 4
    return record


async def test_many_owned_terminal_checks_recover_after_restart_from_real_saved_positive_idle():
    f = await setup()
    try:
        for n in range(1, 29):
            await complete(f, n)
        assert len(f.history) == 57 and len(f.shells) == 25
        original_reader = V2CheckTailReader(
            f.transport, f.qualification, f.proofs.check_tail.known, model_settings=None
        )
        with pytest.raises(ContractError, match="positive_idle_not_found|shell_pair_missing"):
            await original_reader.read(REF, f.data["session.get"]["data"], f.history[0])
        # A Bridge restart replaces its volatile feed; original Native owner,
        # original session and immutable preflights remain unchanged.
        previous_epoch = f.proofs.generation(REF)
        f.proofs.revoke_watch(REF)
        # Reconstruct every immutable DTO from persisted JSON, rather than
        # borrowing the old process's witness/anchor object identities.
        stored = json.loads(
            json.dumps({k: v.model_dump(mode="json") for k, v in f.records.items()})
        )
        f.records.clear()
        f.records.update({k: CheckDispatchPreflight.model_validate(v) for k, v in stored.items()})
        replacement = VolatileFeedIndex(PROFILE, (REF,), OWNER)
        replacement.accept(frame({**CONNECTED, "id": "evt_synthetic_bridge_restart"}))
        f.proofs.feed.index = replacement
        recovered = V2LeafResourceProofs(f.proofs.feed, f.proofs.projects)
        f.proofs = recovered
        f.client = f.attach(recovered)
        assert recovered.generation(REF) != previous_epoch
        assert not recovered._watched
        f.requests.clear()
        witness = await recovered.watch(REF, require_idle=True)
        assert witness.state == ExecutionState.IDLE
        # Only the latest check and sealed head are visited, not57 records or
        # the evicted older shell captures. Actual Native Idle is read by id.
        lists = [r for r in f.requests if r.url.path.endswith("/message")]
        assert lists and max(int(r.url.params["limit"]) for r in lists) == TAIL_PAGE_SIZE
        assert any(r.url.path.endswith("/message/msg_idle") for r in f.requests)
        assert all(r.method == "GET" for r in f.requests)
        assert {r.url.path for r in f.requests if r.url.path.startswith("/api/shell/")} == {
            "/api/shell/sh_synthetic_28"
        }
    finally:
        await finish(f.proofs, f.transport)


async def test_legacy_preflight_without_anchor_still_requires_native_positive_boundary():
    f = await setup()
    try:
        record = await complete(f, 1, legacy=True)
        assert record.idle_anchor is None
        assert (await f.proofs.watch(REF)).state == ExecutionState.IDLE
        # State="idle" in a journal is never enough after the actual Native
        # Idle disappears from the bounded history.
        f.history[:] = f.history[:2]
        with pytest.raises(ContractError, match="positive_idle_not_found"):
            await f.proofs.watch(REF)
        assert not f.proofs._watched
    finally:
        await finish(f.proofs, f.transport)


@pytest.mark.parametrize("controls", [48, 49])
async def test_legacy_tail_reuses_one_small_page_51_record_budget(controls):
    f = await setup()
    try:
        qualify_model_controls(f)
        await complete(f, 1, legacy=True)
        append_controls(f, controls)
        f.requests.clear()
        reader = f.proofs.check_tail
        if controls == 48:
            result = await reader.read(REF, f.data["session.get"]["data"], f.history[0])
            assert result["idle"]["id"] == "msg_idle" and not result["pristine"]
            assert result["preflight_anchor_sha256"] is None
        else:
            with pytest.raises(ContractError, match="record_capacity"):
                await reader.read(REF, f.data["session.get"]["data"], f.history[0])
        pages = [r for r in f.requests if r.url.path.endswith("/message")]
        assert pages and max(int(r.url.params["limit"]) for r in pages) == TAIL_PAGE_SIZE
        assert sum(int(r.url.params["limit"]) for r in pages) == 51
        assert sum("cursor" not in r.url.params for r in pages) == 1
        assert all(r.method == "GET" for r in f.requests)
    finally:
        await finish(f.proofs, f.transport)


async def test_legacy_tail_cannot_borrow_an_older_journals_anchor_to_skip_real_idle():
    f = await setup()
    try:
        qualify_model_controls(f)
        await complete(f, 1)
        await complete(f, 2, legacy=True)
        append_controls(f, 48)
        f.requests.clear()
        with pytest.raises(ContractError, match="record_capacity"):
            await f.proofs.check_tail.read(REF, f.data["session.get"]["data"], f.history[0])
        pages = [r for r in f.requests if r.url.path.endswith("/message")]
        assert sum(int(r.url.params["limit"]) for r in pages) == 51
        assert not any(r.url.path.endswith("/message/msg_idle") for r in f.requests)
    finally:
        await finish(f.proofs, f.transport)


async def test_legacy_pristine_tail_uses_same_exhausted_iterator_without_invented_idle():
    f = await setup(pristine=True)
    try:
        await complete(f, 1, legacy=True)
        f.requests.clear()
        result = await f.proofs.check_tail.read(REF, f.data["session.get"]["data"], f.history[0])
        assert result["pristine"] and result["idle"] is None
        pages = [r for r in f.requests if r.url.path.endswith("/message")]
        assert len(pages) == 1 and int(pages[0].url.params["limit"]) == 2
    finally:
        await finish(f.proofs, f.transport)


async def test_pristine_anchor_requires_unfiltered_end_of_original_history():
    f = await setup(pristine=True)
    try:
        record = await complete(f, 1)
        assert record.idle_anchor.pristine and record.idle_anchor.head is None
        assert (await f.proofs.watch(REF)).state == ExecutionState.IDLE
        f.history.append(
            {
                "id": "msg_unowned",
                "type": "synthetic",
                "text": "not an Idle",
                "time": {"created": 1},
            }
        )
        with pytest.raises(ContractError):
            await f.proofs.watch(REF)
        assert not f.proofs._watched
    finally:
        await finish(f.proofs, f.transport)


@pytest.mark.parametrize(
    "fault",
    [
        "head",
        "idle",
        "owner",
        "native-owner",
        "qualification",
        "shell",
        "missing-shell",
        "unknown-prefix",
        "running",
        "notice",
        "feed",
        "metadata",
        "expired-window",
    ],
)
async def test_anchor_never_hides_changed_owner_boundary_or_original_terminal_pair(
    fault, monkeypatch
):
    f = await setup()
    try:
        record = await complete(f, 1)
        if fault == "idle":
            record = await complete(f, 2)
        delegate = f.transport.client._transport
        changed = False
        original_time = time.time()

        def drifting(request):
            nonlocal changed
            response = delegate.handler(request)
            if (
                fault in {"feed", "metadata", "expired-window"}
                and request.url.path.startswith("/api/shell/")
                and not changed
            ):
                changed = True
                if fault == "feed":
                    f.proofs.feed.index.accept(frame(text_delta("evt_anchor_drift")))
                elif fault == "metadata":
                    f.data["session.get"]["data"]["title"] = "Changed metadata"
                else:
                    monkeypatch.setattr(time, "time", lambda: original_time + 10)
            return response

        f.transport.client._transport = httpx.MockTransport(drifting)
        if fault == "head":
            f.history[-1]["metadata"] = {"changed": True}
        elif fault == "idle":
            f.history[-1]["outcome"] = "failed"
        elif fault == "owner":
            f.records[record.action_id] = record.model_copy(update={"owner_epoch": "b" * 64})
        elif fault == "native-owner":
            replacement = VolatileFeedIndex(PROFILE, (REF,), "b" * 64)
            replacement.accept(frame({**CONNECTED, "id": "evt_synthetic_native_restart"}))
            f.proofs.feed.index = replacement
            f.proofs.feed.owner.read.return_value = SimpleNamespace(
                owner_epoch="b" * 64, model_dump=lambda **kwargs: {"fixture_owner": "b" * 64}
            )
        elif fault == "qualification":
            f.records[record.action_id] = record.model_copy(
                update={"qualification_sha256": "b" * 64}
            )
        elif fault == "shell":
            f.shells["sh_synthetic_1"]["command"] = "echo forged pass"
        elif fault == "missing-shell":
            f.shells.clear()
        elif fault == "unknown-prefix":
            f.history.insert(
                0,
                {
                    "id": "msg_unowned",
                    "type": "synthetic",
                    "text": "passed",
                    "time": {"created": 24},
                },
            )
        elif fault == "running":
            f.history[1]["status"] = f.shells["sh_synthetic_1"]["status"] = "running"
            f.history[1].pop("exit")
            f.history[1]["time"].pop("completed")
        elif fault == "notice":
            f.history[0]["metadata"]["shellID"] = "sh_foreign"
        with pytest.raises((ContractError, Conflict, TransportError)):
            await f.proofs.watch(REF)
        assert not f.proofs._watched
    finally:
        await finish(f.proofs, f.transport)


async def test_preflight_old_without_anchor_is_not_silently_augmented_or_requalified():
    f = await setup()
    try:
        preflight = await complete(f, 1, legacy=True)
        raw = preflight.model_dump(mode="json")
        raw.pop("idle_anchor")
        historical = CheckDispatchPreflight.model_validate(raw)
        assert historical.idle_anchor is None
        assert historical.owner_epoch == preflight.owner_epoch
        assert historical.issued_at == preflight.issued_at
        wrong = preflight.model_dump(mode="python")
        wrong["idle_anchor"] = {
            "reference": REF.model_copy(update={"upstream_session_id": "ses_foreign"}).model_dump(),
            "head": None,
            "idle": None,
            "pristine": True,
        }
        with pytest.raises(ValidationError, match="idle_anchor_scope"):
            CheckDispatchPreflight.model_validate(wrong)
        with pytest.raises(ValidationError):
            CheckIdleAnchor(reference=REF, head=None, idle=None, pristine=False)
    finally:
        await finish(f.proofs, f.transport)


def qualify_model_controls(f):
    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )

    qualification = ModelSettingsAttestation(
        REF, INSTALLED_SCHEMA, MODEL_SETTING_SEMANTICS, "c" * 64
    )
    f.proofs.model_settings = qualification
    f.proofs.check_tail.model_settings = qualification


def append_controls(f, count):
    previous = f.data["session.get"]["data"].get("model")
    for n in range(1, count + 1):
        target = {"providerID": "synthetic-provider", "id": "synthetic-model-" + str(n)}
        row = {
            "id": "msg_synthetic_model_" + str(n),
            "type": "model-switched",
            "model": target,
            "time": {"created": 1000 + n},
        }
        if previous is not None:
            row["previous"] = previous
        f.history.insert(0, row)
        previous = target
    f.data["session.get"]["data"]["model"] = previous
    f.data["session.get"]["data"]["time"]["updated"] = 1000 + count


@pytest.mark.parametrize("controls", [48, 49])
async def test_anchor_keeps_original_51_record_guard_and_unfiltered_cursor_continuity(controls):
    f = await setup()
    try:
        qualify_model_controls(f)
        await complete(f, 1)
        append_controls(f, controls)
        if controls == 48:
            assert (await f.proofs.watch(REF)).state == ExecutionState.IDLE
        else:
            with pytest.raises(ContractError, match="record_capacity"):
                await f.proofs.watch(REF)
            assert not f.proofs._watched
    finally:
        await finish(f.proofs, f.transport)


async def test_pristine_model_control_anchor_is_a_verified_boundary_not_an_invented_idle():
    f = await setup(pristine=True)
    try:
        qualify_model_controls(f)
        append_controls(f, 1)
        record = await complete(f, 101)
        assert record.idle_anchor.pristine
        assert record.idle_anchor.idle is None
        assert record.idle_anchor.head.type == "model-switched"
        # complete uses clock1020, newer than the original model control1001.
        assert (await f.proofs.watch(REF)).state == ExecutionState.IDLE
    finally:
        await finish(f.proofs, f.transport)


@pytest.mark.parametrize("legacy", [False, True])
async def test_large_terminal_preview_uses_bounded_pages_and_exact_original_shell_pair(legacy):
    f = await setup()
    try:
        await complete(f, 1, output="x" * 1048576, legacy=legacy)
        assert (await f.proofs.watch(REF)).state == ExecutionState.IDLE
        lists = [r for r in f.requests if r.url.path.endswith("/message")]
        assert max(int(r.url.params["limit"]) for r in lists) == TAIL_PAGE_SIZE
    finally:
        await finish(f.proofs, f.transport)


@pytest.mark.parametrize(
    "fault", ["cursor-cycle", "duplicate", "unknown-control", "missing-positive-idle"]
)
async def test_anchored_cursor_or_persisted_head_cannot_hide_unobserved_history(fault):
    f = await setup()
    try:
        if fault == "cursor-cycle":
            qualify_model_controls(f)
        await complete(f, 1)
        if fault == "cursor-cycle":
            append_controls(f, 3)
        if fault == "missing-positive-idle":
            await complete(f, 2)
            f.history[:] = [r for r in f.history if r["id"] != "msg_idle"]
        if fault == "unknown-control":
            f.history.insert(
                2,
                {
                    "id": "msg_unknown_before_head",
                    "type": "synthetic",
                    "text": "not approved",
                    "time": {"created": 4},
                },
            )
        delegate = f.transport.client._transport

        def tampered(request):
            response = delegate.handler(request)
            if request.url.path.endswith("/message") and request.url.params.get("limit") == "2":
                data = response.json()
                if fault == "duplicate" and "cursor" in request.url.params:
                    data["data"][0] = copy.deepcopy(f.history[0])
                if fault == "cursor-cycle":
                    data["cursor"] = {"next": "opaque-native-next-2"}
                return httpx.Response(200, json=data)
            return response

        f.transport.client._transport = httpx.MockTransport(tampered)
        with pytest.raises((ContractError, Conflict, TransportError)) as caught:
            await f.proofs.watch(REF)
        if fault == "cursor-cycle":
            assert "cursor_changed" in str(caught.value)
        assert not f.proofs._watched
    finally:
        await finish(f.proofs, f.transport)
