"""Synthetic original-owner/new-Root RPC checks, not a live create qualification."""

import copy
import json
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEvidence
from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.session_creation import (
    NativePermissionRule,
    RootCreationTemplate,
    SessionCreationIntent,
)
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_host_owner import evidence
from tests.contract.test_v2_catalog import SCOPE, native


def stamp(**changes):
    value = evidence(
        backend_id=SCOPE.backend_id, backend_identity=SCOPE.backend_identity, **changes
    )
    value["observed_at"] = time.time()
    return HostOwnerEvidence.model_validate(value)


def setup(mode="success", title="Original new project"):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )
    template = RootCreationTemplate(
        scope=SCOPE,
        native_project_id="native-project-id",
        agent_id="build",
        permissions=(NativePermissionRule(action="*", resource="*", effect="ask"),),
    )
    current_owner = stamp()
    intent = SessionCreationIntent(
        intent_id="a" * 32,
        scope=SCOPE,
        native_session_id="ses_jtoz_" + "b" * 32,
        source_sha256="c" * 64,
        owner_epoch=current_owner.owner_epoch,
        title=title,
    )
    calls = []
    rows = {}

    async def owner_read():
        return current_owner.model_copy(update={"observed_at": time.time()})

    def handler(request):
        nonlocal current_owner
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            assert request.url.path == "/api/session" and not request.url.query
            body = json.loads(request.content)
            assert set(body) == {"id", "location", "agent", "permissions", "metadata"} | (
                {"title"} if title is not None else set()
            )
            assert "parentID" not in body and "model" not in body
            rows[body["id"]] = native(
                id=body["id"],
                location=body["location"],
                agent=body["agent"],
                permissions=body["permissions"],
                metadata=body["metadata"],
            )
            if title is not None:
                rows[body["id"]]["title"] = title
            else:
                rows[body["id"]].pop("title")
            if mode == "lost-ack":
                raise httpx.ReadTimeout("synthetic lost ACK", request=request)
            if mode == "owner-after-send":
                current_owner = stamp(pid=124)
            if mode == "attestation-after-send":
                transport.attestation = replace(transport.attestation)
            raw = copy.deepcopy(rows[body["id"]])
            if mode == "foreign-ack":
                raw["projectID"] = "foreign"
            return httpx.Response(200, json={"data": raw})
        assert (
            request.method == "GET"
            and request.url.path == "/api/session/" + intent.native_session_id
        )
        raw = copy.deepcopy(rows[intent.native_session_id])
        if mode == "changed-readback":
            raw["permissions"] = []
        return httpx.Response(200, json={"data": raw})

    async def identity():
        return True

    transport = V2HTTPTransport(
        "https://native.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256,
            SCOPE.backend_identity,
            "2.0.32",
            frozenset({"session.create", "session.get"}),
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handler),
    )
    client = V2SessionCreation(
        transport, SimpleNamespace(read=owner_read), {SCOPE.project_id: template}
    )
    return client, transport, intent, rows, calls


@pytest.mark.parametrize("title", [None, "原生專案 · literal @**all** title"])
async def test_single_explicit_root_creation_uses_exact_project_template_and_readback(title):
    client, transport, intent, rows, calls = setup(title=title)
    guarded = []

    def guard():
        guarded.append((digest(intent.model_dump(mode="json")), tuple(calls)))
        assert not rows

    try:
        candidate = await client.create(intent, before_send=guard)
        assert calls == [
            ("POST", "/api/session"),
            ("GET", "/api/session/" + intent.native_session_id),
        ]
        # Preflight and Auth-after Mock boundary both check the same intent
        # before the one POST. Mock has no pool/connect/wire qualification.
        original_intent = digest(intent.model_dump(mode="json"))
        assert guarded == [(original_intent, ()), (original_intent, ())]
        assert await client.current(intent, candidate)
        assert not await client.current(intent, candidate.model_copy())
        assert candidate.reference.canonical_directory == SCOPE.canonical_directory
        assert candidate.reference.upstream_session_id == intent.native_session_id
        assert candidate.session_info_sha256 == digest(rows[intent.native_session_id])
        assert candidate.native_created_at == rows[intent.native_session_id]["time"]["created"]
        assert not candidate.starts_execution and not candidate.registered_for_execution
        with pytest.raises(ValidationError):
            type(candidate).model_validate(
                {**candidate.model_dump(), "registered_for_execution": True}
            )
    finally:
        await transport.close()


async def test_used_root_recovery_keeps_original_id_and_origin_without_relaxing_pristine_readback():
    client, transport, intent, rows, calls = setup()
    try:
        receipt = await client.create(intent, before_send=lambda: None)
        raw = rows[intent.native_session_id]
        raw.update(title="Renamed after work", cost=1.5, outcome="succeeded")
        raw["tokens"]["input"] = 50
        raw["time"].update(updated=10, idle=10)
        assert not await client.current(intent, receipt)
        with pytest.raises(ContractError):
            await client.observe(intent)
        post_count = sum(method == "POST" for method, _ in calls)
        observation = await client.observe_existing(intent, receipt.model_copy())
        assert observation.native_created_at == receipt.native_created_at
        assert observation.reference == receipt.reference
        assert await client.existing_current(intent, receipt, observation)
        assert not await client.existing_current(intent, receipt, observation.model_copy())
        assert sum(method == "POST" for method, _ in calls) == post_count == 1
        assert "Renamed" not in observation.model_dump_json()
    finally:
        await transport.close()


async def test_lost_ack_recovery_checks_owned_origin_without_issuing_pristine_candidate():
    client, transport, intent, rows, calls = setup(mode="lost-ack")
    try:
        with pytest.raises(TransportError, match="upstream_transport_or_encoding_error"):
            await client.create(intent, before_send=lambda: None)
        raw = rows[intent.native_session_id]
        raw.update(title="Original Root subsequently renamed", cost=2.5)
        raw["tokens"]["input"] = 100
        raw["time"].update(updated=10, idle=10)
        with pytest.raises(ContractError):
            await client.observe(intent)
        start = len(calls)
        receipt, observation = await client.recover(intent)
        assert receipt.native_created_at == raw["time"]["created"]
        assert receipt.reference.upstream_session_id == intent.native_session_id
        assert receipt.session_info_sha256 == digest(raw)
        assert observation.creation_receipt_sha256 == digest(receipt.model_dump(mode="json"))
        assert await client.existing_current(intent, receipt, observation)
        assert not await client.current(intent, receipt)
        assert not await client.existing_current(intent, receipt, observation.model_copy())
        assert all(method == "GET" for method, _ in calls[start:])
        assert sum(method == "POST" for method, _ in calls) == 1 and not client._candidates
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault",
    [
        "id",
        "project",
        "directory",
        "agent",
        "permissions",
        "metadata",
        "parent",
        "fork",
        "archived",
        "created-between-reads",
        "owner-between-reads",
        "attestation-between-reads",
    ],
)
async def test_unobserved_used_root_recovery_rejects_foreign_or_changing_origin(fault):
    client, transport, intent, rows, calls = setup(mode="lost-ack")
    try:
        with pytest.raises(TransportError, match="upstream_transport_or_encoding_error"):
            await client.create(intent, before_send=lambda: None)
        raw = rows[intent.native_session_id]
        raw.update(title="Used before first receipt", cost=1.0)
        if fault == "id":
            raw["id"] = "ses_foreign"
        elif fault == "project":
            raw["projectID"] = "foreign"
        elif fault == "directory":
            raw["location"] = {"directory": "/foreign"}
        elif fault == "agent":
            raw["agent"] = "other"
        elif fault == "permissions":
            raw["permissions"] = []
        elif fault == "metadata":
            raw["metadata"] = {}
        elif fault == "parent":
            raw["parentID"] = "ses_foreign"
        elif fault == "fork":
            raw["fork"] = {"sessionID": "ses_foreign"}
        elif fault == "archived":
            raw["time"]["archived"] = 10
        else:
            original = transport.client._transport
            seen = 0
            owner_read = client.owner.read

            def changed(request):
                nonlocal seen
                response = original.handler(request)
                seen += 1
                if seen == 1:
                    if fault == "created-between-reads":
                        raw["time"]["created"] += 1
                    elif fault == "attestation-between-reads":
                        transport.attestation = replace(transport.attestation)
                    else:

                        async def foreign_owner():
                            return (await owner_read()).model_copy(update={"owner_epoch": "f" * 64})

                        client.owner.read = foreign_owner
                return response

            transport.client._transport = httpx.MockTransport(changed)
        start = len(calls)
        with pytest.raises(ValueError):
            await client.recover(intent)
        assert all(method == "GET" for method, _ in calls[start:])
        assert not client._existing and not client._candidates
        assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()


async def test_unobserved_recovery_tolerates_usage_progress_but_fences_live_origin():
    client, transport, intent, rows, calls = setup(mode="lost-ack")
    try:
        with pytest.raises(TransportError, match="upstream_transport_or_encoding_error"):
            await client.create(intent, before_send=lambda: None)
        original = transport.client._transport

        def progressing(request):
            response = original.handler(request)
            raw = rows[intent.native_session_id]
            raw["title"] = "Changed during work"
            raw["cost"] += 1.0
            raw["tokens"]["input"] += 10
            return response

        transport.client._transport = httpx.MockTransport(progressing)
        receipt, observation = await client.recover(intent)
        assert await client.existing_current(intent, receipt, observation)
        assert not await client.current(intent, receipt)
        rows[intent.native_session_id]["agent"] = "changed"
        assert not await client.existing_current(intent, receipt, observation)
        assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault",
    [
        "id",
        "project",
        "directory",
        "agent",
        "permissions",
        "metadata",
        "created",
        "parent",
        "fork",
        "archived",
        "receipt-ref",
        "receipt-intent",
        "receipt-owner",
        "receipt-created",
        "receipt-bool-created",
        "legacy-receipt",
    ],
)
async def test_used_root_requires_exact_owned_creation_identity_and_rejects_legacy_receipts(fault):
    client, transport, intent, rows, calls = setup()
    try:
        receipt = await client.create(intent, before_send=lambda: None)
        raw = rows[intent.native_session_id]
        if fault == "id":
            raw["id"] = "ses_foreign"
        elif fault == "project":
            raw["projectID"] = "foreign"
        elif fault == "directory":
            raw["location"] = {"directory": "/foreign"}
        elif fault == "agent":
            raw["agent"] = "other"
        elif fault == "permissions":
            raw["permissions"] = []
        elif fault == "metadata":
            raw["metadata"] = {}
        elif fault == "created":
            raw["time"]["created"] += 1
        elif fault == "parent":
            raw["parentID"] = "ses_other"
        elif fault == "fork":
            raw["fork"] = {"sessionID": "ses_other"}
        elif fault == "archived":
            raw["time"]["archived"] = 5
        elif fault == "receipt-ref":
            receipt = receipt.model_copy(
                update={
                    "reference": receipt.reference.model_copy(
                        update={"canonical_directory": "/foreign"}
                    )
                }
            )
        elif fault == "receipt-intent":
            receipt = receipt.model_copy(update={"intent_sha256": "f" * 64})
        elif fault == "receipt-owner":
            receipt = receipt.model_copy(update={"owner_epoch": "f" * 64})
        elif fault in {"receipt-created", "receipt-bool-created"}:
            receipt = receipt.model_copy(
                update={"native_created_at": 2 if fault == "receipt-created" else True}
            )
        else:
            receipt = type(receipt).model_construct(
                **receipt.model_dump(exclude={"native_created_at", "reference"}),
                reference=receipt.reference,
            )
        with pytest.raises((ValueError, KeyError)):
            await client.observe_existing(intent, receipt)
        assert sum(method == "POST" for method, _ in calls) == 1
        assert not client._existing
    finally:
        await transport.close()


async def test_recovery_origin_change_between_reads_never_issues_a_live_observation():
    client, transport, intent, rows, calls = setup()
    try:
        receipt = await client.create(intent, before_send=lambda: None)
        original = transport.client._transport
        seen = 0

        def handle(request):
            nonlocal seen
            response = original.handler(request)
            seen += 1
            if seen == 1:
                rows[intent.native_session_id]["time"]["created"] += 1
            return response

        transport.client._transport = httpx.MockTransport(handle)
        with pytest.raises(ValueError):
            await client.observe_existing(intent, receipt)
        assert not client._existing
        assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("fault", ["copy", "expiry", "replacement", "origin", "owner", "receipt"])
async def test_existing_observation_is_original_short_lived_and_bound_to_its_historical_receipt(
    fault,
):
    client, transport, intent, rows, calls = setup()
    try:
        receipt = await client.create(intent, before_send=lambda: None)
        observation = await client.observe_existing(intent, receipt)
        if fault == "copy":
            observation = observation.model_copy()
        elif fault == "expiry":
            observation = observation.model_copy(update={"observed_at": time.time() - 6})
        elif fault == "replacement":
            await client.observe_existing(intent, receipt)
        elif fault == "origin":
            rows[intent.native_session_id]["metadata"] = {}
        elif fault == "owner":
            intent = intent.model_copy(update={"owner_epoch": "f" * 64})
        else:
            receipt = receipt.model_copy(update={"session_info_sha256": "f" * 64})
        assert not await client.existing_current(intent, receipt, observation)
        assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault", ["scope", "owner", "operation", "contract", "version", "guard", "late-guard"]
)
async def test_preflight_and_sync_guard_reject_without_a_post(fault):
    client, transport, intent, rows, calls = setup()
    guard_calls = 0

    def guard():
        return None

    if fault == "scope":
        intent = intent.model_copy(
            update={"scope": SCOPE.model_copy(update={"canonical_directory": "/foreign"})}
        )
    elif fault == "owner":
        intent = intent.model_copy(update={"owner_epoch": "f" * 64})
    elif fault == "operation":
        transport.attestation = replace(
            transport.attestation, verified_operations=frozenset({"session.get"})
        )
    elif fault == "contract":
        transport.attestation = replace(transport.attestation, schema_sha256="f" * 64)
    elif fault == "version":
        transport.attestation = replace(transport.attestation, upstream_version="unqualified")
    else:

        def guard():
            nonlocal guard_calls
            guard_calls += 1
            if fault == "guard" or guard_calls == 2:
                raise ValueError("synthetic lost fence or authority")

    try:
        with pytest.raises(MutationNotSent):
            await client.create(intent, before_send=guard)
        assert not calls and not rows
        if fault == "late-guard":
            assert guard_calls == 2
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "mode",
    ["lost-ack", "owner-after-send", "attestation-after-send", "foreign-ack", "changed-readback"],
)
async def test_fault_after_post_stays_uncertain_and_never_replays_creation(mode):
    client, transport, intent, rows, calls = setup(mode)
    try:
        with pytest.raises(ValueError) as error:
            await client.create(intent, before_send=lambda: None)
        assert not isinstance(error.value, MutationNotSent)
        assert sum(method == "POST" for method, _ in calls) == 1
        assert intent.native_session_id in rows
        if mode == "lost-ack":
            candidate = await client.observe(intent)
            assert await client.current(intent, candidate)
            assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("fault", ["copy", "changed-info", "attestation", "owner", "intent"])
async def test_registration_handoff_rechecks_seal_current_owner_and_native_info(fault):
    client, transport, intent, rows, calls = setup()
    try:
        candidate = await client.create(intent, before_send=lambda: None)
        if fault == "copy":
            candidate = candidate.model_copy()
        elif fault == "changed-info":
            rows[intent.native_session_id]["title"] = "Concurrent App edit"
        elif fault == "attestation":
            transport.attestation = replace(transport.attestation)
        elif fault == "intent":
            intent = intent.model_copy(update={"source_sha256": "e" * 64})
        else:

            async def other_owner():
                return stamp(pid=124)

            client.owner = SimpleNamespace(read=other_owner)
        assert not await client.current(intent, candidate)
        assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()


async def test_owner_freshness_expiring_during_identity_check_prevents_the_post(monkeypatch):
    from jt_oz_bridge.adapters.opencode import session_creation

    clock = [time.time()]
    monkeypatch.setattr(session_creation.time, "time", lambda: clock[0])
    client, transport, intent, rows, calls = setup()

    async def slow_identity():
        clock[0] += 6
        return True

    transport.verify_identity = slow_identity
    try:
        with pytest.raises(MutationNotSent):
            await client.create(intent, before_send=lambda: None)
        assert not calls and not rows
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault",
    [
        "id",
        "project",
        "location",
        "parent",
        "fork",
        "agent",
        "permissions",
        "metadata",
        "title",
        "model",
        "outcome",
        "idle",
        "archived",
        "cost",
        "tokens",
        "cache",
    ],
)
async def test_get_only_recovery_rejects_existing_but_unrelated_or_changed_session(fault):
    client, transport, intent, rows, calls = setup()
    try:
        candidate = await client.create(intent, before_send=lambda: None)
        row = rows[intent.native_session_id]
        if fault in {"idle", "archived"}:
            row["time"][fault] = 3
        elif fault == "tokens":
            row["tokens"]["output"] = 1
        elif fault == "cache":
            row["tokens"]["cache"]["write"] = 1
        else:
            key, value = {
                "id": ("id", "ses_foreign"),
                "project": ("projectID", "foreign"),
                "location": ("location", {"directory": "/foreign"}),
                "parent": ("parentID", "ses_parent"),
                "fork": (
                    "fork",
                    {
                        "sessionID": "ses_parent",
                        "boundary": {"type": "before", "messageID": "msg_other"},
                    },
                ),
                "agent": ("agent", "different"),
                "permissions": ("permissions", []),
                "metadata": ("metadata", {}),
                "title": ("title", "different"),
                "model": ("model", {"id": "other", "providerID": "other"}),
                "outcome": ("outcome", "succeeded"),
                "cost": ("cost", 1),
            }[fault]
            row[key] = value
        with pytest.raises(ContractError):
            await client.observe(intent)
        assert sum(method == "POST" for method, _ in calls) == 1
        assert candidate.registered_for_execution is False
    finally:
        await transport.close()


@pytest.mark.parametrize("title", ["", " padded ", "two\nlines", "a\u202eb", "x" * 513])
def test_new_title_cannot_hide_controls_or_exceed_limit(title):
    with pytest.raises(ValidationError):
        SessionCreationIntent(
            intent_id="a" * 32,
            scope=SCOPE,
            native_session_id="ses_jtoz_" + "b" * 32,
            source_sha256="c" * 64,
            owner_epoch="d" * 64,
            title=title,
        )


async def test_original_existing_observation_expires_even_when_identity_and_origin_stay_same(
    monkeypatch,
):
    client, transport, intent, rows, calls = setup()
    try:
        receipt = await client.create(intent, before_send=lambda: None)
        historical = receipt.model_copy(update={"observed_at": time.time() - 600})
        observed = await client.observe_existing(intent, historical)
        assert await client.existing_current(intent, historical, observed)
        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now + 6)
        assert not await client.existing_current(intent, historical, observed)
        assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        await transport.close()
