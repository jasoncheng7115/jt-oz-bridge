"""Synthetic original-owner/schema lifecycle tests, not live mutation qualification."""

import copy
import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import (
    ContractError,
    OpenAPIProfile,
    SnapshotBoundaryChanged,
)
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.domain.execution import HumanMessage, MutationNotSent
from jt_oz_bridge.domain.session_lifecycle import SessionRename, SessionRenameOutcome
from tests.contract.test_v2_execution import SyntheticProofs
from tests.contract.test_v2_model_catalog import REF, SCOPE, info


def setup(mode="success"):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )
    provider = SyntheticProofs()
    data = info()
    data["title"] = "Original title"
    seen = []

    def handler(request):
        assert request.url.path == "/api/session/ses_original"
        if request.method == "PATCH":
            body = json.loads(request.content)
            assert set(body) == {"title"}
            seen.append(body)
            data["title"] = body["title"]
            if mode == "lost-ack":
                raise httpx.ReadTimeout("synthetic lost acknowledgement", request=request)
            if mode == "changed-title":
                data["title"] = "Concurrent TUI rename"
            if mode == "owner-lost":
                provider.epoch = "new-owner-epoch"
            if mode == "attestation-replaced":
                transport.attestation = replace(transport.attestation)
            return httpx.Response(204)
        assert request.method == "GET"
        return httpx.Response(200, json={"data": copy.deepcopy(data)})

    async def identity():
        return True

    transport = V2HTTPTransport(
        "https://native.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256,
            REF.backend_identity,
            "2.0.32",
            frozenset({"session.get", "session.update"}),
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(handler),
    )
    client = V2ExecutionClient(
        transport, {SCOPE.project_id: V2CatalogProject(SCOPE, "native-project")}, proofs=provider
    )
    change = SessionRename(previous_title="Original title", target_title="My project · 新工作")
    source = HumanMessage(
        realm_id="realm",
        channel_id=4,
        topic="original",
        message_id=12,
        revision=0,
        author_id=9,
        text="!oz rename " + change.target_title,
    )
    payload = {
        "operation": "session.rename",
        "reference": REF.model_dump(mode="json"),
        "source": source.model_dump(mode="json"),
        "change": change.model_dump(mode="json"),
        "reply_locale": "zh-TW",
    }
    return client, transport, data, payload, seen


async def test_fixed_title_patch_preserves_original_identity_and_does_not_start_a_turn():
    client, transport, data, payload, seen = setup()
    try:
        before = copy.deepcopy(data)
        admission = await client.submit(REF, payload, "explicit-rename")
        outcome = SessionRenameOutcome.model_validate(admission.details)
        assert admission.status == "completed" and admission.upstream_id is None
        assert outcome.observed_title == payload["change"]["target_title"]
        assert not outcome.starts_execution and not outcome.turn_completed
        assert seen == [{"title": outcome.observed_title}]
        assert {k: v for k, v in data.items() if k != "title"} == {
            k: v for k, v in before.items() if k != "title"
        }
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault",
    ["source", "edited", "bot", "deleted", "previous-title", "reference", "extra", "unqualified"],
)
async def test_rename_preflight_faults_never_send_a_patch(fault):
    client, transport, data, payload, seen = setup()
    if fault == "source":
        payload["source"]["text"] = "!oz rename Different"
    elif fault == "edited":
        payload["source"]["revision"] = 1
    elif fault == "bot":
        payload["source"]["is_bot"] = True
    elif fault == "deleted":
        payload["source"]["deleted"] = True
    elif fault == "previous-title":
        data["title"] = "Already renamed on the TUI"
    elif fault == "reference":
        payload["reference"]["canonical_directory"] = "/foreign"
    elif fault == "extra":
        payload["metadata"] = {"permissions": "never send"}
    else:
        transport.attestation = replace(
            transport.attestation, verified_operations=frozenset({"session.get"})
        )
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload, "explicit-rename")
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "mode", ["lost-ack", "changed-title", "owner-lost", "attestation-replaced"]
)
async def test_post_patch_uncertainty_is_never_reported_as_not_sent(mode):
    client, transport, data, payload, seen = setup(mode)
    try:
        with pytest.raises(ValueError) as error:
            await client.submit(REF, payload, "explicit-rename")
        assert not isinstance(error.value, MutationNotSent)
        assert len(seen) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "title",
    [
        "",
        "  ",
        " outer ",
        "two\nlines",
        "two\u2028lines",
        "escape\x1b[31m",
        "fake\u202ename",
        "x" * 513,
    ],
)
def test_rename_titles_are_bounded_and_cannot_disguise_controls(title):
    with pytest.raises(ValidationError):
        SessionRename(previous_title="original", target_title=title)


@pytest.mark.parametrize("boundaries", [1, 3, 4])
async def test_post_patch_mutable_boundary_only_retries_reads_with_a_fixed_limit(boundaries):
    client, transport, data, payload, seen = setup()
    original = client.proofs.prove
    reads = 0

    async def crossing(*args):
        nonlocal reads
        if seen:
            reads += 1
            if reads <= boundaries:
                raise SnapshotBoundaryChanged("synthetic_mutable_snapshot_boundary")
        return await original(*args)

    client.proofs.prove = crossing
    try:
        if boundaries == 4:
            with pytest.raises(SnapshotBoundaryChanged):
                await client.submit(REF, payload, "bounded-readback")
            assert reads == 4
        else:
            admission = await client.submit(REF, payload, "bounded-readback")
            assert (
                SessionRenameOutcome.model_validate(admission.details).observed_title
                == data["title"]
            )
            assert reads == boundaries + 1
        assert len(seen) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("fault", ["contract", "owner", "attestation", "title"])
async def test_readback_never_retries_contract_errors_or_crosses_original_identity(fault):
    client, transport, data, payload, seen = setup()
    original = client.proofs.prove
    reads = 0

    async def changed(*args):
        nonlocal reads
        if seen:
            reads += 1
            if reads == 1:
                if fault == "contract":
                    raise ContractError("synthetic_permanent_contract_failure")
                if fault == "owner":
                    client.proofs.epoch = "different-original-owner"
                elif fault == "attestation":
                    transport.attestation = replace(transport.attestation)
                elif fault == "title":
                    data["title"] = "Another client's title"
                raise SnapshotBoundaryChanged("synthetic_boundary_with_changed_identity")
        return await original(*args)

    client.proofs.prove = changed
    try:
        with pytest.raises(ContractError) as error:
            await client.submit(REF, payload, "changed-readback")
        assert not isinstance(error.value, MutationNotSent)
        assert reads == (2 if fault == "title" else 1)
        assert len(seen) == 1
    finally:
        await transport.close()


async def test_snapshot_boundary_before_patch_is_not_retried_as_a_mutation():
    client, transport, data, payload, seen = setup()
    reads = 0

    async def crossing(*args):
        nonlocal reads
        reads += 1
        raise SnapshotBoundaryChanged("synthetic_preflight_boundary")

    client.proofs.prove = crossing
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload, "preflight-race")
        assert reads == 1 and not seen
    finally:
        await transport.close()


async def test_stalled_post_patch_readback_has_a_deadline_and_never_replays_patch():
    import asyncio

    client, transport, data, payload, seen = setup()
    original = client.proofs.prove

    async def stalled(*args):
        if seen:
            await asyncio.Event().wait()
        return await original(*args)

    client.proofs.prove = stalled
    try:
        with pytest.raises(TimeoutError):
            await client.submit(REF, payload, "stalled-readback")
        assert len(seen) == 1
    finally:
        await transport.close()
