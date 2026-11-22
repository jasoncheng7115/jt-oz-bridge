"""Actual V2 preflight/ACK and durable correlation, with synthetic peers only."""

import copy
import json
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation
from jt_oz_bridge.domain.attachments import PromptAttachmentReceipt, WorkspaceAttachmentManifest
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.workspace_attachments import (
    PreparedWorkspaceAttachments,
    WorkspacePromptProjection,
    workspace_projection,
)
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.services.resource_execution_results import correlation
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup
from tests.integration.test_dispatch import message


def payload():
    source = message(text="整理重點，摘要 [AGENTS.md](/user_uploads/2/fixture/AGENTS.md)")
    file = PromptAttachmentReceipt(
        artifact_id=str(uuid4()),
        source_upload="/user_uploads/2/fixture/AGENTS.md",
        source_message_id=source.message_id,
        source_sha256=digest(source.model_dump(mode="json")),
        filename="AGENTS.md",
        mime_type="text/markdown",
        size=123,
        sha256="a" * 64,
    )
    manifest = WorkspaceAttachmentManifest(files=(file,))
    data = {
        "operation": "prompt",
        "reference": REF.model_dump(mode="json"),
        "text": source.text,
        "source": source.model_dump(mode="json"),
        "workspace_attachments": manifest.model_dump(mode="json"),
    }
    return source, manifest, data, str(uuid4())


class SyntheticProvider:
    def __init__(self, frozen):
        self.frozen = frozen
        self.active = True
        self.prepared = None
        self.qualified_flag = True
        self.hook = None
        self.mode = "normal"
        self.calls = 0

    def qualified(self, ref, schema):
        return self.qualified_flag and ref == REF

    async def prepare(self, ref, action, source, manifest, text):
        self.calls += 1
        projection = workspace_projection(
            ref, action, text, manifest, ".jt-oz-incoming-fixture", "b" * 64
        )
        result = PreparedWorkspaceAttachments(
            ref,
            action,
            source.realm_id,
            digest(source.model_dump(mode="json")),
            digest(self.frozen),
            projection,
        )
        self.prepared = result
        if self.mode == "digest":
            result = replace(result, operation_digest="f" * 64)
        elif self.mode == "scope":
            result = replace(
                result, reference=ref.model_copy(update={"upstream_session_id": "foreign"})
            )
        elif self.mode == "reconstructed":
            result = replace(result)
        elif self.mode == "projection":
            result = replace(
                result, projection=projection.model_copy(update={"prompt_text_sha256": "f" * 64})
            )
        if self.hook:
            self.hook()
        return result

    def current(self, ref, action, prepared):
        return self.active and prepared is self.prepared


async def setup(mode="normal"):
    p, t, d, g, client, policy_calls, writes = await policy_setup()
    source, manifest, frozen, action = payload()
    provider = SyntheticProvider(frozen)
    client.workspace_attachments = provider
    original = t.client._transport

    def handler(request):
        if request.method != "POST" or not request.url.path.endswith("/prompt"):
            return original.handler(request)
        writes.append(request)
        body = json.loads(request.content)
        ack = {
            "id": "msg_workspace",
            "sessionID": REF.upstream_session_id,
            "time": {"created": 1},
            "type": "user",
            "payload": {k: copy.deepcopy(v) for k, v in body.items() if k != "delivery"},
            "delivery": "queue",
        }
        if mode == "text":
            ack["payload"]["text"] = source.text
        if mode == "session":
            ack["sessionID"] = "foreign"
        if mode == "delivery":
            ack["delivery"] = "steer"
        if mode == "metadata":
            ack["payload"]["metadata"]["jt_oz_bridge"]["operation_digest"] = "f" * 64
        if mode == "missing-metadata":
            ack["payload"].pop("metadata")
        if mode == "action":
            ack["payload"]["metadata"]["jt_oz_bridge"]["action_id"] = "foreign"
        if mode == "files":
            ack["payload"]["files"] = [{"uri": "https://foreign", "mimeType": "text/plain"}]
        if mode == "agents":
            ack["payload"]["agents"] = [{"id": "other"}]
        if mode == "skills":
            ack["payload"]["skills"] = ["unexpected"]
        return httpx.Response(200, json={"data": ack})

    t.client._transport = httpx.MockTransport(handler)
    return p, t, client, provider, source, manifest, frozen, action, writes


async def test_one_original_prompt_contains_projected_uuid_paths_without_inline_or_autoload_names():
    p, t, client, provider, source, manifest, frozen, action, writes = await setup()
    before = copy.deepcopy(frozen)
    try:
        admission = await client.submit(REF, frozen, action)
        assert admission.status == "admitted" and admission.upstream_id == "msg_workspace"
        assert len(writes) == 1 and frozen == before
        body = json.loads(writes[0].content)
        projection = WorkspacePromptProjection.model_validate(
            admission.details["workspace_projection"]
        )
        assert body["text"] == projection.checked(REF, action, source.text, manifest)
        assert body["text"].startswith(source.text + "\n\n")
        assert (
            ".jt-oz-incoming-fixture/" + action + "_" + manifest.files[0].artifact_id
            in body["text"]
        )
        assert '/AGENTS.md"' not in body["text"]
        assert not any(k in body for k in ("files", "agents", "skills"))
        assert (
            "attachments" not in admission.details
            and admission.details["model_visibility"] == "unverified"
        )
        assert provider.calls == 1
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "mode",
    [
        "text",
        "session",
        "delivery",
        "metadata",
        "missing-metadata",
        "action",
        "files",
        "agents",
        "skills",
    ],
)
async def test_changed_native_ack_is_ambiguous_after_one_send_never_claimed_unsent_or_retried(mode):
    p, t, client, provider, source, manifest, frozen, action, writes = await setup(mode)
    try:
        with pytest.raises(ContractError):
            await client.submit(REF, frozen, action)
        assert len(writes) == 1
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "mode",
    [
        "absent",
        "unqualified",
        "digest",
        "scope",
        "reconstructed",
        "projection",
        "replaced",
        "expired",
        "source",
        "mixed",
        "format",
        "altered-text",
    ],
)
async def test_workspace_preflight_and_final_original_object_checks_reject_without_post(mode):
    p, t, client, provider, source, manifest, frozen, action, writes = await setup()
    if mode == "absent":
        client.workspace_attachments = None
    elif mode == "unqualified":
        provider.qualified_flag = False
    elif mode in {"digest", "scope", "reconstructed", "projection"}:
        provider.mode = mode
    elif mode == "replaced":
        provider.hook = lambda: setattr(client, "workspace_attachments", SyntheticProvider(frozen))
    elif mode == "expired":
        provider.hook = lambda: setattr(provider, "active", False)
    elif mode == "source":
        frozen["source"]["is_bot"] = True
    elif mode == "mixed":
        frozen["attachments"] = {"files": []}
    elif mode == "format":
        frozen["workspace_attachments"]["format"] = "inline"
    else:
        frozen["text"] += " extra"
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, frozen, action)
        assert not writes
        if mode in {"mixed", "format", "altered-text", "source"}:
            assert not provider.calls
    finally:
        await finish(p, t)


def admitted_action():
    source, manifest, frozen, action = payload()
    projection = workspace_projection(
        REF, action, source.text, manifest, ".jt-oz-incoming-fixture", "b" * 64
    )
    from jt_oz_bridge.domain.execution import Admission

    admission = Admission(
        status="admitted",
        upstream_id="msg_workspace",
        details={
            "workspace_projection": projection.model_dump(mode="json"),
            "model_visibility": "unverified",
        },
    )
    receipt = ExecutionReceipt(
        action_id=action,
        operation_digest=digest(frozen),
        reference=REF,
        contract_sha256="a" * 64,
        admission=admission,
    )
    row = Action(
        id=action,
        operation="prompt",
        owner="opencode",
        actor_id=source.author_id,
        payload=frozen,
        operation_digest=digest(frozen),
        upstream_id=admission.upstream_id,
        admission=receipt.model_dump(mode="json"),
    )
    return row, source, manifest, projection


def test_durable_turn_correlation_reconstructs_exact_projected_text_and_preserves_original_human_text():
    row, source, manifest, projection = admitted_action()
    result = correlation(row)
    assert result.text == projection.checked(REF, row.id, source.text, manifest)
    assert row.payload["text"] == source.text
    assert result.workspace_projection_sha256 == digest(projection.model_dump(mode="json"))
    assert not result.attachments and result.attachment_semantics_sha256 is None
    raw = result.model_dump(mode="json")
    assert "attachments" not in raw and "attachment_semantics_sha256" not in raw
    assert TurnCorrelation.model_validate(raw) == result


@pytest.mark.parametrize(
    "change", ["missing", "digest", "namespace", "files", "source-hash", "unexpected", "mixed"]
)
def test_durable_receipt_cannot_rebind_projection_to_different_input_or_text(change):
    row, source, manifest, projection = admitted_action()
    details = row.admission["admission"]["details"]
    if change == "missing":
        details.pop("workspace_projection")
    elif change == "digest":
        details["workspace_projection"]["prompt_text_sha256"] = "f" * 64
    elif change == "namespace":
        details["workspace_projection"]["namespace_name"] = "../../escape"
    elif change == "files":
        details["workspace_projection"]["files"][0]["filename"] = "changed.txt"
    elif change == "source-hash":
        details["workspace_projection"]["source_text_sha256"] = "f" * 64
    elif change == "unexpected":
        row.payload.pop("workspace_attachments")
        row.operation_digest = digest(row.payload)
        row.admission["operation_digest"] = row.operation_digest
    else:
        row.payload["attachments"] = {"files": []}
        row.operation_digest = digest(row.payload)
        row.admission["operation_digest"] = row.operation_digest
    with pytest.raises((ValueError, Conflict)):
        correlation(row)


def test_legacy_plain_text_turn_serialization_is_unchanged():
    source, manifest, frozen, action = payload()
    data = {
        "reference": REF.model_dump(mode="json"),
        "action_id": action,
        "operation_digest": digest(frozen),
        "upstream_id": "msg_existing",
        "text": source.text,
    }
    assert TurnCorrelation(**data).model_dump(mode="json") == data


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", ".jt-oz-incoming-", "ordinary", ".jt-oz-incoming-bad/name"]
)
def test_only_controlled_namespace_paths_can_enter_prompt_projection(name):
    source, manifest, frozen, action = payload()
    with pytest.raises(ValueError):
        workspace_projection(REF, action, source.text, manifest, name, "b" * 64)


@pytest.mark.parametrize(
    "change", ["none", "plain-text", "foreign-text", "files", "agents", "skills"]
)
async def test_original_native_projected_turn_must_match_workspace_text_and_have_no_inline_inputs(
    change,
):
    from tests.contract.test_turn_resources import setup as turn_setup

    row, source, manifest, projection = admitted_action()
    expected = correlation(row)
    p, t, d, m, reader, pages = await turn_setup()
    user = m[-1]
    user.update(
        id=expected.upstream_id,
        text=expected.text,
        metadata={
            "jt_oz_bridge": {
                "action_id": expected.action_id,
                "operation_digest": expected.operation_digest,
            }
        },
    )
    if change == "plain-text":
        user["text"] = source.text
    elif change == "foreign-text":
        user["text"] += " another turn"
    elif change in {"files", "agents", "skills"}:
        user[change] = [{"unexpected": "input"}]
    try:
        if change == "none":
            evidence = await reader.capture(expected)
            assert (
                evidence.correlation.workspace_projection_sha256
                == expected.workspace_projection_sha256
            )
            assert reader.current(evidence) and evidence.attachment_evidence_sha256 is None
            assert evidence.turn.text[0].text == "Exact final answer"
        else:
            with pytest.raises(ContractError):
                await reader.capture(expected)
    finally:
        await finish(p, t)
