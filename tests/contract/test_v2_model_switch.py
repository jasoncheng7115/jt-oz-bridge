"""Synthetic setting admission/race tests; actual Native observations are separate."""

import copy
import json
from pathlib import Path

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.model_catalog import READS
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
)
from jt_oz_bridge.adapters.opencode.transport import (
    ContractAttestation,
    TransportError,
    V2HTTPTransport,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.model_catalog import ModelSelection, NativeModelRef
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_v2_execution import SyntheticProofs
from tests.contract.test_v2_model_catalog import LOCATION, REF, SCOPE, info, model
from tests.integration.test_dispatch import message

TOKEN = "opaque-actor-bound-choice"


async def setup(*, origin="model", hook=None, state=ExecutionState.IDLE):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )
    provider = SyntheticProofs()
    provider.state = state
    provider.model_settings = ModelSettingsAttestation(
        REF, profile.sha256, MODEL_SETTING_SEMANTICS, "a" * 64
    )
    data = {
        "session": info(),
        "models": [model(), model(providerID="ollama", id="example-model:27b", variants=[])],
        "readback": "normalize-default",
    }
    seen = []

    def handle(request):
        seen.append(request)
        if hook is not None:
            response = hook(request, data, provider)
            if response is not None:
                return response
        if request.method == "POST":
            assert request.url.path == "/api/session/ses_original/model"
            body = json.loads(request.content)
            data["session"]["model"] = dict(body["model"])
            if data["readback"] == "normalize-default":
                data["session"]["model"].setdefault("variant", "default")
            if data["readback"] == "lost-ack":
                raise httpx.ReadTimeout("synthetic acknowledgement loss", request=request)
            if data["readback"] == "changed-model":
                data["session"]["model"] = {"providerID": "other", "id": "foreign"}
            return httpx.Response(204)
        if request.url.path == "/api/model":
            return httpx.Response(
                200, json={"location": LOCATION, "data": copy.deepcopy(data["models"])}
            )
        if request.url.path == "/api/model/default":
            return httpx.Response(200, json={"location": LOCATION, "data": model()})
        assert request.url.path == "/api/session/ses_original"
        return httpx.Response(200, json={"data": copy.deepcopy(data["session"])})

    async def verify():
        return True

    transport = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, REF.backend_identity, "2.0.32", READS | {"session.switchModel"}
        ),
        verify_identity=verify,
        transport=httpx.MockTransport(handle),
    )
    client = V2ExecutionClient(
        transport, {SCOPE.project_id: V2CatalogProject(SCOPE, "native-project")}, proofs=provider
    )
    catalog = await client.models.read(REF)
    target = (
        NativeModelRef(provider_id="ollama", model_id="example-model:27b")
        if origin == "model"
        else catalog.selected.model_copy(update={"variant": "high"})
    )
    choice = ModelSelection(
        origin=origin,
        target=target,
        previous=catalog.selected,
        catalog_sha256=digest(catalog.model_dump(mode="json")),
    )
    payload = {
        "operation": "model.switch",
        "reference": REF.model_dump(mode="json"),
        "source": message(text=f"!oz {origin} {TOKEN}", revision=0).model_dump(mode="json"),
        "selection": choice.model_dump(mode="json"),
        "selection_token_sha256": token_hash(TOKEN),
    }
    seen.clear()
    return client, transport, provider, data, seen, payload


@pytest.mark.parametrize(
    "state", [ExecutionState.IDLE, ExecutionState.RUNNING, ExecutionState.WAITING_INPUT]
)
async def test_one_session_setter_affects_subsequent_turns_and_accepts_native_default_readback(
    state,
):
    client, transport, _provider, _data, seen, payload = await setup(state=state)
    try:
        result = await client.submit(REF, payload, "action-model")
        assert result.status == "completed" and result.upstream_id is None
        assert result.details["effect"] == "subsequent_provider_turns"
        assert (
            result.details["starts_execution"] is False
            and result.details["turn_completed"] is False
        )
        assert result.details["observed"]["variant"] == "default"
        posts = [r for r in seen if r.method == "POST"]
        assert len(posts) == 1 and json.loads(posts[0].content) == {
            "model": {"providerID": "ollama", "id": "example-model:27b"}
        }
        assert all(
            r.url.path
            in {
                "/api/session/ses_original",
                "/api/session/ses_original/model",
                "/api/model",
                "/api/model/default",
            }
            for r in seen
        )
    finally:
        await transport.close()


async def test_a_phone_number_stands_for_the_model_row_it_picked():
    client, transport, _provider, _data, seen, payload = await setup()
    payload["source"]["text"] = "!2"
    payload["shortcut"] = f"!oz model {TOKEN}"
    try:
        result = await client.submit(REF, payload, "action-model")
        assert result.status == "completed"
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()


async def test_explicit_variant_selects_same_provider_model_without_restarting_execution():
    client, transport, _provider, _data, seen, payload = await setup(origin="variant")
    try:
        result = await client.submit(REF, payload, "action-variant")
        assert result.details["observed"]["variant"] == "high"
        posts = [r for r in seen if r.method == "POST"]
        assert len(posts) == 1 and json.loads(posts[0].content)["model"] == {
            "providerID": "synthetic-provider",
            "id": "CaseSensitive/Alias",
            "variant": "high",
        }
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change",
    [
        "no-settings-qualification",
        "unverified-source",
        "wrong-token",
        "edited-source",
        "bot",
        "command",
        "catalog",
        "previous",
        "disabled",
        "foreign-variant",
        "extra-payload",
        "shortcut-other-row",
        "shortcut-without-number",
        "shortcut-on-a-typed-command",
    ],
)
async def test_stale_unavailable_or_unqualified_setting_is_rejected_before_any_post(change):
    client, transport, provider, data, seen, payload = await setup()
    if change == "no-settings-qualification":
        provider.model_settings = None
    elif change == "unverified-source":
        provider.model_settings = ModelSettingsAttestation(
            REF, transport.profile.sha256, "b" * 64, "a" * 64
        )
    elif change == "wrong-token":
        payload["selection_token_sha256"] = "b" * 64
    elif change == "edited-source":
        payload["source"]["revision"] = 1
    elif change == "bot":
        payload["source"]["is_bot"] = True
    elif change == "command":
        payload["source"]["text"] = "ordinary model request"
    elif change == "catalog":
        payload["selection"]["catalog_sha256"] = "b" * 64
    elif change == "previous":
        data["session"]["model"]["variant"] = "high"
    elif change == "disabled":
        data["models"][1]["enabled"] = False
    elif change == "foreign-variant":
        payload["selection"]["origin"] = "variant"
        payload["source"]["text"] = f"!oz variant {TOKEN}"
    elif change == "shortcut-other-row":
        payload["source"]["text"] = "!2"
        payload["shortcut"] = "!oz model " + "Z" * 32
    elif change == "shortcut-without-number":
        payload["source"]["text"] = "!2"
    elif change == "shortcut-on-a-typed-command":
        payload["shortcut"] = f"!oz model {TOKEN}"
    else:
        payload["headers"] = {"Authorization": "arbitrary"}
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload, "action-model")
        assert not [r for r in seen if r.method == "POST"]
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["lost-ack", "changed-model"])
async def test_uncertain_after_send_is_never_called_unsent_or_automatically_retried(change):
    client, transport, _provider, data, seen, payload = await setup()
    data["readback"] = change
    try:
        with pytest.raises((ContractError, TransportError)) as caught:
            await client.submit(REF, payload, "action-model")
        assert not isinstance(caught.value, MutationNotSent)
        assert len([r for r in seen if r.method == "POST"]) == 1
    finally:
        await transport.close()


async def test_model_qualification_revoked_during_final_identity_await_prevents_post():
    client, transport, provider, _data, seen, payload = await setup()
    ready_for_send = False

    class Guard:
        def enrolled(self, reference, operation):
            return True

        async def authorize(self, reference, operation, proof):
            nonlocal ready_for_send
            assert operation == "model.switch"
            ready_for_send = True
            return object()

        def current(self, *args):
            return True

    async def verify():
        if ready_for_send:
            provider.model_settings = None
        return True

    client.scope_guard = Guard()
    transport.verify_identity = verify
    try:
        with pytest.raises(MutationNotSent):
            await client.submit(REF, payload, "action-model")
        assert not [r for r in seen if r.method == "POST"]
    finally:
        await transport.close()
