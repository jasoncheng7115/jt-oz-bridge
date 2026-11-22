"""Installed-schema fixtures, not claims of live provider inference."""

import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.model_catalog import READS, V2ModelCatalog
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.model_catalog import NativeModelRef
from jt_oz_bridge.domain.models import SessionRef

SCOPE = ProjectScope(
    backend_id="backend",
    backend_identity="synthetic-original-owner",
    project_id="bridge-project",
    canonical_directory="/workspace/approved",
)
REF = SessionRef(**SCOPE.model_dump(), upstream_session_id="ses_original")
LOCATION = {"directory": SCOPE.canonical_directory}
SELECTED = {"providerID": "synthetic-provider", "id": "CaseSensitive/Alias", "variant": "none"}


def info(**changes):
    return {
        "id": REF.upstream_session_id,
        "projectID": "native-project",
        "location": LOCATION,
        "model": dict(SELECTED),
        "cost": 0,
        "tokens": {"input": 0, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}},
        "time": {"created": 1, "updated": 2},
        **changes,
    }


def model(**changes):
    return {
        "id": SELECTED["id"],
        "providerID": "synthetic-provider",
        "modelID": "different-upstream-model-id",
        "name": "Native model label",
        "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
        "variants": [
            {"id": "none", "headers": {"Authorization": "variant-private-value"}},
            {"id": "high", "body": {"private": "variant-body-value"}},
        ],
        "time": {"released": 0},
        "cost": [],
        "status": "active",
        "enabled": True,
        "limit": {"context": 1000, "output": 100},
        "headers": {"Authorization": "model-private-value"},
        "body": {"private": "model-body-value"},
        "settings": {},
        **changes,
    }


async def identity():
    return True


def client(handler=None, *, verify=identity, operations=READS, attested=True):
    profile = OpenAPIProfile.from_file(
        Path("tests/fixtures/contracts/opencode-v2.0.32-installed.json")
    )
    seen = []

    def handle(request):
        seen.append(request)
        assert request.method == "GET"
        if handler is not None:
            result = handler(request, seen)
            if result is not None:
                return result
        if request.url.path == "/api/model":
            return httpx.Response(200, json={"location": LOCATION, "data": [model()]})
        if request.url.path == "/api/model/default":
            return httpx.Response(200, json={"location": LOCATION, "data": model()})
        assert request.url.path == "/api/session/ses_original"
        return httpx.Response(200, json={"data": info()})

    transport = V2HTTPTransport(
        "https://private.invalid",
        profile,
        attestation=ContractAttestation(
            profile.sha256, SCOPE.backend_identity, "2.0.32", operations
        )
        if attested
        else None,
        verify_identity=verify,
        transport=httpx.MockTransport(handle),
    )
    catalog = V2ModelCatalog(
        transport, {SCOPE.project_id: V2CatalogProject(SCOPE, "native-project")}
    )
    return catalog, transport, seen


async def test_only_safe_fields_are_disclosed_and_native_alias_is_preserved():
    catalog, transport, seen = client()
    try:
        result = await catalog.read(REF)
        assert result.reference == REF and result.providers == ("synthetic-provider",)
        assert result.selected.wire() == SELECTED
        assert result.default.wire() == {"providerID": "synthetic-provider", "id": SELECTED["id"]}
        selected = result.option(result.selected)
        assert selected.upstream_model_id == "different-upstream-model-id"
        assert selected.reference.model_id == SELECTED["id"]
        assert selected.variant_ids == ("none", "high")
        encoded = result.model_dump_json()
        for value in (
            "headers",
            "body",
            "settings",
            "private-value",
            "body-value",
            "Authorization",
        ):
            assert value not in encoded
        assert len(seen) == 4
        for request in seen:
            if request.url.path.startswith("/api/model"):
                assert dict(request.url.params) == {
                    "location[directory]": SCOPE.canonical_directory
                }
            else:
                assert not request.url.params
    finally:
        await transport.close()


async def test_enabled_catalog_uses_all_native_models_and_separates_provider_aliases():
    def handler(request, seen):
        if request.url.path == "/api/model":
            rows = [
                model(providerID="ollama", id="hf.co/Team/Model:Q4", variants=[]),
                model(providerID="synthetic-provider", id="same-alias"),
                model(providerID="ollama", id="same-alias"),
                model(id="disabled-model", enabled=False),
            ]
            return httpx.Response(200, json={"location": LOCATION, "data": rows})

    catalog, transport, _seen = client(handler)
    try:
        result = await catalog.read(REF)
        assert result.providers == ("ollama", "synthetic-provider")
        assert [(x.reference.provider_id, x.reference.model_id) for x in result.items] == [
            ("ollama", "hf.co/Team/Model:Q4"),
            ("ollama", "same-alias"),
            ("synthetic-provider", "same-alias"),
        ]
        # Current/default may no longer be in the selectable snapshot. Do not
        # invent an enabled option or silently choose a replacement for them.
        assert result.option(result.selected) is None
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["no-session-model", "no-default", "neither"])
async def test_absence_of_explicit_or_default_model_is_not_guessed(change):
    def handler(request, seen):
        if request.url.path == "/api/session/ses_original" and change != "no-default":
            row = info()
            row.pop("model")
            return httpx.Response(200, json={"data": row})
        if request.url.path == "/api/model/default" and change != "no-session-model":
            return httpx.Response(200, json={"location": LOCATION, "data": None})

    catalog, transport, _seen = client(handler)
    try:
        result = await catalog.read(REF)
        assert (result.selected is None) == (change != "no-default")
        assert (result.default is None) == (change != "no-session-model")
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["unattested", "missing-read", "wrong-scope", "unverified"])
async def test_no_transport_on_missing_scope_or_contract_or_owner(change):
    async def unverified():
        return False

    catalog, transport, seen = client(
        attested=change != "unattested",
        operations=READS - {"model.default"} if change == "missing-read" else READS,
        verify=unverified if change == "unverified" else identity,
    )
    ref = (
        REF.model_copy(update={"canonical_directory": "/foreign"})
        if change == "wrong-scope"
        else REF
    )
    try:
        with pytest.raises(ContractError):
            await catalog.read(ref)
        assert not seen
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "change",
    [
        "foreign-model-location",
        "foreign-default-location",
        "foreign-project",
        "foreign-session",
        "foreign-directory",
        "duplicate",
        "duplicate-disabled",
        "variant-duplicate",
        "overflow",
    ],
)
async def test_schema_valid_but_foreign_or_ambiguous_model_information_is_refused(change):
    def handler(request, seen):
        if request.url.path == "/api/model" and change in {
            "foreign-model-location",
            "duplicate",
            "duplicate-disabled",
            "variant-duplicate",
            "overflow",
        }:
            location, rows = LOCATION, [model()]
            if change == "foreign-model-location":
                location = {"directory": "/foreign"}
            elif change in {"duplicate", "duplicate-disabled"}:
                rows.append(model(enabled=change == "duplicate"))
            elif change == "variant-duplicate":
                rows = [model(variants=[{"id": "high"}, {"id": "high"}])]
            else:
                rows = [model(id=f"model-{i}", variants=[]) for i in range(4097)]
            return httpx.Response(200, json={"location": location, "data": rows})
        if request.url.path == "/api/model/default" and change == "foreign-default-location":
            return httpx.Response(200, json={"location": {"directory": "/foreign"}, "data": None})
        if request.url.path == "/api/session/ses_original":
            changes = {
                "foreign-project": {"projectID": "foreign"},
                "foreign-session": {"id": "ses_foreign"},
                "foreign-directory": {"location": {"directory": "/foreign"}},
            }.get(change)
            if changes:
                return httpx.Response(200, json={"data": info(**changes)})

    catalog, transport, _seen = client(handler)
    try:
        with pytest.raises(ValueError):
            await catalog.read(REF)
    finally:
        await transport.close()


async def test_selection_changed_during_reads_is_not_returned_as_current():
    reads = 0

    def handler(request, seen):
        nonlocal reads
        if request.url.path == "/api/session/ses_original":
            reads += 1
            return httpx.Response(
                200,
                json={"data": info(model={**SELECTED, "variant": "high" if reads > 1 else "none"})},
            )

    catalog, transport, _seen = client(handler)
    try:
        with pytest.raises(ContractError, match="selection_changed"):
            await catalog.read(REF)
    finally:
        await transport.close()


async def test_backend_changed_during_catalog_read_discards_result():
    checks = 0

    async def verify():
        nonlocal checks
        checks += 1
        return checks == 1

    catalog, transport, _seen = client(verify=verify)
    try:
        with pytest.raises(ContractError, match="backend_unverified"):
            await catalog.read(REF)
    finally:
        await transport.close()


def test_variant_omission_and_literal_none_remain_distinct_and_case_is_preserved():
    omitted = NativeModelRef(provider_id="synthetic-provider", model_id="Team/ALIAS:Q4")
    explicit = NativeModelRef(
        provider_id="synthetic-provider", model_id="Team/ALIAS:Q4", variant="none"
    )
    assert omitted != explicit
    assert "variant" not in omitted.wire() and explicit.wire()["variant"] == "none"
    assert json.loads(explicit.model_dump_json())["model_id"] == "Team/ALIAS:Q4"
    with pytest.raises(ValidationError):
        NativeModelRef(provider_id="synthetic-provider", model_id="bad\nvalue")
    default = NativeModelRef(
        provider_id="synthetic-provider", model_id="Team/ALIAS:Q4", variant="default"
    )
    assert default != omitted and default.same_native_selection(omitted)
    assert not explicit.same_native_selection(default)
    assert not default.same_native_selection(None)
