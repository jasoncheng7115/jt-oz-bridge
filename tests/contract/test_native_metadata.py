"""Synthetic installed-schema HTTP + original-owner fixtures, no live acceptance."""

import copy
from dataclasses import replace

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.native_metadata import (
    OPERATIONS,
    V2NativeMetadataReader,
    project_items,
    project_usage,
)
from jt_oz_bridge.domain.native_metadata import (
    CommandMetadata,
    NativeMetadataSnapshot,
    NativeUsage,
)
from tests.contract.test_leaf_resources import REF
from tests.contract.test_turn_resources import setup


def catalogs():
    agent = {
        "id": "Build/Exact",
        "name": "Build agent",
        "mode": "primary",
        "hidden": False,
        "permissions": [],
        "request": {
            "settings": {},
            "headers": {"Authorization": "Bearer NEVER_RETAIN_HEADERS"},
            "body": {"api_key": "NEVER_RETAIN_BODY"},
        },
        "system": "NEVER_RETAIN_SYSTEM",
        "description": "NEVER_RETAIN_DESCRIPTION",
    }
    return {
        "agents": [agent, {**agent, "id": "hidden", "name": "HIDDEN_AGENT", "hidden": True}],
        "commands": [{"name": "Review/Exact", "description": "NEVER_RETAIN_COMMAND_TEXT"}],
        "skills": [
            {
                "id": "Skill/Exact",
                "name": "Native skill",
                "path": "/private/NEVER_RETAIN_PATH/SKILL.md",
                "content": "NEVER_RETAIN_SKILL_CONTENT",
                "autoinvoke": True,
            }
        ],
        "mcp": [
            {"name": "connected", "status": {"status": "connected"}},
            {
                "name": "needs-login",
                "status": {"status": "needs_auth", "error": "NEVER_RETAIN_MCP_ERROR"},
                "integrationID": "NEVER_RETAIN_INTEGRATION_CONFIGURATION",
            },
        ],
    }


async def prepared(hook=None):
    p, t, data, messages, qualified, _ = await setup()
    t.attestation = replace(
        t.attestation,
        verified_operations=t.attestation.verified_operations | set(OPERATIONS.values()),
    )
    source = catalogs()
    calls = []
    delegate = t.client._transport
    routes = {
        "/api/agent": "agents",
        "/api/command": "commands",
        "/api/skill": "skills",
        "/api/mcp": "mcp",
    }

    def handler(request):
        if request.url.path in routes:
            assert request.method == "GET"
            assert dict(request.url.params) == {"location[directory]": REF.canonical_directory}
            kind = routes[request.url.path]
            calls.append(kind)
            value = {
                "location": {"directory": REF.canonical_directory},
                "data": copy.deepcopy(source[kind]),
            }
            if hook:
                hook(kind, len(calls), value, p, t, data)
            return httpx.Response(200, json=value)
        return delegate.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    # Replacing the contract invalidates its earlier mutation qualification.
    # This explicit fixture watch performs fresh original resource reads.
    await p.watch(REF)
    return p, t, data, V2NativeMetadataReader(qualified.client, REF), calls, source


@pytest.mark.parametrize("kind", ["agents", "commands", "skills", "mcp", "usage"])
async def test_original_location_and_owner_project_only_safe_fields(kind):
    p, t, data, reader, calls, source = await prepared()
    try:
        snapshot = await reader.read(REF, kind)
        assert snapshot.reference == REF and snapshot.kind == kind and reader.current(snapshot)
        assert not reader.current(snapshot.model_copy())
        assert not reader.current(
            NativeMetadataSnapshot.model_validate_json(snapshot.model_dump_json())
        )
        assert "NEVER_RETAIN" not in snapshot.model_dump_json()
        assert "HIDDEN_AGENT" not in snapshot.model_dump_json()
        assert calls == ([] if kind == "usage" else [kind, kind])
        if kind == "agents":
            assert snapshot.items[0].native_id == "Build/Exact" and len(snapshot.items) == 1
        if kind == "usage":
            assert snapshot.usage.cost_usd == data["session.get"]["data"]["cost"]
        t.attestation = replace(t.attestation, verified_operations=frozenset({"session.get"}))
        assert not reader.current(snapshot)
    finally:
        await t.close()


@pytest.mark.parametrize("kind", ["agents", "commands", "skills", "mcp"])
async def test_advertised_but_unqualified_rpc_is_not_called(kind):
    p, t, data, reader, calls, source = await prepared()
    try:
        t.attestation = replace(
            t.attestation,
            verified_operations=t.attestation.verified_operations - {OPERATIONS[kind]},
        )
        assert kind not in reader.available_kinds(REF)
        with pytest.raises(ContractError):
            await reader.read(REF, kind)
        assert not calls
    finally:
        await t.close()


@pytest.mark.parametrize("failure", ["location", "catalog", "owner", "attestation", "duplicate"])
async def test_changes_during_read_fail_closed(failure):
    def hook(kind, count, value, p, t, data):
        if failure == "location":
            value["location"]["directory"] = "/another/workspace"
        elif failure == "catalog" and count == 2:
            value["data"][0]["name"] = "changed"
        elif failure == "owner":
            p.feed.owner.read.side_effect = ContractError("owner_lost")
        elif failure == "attestation":
            t.attestation = replace(t.attestation)
        elif failure == "duplicate":
            value["data"].append(copy.deepcopy(value["data"][0]))

    p, t, data, reader, calls, source = await prepared(hook)
    try:
        with pytest.raises((ValueError, ContractError)):
            await reader.read(REF, "commands")
    finally:
        await t.close()


async def test_wrong_original_root_cannot_reuse_enrolled_reader():
    p, t, data, reader, calls, source = await prepared()
    try:
        for change in (
            {"upstream_session_id": "other"},
            {"backend_identity": "other"},
            {"canonical_directory": "/other"},
        ):
            with pytest.raises(ContractError):
                await reader.read(REF.model_copy(update=change), "commands")
        assert not calls
    finally:
        await t.close()


def test_usage_requires_every_original_field_without_zero_fill_or_total():
    info = {
        "cost": 0.0125,
        "tokens": {"input": 100, "output": 20, "reasoning": 7, "cache": {"read": 30, "write": 40}},
    }
    usage = project_usage(info)
    assert usage.model_dump() == {
        "cost_usd": 0.0125,
        "input": 100,
        "output": 20,
        "reasoning": 7,
        "cache_read": 30,
        "cache_write": 40,
    }
    del info["tokens"]["reasoning"]
    with pytest.raises(KeyError):
        project_usage(info)


@pytest.mark.parametrize("value", [True, "1", -1, float("inf"), float("nan"), 10**500])
def test_bad_native_numbers_cannot_be_displayed_as_measurements(value):
    with pytest.raises(ValidationError):
        NativeUsage(cost_usd=value, input=1, output=2, reasoning=3, cache_read=4, cache_write=5)


def test_catalog_capacity_and_duplicate_identity_are_not_silently_truncated():
    with pytest.raises(ContractError):
        project_items("commands", [{"name": "same"}] * 2)
    with pytest.raises(ContractError):
        project_items("commands", [{"name": str(i)} for i in range(4097)])
    with pytest.raises(ValidationError):
        NativeMetadataSnapshot(
            reference=REF,
            contract_sha256="a" * 64,
            kind="skills",
            items=(CommandMetadata(native_id="a", name="a"),),
        )


async def test_attestation_replacement_and_bounded_witness_cache_invalidate_old_authority():
    p, t, data, reader, calls, source = await prepared()
    try:
        first = await reader.read(REF, "commands")
        for _ in range(8):
            last = await reader.read(REF, "commands")
        assert len(reader._observed) == 8 and reader._observed_bytes <= 4 * 1024 * 1024
        assert not reader.current(first) and reader.current(last)
        t.attestation = replace(t.attestation)
        assert not reader.current(last)
    finally:
        await t.close()


async def test_oversized_safe_catalog_is_rejected_without_retaining_a_witness():
    p, t, data, reader, calls, source = await prepared()
    source["commands"] = [{"name": str(i) + "x" * 600} for i in range(4096)]
    try:
        with pytest.raises(ContractError, match="capacity"):
            await reader.read(REF, "commands")
        assert not reader._observed and reader._observed_bytes == 0
    finally:
        await t.close()
