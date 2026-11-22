"""Complete response contracts; batch reads never supply reusable authority."""

import asyncio
import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio

from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient, ZulipError
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
from tests.contract.test_zulip_scope import URL, Server


@pytest_asyncio.fixture
async def bulk():
    server = Server()
    calls = []

    def hook(route, value):
        return value

    q = SimpleNamespace(
        bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
    )

    def peer(request):
        route = request.url.path.removeprefix("/api/v1/")
        calls.append(route)
        if route == "users/me":
            value = {
                "user_id": 11,
                "is_bot": True,
                "is_active": True,
                "bot_owner_id": 8,
                "role": 400,
            }
        elif route == "server_settings":
            value = {
                "realm_url": URL,
                "zulip_version": q.zulip_version,
                "zulip_feature_level": q.feature_level,
            }
        elif route == "users/me/subscriptions":
            assert dict(request.url.params) == {"include_subscribers": "true"}
            value = {
                "subscriptions": [
                    {**server.stream, "is_archived": False, "subscribers": server.subscribers}
                ]
            }
        elif route == "users":
            assert (
                request.url.params["client_gravatar"]
                == request.url.params["include_custom_profile_fields"]
                == "false"
            )
            ids = json.loads(request.url.params["user_ids"])
            assert ids == [8, 9]  # No broad directory lookup or Bot elevation.
            value = {"members": [server.users[identity] for identity in ids]}
        else:
            return server.handle(request)
        return httpx.Response(200, json={"result": "success", **hook(route, copy.deepcopy(value))})

    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "private-test-key",
        attestation=ZulipAttestation(
            URL, "2", 11, 500, 10000, 60, verified_scope_operations=SCOPE_OPERATIONS
        ),
        transport=httpx.MockTransport(peer),
    )
    guard = ZulipRuntimeIdentity(client, q)
    client.verify_identity = guard
    reader = ZulipScopeReader(client, channel_ids=frozenset({4}), bulk_metadata=True)

    def set_hook(value):
        nonlocal hook
        hook = value

    try:
        yield server, reader, calls, q, set_hook
    finally:
        await client.close()


async def test_complete_batch_has_two_fresh_sides_and_only_numeric_profiles(bulk):
    _, reader, calls, _, _ = bulk
    first = await reader.inspect("2", 4, "CanonicalTopic")
    assert first.user_ids == {8, 9} and first.private and not first.untrusted_bot_ids
    assert len(calls) == 12
    assert calls.count("users/me/subscriptions") == calls.count("users") == 2
    assert calls.count("users/me") == calls.count("server_settings") == 2
    assert first == await reader.inspect("2", 4, "CanonicalTopic")
    assert len(calls) == 24  # No cross-operation reuse.


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "missing",
        "duplicate",
        "coerced",
        "archived",
        "partial",
        "no_bot",
        "duplicate_member",
        "bool_member",
        "missing_flag",
        "bad_flag",
    ],
)
async def test_incomplete_subscription_never_falls_back_or_proves_acl(bulk, kind):
    _, reader, calls, _, set_hook = bulk

    def malformed(route, value):
        if route != "users/me/subscriptions":
            return value
        row = value["subscriptions"][0]
        if kind == "empty":
            value["subscriptions"] = []
        elif kind == "missing":
            row["stream_id"] = 5
        elif kind == "duplicate":
            value["subscriptions"].append(copy.deepcopy(row))
        elif kind == "coerced":
            row["stream_id"] = "4"
        elif kind == "archived":
            row["is_archived"] = True
        elif kind == "partial":
            row["partial_subscribers"] = row.pop("subscribers")
        elif kind == "no_bot":
            row["subscribers"] = [8, 9]
        elif kind == "duplicate_member":
            row["subscribers"].append(9)
        elif kind == "bool_member":
            row["subscribers"].append(True)
        elif kind == "missing_flag":
            del row["is_archived"]
        elif kind == "bad_flag":
            row["history_public_to_subscribers"] = 0
        return value

    set_hook(malformed)
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")
    assert "streams/4" not in calls and "streams/4/members" not in calls


@pytest.mark.parametrize(
    "kind", ["empty", "missing", "duplicate", "foreign", "inactive", "bad_bool", "coerced"]
)
async def test_exact_profile_set_required_without_hidden_directory_fallback(bulk, kind):
    _, reader, calls, _, set_hook = bulk

    def malformed(route, value):
        if route != "users":
            return value
        profiles = value["members"]
        if kind == "empty":
            value["members"] = []
        elif kind == "missing":
            profiles.pop()
        elif kind == "duplicate":
            profiles[1] = profiles[0]
        elif kind == "foreign":
            profiles[1]["user_id"] = 12
        elif kind == "inactive":
            profiles[0]["is_active"] = False
        elif kind == "bad_bool":
            profiles[0]["is_bot"] = 0
        elif kind == "coerced":
            profiles[0]["user_id"] = "8"
        return value

    set_hook(malformed)
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")
    assert "users/8" not in calls and "users/9" not in calls


@pytest.mark.parametrize("change", ["privacy", "members", "user"])
async def test_second_independent_side_detects_changes(bulk, change):
    _, reader, calls, _, set_hook = bulk

    def mutate(route, value):
        if (
            change in {"privacy", "members"}
            and route == "users/me/subscriptions"
            and calls.count(route) == 2
        ):
            row = value["subscriptions"][0]
            if change == "privacy":
                row["invite_only"] = False
            else:
                row["subscribers"].remove(9)
        if change == "user" and route == "users" and calls.count(route) == 2:
            value["members"][0]["is_bot"] = True
        return value

    set_hook(mutate)
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")


@pytest.mark.parametrize(
    "change", ["transport", "http", "attestation", "guard", "qualification", "q_fields", "channels"]
)
async def test_inflight_identity_changes_cannot_reuse_batch(bulk, change):
    _, reader, _, q, set_hook = bulk
    client = reader.client
    original_http = client.client

    def mutate(route, value):
        if route == "users/me/subscriptions":
            if change == "transport":
                original_http._transport = httpx.MockTransport(lambda _: httpx.Response(500))
            elif change == "http":
                client.client = httpx.AsyncClient(
                    transport=httpx.MockTransport(lambda _: httpx.Response(500))
                )
            elif change == "attestation":
                client.attestation = replace(reader.enrolled)
            elif change == "guard":
                client.verify_identity = ZulipRuntimeIdentity(client, q)
            elif change == "qualification":
                client.verify_identity.qualification = copy.copy(q)
            elif change == "q_fields":
                q.bot_owner_id = 9
            elif change == "channels":
                reader.channel_ids = frozenset({4, 5})
        return value

    set_hook(mutate)
    try:
        with pytest.raises(ZulipError):
            await reader.inspect("2", 4, "CanonicalTopic")
    finally:
        await original_http.aclose()


async def test_task_inheritance_cannot_use_parent_batch(bulk):
    _, reader, _, _, _ = bulk
    async with reader.identity_reads():
        await reader.channel(4)
        with pytest.raises(ZulipError):
            await asyncio.create_task(reader.members(4))
        assert await reader.members(4) == (8, 9, 11)


async def test_repeated_parts_and_nested_operations_do_not_extend_or_reuse(bulk):
    _, reader, calls, _, _ = bulk
    async with reader.identity_reads():
        await reader.channel(4)
        await reader.members(4)
        await reader.user(8)
        await reader.user(9)
        assert calls.count("users") == 1
        await reader.user(8)
        assert calls.count("users") == 2
        await reader.members(4)
        await reader.channel(4)
        assert calls.count("users/me/subscriptions") == 2
        async with reader.identity_reads():
            await reader.channel(4)
            await reader.members(4)
        assert calls.count("users/me/subscriptions") == 3
    await reader.user(8)
    assert calls[-1] == "users/8"  # Outside operation, individual guard/API.


@pytest.mark.parametrize("mode", ["disabled", "unknown_version", "custom_guard"])
async def test_unqualified_or_unselected_paths_use_original_individual_reads(bulk, mode):
    _, reader, calls, q, _ = bulk
    if mode == "disabled":
        reader = ZulipScopeReader(reader.client, channel_ids=reader.channel_ids)
    elif mode == "unknown_version":
        q.zulip_version = "future"
    else:

        async def custom():
            return True

        reader.client.verify_identity = custom
    audience = await reader.inspect("2", 4, "CanonicalTopic")
    assert audience.user_ids == {8, 9}
    assert "users/me/subscriptions" not in calls and "users" not in calls
    assert "streams/4" in calls and "users/8" in calls


@pytest.mark.parametrize(
    "route,params",
    [
        ("users", None),
        ("users", {}),
        ("users", {"user_ids": "[8]"}),
        *[
            (
                "users",
                {
                    "user_ids": value,
                    "client_gravatar": "false",
                    "include_custom_profile_fields": "false",
                },
            )
            for value in ("[]", "[true]", "[8,8]", '["8"]', "null", "{", [8])
        ],
        ("users/me/subscriptions", {}),
        ("users/me/subscriptions", {"include_subscribers": "partial"}),
    ],
)
async def test_unfiltered_or_malformed_batch_parameters_never_touch_http(bulk, route, params):
    _, reader, calls, _, _ = bulk
    with pytest.raises(ZulipError):
        await reader.client.request("GET", route, params=params)
    assert not calls


async def test_original_scope_deadline_is_never_extended_by_batch_reuse(bulk):
    _, reader, _, _, _ = bulk
    guard = reader.client.verify_identity
    with pytest.raises(ZulipError, match="scope_identity_window_expired"):
        async with reader.identity_reads():
            await reader.channel(4)
            guard._scope.get().deadline = 0
            await reader.members(4)


async def test_untrusted_bot_and_copy_isolation_are_preserved(bulk):
    server, reader, _, _, _ = bulk
    server.users[8]["is_bot"] = True
    audience = await reader.inspect("2", 4, "CanonicalTopic")
    assert audience.user_ids == {9} and audience.untrusted_bot_ids == {8}
    async with reader.identity_reads():
        value = await reader.channel(4)
        value["stream_id"] = 500
        assert await reader.members(4) == (8, 9, 11)
        profile = await reader.user(8)
        profile["is_active"] = False
        assert (await reader.user(9))["is_active"] is True
