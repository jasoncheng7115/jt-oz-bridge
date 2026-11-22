"""Real Bot guard with synthetic HTTP; scope coalescing never caches Human ACL."""

import asyncio
from collections import Counter
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient, ZulipError
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader, ZulipSourceReader
from jt_oz_bridge.services import runtime_enrollment as runtime
from tests.contract.test_zulip_scope import URL, Server, expected


@pytest.fixture
async def identity_peer(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    server, calls = Server(), []
    me = {"user_id": 11, "is_bot": True, "bot_owner_id": 8, "role": 400}
    settings = {"realm_url": URL, "zulip_version": "12.3", "zulip_feature_level": 500}
    state = {"latency": 0.3, "hook": None}

    async def handle(request):
        path = request.url.path.removeprefix("/api/v1/")
        calls.append((request.method, path))
        clock[0] += state["latency"]
        if state["hook"]:
            await state["hook"](path)
        if path == "users/me":
            return httpx.Response(200, json={"result": "success", **me})
        if path == "server_settings":
            return httpx.Response(200, json={"result": "success", **settings})
        return server.handle(request)

    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic-key",
        attestation=ZulipAttestation(
            URL, "2", 11, 500, 10000, 60, verified_scope_operations=SCOPE_OPERATIONS
        ),
        transport=httpx.MockTransport(handle),
    )
    qualification = SimpleNamespace(
        bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
    )
    guard = runtime.ZulipRuntimeIdentity(client, qualification)
    client.verify_identity = guard
    scope = ZulipScopeReader(client, channel_ids=frozenset({4}))
    value = SimpleNamespace(
        clock=clock,
        server=server,
        calls=calls,
        me=me,
        settings=settings,
        state=state,
        client=client,
        guard=guard,
        scope=scope,
    )
    try:
        yield value
    finally:
        await client.close()


async def test_slow_scope_keeps_complete_two_human_members_topic_reads_with_bounded_bot_metadata(
    identity_peer,
):
    p = identity_peer
    view = await p.scope.inspect("2", 4, "CanonicalTopic")
    counts = Counter(path for _, path in p.calls)
    assert view.user_ids == {8, 9} and view.private
    assert all(
        counts[path] == 2
        for path in (
            "streams/4",
            "streams/4/members",
            "users/8",
            "users/9",
            "users/11",
            "messages",
            "users/me/4/topics",
        )
    )
    assert counts["users/me"] <= 4 and counts["server_settings"] <= 4
    assert p.clock[0] < 110  # Network/proof model only, not accelerated Native/Human proof.


async def test_source_retains_original_identity_behavior_and_both_message_and_author_reads(
    identity_peer,
):
    p = identity_peer
    source = await ZulipSourceReader(p.scope, expected).read("2", 19)
    counts = Counter(path for _, path in p.calls)
    assert source.author_id == 8 and source.text == "!oz status"
    assert counts["messages/19"] == counts["users/8"] == 2
    assert counts["users/me"] == counts["server_settings"] == 1


@pytest.mark.parametrize(
    "fault", ["bot-owner", "bot-role", "server-version", "guard", "attestation"]
)
async def test_final_bot_or_pointer_revocation_does_not_return_audience(identity_peer, fault):
    p = identity_peer

    async def hook(path):
        if path == "users/me/4/topics" and p.server.counts.get(path, 0) == 1:
            if fault == "bot-owner":
                p.me["bot_owner_id"] = 999
            elif fault == "bot-role":
                p.me["role"] = 200
            elif fault == "server-version":
                p.settings["zulip_version"] = "other"
            elif fault == "guard":

                async def replacement():
                    return True

                p.client.verify_identity = replacement
            else:
                p.client.attestation = replace(p.client.attestation)

    p.state["hook"] = hook
    with pytest.raises(ZulipError):
        await p.scope.inspect("2", 4, "CanonicalTopic")


@pytest.mark.parametrize("fault", ["member", "user", "topic", "message"])
async def test_scope_coalescing_retains_original_acl_and_source_double_read_failures(
    identity_peer, fault
):
    p = identity_peer

    def hook(path, count):
        if fault == "member" and path == "streams/4/members" and count == 2:
            p.server.subscribers = [8, 11]
        elif fault == "user" and path == "users/9" and count == 2:
            p.server.users[9]["is_active"] = False
        elif fault == "topic" and path == "messages" and count == 2:
            p.server.raw["subject"] = "Moved"
        elif fault == "message" and path == "messages/19" and count == 2:
            p.server.raw["content"] = "edited"

    p.server.hook = hook
    with pytest.raises(ZulipError):
        if fault == "message":
            await ZulipSourceReader(p.scope, expected).read("2", 19)
        else:
            await p.scope.inspect("2", 4, "CanonicalTopic")


async def test_scoped_child_task_cannot_inherit_parent_bot_read_proof(identity_peer):
    p = identity_peer
    assert callable(getattr(p.guard, "scope_reads", None))
    async with p.guard.scope_reads():
        before = len(p.calls)
        with pytest.raises(ZulipError):
            await asyncio.create_task(p.scope.user(8))
        assert len(p.calls) == before


async def test_scoped_post_still_uses_original_guard_and_rejects_revoked_bot(identity_peer):
    p = identity_peer
    assert callable(getattr(p.guard, "scope_reads", None))
    async with p.guard.scope_reads():
        p.clock[0] += 1.1
        p.me["role"] = 200
        with pytest.raises(ZulipError, match="message_mutation_not_attested"):
            await p.client.request("POST", "messages", data={"content": "not-sent"})
        assert all(method != "POST" for method, _ in p.calls)
        p.me["role"] = 400


@pytest.mark.parametrize("failure", ["error", "cancelled"])
async def test_failed_scope_always_discards_context_and_next_read_refreshes(identity_peer, failure):
    p = identity_peer
    with pytest.raises(ValueError if failure == "error" else asyncio.CancelledError):
        async with p.guard.scope_reads():
            assert await p.guard.scope_read()
            if failure == "error":
                raise ValueError("synthetic")
            raise asyncio.CancelledError()
    assert p.guard._scope.get() is None
    before = Counter(path for _, path in p.calls)["users/me"]
    async with p.guard.scope_reads():
        pass
    assert Counter(path for _, path in p.calls)["users/me"] == before + 2


@pytest.mark.parametrize("fault", ["deadline", "capacity", "nested-deadline"])
async def test_scope_bound_is_not_renewed_or_bypassed_by_nested_reader(identity_peer, fault):
    p = identity_peer
    p.state["latency"] = 0
    with pytest.raises(ZulipError):
        async with p.guard.scope_reads():
            if fault == "capacity":
                for _ in range(32):
                    assert await p.guard.scope_read()
                await p.guard.scope_read()
            elif fault == "nested-deadline":
                p.clock[0] += 9
                async with p.guard.scope_reads():
                    p.clock[0] += 1.01
                    await p.guard.scope_read()
            else:
                p.clock[0] += 10.01
                await p.guard.scope_read()
    assert p.guard._scope.get() is None


@pytest.mark.parametrize("kind", ["function", "asyncmock"])
async def test_default_guard_fallback_retains_both_human_and_identity_checks(identity_peer, kind):
    p = identity_peer
    called = []

    async def guard():
        called.append(True)
        return True

    p.client.verify_identity = guard if kind == "function" else AsyncMock(side_effect=guard)
    result = await p.scope.inspect("2", 4, "CanonicalTopic")
    assert result.user_ids == {8, 9} and len(called) >= 12
    counts = Counter(path for _, path in p.calls)
    assert counts["users/8"] == counts["users/9"] == counts["streams/4/members"] == 2
    assert not counts["users/me"]


def operation_source(peer):
    from jt_oz_bridge.domain.execution import HumanMessage

    return HumanMessage(
        realm_id="2",
        channel_id=4,
        topic="CanonicalTopic",
        message_id=19,
        revision=0,
        author_id=8,
        text="!oz status",
        is_bot=False,
        deleted=False,
    )


async def test_closed_operation_brackets_read_only_callback_and_consumes_once(identity_peer):
    p = identity_peer
    reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)
    admissions = []

    async def read_only(audience):
        counts = Counter(path for _, path in p.calls)
        assert counts["messages/19"] == counts["streams/4/members"] == 1
        assert counts["users/8"] == counts["users/9"] == counts["users/11"] == 1
        assert audience.user_ids == {8, 9} and not audience.untrusted_bot_ids
        admissions.append(audience)
        await asyncio.sleep(0)  # Actual awaited read-only work stays inside the observation.
        return ("qualified-original-native-get", 17)

    observation = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    counts = Counter(path for _, path in p.calls)
    assert counts["messages/19"] == counts["streams/4/members"] == 2
    assert counts["users/8"] == counts["users/9"] == counts["users/11"] == 2
    assert counts["users/me"] == counts["server_settings"] == 2
    assert len(p.calls) == 18
    assert counts["messages"] == 0 and counts["users/me/4/topics"] == 2
    completed = p.scope.consume_observation(observation, reader, (source,))
    assert completed.audience == admissions[0]
    assert completed.sources == (source,) and completed.value == (
        "qualified-original-native-get",
        17,
    )
    with pytest.raises(ZulipError):
        p.scope.consume_observation(observation, reader, (source,))
    assert p.guard._scope.get() is None


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "revision",
        "topic",
        "member",
        "privacy",
        "human-active",
        "human-bot",
        "bot",
        "owner",
        "role",
        "server",
        "guard",
        "attestation",
        "expected-channel",
    ],
)
async def test_closed_operation_rejects_changes_during_read_only_work(identity_peer, fault):
    p = identity_peer
    source, index = operation_source(p), [4]

    async def scoped(realm, message_id):
        return index[0]

    reader = ZulipSourceReader(p.scope, scoped)
    called = []

    async def read_only(audience):
        called.append(audience)
        if fault == "source":
            p.server.raw["content"] = "changed"
        elif fault == "revision":
            p.server.raw.update(edit_history=[{}], last_edit_timestamp=1)
        elif fault == "topic":
            p.server.raw["subject"] = "Moved"
        elif fault == "member":
            p.server.subscribers = [8, 11]
        elif fault == "privacy":
            p.server.stream["invite_only"] = False
        elif fault == "human-active":
            p.server.users[8]["is_active"] = False
        elif fault == "human-bot":
            p.server.users[8]["is_bot"] = True
        elif fault == "bot":
            p.server.users[11]["is_bot"] = False
        elif fault == "owner":
            p.me["bot_owner_id"] = 999
        elif fault == "role":
            p.me["role"] = 200
        elif fault == "server":
            p.settings["zulip_version"] = "different"
        elif fault == "guard":
            p.client.verify_identity = AsyncMock(return_value=True)
        elif fault == "attestation":
            p.client.attestation = replace(p.client.attestation)
        else:
            index[0] = 5
        await asyncio.sleep(0)
        return "must-not-be-authorized"

    with pytest.raises(ZulipError):
        await p.scope.observe_sources(reader, (source,), read_only=read_only)
    assert len(called) == 1 and p.guard._scope.get() is None
    assert all(method == "GET" for method, _ in p.calls)


@pytest.mark.parametrize("fault", ["source", "human-active", "member", "privacy", "bot"])
async def test_closed_operation_never_calls_native_before_complete_admission(identity_peer, fault):
    p = identity_peer
    source = operation_source(p)
    if fault == "source":
        p.server.raw["content"] = "wrong"
    elif fault == "human-active":
        p.server.users[8]["is_active"] = False
    elif fault == "member":
        p.server.subscribers = [9, 11]
    elif fault == "privacy":
        p.server.stream["is_web_public"] = True
    else:
        p.server.users[11]["is_bot"] = False
    callback = AsyncMock(return_value="forbidden")
    with pytest.raises(ZulipError):
        await p.scope.observe_sources(
            ZulipSourceReader(p.scope, expected), (source,), read_only=callback
        )
    callback.assert_not_awaited()
    assert p.guard._scope.get() is None


@pytest.mark.parametrize("fault", ["cancel", "fence", "deadline"])
async def test_failed_read_only_callback_cannot_issue_an_observation(identity_peer, fault):
    from jt_oz_bridge.storage.durable import Conflict

    p = identity_peer

    async def read_only(audience):
        await asyncio.sleep(0)
        if fault == "cancel":
            raise asyncio.CancelledError()
        if fault == "fence":
            raise Conflict("synthetic-current-fence-revoked")
        p.clock[0] += 10.01
        return "expired"

    expected_error = (
        asyncio.CancelledError
        if fault == "cancel"
        else Conflict
        if fault == "fence"
        else ZulipError
    )
    with pytest.raises(expected_error):
        await p.scope.observe_sources(
            ZulipSourceReader(p.scope, expected), (operation_source(p),), read_only=read_only
        )
    assert p.guard._scope.get() is None


@pytest.mark.parametrize("fault", ["yield", "cross-task", "forged", "other-reader", "other-source"])
async def test_operation_receipt_is_issuer_task_source_owned_and_never_a_ttl_cache(
    identity_peer, fault
):
    from jt_oz_bridge.adapters.zulip import scope as module

    p = identity_peer
    reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)

    async def read_only(audience):
        return "only-this-operation"

    observation = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    if fault == "yield":
        await asyncio.sleep(0)
    elif fault == "forged":
        observation = module.ZulipOperationObservation()
    elif fault == "other-reader":
        reader = ZulipSourceReader(p.scope, expected)
    elif fault == "other-source":
        source = source.model_copy(update={"text": "different"})
    if fault == "cross-task":

        async def child():
            with pytest.raises(ZulipError):
                p.scope.consume_observation(observation, reader, (source,))

        await asyncio.create_task(child())
    else:
        with pytest.raises(ZulipError):
            p.scope.consume_observation(observation, reader, (source,))


async def test_inflight_operation_has_no_receipt_or_partial_authorized_result(identity_peer):
    p = identity_peer
    started, release = asyncio.Event(), asyncio.Event()
    callback_results = []

    async def read_only(audience):
        started.set()
        await release.wait()
        callback_results.append("private-partial")
        return "private-complete"

    async def observe():
        return await p.scope.observe_sources(
            ZulipSourceReader(p.scope, expected), (operation_source(p),), read_only=read_only
        )

    task = asyncio.create_task(observe())
    entered = asyncio.create_task(started.wait())
    try:
        await asyncio.wait({task, entered}, return_when=asyncio.FIRST_COMPLETED, timeout=1)
        if task.done():
            await task
        assert entered.done(), "Observation callback never started"
    finally:
        entered.cancel()
        await asyncio.gather(entered, return_exceptions=True)
    assert not task.done() and not callback_results
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not callback_results


async def test_operation_observes_exact_prior_human_and_dedicated_bot_with_one_native_get(
    identity_peer,
):
    import copy

    p = identity_peer
    source = operation_source(p)
    prior = source.model_copy(update={"message_id": 17, "text": "!projects"})
    preview = source.model_copy(
        update={"message_id": 18, "author_id": 11, "is_bot": True, "text": "Original preview"}
    )
    raw = {
        17: {**copy.deepcopy(p.server.raw), "id": 17, "content": prior.text},
        18: {**copy.deepcopy(p.server.raw), "id": 18, "sender_id": 11, "content": preview.text},
    }
    original = p.server.handle

    def handle(request):
        path = request.url.path.removeprefix("/api/v1/")
        if path in {"messages/17", "messages/18"}:
            return httpx.Response(
                200,
                json={"result": "success", "message": copy.deepcopy(raw[int(path.split("/")[1])])},
            )
        return original(request)

    p.server.handle = handle

    async def index(realm, message_id):
        return 4 if realm == "2" and message_id in {17, 18, 19} else None

    reader = ZulipSourceReader(p.scope, index)
    native_calls = []

    async def native_peer(request):
        assert request.method == "GET" and request.url.path == "/session/original"
        native_calls.append(request.method)
        return httpx.Response(200, json={"id": "original", "reconciled": True})

    async def read_only(audience):
        assert audience.user_ids == {8, 9}
        async with httpx.AsyncClient(transport=httpx.MockTransport(native_peer)) as native:
            response = await native.get("https://native.example.invalid/session/original")
        await asyncio.sleep(0)
        return response.json()

    sources = (source, prior, preview)
    observation = await p.scope.observe_sources(reader, sources, read_only=read_only)
    completed = p.scope.consume_observation(observation, reader, sources)
    assert completed.sources == sources and completed.value == {
        "id": "original",
        "reconciled": True,
    }
    counts = Counter(path for _, path in p.calls)
    assert counts["users/8"] == counts["users/9"] == counts["users/11"] == 2
    assert counts["messages/17"] == counts["messages/18"] == counts["messages/19"] == 2
    assert counts["users/me"] == counts["server_settings"] == 2
    assert len(p.calls) == 22 and native_calls == ["GET"]
    assert counts["messages"] == 0 and counts["users/me/4/topics"] == 2


@pytest.mark.parametrize(
    "fault",
    [
        "human-bot",
        "other-human",
        "other-bot",
        "duplicate",
        "other-topic",
        "no-index",
        "plain-guard",
    ],
)
async def test_operation_never_generalizes_sources_or_bounded_guard(identity_peer, fault):
    p = identity_peer
    source = operation_source(p)
    sources, index = (source,), expected
    if fault == "human-bot":
        sources = (source.model_copy(update={"author_id": 11, "is_bot": True}),)
    elif fault == "other-human":
        sources += (source.model_copy(update={"message_id": 18, "author_id": 9}),)
    elif fault == "other-bot":
        sources += (source.model_copy(update={"message_id": 18, "author_id": 12, "is_bot": True}),)
    elif fault == "duplicate":
        sources += sources
    elif fault == "other-topic":
        sources += (source.model_copy(update={"message_id": 18, "topic": "Foreign"}),)
    elif fault == "no-index":

        async def missing(realm, message_id):
            return None

        index = missing
    else:
        p.client.verify_identity = AsyncMock(return_value=True)
    callback = AsyncMock()
    with pytest.raises(ZulipError):
        await p.scope.observe_sources(
            ZulipSourceReader(p.scope, index), sources, read_only=callback
        )
    callback.assert_not_awaited()
    assert not any(path.startswith("messages/") for _, path in p.calls)


@pytest.mark.parametrize(
    "fault",
    ["guard", "attestation", "qualification", "other-issuer", "enrolled", "channels", "index"],
)
async def test_immediate_receipt_still_requires_exact_current_issuer_identity(identity_peer, fault):
    p = identity_peer
    source, reader = operation_source(p), ZulipSourceReader(p.scope, expected)

    async def read_only(audience):
        return "data-only"

    observation = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    issuer = p.scope
    if fault == "guard":
        p.client.verify_identity = AsyncMock(return_value=True)
    elif fault == "attestation":
        p.client.attestation = replace(p.client.attestation)
    elif fault == "qualification":
        p.guard.qualification = SimpleNamespace(**vars(p.guard.qualification))
    elif fault == "enrolled":
        p.scope.enrolled = replace(p.scope.enrolled)
    elif fault == "channels":
        p.scope.channel_ids = frozenset()
    elif fault == "index":

        async def replacement(realm, message_id):
            return 4

        reader.expected_channel = replacement
    else:
        issuer = ZulipScopeReader(p.client, channel_ids=frozenset({4}))
    with pytest.raises(ZulipError):
        issuer.consume_observation(observation, reader, (source,))


async def test_final_identity_is_completed_before_any_receipt_is_issued(identity_peer):
    p = identity_peer

    async def hook(path):
        if path == "users/me" and Counter(route for _, route in p.calls)[path] == 2:
            assert not p.scope._observations
            p.me["bot_owner_id"] = 999

    p.state["hook"] = hook

    async def read_only(audience):
        return "private-data"

    with pytest.raises(ZulipError):
        await p.scope.observe_sources(
            ZulipSourceReader(p.scope, expected), (operation_source(p),), read_only=read_only
        )
    assert not p.scope._observations and p.guard._scope.get() is None


@pytest.mark.parametrize("fault", ["enrolled", "channels", "index"])
@pytest.mark.parametrize("when", ["first-message", "callback", "last-message"])
async def test_closed_operation_pins_issuer_channels_and_expected_index_at_awaits(
    identity_peer, fault, when
):
    p = identity_peer
    reader = ZulipSourceReader(p.scope, expected)

    def mutate():
        if fault == "enrolled":
            p.scope.enrolled = replace(p.scope.enrolled)
        elif fault == "channels":
            p.scope.channel_ids = frozenset()
        else:

            async def replacement(realm, message_id):
                return 4

            reader.expected_channel = replacement

    async def hook(path):
        count = Counter(route for _, route in p.calls)["messages/19"]
        if path == "messages/19" and (
            when == "first-message" and count == 1 or when == "last-message" and count == 2
        ):
            mutate()

    p.state["hook"] = hook
    called = []

    async def read_only(audience):
        called.append(audience)
        if when == "callback":
            mutate()
        return "not-authorized"

    with pytest.raises(ZulipError):
        await p.scope.observe_sources(reader, (operation_source(p),), read_only=read_only)
    assert len(called) == (0 if when == "first-message" else 1)
    assert not p.scope._observations and p.guard._scope.get() is None


@pytest.mark.parametrize("surface", ["inspect", "observation"])
async def test_complete_own_bot_record_reuses_only_this_scopes_fresh_metadata(
    identity_peer, surface
):
    p = identity_peer
    p.me["is_active"] = True
    if surface == "inspect":
        assert (await p.scope.inspect("2", 4, "CanonicalTopic")).user_ids == {8, 9}
    else:
        reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)
        observation = await p.scope.observe_sources(
            reader, (source,), read_only=AsyncMock(return_value=17)
        )
        assert p.scope.consume_observation(observation, reader, (source,)).value == 17
    counts = Counter(path for _, path in p.calls)
    assert counts["users/11"] == 0, counts
    assert counts["users/8"] == counts["users/9"] == counts["streams/4/members"] == 2
    assert counts["users/me"] == counts["server_settings"] == 2


@pytest.mark.parametrize("surface", ["inspect", "observation"])
@pytest.mark.parametrize("fault", ["missing", "false", "string", "integer", "owner", "role", "bot"])
async def test_enabled_own_bot_record_requires_complete_final_fresh_metadata(
    identity_peer, surface, fault
):
    p = identity_peer
    p.me["is_active"] = True

    async def hook(path):
        if path == "users/me" and Counter(route for _, route in p.calls)[path] == 2:
            if fault == "missing":
                p.me.pop("is_active")
            elif fault == "false":
                p.me["is_active"] = False
            elif fault == "string":
                p.me["is_active"] = "true"
            elif fault == "integer":
                p.me["is_active"] = 1
            elif fault == "owner":
                p.me["bot_owner_id"] = 999
            elif fault == "role":
                p.me["role"] = 200
            else:
                p.me["is_bot"] = False

    p.state["hook"] = hook
    with pytest.raises(ZulipError):
        if surface == "inspect":
            await p.scope.inspect("2", 4, "CanonicalTopic")
        else:
            await p.scope.observe_sources(
                ZulipSourceReader(p.scope, expected),
                (operation_source(p),),
                read_only=AsyncMock(return_value="unpublished"),
            )
    assert p.guard._scope.get() is None and not p.scope._observations
    counts = Counter(route for _, route in p.calls)
    assert counts["users/11"] == 0 and counts["users/8"] == counts["users/9"] == 2
    assert all(method == "GET" for method, _ in p.calls)


@pytest.mark.parametrize("bad", [False, "true", 1])
async def test_explicit_invalid_own_bot_active_field_never_uses_a_legacy_positive(
    identity_peer, bad
):
    p = identity_peer
    p.me["is_active"] = bad
    with pytest.raises(ZulipError):
        await p.scope.inspect("2", 4, "CanonicalTopic")
    assert not any(path.startswith("users/") and path != "users/me" for _, path in p.calls)
    assert p.guard._scope.get() is None


@pytest.mark.parametrize("surface", ["inspect", "observation"])
async def test_missing_initial_bot_active_keeps_entire_scope_legacy_even_if_tail_adds_it(
    identity_peer, surface
):
    p = identity_peer

    async def hook(path):
        if path == "server_settings":
            p.me["is_active"] = True

    p.state["hook"] = hook
    if surface == "inspect":
        assert (await p.scope.inspect("2", 4, "CanonicalTopic")).user_ids == {8, 9}
    else:
        reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)
        handle = await p.scope.observe_sources(
            reader, (source,), read_only=AsyncMock(return_value=17)
        )
        assert p.scope.consume_observation(handle, reader, (source,)).value == 17
    counts = Counter(path for _, path in p.calls)
    assert counts["users/11"] == counts["users/8"] == counts["users/9"] == 2
    assert counts["users/me"] == counts["server_settings"] == 2


async def test_scope_bot_record_is_not_available_outside_context_or_a_human_cache(identity_peer):
    p = identity_peer
    p.me["is_active"] = True
    assert p.guard.scope_bot_user() is None
    before = Counter(path for _, path in p.calls)["users/11"]
    assert (await p.scope.user(11))["is_active"] is True
    assert Counter(path for _, path in p.calls)["users/11"] == before + 1
    async with p.guard.scope_reads():
        profile = p.guard.scope_bot_user()
        assert profile == {"user_id": 11, "is_bot": True, "is_active": True}
        profile["is_active"] = False  # Caller owns this copy, never the stored tuple.
        assert (await p.scope.user(11))["is_active"] is True
        await p.scope.user(8)
        await p.scope.user(8)
    counts = Counter(path for _, path in p.calls)
    assert counts["users/11"] == before + 1 and counts["users/8"] == 2
    assert p.guard.scope_bot_user() is None
    await p.scope.user(11)
    assert Counter(path for _, path in p.calls)["users/11"] == before + 2


@pytest.mark.parametrize(
    "fault", ["child-task", "guard", "attestation", "qualification", "deadline"]
)
async def test_scope_bot_record_rejects_inherited_or_changed_identity_context(identity_peer, fault):
    p = identity_peer
    p.me["is_active"] = True
    p.state["latency"] = 0
    old_guard, old_attestation, old_qualification = (
        p.client.verify_identity,
        p.client.attestation,
        p.guard.qualification,
    )
    from contextlib import nullcontext

    rejected_exit = pytest.raises(ZulipError) if fault == "deadline" else nullcontext()
    with rejected_exit:
        async with p.guard.scope_reads():
            before = len(p.calls)
            if fault == "child-task":

                async def child():
                    return p.guard.scope_bot_user()

                with pytest.raises(ZulipError):
                    await asyncio.create_task(child())
            else:
                if fault == "guard":
                    p.client.verify_identity = AsyncMock(return_value=True)
                elif fault == "attestation":
                    p.client.attestation = replace(p.client.attestation)
                elif fault == "qualification":
                    p.guard.qualification = SimpleNamespace(**vars(p.guard.qualification))
                else:
                    p.clock[0] += 10.01
                with pytest.raises(ZulipError):
                    p.guard.scope_bot_user()
            assert len(p.calls) == before
            p.client.verify_identity, p.client.attestation, p.guard.qualification = (
                old_guard,
                old_attestation,
                old_qualification,
            )
            if fault == "deadline":
                # The outer context also rejects this expired state. Never rewind
                # the clock or extend/renew the operation's actual expiry.
                with pytest.raises(ZulipError):
                    await p.guard.scope_read()


async def test_closed_topic_anchor_uses_only_actual_side_get_and_fresh_catalog_without_narrow(
    identity_peer,
):
    p = identity_peer
    source, reader = operation_source(p), ZulipSourceReader(p.scope, expected)
    admitted = []

    async def read_only(audience):
        counts = Counter(path for _, path in p.calls)
        assert counts["messages/19"] == counts["users/me/4/topics"] == 1
        assert counts["messages"] == 0
        assert counts["streams/4/members"] == counts["users/8"] == counts["users/9"] == 1
        admitted.append(audience)
        return "only-read-after-positive-source-and-topic"

    handle = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    completed = p.scope.consume_observation(handle, reader, (source,))
    counts = Counter(path for _, path in p.calls)
    assert counts["messages"] == 0
    assert counts["messages/19"] == counts["users/me/4/topics"] == 2
    assert counts["streams/4/members"] == counts["users/8"] == counts["users/9"] == 2
    assert len(p.calls) == 18
    assert completed.audience == admitted[0] and completed.value.startswith("only-read-after")


async def test_closed_topic_unknown_maximum_keeps_original_narrow_and_second_catalog(identity_peer):
    import copy

    p = identity_peer
    source, reader = operation_source(p), ZulipSourceReader(p.scope, expected)
    latest = copy.deepcopy(p.server.raw)
    latest["id"] = 20
    p.server.topics[0]["max_id"] = 20  # This ID has not been GET-read as an original source.
    original = p.server.handle

    def handle(request):
        if request.url.path.endswith("/api/v1/messages"):
            return httpx.Response(200, json={"result": "success", "messages": [latest]})
        return original(request)

    p.server.handle = handle
    callback = AsyncMock(return_value="original fallback")
    result = await p.scope.observe_sources(reader, (source,), read_only=callback)
    assert p.scope.consume_observation(result, reader, (source,)).value == "original fallback"
    counts = Counter(path for _, path in p.calls)
    assert counts["messages"] == 2 and counts["users/me/4/topics"] == 4
    assert counts["messages/19"] == counts["streams/4/members"] == counts["users/8"] == 2
    callback.assert_awaited_once()


@pytest.mark.parametrize("empty_first", [False, True])
async def test_closed_topic_positive_allows_unrelated_empty_topic_with_distinct_maximum(
    identity_peer, empty_first
):
    p = identity_peer
    source, reader = operation_source(p), ZulipSourceReader(p.scope, expected)
    empty = {"name": "", "max_id": 20}
    p.server.topics.insert(0 if empty_first else 1, empty)
    admitted = []

    async def read_only(audience):
        counts = Counter(path for _, path in p.calls)
        assert counts["messages/19"] == counts["users/me/4/topics"] == 1
        assert counts["messages"] == 0
        admitted.append(audience)
        return "unrelated empty topic is not the current source topic"

    handle = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    completed = p.scope.consume_observation(handle, reader, (source,))
    counts = Counter(path for _, path in p.calls)
    assert completed.value == "unrelated empty topic is not the current source topic"
    assert completed.audience == admitted[0]
    assert counts["messages"] == 0
    assert counts["messages/19"] == counts["users/me/4/topics"] == 2
    assert counts["streams/4/members"] == counts["users/8"] == counts["users/9"] == 2
    assert len(p.calls) == 18


@pytest.mark.parametrize(
    "catalog",
    [
        None,
        {},
        [],
        [{"name": "CanonicalTopic", "max_id": True}],
        [{"name": "CanonicalTopic", "max_id": "19"}],
        [{"name": "CanonicalTopic", "max_id": 0}],
        [{"name": "CanonicalTopic", "max_id": 10**18}],
        [{"name": None, "max_id": 19}],
        [{"name": "", "max_id": 19}],
        [{"name": "x" * 61, "max_id": 19}],
        [{"name": "canonicaltopic", "max_id": 19}],
        [{"name": "CanonicalTopic", "max_id": 19}, {"name": "Other", "max_id": 19}],
        [{"name": "CanonicalTopic", "max_id": 19}, {"name": "CanonicalTopic", "max_id": 20}],
        [{"name": "CanonicalTopic", "max_id": 19}, {"name": "Malformed later", "max_id": False}],
        [{"name": "Topic" + str(n), "max_id": n + 1} for n in range(10001)],
    ],
    ids=[
        "missing",
        "object",
        "empty",
        "bool-id",
        "string-id",
        "zero-id",
        "large-id",
        "name-type",
        "empty-name",
        "long-name",
        "alias",
        "duplicate-id",
        "duplicate-name",
        "invalid-after-positive",
        "oversized",
    ],
)
async def test_closed_topic_catalog_never_admits_native_callback_from_invalid_positive(
    identity_peer, catalog
):
    p = identity_peer
    p.server.topics = catalog
    callback = AsyncMock(return_value="forbidden")
    with pytest.raises(ZulipError):
        await p.scope.observe_sources(
            ZulipSourceReader(p.scope, expected), (operation_source(p),), read_only=callback
        )
    callback.assert_not_awaited()
    counts = Counter(path for _, path in p.calls)
    assert counts["messages/19"] == counts["users/me/4/topics"] == 1
    assert counts["messages"] == 0


async def test_closed_topic_exact_actual_bot_get_can_be_catalog_positive_maximum(identity_peer):
    import copy

    from jt_oz_bridge.domain.execution import HumanMessage

    p = identity_peer
    original = p.server.handle
    preview = copy.deepcopy(p.server.raw)
    preview.update(id=20, sender_id=11, content="actual original Bot preview")
    p.server.topics[0]["max_id"] = 20

    def handle(request):
        if request.url.path.endswith("/messages/20"):
            return httpx.Response(200, json={"result": "success", "message": preview})
        return original(request)

    p.server.handle = handle

    async def index(realm, message_id):
        return 4 if realm == "2" and message_id in {19, 20} else None

    reader = ZulipSourceReader(p.scope, index)
    sources = (
        operation_source(p),
        HumanMessage(
            realm_id="2",
            channel_id=4,
            topic="CanonicalTopic",
            message_id=20,
            revision=0,
            author_id=11,
            text=preview["content"],
            is_bot=True,
        ),
    )
    result = await p.scope.observe_sources(reader, sources, read_only=AsyncMock(return_value=17))
    assert p.scope.consume_observation(result, reader, sources).value == 17
    counts = Counter(path for _, path in p.calls)
    assert counts["messages/19"] == counts["messages/20"] == counts["users/me/4/topics"] == 2
    assert counts["messages"] == 0


@pytest.mark.parametrize("field", ["subject", "content", "sender_id", "edit_history"])
async def test_closed_topic_positive_requires_actual_source_match_before_any_catalog(
    identity_peer, field
):
    p = identity_peer
    p.server.raw[field] = {
        "subject": "Other",
        "content": "edited",
        "sender_id": 9,
        "edit_history": [{}],
    }[field]
    callback = AsyncMock(return_value="forbidden")
    with pytest.raises(ZulipError):
        await p.scope.observe_sources(
            ZulipSourceReader(p.scope, expected), (operation_source(p),), read_only=callback
        )
    callback.assert_not_awaited()
    assert Counter(path for _, path in p.calls)["users/me/4/topics"] == 0


@pytest.mark.parametrize("fault", ["alias", "duplicate", "unknown-latest-alias"])
async def test_closed_topic_final_catalog_change_discards_completed_read_only_result(
    identity_peer, fault
):
    import copy

    p = identity_peer
    reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)
    original = p.server.handle

    async def read_only(_audience):
        if fault == "alias":
            p.server.topics[0]["name"] = "canonicaltopic"
        elif fault == "duplicate":
            p.server.topics.append(dict(p.server.topics[0]))
        else:
            p.server.topics = [{"name": "canonicaltopic", "max_id": 20}]
            latest = copy.deepcopy(p.server.raw)
            latest.update(id=20, subject="canonicaltopic")

            def handle(request):
                if request.url.path.endswith("/api/v1/messages"):
                    return httpx.Response(200, json={"result": "success", "messages": [latest]})
                return original(request)

            p.server.handle = handle
        return "private completed Native GET result"

    with pytest.raises(ZulipError):
        await p.scope.observe_sources(reader, (source,), read_only=read_only)
    assert not p.scope._observations
    counts = Counter(path for _, path in p.calls)
    assert counts["messages/19"] == 2
    assert counts["messages"] == (1 if fault == "unknown-latest-alias" else 0)


async def test_local_write_permission_requires_completed_source_sides_and_consumption(
    identity_peer,
):
    p = identity_peer
    reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)
    with pytest.raises(ZulipError):
        p.scope.local_write_permit(reader, source, await p.scope.inspect("2", 4, source.topic))
    p.calls.clear()

    async def read_only(audience):
        permit = p.scope.local_write_permit(reader, source, audience)
        p.scope.require_read_permit(permit, reader, source, audience)
        with pytest.raises(ZulipError):
            p.scope.require_write_permit(permit, reader, source, audience)
        return permit, audience

    observation = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    completed = p.scope.consume_observation(observation, reader, (source,))
    permit, audience = completed.value
    p.scope.require_write_permit(permit, reader, source, audience)
    with pytest.raises(ZulipError):
        p.scope.require_read_permit(permit, reader, source, audience)
    # Permission issuance/rechecks add no HTTP and retain both original sides.
    counts = Counter(path for _, path in p.calls)
    assert counts["messages/19"] == counts["streams/4/members"] == 2
    assert counts["users/8"] == counts["users/9"] == counts["users/11"] == 2
    assert counts["users/me"] == counts["server_settings"] == 2
    await asyncio.sleep(0)  # Local SQL awaits are allowed inside the bounded phase.
    p.scope.require_write_permit(permit, reader, source, audience)


@pytest.mark.parametrize(
    "fault", ["source-edit", "callback-error", "callback-cancel", "late-consume"]
)
async def test_failed_or_unconsumed_source_operation_never_authorizes_local_writes(
    identity_peer, fault
):
    p = identity_peer
    reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)
    issued = []

    async def read_only(audience):
        issued.append((p.scope.local_write_permit(reader, source, audience), audience))
        if fault == "source-edit":
            p.server.raw["content"] = "edited after original Native observation"
        elif fault == "callback-error":
            raise RuntimeError("read-only preparation failed")
        elif fault == "callback-cancel":
            raise asyncio.CancelledError
        return "unpublished original Native observation"

    if fault == "late-consume":
        observation = await p.scope.observe_sources(reader, (source,), read_only=read_only)
        await asyncio.sleep(0)
        with pytest.raises(ZulipError):
            p.scope.consume_observation(observation, reader, (source,))
    else:
        with pytest.raises((ZulipError, RuntimeError, asyncio.CancelledError)):
            await p.scope.observe_sources(reader, (source,), read_only=read_only)
    assert len(issued) == 1
    permit, audience = issued[0]
    with pytest.raises(ZulipError):
        p.scope.require_write_permit(permit, reader, source, audience)


@pytest.mark.parametrize(
    "fault", ["forged", "reader", "actor-copy", "audience-copy", "guard", "expiry", "task"]
)
async def test_closed_local_write_permission_is_task_bound_current_and_bounded(
    identity_peer, monkeypatch, fault
):
    from jt_oz_bridge.adapters.zulip import scope as module

    p = identity_peer
    reader, source = ZulipSourceReader(p.scope, expected), operation_source(p)

    async def read_only(audience):
        return p.scope.local_write_permit(reader, source, audience), audience

    observation = await p.scope.observe_sources(reader, (source,), read_only=read_only)
    permit, audience = p.scope.consume_observation(observation, reader, (source,)).value
    if fault == "forged":
        permit = module.ZulipLocalWritePermit()
    elif fault == "reader":
        reader = ZulipSourceReader(p.scope, expected)
    elif fault == "actor-copy":
        source = source.model_copy()
    elif fault == "audience-copy":
        audience = audience.model_copy()
    elif fault == "guard":
        p.client.verify_identity = AsyncMock(return_value=True)
    elif fault == "expiry":
        now = module.time.monotonic()
        monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: now + 5))

    async def require_rejected():
        with pytest.raises(ZulipError):
            p.scope.require_write_permit(permit, reader, source, audience)

    if fault == "task":
        await asyncio.create_task(require_rejected())
    else:
        await require_rejected()


@pytest.mark.parametrize(
    ("version", "level", "accepted"),
    [
        ("12.3", 500, True),
        ("12.5", 501, True),  # A security maintenance release keeps the enrollment.
        ("12.4", 500, True),
        ("12.2", 500, False),  # Older than the qualified release.
        ("12.5", 499, False),  # A feature level only grows.
        ("13.0", 510, False),  # A new major release needs its own qualification.
        ("12.5-dev+git", 501, False),  # So does a development build.
        ("12.5", "501", False),
        (None, 501, False),
    ],
)
async def test_a_later_maintenance_release_keeps_the_qualified_identity(
    identity_peer, caplog, version, level, accepted
):
    p = identity_peer
    p.settings["zulip_version"], p.settings["zulip_feature_level"] = version, level
    with caplog.at_level("WARNING", logger=runtime.__name__):
        assert await p.guard() is accepted
        p.clock[0] += 5
        assert await p.guard() is accepted
    refused = [
        r.getMessage() for r in caplog.records if "zulip_release_not_qualified" in r.getMessage()
    ]
    # Said once per release seen, never on every refusal.
    assert len(refused) == (0 if accepted else 1)
    if not accepted:
        assert refused[0].endswith("qualified=12.3/500")
