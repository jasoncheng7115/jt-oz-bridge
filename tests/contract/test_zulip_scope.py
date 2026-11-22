import copy
import json
from dataclasses import replace

import httpx
import pytest

from jt_oz_bridge.adapters.zulip.client import (
    ZulipAttestation,
    ZulipClient,
    ZulipError,
    ZulipReadUnavailable,
)
from jt_oz_bridge.adapters.zulip.scope import (
    SCOPE_OPERATIONS,
    ZulipScopeReader,
    ZulipSourceReader,
)

URL = "https://chat.example.invalid"


class Server:
    def __init__(self):
        self.stream = {
            "stream_id": 4,
            "invite_only": True,
            "is_web_public": False,
            "history_public_to_subscribers": False,
        }
        self.subscribers = [8, 9, 11]
        self.users = {
            n: {"user_id": n, "is_bot": n == 11, "is_active": True} for n in self.subscribers
        }
        self.raw = {
            "id": 19,
            "type": "stream",
            "stream_id": 4,
            "subject": "CanonicalTopic",
            "sender_id": 8,
            "content": "!oz status",
            "content_type": "text/x-markdown",
            "edit_history": [],
        }
        self.topics = [{"name": "CanonicalTopic", "max_id": 19}]
        self.calls = []
        self.counts = {}
        self.hook = lambda path, count: None

    def handle(self, request):
        path = request.url.path.removeprefix("/api/v1/")
        self.calls.append((request.method, path))
        assert request.method == "GET"
        self.counts[path] = self.counts.get(path, 0) + 1
        self.hook(path, self.counts[path])
        if path == "streams/4":
            value = {"stream": self.stream}
        elif path == "streams/4/members":
            value = {"subscribers": self.subscribers}
        elif path == "users/me/4/topics":
            value = {"topics": self.topics}
        elif path.startswith("users/"):
            value = {"user": self.users[int(path.split("/")[1])]}
        elif path == "messages":
            narrow = json.loads(request.url.params["narrow"])
            assert narrow[0] == {"operator": "channel", "operand": 4}
            assert request.url.params["apply_markdown"] == "false"
            value = {"messages": [self.raw]}
        elif path == "messages/19":
            value = {"message": self.raw}
        else:
            raise AssertionError(path)
        return httpx.Response(200, json={"result": "success", **copy.deepcopy(value)})


@pytest.fixture
async def pair():
    server = Server()

    async def identity():
        return True

    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "private-test-key",
        attestation=ZulipAttestation(
            URL, "2", 11, 500, 10000, 60, verified_scope_operations=SCOPE_OPERATIONS
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(server.handle),
    )
    reader = ZulipScopeReader(client, channel_ids=frozenset({4}))
    try:
        yield server, reader
    finally:
        await client.close()


async def test_complete_private_audience_and_positive_server_alias_resolution(pair):
    server, reader = pair
    a = await reader.inspect("2", 4, "CANONICALtopic")
    assert a.canonical_topic == "CanonicalTopic"
    assert a.user_ids == {8, 9} and a.private and not a.untrusted_bot_ids
    assert a == await reader.inspect("2", 4, "CanonicalTopic")
    assert all(method == "GET" for method, _ in server.calls)


@pytest.mark.parametrize("ids", [[], [8, 9], [8, 9, 11, 11], [8, "9", 11], [8, True, 11]])
async def test_incomplete_duplicate_or_coerced_membership_is_not_authority(pair, ids):
    server, reader = pair
    server.subscribers = ids
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")


@pytest.mark.parametrize(
    "key,value",
    [
        ("invite_only", False),
        ("invite_only", "true"),
        ("is_web_public", True),
        ("is_web_public", 0),
        ("history_public_to_subscribers", "false"),
        ("stream_id", "4"),
        ("stream_id", 5),
        ("is_archived", True),
    ],
)
async def test_public_or_malformed_channel_never_proves_private_scope(pair, key, value):
    server, reader = pair
    server.stream[key] = value
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")


async def test_other_bots_are_reported_untrusted_instead_of_treated_as_humans(pair):
    server, reader = pair
    server.subscribers.append(12)
    server.users[12] = {"user_id": 12, "is_bot": True, "is_active": True}
    a = await reader.inspect("2", 4, "CanonicalTopic")
    assert a.user_ids == {8, 9} and a.untrusted_bot_ids == {12}


@pytest.mark.parametrize(
    "member,key,value",
    [(8, "is_active", False), (9, "is_bot", 0), (11, "is_bot", False), (8, "user_id", 9)],
)
async def test_user_activity_types_and_dedicated_bot_identity_are_positive_evidence(
    pair, member, key, value
):
    server, reader = pair
    server.users[member][key] = value
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")


@pytest.mark.parametrize("mutation", ["members", "privacy", "user", "topic"])
async def test_midinspection_changes_refuse_instead_of_returning_a_mixed_snapshot(pair, mutation):
    server, reader = pair

    def hook(path, count):
        if mutation == "members" and path == "streams/4/members" and count == 2:
            server.subscribers = [8, 11]
        if mutation == "privacy" and path == "streams/4" and count == 2:
            server.stream["history_public_to_subscribers"] = True
        if mutation == "user" and path == "users/9" and count == 2:
            server.users[9]["is_bot"] = True
        if mutation == "topic" and path == "messages" and count == 2:
            server.raw["subject"] = "MovedTopic"
            server.topics[0]["name"] = "MovedTopic"

    server.hook = hook
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")


@pytest.mark.parametrize(
    "bad", ["wrong_max_id", "wrong_subject", "duplicate_id", "duplicate_name", "html"]
)
async def test_topic_resolution_needs_matching_server_catalog_and_raw_latest_message(pair, bad):
    server, reader = pair
    if bad == "wrong_max_id":
        server.topics[0]["max_id"] = 18
    elif bad == "wrong_subject":
        server.raw["subject"] = "AnotherTopic"
    elif bad == "duplicate_id":
        server.topics.append({"name": "Other", "max_id": 19})
    elif bad == "duplicate_name":
        server.topics.append({"name": "CanonicalTopic", "max_id": 20})
    elif bad == "html":
        server.raw["content_type"] = "text/html"
    with pytest.raises(ZulipError):
        await reader.inspect("2", 4, "CanonicalTopic")


@pytest.mark.parametrize("realm,channel", [("3", 4), ("2", 5), ("2", True)])
async def test_other_scopes_refuse_before_any_request(pair, realm, channel):
    server, reader = pair
    with pytest.raises(ZulipError):
        await reader.inspect(realm, channel, "CanonicalTopic")
    assert not server.calls


async def expected(realm, message_id):
    return 4 if (realm, message_id) == ("2", 19) else None


async def test_original_source_uses_active_server_identity_and_native_edit_count(pair):
    server, scope = pair
    server.raw.update(edit_history=[{}, {}], last_edit_timestamp=100)
    source = await ZulipSourceReader(scope, expected).read("2", 19)
    assert source.revision == 2 and source.author_id == 8
    assert source.text == "!oz status" and source.topic == "CanonicalTopic"
    assert not source.is_bot and not source.deleted
    assert server.counts["messages/19"] == 2 and server.counts["users/8"] == 2


async def test_actual_bot_author_is_not_relabelled_as_human(pair):
    server, scope = pair
    server.raw["sender_id"] = 11
    assert (await ZulipSourceReader(scope, expected).read("2", 19)).is_bot


@pytest.mark.parametrize(
    "change", ["text", "channel", "topic", "revision", "author_bot", "deactivated"]
)
async def test_source_change_between_reads_never_becomes_a_stable_human_command(pair, change):
    server, scope = pair

    def hook(path, count):
        if path == "messages/19" and count == 2:
            if change == "text":
                server.raw["content"] = "!oz stop"
            elif change == "channel":
                server.raw["stream_id"] = 5
            elif change == "topic":
                server.raw["subject"] = "Other"
            elif change == "revision":
                server.raw.update(edit_history=[{}], last_edit_timestamp=100)
            elif change == "author_bot":
                server.users[8]["is_bot"] = True
            elif change == "deactivated":
                server.users[8]["is_active"] = False

    server.hook = hook
    with pytest.raises(ZulipError):
        await ZulipSourceReader(scope, expected).read("2", 19)


async def test_edited_source_without_native_revision_history_refuses(pair):
    server, scope = pair
    server.raw["last_edit_timestamp"] = 100
    with pytest.raises(ZulipError):
        await ZulipSourceReader(scope, expected).read("2", 19)


async def test_message_without_a_trusted_event_or_receipt_scope_is_not_fetched(pair):
    server, scope = pair
    with pytest.raises(ZulipError):
        await ZulipSourceReader(scope, expected).read("2", 20)
    assert not server.calls


async def test_changed_expected_scope_is_not_redirected_to_another_channel(pair):
    server, scope = pair
    calls = 0

    async def index(realm, message_id):
        nonlocal calls
        calls += 1
        return 4 if calls == 1 else 5

    with pytest.raises(ZulipError):
        await ZulipSourceReader(scope, index).read("2", 19)
    assert not any("streams/5" in path for _, path in server.calls)


async def test_scope_attestation_change_or_failed_identity_prevents_source_fetch(pair):
    server, scope = pair
    scope.client.attestation = replace(scope.enrolled, realm_id="other")
    with pytest.raises(ZulipError):
        await ZulipSourceReader(scope, expected).read("2", 19)
    scope.client.attestation = scope.enrolled

    async def false():
        return False

    scope.client.verify_identity = false
    with pytest.raises(ZulipError):
        await ZulipSourceReader(scope, expected).read("2", 19)
    assert not server.calls


@pytest.mark.parametrize(
    "route", ["streams/4", "streams/4/members", "users/8", "users/me/4/topics"]
)
async def test_new_resource_routes_require_their_own_explicit_qualification(pair, route):
    server, scope = pair
    scope.client.attestation = replace(scope.enrolled, verified_scope_operations=frozenset())
    with pytest.raises(ZulipError):
        await scope.client.request("GET", route)
    assert not server.calls


async def test_no_global_user_directory_or_guessable_resource_alias_is_added(pair):
    server, scope = pair
    for route in [
        "users",
        "streams/04",
        "users/8?x=1",
        "streams/4/members/../5",
        "users/me/0/topics",
    ]:
        with pytest.raises(ZulipError):
            await scope.client.request("GET", route)
    assert not server.calls


async def test_topic_head_append_rechecks_server_canonical_proof_without_retargeting(pair):
    server, reader = pair

    def append(path, count):
        if path == "users/me/4/topics" and count == 1:
            # The narrow already returned id19. A legitimate newer message
            # arrives before the independent topic catalog GET completes.
            server.raw = {**server.raw, "id": 20, "content": "new concurrent message"}
            server.topics = [{"name": "CanonicalTopic", "max_id": 20}]

    server.hook = append
    audience = await reader.inspect("2", 4, "CANONICALtopic")
    assert audience.canonical_topic == "CanonicalTopic"
    assert audience.user_ids == frozenset({8, 9})
    assert server.counts["messages"] == server.counts["users/me/4/topics"] == 3
    assert all(method == "GET" for method, _ in server.calls)


async def test_continuously_advancing_topic_head_is_bounded_transient_read_only(pair):
    server, reader = pair

    def append(path, count):
        if path == "users/me/4/topics":
            next_id = 19 + count
            server.raw = {**server.raw, "id": next_id}
            server.topics = [{"name": "CanonicalTopic", "max_id": next_id}]

    server.hook = append
    with pytest.raises(ZulipReadUnavailable, match="topic_head_changed_during_resolution"):
        await reader.inspect("2", 4, "CanonicalTopic")
    assert server.counts["messages"] == server.counts["users/me/4/topics"] == 2
    assert all(method == "GET" for method, _ in server.calls)


@pytest.mark.parametrize("mutation", ["members", "privacy", "user", "topic", "wrong_id"])
async def test_topic_append_retry_cannot_hide_changed_scope_or_catalog(pair, mutation):
    server, reader = pair

    def change(path, count):
        if path == "users/me/4/topics" and count == 1:
            server.raw = {**server.raw, "id": 20}
            server.topics = [{"name": "CanonicalTopic", "max_id": 20}]
        if path == "messages" and count == 2:
            if mutation == "members":
                server.subscribers = [8, 11]
            elif mutation == "privacy":
                server.stream["is_web_public"] = True
            elif mutation == "user":
                server.users[9]["is_active"] = False
            elif mutation == "topic":
                server.raw["subject"] = "Different topic"
            else:
                server.topics = [{"name": "Different topic", "max_id": 20}]

    server.hook = change
    with pytest.raises(ZulipError) as error:
        await reader.inspect("2", 4, "CanonicalTopic")
    assert not isinstance(error.value, ZulipReadUnavailable)
    assert all(method == "GET" for method, _ in server.calls)
