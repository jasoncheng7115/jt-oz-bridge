"""Synthetic server/domain composition: no installed-human or phone certificate."""

import copy
import time
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import func, select, update

from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient, ZulipError
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader, ZulipSourceReader
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.zulip_consumer import (
    EVENT_OPERATIONS,
    UNCLEAR_PAUSE_RECHECK_SECONDS,
    ZulipCommandConsumer,
)
from jt_oz_bridge.services.zulip_events import ZulipEventJournal
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, InputEvent
from tests.support import bound

URL = "https://chat.example.invalid"


class Server:
    def __init__(self):
        self.events = []
        self.messages = {}
        self.calls = []
        self.private = True
        self.identity = True
        self.expired = False
        self.bots = {11}
        self.deleted = set()
        self.hook = lambda request: None
        self.topic_history = []
        self.posted = []

    def message(self, text="!oz help", mid=101, author=7):
        m = {
            "id": mid,
            "type": "stream",
            "stream_id": 10,
            "subject": "Original work",
            "sender_id": author,
            "content": text,
            "content_type": "text/x-markdown",
            "edit_history": [],
        }
        self.messages[mid] = m
        return copy.deepcopy(m)

    def event(self, text="!oz help", eid=0, mid=101, author=7):
        e = {"id": eid, "type": "message", "message": self.message(text, mid, author)}
        self.events.append(e)
        return e

    def handle(self, request):
        route = request.url.path.removeprefix("/api/v1/")
        self.calls.append((request.method, route))
        self.hook(request)
        if request.method == "POST" and route == "register":
            from urllib.parse import parse_qs

            p = parse_qs(request.content.decode())
            assert (
                p["apply_markdown"] == ["false"]
                and p["all_public_streams"] == ["false"]
                and p["fetch_event_types"] in (["[]"], ['["realm"]'])
            )
            assert "narrow" not in p
            data = {"queue_id": "native-queue", "last_event_id": -1}
        elif request.method == "DELETE" and route == "events":
            data = {}
        elif route == "events":
            if self.expired:
                return httpx.Response(
                    400, json={"result": "error", "code": "BAD_EVENT_QUEUE_ID", "msg": "expired"}
                )
            last = int(request.url.params["last_event_id"])
            data = {"events": [e for e in self.events if e["id"] > last]}
        elif route == "streams/10":
            data = {
                "stream": {
                    "stream_id": 10,
                    "invite_only": self.private,
                    "is_web_public": False,
                    "history_public_to_subscribers": False,
                }
            }
        elif route == "streams/10/members":
            data = {"subscribers": [7, 8, 11]}
        elif route.startswith("users/"):
            uid = int(route.split("/")[1])
            data = {"user": {"user_id": uid, "is_active": True, "is_bot": uid in self.bots}}
        elif request.method == "POST" and route == "messages":
            from urllib.parse import parse_qs

            p = parse_qs(request.content.decode(), keep_blank_values=True)
            self.posted.append({k: v[0] for k, v in p.items()})
            data = {"id": 900 + len(self.posted)}
        elif route == "messages":
            data = {"messages": self.topic_history}
        elif route.startswith("messages/"):
            mid = int(route.split("/")[1])
            if mid in self.deleted:
                return httpx.Response(404, json={"result": "error", "msg": "gone"})
            data = {"message": self.messages[mid]}
        else:
            raise AssertionError(route)
        return httpx.Response(200, json={"result": "success", **copy.deepcopy(data)})


async def setup(db, *, publisher=None):
    bindings, b, control, _ = await bound(db)
    server = Server()

    async def identity():
        return server.identity

    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic-private-key",
        attestation=ZulipAttestation(
            URL,
            "realm",
            11,
            500,
            10000,
            60,
            verified_scope_operations=SCOPE_OPERATIONS,
            verified_event_operations=EVENT_OPERATIONS | {"cleanup"},
        ),
        verify_identity=identity,
        transport=httpx.MockTransport(server.handle),
    )
    scope = ZulipScopeReader(client, channel_ids=frozenset({10}))
    f = await DurableStore(db).acquire_lease("consumer")
    assert f
    journal = ZulipEventJournal(
        db,
        ConsumerFence("consumer", f),
        realm_id="realm",
        bot_user_id=11,
        url=URL,
        channel_ids=frozenset({10}),
    )
    reader = ZulipSourceReader(scope, journal.expected_channel)
    router = CommandRouter(bindings, reader, CommandInbox(db, "consumer", f))
    c = ZulipCommandConsumer(scope, reader, journal, router, publish=publisher)
    await c.start()
    return c, server, b, control


async def count(db, table):
    async with db.sessions() as s:
        return await s.scalar(select(func.count()).select_from(table))


async def test_real_source_reads_into_existing_help_router_and_local_reply_publisher(db):
    published = []

    async def publish(routed):
        published.append(routed)

    c, s, b, control = await setup(db, publisher=publish)
    try:
        s.event()
        states = await c.poll()
        assert states == ("reply",) and len(published) == 1 and "!stop" in published[0].text
        assert published[0].binding_id == b.id and await count(db, Action) == 0
        assert (await c.poll()) == ()
        assert len([call for call in s.calls if call == ("GET", "messages/101")]) >= 4
        assert not any(
            m in {"PATCH", "PUT"} or (m == "POST" and path != "register") for m, path in s.calls
        )
    finally:
        await c.close()
        await c.scope.client.close()


async def test_fresh_prompt_only_queues_once_without_executing_native_or_replaying(db):
    c, s, b, control = await setup(db)
    try:
        s.event("Do the scoped test task.")
        assert (await c.poll()) == ("ignore",)
        assert await count(db, Action) == 1
        await c.drain()
        assert await count(db, Action) == 1
        async with db.sessions() as sess:
            a = await sess.scalar(select(Action))
        assert a.state == "queued" and a.owner == "bridge"
    finally:
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("author", [11, 13])
async def test_bot_classification_is_truthful_and_no_bot_output_becomes_a_prompt(db, author):
    c, s, b, control = await setup(db)
    s.bots.add(author)
    try:
        s.event("!oz send erase everything", author=author)
        assert await c.poll() == ("ignored",)
        assert await count(db, Action) == 0
        if author == 11:
            assert ("GET", "messages/101") not in s.calls
    finally:
        await c.close()
        await c.scope.client.close()


async def test_active_ungranted_human_is_held_without_output_or_action(db):
    publish = AsyncMock()
    c, s, b, control = await setup(db, publisher=publish)
    try:
        s.event("Do the task", author=13)
        assert await c.poll() == ("held",)
        assert await count(db, Action) == 0 and publish.await_count == 0
        assert s.posted == []  # A refused author still gets no reply.
    finally:
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("change", ["text", "author", "topic", "revision", "deleted"])
async def test_original_source_change_or_delete_never_authorizes_wire_prompt(db, change):
    c, s, b, control = await setup(db)
    try:
        s.event("Do the task")
        if change == "text":
            s.messages[101]["content"] = "different task"
        elif change == "author":
            s.messages[101]["sender_id"] = 8
        elif change == "topic":
            s.messages[101]["subject"] = "Different"
        elif change == "revision":
            s.messages[101]["edit_history"] = [{"timestamp": 1}]
            s.messages[101]["last_edit_timestamp"] = 1
        else:
            s.deleted.add(101)
        assert await c.poll() == ("held",)
        assert await count(db, Action) == 0
    finally:
        await c.close()
        await c.scope.client.close()


async def test_create_followed_by_delete_same_batch_does_not_fetch_or_queue_deleted_human(db):
    c, s, b, control = await setup(db)
    try:
        s.event("Do task")
        s.events.append({"id": 1, "type": "delete_message", "message_id": 101, "stream_id": 10})
        assert await c.poll() == ("held", "ignored")
        assert ("GET", "messages/101") not in s.calls and await count(db, Action) == 0
        assert await c.journal.expected_channel("realm", 101) is None
    finally:
        await c.close()
        await c.scope.client.close()


async def test_historical_message_is_held_as_recovered_intent(db):
    c, s, b, control = await setup(db)
    try:
        s.event("Do task")["historical"] = True
        await c.poll()
        async with db.sessions() as sess:
            a = await sess.scalar(select(Action))
        assert a and a.state == "held"
    finally:
        await c.close()
        await c.scope.client.close()


async def test_general_chat_gets_one_name_a_topic_notice_and_never_routes(db):
    publish = AsyncMock()
    c, s, b, control = await setup(db, publisher=publish)
    try:
        s.event("hi")
        s.messages[101]["subject"] = ""
        s.events[-1]["message"]["subject"] = ""
        s.event("!go", eid=1, mid=102)["historical"] = True
        s.messages[102]["subject"] = ""
        s.events[-1]["message"]["subject"] = ""
        assert await c.poll() == ("ignored", "ignored")
        assert await count(db, Action) == 0 and publish.await_count == 0
        assert len(s.posted) == 1  # Not for the historical one.
        assert s.posted[0]["topic"] == "" and "general chat" in s.posted[0]["content"]
    finally:
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("refused", [False, True])
async def test_routing_error_holds_with_a_log_and_tells_the_person(db, caplog, refused):
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.durable import Conflict

    publish = AsyncMock()
    c, s, b, control = await setup(db, publisher=publish)
    original = c.router.route
    error = AccessDenied("grant_required") if refused else Conflict("root_watch_lost")
    c.router.route = AsyncMock(side_effect=error)
    try:
        s.event("!go")
        with caplog.at_level("WARNING"):
            assert await c.poll() == ("held",)
        code = "grant_required" if refused else "root_watch_lost"
        assert f"stage=routing error_type={type(error).__name__} code={code}" in caplog.text
        if refused:
            assert s.posted == []
        else:
            assert len(s.posted) == 1 and "root_watch_lost" in s.posted[0]["content"]
            assert s.posted[0]["topic"] == "Original work"
    finally:
        c.router.route = original
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("closed", [False, True])
async def test_a_conversation_gap_tells_the_person_to_reconnect(db, closed):
    from jt_oz_bridge.storage.durable import Conflict

    c, s, b, control = await setup(db, publisher=AsyncMock())
    name = "route_closed_menu_event" if closed else "route"
    original = getattr(c.router, name)
    setattr(
        c.router,
        name,
        AsyncMock(side_effect=Conflict("transcript_gap_requires_review_and_rebind")),
    )
    try:
        s.event("!go")
        assert await c.poll() == ("held",)
        assert len(s.posted) == 1 and "!ok" in s.posted[0]["content"]
        assert s.posted[0]["content"].startswith(c.router.tr.render("router.gap_go", "en"))
    finally:
        setattr(c.router, name, original)
        await c.close()
        await c.scope.client.close()


async def test_foreign_channel_and_dm_never_trigger_source_fetch(db):
    c, s, b, control = await setup(db)
    try:
        e = s.event("foreign secret")
        e["message"]["stream_id"] = 99
        f = s.event("dm secret", eid=1, mid=102)
        f["message"]["type"] = "private"
        assert await c.poll() == ("ignored", "ignored")
        assert not any(path.startswith("messages/") for method, path in s.calls)
        assert await count(db, Action) == 0
    finally:
        await c.close()
        await c.scope.client.close()


async def test_queue_expiry_pauses_binding_and_does_not_silently_reregister(db):
    c, s, b, control = await setup(db)
    s.expired = True
    try:
        with pytest.raises(ZulipError, match="queue_expired"):
            await c.poll()
        assert c.queue_id is None
        async with db.sessions() as sess:
            assert (await sess.get(Binding, b.id)).dispatch_paused
        assert s.calls.count(("POST", "register")) == 1
    finally:
        await c.scope.client.close()


async def restart_pause_state(db, c, b, queue="queue-after-restart"):
    # A restart in place: a new Zulip queue for the same consumer fence.
    c.queue_id = queue
    await c.journal.enroll(queue, -1)
    async with db.sessions() as session:
        assert (await session.get(Binding, b.id)).dispatch_paused
    await c._release_restart_pauses()
    async with db.sessions() as session:
        return (await session.get(Binding, b.id)).dispatch_paused


def history(s, mid, text="Do the task while away", *, author=7, age=0.0, edited=False):
    """One message as GET /messages returns it, sent ``age`` seconds ago."""
    m = s.message(text, mid, author)
    m["timestamp"] = int(time.time() - age)
    if edited:
        m["last_edit_timestamp"] = m["timestamp"]
        s.messages[mid]["last_edit_timestamp"] = m["timestamp"]
    return m


def said(key):
    from jt_oz_bridge.i18n import Translator

    return Translator().render(key, "en")


async def waiting_prompt(db, c, s, *, age=0.0, reason=None, revision_delta=0):
    """A prompt queued before the restart, then held by startup recovery."""
    s.event("Do the scoped test task.")
    await c.poll()
    await DurableStore(db).recover()
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).values(
                created_at=Action.created_at - age,
                status_reason=reason,
                binding_revision=Action.binding_revision + revision_delta,
            )
        )
    s.events.clear()
    async with db.sessions() as session:
        return await session.scalar(select(Action))


async def test_restart_that_missed_nothing_does_not_stop_the_topic(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        s.topic_history = [history(s, 900, "Bridge output", author=11)]  # Only the Bot's own.
        assert await restart_pause_state(db, c, b) is False
        assert s.posted == []
    finally:
        await c.scope.client.close()


async def test_a_message_sent_during_a_short_outage_goes_out_when_bridge_returns(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        s.topic_history = [history(s, 150, age=60)]
        assert await restart_pause_state(db, c, b) is False
        assert s.posted == [] and await count(db, Action) == 0
        # The normal path reads the message again before anything is queued.
        assert await c.poll() == ("ignore",)
        assert ("GET", "messages/150") in s.calls
        async with db.sessions() as session:
            action = await session.scalar(select(Action))
        assert action.state == "queued" and action.payload["source"]["message_id"] == 150
        # Seen now: another restart neither captures nor reports it again.
        assert await restart_pause_state(db, c, b, "queue-after-second-restart") is False
        assert await count(db, Action) == 1 and s.posted == []
    finally:
        await c.scope.client.close()


async def test_a_missed_message_that_changed_is_never_sent(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        s.topic_history = [history(s, 150, age=60)]
        s.messages[150]["content"] = "something else"  # Changed after the GET.
        assert await restart_pause_state(db, c, b) is False
        assert await c.poll() == ("held",)
        assert await count(db, Action) == 0
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize("old", ["age", "edited"])
async def test_older_missed_messages_get_one_reply_and_are_not_sent(db, old):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        s.topic_history = [history(s, 150, age=900 if old == "age" else 60, edited=old == "edited")]
        assert await restart_pause_state(db, c, b) is False
        assert await c.poll() == () and await count(db, Action) == 0
        assert len(s.posted) == 1 and said("router.restart_missed") in s.posted[0]["content"]
        assert s.posted[0]["topic"] == "Original work"
        # A retry of the same restart finds its own reply instead of posting twice.
        s.topic_history.append({**history(s, 951, s.posted[0]["content"], author=11), "id": 951})
        async with db.sessions() as session:
            binding = await session.get(Binding, b.id)
        await c._topic_notice(binding, ["router.restart_missed"])
        assert len(s.posted) == 1
    finally:
        await c.scope.client.close()


async def test_a_message_missed_in_an_outage_days_ago_is_not_reported_again(db):
    # 11-25: a restart told the topic about two messages missed in the 11-14 outage.
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        s.topic_history = [history(s, 150, age=2 * 86400)]
        assert await restart_pause_state(db, c, b) is False
        assert await c.poll() == () and await count(db, Action) == 0
        assert s.posted == []
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize("reason", [None, "queue_paused"])
async def test_work_the_restart_held_goes_out_again(db, reason):
    from jt_oz_bridge.storage.models import AuditEvent

    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=60, reason=reason)
        assert held.state == "held"
        s.topic_history = [history(s, 101, "Do the scoped test task.")]  # Captured before.
        assert await restart_pause_state(db, c, b) is False
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == "queued"
            events = list(await session.scalars(select(AuditEvent.event)))
        assert "queue_resumed_after_restart" in events and s.posted == []
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize(
    ("age", "edited", "state"), [(30, False, "queued"), (900, False, "held"), (30, True, None)]
)
async def test_a_recent_message_the_restart_cut_off_goes_out_like_a_new_one(db, age, edited, state):
    """Captured by the previous process but never begun: recent and unedited is fresh."""
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        event = s.event("Do the scoped test task.")
        event["message"]["timestamp"] = int(time.time() - age)
        if edited:
            event["message"]["last_edit_timestamp"] = event["message"]["timestamp"]
        await c.journal.capture(c.queue_id, [event])
        s.events.clear()
        s.topic_history = [history(s, 101, "Do the scoped test task.", age=age)]
        assert await restart_pause_state(db, c, b) is False
        await c.drain()
        async with db.sessions() as session:
            action = await session.scalar(select(Action))
        # Older or edited ones stay recovered intent: never sent on their own.
        assert (action.state if action else None) == state
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize(("age", "reason"), [(900, None), (60, "installed_contract_not_certified")])
async def test_older_waiting_work_keeps_the_pause_and_asks_once(db, age, reason):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=age, reason=reason)
        # A recent missed message would let the older one go along: it is not sent.
        s.topic_history = [history(s, 150, age=30)]
        assert await restart_pause_state(db, c, b) is True
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == "held"
        assert await c.journal.expected_channel("realm", 150) is None
        assert len(s.posted) == 1
        assert said("router.restart_waiting") in s.posted[0]["content"]
        assert said("router.restart_missed") in s.posted[0]["content"]
    finally:
        await c.scope.client.close()


async def test_held_work_of_an_older_topic_revision_does_not_keep_the_pause(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=900, revision_delta=-1)
        assert await restart_pause_state(db, c, b) is False
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == "held"
        assert s.posted == []
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize("state", ["dispatching", "ambiguous"])
async def test_restart_with_unclear_work_keeps_the_pause(db, state):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=60)
        async with db.sessions.begin() as session:
            await session.execute(update(Action).values(state=state))
        assert await restart_pause_state(db, c, b) is True
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == state
    finally:
        await c.scope.client.close()


async def unclear_sibling(db, held):
    """An earlier prompt of the same topic whose fate is unclear (its own row)."""
    sibling = Action(
        dedupe_key="unclear-" + held.id,
        binding_id=held.binding_id,
        binding_revision=held.binding_revision,
        actor_id=held.actor_id,
        operation_digest=held.operation_digest,
        payload=held.payload,
        operation=held.operation,
        state="ambiguous",
        created_at=held.created_at - 1,
    )
    async with db.sessions.begin() as session:
        session.add(sibling)
    return sibling.id


async def settle(db, action_id):
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action_id)
            .values(state="rejected", status_reason="native_prompt_never_arrived")
        )


@pytest.mark.parametrize(("age", "settled"), [(60, "queued"), (900, "held")])
async def test_a_pause_kept_for_unclear_work_is_looked_at_again_once_it_settles(db, age, settled):
    """Work that settles seconds after a restart must not leave the topic silent."""
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=age)
        unclear = await unclear_sibling(db, held)
        assert await restart_pause_state(db, c, b) is True
        await c._recheck_unclear_pauses()  # Still unclear: nothing moves, nothing is said.
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == "held"
        assert s.posted == []
        await settle(db, unclear)
        await c._recheck_unclear_pauses()  # Not yet due: it waits its interval.
        assert s.posted == [] and c._unclear_pauses
        c._unclear_checked_at -= UNCLEAR_PAUSE_RECHECK_SECONDS
        await c._recheck_unclear_pauses()
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == settled
            assert (await session.get(Binding, b.id)).dispatch_paused is (settled == "held")
        # Recent work goes out as the restart would have sent it; older work asks once.
        if settled == "held":
            assert len(s.posted) == 1
            assert said("router.restart_waiting") in s.posted[0]["content"]
        else:
            assert s.posted == []
        assert not c._unclear_pauses
        c._unclear_checked_at -= UNCLEAR_PAUSE_RECHECK_SECONDS
        await c._recheck_unclear_pauses()
        assert len(s.posted) == (settled == "held")
    finally:
        await c.scope.client.close()


async def test_a_persons_choice_ends_the_recheck_of_an_unclear_pause(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=900)
        unclear = await unclear_sibling(db, held)
        assert await restart_pause_state(db, c, b) is True
        async with db.sessions.begin() as session:  # As `!go` / `!no` move the queue.
            await session.execute(update(Binding).values(queue_revision=Binding.queue_revision + 1))
        await settle(db, unclear)
        await c._recheck_unclear_pauses()
        assert not c._unclear_pauses and s.posted == []
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == "held"
    finally:
        await c.scope.client.close()


async def test_restart_keeps_a_pause_that_existed_before_it(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        held = await waiting_prompt(db, c, s, age=60)
        async with db.sessions.begin() as session:
            await session.execute(update(Binding).values(dispatch_paused=True))
        s.topic_history = [history(s, 150, age=30)]
        assert await restart_pause_state(db, c, b) is True
        async with db.sessions() as session:
            assert (await session.get(Action, held.id)).state == "held"
        # Admitting the missed message could carry the held one along without a
        # `!go`, so it is not captured; the topic is told once instead.
        assert await count(db, InputEvent) == 1
        assert len(s.posted) == 1 and said("router.restart_missed") in s.posted[0]["content"]
        assert await c.poll() == ()
        async with db.sessions() as session:
            assert (await session.get(Binding, b.id)).dispatch_paused
            assert (await session.get(Action, held.id)).state == "held"
    finally:
        await c.scope.client.close()


async def test_failed_history_read_after_restart_keeps_the_pause(db):
    c, s, b, control = await setup(db)
    try:
        s.topic_history = "not-a-list"
        assert await restart_pause_state(db, c, b) is True
    finally:
        await c.scope.client.close()


async def test_identity_loss_after_poll_prevents_checkpoint_and_receipt(db):
    c, s, b, control = await setup(db)
    s.event()

    def hook(req):
        if req.url.path.endswith("/events"):
            s.identity = False

    s.hook = hook
    try:
        with pytest.raises(ZulipError):
            await c.poll()
        assert await c.journal.cursor(c.queue_id) == -1 and await count(db, InputEvent) == 0
    finally:
        await c.scope.client.close()


async def test_private_scope_loss_stops_before_polling_content(db):
    c, s, b, control = await setup(db)
    s.private = False
    try:
        with pytest.raises(ZulipError):
            await c.poll()
        assert ("GET", "events") not in s.calls
    finally:
        await c.scope.client.close()


async def test_publisher_failure_does_not_claim_an_already_queued_action_never_existed(db):
    async def fail(routed):
        raise ValueError("local publication failure")

    c, s, b, control = await setup(db, publisher=fail)
    try:
        s.event("Do task")
        assert await c.poll() == ("held",)
        assert await count(db, Action) == 1
    finally:
        await c.close()
        await c.scope.client.close()


async def test_mixed_scope_or_unattested_event_components_cannot_start(db):
    c, s, b, control = await setup(db)
    try:
        wrong = ZulipSourceReader(c.scope, AsyncMock(return_value=10))
        with pytest.raises(ValueError):
            ZulipCommandConsumer(c.scope, wrong, c.journal, c.router)
        c.scope.enrolled = replace(c.scope.enrolled, verified_event_operations=frozenset())
        with pytest.raises(ValueError):
            ZulipCommandConsumer(c.scope, c.source, c.journal, c.router)
    finally:
        await c.scope.client.close()


async def test_direct_cleanup_route_cannot_bypass_event_attestation(db):
    c, s, b, control = await setup(db)
    try:
        c.scope.client.attestation = replace(
            c.scope.enrolled, verified_event_operations=frozenset()
        )
        with pytest.raises(ZulipError, match="cleanup_not_attested"):
            await c.scope.client.request("DELETE", "events", params={"queue_id": "native-queue"})
    finally:
        await c.scope.client.close()


async def release_retry(db):
    from sqlalchemy import update

    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    async with db.sessions.begin() as session:
        await session.execute(update(ZulipReceiptRetry).values(retry_at=0))


@pytest.mark.parametrize("failure", ["rate", "read"])
async def test_source_throttle_preserves_fifo_and_retries_fresh_without_duplicate_actions(
    db, failure
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    c, s, _, _ = await setup(db)
    original = c.source.read
    c.source.read = AsyncMock(
        side_effect=DeliveryRateLimited(1)
        if failure == "rate"
        else ZulipReadUnavailable("zulip_read_service_unavailable")
    )
    s.event("First prompt", eid=0, mid=101)
    s.event("Second prompt", eid=1, mid=102)
    try:
        assert await c.poll() == ("deferred",)
        assert await count(db, Action) == 0 and await count(db, ZulipReceiptRetry) == 1
        assert await c.journal.cursor(c.queue_id) == 1  # Both receipts are durable.
        calls = len(s.calls)
        assert await c.poll() == ("deferred",) and len(s.calls) == calls
        c.source.read = original
        await release_retry(db)
        assert await c.poll() == ("ignore", "ignore")
        async with db.sessions() as session:
            actions = (await session.scalars(select(Action).order_by(Action.created_at))).all()
        assert len(actions) == 2
        assert [a.dedupe_key for a in actions] == ["human:realm:101", "human:realm:102"]
        assert await count(db, ZulipReceiptRetry) == 0
        assert await c.poll() == () and await count(db, Action) == 2
    finally:
        c.source.read = original
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("failure", ["rate", "read"])
async def test_deferred_publication_restores_saved_reply_without_rerouting_command_or_prompt(
    db, failure
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    publish = AsyncMock(
        side_effect=DeliveryRateLimited(1)
        if failure == "rate"
        else ZulipReadUnavailable("zulip_read_service_unavailable")
    )
    c, s, _, _ = await setup(db, publisher=publish)
    original = c.router.route
    c.router.route = AsyncMock(wraps=original)
    s.event("Only queue this task once")
    try:
        assert await c.poll() == ("deferred",)
        assert c.router.route.await_count == 1 and await count(db, Action) == 1
        async with db.sessions() as session:
            event = await session.scalar(select(InputEvent))
            assert event.state == "zulip_deferred" and event.payload["routed_reply"]["action_id"]
        publish.side_effect = None
        await release_retry(db)
        assert await c.poll() == ("ignore",)
        assert c.router.route.await_count == 1 and await count(db, Action) == 1
        assert publish.await_count == 2 and await count(db, ZulipReceiptRetry) == 0
        assert publish.await_args_list[0].args[0] == publish.await_args_list[1].args[0]
    finally:
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("change", ["text", "deleted", "private"])
@pytest.mark.parametrize("failure", ["rate", "read"])
async def test_deferred_reply_does_not_bypass_fresh_source_and_private_scope_checks(
    db, change, failure
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited

    publish = AsyncMock(
        side_effect=DeliveryRateLimited(1)
        if failure == "rate"
        else ZulipReadUnavailable("zulip_read_service_unavailable")
    )
    c, s, _, _ = await setup(db, publisher=publish)
    s.event("!oz help")
    try:
        assert await c.poll() == ("deferred",)
        publish.side_effect = None
        await release_retry(db)
        if change == "text":
            s.messages[101]["content"] = "Edited content"
        elif change == "deleted":
            s.deleted.add(101)
        else:
            s.private = False
        if change == "private":
            with pytest.raises(ZulipError, match="private_channel"):
                await c.poll()
        else:
            assert await c.poll() == ("held",)
        assert publish.await_count == 1 and await count(db, Action) == 0
    finally:
        s.private = True
        await c.close()
        await c.scope.client.close()


async def test_router_read_only_throttle_is_deferred_but_unknown_partial_route_is_held(db):
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited
    from jt_oz_bridge.domain.routing import RoutingRateDeferred

    c, s, _, _ = await setup(db)
    original = c.router.route
    c.router.route = AsyncMock(side_effect=RoutingRateDeferred(1))
    s.event("!oz help")
    try:
        assert await c.poll() == ("deferred",)
        await release_retry(db)
        c.router.route.side_effect = DeliveryRateLimited(
            1
        )  # No claim of being before local effects.
        assert await c.poll() == ("held",)
        assert await count(db, Action) == 0
    finally:
        c.router.route = original
        await c.close()
        await c.scope.client.close()


async def test_transient_read_after_unknown_router_effect_holds_without_replaying(db):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable

    c, s, _, _ = await setup(db)
    original = c.router.route

    async def partial(*args, **kwargs):
        await original(*args, **kwargs)
        raise ZulipReadUnavailable("zulip_read_service_unavailable")

    route = AsyncMock(side_effect=partial)
    c.router.route = route
    s.event("Only queue this task once")
    try:
        assert await c.poll() == ("held",)
        assert await count(db, Action) == 1 and route.await_count == 1
        assert await c.poll() == ()
        assert await count(db, Action) == 1 and route.await_count == 1
    finally:
        c.router.route = original
        await c.close()
        await c.scope.client.close()


@pytest.mark.parametrize("stage", ["source", "routing", "publication"])
@pytest.mark.parametrize("retry,window,expected", [(1, 60, 60), (120, 60, 120), (1, 20, 20)])
async def test_safe_receipt_retry_allows_complete_budget_window_to_refill(
    db, stage, retry, window, expected
):
    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget
    from jt_oz_bridge.domain.routing import RoutingRateDeferred

    publisher = AsyncMock()
    consumer, server, _, _ = await setup(db, publisher=publisher)
    consumer.scope.client.budget = ZulipRequestBudget(window=window)
    defer = AsyncMock(wraps=consumer.journal.defer)
    consumer.journal.defer = defer
    source, route = consumer.source.read, consumer.router.route
    error = RequestBudgetDeferred(retry)
    if stage == "source":
        consumer.source.read = AsyncMock(side_effect=error)
    elif stage == "routing":
        consumer.router.route = AsyncMock(side_effect=RoutingRateDeferred(retry))
    else:
        publisher.side_effect = error
    server.event("!oz help")
    try:
        assert await consumer.poll() == ("deferred",)
        assert defer.await_count == 1
        assert defer.call_args.args[1] == expected
        assert await count(db, Action) == 0
        calls = len(server.calls)
        assert await consumer.poll() == ("deferred",)
        assert len(server.calls) == calls
    finally:
        consumer.source.read, consumer.router.route = source, route
        consumer.scope.client.budget = None
        await consumer.close()
        await consumer.scope.client.close()


@pytest.mark.parametrize(
    "configured,window,retry,expected", [(True, 60, 1, 60), (True, 20, 120, 120), (False, 60, 2, 2)]
)
async def test_runtime_pre_poll_budget_retries_use_same_complete_window_policy(
    db, monkeypatch, configured, window, retry, expected
):
    import asyncio
    from types import SimpleNamespace

    import jt_oz_bridge.services.consumer_runtime as runtime_module
    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget
    from tests.integration.test_consumer_runtime import setup as whole_pipeline

    pipeline, *_ = await whole_pipeline(db, bound=False)
    pipeline.scope.client.budget = ZulipRequestBudget(window=window) if configured else None
    pipeline.consumer.poll = AsyncMock(side_effect=RequestBudgetDeferred(retry))
    waits = []

    async def stop_after_scheduled_delay(delay):
        waits.append(delay)
        raise asyncio.CancelledError()

    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                runtime_module, "asyncio", SimpleNamespace(sleep=stop_after_scheduled_delay)
            )
            with pytest.raises(asyncio.CancelledError):
                await pipeline.poll()
        assert waits == [expected]
        assert pipeline.consumer.poll.await_count == 1
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("kind", ["known-bot", "nonmessage"])
async def test_ignored_owned_receipt_needs_no_remote_check_or_source(db, monkeypatch, kind):
    c, s, _, native = await setup(db)
    wire = (
        s.event("Only ignore this own Bot output", author=11)
        if kind == "known-bot"
        else {"id": 0, "type": "heartbeat"}
    )
    try:
        rid = (await c.journal.capture(c.queue_id, [wire]))[0]
        check = AsyncMock(
            side_effect=AssertionError("ignored receipt must not access remote scope")
        )
        source = AsyncMock(side_effect=AssertionError("ignored receipt must not fetch Source"))
        monkeypatch.setattr(c, "check", check)
        monkeypatch.setattr(c.source, "read", source)
        before = list(s.calls)
        assert await c.process_receipt(rid) == "ignored"
        check.assert_not_awaited()
        source.assert_not_awaited()
        assert s.calls == before and await count(db, Action) == 0
        assert await c.process_receipt(rid) == "already_claimed_or_settled"
        assert s.calls == before
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize("privacy", [True, False])
async def test_direct_fresh_closed_receipt_relies_on_complete_observer_not_third_check(
    db, monkeypatch, privacy
):
    from types import SimpleNamespace

    from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
    from tests.integration.test_consumer_runtime import setup as whole_pipeline

    pipeline, server, native, *_ = await whole_pipeline(db, bound=False)
    client, delegate = pipeline.scope.client, pipeline.scope.client.client._transport

    def peer(request):
        path = request.url.path.removeprefix("/api/v1/")
        if path == "users/me":
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "user_id": 11,
                    "is_bot": True,
                    "bot_owner_id": 7,
                    "role": 400,
                },
            )
        if path == "server_settings":
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "realm_url": client.url,
                    "zulip_version": "12.3",
                    "zulip_feature_level": 500,
                },
            )
        return delegate.handler(request)

    client.client._transport = httpx.MockTransport(peer)
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=7, url=client.url, zulip_version="12.3", feature_level=500
        ),
    )
    try:
        await pipeline.consumer.start()
        wire = server.input("!projects", 101, topic="Direct fresh closed Source admission")
        rid = (await pipeline.journal.capture(pipeline.consumer.queue_id, [wire]))[0]
        server.private = privacy
        check = AsyncMock(side_effect=AssertionError("closed observer owns current complete scope"))
        monkeypatch.setattr(pipeline.consumer, "check", check)
        assert await pipeline.consumer.process_receipt(rid) == ("reply" if privacy else "held")
        check.assert_not_awaited()
        if privacy:
            assert server.calls.count(("GET", "messages/101")) == 2
        else:
            assert not await count(db, Action) and not server.posts
        assert not native.submitted and not await count(db, Action)
    finally:
        await client.close()


async def test_direct_legacy_receipt_keeps_exact_current_pre_source_check(db, monkeypatch):
    c, s, _, _ = await setup(db)
    try:
        wire = s.event("!oz help")
        rid = (await c.journal.capture(c.queue_id, [wire]))[0]
        order = []
        original_check, original_source = c.check, c.source.read

        async def check():
            order.append("current-check")
            await original_check()

        async def source(*args, **kwargs):
            order.append("original-source")
            return await original_source(*args, **kwargs)

        monkeypatch.setattr(c, "check", check)
        monkeypatch.setattr(c.source, "read", source)
        assert await c.process_receipt(rid) == "reply"
        assert order[0] == "current-check" and order.count("current-check") == 1
        assert "original-source" in order and await count(db, Action) == 0
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize("failure", ["read", "rate", "auth", "privacy", "cancel"])
async def test_pre_source_fallback_check_failure_propagates_and_cannot_stick_processing(
    db, monkeypatch, failure
):
    import asyncio
    import time

    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    c, s, _, _ = await setup(db)
    c.scope.client.budget = ZulipRequestBudget()
    errors = {
        "read": ZulipReadUnavailable("synthetic unavailable check"),
        "rate": RequestBudgetDeferred(2),
        "auth": ZulipError("synthetic authentication_failed"),
        "privacy": ZulipError("private_channel_required"),
        "cancel": asyncio.CancelledError(),
    }
    error = errors[failure]
    try:
        wire = s.event("!oz help")
        rid = (await c.journal.capture(c.queue_id, [wire]))[0]
        monkeypatch.setattr(c, "check", AsyncMock(side_effect=error))
        source = AsyncMock(side_effect=AssertionError("Source must remain unstarted"))
        route = AsyncMock(side_effect=AssertionError("Legacy route must remain unstarted"))
        monkeypatch.setattr(c.source, "read", source)
        monkeypatch.setattr(c.router, "route", route)
        before = time.time()
        with pytest.raises(type(error)) as raised:
            await c.process_receipt(rid)
        assert raised.value is error
        source.assert_not_awaited()
        route.assert_not_awaited()
        async with db.sessions() as session:
            event = await session.get(InputEvent, rid)
            retry = await session.get(ZulipReceiptRetry, rid)
        if failure in {"auth", "privacy"}:
            assert event.state == "zulip_held" and retry is None
        else:
            assert event.state == "zulip_deferred" and not event.payload["defer_recovered"]
            assert retry is not None and retry.retry_at >= before + (60 if failure == "rate" else 1)
        assert await count(db, Action) == 0
    finally:
        c.scope.client.budget = None
        await c.scope.client.close()


async def test_cancel_during_legacy_check_is_journalled_before_cancellation_propagates(
    db, monkeypatch
):
    import asyncio

    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    c, s, _, _ = await setup(db)
    started = asyncio.Event()

    async def wait_check():
        started.set()
        await asyncio.Event().wait()

    try:
        wire = s.event("!oz help")
        rid = (await c.journal.capture(c.queue_id, [wire]))[0]
        monkeypatch.setattr(c, "check", wait_check)
        task = asyncio.create_task(c.process_receipt(rid))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with db.sessions() as session:
            event = await session.get(InputEvent, rid)
            assert event.state == "zulip_deferred" and not event.payload["defer_recovered"]
            assert await session.get(ZulipReceiptRetry, rid) is not None
        assert await count(db, Action) == 0
    finally:
        await c.scope.client.close()


async def test_recovered_pre_source_check_retry_retains_original_recovered_intent(db, monkeypatch):
    from sqlalchemy import update

    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.storage.models import WorkerLease
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    c, server, _, _ = await setup(db)
    try:
        wire = server.event("!oz help")
        rid = (await c.journal.capture(c.queue_id, [wire]))[0]
        assert await c.journal.claim(rid)
        # Isolated ownDB recovery fixture, unrelated to rolling-budget time.
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=0))
        fence = await DurableStore(db).acquire_lease("new-pre-source-owner")
        journal = ZulipEventJournal(
            db,
            ConsumerFence("new-pre-source-owner", fence),
            realm_id="realm",
            bot_user_id=11,
            url=URL,
            channel_ids=frozenset({10}),
        )
        reader = ZulipSourceReader(c.scope, journal.expected_channel)
        router = CommandRouter(
            c.router.bindings, reader, CommandInbox(db, "new-pre-source-owner", fence)
        )
        restored = ZulipCommandConsumer(c.scope, reader, journal, router)
        error = ZulipReadUnavailable("synthetic recovered pre-Source unavailable")
        monkeypatch.setattr(restored, "check", AsyncMock(side_effect=error))
        source = AsyncMock(side_effect=AssertionError("Source must remain unstarted"))
        route = AsyncMock(side_effect=AssertionError("Legacy route must remain unstarted"))
        monkeypatch.setattr(reader, "read", source)
        monkeypatch.setattr(router, "route", route)
        with pytest.raises(ZulipReadUnavailable) as raised:
            await restored.process_receipt(rid)
        assert raised.value is error
        async with db.sessions() as session:
            event = await session.get(InputEvent, rid)
            assert event.state == "zulip_deferred" and event.payload["defer_recovered"] is True
            assert await session.get(ZulipReceiptRetry, rid) is not None
        source.assert_not_awaited()
        route.assert_not_awaited()
        assert await count(db, Action) == 0
    finally:
        await c.scope.client.close()


@pytest.mark.parametrize("failure", ["read", "rate", "auth", "cancel"])
async def test_pre_source_check_cannot_claim_retry_or_hold_after_losing_fence(
    db, monkeypatch, failure
):
    import asyncio

    from sqlalchemy import update

    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.storage.durable import Conflict
    from jt_oz_bridge.storage.models import WorkerLease
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    c, server, _, _ = await setup(db)
    errors = {
        "read": ZulipReadUnavailable("synthetic unavailable after fence loss"),
        "rate": RequestBudgetDeferred(2),
        "auth": ZulipError("synthetic authentication_failed"),
        "cancel": asyncio.CancelledError(),
    }

    async def check_loses_fence():
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
        raise errors[failure]

    try:
        wire = server.event("!oz help")
        rid = (await c.journal.capture(c.queue_id, [wire]))[0]
        monkeypatch.setattr(c, "check", check_loses_fence)
        source = AsyncMock(side_effect=AssertionError("Source must remain unstarted"))
        route = AsyncMock(side_effect=AssertionError("Legacy route must remain unstarted"))
        monkeypatch.setattr(c.source, "read", source)
        monkeypatch.setattr(c.router, "route", route)
        with pytest.raises(Conflict, match="consumer_lease_unavailable"):
            await c.process_receipt(rid)
        async with db.sessions() as session:
            event = await session.get(InputEvent, rid)
            assert event.state == "zulip_processing"
            assert "defer_recovered" not in event.payload
            assert await session.get(ZulipReceiptRetry, rid) is None
        source.assert_not_awaited()
        route.assert_not_awaited()
        assert await count(db, Action) == 0
    finally:
        await c.scope.client.close()


async def pre_paused(db, b):
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding)
            .where(Binding.id == b.id)
            .values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
        )


async def test_a_topic_paused_before_the_outage_still_answers_what_was_sent_meanwhile(db):
    """Messages sent into an already paused topic still get an answer."""
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        await pre_paused(db, b)
        s.topic_history = [
            history(s, 140, "sent early in the outage", age=900),
            history(s, 150, "sent near its end", age=60),
        ]
        # The pause was not this restart's, so it stays.
        assert await restart_pause_state(db, c, b) is True
        assert len(s.posted) == 1 and said("router.restart_missed") in s.posted[0]["content"]
        # The recent one takes the normal path: held behind the pause, with a reply.
        assert await c.poll() == ("reply",)
        async with db.sessions() as session:
            action = await session.scalar(select(Action))
            assert (await session.get(Binding, b.id)).dispatch_paused
        assert action.state == "held" and action.payload["source"]["message_id"] == 150
        # Seen now, and the old one predates nothing new: a second restart is quiet.
        before = len(s.posted)
        assert await restart_pause_state(db, c, b, "queue-after-second-restart") is True
        assert await c.poll() == () and len(s.posted) == before
    finally:
        await c.scope.client.close()


async def test_messages_older_than_the_last_one_seen_are_not_reported_again(db):
    c, s, b, control = await setup(db, publisher=AsyncMock())
    try:
        s.event("Seen live before the outage", mid=160)
        await c.poll()
        s.events.clear()
        await pre_paused(db, b)
        # 155 was missed in some earlier outage, before the newest message seen.
        s.topic_history = [history(s, 155, "an earlier outage", age=900)]
        before = len(s.posted)
        assert await restart_pause_state(db, c, b) is True
        assert await c.poll() == () and len(s.posted) == before
    finally:
        await c.scope.client.close()
