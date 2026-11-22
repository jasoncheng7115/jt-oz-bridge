"""`steer`, `run` and `output` through the real router, SQL queue, tokens and V2 wire.

Native peers are explicit synthetic doubles; nothing here is installed or phone evidence.
"""

import json
import re
from html import unescape

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.presentation.commands import ParsedInput, parse_input
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.history_commands import HistoryCommands
from jt_oz_bridge.services.native_history import StoredPart, StoredPartPage
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from tests.contract.test_v2_execution import REF as WIRE_REF
from tests.contract.test_v2_execution import payload, profile, setup  # noqa: F401
from tests.integration.test_dispatch import message as dispatch_message
from tests.integration.test_router import count, message, router, send
from tests.integration.test_transcript_commands import setup as transcript_setup
from tests.support import bound


@pytest.mark.parametrize(
    ("text", "bound_topic", "expected"),
    [
        ("!oz steer -- keep it short\n", True, ParsedInput("prompt", "steer", "keep it short\n")),
        ("!oz steer --\n!oz stop", True, ParsedInput("prompt", "steer", "!oz stop")),
        ("!steer -- hurry up", True, ParsedInput("prompt", "steer", "hurry up")),
        ("@**jt-oz-bridge** !oz steer -- go", True, ParsedInput("prompt", "steer", "go")),
        ("!oz steer hurry up", True, ParsedInput("invalid", "steer")),
        ("!steer hurry up", True, ParsedInput("invalid", "steer")),
        ("!oz steer -- ", True, ParsedInput("invalid", "steer")),
        ("!oz steer -- hurry up", False, ParsedInput("invalid", "steer")),
        ("!steering wheel", True, ParsedInput("prompt", arguments="!steering wheel")),
        ("!oz send -- exact", True, ParsedInput("prompt", arguments="exact")),
    ],
)
def test_steer_is_literal_text_like_send_and_keeps_its_name(text, bound_topic, expected):
    assert parse_input(text, bound=bound_topic) == expected


async def test_steer_queues_the_exact_text_and_says_where_it_goes(db):
    service, _binding, source, _control, _audience = await router(db)
    original = message("!oz steer -- hurry up\n !oz stop")
    reply = await send(service, source, original)
    assert reply.state == "reply" and reply.action_id is not None
    assert "at its next step if it is still working" in reply.text
    assert "A plain message does the same" in reply.text and "!stop" in reply.text
    async with db.sessions() as session:
        action = await session.get(Action, reply.action_id)
        assert action.state == "queued" and action.payload["operation"] == "prompt"
        assert action.payload["text"] == "hurry up\n !oz stop"
        assert action.payload["source"]["text"] == original.text
    plain = await send(service, source, message("ordinary prompt", 102))
    assert plain.state == "ignore"  # Ordinary text keeps its quiet acknowledgement.
    assert await count(db, Action) == 2


async def test_steer_in_a_paused_topic_keeps_the_hold_and_adds_the_same_warning(db):
    service, binding, source, _control, _audience = await router(db)
    await send(service, source, message("!oz lang zh-TW"))
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    reply = await send(service, source, message("!steer -- 快一點", 102))
    assert "暫停" in reply.text and "會在下一步讀到這則" in reply.text
    async with db.sessions() as session:
        assert (await session.get(Action, reply.action_id)).state == "held"


async def test_steer_needs_the_same_operator_grant_and_stays_off_the_closed_shortcut(db):
    service, _binding, source, _control, _audience = await router(db)
    assert not ClosedBoundQueue.eligible(message("!oz steer -- hurry up"))
    assert ClosedBoundQueue.eligible(message("hurry up"))
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    with pytest.raises(AccessDenied):
        await send(service, source, message("!oz steer -- hurry up"))
    malformed = await send(service, source, message("!oz steer hurry up", 102))
    assert "nothing was sent to OpenCode" in malformed.text
    assert await count(db, Action) == 0


async def test_whole_consumer_answers_steer_and_run_instead_of_the_quiet_shortcut(db):
    from tests.integration.test_consumer_runtime import rows, visible
    from tests.integration.test_consumer_runtime import setup as graph_setup

    pipeline, server, _native, _results, binding, _pulse = await graph_setup(db)
    await pipeline.consumer.start()
    try:
        server.input("!steer -- hurry up", 501, topic=binding.topic)
        server.next_mid = 502
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        assert "at its next step" in visible(server.posts[-1]["content"])
        prompts = [a for a in await rows(db, Action) if a.payload["operation"] == "prompt"]
        assert [a.payload["text"] for a in prompts] == ["hurry up"]
        server.input("!oz run init -- now", 503, topic=binding.topic)
        server.next_mid = 504
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        assert "Nothing was sent" in visible(server.posts[-1]["content"])
        assert len(await rows(db, Action)) == len(prompts)
    finally:
        await pipeline.scope.client.close()


async def test_qualified_closed_queue_leaves_steer_to_the_router_that_explains_it(db, monkeypatch):
    from tests.integration.test_closed_bound_queue import live_identity
    from tests.integration.test_closed_bound_queue import send as closed_send
    from tests.integration.test_consumer_runtime import rows, visible

    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    assert p.closed_bound.qualified()
    try:
        _, quiet = await closed_send(p, server, b, "ordinary prompt")
        assert quiet[-1] == "ignore"
        before = len(server.posts)
        _, outcome = await closed_send(p, server, b, "!steer -- hurry up")
        assert outcome[-1] == "reply" and len(server.posts) == before + 1
        assert "at its next step" in visible(server.posts[-1]["content"])
        texts = [a.payload["text"] for a in await rows(db, Action)]
        assert texts == ["ordinary prompt", "hurry up"] and not native.submitted
    finally:
        await p.scope.client.close()


async def test_steer_source_reaches_native_only_as_one_idle_queue_delivery(profile):  # noqa: F811
    source = dispatch_message(text="!oz steer -- hurry up\n", revision=0)
    steer = payload(text="hurry up\n", source=source.model_dump(mode="json"))
    client, transport, proofs, _data, seen = setup(profile)
    try:
        result = await client.submit(WIRE_REF, steer, "action-steer")
        assert result.status == "admitted" and result.details["delivery"] == "queue"
        posts = [request for request in seen if request.method == "POST"]
        assert len(posts) == 1 and posts[0].url.path.endswith("/prompt")
        wire = json.loads(posts[0].content)
        assert wire["delivery"] == "queue" and wire["text"] == "hurry up\n"
        # Without the dispatcher's steer permission a running turn is never posted to.
        proofs.state = ExecutionState.RUNNING
        seen.clear()
        with pytest.raises(MutationNotSent):
            await client.submit(WIRE_REF, steer, "action-steer-busy")
        assert not [request for request in seen if request.method == "POST"]
    finally:
        await transport.close()


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_run_is_refused_plainly_without_token_action_or_native_call(db, locale):
    service, _binding, source, control, _audience = await router(db)
    if locale == "zh-TW":
        await send(service, source, message("!oz lang zh-TW", 100))
    calls = len(control.calls)
    refused = await send(service, source, message("!oz run opaque-token -- --fix all", 101))
    expected = "Nothing was sent" if locale == "en" else "沒有送出要求"
    assert expected in refused.text and "2.0.32" in refused.text
    assert "!commands" in refused.text
    helped = await send(service, source, message("!oz help run", 102))
    assert expected in helped.text and "run <command-token>" in helped.text
    assert await count(db, Action) == 0 and await count(db, ControlToken) == 0
    assert len(control.calls) == calls
    assert await service.route(source.messages[101]) == refused


async def test_help_explains_steer_and_output(db):
    service, _binding, source, _control, _audience = await router(db)
    steer = await send(service, source, message("!oz help steer"))
    assert "reads it at its next step" in steer.text and "plain message" in steer.text
    output = await send(service, source, message("!oz help output", 102))
    assert "isn't available yet" in output.text  # No history reader in this composition.
    missing = await send(service, source, message("!oz output", 103))
    assert "can't be read" in missing.text
    assert await count(db, Action) == 0


def assistant(native_id, text, created, completed=True, tool_output="PRIVATE_TOOL_OUTPUT"):
    times = {"created": created, "completed": created + 1} if completed else {"created": created}
    return project_message(
        {
            "id": native_id,
            "type": "assistant",
            "time": times,
            "agent": "build",
            "model": {"providerID": "fixture", "id": "test"},
            "content": [
                {
                    "type": "tool",
                    "id": "tool_" + native_id,
                    "name": "bash",
                    "time": {"created": created, "completed": created + 1},
                    "state": {
                        "status": "completed",
                        "input": {"command": "PRIVATE_TOOL_INPUT"},
                        "content": [{"type": "text", "text": tool_output}],
                        "metadata": {"exit": 0},
                    },
                },
                {"type": "text", "text": text},
            ],
        }
    )


def history_tokens(text):
    return re.findall(r"!oz history ([A-Za-z0-9_-]{32})", unescape(text))


async def test_output_pages_the_newest_finished_reply_through_history_tokens(db):
    service, _binding, source, native, _audience, _commands = await transcript_setup(db, 1000)
    long_reply = "\n\n".join(f"Paragraph {i}: " + "original words " * 12 for i in range(40))
    native.messages = [
        project_message(
            {"id": "msg_user", "type": "user", "text": "newer question", "time": {"created": 9}}
        ),
        assistant("msg_running", "still writing", 8, completed=False),
        assistant("msg_done", long_reply, 5),
        assistant("msg_old", "older finished reply", 2),
    ]
    first = await send(service, source, message("!oz output", 101))
    shown = unescape(first.text)
    assert "page 1/" in shown and "Paragraph 0:" in shown
    assert "still writing" not in shown and "older finished reply" not in shown
    assert "PRIVATE_TOOL" not in shown
    pages = int(re.search(r"page 1/(\d+)", shown)[1])
    assert pages > 1
    token = history_tokens(first.text)[0]
    second = await send(service, source, message("!oz output " + token, 102))
    assert "page 2/" in unescape(second.text)
    reused = await send(service, source, message("!oz history " + token, 103))
    assert "page 2/" not in unescape(reused.text)  # Each page token works once.
    nxt = history_tokens(second.text)[0]
    third = await send(service, source, message("!oz history " + nxt, 104))
    assert "page 3/" in unescape(third.text)
    assert await count(db, Action) == 0


async def test_output_without_a_finished_reply_points_to_history(db):
    service, _binding, source, native, _audience, _commands = await transcript_setup(db)
    native.messages = [assistant("msg_running", "still writing", 8, completed=False)]
    reply = await send(service, source, message("!oz output"))
    assert "No finished reply" in reply.text and "!history" in reply.text
    assert await count(db, ControlToken) == 0


@pytest.mark.parametrize("change", ["actor", "audience", "deleted"])
async def test_output_rechecks_reader_grant_audience_and_source(db, change):
    service, _binding, source, native, audience, _commands = await transcript_setup(db)
    native.messages = [assistant("msg_done", "SECRET_REPLY_TEXT", 5)]
    item = message("!oz output")
    if change == "actor":
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
    elif change == "audience":

        async def widen():
            audience.users = frozenset({7, 8, 999})

        native.hook = widen
    else:

        async def delete():
            source.messages[101] = item.model_copy(update={"deleted": True})

        native.hook = delete
    try:
        reply = await send(service, source, item)
    except (AccessDenied, Conflict):
        reply = None
    assert reply is None or "SECRET_REPLY_TEXT" not in reply.text


class StoredReplies:
    """Synthetic StoredHistory; the original ResourceHistory has its own tests."""

    def __init__(self, bindings, parts):
        self.bindings, self.db, self.parts = bindings, bindings.db, parts

    async def current(self, binding_id, realm, actor):
        return await self.bindings.get(binding_id, realm, actor)

    async def page(self, binding_id, realm, actor, *, before=None):
        await self.current(binding_id, realm, actor)
        return StoredPartPage(items=tuple(self.parts))

    async def part(self, binding_id, realm, actor, record_id, record_hash):
        await self.current(binding_id, realm, actor)
        found = next(p for p in self.parts if p.record_id == record_id)
        if found.record_hash != record_hash:
            raise Conflict("stored_history_selection_changed")
        return found

    async def latest_state(self, binding_id, realm, actor):
        return None


def stored(ordinal, text):
    return StoredPart(
        record_id=f"record-{ordinal}",
        record_hash=f"{ordinal:064x}",
        ordinal=ordinal,
        native_message_id=f"msg_{ordinal}",
        part_ordinal=0,
        text=text,
    )


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_output_without_a_native_reader_uses_the_stored_reply_pages(db, locale):
    bindings, _binding, _control, _audience = await bound(db)
    number = await DurableStore(db).acquire_lease("stored-output")
    fence = ConsumerFence("stored-output", number)
    replies = StoredReplies(bindings, [stored(2, "newest stored reply"), stored(1, "older")])
    from tests.integration.test_router import Source

    source = Source()
    history = HistoryCommands(replies, TokenService(db, fence=fence), source, message_limit=2000)
    service = CommandRouter(
        bindings, source, CommandInbox(db, "stored-output", number), history=history
    )
    if locale == "zh-TW":
        await send(service, source, message("!oz lang zh-TW", 100))
    reply = await send(service, source, message("!oz output", 101))
    assert "newest stored reply" in reply.text and "older" not in reply.text
    replies.parts = []
    empty = await send(service, source, message("!oz output", 102))
    assert ("No finished reply" if locale == "en" else "沒有已完成的回覆") in empty.text
    assert await count(db, Action) == 0


def steering_setup(profile, inbox, *, ack_delivery=None, ack_metadata=True):  # noqa: F811
    """The V2 adapter with an attested inbox read; Native is a synthetic double."""
    from jt_oz_bridge.adapters.opencode.transport import ContractAttestation
    from tests.contract.test_v2_catalog import SCOPE
    from tests.contract.test_v2_execution import ALL_OPERATIONS

    def change(request, data, provider):
        if request.method == "GET" and request.url.path.endswith("/inbox"):
            return httpx.Response(200, json={"data": inbox})
        if request.method == "POST" and request.url.path.endswith("/prompt"):
            body = json.loads(request.content)
            payload = {"text": body["text"]}
            if ack_metadata:
                payload["metadata"] = body["metadata"]
            raw = {
                "id": "msg_steered",
                "sessionID": WIRE_REF.upstream_session_id,
                "time": {"created": 5},
                "type": "user",
                "payload": payload,
                "delivery": ack_delivery or body["delivery"],
            }
            return httpx.Response(200, json={"data": raw})
        return None

    client, transport, proofs, data, seen = setup(profile, change=change)
    transport.attestation = ContractAttestation(
        profile.sha256,
        SCOPE.backend_identity,
        "synthetic-fixture",
        ALL_OPERATIONS | {"session.inbox.list"},
    )
    return client, transport, proofs, seen


def pending(identity, delivery, kind="user"):
    return {
        "id": identity,
        "sessionID": WIRE_REF.upstream_session_id,
        "time": {"created": 1},
        "type": kind,
        "payload": {"text": "earlier"},
        "delivery": delivery,
    }


async def test_busy_session_message_is_one_steer_post_correlated_to_its_action(profile):  # noqa: F811
    source = dispatch_message(text="hurry up", revision=0)
    plain = payload(text="hurry up", source=source.model_dump(mode="json"))
    client, transport, proofs, seen = steering_setup(profile, [pending("msg_a", "steer")])
    try:
        assert client.steer_supported(WIRE_REF)
        proofs.state = ExecutionState.RUNNING
        result = await client.submit(WIRE_REF, plain, "action-steer", steer=True)
        assert result.status == "admitted" and result.upstream_id == "msg_steered"
        assert result.details == {
            "operation": "prompt",
            "delivery": "steer",
            "turn_completed": False,
        }
        posts = [request for request in seen if request.method == "POST"]
        assert len(posts) == 1 and posts[0].url.path.endswith("/prompt")
        wire = json.loads(posts[0].content)
        assert wire["delivery"] == "steer" and wire["text"] == "hurry up"
        assert wire["metadata"]["jt_oz_bridge"]["action_id"] == "action-steer"
        assert "resume" not in wire  # Native wakes the running loop for a steer.
        # The inbox was read first, and after the ordinary source/policy preflight.
        reads = [r.url.path for r in seen if r.method == "GET"]
        assert any(path.endswith("/inbox") for path in reads)
    finally:
        await transport.close()


async def test_idle_session_with_steer_permission_sends_nothing_and_says_not_ready(profile):  # noqa: F811
    from jt_oz_bridge.domain.execution import SteerNotReady

    source = dispatch_message(text="hurry up", revision=0)
    plain = payload(text="hurry up", source=source.model_dump(mode="json"))
    client, transport, proofs, seen = steering_setup(profile, [])
    try:
        proofs.state = ExecutionState.IDLE
        with pytest.raises(SteerNotReady):
            await client.submit(WIRE_REF, plain, "action-idle", steer=True)
        # Without the permission an idle session keeps its ordinary queued turn.
        result = await client.submit(WIRE_REF, plain, "action-idle")
        assert result.details["delivery"] == "queue"
        posts = [request for request in seen if request.method == "POST"]
        assert len(posts) == 1 and json.loads(posts[0].content)["delivery"] == "queue"
    finally:
        await transport.close()


@pytest.mark.parametrize(
    ("state", "inbox", "extra"),
    [
        (ExecutionState.RUNNING, [pending("msg_q", "queue")], {}),  # Would overtake it.
        (ExecutionState.RUNNING, [pending("msg_c", "steer", "compaction")], {}),
        (ExecutionState.RUNNING, [], {"schedule": {"kind": "fixture"}}),
        (ExecutionState.WAITING_PERMISSION, [], {}),
        (ExecutionState.WAITING_INPUT, [], {}),
        (ExecutionState.QUEUED, [], {}),
    ],
)
async def test_a_steer_that_cannot_join_cleanly_is_never_posted(profile, state, inbox, extra):  # noqa: F811
    from jt_oz_bridge.domain.execution import MutationNotSent

    source = dispatch_message(text="hurry up", revision=0)
    plain = payload(text="hurry up", source=source.model_dump(mode="json"), **extra)
    client, transport, proofs, seen = steering_setup(profile, inbox)
    try:
        proofs.state = state
        with pytest.raises(MutationNotSent):
            await client.submit(WIRE_REF, plain, "action-refused", steer=True)
        assert not [request for request in seen if request.method == "POST"]
    finally:
        await transport.close()


async def test_parked_steers_after_a_stop_are_woken_by_the_next_queued_prompt(profile):  # noqa: F811
    source = dispatch_message(text="go on", revision=0)
    plain = payload(text="go on", source=source.model_dump(mode="json"))
    client, transport, proofs, seen = steering_setup(profile, [pending("msg_parked", "steer")])
    try:
        proofs.state = ExecutionState.QUEUED
        result = await client.submit(WIRE_REF, plain, "action-after-stop", steer=True)
        assert result.details["delivery"] == "queue"
        wire = json.loads([r for r in seen if r.method == "POST"][0].content)
        assert wire["delivery"] == "queue"  # Runs after the parked input, never before it.
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["delivery", "metadata"])
async def test_a_mismatched_steer_acknowledgement_is_uncertain_not_unsent(profile, change):  # noqa: F811
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from jt_oz_bridge.domain.execution import MutationNotSent

    source = dispatch_message(text="hurry up", revision=0)
    plain = payload(text="hurry up", source=source.model_dump(mode="json"))
    client, transport, proofs, seen = steering_setup(
        profile,
        [],
        ack_delivery="queue" if change == "delivery" else None,
        ack_metadata=change != "metadata",
    )
    try:
        proofs.state = ExecutionState.RUNNING
        with pytest.raises(ContractError) as error:
            await client.submit(WIRE_REF, plain, "action-steer", steer=True)
        assert not isinstance(error.value, MutationNotSent)
        assert len([request for request in seen if request.method == "POST"]) == 1
    finally:
        await transport.close()


async def test_a_running_session_that_moves_between_reads_keeps_the_steer_queued(profile):  # noqa: F811
    from jt_oz_bridge.adapters.opencode.contracts import SnapshotBoundaryChanged
    from jt_oz_bridge.domain.execution import SteerNotReady

    source = dispatch_message(text="hurry up", revision=0)
    plain = payload(text="hurry up", source=source.model_dump(mode="json"))
    client, transport, proofs, seen = steering_setup(profile, [])
    try:
        proofs.state = ExecutionState.RUNNING

        async def moved(*args):
            raise SnapshotBoundaryChanged("leaf_resource_or_feed_boundary_changed")

        proofs.prove = moved
        with pytest.raises(SteerNotReady):
            await client.submit(WIRE_REF, plain, "action-steer", steer=True)
        with pytest.raises(MutationNotSent) as ordinary:
            await client.submit(WIRE_REF, plain, "action-plain")
        assert not isinstance(ordinary.value, SteerNotReady)  # Unchanged without steer.
        assert not [request for request in seen if request.method == "POST"]
    finally:
        await transport.close()


async def test_a_steer_whose_body_was_withheld_keeps_its_place_for_an_ordinary_turn(profile):  # noqa: F811
    from jt_oz_bridge.adapters.opencode.transport import TransportNotSent
    from jt_oz_bridge.domain.execution import MutationNotSent, SteerNotReady

    source = dispatch_message(text="hurry up", revision=0)
    plain = payload(text="hurry up", source=source.model_dump(mode="json"))
    client, transport, proofs, seen = steering_setup(profile, [])
    try:
        proofs.state = ExecutionState.RUNNING
        reads = transport.request

        async def withheld(operation, **kwargs):
            if operation == "session.prompt":
                # The proof moved during the header write: no body byte left.
                raise TransportNotSent("native_mutation_body_withheld")
            return await reads(operation, **kwargs)

        transport.request = withheld
        with pytest.raises(SteerNotReady, match="^v2_native_steer_transport_did_not_send$"):
            await client.submit(WIRE_REF, plain, "action-steer", steer=True)
        proofs.state = ExecutionState.IDLE
        with pytest.raises(MutationNotSent, match="^v2_native_send_proof_moved$") as ordinary:
            await client.submit(WIRE_REF, plain, "action-plain")
        # Known unsent because its proof moved: the dispatcher sends it again shortly.
        assert not isinstance(ordinary.value, SteerNotReady)
    finally:
        await transport.close()
