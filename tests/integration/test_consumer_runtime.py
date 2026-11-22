"""Whole service graph with synthetic HTTP/Native; not live Human/mobile evidence."""

import asyncio
import copy
import json
import re
from dataclasses import replace
from html import unescape
from unittest.mock import AsyncMock
from urllib.parse import parse_qs

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.domain.catalog import CatalogPage, CatalogSession, ProjectScope
from jt_oz_bridge.domain.control import ExecutionState, InteractionSnapshot, QuestionField
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.consumer_runtime import (
    ConsumerPipeline,
    EnrolledSessionCatalog,
    RuntimeBackend,
)
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
from jt_oz_bridge.storage.control_models import Binding, PendingInteraction
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryLane, InputEvent
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_model_commands import Catalog
from tests.integration.test_resource_execution_results import Reader
from tests.integration.test_zulip_consumer import URL, Server
from tests.support import REF, service


@pytest_asyncio.fixture(autouse=True)
async def bounded_runtime_diagnostics(request):
    """Observe a rare full-suite stall without cancelling workers or their receipts.

    No locals, HTTP bodies or exception payloads are printed. A normal case
    completes before the timer. Six snapshots bound a stalled case's log.
    """
    loop = asyncio.get_running_loop()
    remaining = 6
    handle = None

    def dump_tasks():
        nonlocal remaining, handle
        remaining -= 1
        print("runtime_test_pending_tasks", flush=True)
        print("runtime_test_case", request.node.nodeid, flush=True)
        for task in sorted(asyncio.all_tasks(loop), key=lambda task: task.get_name()):
            print("runtime_task", task.get_name(), "cancelling", task.cancelling(), flush=True)
            coro, seen = task.get_coro(), set()
            while coro is not None and id(coro) not in seen:
                seen.add(id(coro))
                frame = (
                    getattr(coro, "cr_frame", None)
                    or getattr(coro, "gi_frame", None)
                    or getattr(coro, "ag_frame", None)
                )
                if frame is not None:
                    print(
                        "runtime_await",
                        frame.f_code.co_filename,
                        frame.f_code.co_name,
                        frame.f_lineno,
                        flush=True,
                    )
                coro = (
                    getattr(coro, "cr_await", None)
                    or getattr(coro, "gi_yieldfrom", None)
                    or getattr(coro, "ag_await", None)
                )
        if remaining:
            handle = loop.call_later(10, dump)

    def dump():
        # Normal pytest capture buffers a hung case until it finishes. Emit the
        # bounded metadata directly so an operator can inspect a still-live run.
        capture = request.config.pluginmanager.getplugin("capturemanager")
        if capture is None:
            dump_tasks()
        else:
            with capture.global_and_fixture_disabled():
                dump_tasks()

    handle = loop.call_later(15, dump)
    try:
        yield
    finally:
        handle.cancel()


class WholeServer(Server):
    def __init__(self):
        super().__init__()
        self.posts = []
        self.edits = []
        self.next_mid = 10000
        self.next_eid = 0
        self.post_mode = "success"
        self.message("Existing original topic", 90)

    def input(self, text, mid=101, author=7, topic=None):
        event = self.event(text, self.next_eid, mid, author)
        self.next_eid += 1
        if topic is not None:
            event["message"]["subject"] = topic
            self.messages[mid]["subject"] = topic
        return event

    def handle(self, request):
        route = request.url.path.removeprefix("/api/v1/")
        if request.method == "PATCH" and re.fullmatch(r"messages/[0-9]+", route):
            identity = int(route.split("/")[1])
            assert self.messages[identity]["sender_id"] == 11
            self.messages[identity]["content"] = parse_qs(request.content.decode())["content"][0]
            self.edits.append(copy.deepcopy(self.messages[identity]))
            return httpx.Response(200, json={"result": "success"})
        if route == "messages" or route == "users/me/10/topics":
            if request.method == "POST":
                data = parse_qs(request.content.decode())
                assert json.loads(data["to"][0]) == 10
                mid = self.next_mid
                self.next_mid += 1
                event = self.input(data["content"][0], mid, 11)
                event["message"]["subject"] = data["topic"][0]
                self.messages[mid]["subject"] = data["topic"][0]
                self.posts.append(copy.deepcopy(self.messages[mid]))
                if "widget_content" in data:
                    self.posts[-1]["widget_content"] = data["widget_content"][0]
                if self.post_mode == "timeout":
                    raise httpx.ReadTimeout("synthetic accepted post / lost response")
                result = {"id": mid}
            elif route == "users/me/10/topics":
                topics = {}
                for m in self.messages.values():
                    topics[m["subject"]] = max(topics.get(m["subject"], 0), m["id"])
                result = {"topics": [{"name": name, "max_id": mid} for name, mid in topics.items()]}
            else:
                narrow = json.loads(request.url.params.get("narrow", "[]"))
                topic = next(
                    (x["operand"] for x in narrow if x["operator"] == "topic"), "Original work"
                )
                rows = sorted(
                    (m for m in self.messages.values() if m["subject"] == topic),
                    key=lambda m: m["id"],
                )
                result = {"messages": rows[-2:]}
            return httpx.Response(200, json={"result": "success", **copy.deepcopy(result)})
        return super().handle(request)


class Sessions:
    def contract_for_project(self, scope):
        return INSTALLED_SCHEMA

    async def list_sessions(self, scope, *, search, cursor, limit):
        return CatalogPage(
            scope=scope,
            contract_sha256=INSTALLED_SCHEMA,
            search=search,
            cursor=cursor,
            items=(
                CatalogSession(reference=REF, title="Original session", state=ExecutionState.IDLE),
            ),
        )


async def setup(db, *, bound=True, agent_fields=None):
    server, execution, results = WholeServer(), SyntheticExecution(), Reader()
    execution.contract_hash = INSTALLED_SCHEMA
    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic-only-key",
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
        verify_identity=AsyncMock(return_value=True),
        transport=httpx.MockTransport(server.handle),
    )
    scope = ZulipScopeReader(client, channel_ids=frozenset({10}))
    await service(db, control=execution, audience=scope)
    f = await DurableStore(db).acquire_lease("whole-pipeline", ttl=120)
    assert f
    projects = {REF.project_id: REF.canonical_directory}

    async def pending(ref):
        return tuple(execution.requests)

    pulse = AsyncMock()
    backend = RuntimeBackend(
        RegisteredBackend(REF.backend_identity, INSTALLED_SCHEMA, projects, execution),
        RegisteredCatalog(REF.backend_identity, INSTALLED_SCHEMA, projects, Sessions()),
        Catalog(REF, INSTALLED_SCHEMA),
        results,
        (REF,),
        pending,
        pulse,
        (),
        **(agent_fields or {}),
    )
    pipeline = ConsumerPipeline(
        db,
        ConsumerFence("whole-pipeline", f),
        scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    binding = await pipeline.bindings.bind("realm", 7, 10, "Original work", REF) if bound else None
    return pipeline, server, execution, results, binding, pulse


async def until(check):
    async with asyncio.timeout(8):
        while True:
            result = await check()
            if result:
                return result
            await asyncio.sleep(0.01)


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


def visible(content):
    # Search synthetic wire bodies using the entity decoding demonstrated by
    # the installed Zulip renderer. Never strip genuine source backslashes.
    return unescape(content)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_supervised_unsent_native_request_gets_one_localized_terminal_notice(db, locale):
    from jt_oz_bridge.domain.execution import MutationNotSent

    pipeline, server, native, _, binding, _ = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(locale=locale))
    attempts = []

    async def refused(*args):
        attempts.append(args)
        raise MutationNotSent("private-backend-token://DO_NOT_DISCLOSE")

    native.submit = refused
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("Original sensitive task")
        phrase = "sent to OpenCode" if locale == "en" else "沒有送到 OpenCode"
        notice = await post_containing(server, phrase)

        async def committed():
            return all(d.state == "delivered" for d in await rows(db, Delivery))

        await until(committed)
        assert notice["subject"] == binding.topic and notice["sender_id"] == 11
        assert runtime.healthy and len(attempts) == 1
        action = (await rows(db, Action))[0]
        assert action.state == "rejected" and action.status_reason == "native_mutation_not_sent"
        for _ in range(3):
            await pipeline.publish_once()
            await pipeline.dispatch_once()
            await pipeline.deliver_once()
        assert len([m for m in server.posts if phrase in visible(m["content"])]) == 1
        assert len(attempts) == 1 and not action.admission and action.upstream_id is None
        assert all("DO_NOT_DISCLOSE" not in m["content"] for m in server.posts)
        assert "Original sensitive task" not in notice["content"]
    finally:
        await runtime.close()
        await pipeline.scope.client.close()


@pytest.mark.parametrize(
    "state, reason, phrase",
    [
        ("held", "source_or_identity_changed", "`!no` drops it"),
        ("rejected", "source_or_identity_changed", "could not be confirmed"),
        ("rejected", "preflight_unavailable", "could not be reached"),
        ("rejected", "native_state_unconfirmed", "could not confirm the state"),
        ("rejected", "native_prompt_never_arrived", "never reached OpenCode"),
        ("rejected", "session_unavailable", "keeps trying to reconnect"),
        ("rejected", "schedule_unavailable", "scheduled sends are off"),
        ("rejected", "attachments_not_qualified", "can't take file uploads"),
    ],
)
async def test_message_stopped_at_dispatch_tells_the_person_exactly_once(db, state, reason, phrase):
    pipeline, server, _native, _, _binding, _ = await setup(db)
    await pipeline.consumer.start()
    try:
        server.input("Original sensitive task")
        await pipeline.consumer.poll()
        async with db.sessions.begin() as session:
            await session.execute(
                update(Action).values(state=state, status_reason=reason, version=Action.version + 1)
            )
        for _ in range(3):
            await pipeline.publish_once()
            await pipeline.deliver_once()
        notices = [post for post in server.posts if phrase in visible(post["content"])]
        assert len(notices) == 1
        assert "Original sensitive task" not in notices[0]["content"]
    finally:
        await pipeline.scope.client.close()


def test_short_commands_control_a_connected_topic_and_literal_text_stays_literal():
    from jt_oz_bridge.presentation.commands import ParsedInput, parse_input

    assert parse_input("!stop", bound=True) == ParsedInput("command", "stop")
    assert parse_input("!file docs/a.txt\n", bound=True) == ParsedInput(
        "command", "file", "docs/a.txt"
    )
    assert parse_input("!oz send -- !stop", bound=True) == ParsedInput("prompt", arguments="!stop")
    assert parse_input("!important fix this", bound=True).kind == "prompt"
    assert parse_input("please !stop", bound=True).kind == "prompt"
    assert parse_input("!send hello", bound=True).kind == "prompt"
    # Before a topic is connected `!stop` only pauses a conversation being created there.
    assert parse_input("!stop").command == "stop"


async def test_help_is_short_and_the_full_list_is_one_command_away(db):
    pipeline, server, _native, _, binding, _ = await setup(db)
    await pipeline.consumer.start()
    try:
        server.input("!help", 501, topic=binding.topic)
        server.next_mid = 502
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        short = visible(server.posts[-1]["content"])
        assert "`!stop`" in short and "`worktree`" not in short
        server.input("!oz help all", 503, topic=binding.topic)
        server.next_mid = 504
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        assert "`worktree`" in visible(server.posts[-1]["content"])
    finally:
        await pipeline.scope.client.close()


async def test_malformed_command_says_so_instead_of_expired(db):
    pipeline, server, _native, _, binding, _ = await setup(db)
    await pipeline.consumer.start()
    try:
        server.input("!oz menu extra", 501, topic=binding.topic)
        server.next_mid = 502
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        assert "isn't in the right form" in visible(server.posts[-1]["content"])
    finally:
        await pipeline.scope.client.close()


async def test_unbind_frees_the_conversation_and_replies_in_the_now_unbound_topic(db):
    pipeline, server, native, _, binding, _ = await setup(db)
    await pipeline.consumer.start()
    try:
        server.input("!oz unbind", 501, topic=binding.topic)
        server.next_mid = 502
        await pipeline.consumer.poll()
        for delivery in await rows(db, Delivery):
            if delivery.state == "pending":
                assert await pipeline.discovery_delivery.advance(delivery.id) == "delivered"
        assert "Disconnected" in visible(server.posts[-1]["content"])
        assert (await rows(db, Binding))[0].state == "unbound"
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


async def test_unbind_refuses_while_work_is_waiting(db):
    pipeline, server, _native, _, binding, _ = await setup(db)
    await pipeline.consumer.start()
    try:
        server.input("Original sensitive task", 501, topic=binding.topic)
        server.next_mid = 502
        await pipeline.consumer.poll()
        server.input("!unbind", 503, topic=binding.topic)
        server.next_mid = 504
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        assert "still has running or waiting work" in visible(server.posts[-1]["content"])
        assert (await rows(db, Binding))[0].state == "active"
    finally:
        await pipeline.scope.client.close()


async def unsent_pipeline(db):
    from jt_oz_bridge.domain.execution import MutationNotSent

    pipeline, server, native, _, binding, _ = await setup(db)
    await pipeline.consumer.start()
    server.input("Original sensitive task")
    await pipeline.consumer.poll()
    # Confirm the original ACK independently; no result/feedback is implied.
    await pipeline.deliver_once()
    calls = []

    async def refused(*args):
        calls.append(args)
        raise MutationNotSent("private-backend-token://DO_NOT_DISCLOSE")

    native.submit = refused
    await pipeline.dispatch_once()
    action = (await rows(db, Action))[0]
    assert action.state == "rejected" and len(calls) == 1
    return pipeline, server, native, binding, action, calls


@pytest.mark.parametrize(
    "change", ["edit", "delete", "private", "grant", "viewer", "move", "action-version"]
)
async def test_unsent_notice_rechecks_original_source_scope_and_actor_before_http(db, change):
    from jt_oz_bridge.storage.models import Grant

    pipeline, server, _, binding, action, calls = await unsent_pipeline(db)
    try:
        await pipeline.publish_once()
        original_posts = len(server.posts)
        if change == "edit":
            server.messages[101]["content"] = "Edited source"
            server.messages[101]["edit_history"] = [{"prev_content": "Original sensitive task"}]
        elif change == "delete":
            server.deleted.add(101)
        elif change == "private":
            server.private = False
        else:
            async with db.sessions.begin() as session:
                if change in {"grant", "viewer"}:
                    statement = update(Grant).where(Grant.user_id == action.actor_id)
                    if change == "viewer":
                        statement = statement.where(Grant.role != "viewer")
                    await session.execute(statement.values(active=False))
                elif change == "move":
                    await session.execute(
                        update(Binding)
                        .where(Binding.id == binding.id)
                        .values(revision=Binding.revision + 1, topic="Other topic")
                    )
                else:
                    await session.execute(
                        update(Action)
                        .where(Action.id == action.id)
                        .values(version=Action.version + 1)
                    )
        await pipeline.deliver_once()
        assert len(server.posts) == original_posts and len(calls) == 1
        deliveries = await rows(db, Delivery)
        assert sum(d.state == "held" for d in deliveries) == 1
        assert (await pipeline.dispatcher.load(action.id)).state == "rejected"
    finally:
        await pipeline.scope.client.close()


async def test_unsent_notice_recovers_after_consumer_replacement_without_replaying_native(db):
    pipeline, server, _, _, action, calls = await unsent_pipeline(db)
    old = pipeline.fence
    try:
        await pipeline.publish_once()
        prior_deliveries = [d.id for d in await rows(db, Delivery)]
        await DurableStore(db).release_lease(old.holder, old.fencing)
        fencing = await DurableStore(db).acquire_lease("successor", ttl=120)
        successor = ConsumerPipeline(
            db,
            ConsumerFence("successor", fencing),
            pipeline.scope,
            dict(pipeline.backends),
            interval=0.02,
            delivery_interval=0,
        )
        assert await successor.dispatch_feedback.next_pending() is None
        await successor.publish_once()
        await successor.deliver_once()
        await successor.deliver_once()
        await successor.dispatch_once()
        assert prior_deliveries == [d.id for d in await rows(db, Delivery)]
        assert len(calls) == 1
        assert len([m for m in server.posts if "sent to OpenCode" in visible(m["content"])]) == 1
        saved = await successor.dispatcher.load(action.id)
        assert saved.state == "rejected" and saved.operation_digest == action.operation_digest
    finally:
        await pipeline.scope.client.close()


async def test_unsent_notice_late_operator_revocation_is_denied_inside_delivery_claim(db):
    from jt_oz_bridge.storage.models import Grant

    pipeline, server, _, _, _, calls = await unsent_pipeline(db)
    try:
        await pipeline.publish_once()
        original_posts = len(server.posts)
        claim = pipeline.bound_delivery.claim

        async def revoked_after_external_source_checks(saved, payload):
            async with db.sessions.begin() as session:
                await session.execute(
                    update(Grant)
                    .where(Grant.user_id == 7, Grant.role != "viewer")
                    .values(active=False)
                )
            return await claim(saved, payload)

        pipeline.bound_delivery.claim = revoked_after_external_source_checks
        await pipeline.deliver_once()
        assert len(server.posts) == original_posts and len(calls) == 1
        assert sum(d.state == "held" for d in await rows(db, Delivery)) == 1
    finally:
        await pipeline.scope.client.close()


async def test_unsent_notice_action_version_is_rechecked_after_fenced_scope_lock(db, monkeypatch):
    from jt_oz_bridge.services import dispatch_feedback

    pipeline, server, _, _, action, calls = await unsent_pipeline(db)
    try:
        await pipeline.publish_once()
        before = len(server.posts)
        scope_lock = dispatch_feedback.lock_output_scope
        raced = []

        async def late_version_change(bindings, session, binding):
            current = await scope_lock(bindings, session, binding)
            # Same SQL identity map as lock_delivery: refresh must not make
            # the previously read expected version follow the changed row.
            await session.execute(
                update(Action)
                .where(Action.id == action.id)
                .values(version=Action.version + 1)
                .execution_options(synchronize_session=False)
            )
            raced.append(action.id)
            return current

        monkeypatch.setattr(dispatch_feedback, "lock_output_scope", late_version_change)
        await pipeline.deliver_once()
        assert raced == [action.id]
        assert len(server.posts) == before and len(calls) == 1
        assert sum(d.state == "held" for d in await rows(db, Delivery)) == 1
    finally:
        await pipeline.scope.client.close()


async def test_unsent_notice_without_its_original_delivery_guard_never_posts(db):
    from jt_oz_bridge.services.delivery import DeliveryWorker

    pipeline, server, _, _, _, calls = await unsent_pipeline(db)
    try:
        await pipeline.publish_once()
        original_posts = len(server.posts)
        worker = DeliveryWorker(
            pipeline.bound_outbox,
            pipeline.gateway,
            pipeline.fence.holder,
            pipeline.fence.fencing,
            minimum_interval=0,
        )
        pending = next(d for d in await rows(db, Delivery) if d.state == "pending")
        assert await worker.advance(pending.id) == "held"
        assert len(server.posts) == original_posts and len(calls) == 1
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("phase", ["queue-commit", "after-claim"])
async def test_unsent_notice_expired_source_witness_cannot_commit_or_send(db, monkeypatch, phase):
    import time
    from types import SimpleNamespace

    from jt_oz_bridge.services import dispatch_feedback

    pipeline, server, _, _, action, calls = await unsent_pipeline(db)
    clock = [time.monotonic()]
    monkeypatch.setattr(dispatch_feedback, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    try:
        before = len(server.posts)
        if phase == "queue-commit":
            enqueue = pipeline.bound_outbox.queue_batch_in_session

            async def expire_before_commit(*args, **kwargs):
                result = await enqueue(*args, **kwargs)
                clock[0] += 6
                return result

            monkeypatch.setattr(
                pipeline.bound_outbox, "queue_batch_in_session", expire_before_commit
            )
            await pipeline.publish_once()
            assert not await rows(db, Delivery)  # The prompt queued silently; no notice commits.
        else:
            await pipeline.publish_once()
            claim = pipeline.bound_delivery.claim

            async def expire_after_claim(*args):
                claimed = await claim(*args)
                clock[0] += 6
                return claimed

            monkeypatch.setattr(pipeline.bound_delivery, "claim", expire_after_claim)
            await pipeline.deliver_once()
            held = next(d for d in await rows(db, Delivery) if d.state == "held")
            assert held.attempts == 0 and held.posted_message_id is None
        assert len(server.posts) == before and len(calls) == 1
        assert (await pipeline.dispatcher.load(action.id)).state == "rejected"
    finally:
        await pipeline.scope.client.close()


async def test_unsent_notice_lost_http_ack_is_ambiguous_without_native_or_chat_replay(db):
    pipeline, server, _, _, _, calls = await unsent_pipeline(db)
    try:
        await pipeline.publish_once()
        original_posts = len(server.posts)
        server.post_mode = "timeout"
        await pipeline.deliver_once()
        assert len(server.posts) == original_posts + 1
        pending = next(d for d in await rows(db, Delivery) if d.state == "ambiguous")
        server.post_mode = "success"
        for _ in range(3):
            await pipeline.publish_once()
            await pipeline.dispatch_once()
            await pipeline.deliver_once()
        assert (await pipeline.bound_outbox.load(pending.id)).state == "ambiguous"
        assert len(server.posts) == original_posts + 1 and len(calls) == 1
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("outcome", ["generic-reject", "ambiguous"])
async def test_unsent_publisher_does_not_infer_not_sent_or_backfill_old_terminal_actions(
    db, outcome
):
    from jt_oz_bridge.domain.execution import MutationRejected

    pipeline, server, native, _, _, _ = await setup(db)
    await pipeline.consumer.start()
    try:
        server.input("Original task")
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        calls = []

        async def uncertain(*args):
            calls.append(args)
            if outcome == "ambiguous":
                raise TimeoutError("private unknown outcome")
            raise MutationRejected("private refusal")

        native.submit = uncertain
        await pipeline.dispatch_once()
        action = (await rows(db, Action))[0]
        assert action.status_reason is None
        original = (action.state, action.version, action.payload, action.admission)
        before = len(server.posts)
        for _ in range(2):
            await pipeline.publish_once()
            await pipeline.dispatch_once()
            await pipeline.deliver_once()
        saved = await pipeline.dispatcher.load(action.id)
        assert (saved.state, saved.version, saved.payload, saved.admission) == original
        assert len(server.posts) == before and len(calls) == 1
    finally:
        await pipeline.scope.client.close()


async def post_containing(server, text, *, start=0):
    async def check():
        return next((m for m in server.posts[start:] if text in visible(m["content"])), None)

    return await until(check)


async def _seven_loop_exchange(db, *, final_response_gate=None):
    pipeline, server, native, result_reader, binding, pulse = await setup(db)
    if final_response_gate is not None:
        entered, release = final_response_gate

        async def delayed_final_response(request):
            response = server.handle(request)
            if (
                request.method == "POST"
                and request.url.path.endswith("/messages")
                and "PRIVATE_NATIVE_FINAL_RESULT"
                in visible(parse_qs(request.content.decode())["content"][0])
            ):
                entered.set()
                await release.wait()
            return response

        pipeline.scope.client.client._transport = httpx.MockTransport(delayed_final_response)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        # Keep the original overall eight-second delivery bound. A mock HTTP
        # post becoming visible is earlier than the outbox's durable commit.
        async with asyncio.timeout(8):
            server.input("Exact human task")
            delivered = await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
            actions = await rows(db, Action)
            assert len(actions) == 1 and actions[0].state == "completed"
            assert actions[0].native_result["evidence"]["correlation"]["text"] == "Exact human task"
            assert native.submitted[0][0] == REF and len(native.submitted) == 1
            assert delivered["sender_id"] == 11 and delivered["subject"] == binding.topic
            assert result_reader.calls >= 1 and pulse.await_count > 0 and runtime.healthy

            async def all_confirmed():
                deliveries = await rows(db, Delivery)
                return deliveries and all(d.state == "delivered" for d in deliveries)

            await until(all_confirmed)
            await asyncio.sleep(0.1)
            assert len(await rows(db, Action)) == 1 and len(native.submitted) == 1
            assert all(d.state == "delivered" for d in await rows(db, Delivery))
            assert (
                sum("PRIVATE_NATIVE_FINAL_RESULT" in visible(m["content"]) for m in server.posts)
                == 1
            )
    finally:
        await runtime.close()


async def test_seven_loops_deliver_correlated_final_and_never_feed_bot_reply_to_native(db):
    await _seven_loop_exchange(db)


async def test_wire_visible_final_waits_for_durable_delivery_before_stopping_workers(db):
    entered, release = asyncio.Event(), asyncio.Event()
    exercise = asyncio.create_task(_seven_loop_exchange(db, final_response_gate=(entered, release)))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        # Deliberately hold the actual mock HTTP response past the old 100ms
        # sleep. The original workers must remain alive to finish the commit.
        await asyncio.sleep(0.15)
        assert not exercise.done()
        assert any(d.state == "sending" for d in await rows(db, Delivery))
    finally:
        release.set()
        await exercise


async def test_actual_http_scope_429_defers_unsent_delivery_and_fresh_retry_posts_once(db):
    pipeline, server, native, _, binding, _ = await setup(db)
    identity = await pipeline.bound_outbox.queue("actual-scope-429", binding.id, 1, "Safe retry")
    limited = True

    def handle(request):
        nonlocal limited
        if limited and request.url.path.endswith("/streams/10"):
            limited = False
            return httpx.Response(
                429,
                headers={"Retry-After": "10"},
                json={"result": "error", "code": "RATE_LIMIT_HIT"},
            )
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    assert await pipeline.bound_delivery.advance(identity) == "pending"
    async with db.sessions() as session:
        saved = await session.get(Delivery, identity)
        assert saved.status_reason == "scope_rate_limited" and saved.attempts == 0
    assert not server.posts and not native.submitted
    async with db.sessions.begin() as session:
        await session.execute(update(DeliveryLane).values(not_before=0))
        await session.execute(update(Delivery).values(retry_at=0))
    assert await pipeline.bound_delivery.advance(identity) == "delivered"
    assert len(server.posts) == 1 and not native.submitted


async def test_native_history_from_computer_flows_through_actual_consumer_and_outbox_without_action(
    db,
):
    from tests.integration.test_transcript_commands import OriginalReader

    previous, server, native, _, binding, _ = await setup(db)
    history = OriginalReader()
    history.contract_hash = INSTALLED_SCHEMA
    backend = replace(previous.backends[REF.backend_id], transcripts={REF: history})
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz history", 101)
        menu = await post_containing(server, "OpenCode messages")
        token = re.search(r"!oz history ([A-Za-z0-9_-]{32})", visible(menu["content"])).group(1)
        server.input("!oz history " + token + " 1", 102)
        reply = await post_containing(server, "Original computer input 0")
        assert reply["subject"] == binding.topic and reply["sender_id"] == 11
        await asyncio.sleep(0.1)
        assert not native.submitted and not await rows(db, Action)
        assert len(history.calls) == 2 and runtime.healthy
    finally:
        await runtime.close()


@pytest.mark.parametrize("token_edges", [False, True])
async def test_unbound_human_selects_original_session_confirms_binds_then_runs(
    db, monkeypatch, token_edges
):
    if token_edges:
        counter = 0

        def opaque(size):
            nonlocal counter
            counter += 1
            return "_" + f"{counter:030x}" + "_"

        monkeypatch.setattr("jt_oz_bridge.services.tokens.secrets.token_urlsafe", opaque)
    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz backends", 101)
        prior = 0
        for mid in (102, 103, 104):
            menu = await post_containing(server, "!oz choose", start=prior)
            prior = server.posts.index(menu) + 1
            token = re.search(r"!oz choose ([A-Za-z0-9_-]{32}) 1", visible(menu["content"]))[1]
            server.input("!oz choose " + token + " 1", mid)
        preview = await post_containing(server, "!ok", start=prior)
        assert not await rows(db, Binding) and not native.submitted
        token = re.search(r"!(?:oz confirm|ok) ([A-Za-z0-9_-]{32})", visible(preview["content"]))[1]
        server.input("!oz confirm " + token, 105)

        async def bound():
            return await rows(db, Binding)

        bindings = await until(bound)
        assert len(bindings) == 1 and bindings[0].session_id == REF.upstream_session_id
        server.input("Run after explicit binding", 106)
        await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
        assert len(native.submitted) == 1 and native.submitted[0][0] == REF
        assert any(
            d.destination_id is not None and d.state == "delivered"
            for d in await rows(db, Delivery)
        )
    finally:
        await runtime.close()


async def test_unauthorized_human_event_is_held_with_no_native_or_reply(db):
    pipeline, server, native, _, _, _ = await setup(db)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("Unauthorized task", author=13)

        async def settled():
            return any(row.state == "zulip_held" for row in await rows(db, InputEvent))

        await until(settled)
        assert not native.submitted and not server.posts and not await rows(db, Action)
    finally:
        await runtime.close()


async def test_native_ambiguous_post_is_never_resubmitted_by_polling_loops(db):
    pipeline, server, native, _, _, _ = await setup(db)
    native.mode = "timeout"
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("Ambiguous task")

        async def ambiguous():
            return any(a.state == "ambiguous" for a in await rows(db, Action))

        await until(ambiguous)
        await asyncio.sleep(0.15)
        assert len(native.submitted) == 1 and runtime.healthy
        assert not any("PRIVATE_NATIVE_FINAL_RESULT" in m["content"] for m in server.posts)
    finally:
        await runtime.close()


async def test_owner_feed_failure_stops_whole_pipeline_without_restart(db):
    pipeline, server, native, _, _, pulse = await setup(db)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        pulse.side_effect = ValueError("synthetic original owner disappeared")
        await asyncio.wait_for(runtime.wait_stopped(), 3)
        await runtime.close()
        before = len(server.posts)
        server.input("Must not run after owner loss")
        await asyncio.sleep(0.1)
        assert not native.submitted and not runtime.healthy and len(server.posts) == before
    finally:
        await runtime.close()


async def test_pending_notice_is_idempotent_and_human_can_open_existing_form(db):
    pipeline, server, native, _, binding, _ = await setup(db)
    native.requests["form-original"] = InteractionSnapshot(
        reference=REF,
        upstream_request_id="form-original",
        generation="synthetic-generation",
        kind="form",
        pending=True,
        description="Existing form",
        fields=(QuestionField(id="name", label="Test field", kind="text"),),
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        # A one-question form now shows the question itself; `!oz pending` still opens it.
        await post_containing(server, "OpenCode has a question for you")
        await asyncio.sleep(0.15)
        assert len([m for m in server.posts if "has a question for you" in m["content"]]) == 1
        assert len(await rows(db, PendingInteraction)) == 1
        server.input("!oz pending")
        await post_containing(server, "Existing form")
        assert not native.submitted and runtime.healthy
    finally:
        await runtime.close()


async def test_stop_passes_busy_prompt_and_holds_queue_without_submitting_it(db):
    pipeline, server, native, _, _, _ = await setup(db)
    native.state = ExecutionState.RUNNING
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("Queued while original session busy", 101)

        async def queued():
            return any(a.state == "queued" for a in await rows(db, Action))

        await until(queued)
        server.input("!oz stop", 102)

        async def stopped():
            return any(payload["operation"] == "interrupt" for _, payload, _ in native.submitted)

        await until(stopped)
        assert all(payload["operation"] != "prompt" for _, payload, _ in native.submitted)
        assert any(a.operation == "prompt" and a.state == "held" for a in await rows(db, Action))
    finally:
        await runtime.close()


async def test_accepted_zulip_post_with_lost_response_is_held_without_second_post(db):
    pipeline, server, native, _, _, _ = await setup(db)
    server.post_mode = "timeout"
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz help")

        async def ambiguous():
            return any(d.state == "ambiguous" for d in await rows(db, Delivery))

        await until(ambiguous)
        await asyncio.sleep(0.15)
        assert len(server.posts) == 1 and not native.submitted and runtime.healthy
    finally:
        await runtime.close()


async def test_catalog_preserves_native_continuation_when_no_qualified_session_on_page():
    class PagedSessions(Sessions):
        async def list_sessions(self, scope, *, search, cursor, limit):
            page = await super().list_sessions(scope, search=search, cursor=cursor, limit=limit)
            return page.model_copy(update={"next_cursor": "native-next"})

    filtered = EnrolledSessionCatalog(PagedSessions(), ())
    page = await filtered.list_sessions(
        ProjectScope(**REF.model_dump(exclude={"upstream_session_id"})),
        search="exact",
        cursor=None,
        limit=10,
    )
    assert page.items == () and page.search == "exact" and page.next_cursor == "native-next"


@pytest.mark.parametrize("value", [(), (REF, REF), [REF]])
def test_dynamic_catalog_cannot_drop_original_scope_or_accept_malformed_provider(value):
    selected = EnrolledSessionCatalog(Sessions(), (REF,), reference_provider=lambda: value)
    with pytest.raises(ValueError, match="append_only"):
        _ = selected.references


@pytest.mark.parametrize("fault", ["remove", "duplicate", "list", "backend", "directory"])
async def test_dynamic_backend_reference_provider_keeps_originals_and_exact_backend_scope(
    db, fault
):
    pipeline, server, native, result, binding, pulse = await setup(db, bound=False)
    backend = pipeline.backends[REF.backend_id]
    value = {
        "remove": (),
        "duplicate": (REF, REF),
        "list": [REF],
        "backend": (
            REF,
            REF.model_copy(update={"backend_id": "foreign", "upstream_session_id": "new"}),
        ),
        "directory": (
            REF,
            REF.model_copy(
                update={"canonical_directory": "/foreign", "upstream_session_id": "new"}
            ),
        ),
    }[fault]
    try:
        candidate = replace(backend, reference_provider=lambda: value)
        with pytest.raises(ValueError, match="provider_scope"):
            _ = candidate.current_references
    finally:
        await pipeline.scope.client.close()


async def test_running_graph_adopts_one_complete_root_for_catalog_history_metadata_and_mirroring(
    db,
):
    from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
    from tests.integration.test_native_metadata_commands import Catalog as Metadata
    from tests.integration.test_transcript_collector import entry
    from tests.integration.test_transcript_commands import OriginalReader

    previous, server, old_native, old_results, _, pulse = await setup(db, bound=False)
    new_ref = REF.model_copy(update={"upstream_session_id": "new-synthetic-original"})

    class ScopedHistory(OriginalReader):
        def __init__(self, ref):
            super().__init__()
            self.ref, self.contract_hash = ref, INSTALLED_SCHEMA
            self.messages, self.state = [], ExecutionState.IDLE

        def contract_for(self, ref):
            assert ref == self.ref
            return self.contract_hash

    class AllSessions(Sessions):
        async def list_sessions(self, scope, *, search, cursor, limit):
            page = await super().list_sessions(scope, search=search, cursor=cursor, limit=limit)
            return page.model_copy(
                update={
                    "items": (*page.items, CatalogSession(reference=new_ref, title="New original"))
                }
            )

    old_history, new_history = ScopedHistory(REF), ScopedHistory(new_ref)
    old_metadata, new_metadata = (
        Metadata(REF, INSTALLED_SCHEMA),
        Metadata(new_ref, INSTALLED_SCHEMA),
    )
    old_entry = RegisteredSession(
        REF,
        INSTALLED_SCHEMA,
        old_native,
        Catalog(REF, INSTALLED_SCHEMA),
        old_results,
        AsyncMock(return_value=()),
        transcript=old_history,
        metadata=old_metadata,
    )
    registry = SessionRegistry({REF: old_entry})
    projects = {REF.project_id: REF.canonical_directory}
    backend = RuntimeBackend(
        RegisteredBackend(REF.backend_identity, INSTALLED_SCHEMA, projects, registry),
        RegisteredCatalog(REF.backend_identity, INSTALLED_SCHEMA, projects, AllSessions()),
        registry.models,
        registry.results,
        (REF,),
        registry.pending,
        pulse,
        (),
        registry.transcripts,
        registry.live_text,
        registry.metadata,
        reference_provider=registry.reference_snapshot,
    )
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
        mirror_enabled=True,
    )
    await pipeline.bindings.bind("realm", 7, 10, "Original work", REF)
    filtered = pipeline.discovery.catalogs[REF.backend_id].client
    project = ProjectScope(**REF.model_dump(exclude={"upstream_session_id"}))
    first = await filtered.list_sessions(project, search="", cursor=None, limit=10)
    assert tuple(item.reference for item in first.items) == (REF,)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz usage", 101)
        await post_containing(server, "0.0125")
        assert old_metadata.calls == ["usage"]
        new_native = SyntheticExecution()
        new_native.ref, new_native.contract_hash = new_ref, INSTALLED_SCHEMA
        new_entry = RegisteredSession(
            new_ref,
            INSTALLED_SCHEMA,
            new_native,
            Catalog(new_ref, INSTALLED_SCHEMA),
            Reader(),
            AsyncMock(return_value=()),
            transcript=new_history,
            metadata=new_metadata,
        )
        await registry.adopt(new_entry, authorize=AsyncMock(return_value=True))
        assert registry.sessions[REF] is old_entry
        assert backend.current_references == (REF, new_ref)
        assert pipeline.router.history.readers[new_ref] is new_history
        assert pipeline.mirrors.readers[new_ref] is new_history
        assert pipeline.bound_delivery.draft_readers[new_ref] is new_history
        assert pipeline.router.metadata.readers[new_ref] is new_metadata
        assert new_ref in pipeline.results.excluded_references
        assert new_ref in pipeline.model_results.excluded_references
        after = await filtered.list_sessions(project, search="", cursor=None, limit=10)
        assert tuple(item.reference for item in after.items) == (REF, new_ref)

        topic = "New Root work"
        # Explicitly synthetic stored source establishes the fixture's new topic
        # without enqueuing an ordinary prompt before binding.
        server.message("!oz menu", 91)
        server.messages[91]["subject"] = topic
        await pipeline.bindings.bind("realm", 7, 10, topic, new_ref)
        start = len(server.posts)
        server.input("!oz usage", 102, topic=topic)
        await post_containing(server, "0.0125", start=start)
        assert new_metadata.calls == ["usage"] and old_metadata.calls == ["usage"]
        new_history.messages = [entry("native_new_message", "New root history marker")]
        start = len(server.posts)
        server.input("!oz history", 103, topic=topic)
        menu = await post_containing(server, "OpenCode messages", start=start)
        token = re.search(r"!oz history ([A-Za-z0-9_-]{32})", visible(menu["content"]))[1]
        server.input("!oz history " + token + " 1", 104, topic=topic)
        output = await post_containing(server, "New root history marker", start=start)
        assert output["subject"] == topic
        assert not any(
            "New root history marker" in visible(m["content"]) and m["subject"] != topic
            for m in server.posts
        )
        assert not old_native.submitted and not new_native.submitted and runtime.healthy
    finally:
        await runtime.close()


async def test_idle_and_busy_polling_do_not_repeatedly_read_human_sources_or_audience(db):
    pipeline, server, native, _, _, _ = await setup(db)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.calls.clear()
        await asyncio.sleep(0.1)
        assert not any(route in {"users/7", "users/8"} for _, route in server.calls)
        native.state = ExecutionState.RUNNING
        server.input("Wait while original work is running")

        async def queued():
            return any(a.state == "queued" for a in await rows(db, Action))

        await until(queued)

        async def source_finished():
            events = await rows(db, InputEvent)
            return bool(events) and all(e.state in {"zulip_done", "zulip_ignored"} for e in events)

        # Routing must still perform fresh audience/source reads. Measure idle
        # polling only after that real work finishes, not after a timing guess.
        await until(source_finished)
        server.calls.clear()
        await asyncio.sleep(1)
        assert not any(route in {"users/7", "users/8", "messages/101"} for _, route in server.calls)
        assert not native.submitted and runtime.healthy
    finally:
        await runtime.close()


async def two_session_pipeline(db):
    from jt_oz_bridge.adapters.opencode.turn_resources import ResourceText
    from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
    from tests.integration.test_model_commands import ModelExecution

    first, server, _, _, _, pulse = await setup(db)
    second_ref = REF.model_copy(update={"upstream_session_id": "second-original-session"})
    server.messages[89] = server.message("Existing second topic", 89)
    server.messages[89]["subject"] = "Second work"

    class NamedReader(Reader):
        def __init__(self, label):
            super().__init__()
            self.label = label

        async def capture(self, correlation):
            value = await super().capture(correlation)
            text = ResourceText(
                assistant_id="msg_synthetic_final", content_index=0, text=self.label
            )
            self.evidence = value.model_copy(
                update={"turn": value.turn.model_copy(update={"text": (text,)})}
            )
            return self.evidence

    native = {}
    entries = {}
    for ref, label in ((REF, "FIRST_ROOT_RESULT"), (second_ref, "SECOND_ROOT_RESULT")):
        execution = ModelExecution()
        execution.ref = ref
        execution.contract_hash = INSTALLED_SCHEMA

        async def pending(selected, client=execution):
            return tuple(client.requests)

        entries[ref] = RegisteredSession(
            ref,
            INSTALLED_SCHEMA,
            execution,
            Catalog(ref, INSTALLED_SCHEMA),
            NamedReader(label),
            pending,
        )
        native[ref] = execution
    registry = SessionRegistry(entries)

    class TwoSessions(Sessions):
        async def list_sessions(self, scope, *, search, cursor, limit):
            return CatalogPage(
                scope=scope,
                contract_sha256=INSTALLED_SCHEMA,
                search=search,
                cursor=cursor,
                items=tuple(
                    CatalogSession(reference=ref, title=ref.upstream_session_id) for ref in entries
                ),
            )

    backend = RuntimeBackend(
        RegisteredBackend(REF.backend_identity, INSTALLED_SCHEMA, registry.projects, registry),
        RegisteredCatalog(REF.backend_identity, INSTALLED_SCHEMA, registry.projects, TwoSessions()),
        registry.models,
        registry.results,
        tuple(entries),
        registry.pending,
        pulse,
        (),
    )
    pipeline = ConsumerPipeline(
        db, first.fence, first.scope, {REF.backend_id: backend}, interval=0.02, delivery_interval=0
    )
    await pipeline.bindings.bind("realm", 7, 10, "Second work", second_ref)
    return pipeline, server, native, second_ref


async def test_two_topics_route_prompts_and_native_final_text_to_their_original_roots(db):
    pipeline, server, native, second = await two_session_pipeline(db)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("First topic task", 101)
        server.input("Second topic task", 102, topic="Second work")
        first = await post_containing(server, "FIRST_ROOT_RESULT")
        other = await post_containing(server, "SECOND_ROOT_RESULT")
        assert first["subject"] == "Original work" and other["subject"] == "Second work"
        assert len(native[REF].submitted) == len(native[second].submitted) == 1
        assert native[REF].submitted[0][1]["text"] == "First topic task"
        assert native[second].submitted[0][1]["text"] == "Second topic task"
        actions = await rows(db, Action)
        assert len(actions) == 2 and all(a.state == "completed" for a in actions)
        assert {a.native_result["reference"]["upstream_session_id"] for a in actions} == {
            REF.upstream_session_id,
            second.upstream_session_id,
        }
    finally:
        await runtime.close()


async def test_stopping_one_busy_root_does_not_stop_or_pause_the_other(db):
    pipeline, server, native, second = await two_session_pipeline(db)
    for client in native.values():
        client.state = ExecutionState.RUNNING
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("First waiting task", 101)
        server.input("Second waiting task", 102, topic="Second work")

        async def queued():
            return len(await rows(db, Action)) == 2

        await until(queued)
        server.input("!oz stop", 103, topic="Second work")

        async def stopped():
            return bool(native[second].submitted)

        await until(stopped)
        assert (
            native[second].submitted[0][1]["operation"] == "interrupt" and not native[REF].submitted
        )
        bindings = await rows(db, Binding)
        assert next(
            b for b in bindings if b.session_id == second.upstream_session_id
        ).dispatch_paused
        assert not next(
            b for b in bindings if b.session_id == REF.upstream_session_id
        ).dispatch_paused
        native[REF].state = ExecutionState.IDLE
        await post_containing(server, "FIRST_ROOT_RESULT")
        assert (
            len(native[REF].submitted) == 1 and native[REF].submitted[0][1]["operation"] == "prompt"
        )
        assert len(native[second].submitted) == 1
    finally:
        await runtime.close()


async def test_model_menu_token_from_one_topic_cannot_select_a_model_in_another(db):
    pipeline, server, native, second = await two_session_pipeline(db)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz models", 101)
        shown = await post_containing(server, "!oz models")
        token = re.search(r"!oz models ([A-Za-z0-9_-]{32})", visible(shown["content"]))[1]
        prior = len(server.posts)
        server.input("!oz models " + token, 102, topic="Second work")

        async def replied():
            return len(server.posts) > prior

        await until(replied)
        assert server.posts[-1]["subject"] == "Second work"
        assert not await rows(db, Action) and all(not c.submitted for c in native.values())
    finally:
        await runtime.close()


async def test_real_http_input_429_preserves_runtime_and_retries_same_queue_without_reregister(db):
    pipeline, server, native, _, _, _ = await setup(db)
    normal = server.handle
    calls = []
    limited = True

    def handle(request):
        nonlocal limited
        route = request.url.path.removeprefix("/api/v1/")
        calls.append((request.method, route))
        if limited and route == "events" and request.method == "GET":
            limited = False
            return httpx.Response(
                429,
                headers={"Retry-After": "1"},
                json={"result": "error", "code": "RATE_LIMIT_HIT"},
            )
        return normal(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("One prompt after transient input throttle")
        await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
        assert runtime.healthy and pipeline.deferred.get("zulip_input_rate_limited") == 1
        assert len(native.submitted) == 1
        assert calls.count(("POST", "register")) == 1
        assert len([c for c in calls if c == ("GET", "events")]) >= 2
    finally:
        await runtime.close()


@pytest.mark.parametrize("target", ["events", "streams/10"])
@pytest.mark.parametrize("failure", [500, 502, 503, 504, "connect", "read_timeout"])
async def test_input_proxy_restart_preserves_live_runtime_and_same_queue(db, target, failure):
    pipeline, server, native, _, _, _ = await setup(db)
    failed = asyncio.Event()
    outage = False
    calls = []

    def handle(request):
        route = request.url.path.removeprefix("/api/v1/")
        calls.append((request.method, route, dict(request.url.params)))
        if outage and route == target and request.method == "GET":
            failed.set()
            if failure == "connect":
                raise httpx.ConnectError("PRIVATE_UPSTREAM_ERROR", request=request)
            if failure == "read_timeout":
                raise httpx.ReadTimeout("PRIVATE_UPSTREAM_ERROR", request=request)
            return httpx.Response(failure, text="<html>PRIVATE_UPSTREAM_ERROR</html>")
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    runtime = pipeline.runtime()
    await runtime.start()
    queue = pipeline.consumer.queue_id
    try:
        outage = True
        await asyncio.wait_for(failed.wait(), 2)
        await asyncio.sleep(0.05)
        assert runtime.healthy
        assert pipeline.deferred.get("zulip_input_read_unavailable") == 1
        assert pipeline.consumer.queue_id == queue and not native.submitted
        outage = False
        server.input("Only execute once after the server returns")
        await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
        assert runtime.healthy and len(native.submitted) == 1
        assert len([c for c in calls if c[:2] == ("POST", "register")]) == 1
        assert {c[2]["queue_id"] for c in calls if c[:2] == ("GET", "events")} == {queue}
    finally:
        outage = False
        await runtime.close()


@pytest.mark.parametrize("failure", ["auth", "redirect", "schema", "expired"])
async def test_input_authority_contract_and_queue_failures_still_stop_runtime(db, failure, caplog):
    pipeline, server, native, _, _, _ = await setup(db)
    broken = False
    calls = []

    def handle(request):
        route = request.url.path.removeprefix("/api/v1/")
        calls.append((request.method, route))
        if broken and route == "events" and request.method == "GET":
            if failure == "schema":
                return httpx.Response(200, text="PRIVATE_INVALID_SCHEMA")
            if failure == "expired":
                return httpx.Response(400, json={"result": "error", "code": "BAD_EVENT_QUEUE_ID"})
            return httpx.Response(
                401 if failure == "auth" else 302,
                headers={"Location": "https://evil.invalid/PRIVATE_REDIRECT"},
                json={"result": "error", "msg": "PRIVATE_UPSTREAM_ERROR"},
            )
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        broken = True
        await asyncio.wait_for(runtime.wait_stopped(), 2)
        assert not runtime.healthy and not native.submitted
        assert "zulip_input_read_unavailable" not in pipeline.deferred
        assert calls.count(("POST", "register")) == 1
        assert "PRIVATE_" not in caplog.text
    finally:
        broken = False
        await runtime.close()


async def test_cancel_input_read_backoff_closes_without_retry_or_new_registration(db):
    pipeline, server, native, _, _, _ = await setup(db)
    outage = False
    calls = []

    def handle(request):
        route = request.url.path.removeprefix("/api/v1/")
        calls.append((request.method, route))
        if outage and route == "events" and request.method == "GET":
            return httpx.Response(502, text="PRIVATE_UPSTREAM_ERROR")
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    runtime = pipeline.runtime()
    await runtime.start()
    polls_before = calls.count(("GET", "events"))
    outage = True

    async def deferred():
        return pipeline.deferred.get("zulip_input_read_unavailable") == 1

    try:
        await until(deferred)
        outage = False
        await asyncio.wait_for(runtime.close(), 2)
        assert not runtime.healthy and not native.submitted
        assert calls.count(("POST", "register")) == 1
        assert calls.count(("GET", "events")) <= polls_before + 1
    finally:
        outage = False
        await runtime.close()


async def test_input_read_retry_backoff_is_bounded_resets_and_does_not_recreate_queue(
    db, monkeypatch
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable

    pipeline, _, _, _, _, _ = await setup(db)
    pipeline.consumer.poll = AsyncMock(
        side_effect=[
            *[ZulipReadUnavailable("zulip_read_service_unavailable") for _ in range(9)],
            (),
            ZulipReadUnavailable("zulip_read_service_unavailable"),
            asyncio.CancelledError(),
        ]
    )
    sleeper = AsyncMock()
    ranges = []

    def choose(lower, upper):
        ranges.append((lower, upper))
        return lower

    try:
        with monkeypatch.context() as patch:
            patch.setattr("jt_oz_bridge.services.consumer_runtime.asyncio.sleep", sleeper)
            patch.setattr("jt_oz_bridge.services.consumer_runtime.random.uniform", choose)
            with pytest.raises(asyncio.CancelledError):
                await pipeline.poll()
        assert [upper for _, upper in ranges] == [1, 2, 4, 8, 16, 32, 60, 60, 60, 1]
        assert all(1 <= lower <= upper <= 60 for lower, upper in ranges)
        assert pipeline.deferred == {"zulip_input_read_unavailable": 10}
        assert all(0 < call.args[0] <= 60 for call in sleeper.await_args_list)
        assert pipeline.consumer.queue_id is None
    finally:
        await pipeline.scope.client.close()


async def test_proxy_outage_preserves_committed_cursor_and_does_not_repeat_previous_prompt(db):
    pipeline, server, native, _, _, _ = await setup(db)
    outage = False
    attempts = []

    def handle(request):
        if outage and request.method == "GET" and request.url.path.endswith("/events"):
            attempts.append(dict(request.url.params))
            return httpx.Response(502, text="PRIVATE_PROXY_ERROR")
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("Prior prompt", 101)
        await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
        outage = True

        async def retried():
            return len(attempts) >= 2

        await until(retried)
        assert len(native.submitted) == 1
        queue = pipeline.consumer.queue_id
        assert {a["queue_id"] for a in attempts} == {queue}
        watermark = await pipeline.consumer.journal.cursor(queue)
        assert {int(a["last_event_id"]) for a in attempts} == {watermark}
        assert watermark >= 0
        prior_posts = len(server.posts)
        server.input("Next prompt", 102)
        outage = False
        await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT", start=prior_posts)
        assert len(native.submitted) == 2 and len(await rows(db, Action)) == 2
        assert runtime.healthy
    finally:
        outage = False
        await runtime.close()


async def test_backoff_does_not_preserve_permission_when_channel_becomes_public(db):
    pipeline, server, native, _, _, _ = await setup(db)
    outage = False

    def handle(request):
        if outage and request.method == "GET" and request.url.path.endswith("/events"):
            return httpx.Response(503, text="PRIVATE_PROXY_ERROR")
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        outage = True

        async def deferred():
            return pipeline.deferred.get("zulip_input_read_unavailable") == 1

        await until(deferred)
        server.private = False
        server.input("Must not reach Native", 101)
        outage = False
        await asyncio.wait_for(runtime.wait_stopped(), 3)
        assert not runtime.healthy and not native.submitted
        assert not await rows(db, Action)
    finally:
        server.private = True
        outage = False
        await runtime.close()


async def test_result_candidates_share_one_read_and_keep_each_operation_fair(db):
    """One operation's backlog cannot hide the other's original pending work."""
    from sqlalchemy import event

    pipeline, _, native, _, binding, _ = await setup(db)
    expected = []
    async with db.sessions.begin() as session:
        for index in range(101):
            for operation, offset in (("prompt", 0), ("check.run", 1)):
                identity = f"candidate-{operation}-{index:03}"
                created = index * 2 + offset
                session.add(
                    Action(
                        id=identity,
                        dedupe_key=identity,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                        actor_id=7,
                        operation_digest="a" * 64,
                        payload={},
                        operation=operation,
                        state=("admitted", "running", "ambiguous")[index % 3]
                        if operation == "check.run"
                        else ("admitted", "running")[index % 2],
                        created_at=created,
                    )
                )
                if index < 100:
                    expected.append((created, operation, identity))
        for operation in ("prompt", "check.run"):
            identity = "prior-revision-" + operation
            session.add(
                Action(
                    id=identity,
                    dedupe_key=identity,
                    binding_id=binding.id,
                    binding_revision=binding.revision - 1,
                    actor_id=7,
                    operation_digest="a" * 64,
                    payload={},
                    operation=operation,
                    state="admitted",
                    created_at=-1 if operation == "check.run" else 1000,
                )
            )
    visited = []

    async def collect_prompt(identity, realm):
        assert realm == "realm"
        visited.append(("prompt", identity))

    async def collect_check(identity, realm):
        assert realm == "realm"
        visited.append(("check.run", identity))
        return True

    pipeline.collectors[REF.backend_id].collect = AsyncMock(side_effect=collect_prompt)
    pipeline.check_collector.collect = AsyncMock(side_effect=collect_check)
    pipeline.idle = AsyncMock(return_value=True)
    statements = []

    def record(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", record)
    try:
        await pipeline.collect_once()
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", record)
    assert len(statements) == 1
    assert visited == [(operation, identity) for _, operation, identity in sorted(expected)]
    assert pipeline.idle.await_count == 100
    assert pipeline._publication_wake.is_set()
    assert not native.submitted


async def test_no_check_enrollment_still_routes_durable_check_result_publication(db):
    """Revoking execution enrollment must not erase the prior publication obligation."""
    pipeline, _, native, _, _, _ = await setup(db)
    assert not pipeline.backends[REF.backend_id].checks
    for publisher in (pipeline.results, pipeline.model_results, pipeline.lifecycle_results):
        publisher.next_pending = AsyncMock(return_value=None)
    pipeline.check_results.next_pending = AsyncMock(return_value="durable-original-check")
    pipeline.check_results.publish = AsyncMock()
    await pipeline.publish_once()
    pipeline.check_results.publish.assert_awaited_once_with("durable-original-check")
    assert not native.submitted


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("!oz projects", "Choose a project"),
        ("!oz backends", "Choose a backend"),
        ("!oz", "`!go`"),
        ("!oz help", "`!go`"),
        ("!help", "`!go`"),
        ("hi", "wasn't sent"),
    ],
)
async def test_first_project_menu_is_delivered_with_default_request_budget(db, text, fragment):
    """A real bounded HTTP client must complete the first unbound command."""
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.storage.command_models import CommandReceipt

    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    pipeline.scope.client.budget = ZulipRequestBudget()
    try:
        await pipeline.consumer.start()
        server.input(text, 101, topic="First use")
        states = await pipeline.consumer.poll()
        assert states == ("reply",), pipeline.scope.client.budget.deferred
        receipts = await rows(db, CommandReceipt)
        assert len(receipts) == 1 and receipts[0].state == "completed"
        deliveries = await rows(db, Delivery)
        assert deliveries and all(d.destination_id is not None for d in deliveries)
        for delivery in deliveries:
            assert await pipeline.discovery_delivery.advance(delivery.id) == "delivered"
        assert len(server.posts) == len(deliveries) == 1
        assert fragment in visible(server.posts[0]["content"])
        assert pipeline.scope.client.budget.deferred == 0
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


async def test_consecutive_unbound_commands_are_deferred_safely_when_budget_is_low(db):
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.storage.command_models import CommandReceipt

    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    pipeline.scope.client.budget = ZulipRequestBudget()
    try:
        await pipeline.consumer.start()
        server.input("!oz projects", 101, topic="First use")
        assert await pipeline.consumer.poll() == ("reply",)
        first = (await rows(db, Delivery))[0]
        assert await pipeline.discovery_delivery.advance(first.id) == "delivered"
        token = re.search(r"!oz choose ([A-Za-z0-9_-]{32}) 1", visible(server.posts[0]["content"]))[
            1
        ]
        server.input("!oz choose " + token + " 1", 102, topic="First use")
        states = await pipeline.consumer.poll()
        assert all(state not in {"held", "ambiguous"} for state in states)
        receipts = await rows(db, CommandReceipt)
        assert all(row.state != "ambiguous" for row in receipts)
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("spent", [20, 40, 80, 100])
async def test_partial_window_project_menu_retries_without_losing_the_human_command(db, spent):
    """A used request window must not turn a read-only menu into uncertainty."""
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.storage.command_models import CommandReceipt

    clock = [100.0]
    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    pipeline.scope.client.budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    try:
        await pipeline.consumer.start()
        for _ in range(spent):
            pipeline.scope.client.budget.acquire()
        server.input("!oz projects", 101, topic="First use")
        states = await pipeline.consumer.poll()
        assert all(state not in {"held", "ambiguous"} for state in states)
        assert all(row.state != "ambiguous" for row in await rows(db, CommandReceipt))
        if any(row.state == "deferred" for row in await rows(db, CommandReceipt)):
            from jt_oz_bridge.storage.control_models import ControlToken

            assert await rows(db, ControlToken) == []
        clock[0] += 61
        # The persisted retry deadline uses wall time, independently of the
        # request-budget clock. Advance that one scheduling deadline explicitly.
        from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

        async with db.sessions.begin() as session:
            await session.execute(update(ZulipReceiptRetry).values(retry_at=0))
        await pipeline.consumer.drain()
        for delivery in await rows(db, Delivery):
            assert await pipeline.discovery_delivery.advance(delivery.id) == "delivered"
        assert len(server.posts) == 1
        assert "Choose a project" in visible(server.posts[0]["content"])
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("pause_between_commands", [False, True])
async def test_short_discovery_binding_chain_uses_default_http_budget_and_journal_bot_sources(
    db, pause_between_commands
):
    """Synthetic bounded HTTP, exact journal sources, no raised limits or new Native work."""
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import Binding
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    clock = [100.0]
    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    assert budget.limit == 180 and budget.reserved == 64
    pipeline.scope.client.budget = budget
    try:
        await pipeline.consumer.start()
        expected = (
            "Choose a project",
            "Choose a conversation",
            "Connected to",
        )
        for text, fragment in zip(("!projects", "!1", "!1"), expected, strict=True):
            if pause_between_commands:
                clock[0] += 61
            mid = max(server.messages) + 1
            prior = len(server.posts)
            server.input(text, mid, topic="Mobile short trial")
            server.next_mid = mid + 1  # Preserve the real server's monotonic Human/Bot ordering.
            states = await pipeline.consumer.poll()
            assert not {"held", "ambiguous"} & set(states)
            for _attempt in range(4):
                for delivery in await rows(db, Delivery):
                    if delivery.state == "pending":
                        worker = (
                            pipeline.discovery_delivery
                            if delivery.destination_id
                            else pipeline.bound_delivery
                        )
                        assert await worker.advance(delivery.id) not in {"held", "ambiguous"}
                if len(server.posts) > prior:
                    break
                clock[0] += 61
                async with db.sessions.begin() as session:
                    await session.execute(update(ZulipReceiptRetry).values(retry_at=0))
                    await session.execute(update(Delivery).values(retry_at=0))
                await pipeline.consumer.drain()
            assert len(server.posts) == prior + 1
            assert fragment in visible(server.posts[-1]["content"])
            assert all(r.state == "completed" for r in await rows(db, CommandReceipt))
            assert server.messages[mid]["content"] == text
        bindings = await rows(db, Binding)
        assert len(bindings) == 1 and bindings[0].session_id == REF.upstream_session_id
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


async def original_graph_pipeline(db, *, adopted=False, enabled=True, tree=True):
    """Actual graph adapters/own journal, synthetic peers; no live Human proof."""
    from tests.contract.test_lineage_resources import TARGET
    from tests.integration.test_session_adoption import setup as adoption_setup

    controller, item, _, _, factory, state, writes, anchor, native = await adoption_setup(
        db, leaf=True, tree_qualification=tree
    )
    if adopted:
        await controller.adopt(item, TARGET)
    original_transport = native.client._transport

    def leaf_peer(request):
        if request.url.path == "/api/session" and request.url.params.get("limit") == "1":
            parent = factory.policy.anchor.model_copy(
                update={"upstream_session_id": request.url.params["parentID"]}
            )
            graph = state["metadata_tree"]
            return httpx.Response(
                200,
                json={
                    "data": [
                        copy.deepcopy(graph["rows"][ref])
                        for ref in graph["edges"].get(parent, [])[:1]
                    ],
                    "cursor": {},
                },
            )
        return original_transport.handler(request)

    native.client._transport = httpx.MockTransport(leaf_peer)
    pipeline, client = await graph_pipeline_from_factory(
        db, factory, controller.journal.fence, enabled=enabled
    )
    return pipeline, factory, state, writes, anchor, native, client


async def graph_pipeline_from_factory(db, factory, fence, *, enabled=True):
    from jt_oz_bridge.services.session_adoption import SessionAdoptionService

    reference = factory.policy.anchor
    server = WholeServer()
    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic-only-key",
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
        verify_identity=AsyncMock(return_value=True),
        transport=httpx.MockTransport(server.handle),
    )
    registry = factory.registry
    backend = RuntimeBackend(
        RegisteredBackend(
            reference.backend_identity, INSTALLED_SCHEMA, registry.projects, registry
        ),
        RegisteredCatalog(
            reference.backend_identity, INSTALLED_SCHEMA, registry.projects, Sessions()
        ),
        registry.models,
        registry.results,
        registry.reference_snapshot(),
        registry.pending,
        AsyncMock(),
        (),
        transcripts=registry.transcripts,
        metadata=registry.metadata,
        live_text=registry.live_text,
        reference_provider=registry.reference_snapshot,
    )

    def adopter(bindings, source):
        return SessionAdoptionService(bindings, source, fence, {reference.project_id: factory})

    pipeline = ConsumerPipeline(
        db,
        fence,
        ZulipScopeReader(client, channel_ids=frozenset({10})),
        {reference.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
        adoption_factory=adopter if enabled else None,
    )
    # These tests count every pulse; the quiet skip has its own test.
    pipeline.graph_quiet_seconds = 0
    pipeline.source.read = AsyncMock(wraps=pipeline.source.read)
    return pipeline, client


@pytest.mark.parametrize("adopted", [False, True])
@pytest.mark.parametrize("running", [False, True])
async def test_runtime_graph_worker_initializes_and_extends_original_roots_without_human(
    db, adopted, running
):
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_lineage_resources import CHILD, TARGET

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(
        db, adopted=adopted
    )
    root = TARGET if adopted else factory.policy.anchor
    original = factory.registry.selected(root)
    try:
        if running:
            state["active"][root.upstream_session_id] = {"type": "running"}
        await pipeline.restore_adopted()
        baseline = factory.registry.publication.generation(root)
        assert baseline.record is not None and baseline.context is not None
        child = root.model_copy(update={"upstream_session_id": CHILD.upstream_session_id})
        graph = state["metadata_tree"]
        row = copy.deepcopy(graph["rows"][TARGET])
        row.update(id=child.upstream_session_id, parentID=root.upstream_session_id, agent="task")
        row["time"]["created"] = 100
        graph["rows"][child] = row
        graph["edges"][root] = [child]
        state["resources"][child] = copy.deepcopy(state["resources"][TARGET])
        if running:
            state["active"][child.upstream_session_id] = {"type": "running"}
        for _ in range(2):
            await pipeline.maintain_original_graphs_once()
        assert factory.registry.selected(root) is original
        assert factory.registry.selected(child).reference == child
        assert factory.registry.publication.generation(root) is not baseline
        snapshot = await factory.registry.snapshot(child)
        assert snapshot.state == (ExecutionState.RUNNING if running else ExecutionState.IDLE)
        assert not pipeline.source.read.await_count and not writes
        assert not await rows(db, Binding) and not await rows(db, Action)
        runtime = pipeline.runtime()
        assert "native-session-graphs" in {worker.name for worker in runtime.workers}
        names = [resource.name for resource in runtime.resources]
        assert names.index("original-session-restoration") < names.index("zulip-consumer")
    finally:
        await client.close()
        await finish(anchor, native)


@pytest.mark.parametrize("mode", ["disabled", "unqualified"])
async def test_runtime_graph_worker_disabled_or_unqualified_adds_zero_native_gets(db, mode):
    from tests.contract.test_leaf_resources import finish

    pipeline, _, state, writes, anchor, native, client = await original_graph_pipeline(
        db, enabled=mode != "disabled", tree=mode != "unqualified"
    )
    try:
        before = len(state["resource_calls"])
        await pipeline.restore_adopted()
        assert not await pipeline.maintain_original_graphs_once()
        assert len(state["resource_calls"]) == before and not writes
        assert "native-session-graphs" not in {w.name for w in pipeline.runtime().workers}
        assert not pipeline.source.read.await_count
    finally:
        await client.close()
        await finish(anchor, native)


@pytest.mark.parametrize("fault", ["operator", "fence", "enrollment", "scope_identity"])
async def test_runtime_graph_worker_requires_current_operator_fence_enrollment_before_native_get(
    db, fault
):
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.control_models import EnrolledBackend
    from jt_oz_bridge.storage.durable import Conflict
    from jt_oz_bridge.storage.models import Grant, WorkerLease
    from tests.contract.test_leaf_resources import finish

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    try:
        await pipeline.restore_adopted()
        original = factory.registry.publication.snapshot()
        if fault == "scope_identity":
            pipeline.scope.client.verify_identity = AsyncMock(return_value=True)
        else:
            async with db.sessions.begin() as session:
                if fault == "operator":
                    await session.execute(update(Grant).values(active=False))
                elif fault == "fence":
                    await session.execute(
                        update(WorkerLease).values(fencing=WorkerLease.fencing + 1)
                    )
                else:
                    await session.execute(update(EnrolledBackend).values(enabled=False))
        before = len(state["resource_calls"])
        with pytest.raises((AccessDenied, Conflict)):
            await pipeline.maintain_original_graphs_once()
        assert len(state["resource_calls"]) == before
        assert factory.registry.publication.snapshot() is original
        assert not pipeline.source.read.await_count and not writes
        assert not await rows(db, Action) and not await rows(db, Binding)
    finally:
        await client.close()
        await finish(anchor, native)


async def test_supervised_graph_worker_runs_without_blocking_original_owner_pulse(db):
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_lineage_resources import CHILD, TARGET

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    runtime = pipeline.runtime()
    root = factory.policy.anchor
    original = factory.registry.selected(root)
    entered, release = asyncio.Event(), asyncio.Event()
    delegate = native.client._transport
    armed, blocked = False, False

    async def blocking_peer(request):
        nonlocal blocked
        if armed and not blocked and request.url.path == "/api/session/" + root.upstream_session_id:
            blocked = True
            entered.set()
            await release.wait()
        return delegate.handler(request)

    native.client._transport = httpx.MockTransport(blocking_peer)
    try:
        await runtime.start()
        child = root.model_copy(update={"upstream_session_id": CHILD.upstream_session_id})
        graph = state["metadata_tree"]
        row = copy.deepcopy(graph["rows"][TARGET])
        row.update(id=child.upstream_session_id, parentID=root.upstream_session_id, agent="task")
        row["time"]["created"] = 100
        graph["rows"][child] = row
        graph["edges"][root] = [child]
        state["resources"][child] = copy.deepcopy(state["resources"][TARGET])
        armed = True
        async with asyncio.timeout(3):
            await entered.wait()
        pulse = pipeline.backends[root.backend_id].pulse
        before = pulse.await_count
        await asyncio.sleep(0.06)
        assert pulse.await_count > before and runtime.healthy
        release.set()

        async def registered():
            return child in factory.registry.sessions

        assert await until(registered)
        assert factory.registry.selected(root) is original
        assert not writes and not pipeline.source.read.await_count
        assert not await rows(db, Action) and not await rows(db, Binding)
    finally:
        release.set()
        await runtime.close()
        await client.close()
        await finish(anchor, native)


async def test_graph_worker_typed_authentication_denial_is_not_a_snapshot_retry(db):
    from jt_oz_bridge.adapters.zulip.client import ZulipAuthenticationFailed
    from tests.contract.test_leaf_resources import finish

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    try:
        await pipeline.restore_adopted()
        original = factory.registry.publication.snapshot()

        async def denied(*args, **kwargs):
            raise ZulipAuthenticationFailed("synthetic_typed_authentication_denial")

        # Inject the explicit typed failure at the trusted authority dependency;
        # the actual worker loop must propagate it, never classify it as transient.
        pipeline.adoption.journal.enrollment_scope = denied
        before = len(state["resource_calls"])
        with pytest.raises(ZulipAuthenticationFailed):
            await pipeline.maintain_original_graphs()
        assert len(state["resource_calls"]) == before
        assert factory.registry.publication.snapshot() is original
        assert pipeline.deferred.get("original_graph_snapshot_not_current", 0) == 0
        assert not writes and not pipeline.source.read.await_count
    finally:
        await client.close()
        await finish(anchor, native)


async def test_runtime_graph_worker_extends_restored_created_root_without_replaying_creation(db):
    from jt_oz_bridge.adapters.opencode.existing_session_graph import V2ExistingSessionGraphObserver
    from jt_oz_bridge.adapters.opencode.existing_sessions import (
        ExistingSessionProtocol,
        V2ExistingSessionObserver,
    )
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LINEAGE_SEMANTICS,
        LineageResourceAttestation,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import POLICY_READS
    from jt_oz_bridge.adapters.opencode.resources import READS
    from jt_oz_bridge.domain.session_adoption import SessionAdoptionPolicy
    from jt_oz_bridge.services.existing_session_factory import V2ExistingSessionFactory
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_public_live_feed import REF as native_anchor
    from tests.integration.test_session_creation_activation import setup as creation_setup

    created = await creation_setup(db)
    client = None
    try:
        await created["service"].reconcile(created["identity"])
        registry = created["factory"].registry
        root = native_anchor.model_copy(
            update={"upstream_session_id": created["intent"].native_session_id}
        )
        original = registry.selected(root)
        provenance = created["factory"]._records[root]
        action, binding = await created["journal"].load(created["identity"])
        original_result = copy.deepcopy(action.native_result)
        original_binding = (binding.id, binding.revision, binding.session_id)
        source_reads = list(created["source"].calls)
        observer = V2ExistingSessionGraphObserver(
            V2ExistingSessionObserver(
                created["anchor"].execution.scope_guard,
                ExistingSessionProtocol(
                    native_anchor.backend_id,
                    native_anchor.backend_identity,
                    INSTALLED_SCHEMA,
                    "e" * 64,
                    POLICY_READS | {"session.list"},
                ),
                native_anchor,
            )
        )
        factory = V2ExistingSessionFactory(
            observer,
            registry,
            SessionAdoptionPolicy(
                anchor=native_anchor,
                contract_sha256=INSTALLED_SCHEMA,
                installed_protocol_evidence_sha256="e" * 64,
                protocol_scope="backend",
                operations=frozenset({"prompt"}),
            ),
            lineage=LineageResourceAttestation(
                native_anchor.backend_id,
                native_anchor.backend_identity,
                INSTALLED_SCHEMA,
                LINEAGE_SEMANTICS,
                "e" * 64,
                READS,
            ),
        )
        pipeline, client = await graph_pipeline_from_factory(db, factory, created["journal"].fence)
        await pipeline.restore_adopted()
        child = root.model_copy(update={"upstream_session_id": "ses_created_runtime_child"})
        row = copy.deepcopy(created["state"]["info"])
        row.update(
            id=child.upstream_session_id,
            parentID=root.upstream_session_id,
            agent="task",
            outcome="succeeded",
        )
        row["time"] = {"created": 101, "updated": 110, "idle": 110}
        previous = created["t"].client._transport

        def child_peer(request):
            assert request.method == "GET"
            if request.url.path == "/api/session":
                return httpx.Response(
                    200,
                    json={
                        "data": [copy.deepcopy(row)]
                        if request.url.params.get("parentID") == root.upstream_session_id
                        else [],
                        "cursor": {},
                    },
                )
            if request.url.path == "/api/session/" + child.upstream_session_id:
                return httpx.Response(200, json={"data": copy.deepcopy(row)})
            if request.url.path == "/api/agent/task":
                agent = copy.deepcopy(created["d"]["agent.get"])
                agent["data"].update(id="task", mode="subagent")
                return httpx.Response(200, json=agent)
            if request.url.path.startswith("/api/session/" + child.upstream_session_id + "/"):
                value = {"data": []}
                if request.url.path.endswith("/message"):
                    value = {
                        "data": [
                            {
                                "id": "msg_created_runtime_idle",
                                "type": "idle",
                                "time": {"created": 110},
                                "outcome": "succeeded",
                            }
                        ],
                        "cursor": {},
                    }
                return httpx.Response(200, json=value)
            return previous.handler(request)

        created["t"].client._transport = httpx.MockTransport(child_peer)
        for _ in range(2):
            await pipeline.maintain_original_graphs_once()
        assert registry.selected(root) is original and registry.selected(child).reference == child
        assert created["factory"]._records[root] is provenance
        current_action, current_binding = await created["journal"].load(created["identity"])
        assert current_action.native_result == original_result
        assert (
            current_binding.id,
            current_binding.revision,
            current_binding.session_id,
        ) == original_binding
        assert created["source"].calls == source_reads and not pipeline.source.read.await_count
        assert not created["writes"] and len(await rows(db, Action)) == 1
        assert len(await rows(db, Binding)) == 1
    finally:
        if client is not None:
            await client.close()
        await finish(created["p"], created["t"])


@pytest.mark.parametrize(
    "reason", ["original_owner_changed", "backend_identity_unverified", "duplicate_or_cyclic_edge"]
)
async def test_graph_worker_does_not_retry_permanent_native_contract_failures(db, reason):
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from tests.contract.test_leaf_resources import finish

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    try:
        await pipeline.restore_adopted()
        original = factory.registry.publication.snapshot()

        async def denied(*args, **kwargs):
            raise ContractError(reason)

        factory.observer.observe = denied
        before = len(state["resource_calls"])
        with pytest.raises(ContractError, match=reason):
            async with asyncio.timeout(0.2):
                await pipeline.maintain_original_graphs()
        assert factory.registry.publication.snapshot() is original
        assert len(state["resource_calls"]) == before
        assert pipeline.deferred.get("original_graph_snapshot_not_current", 0) == 0
        assert not writes and not pipeline.source.read.await_count
    finally:
        await client.close()
        await finish(anchor, native)


async def test_graph_worker_only_retries_typed_snapshot_boundary_then_reproves_real_native(db):
    from jt_oz_bridge.adapters.opencode.contracts import SnapshotBoundaryChanged
    from tests.contract.test_leaf_resources import finish

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    try:
        await pipeline.restore_adopted()
        original, observed, calls = factory.observer.observe, [], 0

        async def changing(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise SnapshotBoundaryChanged("synthetic_fresh_resource_boundary")
            if calls == 3:
                raise RuntimeError("synthetic_stop_after_real_reproof")
            result = await original(*args, **kwargs)
            observed.append(result)
            return result

        factory.observer.observe = changing
        before = len(state["resource_calls"])
        with pytest.raises(RuntimeError, match="stop_after_real_reproof"):
            await pipeline.maintain_original_graphs()
        assert len(observed) == 1 and len(state["resource_calls"]) > before
        assert pipeline.deferred["original_graph_snapshot_not_current"] == 1
        assert not writes and not pipeline.source.read.await_count
    finally:
        await client.close()
        await finish(anchor, native)


async def test_graph_worker_reads_again_after_a_failed_native_get(db):
    from jt_oz_bridge.adapters.opencode.transport import TransportError
    from tests.contract.test_leaf_resources import finish

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    try:
        await pipeline.restore_adopted()
        original, observed, calls = factory.observer.observe, [], 0

        async def flaky(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls in {1, 2}:
                raise TransportError("upstream_transport_or_encoding_error")
            if calls == 4:
                raise RuntimeError("synthetic_stop_after_real_reproof")
            result = await original(*args, **kwargs)
            observed.append(result)
            return result

        factory.observer.observe = flaky
        before = len(state["resource_calls"])
        with pytest.raises(RuntimeError, match="stop_after_real_reproof"):
            await pipeline.maintain_original_graphs()
        # Two failed GETs were deferred, then the real Native was read again.
        assert len(observed) == 1 and len(state["resource_calls"]) > before
        assert pipeline.deferred["original_graph_native_unavailable"] == 2
        assert pipeline.deferred.get("original_graph_snapshot_not_current", 0) == 0
        assert not writes and not pipeline.source.read.await_count
    finally:
        await client.close()
        await finish(anchor, native)


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        ("contract", "existing_session_original_observation_changed"),
        ("contract", "existing_session_graph_original_observation_changed"),
        ("contract", "existing_session_graph_final_observation_expired"),
        ("contract", "existing_session_graph_observation_expired"),
        ("contract", "original_graph_generation_changed_during_read"),
        ("contract", "v2_execution_owner_or_snapshot_evidence_changed"),
        ("conflict", "original_graph_update_original_resource_proof_changed"),
        ("conflict", "original_session_registration_proof_expired"),
        ("conflict", "original_graph_update_publication_head_changed"),
        ("denied", "original_session_graph_maintenance_authority_changed"),
    ],
)
async def test_graph_worker_reads_again_when_the_session_moved_mid_read(db, kind, code):
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.durable import Conflict
    from tests.contract.test_leaf_resources import finish

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    error = {"contract": ContractError, "conflict": Conflict, "denied": AccessDenied}[kind]
    try:
        await pipeline.restore_adopted()
        original, observed, calls = factory.observer.observe, [], 0

        async def moving(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise error(code)
            if calls == 3:
                raise RuntimeError("synthetic_stop_after_real_reproof")
            result = await original(*args, **kwargs)
            observed.append(result)
            return result

        factory.observer.observe = moving
        with pytest.raises(RuntimeError, match="stop_after_real_reproof"):
            await pipeline.maintain_original_graphs()
        assert len(observed) == 1
        assert pipeline.deferred["original_graph_changed_while_reading"] == 1
        assert not writes and not pipeline.source.read.await_count
    finally:
        await client.close()
        await finish(anchor, native)


async def test_a_quiet_tree_is_read_again_on_an_arrival_in_its_directory_or_after_a_while(db):
    from jt_oz_bridge.adapters.opencode.live import V2PublicFeed
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_public_live_feed import REAL, frame

    pipeline, factory, state, writes, anchor, native, client = await original_graph_pipeline(db)
    try:
        await pipeline.restore_adopted()
        (root,) = pipeline.original_graph_roots()
        feed = factory.observer.observer.anchor.proofs.feed
        assert isinstance(feed, V2PublicFeed) and feed.index is not None
        pipeline.graph_quiet_seconds = 60
        calls = []
        original = pipeline.adoption.maintain_root

        async def counted(*args, **kwargs):
            calls.append(args[2])
            return await original(*args, **kwargs)

        pipeline.adoption.maintain_root = counted
        await pipeline.maintain_original_graphs_once()
        await pipeline.maintain_original_graphs_once()
        assert calls == [root]
        # Another project's activity leaves it quiet.
        elsewhere = json.loads(
            json.dumps(REAL[0]).replace(REAL[0]["data"]["sessionID"], "ses_other_project")
        )
        elsewhere["location"] = {"directory": "/home/opencode/workspaces/another-project"}
        feed.index.accept(frame(elsewhere))
        await pipeline.maintain_original_graphs_once()
        assert calls == [root]
        # An unknown session in this tree's directory may be a new subagent.
        here = json.loads(
            json.dumps(REAL[0]).replace(REAL[0]["data"]["sessionID"], "ses_new_subagent")
        )
        here["location"] = {"directory": root.canonical_directory}
        feed.index.accept(frame(here))
        await pipeline.maintain_original_graphs_once()
        assert calls == [root, root]
        pipeline.graph_quiet_seconds = 0
        await pipeline.maintain_original_graphs_once()
        assert calls == [root, root, root]
        assert not writes
    finally:
        await client.close()
        await finish(anchor, native)


def install_synthetic_native_current_for_budget_only(pipeline, native, monkeypatch):
    """Zulip cost fixture ONLY; no OriginalExecutionProof or live Native qualification.

    The existing SyntheticExecution remains the actual read-only peer. Pin its
    identity, contract, reference and stable state instead of adding a product
    fallback or treating an unconditional lambda as Native authority.
    """
    from jt_oz_bridge.storage.durable import Conflict, digest

    confirmation = pipeline.router.unbound.confirmations
    control = pipeline.bindings.control
    backend = control.selected(REF)
    assert backend.client is native and type(native) is SyntheticExecution

    def stable_state():
        return digest(
            {
                "reference": native.ref.model_dump(mode="json"),
                "state": native.state.value,
                "resolved": native.resolved,
                "descendants": [ref.model_dump(mode="json") for ref in native.descendants],
                "requests": {
                    key: value.model_dump(mode="json") for key, value in native.requests.items()
                },
            }
        )

    async def synthetic_snapshot(selected):
        assert selected == REF
        snapshot = await native.snapshot(selected)
        contract, state = native.contract_hash, stable_state()

        def require_current():
            if (
                pipeline.bindings.control is not control
                or control.selected(selected) is not backend
                or backend.client is not native
                or native.contract_hash != contract
                or control.contract_for(selected) != contract
                or selected != REF
                or snapshot.reference != selected
                or stable_state() != state
            ):
                raise Conflict("synthetic-budget-native-current-changed")

        require_current()
        return snapshot, require_current

    monkeypatch.setattr(confirmation, "_observed_native_snapshot", synthetic_snapshot)


@pytest.mark.parametrize("seconds_per_http", [0.15, 0.3])
async def test_real_identity_short_binding_chain_recovers_distributed_default_budget(
    db, monkeypatch, seconds_per_http
):
    """Synthetic scheduling: real guard/journal, not accelerated authorization proof."""
    import time
    from types import SimpleNamespace

    from jt_oz_bridge.adapters.zulip.budget import (
        RequestBudgetDeferred,
        ZulipRequestBudget,
        request_lane,
    )
    from jt_oz_bridge.services import runtime_enrollment as identity_module
    from jt_oz_bridge.services import zulip_events as event_module
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    install_synthetic_native_current_for_budget_only(pipeline, native, monkeypatch)
    clock, wall = [100.0], time.time()
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
    client = pipeline.scope.client
    client.budget = budget
    delegate = client.client._transport

    def peer(request):
        path = request.url.path.removeprefix("/api/v1/")
        if path == "users/me":
            data = {"user_id": 11, "is_bot": True, "bot_owner_id": 7, "role": 400}
        elif path == "server_settings":
            data = {"realm_url": client.url, "zulip_version": "12.3", "zulip_feature_level": 500}
        elif path == "streams/10/members":
            data = {"subscribers": [7, 8, 11]}
        else:
            return delegate.handler(request)
        return httpx.Response(200, json={"result": "success", **data})

    async def elapsed_http(request):
        clock[0] += seconds_per_http

    client.client._transport = httpx.MockTransport(peer)
    client.client.event_hooks["request"].append(elapsed_http)
    monkeypatch.setattr(identity_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(event_module, "time", SimpleNamespace(time=lambda: wall + clock[0] - 100))
    client.verify_identity = identity_module.ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=7, url=client.url, zulip_version="12.3", feature_level=500
        ),
    )
    try:
        await pipeline.consumer.start()
        with request_lane("control"):
            for _ in range(100):
                budget.acquire()
                clock[0] += 0.3
        fragments = (
            "Choose a project",
            "Choose a conversation",
            "Connect this conversation",
            "Connected.",
        )
        for text, fragment in zip(("!projects", "!1", "!1", "!confirm"), fragments, strict=True):
            mid, prior = max(server.messages) + 1, len(server.posts)
            server.input(text, mid, topic="Real guard synthetic short trial")
            server.next_mid = mid + 1
            polled = False
            for _attempt in range(12):
                try:
                    states = await (
                        pipeline.consumer.poll() if not polled else pipeline.consumer.drain()
                    )
                    polled = True
                except RequestBudgetDeferred as error:
                    if polled:
                        raise  # Persisted routing must use its own retry_at below.
                    # Match ConsumerPipeline.poll's read-only rate-limit policy:
                    # max(retry_after, configured budget.window). The original
                    # server event has not been fetched/claimed or gained effects.
                    clock[0] += max(error.retry_after, budget.window) + 0.01
                    continue
                assert not {"held", "ambiguous"} & set(states)
                for delivery in await rows(db, Delivery):
                    if delivery.state == "pending":
                        worker = (
                            pipeline.discovery_delivery
                            if delivery.destination_id
                            else pipeline.bound_delivery
                        )
                        assert await worker.advance(delivery.id) not in {"held", "ambiguous"}
                if len(server.posts) > prior:
                    break
                retries = await rows(db, ZulipReceiptRetry)
                deliveries = [d for d in await rows(db, Delivery) if d.state == "pending"]
                assert retries or deliveries, "No safe retry or pending delivery remains"
                if retries:
                    # Honor persisted routing retry_at. Never rewrite receipt rows.
                    target = min(r.retry_at for r in retries) - wall + 100
                else:
                    target = clock[0] + max(0, min(d.retry_at for d in deliveries) - time.time())
                clock[0] = max(clock[0], target + 0.01)
                # Only isolated synthetic delivery due timers are translated.
                # This does not qualify Source/Native wall-clock TTLs or authorize
                # receipt replay; routing rows and authority proofs are untouched.
                async with db.sessions.begin() as session:
                    await session.execute(update(Delivery).values(retry_at=0))
                    await session.execute(update(DeliveryLane).values(not_before=0))
            assert len(server.posts) == prior + 1
            assert fragment in visible(server.posts[-1]["content"])
            assert server.messages[mid]["content"] == text
        receipts, bindings = await rows(db, CommandReceipt), await rows(db, Binding)
        assert len(server.posts) == len(receipts) == 4
        assert all(r.state == "completed" for r in receipts)
        assert len(bindings) == 1 and bindings[0].state == "active"
        assert bindings[0].session_id == REF.upstream_session_id
        assert not native.submitted and not await rows(db, Action)
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
    finally:
        await client.close()


@pytest.mark.parametrize("seconds_per_http", [0.15, 0.3])
@pytest.mark.parametrize("overlapping_poll", [False, True])
async def test_cold_project_menu_and_immediate_delivery_fit_default_budget_without_timer_moves(
    db, monkeypatch, seconds_per_http, overlapping_poll
):
    """HTTP-only virtual elapsed time; no retry/lease/proof timer is advanced or rewritten."""
    from types import SimpleNamespace

    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget, request_lane
    from jt_oz_bridge.services import runtime_enrollment as identity_module
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    client, clock, calls = pipeline.scope.client, [100.0], []
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    client.budget = budget
    delegate = client.client._transport

    def peer(request):
        path = request.url.path.removeprefix("/api/v1/")
        if path == "users/me":
            data = {"user_id": 11, "is_bot": True, "bot_owner_id": 7, "role": 400}
        elif path == "server_settings":
            data = {"realm_url": client.url, "zulip_version": "12.3", "zulip_feature_level": 500}
        else:
            return delegate.handler(request)
        return httpx.Response(200, json={"result": "success", **data})

    async def elapsed_http(request):
        clock[0] += seconds_per_http
        calls.append((request.method, request.url.path))

    client.client._transport = httpx.MockTransport(peer)
    client.client.event_hooks["request"].append(elapsed_http)
    monkeypatch.setattr(identity_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    client.verify_identity = identity_module.ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=7, url=client.url, zulip_version="12.3", feature_level=500
        ),
    )

    async def poll():
        with request_lane("control"):
            return await pipeline.consumer.poll()

    try:
        await pipeline.consumer.start()
        server.input("!projects", 101, topic="Cold complete menu synthetic")
        await poll()
        assert len(await rows(db, CommandReceipt)) == 1
        assert (await rows(db, CommandReceipt))[0].state == "completed"
        assert not server.posts
        if overlapping_poll:
            await asyncio.gather(poll(), pipeline.deliver_once())
        else:
            await pipeline.deliver_once()
        assert len(server.posts) == 1
        assert "Choose a project" in visible(server.posts[0]["content"])
        deliveries = await rows(db, Delivery)
        assert len(deliveries) == 1 and deliveries[0].state == "delivered"
        assert not await rows(db, ZulipReceiptRetry)
        assert budget.deferred == 0 and len(calls) < 180
        assert clock[0] == pytest.approx(100 + seconds_per_http * len(calls))
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
        assert not await rows(db, Action) and not native.submitted
        assert not await rows(db, Binding)
    finally:
        await client.close()


@pytest.mark.parametrize("seconds_per_http", [0.15, 0.3])
async def test_entire_mobile_binding_flow_fits_original_budget_without_timer_moves(
    db, monkeypatch, seconds_per_http
):
    """Four immediate original-menu controls, real identity, no scheduling shortcuts.

    Only request start latency advances the isolated HTTP scheduling clock. This
    is a synthetic cost/causality check, not Native or mobile freshness evidence.
    No retry, delivery, lease, proof or token deadline is advanced or rewritten.
    """
    from types import SimpleNamespace

    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget, request_lane
    from jt_oz_bridge.services import runtime_enrollment as identity_module
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    install_synthetic_native_current_for_budget_only(pipeline, native, monkeypatch)
    client, clock, calls = pipeline.scope.client, [100.0], []
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    client.budget = budget
    delegate = client.client._transport

    def peer(request):
        path = request.url.path.removeprefix("/api/v1/")
        if path == "users/me":
            # get-own-user declares is_active since FL10; incomplete responses
            # are covered separately and retain the original user.info reads.
            data = {
                "user_id": 11,
                "is_bot": True,
                "is_active": True,
                "bot_owner_id": 7,
                "role": 400,
            }
        elif path == "server_settings":
            data = {"realm_url": client.url, "zulip_version": "12.3", "zulip_feature_level": 500}
        elif path == "streams/10/members":
            # Two synthetic Humans and the dedicated Bot.
            data = {"subscribers": [7, 8, 11]}
        else:
            return delegate.handler(request)
        return httpx.Response(200, json={"result": "success", **data})

    async def elapsed_http(request):
        clock[0] += seconds_per_http
        calls.append((request.method, request.url.path))

    client.client._transport = httpx.MockTransport(peer)
    client.client.event_hooks["request"].append(elapsed_http)
    monkeypatch.setattr(identity_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    client.verify_identity = identity_module.ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=7, url=client.url, zulip_version="12.3", feature_level=500
        ),
    )

    async def poll():
        with request_lane("control"):
            return await pipeline.consumer.poll()

    timeline = []
    original_ids = []
    commands = ("!projects", "!1", "!1", "!confirm")
    fragments = (
        "Choose a project",
        "Choose a conversation",
        "Connect this conversation",
        "Connected.",
    )
    try:
        await pipeline.consumer.start()
        for index, (text, fragment) in enumerate(zip(commands, fragments, strict=True)):
            mid = max(server.messages) + 1
            original_ids.append(mid)
            server.input(text, mid, topic="Entire mobile original-budget flow synthetic")
            server.next_mid = mid + 1
            started = len(calls)
            states = await poll()
            routed_http = len(calls) - started
            await pipeline.deliver_once()
            timeline.append(
                {
                    "command": text,
                    "human_message_id": mid,
                    "states": states,
                    "poll_http": routed_http,
                    "delivery_http": len(calls) - started - routed_http,
                    "total_http": len(calls),
                    "posts": len(server.posts),
                    "deferred": budget.deferred,
                }
            )
            print("mobile_flow_http_timeline", json.dumps(timeline), flush=True)
            # Stop on the first actual defer/failure; never move a retry timer
            # or manufacture a later reply merely to reach the next selection.
            assert not {"held", "ambiguous", "deferred"} & set(states), timeline
            assert budget.deferred == 0, timeline
            assert len(server.posts) == index + 1, timeline
            posted = server.posts[-1]
            assert posted["id"] > mid and posted["subject"] == server.messages[mid]["subject"]
            assert fragment in visible(posted["content"]), timeline
            assert server.messages[mid]["content"] == text
            assert not await rows(db, ZulipReceiptRetry), timeline
            assert all(row.state == "delivered" for row in await rows(db, Delivery)), timeline
            assert all(row.state == "completed" for row in await rows(db, CommandReceipt))

        # Include the last dedicated Bot echo as well as the echoes consumed
        # with each subsequent Human command. No echo may become Native input.
        assert set(await poll()) <= {"ignored", "already_claimed_or_settled"}
        assert len(server.posts) == 4 and len(await rows(db, Delivery)) == 4
        assert original_ids == sorted(set(original_ids))
        bindings = await rows(db, Binding)
        assert len(bindings) == 1 and bindings[0].session_id == REF.upstream_session_id
        assert bindings[0].canonical_directory == REF.canonical_directory
        assert bindings[0].owner_id == 7 and bindings[0].audience_user_ids == [7, 8]
        assert len(await rows(db, CommandReceipt)) == 4
        assert any(token.used for token in await rows(db, ControlToken))
        assert budget.deferred == 0 and len(calls) < 180, timeline
        assert clock[0] == pytest.approx(100 + seconds_per_http * len(calls))
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
        assert not native.submitted and not await rows(db, Action)
    finally:
        await client.close()


@pytest_asyncio.fixture
async def closed_menu_http_fixture(db):
    """Synthetic catalog/HTTP with the actual Bot identity guard; no Native writes."""
    from types import SimpleNamespace

    from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity

    pipeline, server, native, *_ = await setup(db, bound=False)
    client = pipeline.scope.client
    delegate = client.client._transport

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
    await pipeline.consumer.start()
    try:
        yield SimpleNamespace(pipeline=pipeline, server=server, native=native, client=client)
    finally:
        await client.close()


async def test_closed_menu_commits_tokens_receipt_target_and_all_pages_once(
    db, closed_menu_http_fixture
):
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.models import DeliveryBatch
    from jt_oz_bridge.storage.output_models import OutputDestination

    p = closed_menu_http_fixture
    p.server.input("!projects", 101, topic="Atomic closed menu")
    p.server.next_mid = 102
    assert await p.pipeline.consumer.poll() == ("reply",)
    receipts, batches = await rows(db, CommandReceipt), await rows(db, DeliveryBatch)
    tokens = await rows(db, ControlToken)
    assert len(receipts) == len(batches) == len(await rows(db, OutputDestination)) == 1
    assert (
        receipts[0].state == "completed"
        and receipts[0].response["queued_batch_id"] == batches[0].id
    )
    assert len(tokens) == 2 and not any(token.used for token in tokens)
    assert len(await rows(db, Delivery)) == batches[0].page_count == 1
    assert not p.server.posts and not await rows(db, Binding)
    source = await p.pipeline.source.read("realm", 101)
    replay = await p.pipeline.router.route(source)
    assert replay.queued_batch_id == batches[0].id
    assert len(await rows(db, DeliveryBatch)) == 1 and len(await rows(db, ControlToken)) == 2
    await p.pipeline.deliver_once()
    assert len(p.server.posts) == 1 and not p.native.submitted and not await rows(db, Action)


async def prepared_closed_confirmation(p, monkeypatch):
    """Only the SQL/HTTP boundary uses the declared synthetic Native current fixture."""
    install_synthetic_native_current_for_budget_only(p.pipeline, p.native, monkeypatch)
    topic = "Closed original binding transaction synthetic"
    for text in ("!projects", "!1", "!1"):
        mid = max(p.server.messages) + 1
        p.server.input(text, mid, topic=topic)
        p.server.next_mid = mid + 1
        states = await p.pipeline.consumer.poll()
        assert "reply" in states
        await p.pipeline.deliver_once()
    assert len(p.server.posts) == 3
    mid = max(p.server.messages) + 1
    p.server.input("!confirm", mid, topic=topic)
    p.server.next_mid = mid + 1
    return mid


@pytest.mark.parametrize(
    "fault",
    [None, "source", "preview", "view", "operate", "fence", "cancel", "current", "after-commit"],
)
async def test_closed_confirmation_keeps_binding_token_receipt_and_ack_atomic(
    db, closed_menu_http_fixture, monkeypatch, fault
):
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.durable import Conflict
    from jt_oz_bridge.storage.models import DeliveryBatch, Grant, WorkerLease

    p = closed_menu_http_fixture
    mid = await prepared_closed_confirmation(p, monkeypatch)
    token_before = sorted((row.token_hash, row.used) for row in await rows(db, ControlToken))
    confirmations = p.pipeline.router.unbound.confirmations
    if fault in {"source", "preview", "current"}:
        original = confirmations._observed_native_snapshot

        async def changed(selected):
            snapshot, require_current = await original(selected)
            if fault == "source":
                p.server.messages[mid]["content"] = "!confirm changed"
            elif fault == "preview":
                p.server.messages[mid - 1]["content"] = "different original preview"
            else:

                def require_current():
                    raise Conflict("synthetic_current_proof_expired")

            return snapshot, require_current

        monkeypatch.setattr(confirmations, "_observed_native_snapshot", changed)
    elif fault in {"view", "operate", "fence", "cancel"}:
        original = p.pipeline.discovery_outbox.queue_batch_in_session

        async def changed(session, *args, **kwargs):
            result = await original(session, *args, **kwargs)
            if fault in {"view", "operate"}:
                await session.execute(
                    update(Grant)
                    .where(Grant.user_id == (8 if fault == "view" else 7))
                    .values(active=False)
                )
            elif fault == "fence":
                await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
            else:
                raise asyncio.CancelledError()
            return result

        monkeypatch.setattr(p.pipeline.discovery_outbox, "queue_batch_in_session", changed)
    elif fault == "after-commit":
        inbox = p.pipeline.router.unbound.inbox
        original = inbox.finish

        async def committed_then_cancelled(*args, **kwargs):
            await original(*args, **kwargs)
            raise asyncio.CancelledError()

        monkeypatch.setattr(inbox, "finish", committed_then_cancelled)
    if fault in {"cancel", "after-commit"}:
        with pytest.raises(asyncio.CancelledError):
            await p.pipeline.consumer.poll()
    else:
        await p.pipeline.consumer.poll()
    successful = fault in {None, "after-commit"}
    assert len(await rows(db, Binding)) == int(successful)
    assert (
        len(await rows(db, DeliveryBatch)) == len(await rows(db, Delivery)) == 3 + int(successful)
    )
    last = next(row for row in await rows(db, CommandReceipt) if row.message_id == mid)
    assert (last.state == "completed") is successful
    tokens_after = sorted((row.token_hash, row.used) for row in await rows(db, ControlToken))
    if successful:
        assert sum(used for _, used in tokens_after) == sum(used for _, used in token_before) + 1
        await p.pipeline.deliver_once()
        assert len(p.server.posts) == 4
        assert "Connected." in visible(p.server.posts[-1]["content"])
    else:
        assert tokens_after == token_before and len(p.server.posts) == 3
    assert not p.native.submitted and not await rows(db, Action)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "text",
        "saved-text",
        "source",
        "receipt",
        "binding",
        "session",
        "title",
        "late-operate",
        "manifest",
        "page",
        "view",
        "operate",
        "fence",
    ],
)
async def test_already_committed_binding_ack_validates_without_http_or_requeue(
    db, closed_menu_http_fixture, monkeypatch, fault
):
    from dataclasses import replace

    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.durable import Conflict, digest
    from jt_oz_bridge.storage.models import DeliveryBatch, Grant, WorkerLease

    p = closed_menu_http_fixture
    mid = await prepared_closed_confirmation(p, monkeypatch)
    publish = p.pipeline.consumer.publish
    captured = []

    async def capture(routed):
        captured.append(routed)
        return await publish(routed)

    monkeypatch.setattr(p.pipeline.consumer, "publish", capture)
    await p.pipeline.consumer.poll()
    routed = captured[-1]
    assert routed.queued_batch_id and routed.binding_id
    if fault == "text":
        routed = replace(routed, text="different ACK")
    elif fault == "late-operate":
        import jt_oz_bridge.services.reply_publisher as publisher_module

        lock_scope = publisher_module.lock_output_scope
        visits = []

        async def revoked_after_scope(session_bindings, session, binding):
            result = await lock_scope(session_bindings, session, binding)
            visits.append(True)
            if len(visits) == 2:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            return result

        monkeypatch.setattr(publisher_module, "lock_output_scope", revoked_after_scope)
    elif fault is not None:
        async with db.sessions.begin() as session:
            receipt = await session.scalar(
                select(CommandReceipt).where(CommandReceipt.message_id == mid)
            )
            if fault in {"saved-text", "source"}:
                data = dict(receipt.response)
                if fault == "saved-text":
                    routed = replace(routed, text="changed in both places")
                    data["text"] = routed.text
                else:
                    data["confirmation_source"] = {
                        **data["confirmation_source"],
                        "message_id": mid + 1000,
                    }
                receipt.response = data
            elif fault == "receipt":
                receipt.state = "processing"
            elif fault == "binding":
                await session.execute(update(Binding).values(anchor_message_id=mid + 1))
            elif fault == "session":
                await session.execute(update(Binding).values(session_id="another-original-session"))
            elif fault == "title":
                await session.execute(update(Binding).values(title="different confirmed title"))
            elif fault == "manifest":
                await session.execute(
                    update(DeliveryBatch)
                    .where(DeliveryBatch.id == routed.queued_batch_id)
                    .values(renderer_version="different")
                )
            elif fault == "page":
                row = await session.scalar(
                    select(Delivery).where(Delivery.batch_id == routed.queued_batch_id)
                )
                row.payload = {**row.payload, "content": "changed page\n\n`jtoz:" + row.id + "`"}
                row.payload_hash = digest(row.payload)
            elif fault in {"view", "operate"}:
                await session.execute(
                    update(Grant)
                    .where(Grant.user_id == (8 if fault == "view" else 7))
                    .values(active=False)
                )
            elif fault == "fence":
                await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
    http_before, deliveries_before = len(p.server.calls), len(await rows(db, Delivery))
    if fault is None:
        batch = await publish(routed)
        assert batch.id == routed.queued_batch_id
    else:
        with pytest.raises((AccessDenied, Conflict, ValueError)):
            await publish(routed)
    assert len(p.server.calls) == http_before
    assert len(await rows(db, Delivery)) == deliveries_before == 4
    assert len(p.server.posts) == 3 and not p.native.submitted


@pytest.mark.parametrize("mutation", ["source", "member", "privacy"])
async def test_closed_session_catalog_mutation_never_commits_staged_selection(
    db, closed_menu_http_fixture, monkeypatch, mutation
):
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.models import DeliveryBatch
    from jt_oz_bridge.storage.output_models import OutputDestination

    p = closed_menu_http_fixture
    p.server.input("!projects", 101, topic="Atomic closed catalog mutation")
    p.server.next_mid = 102
    await p.pipeline.consumer.poll()
    await p.pipeline.deliver_once()
    old_tokens = sorted((row.token_hash, row.used) for row in await rows(db, ControlToken))
    catalog = p.pipeline.discovery.catalogs[REF.backend_id].client
    original = catalog.list_sessions
    visited = []

    async def changed(*args, **kwargs):
        result = await original(*args, **kwargs)
        visited.append("read-only-original-catalog")
        if mutation == "source":
            p.server.messages[103]["content"] = "!2"
        elif mutation == "member":
            prior = p.server.handle

            def handle(request):
                if request.url.path.endswith("/streams/10/members"):
                    return httpx.Response(200, json={"result": "success", "subscribers": [7, 11]})
                return prior(request)

            p.client.client._transport = httpx.MockTransport(handle)
        else:
            p.server.private = False
        return result

    monkeypatch.setattr(catalog, "list_sessions", changed)
    p.server.input("!1", 103, topic="Atomic closed catalog mutation")
    p.server.next_mid = 104
    await p.pipeline.consumer.poll()
    assert visited == ["read-only-original-catalog"]
    assert sorted((row.token_hash, row.used) for row in await rows(db, ControlToken)) == old_tokens
    assert len(await rows(db, DeliveryBatch)) == len(await rows(db, OutputDestination)) == 1
    assert len(await rows(db, Delivery)) == len(p.server.posts) == 1
    assert not await rows(db, Binding) and not p.native.submitted and not await rows(db, Action)


@pytest.mark.parametrize("failure", ["grant", "fence", "cancel"])
async def test_closed_menu_late_sql_failure_rolls_back_tokens_receipt_target_and_batch(
    db, closed_menu_http_fixture, monkeypatch, failure
):
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.models import DeliveryBatch, Grant, WorkerLease
    from jt_oz_bridge.storage.output_models import OutputDestination

    p = closed_menu_http_fixture
    original = p.pipeline.discovery_outbox.queue_scope_batch_in_session
    visited = []

    async def changed(session, *args, **kwargs):
        visited.append("same-ownSQL-transaction")
        if failure == "grant":
            await session.execute(update(Grant).values(active=False))
        elif failure == "fence":
            await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
        result = await original(session, *args, **kwargs)
        if failure == "cancel":
            raise asyncio.CancelledError()
        return result

    monkeypatch.setattr(p.pipeline.discovery_outbox, "queue_scope_batch_in_session", changed)
    p.server.input("!projects", 101, topic="Atomic closed SQL rollback")
    p.server.next_mid = 102
    if failure == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await p.pipeline.consumer.poll()
    else:
        await p.pipeline.consumer.poll()
    assert visited == ["same-ownSQL-transaction"]
    assert not await rows(db, ControlToken) and not await rows(db, OutputDestination)
    assert not await rows(db, DeliveryBatch) and not await rows(db, Delivery)
    assert all(row.state != "completed" for row in await rows(db, CommandReceipt))
    assert not p.server.posts and not p.native.submitted and not await rows(db, Action)


@pytest.mark.parametrize("status", [401, 403])
async def test_closed_catalog_permanent_auth_failure_is_held_without_transient_replay(
    db, closed_menu_http_fixture, monkeypatch, status
):
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    p = closed_menu_http_fixture
    p.server.input("!projects", 101, topic="Closed permanent auth failure")
    p.server.next_mid = 102
    await p.pipeline.consumer.poll()
    await p.pipeline.deliver_once()
    old_tokens = sorted((row.token_hash, row.used) for row in await rows(db, ControlToken))
    catalog = p.pipeline.discovery.catalogs[REF.backend_id].client
    original = catalog.list_sessions

    async def denied(*args, **kwargs):
        result = await original(*args, **kwargs)
        previous = p.client.client._transport

        def peer(request):
            if request.url.path.endswith("/messages/103"):
                return httpx.Response(
                    status, json={"result": "error", "msg": "synthetic auth failure"}
                )
            return previous.handler(request)

        p.client.client._transport = httpx.MockTransport(peer)
        return result

    monkeypatch.setattr(catalog, "list_sessions", denied)
    p.server.input("!1", 103, topic="Closed permanent auth failure")
    p.server.next_mid = 104
    assert "held" in await p.pipeline.consumer.poll()
    receipt = next(row for row in await rows(db, CommandReceipt) if row.message_id == 103)
    assert receipt.state == "ambiguous" and not await rows(db, ZulipReceiptRetry)
    assert sorted((row.token_hash, row.used) for row in await rows(db, ControlToken)) == old_tokens
    assert len(await rows(db, Delivery)) == len(p.server.posts) == 1
    assert not await rows(db, Binding) and not p.native.submitted


async def test_fresh_closed_event_is_authenticated_once_by_observer_not_nested_source_readers(
    db, closed_menu_http_fixture, monkeypatch
):
    p = closed_menu_http_fixture
    source_read = AsyncMock(wraps=p.pipeline.source.read)
    monkeypatch.setattr(p.pipeline.source, "read", source_read)
    p.server.input("!projects", 101, topic="Untrusted wire closed admission")
    p.server.next_mid = 102
    assert await p.pipeline.consumer.poll() == ("reply",)
    source_read.assert_not_awaited()
    assert p.server.calls.count(("GET", "messages/101")) == 2
    assert not p.native.submitted and not await rows(db, Action)
    await p.pipeline.deliver_once()
    assert len(p.server.posts) == 1


@pytest.mark.parametrize("fault", ["text", "author", "channel", "topic", "revision"])
async def test_closed_wire_proposal_never_authorizes_different_original_source(
    db, closed_menu_http_fixture, fault
):
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken

    p = closed_menu_http_fixture
    p.server.input("!projects", 101, topic="Closed event mismatch")
    p.server.next_mid = 102
    actual = p.server.messages[101]
    if fault == "text":
        actual["content"] = "!oz backends"
    elif fault == "author":
        actual["sender_id"] = 8
    elif fault == "channel":
        actual["stream_id"] = 12
    elif fault == "topic":
        actual["subject"] = "Other topic"
    else:
        actual.update(edit_history=[{}], last_edit_timestamp=1)
    assert "held" in await p.pipeline.consumer.poll()
    assert not await rows(db, ControlToken) and not await rows(db, CommandReceipt)
    assert not await rows(db, Delivery) and not p.server.posts and not p.native.submitted


@pytest.mark.parametrize("fault", ["edited-wire", "historical", "recovered", "bot"])
async def test_nonfresh_event_does_not_enter_closed_wire_admission(
    db, closed_menu_http_fixture, monkeypatch, fault
):
    p = closed_menu_http_fixture
    forbidden = AsyncMock(side_effect=AssertionError("not a fresh original wire candidate"))
    monkeypatch.setattr(p.pipeline.router, "route_closed_menu_event", forbidden, raising=False)
    event = p.server.input(
        "!projects",
        101,
        author=11 if fault == "bot" else 7,
        topic="Nonfresh event keeps original path",
    )
    p.server.next_mid = 102
    if fault == "edited-wire":
        event["message"]["last_edit_timestamp"] = 1
    elif fault == "historical":
        event["historical"] = True
    elif fault == "recovered":
        original = p.pipeline.journal.claim

        async def recovered(*args, **kwargs):
            claim = await original(*args, **kwargs)
            return replace(claim, recovered=True) if claim else claim

        monkeypatch.setattr(p.pipeline.journal, "claim", recovered)
    await p.pipeline.consumer.poll()
    forbidden.assert_not_awaited()
    assert not p.native.submitted and not await rows(db, Action)


@pytest.mark.parametrize("fault", ["auth", "guard"])
async def test_selected_closed_event_failure_never_falls_back_to_other_router(
    db, closed_menu_http_fixture, monkeypatch, fault
):
    from jt_oz_bridge.adapters.zulip.client import ZulipError
    from jt_oz_bridge.storage.command_models import CommandReceipt

    p = closed_menu_http_fixture
    closed = p.pipeline.router.unbound.closed_menus
    original = closed.route
    called = []

    async def failed(*args, **kwargs):
        called.append("selected")
        if fault == "auth":
            raise ZulipError("synthetic closed admission denied")
        p.client.verify_identity = AsyncMock(return_value=True)
        return await original(*args, **kwargs)

    monkeypatch.setattr(closed, "route", failed)
    legacy = AsyncMock(wraps=p.pipeline.router.route)
    monkeypatch.setattr(p.pipeline.router, "route", legacy)
    source_read = AsyncMock(wraps=p.pipeline.source.read)
    monkeypatch.setattr(p.pipeline.source, "read", source_read)
    p.server.input("!projects", 101, topic="No fallback after closed selection")
    p.server.next_mid = 102
    assert "held" in await p.pipeline.consumer.poll()
    assert called == ["selected"]
    legacy.assert_not_awaited()
    source_read.assert_not_awaited()
    assert not await rows(db, CommandReceipt) and not await rows(db, Delivery)
    assert not p.native.submitted and not await rows(db, Action)


async def test_closed_candidate_none_is_effect_free_before_original_fallback(
    db, closed_menu_http_fixture
):
    from jt_oz_bridge.domain.execution import HumanMessage
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken

    p = closed_menu_http_fixture
    proposal = HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic="No prior menu",
        message_id=101,
        revision=0,
        author_id=7,
        text="!1",
    )
    # This is untrusted proposal data, not a Source receipt or Human approval.
    assert await p.pipeline.router.route_closed_menu_event(proposal) is None
    assert not await rows(db, CommandReceipt) and not await rows(db, ControlToken)
    assert not await rows(db, Delivery) and not await rows(db, Binding)
    assert not p.native.calls and not p.server.posts
    assert not any(path.startswith("messages/") for _, path in p.server.calls)


async def test_binding_arrival_after_candidate_sql_denies_closed_native_and_token_effects(
    db, closed_menu_http_fixture, monkeypatch
):
    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.control_models import ControlToken

    p = closed_menu_http_fixture
    closed = p.pipeline.router.unbound.closed_menus
    original = closed.route
    catalog = p.pipeline.discovery.catalogs[REF.backend_id].client
    native_catalog = AsyncMock(wraps=catalog.list_sessions)
    monkeypatch.setattr(catalog, "list_sessions", native_catalog)

    async def bound(*args, **kwargs):
        await p.pipeline.bindings.bind("realm", 7, 10, "Binding race after proposal", REF)
        return await original(*args, **kwargs)

    monkeypatch.setattr(closed, "route", bound)
    p.server.input("!projects", 101, topic="Binding race after proposal")
    p.server.next_mid = 102
    assert "held" in await p.pipeline.consumer.poll()
    assert len(await rows(db, Binding)) == 1
    assert not await rows(db, CommandReceipt) and not await rows(db, ControlToken)
    assert not await rows(db, Delivery) and not p.server.posts and not p.native.submitted
    native_catalog.assert_not_awaited()


@pytest.mark.parametrize(
    "budget_window,retry_after,expected_delay",
    [(None, 0.25, 1), (60, 0.25, 60), (60, 120, 120), (60, 10000, 3600)],
)
async def test_dispatch_preclaim_rate_limit_waits_without_replaying_or_holding(
    db, monkeypatch, budget_window, retry_after, expected_delay
):
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited

    pipeline, _, native, _, _, _ = await setup(db)
    if budget_window is not None:
        pipeline.scope.client.budget = ZulipRequestBudget(window=budget_window)
    pipeline.dispatch_once = AsyncMock(
        side_effect=[DeliveryRateLimited(retry_after), asyncio.CancelledError()]
    )
    sleeper = AsyncMock()
    try:
        with monkeypatch.context() as patch:
            patch.setattr("jt_oz_bridge.services.consumer_runtime.asyncio.sleep", sleeper)
            with pytest.raises(asyncio.CancelledError):
                await pipeline.dispatch()
        assert pipeline.dispatch_once.await_count == 2
        sleeper.assert_awaited_once_with(expected_delay)
        assert pipeline.deferred == {"zulip_dispatch_rate_limited": 1}
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


async def test_dispatch_read_outage_backoff_is_bounded_and_resets_only_after_success(
    db, monkeypatch
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable

    pipeline, _, native, _, _, _ = await setup(db)
    pipeline.dispatch_once = AsyncMock(
        side_effect=[
            *[ZulipReadUnavailable("zulip_read_service_unavailable") for _ in range(9)],
            None,
            ZulipReadUnavailable("zulip_read_service_unavailable"),
            asyncio.CancelledError(),
        ]
    )
    sleeper, ranges = AsyncMock(), []

    def choose(lower, upper):
        ranges.append((lower, upper))
        return lower

    try:
        with monkeypatch.context() as patch:
            patch.setattr("jt_oz_bridge.services.consumer_runtime.asyncio.sleep", sleeper)
            patch.setattr("jt_oz_bridge.services.consumer_runtime.random.uniform", choose)
            with pytest.raises(asyncio.CancelledError):
                await pipeline.dispatch()
        assert [upper for _, upper in ranges] == [1, 2, 4, 8, 16, 32, 60, 60, 60, 1]
        assert all(1 <= lower <= upper <= 60 for lower, upper in ranges)
        assert pipeline.deferred == {"zulip_dispatch_read_unavailable": 10}
        assert pipeline.dispatch_once.await_count == 12
        assert sleeper.await_count == 11  # ten backoffs and the original successful-loop interval
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("error_kind", ["auth", "privacy", "conflict", "schema"])
async def test_dispatch_permanent_authority_or_schema_failure_is_never_made_retryable(
    db, monkeypatch, error_kind
):
    from jt_oz_bridge.adapters.zulip.client import ZulipAuthenticationFailed, ZulipError
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.storage.durable import Conflict

    errors = {
        "auth": ZulipAuthenticationFailed("authentication_failed"),
        "privacy": AccessDenied("private_channel_required"),
        "conflict": Conflict("consumer_fence_changed"),
        "schema": ZulipError("schema_mismatch"),
    }
    pipeline, _, native, _, _, _ = await setup(db)
    error = errors[error_kind]
    pipeline.dispatch_once = AsyncMock(side_effect=error)
    sleeper = AsyncMock()
    try:
        with monkeypatch.context() as patch:
            patch.setattr("jt_oz_bridge.services.consumer_runtime.asyncio.sleep", sleeper)
            with pytest.raises(type(error)) as caught:
                await pipeline.dispatch()
        assert caught.value is error
        pipeline.dispatch_once.assert_awaited_once()
        sleeper.assert_not_awaited()
        assert pipeline.deferred == {} and not native.submitted
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("failure", ["rate_limit", "read_outage"])
async def test_cancel_dispatch_preclaim_backoff_does_not_start_another_attempt(
    db, monkeypatch, failure
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited

    pipeline, _, native, _, _, _ = await setup(db)
    error = (
        DeliveryRateLimited(60)
        if failure == "rate_limit"
        else ZulipReadUnavailable("zulip_read_service_unavailable")
    )
    pipeline.dispatch_once = AsyncMock(side_effect=error)
    sleeper = AsyncMock(side_effect=asyncio.CancelledError())
    try:
        with monkeypatch.context() as patch:
            patch.setattr("jt_oz_bridge.services.consumer_runtime.asyncio.sleep", sleeper)
            with pytest.raises(asyncio.CancelledError):
                await pipeline.dispatch()
        pipeline.dispatch_once.assert_awaited_once()
        sleeper.assert_awaited_once()
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


async def test_consumer_fifo_denial_precedes_mirror_idle_typing_then_human_cancel_releases_one(
    db, monkeypatch
):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from tests.integration.test_dispatch import _fifo_raw_row

    pipeline, server, native, _, binding, _ = await setup(db)
    calls = []

    def handle(request):
        calls.append((request.method, request.url.path))
        return server.handle(request)

    pipeline.scope.client.client._transport = httpx.MockTransport(handle)
    try:
        await pipeline.consumer.start()
        server.input("Old unsent original", 101)
        await pipeline.consumer.poll()
        old = (await rows(db, Action))[0]
        assert await pipeline.dispatcher.held(old, "source_or_identity_changed") == "held"
        server.input("New original work", 102)
        await pipeline.consumer.poll()
        actions = await rows(db, Action)
        later = next(item for item in actions if item.id != old.id)
        original = await _fifo_raw_row(db, old.id)
        calls.clear()
        remote = AsyncMock(side_effect=AssertionError("blocked FIFO must precede remote work"))

        @asynccontextmanager
        async def processing(binding):
            pytest.fail("blocked FIFO must not report processing")
            yield

        with monkeypatch.context() as patch:
            patch.setattr(
                pipeline,
                "mirrors",
                SimpleNamespace(readers={REF}, require_continuity=remote),
            )
            patch.setattr(pipeline, "idle", remote)
            patch.setattr(pipeline.dispatcher, "advance", remote)
            patch.setattr(pipeline.dispatcher, "processing", processing)
            await pipeline.dispatch_once()
        remote.assert_not_awaited()
        assert not calls and not native.submitted
        assert pipeline.deferred.get("dispatch_fifo_blocked") == 1
        assert await _fifo_raw_row(db, old.id) == original
        assert (await pipeline.dispatcher.load(later.id)).state == "queued"
        # A synthetic Human event through the real service pipeline
        # explicitly cancels via Source/event journal, not SQL or queue resume.
        server.input("!oz cancel " + old.id, 103)
        await pipeline.consumer.poll()
        assert (await pipeline.dispatcher.load(old.id)).state == "cancelled"
        calls.clear()
        await pipeline.dispatch_once()
        await pipeline.dispatch_once()
        assert calls and len(native.submitted) == 1
        assert native.submitted[0][2] == later.id
        assert (await pipeline.dispatcher.load(later.id)).state == "admitted"
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("boundary", [1, 2])
@pytest.mark.parametrize("limited", ["local", "http429"])
async def test_native_results_typed_scope_rate_retries_original_gets_without_native_replay(
    db, monkeypatch, caplog, boundary, limited
):
    """Real result collector + encrypted ownDB; synthetic HTTP, not live proof."""
    from types import SimpleNamespace

    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, ZulipRequestBudget
    from jt_oz_bridge.services import consumer_runtime as module
    from jt_oz_bridge.storage.resource_models import ResourceResultRecord, ResourceTextRecord

    pipeline, server, native, reader, binding, _ = await setup(db)
    try:
        server.input("Exact original collection prompt")
        await pipeline.consumer.start()
        await pipeline.consumer.poll()
        queued = (await rows(db, Action))[0]
        assert await pipeline.dispatcher.advance(queued.id) == "admitted"
        original_get = pipeline.bindings.get
        original_http = server.handle
        gets, pauses = [], []
        armed = False
        budget = ZulipRequestBudget()
        while True:
            try:
                budget.acquire()
            except RequestBudgetDeferred:
                break

        async def selected_get(*args, **kwargs):
            nonlocal armed
            gets.append(args)
            armed = len(gets) == boundary
            if armed and limited == "local":
                pipeline.scope.client.budget = budget
            return await original_get(*args, **kwargs)

        def http(request):
            nonlocal armed
            if armed and limited == "http429":
                armed = False
                return httpx.Response(
                    429,
                    headers={"Retry-After": "2"},
                    json={"result": "error", "code": "RATE_LIMIT_HIT"},
                )
            return original_http(request)

        class StopCollection(asyncio.CancelledError):
            pass

        async def pause(delay):
            pauses.append(delay)
            raise StopCollection()

        monkeypatch.setattr(pipeline.bindings, "get", selected_get)
        pipeline.scope.client.client._transport = httpx.MockTransport(http)
        proxy = SimpleNamespace(**{n: getattr(asyncio, n) for n in dir(asyncio)})
        proxy.sleep = pause
        monkeypatch.setattr(module, "asyncio", proxy)
        with pytest.raises(StopCollection):
            await pipeline.collect()
        assert len(pauses) == 1 and pauses[0] >= (60 if limited == "local" else 2)
        assert pipeline.deferred["native_result_scope_rate_limited"] == 1
        assert reader.calls == boundary - 1
        assert len(native.submitted) == 1
        assert not await rows(db, ResourceResultRecord)
        assert not await rows(db, ResourceTextRecord)
        assert "native_result_collection_deferred" in caplog.text
        assert (
            "RequestBudgetDeferred" if limited == "local" else "DeliveryRateLimited"
        ) in caplog.text
        pipeline.scope.client.budget = None
        monkeypatch.setattr(pipeline.bindings, "get", original_get)
        await pipeline.collect_once()
        saved = (await rows(db, Action))[0]
        assert (
            saved.state == "completed"
            and saved.status_reason == "native_resource_terminal_verified"
        )
        assert len(await rows(db, ResourceResultRecord)) == 1
        assert len(await rows(db, ResourceTextRecord)) == 1
        await pipeline.collect_once()
        assert len(await rows(db, ResourceResultRecord)) == 1
        assert len(native.submitted) == 1
        assert len(await rows(db, Action)) == 1
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("change", ["revoke_after_wait", "committed_before_rate"])
async def test_native_results_retry_preserves_revocation_and_already_committed_result(
    db, monkeypatch, change
):
    from types import SimpleNamespace

    from jt_oz_bridge.domain.delivery import DeliveryRateLimited
    from jt_oz_bridge.services import consumer_runtime as module
    from jt_oz_bridge.storage.models import Grant
    from jt_oz_bridge.storage.resource_models import ResourceResultRecord, ResourceTextRecord

    pipeline, server, native, reader, binding, _ = await setup(db)
    try:
        server.input("One admitted original prompt")
        await pipeline.consumer.start()
        await pipeline.consumer.poll()
        identity = (await rows(db, Action))[0].id
        assert await pipeline.dispatcher.advance(identity) == "admitted"
        collector = pipeline.collectors[REF.backend_id]
        original = collector.collect

        async def limited(*args):
            if change == "committed_before_rate":
                await original(*args)  # OwnDB commit finished, never a second Native send.
            raise DeliveryRateLimited(2)

        class StopCollection(asyncio.CancelledError):
            pass

        async def pause(delay):
            assert delay >= 2
            raise StopCollection()

        proxy = SimpleNamespace(**{n: getattr(asyncio, n) for n in dir(asyncio)})
        proxy.sleep = pause
        monkeypatch.setattr(module, "asyncio", proxy)
        monkeypatch.setattr(collector, "collect", limited)
        with pytest.raises(StopCollection):
            await pipeline.collect()
        monkeypatch.setattr(collector, "collect", original)
        if change == "revoke_after_wait":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).values(active=False))
        calls = reader.calls
        await pipeline.collect_once()
        saved = (await rows(db, Action))[0]
        expected = 1 if change == "committed_before_rate" else 0
        assert len(await rows(db, ResourceResultRecord)) == expected
        assert len(await rows(db, ResourceTextRecord)) == expected
        assert reader.calls == calls
        assert saved.state == ("completed" if expected else "admitted")
        assert len(native.submitted) == 1 and len(await rows(db, Action)) == 1
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("boundary", [1, 2])
async def test_check_result_scope_429_retries_fresh_without_second_native_check(
    db, monkeypatch, caplog, boundary
):
    from types import SimpleNamespace

    from jt_oz_bridge.services import consumer_runtime as module
    from tests.integration.test_check_commands import CheckExecution, choice

    previous, server, old_native, _, _, _ = await setup(db)
    native = CheckExecution()
    native.contract_hash = old_native.contract_hash
    backend = previous.backends[REF.backend_id]
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {
            REF.backend_id: replace(
                backend, registered=replace(backend.registered, client=native), checks={REF: native}
            )
        },
        interval=0.02,
        delivery_interval=0,
    )
    try:
        await pipeline.consumer.start()
        server.input("!oz checks", 101)
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        server.input("!oz check " + choice(server.posts[-1]["content"]), 102)
        await pipeline.consumer.poll()
        identity = (await rows(db, Action))[0].id
        assert await pipeline.dispatcher.advance(identity) == "admitted"
        original = pipeline.bindings.audience_for_output
        calls = 0
        armed = False

        async def audience(*args):
            nonlocal calls, armed
            calls += 1
            armed = calls == boundary
            return await original(*args)

        def http(request):
            nonlocal armed
            if armed:
                armed = False
                return httpx.Response(
                    429,
                    headers={"Retry-After": "2"},
                    json={"result": "error", "code": "RATE_LIMIT_HIT"},
                )
            return server.handle(request)

        class StopCollection(asyncio.CancelledError):
            pass

        async def pause(delay):
            assert delay >= 2
            raise StopCollection()

        proxy = SimpleNamespace(**{n: getattr(asyncio, n) for n in dir(asyncio)})
        proxy.sleep = pause
        monkeypatch.setattr(module, "asyncio", proxy)
        monkeypatch.setattr(pipeline.bindings, "audience_for_output", audience)
        pipeline.scope.client.client._transport = httpx.MockTransport(http)
        with pytest.raises(StopCollection):
            await pipeline.collect()
        assert "phase=check error_type=DeliveryRateLimited" in caplog.text
        assert (await rows(db, Action))[0].state == "admitted"
        monkeypatch.setattr(pipeline.bindings, "audience_for_output", original)
        await pipeline.collect_once()
        assert (await rows(db, Action))[0].state == "completed"
        await pipeline.collect_once()
        assert len(native.submitted) == 1 and not old_native.submitted
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("phase", ["mirror", "collection"])
async def test_native_results_unknown_failure_keeps_original_exception_and_logs_only_labels(
    db, monkeypatch, caplog, phase
):
    pipeline, _, _, _, _, _ = await setup(db)

    class PrivateProviderFailure(Exception):
        pass

    error = PrivateProviderFailure("PRIVATE_PAYLOAD https://credentials.invalid")
    monkeypatch.setattr(
        pipeline, "mirror_once", AsyncMock(side_effect=error if phase == "mirror" else None)
    )
    monkeypatch.setattr(pipeline, "collect_once", AsyncMock(side_effect=error))
    try:
        with pytest.raises(PrivateProviderFailure) as caught:
            await pipeline.collect()
        assert caught.value is error and pipeline.deferred == {}
        assert f"phase={phase} error_type=OtherError" in caplog.text
        assert "PRIVATE" not in caplog.text and "credentials.invalid" not in caplog.text
        assert "PrivateProviderFailure" not in caplog.text
    finally:
        await pipeline.scope.client.close()


async def test_native_results_rate_refill_keeps_actual_supervisor_and_single_result(db):
    from jt_oz_bridge.services.runtime import RuntimeWorker, SupervisedRuntime
    from jt_oz_bridge.storage.resource_models import ResourceResultRecord

    pipeline, server, native, reader, _, _ = await setup(db)
    runtime = None
    try:
        server.input("One result after scope refill")
        await pipeline.consumer.start()
        await pipeline.consumer.poll()
        identity = (await rows(db, Action))[0].id
        assert await pipeline.dispatcher.advance(identity) == "admitted"
        limited = True

        def http(request):
            nonlocal limited
            if limited:
                limited = False
                return httpx.Response(
                    429,
                    headers={"Retry-After": "1"},
                    json={"result": "error", "code": "RATE_LIMIT_HIT"},
                )
            return server.handle(request)

        pipeline.scope.client.client._transport = httpx.MockTransport(http)
        runtime = SupervisedRuntime(
            db, pipeline.fence, (), (RuntimeWorker("native-results", pipeline.collect),)
        )
        await runtime.start()

        async def completed():
            return (await rows(db, Action))[0].state == "completed"

        await until(completed)  # Original 8s deadline; no virtual clock or retry timer rewrite.
        assert runtime.healthy and runtime.failure_detail is None
        assert pipeline.deferred["native_result_scope_rate_limited"] == 1
        assert len(await rows(db, ResourceResultRecord)) == 1
        assert len(native.submitted) == 1 and reader.calls == 1
    finally:
        if runtime is not None:
            await runtime.close()
        await pipeline.scope.client.close()


@pytest.mark.parametrize("retry,expected", [(float("inf"), 60), (10000, 3600), (-1, 1)])
async def test_native_results_retry_delay_keeps_existing_finite_scheduling_bounds(
    db, monkeypatch, retry, expected
):
    from types import SimpleNamespace

    from jt_oz_bridge.domain.delivery import DeliveryRateLimited
    from jt_oz_bridge.services import consumer_runtime as module

    pipeline, _, _, _, _, _ = await setup(db)
    monkeypatch.setattr(pipeline, "mirror_once", AsyncMock())
    monkeypatch.setattr(pipeline, "collect_once", AsyncMock(side_effect=DeliveryRateLimited(retry)))

    class StopCollection(asyncio.CancelledError):
        pass

    async def pause(delay):
        assert delay == expected
        raise StopCollection()

    proxy = SimpleNamespace(**{n: getattr(asyncio, n) for n in dir(asyncio)})
    proxy.sleep = pause
    monkeypatch.setattr(module, "asyncio", proxy)
    try:
        with pytest.raises(StopCollection):
            await pipeline.collect()
        assert pipeline.deferred == {"native_result_scope_rate_limited": 1}
    finally:
        await pipeline.scope.client.close()


async def test_direct_advanced_session_and_bind_commands_preserve_token_edges_end_to_end(
    db, monkeypatch
):
    counter = 0

    def opaque(_size):
        nonlocal counter
        counter += 1
        return "_" + f"{counter:030x}" + "_"

    monkeypatch.setattr("jt_oz_bridge.services.tokens.secrets.token_urlsafe", opaque)
    pipeline, server, native, _, _, _ = await setup(db, bound=False)
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz projects", 101)
        prior = 0
        for command, mid in [("sessions", 102), ("bind", 103), ("confirm", 104)]:
            # The preview offers `!ok <token>`; the advanced form takes the same token.
            shown = "!ok" if command == "confirm" else "!oz " + command
            menu = await post_containing(server, shown, start=prior)
            prior = server.posts.index(menu) + 1
            match = re.search(shown + r" (_[0-9a-f]{30}_)(?=[\s`])", visible(menu["content"]))
            assert match, command
            assert not native.submitted and not await rows(db, Binding)
            server.input("!oz " + command + " " + match[1], mid)

        async def bound():
            return await rows(db, Binding)

        bindings = await until(bound)
        assert len(bindings) == 1 and bindings[0].session_id == REF.upstream_session_id
        server.input("Run after direct original binding", 105)
        await post_containing(server, "PRIVATE_NATIVE_FINAL_RESULT")
        assert len(native.submitted) == 1 and native.submitted[0][0] == REF
    finally:
        await runtime.close()
