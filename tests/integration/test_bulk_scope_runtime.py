"""Synthetic complete supervised worker flow; no live Human or mobile proof."""

import asyncio
import time

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader
from jt_oz_bridge.config import ZulipBudget
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.storage.models import Action
from tests.integration.test_consumer_runtime import rows, visible
from tests.integration.test_mirrored_request_flow import qualified_mirror
from tests.integration.test_transcript_collector import entry
from tests.integration.test_transcript_publisher import assistant
from tests.support_zulip_bulk import batch_transport


@pytest.mark.parametrize("changes", ["final-only", "input-and-final"])
async def test_supervised_answer_and_typing_fit_original_budget(db, monkeypatch, changes):
    previous, server, native, results, b, reader, _, clock, calls, typing = await qualified_mirror(
        db, monkeypatch
    )
    client = previous.scope.client
    client.client._transport = httpx.MockTransport(
        batch_transport(client.client._transport.handler)
    )
    scope = ZulipScopeReader(client, channel_ids=previous.scope.channel_ids, bulk_metadata=True)
    p = ConsumerPipeline(
        db,
        previous.fence,
        scope,
        previous.backends,
        interval=1.0,
        delivery_interval=0,
        mirror_enabled=True,
    )
    token = ["baseline"]
    reader.change_token = lambda ref: token[0]
    await p.mirror_once()
    original = client.client._transport.handler
    changed = asyncio.Event()
    original_input = server.input

    def input_changed(*args, **kwargs):
        result = original_input(*args, **kwargs)
        changed.set()
        return result

    server.input = input_changed

    async def elapsed(request):
        clock[0] += 0.01
        calls.append((request.method, request.url.path))
        await asyncio.sleep(0.01)

    client.client.event_hooks["request"] = [elapsed]

    async def peer(request):
        if request.url.path.endswith("/events") and request.method == "GET":
            last = int(request.url.params["last_event_id"])
            async with asyncio.timeout(30):
                while not any(e["id"] > last for e in server.events):
                    changed.clear()
                    await changed.wait()
        response = original(request)
        return await response if asyncio.iscoroutine(response) else response

    client.client._transport = httpx.MockTransport(peer)
    original_submit = native.submit
    finish = None

    async def submitted(ref, payload, action_id):
        nonlocal finish
        admission = await original_submit(ref, payload, action_id)
        native.state = ExecutionState.RUNNING
        if changes == "input-and-final":
            token[0] = "input"

        async def complete():
            await asyncio.sleep(3)
            native.state = ExecutionState.IDLE
            action = next(a for a in await rows(db, Action) if a.id == action_id)
            reader.messages[:0] = [
                project_message(
                    {
                        "id": "terminal",
                        "type": "idle",
                        "time": {"created": 4},
                        "outcome": "succeeded",
                    }
                ),
                assistant(text="Exact supervised original answer"),
                entry(admission.upstream_id, action.payload["text"]),
            ]
            token[0] = "final"

        finish = asyncio.create_task(complete())
        return admission

    native.submit = submitted
    runtime = p.runtime()
    try:
        await runtime.start()
        client.budget = budget = ZulipRequestBudget(monotonic=lambda: clock[0])
        calls.clear()
        start = len(server.posts)
        started = time.monotonic()
        mid = max(server.messages) + 1
        server.next_mid = mid + 1
        server.input("Exact supervised original task", mid, topic=b.topic)
        async with asyncio.timeout(8):
            while not any(
                "Exact supervised original answer" in visible(m["content"])
                for m in server.posts[start:]
            ):
                assert runtime.healthy, runtime.failure_detail
                await asyncio.sleep(0.05)
        # Eight seconds is the controlled fixture's original deadline, not an
        # eight-second claim about the real LLM, network, phone or live host.
        assert time.monotonic() - started < 8
        assert len(native.submitted) == results.calls == 1
        assert [a.state for a in await rows(db, Action)] == ["completed"]
        assert typing[0] == "start" and "stop" in typing
        assert runtime.healthy and runtime.failure_detail is None
        assert budget.deferred == 0 and len(calls) < 180
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
        assert all(m["subject"] == b.topic for m in server.posts[start:])
        assert not p.deferred
    finally:
        if finish is not None:
            if not finish.done():
                finish.cancel()
            await asyncio.gather(finish, return_exceptions=True)
        await runtime.close()
        await client.close()


async def _three_consecutive_turns(
    db, monkeypatch, changes, *, append_during_lookup=False, append_rounds=1
):
    p, server, native, results, b, reader, _, clock, calls, typing = await qualified_mirror(
        db, monkeypatch, bulk_metadata=True
    )
    p = ConsumerPipeline(
        db, p.fence, p.scope, p.backends, interval=1.0, delivery_interval=0, mirror_enabled=True
    )
    token = ["baseline"]
    reader.change_token = lambda ref: token[0]
    await p.mirror_once()
    client = p.scope.client
    original = client.client._transport.handler
    changed = asyncio.Event()
    turn, human_mid, injected = [0], [0], []
    observed_topic_retries = []
    original_advance = p.dispatcher.advance

    async def observed_advance(identity):
        try:
            return await original_advance(identity)
        except ZulipReadUnavailable as error:
            # The bounded two-pair canonical proof may legitimately defer
            # under concurrent Bot appends. This must still be preclaim:
            # the original second turn remains queued and Native was called
            # only for the already completed first turn.
            assert turn[0] == 2 and len(native.submitted) == 1
            stored = await rows(db, Action)
            queued = [action for action in stored if action.state == "queued"]
            assert len(queued) == 1 and queued[0].id == identity
            assert queued[0].upstream_id is None and not queued[0].admission
            assert [action.state for action in stored].count("completed") == 1
            observed_topic_retries.append((turn[0], str(error), len(injected)))
            raise

    p.dispatcher.advance = observed_advance
    original_input = server.input

    def input_changed(*args, **kwargs):
        value = original_input(*args, **kwargs)
        changed.set()
        return value

    server.input = input_changed

    async def elapsed(request):
        clock[0] += 0.01
        calls.append((request.method, request.url.path))
        await asyncio.sleep(0.01)

    client.client.event_hooks["request"] = [elapsed]

    async def peer(request):
        if request.method == "GET" and request.url.path.endswith("/events"):
            last = int(request.url.params["last_event_id"])
            async with asyncio.timeout(30):
                while not any(e["id"] > last for e in server.events):
                    changed.clear()
                    await changed.wait()
        response = original(request)
        if asyncio.iscoroutine(response):
            response = await response
        task = asyncio.current_task()
        if (
            append_during_lookup
            and turn[0] == 2
            and len(injected) < append_rounds
            and request.method == "GET"
            and request.url.path.endswith("/messages")
            and task is not None
            and "native-dispatch" in task.get_name()
        ):
            raw = response.json()["messages"]
            if raw and max(m["id"] for m in raw) >= human_mid[0]:
                notice = max(server.messages) + 1
                server.next_mid = max(server.next_mid, notice + 1)
                server.input("Synthetic concurrent Bot notice", notice, 11, topic=b.topic)
                injected.append(notice)
        return response

    client.client._transport = httpx.MockTransport(peer)
    original_submit = native.submit
    finishes = []

    async def submitted(ref, payload, action_id):
        admission = await original_submit(ref, payload, action_id)
        n = len(native.submitted)
        native.state = ExecutionState.RUNNING
        if changes == "input-and-final":
            token[0] = "input-" + str(n)

        async def complete():
            await asyncio.sleep(3)
            native.state = ExecutionState.IDLE
            reader.messages[:0] = [
                project_message(
                    {
                        "id": "idle-" + str(n),
                        "type": "idle",
                        "time": {"created": 1000 + n * 3 + 2},
                        "outcome": "succeeded",
                    }
                ),
                project_message(
                    {
                        "id": "reply-" + str(n),
                        "type": "assistant",
                        "agent": "build",
                        "model": {"providerID": "fixture", "id": "model"},
                        "time": {"created": 1000 + n * 3 + 1, "completed": 1000 + n * 3 + 2},
                        "content": [{"type": "text", "text": "Configured answer " + str(n)}],
                    }
                ),
                project_message(
                    {
                        "id": admission.upstream_id,
                        "type": "user",
                        "time": {"created": 1000 + n * 3},
                        "text": payload["text"],
                    }
                ),
            ]
            token[0] = "final-" + str(n)

        finishes.append(asyncio.create_task(complete()))
        return admission

    native.submit = submitted
    runtime = p.runtime()
    try:
        await runtime.start()
        budget = ZulipRequestBudget.from_config(
            ZulipBudget(requests=1800, window_seconds=60.0, reserved_requests=64),
            monotonic=lambda: clock[0],
        )
        client.budget = budget
        calls.clear()
        window_start = clock[0]
        for n in (1, 2, 3):
            turn[0] = n
            mid = max(server.messages) + 1
            human_mid[0] = mid
            server.next_mid = mid + 1
            start, typing_start = len(server.posts), len(typing)
            server.input("Configured task " + str(n), mid, topic=b.topic)
            async with asyncio.timeout(8):
                while not any(
                    "Configured answer " + str(n) in visible(m["content"])
                    for m in server.posts[start:]
                ):
                    assert runtime.healthy, runtime.failure_detail
                    await asyncio.sleep(0.05)
            assert len(native.submitted) == results.calls == n
            assert [a.state for a in await rows(db, Action)] == ["completed"] * n
            assert "start" in typing[typing_start:]
            assert all(m["subject"] == b.topic for m in server.posts[start:])
            assert budget.deferred == 0
            if append_during_lookup:
                assert len(observed_topic_retries) <= 1
                assert all(
                    at_turn == 2
                    and reason == "topic_head_changed_during_resolution"
                    and 1 <= appended <= append_rounds
                    for at_turn, reason, appended in observed_topic_retries
                )
                assert p.deferred == (
                    {"zulip_dispatch_read_unavailable": len(observed_topic_retries)}
                    if observed_topic_retries
                    else {}
                )
            else:
                assert not p.deferred and not observed_topic_retries
        assert len(injected) == (append_rounds if append_during_lookup else 0)
        if append_rounds == 2:
            assert observed_topic_retries == [(2, "topic_head_changed_during_resolution", 2)]
        assert runtime.healthy and runtime.failure_detail is None
        assert typing.count("start") >= 3 and "stop" in typing
        assert (budget.limit, budget.window, budget.reserved) == (1800, 60.0, 64)
        assert 180 < len(calls) < 1800 and clock[0] - window_start < 60
        # Fixture timing and three synthetic inputs are not real mobile/load acceptance.
    finally:
        for task in finishes:
            if not task.done():
                task.cancel()
        await asyncio.gather(*finishes, return_exceptions=True)
        await runtime.close()
        await client.close()


@pytest.mark.parametrize("changes", ["final-only", "input-and-final"])
async def test_three_consecutive_original_turns_use_configured_budget(db, monkeypatch, changes):
    await _three_consecutive_turns(db, monkeypatch, changes)


async def test_concurrent_chat_append_during_second_dispatch_keeps_same_original_turn(
    db, monkeypatch
):
    await _three_consecutive_turns(db, monkeypatch, "final-only", append_during_lookup=True)


async def test_two_concurrent_topic_head_moves_retry_without_changing_original_turn(
    db, monkeypatch
):
    await _three_consecutive_turns(
        db, monkeypatch, "final-only", append_during_lookup=True, append_rounds=2
    )
