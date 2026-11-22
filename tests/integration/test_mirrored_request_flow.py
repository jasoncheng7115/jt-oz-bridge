"""Qualified synthetic full mirrored flow with the 180/60/64 per-lane request budget.

No real Human, Native mutation, phone rendering or wall-latency claim. Only
budget/identity scheduling uses virtual time; Native proofs and lease do not.
"""

import copy
import json
import os
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.transcript import project_message
from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import ZulipError
from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader
from jt_oz_bridge.adapters.zulip.typing import TypingParameters
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from jt_oz_bridge.storage.resource_models import ResourceResultRecord
from tests.integration import test_closed_bound_queue as closed
from tests.integration.test_consumer_runtime import rows, visible
from tests.integration.test_transcript_collector import entry
from tests.integration.test_transcript_publisher import assistant
from tests.integration.test_transcript_runtime import setup
from tests.integration.test_typing_status import _typing_clock
from tests.support_zulip_bulk import batch_transport


async def qualified_mirror(db, monkeypatch, *, background=0, bulk_metadata=False):
    previous, server, native, results, binding, reader = await setup(db)
    await previous.mirror_once()
    for _ in range(25):
        await previous.publish_once()
        await previous.deliver_once()

    async def prepared(_):
        return previous, server, native, results, binding, None

    monkeypatch.setattr(closed, "setup", prepared)
    _, _, _, _, _, clock, calls = await closed.live_identity(db, monkeypatch, initial_prompts=0)
    client = previous.scope.client
    client.typing_parameters = TypingParameters(30, 45, 12)
    original = client.client._transport.handler
    typing = []

    def peer(request):
        if request.url.path.endswith("/typing"):
            typing.append(parse_qs(request.content.decode())["op"][0])
            return httpx.Response(200, json={"result": "success"})
        response = original(request)
        if request.method == "POST" and request.url.path.endswith("/register"):
            return httpx.Response(
                200,
                json={
                    **response.json(),
                    "server_typing_started_wait_period_milliseconds": 30000,
                    "server_typing_started_expiry_period_milliseconds": 45000,
                    "server_typing_stopped_wait_period_milliseconds": 12000,
                },
            )
        return response

    client.client._transport = httpx.MockTransport(batch_transport(peer) if bulk_metadata else peer)
    scope = (
        ZulipScopeReader(client, channel_ids=previous.scope.channel_ids, bulk_metadata=True)
        if bulk_metadata
        else previous.scope
    )
    p = ConsumerPipeline(
        db,
        previous.fence,
        scope,
        previous.backends,
        interval=0.02,
        delivery_interval=0,
        mirror_enabled=True,
    )
    await p.consumer.start()
    client.budget = budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    calls.clear()
    clock[0] = 100
    p._test_http_calls, p._test_phase_costs = calls, []
    for _ in range(background):
        await p.scope.inspect("realm", binding.channel_id, binding.topic)
    return p, server, native, results, binding, reader, budget, clock, calls, typing


@pytest.mark.parametrize("typing_mode", ["none", "short", "refresh"])
@pytest.mark.parametrize("background", [0, 1])
async def test_original_mirror_answer_and_typing_fit_default_window(
    db, monkeypatch, typing_mode, background
):
    p, server, native, _, binding, reader, budget, clock, calls, typing = await qualified_mirror(
        db, monkeypatch, background=background
    )
    before = len(server.posts)
    _typing_clock(monkeypatch, clock)
    try:
        _, outcome = await closed.send(p, server, binding, "Exact phone task")
        assert outcome[-1] == "ignore"
        await p.dispatch_once()
        assert len(native.submitted) == 1
        native.state = ExecutionState.RUNNING
        if typing_mode != "none":
            await p.typing.sync_once()
            assert typing == ["start"]
            if typing_mode == "refresh":
                clock[0] += 30
                await p.typing.sync_once()
                # A silently queued prompt leaves headroom for the refresh even with
                # background spend; the headroom guard has its own typing test.
                assert typing == ["start", "start"]
        native.state = ExecutionState.IDLE
        action = (await rows(db, Action))[0]
        reader.messages[:0] = [
            project_message(
                {
                    "id": "terminal",
                    "type": "idle",
                    "time": {"created": 4},
                    "outcome": "succeeded",
                }
            ),
            assistant(text="One original mirrored answer"),
            entry(action.upstream_id, action.payload["text"]),
        ]
        await p.collect_once()
        await p.mirror_once()
        if typing_mode != "none":
            await p.typing.sync_once()
            starts = ["start"] * (2 if typing_mode == "refresh" else 1)
            assert typing in (starts, starts + ["stop"])
        for _ in range(3):
            await p.publish_once()
            await p.deliver_once()
            if any(
                "One original mirrored answer" in visible(m["content"])
                for m in server.posts[before:]
            ):
                break
        assert (
            sum(
                "One original mirrored answer" in visible(m["content"])
                for m in server.posts[before:]
            )
            == 1
        )
        assert (await rows(db, Action))[0].state == "completed"
        assert len(await rows(db, ResourceResultRecord)) == len(native.submitted) == 1
        assert budget.deferred == 0 and len(calls) <= 180 and clock[0] < 160
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
        assert not any(d.state in {"held", "sending"} for d in await rows(db, Delivery))
        assert all(m["subject"] == binding.topic for m in server.posts[before:])
        if os.environ.get("PROBE_OUT"):
            (Path(os.environ["PROBE_OUT"]) / f"mirror-{background}-{typing_mode}.json").write_text(
                json.dumps(
                    {
                        "synthetic_only": True,
                        "http_requests_until_answer": len(calls),
                        "typing_operations": typing,
                        "local_deferrals": budget.deferred,
                        "budget": [budget.limit, budget.window, budget.reserved],
                    },
                    indent=2,
                )
            )
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize("kind", ["resource", "transcript"])
@pytest.mark.parametrize(
    "change",
    [
        "privacy",
        "human_bot",
        "grant",
        "binding",
        "transport",
        "lease",
        "guard",
        "http",
        "attestation",
        "qualification",
        "expired",
        "enrollment",
    ],
)
async def test_native_capture_change_never_commits_terminal_or_transcript(
    db, monkeypatch, kind, change
):
    await _capture_change(db, monkeypatch, kind, change, bulk_metadata=False)


@pytest.mark.parametrize("kind", ["resource", "transcript"])
@pytest.mark.parametrize(
    "change",
    [
        "privacy",
        "human_bot",
        "grant",
        "binding",
        "transport",
        "lease",
        "guard",
        "http",
        "attestation",
        "qualification",
        "expired",
        "enrollment",
    ],
)
async def test_batched_native_capture_change_never_commits_terminal_or_transcript(
    db, monkeypatch, kind, change
):
    await _capture_change(db, monkeypatch, kind, change, bulk_metadata=True)


async def _capture_change(db, monkeypatch, kind, change, *, bulk_metadata):
    p, server, native, results, binding, reader, _, _, _, _ = await qualified_mirror(
        db, monkeypatch, bulk_metadata=bulk_metadata
    )
    original_http = p.scope.client.client
    try:
        await closed.send(p, server, binding, "One exact task")
        await p.dispatch_once()
        before = len(server.posts)
        original = p.scope.client.client._transport

        async def mutate():
            if change == "privacy":
                server.private = False
            elif change == "human_bot":
                server.bots.add(7)
            elif change == "transport":
                p.scope.client.client._transport = httpx.MockTransport(original.handler)
            elif change == "guard":
                p.scope.client.verify_identity = copy.copy(p.scope.client.verify_identity)
            elif change == "http":
                p.scope.client.client = httpx.AsyncClient(
                    transport=httpx.MockTransport(original.handler)
                )
            elif change == "attestation":
                p.scope.client.attestation = copy.copy(p.scope.client.attestation)
            elif change == "qualification":
                identity = p.scope.client.verify_identity
                identity.qualification = copy.copy(identity.qualification)
            elif change == "expired":
                results.alive = reader.alive = False
            else:
                from jt_oz_bridge.storage.models import WorkerLease

                async with db.sessions.begin() as s:
                    if change == "grant":
                        await s.execute(
                            update(Grant).where(Grant.user_id == 7).values(active=False)
                        )
                    elif change == "binding":
                        await s.execute(
                            update(Binding).where(Binding.id == binding.id).values(revision=2)
                        )
                    elif change == "lease":
                        await s.execute(update(WorkerLease).values(fencing=p.fence.fencing + 1))
                    else:
                        from jt_oz_bridge.storage.control_models import EnrolledProject

                        await s.execute(update(EnrolledProject).values(enabled=False))

        if kind == "resource":
            results.hook = mutate
            action = (await rows(db, Action))[0]
            with pytest.raises((Conflict, AccessDenied, ZulipError)):
                await p.collectors[binding.backend_id].collect(action.id, "realm")
            assert not await rows(db, ResourceResultRecord)
            assert (await rows(db, Action))[0].state == "admitted"
        else:
            from jt_oz_bridge.storage.transcript_models import TranscriptVersion

            old_versions = [(v.id, v.payload_hash) for v in await rows(db, TranscriptVersion)]
            reader.messages.insert(0, assistant(text="Must not be committed"))
            reader.hook = mutate
            with pytest.raises((Conflict, AccessDenied, ZulipError)):
                await p.mirrors.collect(binding)
            assert [
                (v.id, v.payload_hash) for v in await rows(db, TranscriptVersion)
            ] == old_versions
        assert len(server.posts) == before and len(native.submitted) == 1
    finally:
        await p.scope.client.close()
        if p.scope.client.client is not original_http:
            await original_http.aclose()


@pytest.mark.parametrize("cleanup", [False, True])
async def test_confirmed_typing_refresh_below40_does_not_steal_core_headroom(
    db, monkeypatch, cleanup
):
    p, _, native, _, _, _, budget, clock, calls, typing = await qualified_mirror(db, monkeypatch)
    _typing_clock(monkeypatch, clock)
    try:
        native.state = ExecutionState.RUNNING
        await p.typing.sync_once()
        assert typing == ["start"]
        while budget.normal_headroom >= 40:
            budget.acquire()
        before = len(calls)
        clock[0] += 30
        if cleanup:
            native.state = ExecutionState.IDLE
        await p.typing.sync_once()
        assert len(calls) == before and typing == ["start"] and budget.deferred == 0
        if not cleanup:
            clock[0] += 31
            await p.typing.sync_once()
            assert typing == ["start", "start"] and len(calls) > before
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
    finally:
        await p.scope.client.close()
