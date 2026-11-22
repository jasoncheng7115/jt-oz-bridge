"""Own SQLite + real Zulip request/scope composition, synthetic HTTP only.

These are not installed server, Human, browser or mobile typing certificates.
"""

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import delete, update

from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader, ZulipSourceReader
from jt_oz_bridge.adapters.zulip.typing import TypingParameters, ZulipTyping
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.discovery import DiscoveryService
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
from jt_oz_bridge.services.typing_status import TypingStatus
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant, WorkerLease
from tests.integration.test_consumer_runtime import WholeServer
from tests.integration.test_consumer_runtime import setup as pipeline_setup
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_zulip_consumer import URL
from tests.support import REF, service

PARAMETERS = {
    "server_typing_started_wait_period_milliseconds": 10000,
    "server_typing_started_expiry_period_milliseconds": 15000,
    "server_typing_stopped_wait_period_milliseconds": 5000,
}


@dataclass
class Environment:
    status: TypingStatus
    client: ZulipClient
    server: WholeServer
    native: SyntheticExecution
    binding: Binding
    posts: list


@asynccontextmanager
async def environment(
    db, *, feature=500, parameters=PARAMETERS, budget=None, on_typing=None, qualified=False
):
    server, native, posts = WholeServer(), SyntheticExecution(), []
    server.message("original", 100)
    server.typing_registrations = []

    async def handle(request):
        route = request.url.path.removeprefix("/api/v1/")
        if qualified and route == "users/me":
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "user_id": 11,
                    "is_bot": True,
                    "bot_owner_id": 8,
                    "role": 400,
                    "is_active": True,
                },
            )
        if qualified and route == "server_settings":
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "realm_url": URL,
                    "zulip_version": "12.3",
                    "zulip_feature_level": 500,
                },
            )
        if route == "typing":
            data = parse_qs(request.content.decode())
            posts.append(data)
            assert set(data) == {"type", "stream_id", "topic", "op"}
            assert data["type"] == ["channel"] and data["stream_id"] == ["10"]
            assert data["topic"] == ["Original work"]
            if on_typing:
                return await on_typing(request)
            return httpx.Response(200, json={"result": "success", "msg": ""})
        if route == "register":
            server.typing_registrations.append(
                parse_qs(request.content.decode())["fetch_event_types"]
            )
        response = server.handle(request)
        if route == "register" and parameters is not None:
            return httpx.Response(200, json={**response.json(), **parameters})
        return response

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
        ),
        verify_identity=AsyncMock(return_value=True),
        transport=httpx.MockTransport(handle),
        budget=budget,
    )
    if qualified:
        client.verify_identity = ZulipRuntimeIdentity(
            client,
            SimpleNamespace(
                bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
            ),
        )
    scope = ZulipScopeReader(client, channel_ids=frozenset({10}))
    bindings, _, _ = await service(db, control=native, audience=scope)
    binding = await bindings.bind("realm", 7, 10, "Original work", REF)
    fence = await DurableStore(db).acquire_lease("typing-fixture", ttl=120)
    assert fence is not None
    status = TypingStatus(
        bindings, ConsumerFence("typing-fixture", fence), ZulipTyping(client), "realm"
    )
    await client.register_events(typing_status=True)
    if feature != 500:
        client.attestation = replace(client.attestation, feature_level=feature)
        status.adapter = ZulipTyping(client)
    try:
        yield Environment(status, client, server, native, binding, posts)
    finally:
        await status.close()
        await client.close()


async def test_actual_running_original_session_gets_channel_start_then_idle_stop(db):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"]]
        assert e.native.calls[-1] == ("snapshot", REF)
        assert ("GET", "streams/10/members") in e.server.calls
        await e.status.sync_once()
        assert len(e.posts) == 1  # Server interval, no per-poll POST spam.
        e.native.state = ExecutionState.IDLE
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"], ["stop"]]
        assert not e.native.submitted  # No Native writes or invented Action.


@pytest.mark.parametrize("state", [s for s in ExecutionState if s != ExecutionState.RUNNING])
async def test_queued_held_waiting_unknown_are_not_llm_busy(db, state):
    async with environment(db) as e:
        e.native.state = state
        await e.status.sync_once()
        assert e.posts == []


async def test_overlapping_processing_same_topic_refcounts_and_finally_stops(db):
    async with environment(db) as e:
        async with e.status.processing(e.binding):
            async with e.status.processing(e.binding):
                await e.status.sync_once()
                assert e.posts[-1]["op"] == ["start"]
            await e.status.sync_once()
            assert len(e.posts) == 1
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]


async def test_processing_exception_does_not_strand_typing_or_replace_error(db):
    async with environment(db) as e:
        with pytest.raises(RuntimeError, match="original failure"):
            async with e.status.processing(e.binding):
                await e.status.sync_once()
                raise RuntimeError("original failure")
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"], ["stop"]]


@pytest.mark.parametrize("change", ["grant", "audience", "binding", "lease", "identity"])
async def test_current_authority_change_prevents_start(db, change):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        if change == "audience":
            e.server.private = False
        elif change == "identity":
            e.client.verify_identity = AsyncMock(return_value=True)
        else:
            async with db.sessions.begin() as session:
                if change == "grant":
                    await session.execute(
                        update(Grant).where(Grant.user_id == 8).values(active=False)
                    )
                elif change == "binding":
                    await session.execute(update(Binding).values(topic="Moved", revision=2))
                else:
                    await session.execute(
                        update(WorkerLease).values(holder="replacement", fencing=9)
                    )
        await e.status.sync_once()
        assert not any(p["op"] == ["start"] for p in e.posts)


async def test_identity_denial_inside_final_http_guard_prevents_typing(db):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        original = e.client.verify_identity
        entered = False

        async def revoked():
            nonlocal entered
            entered = True
            # Final identity verification must still reject even though the
            # earlier channel audience and local SQL scope were valid.
            return False

        # Same trusted callback identity, changed result; not an accepted replacement.
        assert isinstance(original, AsyncMock)
        original.side_effect = revoked
        await e.status.sync_once()
        assert entered and not e.posts


async def started(e) -> int:
    """Sync until our start indicator is recorded; returns how many posts that took.

    Under a loaded full gate one attempt can hit the unchanged two-second send
    deadline; production then clears the uncertain indicator and retries later.
    """
    for _ in range(5):
        await e.status.sync_once()
        if e.status._sent:
            break
        e.status._retry_at.clear()
    assert e.status._sent and e.posts[-1]["op"] == ["start"]
    return len(e.posts)


async def test_lease_loss_clears_our_indicator_and_never_refreshes_start(db):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        before = await started(e)
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
        # Force a due protocol refresh without weakening server metadata.
        identity = next(iter(e.status._sent))
        binding, _ = e.status._sent[identity]
        e.status._sent[identity] = binding, 0
        await e.status.sync_once()
        assert [p["op"] for p in e.posts][before:] == [["stop"]]


async def test_network_error_is_one_attempt_no_busy_retry_and_does_not_fail_processing(db):
    async def unavailable(request):
        raise httpx.ReadTimeout("synthetic unavailable")

    async with environment(db, on_typing=unavailable) as e:
        async with e.status.processing(e.binding):
            await e.status.sync_once()
            assert [p["op"] for p in e.posts] == [["start"], ["stop"]]
            await e.status.sync_once()
            assert len(e.posts) == 2
            # Typing is the only progress signal: the next refresh tries again.
            e.status._retry_at.clear()
            await e.status.sync_once()
            assert [p["op"] for p in e.posts][2] == ["start"]


async def test_typing_uses_shared_normal_budget_and_preserves_reserved_capacity(db):
    budget = ZulipRequestBudget()
    async with environment(db, budget=budget) as e:
        while budget.retained_requests < 116:
            budget.acquire()
        before = len(e.server.calls)
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert not e.posts
        assert len(e.server.calls) == before
        assert budget.retained_requests == 116
        assert budget.limit == 180 and budget.window == 60 and budget.reserved == 64


@pytest.mark.parametrize("feature,parameters", [(247, PARAMETERS), (500, None), (500, {})])
async def test_unsupported_or_absent_metadata_adds_zero_native_reads_or_typing(
    db, feature, parameters
):
    async with environment(db, feature=feature, parameters=parameters) as e:
        before = len(e.native.calls), len(e.server.calls)
        async with e.status.processing(e.binding):
            await e.status.sync_once()
        assert (len(e.native.calls), len(e.server.calls)) == before
        assert not e.posts and e.status.adapter.parameters is None


@pytest.mark.parametrize("value", [None, False, 0, -1, 1000000, "10000", 10000.0])
async def test_malformed_server_interval_disables_without_fallback(db, value):
    async with environment(
        db, parameters={**PARAMETERS, "server_typing_started_wait_period_milliseconds": value}
    ) as e:
        assert e.status.adapter.parameters is None
        await e.status.sync_once()
        assert not e.posts


async def test_unattested_raw_typing_route_cannot_bypass_scope_witness(db):
    async with environment(db) as e:
        with pytest.raises(ValueError, match="transport_or_schema_error"):
            await e.client.request(
                "POST",
                "typing",
                data={"type": "channel", "stream_id": 10, "topic": "Original work", "op": "start"},
            )
        assert not e.posts


async def test_worker_cancellation_and_close_stop_actual_indicator(db):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        started = asyncio.Event()
        original = e.status.adapter.send

        async def observed(channel, topic, operation):
            await original(channel, topic, operation)
            if operation == "start":
                started.set()

        e.status.adapter.send = observed
        task = asyncio.create_task(e.status.run())
        await asyncio.wait_for(started.wait(), 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert e.posts[-1]["op"] == ["stop"]
        assert e.status._closed


async def test_real_consumer_pipeline_opts_into_realm_metadata_and_worker(db):
    pipeline, server, *_ = await pipeline_setup(db)
    try:
        await pipeline.start_consumer()
        assert pipeline.consumer.typing_status is True
        assert pipeline.typing.adapter.parameters is None  # Fixture has no server parameters.
        assert any(w.name == "zulip-typing" for w in pipeline.runtime().workers)
    finally:
        await pipeline.typing.close()
        await pipeline.consumer.close()
        await pipeline.scope.client.close()


def test_protocol_values_are_only_the_three_server_intervals():
    value = TypingParameters.parse({**PARAMETERS, "realm_secret": "ignored"})
    assert value == TypingParameters(10, 15, 5)
    assert not hasattr(value, "realm_secret")


async def test_registration_metadata_is_explicit_and_default_call_disables_it(db):
    async with environment(db) as e:
        assert e.server.typing_registrations == [['["realm"]']]
        assert e.client.typing_parameters == TypingParameters(10, 15, 5)
        await e.client.register_events()
        assert e.server.typing_registrations[-1] == ["[]"]
        assert e.client.typing_parameters is None


async def test_due_refresh_still_uses_server_interval_and_current_native_state(db):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        before = await started(e)
        identity = next(iter(e.status._sent))
        e.status._sent[identity] = e.binding, 0
        await e.status.sync_once()
        assert [p["op"] for p in e.posts][before:] == [["start"]]
        assert e.status.adapter.parameters.refresh == 10
        e.native.state = ExecutionState.WAITING_INPUT
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]


async def test_last_native_revalidation_becoming_idle_prevents_stale_start(db):
    async with environment(db) as e:
        original = e.native.snapshot
        count = 0

        async def changed(reference):
            nonlocal count
            count += 1
            e.native.state = ExecutionState.RUNNING if count == 1 else ExecutionState.IDLE
            return await original(reference)

        e.native.snapshot = changed
        await e.status.sync_once()
        assert not any(p["op"] == ["start"] for p in e.posts)


async def test_equivalent_identity_replacement_during_final_guard_never_posts(db):
    async with environment(db) as e:
        e.native.state = ExecutionState.RUNNING
        original = e.client.verify_identity
        assert isinstance(original, AsyncMock)
        calls = 0

        async def replace_at_post():
            nonlocal calls
            calls += 1
            # Scope identity also uses this callback. Target the additional
            # final POST identity call only, after the SQL scope is locked.
            if e.status._sent and calls >= 1:
                e.client.verify_identity = AsyncMock(return_value=True)
            return True

        # Use adapter.send as the boundary to select the final verification;
        # actual ZulipClient.request and its synchronous witness remain real.
        send = e.status.adapter.send

        async def final_send(channel, topic, operation):
            original.side_effect = replace_at_post
            await send(channel, topic, operation)

        e.status.adapter.send = final_send
        await e.status.sync_once()
        assert not e.posts


async def test_typing_leaves_normal_headroom_for_core_work_and_retries_after_refill(db):
    budget = ZulipRequestBudget()
    async with environment(db, budget=budget) as e:
        while budget.retained_requests < 53:
            budget.acquire()
        assert budget.retained_requests == 53
        before = len(e.server.calls)
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert len(e.server.calls) == before and not e.posts
        assert budget.retained_requests == 53
        assert not e.status._sent
        # Optional typing did not claim a request or use the reserved lane:
        # normal work still has admission without raising the original limits.
        budget.acquire()
        assert budget.retained_requests == 54
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
        # Real shared-window refill, with the monotonic budget clock advancing;
        # no authority or HTTP response is reused by the later attempt.
        old_clock = budget.clock
        budget.clock = lambda: old_clock() + 61
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["start"]
        assert len(e.server.calls) > before


@asynccontextmanager
async def routed_environment(db, *, unbound=False, on_typing=None, budget=None):
    """Real router, owned SQL and actual qualified scope; synthetic HTTP only."""
    async with environment(db, qualified=True, on_typing=on_typing, budget=budget) as e:
        if unbound:
            async with db.sessions.begin() as session:
                await session.execute(delete(Binding))

        async def channel(realm, mid):
            return 10 if realm == "realm" and mid in e.server.messages else None

        source = ZulipSourceReader(e.status.bindings.audience, channel)
        discovery = DiscoveryService(e.status.bindings, {})
        router = CommandRouter(
            e.status.bindings,
            source,
            CommandInbox(db, e.status.fence.holder, e.status.fence.fencing),
            discovery=discovery,
        )
        if hasattr(router, "configure_typing"):
            router.configure_typing(e.status)
        yield e, router, source


@pytest.mark.parametrize("unbound", [False, True])
async def test_actual_router_work_starts_typing_without_native_running_and_finally_clears(
    db, unbound
):
    async with routed_environment(db, unbound=unbound) as (e, router, source):
        e.server.messages[100]["content"] = "!oz help"
        message = await source.read("realm", 100)
        target = router.unbound if unbound else router
        original = target.execute
        entered, release = asyncio.Event(), asyncio.Event()

        async def blocked(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original(*args, **kwargs)

        target.execute = blocked
        task = asyncio.create_task(router.route(message))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            before = list(e.native.calls)
            await e.status.sync_once()
            assert e.posts and e.posts[-1]["op"] == ["start"]
            assert e.native.calls == before  # No cosmetic Native qualification.
            release.set()
            result = await task
            assert result.state == "reply"
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["stop"]
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("fault", ["source", "actor", "topic", "public", "grant", "lease"])
async def test_route_activity_proposal_cannot_bypass_current_source_audience_or_sql(db, fault):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            if fault == "source":
                e.server.messages[100]["content"] = "changed"
            elif fault == "actor":
                e.server.messages[100]["sender_id"] = 8
            elif fault == "topic":
                e.server.messages[100]["subject"] = "Moved"
            elif fault == "public":
                e.server.private = False
            else:
                async with db.sessions.begin() as session:
                    if fault == "grant":
                        await session.execute(update(Grant).values(active=False))
                    else:
                        await session.execute(update(WorkerLease).values(holder="lost", fencing=99))
            await e.status.sync_once()
            assert not any(p["op"] == ["start"] for p in e.posts)


async def _confirmed_typing_start(e, *, activity="route"):
    """Wait for a real acknowledged indicator, not for a lucky first poll.

    A two-second optional attempt may defer under slow SQL/HTTP. Exercise the
    next real worker tick after its backoff while the same activity is alive;
    every tick must create its own Source/ACL/permit observation. The overall
    eight-second test bound never extends any individual five-second proof.
    """
    async with asyncio.timeout(8):
        while True:
            await e.status.sync_once()
            sent = e.status._sent if activity == "native" else e.status._route_sent
            failed = set() if activity == "native" else e.status._route_failed
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            if sent:
                assert e.posts[-1]["op"] == ["start"]
                return
            assert not failed
            assert deadlines
            delay = min(deadlines.values()) - time.monotonic()
            await asyncio.sleep(max(0.001, delay))


async def test_same_topic_source_work_refcounts_and_cancelled_router_does_not_strand_indicator(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            async with e.status.routing(message):
                await _confirmed_typing_start(e)
                confirmed = len(e.posts)
            await e.status.sync_once()
            assert len(e.posts) == confirmed
        await e.status.sync_once()
        assert [p["op"] for p in e.posts[confirmed:]] == [["stop"]]
        assert not e.status._route_sent
        e.server.messages[100]["content"] = "!oz help"
        message = await source.read("realm", 100)
        entered = asyncio.Event()

        async def blocked(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()

        router.unbound.execute = blocked
        task = asyncio.create_task(router.route(message))
        await asyncio.wait_for(entered.wait(), 2)
        await _confirmed_typing_start(e)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]
        assert not e.status._routes


@pytest.mark.parametrize("activity", ["native", "route"])
@pytest.mark.parametrize("phase", ["pre_send", "post_open"])
async def test_optional_attempt_timeout_defers_and_reobserves_without_poisoning_activity(
    db, monkeypatch, caplog, activity, phase
):
    """Real two-second cancellation, real SQL/scope and protected synthetic HTTP."""
    import jt_oz_bridge.services.typing_status as typing_module

    stalled, cancelled, reads, permits = False, False, [], []

    async def delay():
        nonlocal stalled, cancelled
        stalled = True
        try:
            await asyncio.sleep(2.05)
        except asyncio.CancelledError:
            cancelled = True
            raise

    async def on_typing(request):
        if (
            phase == "post_open"
            and not stalled
            and parse_qs(request.content.decode())["op"] == ["start"]
        ):
            await delay()
        return httpx.Response(200, json={"result": "success", "msg": ""})

    async with routed_environment(db, on_typing=on_typing) as (e, router, reader):
        source = await reader.read("realm", 100)
        scope = e.status.bindings.audience
        original_permit = scope.local_write_permit

        def observe_permit(*args):
            permit = original_permit(*args)
            permits.append(permit)
            return permit

        monkeypatch.setattr(scope, "local_write_permit", observe_permit)

        async def observe_request(request):
            if request.method == "GET":
                reads.append(request.url.path)

        e.client.client.event_hooks.setdefault("request", []).append(observe_request)
        original_lock = typing_module.lock_output_scope
        locks = 0

        async def slow_scope(*args, **kwargs):
            nonlocal locks
            locks += 1
            # Route call1 is the Source read callback; call2 is after the
            # permit was issued and consumed, inside the fresh SQL transaction.
            if phase == "pre_send" and locks == (2 if activity == "route" else 1):
                await delay()
            return await original_lock(*args, **kwargs)

        monkeypatch.setattr(typing_module, "lock_output_scope", slow_scope)
        context = (
            e.status.processing(e.binding) if activity == "native" else e.status.routing(source)
        )
        async with context:
            started = time.monotonic()
            await e.status.sync_once()
            assert stalled and cancelled
            failed = set() if activity == "native" else e.status._route_failed
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            assert not failed and len(deadlines) == 1
            # Two real seconds until cancellation plus the original two-second
            # backoff. Do not assume later SQL scheduling itself is instantaneous.
            assert next(iter(deadlines.values())) >= started + 3.9
            assert [p["op"] for p in e.posts] == (
                [["start"], ["stop"]] if phase == "post_open" else []
            )
            before = len(reads)
            await e.status.sync_once()
            assert len(reads) == before  # No immediate busy retry or old observation reuse.
            # Advance only the scheduling decision, as a later worker tick.
            # Original Source/permit/lease/Native proof clocks remain untouched.
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            for identity in deadlines:
                deadlines[identity] = 0
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"] and len(reads) > before
            if activity == "route":
                assert len(permits) >= (3 if phase == "post_open" else 2)
                assert len({id(permit) for permit in permits}) == len(permits)
            assert not e.native.submitted
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]
        assert "kind=attempt_timeout" in caplog.text and "error_type=TimeoutError" in caplog.text
        assert "phase=" + ("typing_http" if phase == "post_open" else "sql_scope") in caplog.text
        assert "PRIVATE" not in caplog.text


@pytest.mark.parametrize("activity", ["native", "route"])
@pytest.mark.parametrize("change", ["end", "revoke"])
async def test_timeout_reobservation_never_starts_after_activity_end_or_revocation(
    db, monkeypatch, activity, change
):
    import jt_oz_bridge.services.typing_status as typing_module

    async with routed_environment(db) as (e, router, reader):
        source = await reader.read("realm", 100)
        original = typing_module.lock_output_scope
        calls = 0

        async def slow_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                await asyncio.sleep(2.05)
            return await original(*args, **kwargs)

        monkeypatch.setattr(typing_module, "lock_output_scope", slow_once)
        context = (
            e.status.processing(e.binding) if activity == "native" else e.status.routing(source)
        )
        await context.__aenter__()
        try:
            await e.status.sync_once()
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            assert len(deadlines) == 1 and not e.posts
            for identity in deadlines:
                deadlines[identity] = 0
            if change == "end":
                await context.__aexit__(None, None, None)
                context = None
            else:
                async with db.sessions.begin() as session:
                    await session.execute(update(Grant).values(active=False))
            await e.status.sync_once()
            assert not any(post["op"] == ["start"] for post in e.posts)
            assert not e.native.submitted
        finally:
            if context is not None:
                await context.__aexit__(None, None, None)


@pytest.mark.parametrize("activity", ["native", "route"])
async def test_external_cancellation_is_not_reclassified_as_optional_attempt_timeout(db, activity):
    entered = asyncio.Event()

    async def waiting(request):
        if parse_qs(request.content.decode())["op"] == ["start"]:
            entered.set()
            await asyncio.Event().wait()
        return httpx.Response(200, json={"result": "success", "msg": ""})

    async with routed_environment(db, on_typing=waiting) as (e, router, reader):
        source = await reader.read("realm", 100)
        context = (
            e.status.processing(e.binding) if activity == "native" else e.status.routing(source)
        )
        async with context:
            task = asyncio.create_task(e.status.sync_once())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert not e.status._retry_at and not e.status._route_retry_at
                await e.status.close()
                assert [p["op"] for p in e.posts] == [["start"], ["stop"]]
                assert not e.native.submitted
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def test_route_ending_during_final_source_read_cannot_start_after_work_finished(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        context = e.status.routing(message)
        await context.__aenter__()
        original = source.expected_channel
        calls = 0

        async def ending(realm, mid):
            nonlocal calls
            calls += 1
            if calls == 3:
                await context.__aexit__(None, None, None)
            return await original(realm, mid)

        source.expected_channel = ending
        await e.status.sync_once()
        assert calls >= 3
        assert not any(p["op"] == ["start"] for p in e.posts)
        assert not e.status._routes


async def test_route_final_identity_await_revoke_never_posts_and_does_not_raise_into_work(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        guard = e.client.verify_identity
        original = guard.__class__.__call__
        # Revocation at the actual typing HTTP boundary, after the two-sided
        # Source observation and SQL, is tested by the existing client witness.
        send = e.status.adapter.send

        async def revoked(channel, topic, operation):
            e.client.verify_identity = AsyncMock(return_value=True)
            return await send(channel, topic, operation)

        e.status.adapter.send = revoked
        async with e.status.routing(message):
            await e.status.sync_once()
            assert not e.posts
            assert guard.__class__.__call__ is original


async def test_router_to_new_binding_handoff_does_not_stop_other_native_indicator(db):
    async with routed_environment(db) as (e, router, source):
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"]
        # A real original RUNNING observation takes ownership on the next
        # normal poll; ending the Source work must not issue a conflicting stop.
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["start"]
        assert [p["op"] for p in e.posts].count(["stop"]) == 0
        e.native.state = ExecutionState.IDLE
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]


async def test_unbound_route_becomes_bound_then_native_running_keeps_one_topic_indicator(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"]
            binding = await e.status.bindings.bind("realm", 7, 10, "Original work", REF)
            assert binding.state == "active"
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert not any(p["op"] == ["stop"] for p in e.posts)
        e.native.state = ExecutionState.IDLE
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]


async def test_late_sql_revocation_after_closed_source_rejects_typing_start(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        original = e.status._route_scope
        calls = 0

        async def revoke(session, actor, audience):
            nonlocal calls
            calls += 1
            if calls == 2:
                await session.execute(update(Grant).values(active=False))
            return await original(session, actor, audience)

        e.status._route_scope = revoke
        async with e.status.routing(message):
            await e.status.sync_once()
            assert calls >= 2
            assert not any(p["op"] == ["start"] for p in e.posts)


@pytest.mark.parametrize("state", [ExecutionState.QUEUED, ExecutionState.WAITING_PERMISSION])
async def test_actual_route_work_is_typing_without_changing_native_or_admitting_action(db, state):
    async with routed_environment(db) as (e, router, source):
        e.native.state = state
        message = await source.read("realm", 100)
        before = list(e.native.calls)
        async with e.status.routing(message):
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"]
        assert e.native.state is state and e.native.calls == before and not e.native.submitted
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]


async def test_source_router_lease_loss_stops_once_and_never_refreshes(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"]
            async with db.sessions.begin() as session:
                await session.execute(update(WorkerLease).values(holder="replacement", fencing=99))
            # No timer rewrite: fresh lease loss must clear even before refresh.
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["stop"]
            before = len(e.posts)
            await e.status.sync_once()
            assert len(e.posts) == before


async def test_incompatible_source_or_guard_disables_cosmetic_only(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        e.client.verify_identity = AsyncMock(return_value=True)
        async with e.status.routing(message):
            await e.status.sync_once()
            assert e.posts == []
        assert not e.native.submitted


async def test_unqualified_route_does_not_replace_an_existing_original_running_indicator(db):
    async with routed_environment(db) as (e, router, source):
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert e.status._sent and e.posts[-1]["op"] == ["start"]
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            e.server.messages[100]["content"] = "changed"
            await e.status.sync_once()
            assert e.status._sent and not e.status._route_sent
            assert not any(p["op"] == ["stop"] for p in e.posts)
        await e.status.sync_once()
        assert not any(p["op"] == ["stop"] for p in e.posts)


async def test_idle_native_indicator_is_cleared_if_source_handoff_cannot_authorize(db):
    async with routed_environment(db) as (e, router, source):
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        message = await source.read("realm", 100)
        async with e.status.routing(message):
            e.native.state = ExecutionState.IDLE
            e.server.messages[100]["content"] = "changed"
            await e.status.sync_once()
            assert not e.status._sent and not e.status._route_sent
            assert e.posts[-1]["op"] == ["stop"]


async def test_optional_source_work_lease_read_failure_never_raises_into_routing(db):
    async with routed_environment(db, unbound=True) as (e, router, source):
        message = await source.read("realm", 100)
        original = e.status.bindings.db.sessions

        @asynccontextmanager
        async def unavailable():
            raise RuntimeError("controlled-ownDB-read-unavailable")
            yield

        async with e.status.routing(message):
            e.status.bindings.db.sessions = unavailable
            try:
                # Same route-only wake path as the supervised optional worker.
                await e.status._sync_routes()
                assert e.posts == [] and e.status._routes
            finally:
                e.status.bindings.db.sessions = original


@pytest.mark.parametrize("activity", ["native", "route"])
@pytest.mark.parametrize("failure", ["local_budget", "upstream_rate", "get_unavailable"])
async def test_typed_typing_deferral_retries_same_busy_activity_with_fresh_scope(
    db, monkeypatch, caplog, activity, failure
):
    """Synthetic scheduling only; original Source/ACL/5s code runs on every attempt."""
    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred

    budget = ZulipRequestBudget()
    async with routed_environment(db) as (e, router, reader):
        source = await reader.read("realm", 100)
        e.client.budget = budget  # New scheduling fixture, no retained setup traffic.
        normal = e.client.request
        hit = False
        reads = []

        async def request(method, route, **kwargs):
            nonlocal hit
            if method == "GET":
                reads.append(route)
            if method == "GET" and not hit:
                hit = True
                if failure == "local_budget":
                    while True:
                        try:
                            budget.acquire()
                        except RequestBudgetDeferred:
                            break
                    return await normal(method, route, **kwargs)  # Actual local refusal, 0 HTTP.
                # Actual adapter parses a verified HTTP429 or bounded GET503.
                status = 429 if failure == "upstream_rate" else 503
                old_http = e.client.client._transport

                async def unavailable(request):
                    e.client.client._transport = old_http
                    return httpx.Response(
                        status,
                        headers={"Retry-After": "2"},
                        json={"result": "error", "code": "RATE_LIMIT_HIT"},
                    )

                e.client.client._transport = httpx.MockTransport(unavailable)
                return await normal(method, route, **kwargs)
            return await normal(method, route, **kwargs)

        monkeypatch.setattr(e.client, "request", request)
        context = (
            e.status.processing(e.binding) if activity == "native" else e.status.routing(source)
        )
        async with context:
            started = time.monotonic()
            await e.status.sync_once()
            assert hit
            failed = set() if activity == "native" else e.status._route_failed
            assert not failed  # Original source permanently latches this busy key.
            assert not e.posts
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            assert len(deadlines) == 1
            assert next(iter(deadlines.values())) >= started + (
                59 if failure == "local_budget" else 1.9
            )
            before = len(reads)
            await e.status.sync_once()
            assert len(reads) == before and not e.posts
            # Only the scheduling fixture is advanced. No Source/Native witness
            # is reused, and neither system time nor the original 5s proof changes.
            old_clock = budget.clock
            budget.clock = lambda: old_clock() + 61
            # sync_once prunes by replacing the dict, so retrieve its current
            # scheduling map rather than modifying a stale fixture alias.
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            for identity in deadlines:
                deadlines[identity] = 0
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"] and len(reads) > before
            assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)
            assert not failed
        await e.status.sync_once()
        assert e.posts[-1]["op"] == ["stop"]
        assert "typing_send_deferred" in caplog.text and "PRIVATE" not in caplog.text


@pytest.mark.parametrize("activity", ["native", "route"])
@pytest.mark.parametrize("change", ["end", "revoke"])
async def test_deferred_typing_never_starts_after_activity_end_or_grant_revocation(
    db, monkeypatch, activity, change
):
    async with routed_environment(db) as (e, router, reader):
        source = await reader.read("realm", 100)
        normal = e.client.request
        hit = False

        async def request(method, route, **kwargs):
            nonlocal hit
            if method == "GET" and not hit:
                hit = True
                raise DeliveryRateLimited(2)
            return await normal(method, route, **kwargs)

        monkeypatch.setattr(e.client, "request", request)
        context = (
            e.status.processing(e.binding) if activity == "native" else e.status.routing(source)
        )
        await context.__aenter__()
        try:
            await e.status.sync_once()
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            assert len(deadlines) == 1 and not e.posts
            for identity in deadlines:
                deadlines[identity] = 0  # Scheduling only; actual ACL is re-read below.
            if change == "end":
                await context.__aexit__(None, None, None)
                context = None
            else:
                async with db.sessions.begin() as session:
                    await session.execute(update(Grant).values(active=False))
            await e.status.sync_once()
            assert not e.posts
        finally:
            if context is not None:
                await context.__aexit__(None, None, None)


PRODUCTION_TYPING_PERIODS = {
    "server_typing_started_wait_period_milliseconds": 30000,
    "server_typing_started_expiry_period_milliseconds": 45000,
    "server_typing_stopped_wait_period_milliseconds": 12000,
}


async def _spend_actual_protected_http(client):
    from jt_oz_bridge.adapters.zulip.budget import request_lane

    # Real guarded synthetic HTTP, no Human command or Native operation invented.
    with request_lane("control"):
        for _ in range(80):
            await client.request("GET", "users/me")


def _typing_clock(monkeypatch, clock):
    from jt_oz_bridge.services import typing_status as status_module

    # Scheduling clock only: Source permit/Native proof and lease clocks retain
    # their real deadlines. No old Human ACL or HTTP response is reused.
    monkeypatch.setattr(
        status_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock[0], time=time.time),
    )


def _observe_typing_http(client, clock, calls):
    from jt_oz_bridge.adapters.zulip.budget import _lane

    async def observe(request):
        calls.append((clock[0], _lane.get(), request.method, request.url.path))

    client.client.event_hooks["request"].append(observe)


async def test_guarded_native_typing_refresh_crosses_60s_after_real_protected_spend(
    db, monkeypatch
):
    clock, calls = [0.0], []
    async with environment(db, qualified=True, parameters=PRODUCTION_TYPING_PERIODS) as e:
        budget = ZulipRequestBudget(monotonic=lambda: clock[0])
        e.client.budget = budget
        _typing_clock(monkeypatch, clock)
        _observe_typing_http(e.client, clock, calls)
        await _spend_actual_protected_http(e.client)
        assert budget.retained_requests == 80 and budget.normal_headroom == 100
        assert budget.capacity - budget.reserved - budget.retained_requests == 36
        e.native.state = ExecutionState.RUNNING
        starts = []
        for point in (1, 31, 61, 91):
            clock[0] = point
            before = len(calls)
            await e.status.sync_once()
            assert e.posts[-1]["op"] == ["start"] and len(e.posts) == len(starts) + 1
            operation = calls[before:]
            assert 17 <= len(operation) <= 21
            assert all(lane == "normal" for _, lane, _, _ in operation)
            assert sum(method == "POST" for _, _, method, _ in operation) == 1
            starts.append(point)
        assert all(b - a == 30 < 45 for a, b in zip(starts, starts[1:], strict=False))
        assert e.status.adapter.parameters.refresh == 30
        assert e.status.adapter.parameters.expiry == 45
        assert e.status.adapter.parameters.stopped_wait == 12
        clock[0] = 103  # Idle is observed12s after the final refresh, not a new debounce policy.
        e.native.state = ExecutionState.IDLE
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"]] * 4 + [["stop"]]
        assert budget.deferred == 0 and not e.native.submitted
        assert (budget.limit, budget.window, budget.reserved) == (180, 60, 64)


@pytest.mark.parametrize("unbound", [False, True])
async def test_guarded_route_refresh_preserves_fresh_source_across_60s_after_protected_spend(
    db, monkeypatch, unbound
):
    clock, calls = [0.0], []
    async with routed_environment(db, unbound=unbound) as (e, router, source):
        e.client.typing_parameters = TypingParameters.parse(PRODUCTION_TYPING_PERIODS)
        message = await source.read("realm", 100)
        budget = ZulipRequestBudget(monotonic=lambda: clock[0])
        e.client.budget = budget
        _typing_clock(monkeypatch, clock)
        _observe_typing_http(e.client, clock, calls)
        await _spend_actual_protected_http(e.client)
        before_native = list(e.native.calls)
        async with e.status.routing(message):
            for index, point in enumerate((1, 31, 61, 91), 1):
                clock[0] = point
                before = len(calls)
                await e.status._sync_routes()
                assert len(e.posts) == index and e.posts[-1]["op"] == ["start"]
                operation = calls[before:]
                assert 17 <= len(operation) <= 25
                assert all(lane == "normal" for _, lane, _, _ in operation)
                assert sum(path.endswith("/messages/100") for _, _, _, path in operation) == 2
                assert sum(method == "POST" for _, _, method, _ in operation) == 1
        clock[0] = 103
        await e.status._sync_routes()
        assert [p["op"] for p in e.posts] == [["start"]] * 4 + [["stop"]]
        assert e.native.calls == before_native and not e.native.submitted
        assert budget.deferred == 0 and (budget.limit, budget.window, budget.reserved) == (
            180,
            60,
            64,
        )


@pytest.mark.parametrize("activity", ["native", "route"])
async def test_timeout_of_refresh_preserves_cleanup_of_earlier_indicator(db, monkeypatch, activity):
    import jt_oz_bridge.services.typing_status as typing_module

    async with routed_environment(db) as (e, router, reader):
        source = await reader.read("realm", 100)
        context = (
            e.status.processing(e.binding) if activity == "native" else e.status.routing(source)
        )
        async with context:
            await _confirmed_typing_start(e, activity=activity)
            posts_before = len(e.posts)
            sent = e.status._sent if activity == "native" else e.status._route_sent
            identity = next(iter(sent))
            previous, _ = sent[identity]
            sent[identity] = (previous, 0)
            original = typing_module.lock_output_scope
            calls = 0

            async def stall_refresh(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == (2 if activity == "route" else 1):
                    await asyncio.sleep(2.05)
                return await original(*args, **kwargs)

            monkeypatch.setattr(typing_module, "lock_output_scope", stall_refresh)
            await e.status.sync_once()
            sent = e.status._sent if activity == "native" else e.status._route_sent
            deadlines = e.status._retry_at if activity == "native" else e.status._route_retry_at
            assert sent[identity] == (previous, 0) and len(deadlines) == 1
            assert len(e.posts) == posts_before
        await e.status.sync_once()
        assert [p["op"] for p in e.posts[posts_before:]] == [["stop"]]
        assert not e.status._sent and not e.status._route_sent
        assert not e.native.submitted


async def test_an_idle_root_is_snapshotted_again_on_an_arrival_in_its_directory_or_after_a_while(
    db, monkeypatch
):
    from jt_oz_bridge.services import typing_status

    async with environment(db) as e:
        fence = ["before"]
        e.status.quiet_fence = lambda ref: fence[0] if ref == REF else None
        before = e.native.calls.count(("snapshot", REF))
        await e.status.sync_once()
        snapshots = e.native.calls.count(("snapshot", REF))
        assert snapshots == before + 1 and not e.posts
        # Started from the TUI, but its first event has not been seen yet.
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        assert e.native.calls.count(("snapshot", REF)) == snapshots and not e.posts
        # Starting work is an arrival in its directory: snapshotted at once.
        fence[0] = "after"
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"]]
        # A running Root keeps its normal poll, so going idle still stops.
        e.native.state = ExecutionState.IDLE
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"], ["stop"]]
        # Quiet and idle again; the recheck interval still bounds staleness.
        e.native.state = ExecutionState.RUNNING
        monkeypatch.setattr(typing_status, "IDLE_RECHECK_SECONDS", 0)
        await e.status.sync_once()
        assert [p["op"] for p in e.posts] == [["start"], ["stop"], ["start"]]


async def test_running_work_is_reported_with_its_start_until_it_is_seen_idle(db, monkeypatch):
    from jt_oz_bridge.services import typing_status
    from jt_oz_bridge.services.typing_status import key

    async with environment(db) as e:
        assert e.status.running() == {}
        e.native.state = ExecutionState.RUNNING
        await e.status.sync_once()
        ((binding, since),) = e.status.running().values()
        assert binding.id == e.binding.id and 0 <= time.time() - since < 5
        await e.status.sync_once()
        assert e.status.running()[key(e.binding)][1] == since  # Same turn, same start.

        async def unavailable(reference):
            raise RuntimeError("synthetic read failure")

        monkeypatch.setattr(e.native, "snapshot", unavailable)
        await e.status.sync_once()
        assert e.status.running()[key(e.binding)][1] == since  # Unknown is not idle.
        monkeypatch.setattr(typing_status, "RUNNING_FRESH_SECONDS", 0)
        assert e.status.running() == {}  # Not confirmed again: no longer reported.
        monkeypatch.undo()
        e.native.state = ExecutionState.IDLE
        await e.status.sync_once()
        assert e.status._running == {}


@dataclass
class StillWorking:
    notices: object
    running: dict
    outbox: object
    binding: Binding
    worker: object
    chat: object


async def still_working(db, *, locale="en", waiting=lambda _binding: False):
    from jt_oz_bridge.services.still_working import StillWorkingNotices
    from tests.integration.test_routed_output import setup as output_setup

    outbox, binding, worker, replies, chat = await output_setup(db)
    if locale != "en":
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(locale=locale)
            )
        binding.locale = locale
    running: dict = {}
    notices = StillWorkingNotices(replies, lambda: running, waiting=waiting)
    return StillWorking(notices, running, outbox, binding, worker, chat)


def run_since(w, seconds_ago):
    from jt_oz_bridge.services.typing_status import key

    since = time.time() - seconds_ago
    w.running.clear()
    w.running[key(w.binding)] = (w.binding, since)
    return since


async def post(w, name, *, ago=None, widget=None):
    """One other delivered Bridge post in the topic, optionally made ``ago`` seconds back."""
    from jt_oz_bridge.storage.models import Delivery, DeliveryBatch

    queued = await w.outbox.queue_batch(
        name,
        w.binding.id,
        w.binding.revision,
        (name,),
        renderer_version="test-v1",
        message_limit=300,
        topic_limit=100,
        widget=widget,
    )
    assert await w.worker.advance(queued.deliveries[0]) == "delivered"
    if ago is not None:
        async with w.outbox.db.sessions.begin() as session:
            await session.execute(
                update(Delivery)
                .where(Delivery.batch_id == queued.id)
                .values(updated_at=time.time() - ago, created_at=time.time() - ago)
            )
            await session.execute(
                update(DeliveryBatch)
                .where(DeliveryBatch.id == queued.id)
                .values(created_at=time.time() - ago)
            )
    return queued


async def age(db, seconds):
    """Every post in the topic so far, as if made ``seconds`` back."""
    from jt_oz_bridge.storage.models import Delivery, DeliveryBatch

    then = time.time() - seconds
    async with db.sessions.begin() as session:
        await session.execute(update(Delivery).values(updated_at=then, created_at=then))
        await session.execute(update(DeliveryBatch).values(created_at=then))


async def notices_in(db):
    from sqlalchemy import select

    from jt_oz_bridge.services.still_working import RENDERER
    from jt_oz_bridge.storage.models import Delivery, DeliveryBatch

    async with db.sessions() as session:
        return list(
            await session.scalars(
                select(Delivery)
                .join(DeliveryBatch, DeliveryBatch.id == Delivery.batch_id)
                .where(DeliveryBatch.renderer_version == RENDERER)
                .order_by(Delivery.created_at)
            )
        )


@pytest.mark.parametrize(
    ("locale", "text"),
    [
        ("en", "⏳ The AI is still working (5 min so far); the reply will appear here."),
        ("zh-TW", "⏳ AI 還在處理中（已 5 分鐘），完成後會在這裡回覆。"),
    ],
)
async def test_a_quiet_running_turn_gets_one_still_working_line_through_the_outbox(
    db, locale, text
):
    from jt_oz_bridge.services.still_working import PRIORITY, StillWorkingNotices

    w = await still_working(db, locale=locale)
    since = run_since(w, 300)
    assert await w.notices.once() == 1
    (saved,) = await notices_in(db)
    assert saved.state == "pending" and saved.priority == PRIORITY < 80
    assert saved.payload["operation"] == "post" and saved.payload["widget"] is None
    assert await w.worker.advance(saved.id) == "delivered"
    assert [call for call, _ in w.chat.calls] == ["send"]
    assert w.chat.calls[0][1].startswith(text)  # Then only the delivery marker.
    # At most once per turn: not again in this process...
    assert await w.notices.once() == 0
    # ...nor after a restart with the same turn start...
    again = StillWorkingNotices(w.notices.replies, lambda: w.running)
    assert await again.once() == 0
    # ...nor after a restart that first sees the turn later: its line is still newest.
    w.running[next(iter(w.running))] = (w.binding, since + 60)
    assert await again.once() == 0
    assert len(await notices_in(db)) == 1 and len(w.chat.calls) == 1


async def test_no_still_working_line_before_the_quiet_period_or_while_idle(db):
    w = await still_working(db)
    assert await w.notices.once() == 0  # Nothing running.
    run_since(w, 60)
    assert await w.notices.once() == 0  # Running, but not for long yet.
    run_since(w, 600)
    await post(w, "🔧 bash")  # Tool progress just appeared in the topic.
    assert await w.notices.once() == 0
    w.running.clear()
    assert await w.notices.once() == 0
    assert await notices_in(db) == []
    # Quiet long enough since that post, and running: now it is said.
    run_since(w, 600)
    await age(db, 130)
    assert await w.notices.once() == 1


async def test_no_still_working_line_while_output_is_queued_or_a_person_is_asked(db):
    w = await still_working(db, waiting=lambda binding: asked[0])
    asked = [True]
    run_since(w, 300)
    assert await w.notices.once() == 0  # A permission request waits on the person.
    asked[0] = False
    await post(w, "Pick one", ago=200, widget='{"widget_type": "zform"}')
    assert await w.notices.once() == 0  # Choice buttons are the newest post.
    await post(w, "🔧 bash", ago=150)
    queued = await w.outbox.queue_batch(
        "reply",
        w.binding.id,
        w.binding.revision,
        ("Final reply",),
        renderer_version="test-v1",
        message_limit=300,
        topic_limit=100,
    )
    assert await w.notices.once() == 0  # The reply is about to appear.
    assert await w.worker.advance(queued.deliveries[0]) == "delivered"
    assert await notices_in(db) == []


async def test_an_unsent_still_working_line_never_lands_after_the_reply_or_turn_end(db):
    from sqlalchemy import select

    from jt_oz_bridge.storage.models import AuditEvent

    w = await still_working(db)
    run_since(w, 300)
    assert await w.notices.once() == 1
    # The reply comes before the line was sent: the line is retired unsent.
    reply = await w.outbox.queue_batch(
        "reply",
        w.binding.id,
        w.binding.revision,
        ("Final reply",),
        renderer_version="test-v1",
        message_limit=300,
        topic_limit=100,
    )
    assert await w.notices.once() == 0
    (retired,) = await notices_in(db)
    assert (retired.state, retired.status_reason) == ("cancelled", "still_working_superseded")
    assert await w.worker.advance(reply.deliveries[0]) == "delivered"
    assert [content for _, content in w.chat.calls] == [
        w.chat.messages[1000].content
    ] and w.chat.messages[1000].content.startswith("Final reply")
    # The turn is over: nothing more, even long after the reply.
    w.running.clear()
    await post(w, "older")
    assert await w.notices.once() == 0
    # A next turn that ends before its line is sent also retires it.
    await age(db, 500)
    run_since(w, 400)
    assert await w.notices.once() == 1
    w.running.clear()
    assert await w.notices.once() == 0
    assert [n.state for n in await notices_in(db)] == ["cancelled", "cancelled"]
    async with db.sessions() as session:
        events = list(
            await session.scalars(
                select(AuditEvent.event).where(AuditEvent.event == "still_working_notice_retired")
            )
        )
    assert len(events) == 2
    assert len(w.chat.calls) == 2  # Only the reply and the other post were sent.


async def test_a_still_working_line_held_by_a_restart_is_retired_not_sent_late(db):
    from jt_oz_bridge.storage.models import Delivery

    w = await still_working(db)
    run_since(w, 300)
    assert await w.notices.once() == 1
    async with db.sessions.begin() as session:
        await session.execute(update(Delivery).values(state="held", status_reason="restart_unsent"))
    assert await w.notices.once() == 0
    (retired,) = await notices_in(db)
    assert retired.state == "cancelled" and w.chat.calls == []


async def test_the_runtime_asks_typing_for_running_work_and_never_fails_on_a_notice(
    db, monkeypatch
):
    from jt_oz_bridge.storage.durable import Conflict

    pipeline, *_ = await pipeline_setup(db)
    try:
        assert pipeline.still_working.running == pipeline.typing.running
        assert pipeline.still_working.replies is pipeline.bound_replies

        async def refused():
            raise Conflict("still_working_fixture_refusal")

        monkeypatch.setattr(pipeline.still_working, "once", refused)
        await pipeline.still_working_once()  # Optional: never raised into the worker.
        assert pipeline.deferred["still_working_notice_not_current"] == 1
        await pipeline.still_working_once()  # Not again before the next check time.
        assert pipeline.deferred["still_working_notice_not_current"] == 1
    finally:
        await pipeline.typing.close()
        await pipeline.scope.client.close()


async def test_a_refused_still_working_line_is_tried_again_only_a_minute_later(db, monkeypatch):
    from jt_oz_bridge.storage.durable import Conflict

    w = await still_working(db)
    run_since(w, 300)
    calls = []

    async def refused(*args, **kwargs):
        calls.append(args)
        raise Conflict("synthetic_output_scope_changed")

    monkeypatch.setattr(w.outbox, "queue_batch", refused)
    assert await w.notices.once() == 0
    assert await w.notices.once() == 0
    assert len(calls) == 1  # No Zulip reads every pass for a refused cosmetic line.
    monkeypatch.undo()
    w.notices.clock = lambda: time.time() + 61
    assert await w.notices.once() == 1


def running_tool(name, status="running", identity="call_1", calls=None):
    state = {"status": status}
    if calls is not None:
        state["metadata"] = {"toolCalls": [{"tool": t, "status": s} for t, s in calls]}
    return {"type": "tool", "id": identity, "name": name, "time": {"created": 2}, "state": state}


def unfinished(identity, *tools, text=""):
    """An assistant step OpenCode is still running."""
    from tests.integration.test_transcript_publisher import assistant

    return assistant(identity, text, completed=False, tools=tools)


def test_only_unfinished_tools_name_what_a_step_waits_on():
    from jt_oz_bridge.services.still_working import running_tools

    def names(*tools):
        return running_tools(unfinished("s", *tools).projection()["content"])

    assert names() == []
    assert names(running_tool("bash", "completed")) == []
    assert names(running_tool("bash", "error"), running_tool("read", "pending", "c2")) == ["read"]
    # Code mode: the MCP call still running, or the newest call until one is marked.
    calls = [("vm_list", "completed"), ("vm_start", "running")]
    assert names(running_tool("code", calls=calls)) == ["vm_start"]
    assert names(running_tool("code", calls=[("vm_list", "completed")])) == ["vm_list"]
    assert names(running_tool("code", calls=[])) == ["code"]
    assert names(running_tool("bash"), running_tool("bash", identity="c2")) == ["bash"]


async def turn_notices(db, locale, *messages):
    """The still-working line of a topic whose newest Native entries are ``messages``."""
    from jt_oz_bridge.services.still_working import StillWorkingNotices
    from jt_oz_bridge.services.typing_status import key
    from tests.integration.test_transcript_publisher import Turn, deliver

    t = await Turn().initialize(db, locale=locale)
    await t.add(*messages)
    await age(db, 300)
    running = {key(t.binding): (t.binding, time.time() - 300)}
    notices = StillWorkingNotices(t.publisher.replies, lambda: running)
    assert await notices.once() == 1
    (saved,) = await notices_in(db)
    await deliver(t.worker)
    return saved.payload["content"]


@pytest.mark.parametrize(
    ("locale", "text"),
    [
        (
            "en",
            "⏳ The AI is still working (5 min so far), waiting for the tool vm&#95;start to "
            "finish; the reply will appear here.",
        ),
        (
            "zh-TW",
            "⏳ AI 還在處理中（已 5 分鐘），正在等工具 vm&#95;start 跑完；完成後會在這裡回覆。",
        ),
    ],
)
async def test_a_still_working_line_names_the_tool_the_turn_waits_on(db, locale, text):
    calls = [("vm_create", "completed"), ("vm_start", "running")]
    content = await turn_notices(db, locale, unfinished("s1", running_tool("code", calls=calls)))
    assert content.startswith(text)


async def test_a_still_working_line_names_a_running_subagent_plainly(db):
    content = await turn_notices(db, "zh-TW", unfinished("s1", running_tool("task")))
    assert content.startswith("⏳ AI 還在處理中（已 5 分鐘），正在等工具 子 agent 跑完")


@pytest.mark.parametrize(
    ("locale", "text"),
    [
        (
            "en",
            "⏳ The AI is still working (5 min so far); the model is thinking or writing, "
            "and the reply will appear here.",
        ),
        ("zh-TW", "⏳ AI 還在處理中（已 5 分鐘），模型正在思考或撰寫回覆；完成後會在這裡回覆。"),
    ],
)
@pytest.mark.parametrize("shape", ["writing", "between_steps"])
async def test_a_still_working_line_says_the_model_is_on_it_when_no_tool_runs(
    db, locale, text, shape
):
    from tests.integration.test_transcript_publisher import step

    newest = (
        (unfinished("s1", text="partial"),)
        if shape == "writing"
        else (step("s1", "bash"),)  # A finished tool step; the next one is being thought.
    )
    assert (await turn_notices(db, locale, *newest)).startswith(text)


async def test_a_still_working_line_stays_general_when_the_newest_entry_does_not_tell(db):
    from tests.integration.test_transcript_publisher import idle

    content = await turn_notices(db, "en", idle("i1"))
    assert content.startswith(
        "⏳ The AI is still working (5 min so far); the reply will appear here."
    )
