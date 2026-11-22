"""Lifecycle and real lease transactions; synthetic workers, no installed API."""

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.config import Settings
from jt_oz_bridge.services.runtime import RuntimeResource, RuntimeWorker, SupervisedRuntime
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import WorkerLease
from jt_oz_bridge.web.app import create_app


async def forever():
    await asyncio.Event().wait()


async def fence(db):
    number = await DurableStore(db).acquire_lease("test-runtime")
    assert number
    return ConsumerFence("test-runtime", number)


async def test_start_requires_real_current_lease_before_opening_any_resource(db):
    opened = AsyncMock()
    runtime = SupervisedRuntime(
        db,
        ConsumerFence("stale", 100),
        (RuntimeResource("resource", opened, AsyncMock()),),
        (RuntimeWorker("worker", forever),),
    )
    with pytest.raises(RuntimeError, match="runtime_start_failed"):
        await runtime.start()
    opened.assert_not_awaited()
    assert not runtime.healthy
    with pytest.raises(RuntimeError, match="single_use"):
        await runtime.start()


async def test_partial_start_failure_cleans_attempted_resources_in_reverse_order(db):
    events = []

    async def first():
        events.append("open_first")

    async def partial():
        events.append("open_partial")
        raise ValueError("PRIVATE_UPSTREAM_PAYLOAD")

    async def close_first():
        assert await db.ready()
        events.append("close_first")

    async def close_partial():
        events.append("close_partial")

    worker = AsyncMock()
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (
            RuntimeResource("first", first, close_first),
            RuntimeResource("partial", partial, close_partial),
        ),
        (RuntimeWorker("worker", worker),),
    )
    with pytest.raises(RuntimeError) as error:
        await runtime.start()
    assert str(error.value) == "runtime_start_failed"
    assert events == ["open_first", "open_partial", "close_partial", "close_first"]
    worker.assert_not_called()
    await runtime.close()
    assert len(events) == 4


async def test_close_joins_cancelled_attempt_before_closing_resources(db):
    events = []
    entered = asyncio.Event()

    async def worker():
        entered.set()
        try:
            await forever()
        except asyncio.CancelledError:
            # Equivalent to dispatcher/delivery's shielded uncertainty receipt.
            await asyncio.shield(asyncio.sleep(0.001))
            events.append("uncertainty_saved")
            raise

    async def cleanup():
        assert events == ["uncertainty_saved"] and await db.ready()
        events.append("resource_closed")

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("resource", AsyncMock(), cleanup),),
        (RuntimeWorker("worker", worker),),
    )
    await runtime.start()
    await entered.wait()
    assert runtime.healthy
    await asyncio.gather(runtime.close(), runtime.close())
    assert events == ["uncertainty_saved", "resource_closed"] and not runtime.healthy


async def test_owner_failure_then_close_does_not_cancel_uncertainty_cleanup_twice(db):
    trigger, cleaning, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
    events = []

    async def owner():
        await trigger.wait()
        raise ValueError("synthetic owner lost")

    async def worker():
        try:
            await forever()
        except asyncio.CancelledError:
            cleaning.set()
            await finish.wait()
            events.append("uncertainty_saved")
            raise

    async def cleanup():
        events.append("resource_closed")

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("resource", AsyncMock(), cleanup),),
        (RuntimeWorker("owner", owner), RuntimeWorker("attempt", worker)),
    )
    await runtime.start()
    trigger.set()
    await asyncio.wait_for(cleaning.wait(), 3)
    closing = asyncio.create_task(runtime.close())
    try:
        # A second cancellation would interrupt the pending durable receipt,
        # allowing resources to close before its final commit completes.
        await asyncio.sleep(0.02)
        assert not closing.done() and not events
        assert runtime._tasks[1].cancelling() == 1
    finally:
        finish.set()
        await asyncio.wait_for(closing, 3)
    assert events == ["uncertainty_saved", "resource_closed"]


@pytest.mark.parametrize("stop_source", ["close", "owner_failure"])
async def test_shutdown_rechecks_worker_after_its_own_timeout_cancellation(db, stop_source):
    timeout_exiting, release_timeout, resumed, owner_failed = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )
    resource_closed = AsyncMock()

    class ObservedTimeout(asyncio.Timeout):
        async def __aexit__(self, *args):
            # Delay only the real timeout's exit, exposing the same temporary
            # cancelling count that close/owner monitoring can race with.
            timeout_exiting.set()
            await release_timeout.wait()
            return await super().__aexit__(*args)

    async def worker():
        try:
            async with ObservedTimeout(asyncio.get_running_loop().time() + 0.01):
                await forever()
        except TimeoutError:
            pass
        resumed.set()
        await forever()

    async def owner():
        await owner_failed.wait()
        raise ValueError("synthetic owner lost")

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("resource", AsyncMock(), resource_closed),),
        (RuntimeWorker("result-publications", worker), RuntimeWorker("owner", owner)),
    )
    await runtime.start()
    await asyncio.wait_for(timeout_exiting.wait(), 1)
    assert runtime._tasks[0].cancelling() == 1
    if stop_source == "owner_failure":
        owner_failed.set()
        await asyncio.wait_for(runtime.wait_stopped(), 1)
    closing = asyncio.create_task(runtime.close())
    try:
        await asyncio.sleep(0.03)
        assert not closing.done() and runtime._tasks[0].cancelling() == 1
        resource_closed.assert_not_awaited()
        release_timeout.set()
        await asyncio.wait_for(closing, 1)
        assert resumed.is_set() and runtime._tasks[0].cancelled()
        assert all(task.done() for task in runtime._cancel_requests.values())
        resource_closed.assert_awaited_once()
    finally:
        release_timeout.set()
        # Bound a pre-fix regression failure without leaving fixture tasks.
        if not runtime._tasks[0].done():
            runtime._tasks[0].cancel()
        await runtime.close()


@pytest.mark.parametrize("stop_source", ["close", "owner_failure"])
async def test_existing_external_cancellation_receipt_is_joined_without_second_cancel(
    db, stop_source
):
    saving, release, owner_failed = asyncio.Event(), asyncio.Event(), asyncio.Event()
    events = []

    async def worker():
        try:
            await forever()
        except asyncio.CancelledError:
            saving.set()
            await release.wait()
            events.append("uncertainty_saved")
            raise

    async def owner():
        await owner_failed.wait()
        raise ValueError("synthetic owner lost")

    async def cleanup():
        assert events == ["uncertainty_saved"]
        events.append("resource_closed")

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("resource", AsyncMock(), cleanup),),
        (RuntimeWorker("attempt", worker), RuntimeWorker("owner", owner)),
    )
    await runtime.start()
    runtime._tasks[0].cancel()
    await asyncio.wait_for(saving.wait(), 1)
    if stop_source == "owner_failure":
        owner_failed.set()
        await asyncio.wait_for(runtime.wait_stopped(), 1)
    closing = asyncio.create_task(runtime.close())
    try:
        await asyncio.sleep(0.03)
        assert not closing.done() and not events
        assert runtime._tasks[0].cancelling() == 1
    finally:
        release.set()
        await asyncio.wait_for(closing, 1)
    assert events == ["uncertainty_saved", "resource_closed"]


@pytest.mark.parametrize("failure", ["return", "error", "cancel"])
async def test_any_worker_stopping_cancels_peer_without_automatic_restart(db, failure):
    trigger, peer_cancelled = asyncio.Event(), asyncio.Event()
    runs = 0

    async def fragile():
        nonlocal runs
        runs += 1
        await trigger.wait()
        if failure == "error":
            raise ValueError("PRIVATE_WORKER_ERROR")
        if failure == "cancel":
            raise asyncio.CancelledError

    async def peer():
        try:
            await forever()
        finally:
            peer_cancelled.set()

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (),
        (RuntimeWorker("fragile", fragile), RuntimeWorker("peer", peer)),
    )
    await runtime.start()
    trigger.set()
    await asyncio.wait_for(runtime.wait_stopped(), 3)
    await asyncio.wait_for(peer_cancelled.wait(), 3)
    assert not runtime.healthy and runtime.failure_code == "runtime_worker_stopped"
    await runtime.close()
    assert runs == 1


async def test_worker_immediate_exit_fails_startup_and_closes_resources(db):
    close = AsyncMock()
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("resource", AsyncMock(), close),),
        (RuntimeWorker("worker", AsyncMock()),),
    )
    with pytest.raises(RuntimeError, match="runtime_start_failed"):
        await runtime.start()
    close.assert_awaited_once()
    assert not runtime.healthy


async def test_cleanup_error_does_not_skip_other_resource_or_leak_error(db):
    first_close = AsyncMock()
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (
            RuntimeResource("first", AsyncMock(), first_close),
            RuntimeResource("second", AsyncMock(), AsyncMock(side_effect=ValueError("SECRET"))),
        ),
        (RuntimeWorker("worker", forever),),
    )
    await runtime.start()
    await runtime.close()
    first_close.assert_awaited_once()
    assert runtime.failure_code == "runtime_cleanup_failed"


@pytest.mark.parametrize("failure", ["worker", "lease"])
async def test_web_runtime_shares_lease_and_degrades_readiness_then_cleans(
    db, monkeypatch, failure
):
    from jt_oz_bridge.web import app as web

    monkeypatch.setattr(web, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    trigger = asyncio.Event()
    closed = asyncio.Event()
    captured = []

    async def worker():
        await trigger.wait()
        raise ValueError("PRIVATE_WORKER_ERROR")

    async def cleanup():
        assert await db.ready()
        closed.set()

    def factory(database, selected_fence):
        assert database is db
        runtime = SupervisedRuntime(
            db,
            selected_fence,
            (RuntimeResource("resource", AsyncMock(), cleanup),),
            (RuntimeWorker("worker", worker),),
        )
        captured.append(runtime)
        return runtime

    app = create_app(Settings(), db, runtime_factory=factory)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bridge.invalid"
        ) as client:
            assert (await client.get("/readyz")).json() == {
                "ready": True,
                "mode": "managed",
                "agent_consumers": True,
            }
            if failure == "worker":
                trigger.set()
            else:
                async with db.sessions.begin() as session:
                    await session.execute(update(WorkerLease).values(expires_at=0))
            await asyncio.wait_for(closed.wait(), 3)
            response = await client.get("/readyz")
            assert response.status_code == 503 and response.json()["agent_consumers"] is False
            assert (
                "PRIVATE" not in response.text and (await client.get("/healthz")).status_code == 200
            )
            assert not captured[0].healthy


async def test_second_web_process_never_constructs_or_starts_a_runtime(db):
    def factory(database, f):
        return SupervisedRuntime(database, f, (), (RuntimeWorker("worker", forever),))

    first = create_app(Settings(), db, runtime_factory=factory)
    second_db = Database(str(db.engine.url), cipher=db.cipher)
    second_factory = AsyncMock()
    second = create_app(Settings(), second_db, runtime_factory=second_factory)
    async with first.router.lifespan_context(first):
        with pytest.raises(RuntimeError, match="another active"):
            async with second.router.lifespan_context(second):
                pytest.fail("duplicate consumer")
        second_factory.assert_not_called()


async def test_web_refuses_a_runtime_with_a_different_fence_before_start(db):
    runtime = SupervisedRuntime(
        db, ConsumerFence("other", 1), (), (RuntimeWorker("worker", forever),)
    )
    runtime.start = AsyncMock()
    app = create_app(Settings(), db, runtime_factory=lambda database, f: runtime)
    with pytest.raises(RuntimeError, match="must_share_process"):
        async with app.router.lifespan_context(app):
            pytest.fail("mismatched lease runtime")
    runtime.start.assert_not_awaited()


async def test_lease_loss_during_resource_start_never_starts_workers(db):
    worker = AsyncMock()

    async def invalidate():
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=0))

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("invalidate", invalidate, AsyncMock()),),
        (RuntimeWorker("worker", worker),),
    )
    with pytest.raises(RuntimeError, match="runtime_start_failed"):
        await runtime.start()
    worker.assert_not_called()


async def test_cancelling_a_close_caller_never_abandons_join_or_cleanup(db):
    cancellation_started, receipt_allowed, cleaned = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )

    async def worker():
        try:
            await forever()
        except asyncio.CancelledError:
            cancellation_started.set()
            await receipt_allowed.wait()
            raise

    async def cleanup():
        assert receipt_allowed.is_set()
        cleaned.set()

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (RuntimeResource("resource", AsyncMock(), cleanup),),
        (RuntimeWorker("worker", worker),),
    )
    await runtime.start()
    closing = asyncio.create_task(runtime.close())
    await asyncio.wait_for(cancellation_started.wait(), 3)
    closing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert not cleaned.is_set()
    receipt_allowed.set()
    await runtime.close()
    assert cleaned.is_set()


async def test_supervisor_cancellation_saves_actual_dispatcher_ambiguity_before_cleanup(db):
    from jt_oz_bridge.services.queue import QueueService
    from tests.integration.test_dispatch import dispatcher, message

    dispatcher_worker, binding, execution, reader = await dispatcher(db)
    execution.mode = "wait"
    reader.messages[101] = message()
    queued = await QueueService(dispatcher_worker.bindings).receive(binding.id, message())
    selected_fence = ConsumerFence(dispatcher_worker.holder, dispatcher_worker.fencing)
    checked = asyncio.Event()

    async def run_dispatcher():
        await dispatcher_worker.advance(queued.action_id)
        await forever()

    async def cleanup():
        # Read the real persisted state before closing DB/lease resources.
        assert (await dispatcher_worker.load(queued.action_id)).state == "ambiguous"
        async with db.sessions.begin() as session:
            await selected_fence.lock(session)
        checked.set()

    runtime = SupervisedRuntime(
        db,
        selected_fence,
        (RuntimeResource("resource", AsyncMock(), cleanup),),
        (RuntimeWorker("dispatch", run_dispatcher),),
    )
    await runtime.start()
    await asyncio.wait_for(execution.entered.wait(), 3)
    await runtime.close()
    assert checked.is_set() and len(execution.submitted) == 1
    assert await dispatcher_worker.advance(queued.action_id) == "ambiguous"
    assert len(execution.submitted) == 1


async def test_failure_callback_runs_once_after_peer_cleanup_with_database_still_open(db):
    trigger, closed, notified = asyncio.Event(), asyncio.Event(), asyncio.Event()
    callback_calls = []

    async def worker():
        await trigger.wait()
        raise ValueError("synthetic runtime failure")

    async def cleanup():
        assert await db.ready()
        closed.set()

    def factory(database, selected_fence):
        return SupervisedRuntime(
            database,
            selected_fence,
            (RuntimeResource("resource", AsyncMock(), cleanup),),
            (RuntimeWorker("worker", worker),),
        )

    def failed():
        assert closed.is_set()
        callback_calls.append("shutdown_requested")
        notified.set()

    application = create_app(Settings(), db, runtime_factory=factory, on_runtime_failure=failed)
    async with application.router.lifespan_context(application):
        trigger.set()
        await asyncio.wait_for(notified.wait(), 3)
        assert callback_calls == ["shutdown_requested"]


@pytest.mark.parametrize("failure", ["error", "return", "cancel"])
async def test_worker_failure_logs_one_bounded_component_without_exception_payload(
    db, caplog, failure
):
    trigger = asyncio.Event()

    async def worker():
        await trigger.wait()
        if failure == "error":
            raise ValueError("PRIVATE_DIALOGUE PASSWORD=file:/private/source")
        if failure == "cancel":
            raise asyncio.CancelledError("PRIVATE_CANCEL_PAYLOAD")

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (),
        (RuntimeWorker("file-transfers", worker), RuntimeWorker("native-results", forever)),
    )
    await runtime.start()
    trigger.set()
    await asyncio.wait_for(runtime.wait_stopped(), 3)
    await runtime.close()
    detail = runtime.failure_detail
    assert detail is not None
    assert (detail.stage, detail.component, detail.index) == ("worker", "file-transfers", 0)
    assert detail.kind == {"error": "raised", "return": "returned", "cancel": "cancelled"}[failure]
    assert (
        detail.error_type
        == {
            "error": "ValueError",
            "return": "none",
            "cancel": "CancelledError",
        }[failure]
    )
    logs = [r for r in caplog.records if r.name == "jt_oz_bridge.services.runtime"]
    assert len(logs) == 1 and logs[0].exc_info is None and logs[0].stack_info is None
    assert "PRIVATE" not in caplog.text and "file:/private" not in caplog.text
    assert not runtime.healthy and runtime.failure_code == "runtime_worker_stopped"


@pytest.mark.parametrize(
    ("message", "code"),
    [("upstream_rejected_request", "upstream_rejected_request"), ("Private text 7", "-")],
)
async def test_worker_failure_logs_a_known_errors_fixed_code_only(db, caplog, message, code):
    from jt_oz_bridge.adapters.opencode.transport import TransportError

    trigger = asyncio.Event()

    async def worker():
        await trigger.wait()
        raise TransportError(message)

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (),
        (RuntimeWorker("file-transfers", worker), RuntimeWorker("native-results", forever)),
    )
    await runtime.start()
    trigger.set()
    await asyncio.wait_for(runtime.wait_stopped(), 3)
    await runtime.close()
    (log,) = [r for r in caplog.records if r.name == "jt_oz_bridge.services.runtime"]
    assert log.getMessage().endswith(f"error_type=TransportError code={code}")
    assert "Private" not in caplog.text


async def test_unknown_worker_and_exception_names_never_enter_logs(db, caplog):
    trigger = asyncio.Event()

    def cannot_stringify(self):
        raise AssertionError("diagnostics must not stringify exceptions")

    private_error = type("PRIVATE_EXCEPTION_CLASS", (Exception,), {"__str__": cannot_stringify})

    async def worker():
        await trigger.wait()
        raise private_error("PRIVATE_FILE_BYTES_OR_CREDENTIAL")

    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (),
        (RuntimeWorker("PRIVATE_WORKER_SOURCE", worker),),
    )
    await runtime.start()
    trigger.set()
    await asyncio.wait_for(runtime.wait_stopped(), 3)
    await runtime.close()
    assert runtime.failure_detail is not None
    assert runtime.failure_detail.component == "other"
    assert runtime.failure_detail.error_type == "OtherError"
    assert "PRIVATE" not in caplog.text


async def test_startup_exit_records_the_actual_worker_before_generic_start_failure(db, caplog):
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (),
        (RuntimeWorker("native-dispatch", AsyncMock()),),
    )
    with pytest.raises(RuntimeError, match="runtime_start_failed"):
        await runtime.start()
    assert runtime.failure_code == "runtime_start_failed"
    assert runtime.failure_detail is not None
    assert (runtime.failure_detail.component, runtime.failure_detail.kind) == (
        "native-dispatch",
        "returned",
    )
    assert caplog.text.count("runtime_component_failed") == 1


@pytest.mark.parametrize(
    "prefix,label", [("native", "native"), ("workspace-catalog", "workspace-catalog")]
)
async def test_resource_failure_logs_fixed_native_label_without_backend_identity(
    db, caplog, prefix, label
):
    closed = AsyncMock()
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (
            RuntimeResource(
                prefix + ":PRIVATE_BACKEND_ID",
                AsyncMock(side_effect=RuntimeError("PRIVATE_UPSTREAM_JSON_OR_SECRET")),
                closed,
            ),
        ),
        (RuntimeWorker("native-owner-feed", forever),),
    )
    with pytest.raises(RuntimeError, match="runtime_start_failed"):
        await runtime.start()
    closed.assert_awaited_once()
    detail = runtime.failure_detail
    assert detail is not None
    assert (detail.stage, detail.component, detail.index, detail.error_type) == (
        "startup",
        label,
        0,
        "RuntimeError",
    )
    assert "PRIVATE" not in caplog.text and caplog.text.count("runtime_component_failed") == 1


async def test_resource_cleanup_failure_reports_safe_component_and_still_closes_peers(db, caplog):
    closed = AsyncMock()
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (
            RuntimeResource("zulip-client", AsyncMock(), closed),
            RuntimeResource(
                "file-returns",
                AsyncMock(),
                AsyncMock(side_effect=ValueError("PRIVATE_UPLOAD_URL_AND_BYTES")),
            ),
        ),
        (RuntimeWorker("native-owner-feed", forever),),
    )
    await runtime.start()
    await runtime.close()
    closed.assert_awaited_once()
    assert runtime.failure_detail is not None
    assert runtime.failure_detail.stage == "cleanup"
    assert runtime.failure_detail.component == "file-returns"
    assert "PRIVATE" not in caplog.text and caplog.text.count("runtime_component_failed") == 1


async def test_normal_close_emits_no_worker_failure_diagnostic(db, caplog):
    runtime = SupervisedRuntime(
        db,
        await fence(db),
        (),
        (RuntimeWorker("native-owner-feed", forever),),
    )
    await runtime.start()
    await asyncio.gather(runtime.close(), runtime.close())
    assert runtime.failure_detail is None
    assert "runtime_component_failed" not in caplog.text


@pytest.mark.parametrize("failure", ["rejected", "error"])
async def test_lease_loss_reports_safe_reason_and_still_closes_before_callback(
    db, monkeypatch, caplog, failure
):
    from jt_oz_bridge.web import app as web

    monkeypatch.setattr(web, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    lose_after_ready = asyncio.Event()

    async def renew_after_ready(*args, **kwargs):
        await lose_after_ready.wait()
        if failure == "error":
            raise ValueError("PRIVATE_DSN_AND_DATABASE_PARAMETERS")
        return False

    monkeypatch.setattr(DurableStore, "renew_lease", renew_after_ready)
    closed, notified = asyncio.Event(), asyncio.Event()

    async def cleanup():
        assert await db.ready()
        closed.set()

    def factory(database, selected_fence):
        return SupervisedRuntime(
            database,
            selected_fence,
            (RuntimeResource("zulip-client", AsyncMock(), cleanup),),
            (RuntimeWorker("native-owner-feed", forever),),
        )

    def failed():
        assert closed.is_set()
        notified.set()

    application = create_app(Settings(), db, runtime_factory=factory, on_runtime_failure=failed)
    async with application.router.lifespan_context(application):
        lose_after_ready.set()
        await asyncio.wait_for(notified.wait(), 3)
        assert "PRIVATE" not in caplog.text
        assert caplog.text.count("consumer_lease_lost") == 1
        assert "runtime_component_failed" not in caplog.text
        assert (
            "reason=renewal_error" if failure == "error" else "reason=renewal_rejected"
        ) in caplog.text
        logs = [r for r in caplog.records if r.name == "jt_oz_bridge.web.app"]
        assert len(logs) == 1 and logs[0].exc_info is None and logs[0].stack_info is None


async def test_lease_lost_during_startup_fails_closed_without_entering_ready_lifespan(
    db, monkeypatch
):
    from jt_oz_bridge.web import app as web

    monkeypatch.setattr(web, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    renewal_seen, closed, worker_stopped = asyncio.Event(), asyncio.Event(), asyncio.Event()
    entered = False

    async def reject(*args, **kwargs):
        renewal_seen.set()
        return False

    monkeypatch.setattr(DurableStore, "renew_lease", reject)

    async def starting():
        await renewal_seen.wait()

    async def cleanup():
        assert await db.ready()
        closed.set()

    async def running():
        try:
            await asyncio.Event().wait()
        finally:
            worker_stopped.set()

    def factory(database, selected_fence):
        return SupervisedRuntime(
            database,
            selected_fence,
            (RuntimeResource("zulip-client", starting, cleanup),),
            (RuntimeWorker("native-owner-feed", running),),
        )

    application = create_app(Settings(), db, runtime_factory=factory)
    with pytest.raises(RuntimeError, match="runtime_not_ready_after_startup"):
        async with application.router.lifespan_context(application):
            entered = True
    assert not entered and closed.is_set() and worker_stopped.is_set()


@pytest.mark.parametrize("kind", ["local", "upstream", "auth"])
async def test_runtime_reports_fixed_rate_and_auth_types_without_exception_body(db, caplog, kind):
    from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred
    from jt_oz_bridge.adapters.zulip.client import ZulipAuthenticationFailed
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited

    error = {
        "local": RequestBudgetDeferred(1, refill_window=60),
        "upstream": DeliveryRateLimited(1),
        "auth": ZulipAuthenticationFailed("PRIVATE_PROVIDER_BODY"),
    }[kind]
    runtime = SupervisedRuntime(
        db, await fence(db), (), (RuntimeWorker("native-results", forever),)
    )
    runtime.record_failure("worker", "native-results", 4, error)
    assert runtime.failure_detail.error_type == type(error).__name__
    assert f"error_type={type(error).__name__}" in caplog.text
    assert "PRIVATE" not in caplog.text and "delivery_rate_limited" not in caplog.text
