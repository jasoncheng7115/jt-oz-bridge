"""Isolated ownDB/controller diagnostics; no live Native or mutation evidence."""

import asyncio
import threading
import time
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.live import VolatileFeedIndex
from jt_oz_bridge.domain.runtime_readiness import RootModeFact, scope_key
from jt_oz_bridge.services import runtime_modes as module
from jt_oz_bridge.services.runtime import RuntimeResource, RuntimeWorker, SupervisedRuntime
from jt_oz_bridge.services.runtime_enrollment import OriginalRuntimeObserver
from jt_oz_bridge.services.runtime_modes import RuntimeModePublisher
from jt_oz_bridge.services.runtime_status import FILENAME, RuntimeStatusReader
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import WorkerLease
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_leaf_resources import setup as leaf_setup
from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, frame
from tests.integration.test_consumer_runtime import setup as pipeline_setup
from tests.integration.test_runtime_enrollment import startup_check_graph


async def wait_for(predicate):
    async with asyncio.timeout(2):
        while not predicate():  # noqa: ASYNC110 - bounded diagnostic task observation
            await asyncio.sleep(0.01)


async def forever():
    await asyncio.Event().wait()


async def publisher(db, tmp_path, *, facts=None, clock=time.time):
    number = await DurableStore(db).acquire_lease("mode-test", ttl=120)
    assert number
    fence = ConsumerFence("mode-test", number)
    if facts is None:
        stamp = float(clock())
        facts = (
            RootModeFact(
                scope_key=scope_key(REF),
                mode="strict",
                reason="strict-observation",
                transition_at=stamp,
            ),
        )
    value = RuntimeModePublisher(
        db, fence, tmp_path / "runtime-modes", lambda: facts, lambda: True, clock=clock
    )
    value._healthy = lambda: True
    return value


async def test_controller_mode_transition_is_stable_across_heartbeat_and_repeated_qualification():
    p, t, _data, calls = await leaf_setup()
    observer = OriginalRuntimeObserver(p.feed, p, REF)
    try:
        await observer.start_root()
        first = observer.mode_fact()
        count = len(calls)
        await asyncio.sleep(0)
        observer._set_mode("strict")
        assert observer.mode_fact() == first and len(calls) == count
        # Diagnostic access must not call any mutating certification method.
        p.certified_epoch = lambda *args: (_ for _ in ()).throw(AssertionError("no watch lookup"))
        p.read_scope = AsyncMock(side_effect=AssertionError("no Native read"))
        assert observer.mode_fact() == first and len(calls) == count
        p.read_scope.assert_not_awaited()
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault", ["feed", "generation", "owner", "attestation", "task-cancelling", "task-done"]
)
async def test_controller_scope_drift_is_diagnostic_unavailable_without_workflow_mutation(fault):
    p, t, _data, calls = await leaf_setup()
    observer = OriginalRuntimeObserver(p.feed, p, REF)
    try:
        await observer.start_root()
        watched = dict(p._watched)
        if fault == "feed":
            index = VolatileFeedIndex(PROFILE, (REF,), OWNER)
            index.accept(frame(CONNECTED))
            p.feed.index = index
        elif fault == "generation":
            p.feed.index.connection_epoch = "b" * 64
        elif fault == "owner":
            p.feed.index.owner_epoch = "b" * 64
        elif fault == "attestation":
            t.attestation = replace(t.attestation)
        else:
            p.feed.task.cancel()
            if fault == "task-done":
                await asyncio.gather(p.feed.task, return_exceptions=True)
        count = len(calls)
        fact = observer.mode_fact()
        assert fact.mode == "unavailable" and fact.reason == "feed-unavailable"
        assert observer.mode_fact() == fact
        assert observer.mode == "strict" and p._watched == watched and len(calls) == count
    finally:
        await finish(p, t)


async def test_genuine_owned_check_controller_reports_readonly_without_fabricating_state(db):
    graph = await startup_check_graph(db)
    try:
        await graph.observer.start()
        fact = graph.observer.mode_fact()
        assert fact.mode == "readonly-owned-check" and fact.reason == "owned-check-recovery"
        assert fact.scope_key == scope_key(graph.ref)
        assert not graph.proofs._watched and set(graph.calls) <= {"GET"}
        await graph.observer.retry_recovery()
        assert graph.observer.mode_fact() == fact
    finally:
        await finish(graph.proofs, graph.transport)


async def test_pipeline_exact_full_scope_missing_dynamic_root_is_not_observed(db):
    pipeline, _server, _execution, _results, _binding, _pulse = await pipeline_setup(db)
    try:
        original = next(iter(pipeline.backends.values()))
        ref = original.references[0]
        first = pipeline.mode_facts()
        assert first[0].mode == "not-observed" and pipeline.mode_facts() == first
        second = ref.model_copy(update={"upstream_session_id": "another-original"})
        fact = RootModeFact(
            scope_key=scope_key(ref),
            mode="strict",
            reason="strict-observation",
            transition_at=time.time(),
        )
        candidate = replace(
            original, reference_provider=lambda: (ref, second), mode_snapshot=lambda: (fact,)
        )
        pipeline.backends = MappingProxyType({ref.backend_id: candidate})
        modes = {x.scope_key: x.mode for x in pipeline.mode_facts()}
        assert modes == {scope_key(ref): "strict", scope_key(second): "not-observed"}
        foreign = fact.model_copy(
            update={
                "scope_key": scope_key(ref.model_copy(update={"canonical_directory": "/foreign"}))
            }
        )
        pipeline.backends = MappingProxyType(
            {ref.backend_id: replace(candidate, mode_snapshot=lambda: (foreign,))}
        )
        with pytest.raises(ValueError, match="provider_scope"):
            pipeline.mode_facts()
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize(
    "fault", ["holder", "fencing", "expired", "healthy", "scope", "future", "stale", "changed-fact"]
)
async def test_snapshot_cannot_survive_lease_health_scope_clock_or_mode_change(db, tmp_path, fault):
    clock = [time.time()]
    pub = await publisher(db, tmp_path, clock=lambda: clock[0])
    assert await pub.collect() is not None
    if fault in {"holder", "fencing", "expired"}:
        values = (
            {"holder": "new-consumer"}
            if fault == "holder"
            else {"fencing": pub.fence.fencing + 1}
            if fault == "fencing"
            else {"expires_at": clock[0] - 1}
        )
        async with db.sessions.begin() as session:
            await session.execute(
                update(WorkerLease).where(WorkerLease.role == "consumer").values(**values)
            )
        assert await pub.collect() is None
    elif fault == "healthy":
        pub._healthy = lambda: False
    elif fault == "scope":
        pub.scope_current = lambda: False
    elif fault == "future":
        clock[0] -= 0.01
    elif fault == "stale":
        clock[0] += 1.0
    else:
        pub.facts = lambda: ()
    assert pub.snapshot() is None
    await pub.close()


async def test_inprocess_and_disk_snapshot_preserve_strict_peer_and_readonly_transition(
    db, tmp_path
):
    stamp = time.time()
    facts = (
        RootModeFact(
            scope_key=scope_key(REF),
            mode="strict",
            reason="strict-observation",
            transition_at=stamp,
        ),
        RootModeFact(
            scope_key=scope_key(REF.model_copy(update={"upstream_session_id": "readonly-peer"})),
            mode="readonly-awaiting-idle",
            reason="positive-idle-required",
            transition_at=stamp,
        ),
    )
    pub = await publisher(db, tmp_path, facts=facts)
    runtime = SupervisedRuntime(
        db, pub.fence, (), (RuntimeWorker("native-owner-feed", forever),), mode_publisher=pub
    )
    try:
        await runtime.start()
        await wait_for(
            lambda: (
                runtime.runtime_mode_snapshot() is not None and (pub.directory / FILENAME).exists()
            )
        )
        first = runtime.runtime_mode_snapshot()
        await wait_for(
            lambda: (
                runtime.runtime_mode_snapshot() is not None
                and runtime.runtime_mode_snapshot().generated_at > first.generated_at
            )
        )
        second = runtime.runtime_mode_snapshot()
        assert second.roots == first.roots
        reader = RuntimeStatusReader(pub.directory)
        try:
            assert reader.read(pub._lease, bridge_healthy=True).roots == second.roots
        finally:
            reader.close()
        assert len(tuple(pub.directory.iterdir())) <= 2 and runtime.healthy
    finally:
        await runtime.close()
    assert runtime.runtime_mode_snapshot() is None and pub._writer is None


@pytest.mark.parametrize("failure", ["publish", "unknown-slot"])
async def test_diagnostic_failure_preserves_business_workers_and_unknown_files(
    db, tmp_path, monkeypatch, failure
):
    pub = await publisher(db, tmp_path)
    unknown = None
    if failure == "unknown-slot":
        pub.directory.mkdir(mode=0o700)
        unknown = pub.directory / FILENAME
        unknown.write_bytes(b"operator-owned-unknown")
        unknown.chmod(0o600)
    else:
        monkeypatch.setattr(
            module.RuntimeStatusWriter,
            "publish",
            lambda *args: (_ for _ in ()).throw(OSError("private path omitted")),
        )
    runtime = SupervisedRuntime(
        db, pub.fence, (), (RuntimeWorker("native-owner-feed", forever),), mode_publisher=pub
    )
    try:
        await runtime.start()
        await wait_for(lambda: pub._failed)
        assert runtime.healthy and runtime.failure_code is None
        assert runtime.runtime_mode_snapshot() is None and pub._writer is None
        if unknown is not None:
            assert unknown.read_bytes() == b"operator-owned-unknown"
    finally:
        await runtime.close()


async def test_shutdown_joins_inflight_diagnostic_io_before_closing_fd(db, tmp_path, monkeypatch):
    pub = await publisher(db, tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = module.RuntimeStatusWriter.publish
    writers = []

    def blocked(writer, snapshot):
        writers.append(writer)
        entered.set()
        assert release.wait(2)
        original(writer, snapshot)

    monkeypatch.setattr(module.RuntimeStatusWriter, "publish", blocked)
    runtime = SupervisedRuntime(
        db, pub.fence, (), (RuntimeWorker("native-owner-feed", forever),), mode_publisher=pub
    )
    await runtime.start()
    assert await asyncio.to_thread(entered.wait, 2)
    closer = asyncio.create_task(runtime.close())
    try:
        await asyncio.sleep(0)
        assert not closer.done()
    finally:
        release.set()
        await closer
    assert pub._writer is None and pub._task.done() and writers[0].directory.fd == -1


async def test_disabled_and_partial_startup_never_leave_diagnostic_fds(db, tmp_path):
    pub = await publisher(db, tmp_path)
    runtime = SupervisedRuntime(db, pub.fence, (), (RuntimeWorker("native-owner-feed", forever),))
    assert runtime.runtime_mode_snapshot() is None
    await runtime.start()
    await runtime.close()
    assert not pub.directory.exists()
    bad = SupervisedRuntime(
        db,
        pub.fence,
        (RuntimeResource("native:test", AsyncMock(side_effect=ValueError("failed")), AsyncMock()),),
        (RuntimeWorker("native-owner-feed", forever),),
        mode_publisher=pub,
    )
    with pytest.raises(RuntimeError, match="start_failed"):
        await bad.start()
    assert pub._closed and pub._writer is None and pub._task is None


async def test_diagnostic_close_error_cannot_skip_business_cleanup(db, tmp_path, monkeypatch):
    pub = await publisher(db, tmp_path)
    cleanup = AsyncMock()
    original = module.RuntimeStatusWriter.close

    def failed_close(writer):
        original(writer)
        raise OSError("synthetic close error")

    monkeypatch.setattr(module.RuntimeStatusWriter, "close", failed_close)
    runtime = SupervisedRuntime(
        db,
        pub.fence,
        (RuntimeResource("test-resource", AsyncMock(), cleanup),),
        (RuntimeWorker("native-owner-feed", forever),),
        mode_publisher=pub,
    )
    await runtime.start()
    await wait_for(lambda: pub.snapshot() is not None)
    await runtime.close()
    cleanup.assert_awaited_once()
    assert pub._writer is None and not runtime.healthy


async def test_cancelled_close_waiter_does_not_cancel_owned_io_join(db, tmp_path, monkeypatch):
    pub = await publisher(db, tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = module.RuntimeStatusWriter.publish
    writers = []

    def blocked(writer, snapshot):
        writers.append(writer)
        entered.set()
        assert release.wait(2)
        original(writer, snapshot)

    monkeypatch.setattr(module.RuntimeStatusWriter, "publish", blocked)
    await pub.start(lambda: True)
    assert await asyncio.to_thread(entered.wait, 2)
    first = asyncio.create_task(pub.close())
    await asyncio.sleep(0)
    first.cancel()
    await asyncio.gather(first, return_exceptions=True)
    second = asyncio.create_task(pub.close())
    try:
        await asyncio.sleep(0)
        assert not second.done() and writers[0].directory.fd >= 0
    finally:
        release.set()
        await second
    assert writers[0].directory.fd == -1 and pub._writer is None


@pytest.mark.parametrize(
    "mode,reason", [("unavailable", "feed-unavailable"), ("not-observed", "not-observed")]
)
async def test_newly_observed_transition_precedes_snapshot_generation(db, tmp_path, mode, reason):
    pub = await publisher(db, tmp_path)
    saved = []

    def first_observation():
        if not saved:
            saved.append(
                RootModeFact(
                    scope_key=scope_key(REF), mode=mode, reason=reason, transition_at=time.time()
                )
            )
        return tuple(saved)

    pub.facts = first_observation
    result = await pub.collect()
    assert result is not None and result.roots[0].transition_at <= result.generated_at
    assert pub.snapshot() == result
    await pub.close()


async def test_symlink_parent_is_rejected_before_creating_any_foreign_directory(db, tmp_path):
    pub = await publisher(db, tmp_path)
    outside = tmp_path / "unrelated"
    outside.mkdir(mode=0o700)
    link = tmp_path / "changed-state-parent"
    link.symlink_to(outside, target_is_directory=True)
    pub.directory = link / "runtime-modes"
    await pub.start(lambda: True)
    assert pub._failed and pub._writer is None and pub.snapshot() is None
    assert not (outside / "runtime-modes").exists() and link.is_symlink()
    await pub.close()


@pytest.mark.parametrize("with_runtime", [False, True])
async def test_publisher_cancel_joins_real_sql_session_close_before_shutdown(
    db, tmp_path, monkeypatch, with_runtime
):
    pub = await publisher(db, tmp_path)
    entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
    original = AsyncSession.close
    runtime = (
        SupervisedRuntime(
            db, pub.fence, (), (RuntimeWorker("native-owner-feed", forever),), mode_publisher=pub
        )
        if with_runtime
        else None
    )
    if runtime is not None:
        await runtime.start()

    async def blocked_close(session):
        entered.set()
        await release.wait()
        try:
            await original(session)
        finally:
            finished.set()

    monkeypatch.setattr(AsyncSession, "close", blocked_close)
    if runtime is None:
        await pub.start(lambda: True)
    closer = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert db.engine.pool.checkedout() > 0
        closer = asyncio.create_task(runtime.close() if runtime is not None else pub.close())
        await asyncio.sleep(0.05)
        assert not closer.done(), "shutdown returned before its SQL cleanup completed"
        assert not finished.is_set() and db.engine.pool.checkedout() > 0
    finally:
        # Even the deliberately failing old implementation must not leave the
        # controlled close task/connection alive after this test's event loop.
        release.set()
        if closer is not None:
            await closer
        await asyncio.wait_for(finished.wait(), 2)
        await pub.close()
        if runtime is not None:
            await runtime.close()
    assert db.engine.pool.checkedout() == 0


async def test_strict_root_that_lost_its_watch_is_restored_by_fresh_reads():
    p, t, _data, _calls = await leaf_setup()
    observer = OriginalRuntimeObserver(p.feed, p, REF)
    try:
        await observer.start_root()
        assert not observer.lost_watch()
        p.revoke_watch(REF)
        assert observer.lost_watch()
        await observer.restore_watch()
        assert not observer.lost_watch() and p.holds_watch(REF)
    finally:
        await finish(p, t)


async def test_lost_watch_stays_closed_when_the_original_owner_changed():
    p, t, _data, _calls = await leaf_setup()
    observer = OriginalRuntimeObserver(p.feed, p, REF)
    try:
        await observer.start_root()
        p.revoke_watch(REF)
        observer.owner_epoch = "another-owner"
        await observer.restore_watch()
        assert observer.lost_watch() and not p.holds_watch(REF)
        assert observer.retry_at > 0
    finally:
        await finish(p, t)


def test_deferred_refusal_is_logged_with_a_fixed_reason_only():
    from jt_oz_bridge.services.consumer_runtime import fixed_reason

    assert fixed_reason(ValueError("v2_original_execution_proof_unavailable")) == (
        "v2_original_execution_proof_unavailable"
    )
    assert "secret" not in fixed_reason(ValueError("free text with a secret"))
