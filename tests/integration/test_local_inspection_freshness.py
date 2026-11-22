"""Normal delayed observer/socket/CLI paths; synthetic state, real readonly DB/AF_UNIX.

These cases do not qualify Native/Human/mobile or an installed artifact on their own.
"""

import argparse
import asyncio
import json
import math
import os
import tempfile
import time
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from sqlalchemy import update

from jt_oz_bridge import local_cli
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.inspection import (
    InspectionClock,
    InspectionCoverage,
    InspectionQuery,
    InspectionResponse,
    fresh_inspection_response,
)
from jt_oz_bridge.services import inspection_socket, local_inspection
from jt_oz_bridge.services.inspection_socket import InspectionSocketServer, inspect_query
from jt_oz_bridge.storage.models import WorkerLease
from tests.integration.test_local_inspection import row, setup


@pytest.fixture
def socket_path():
    with tempfile.TemporaryDirectory(prefix="jtoz-fresh-", dir="/tmp") as directory:
        yield Path(directory).resolve() / "observer.sock"


class Clock:
    def __init__(self):
        self.wall = time.time()
        self.tick = 1000.0
        self.source = SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.tick)

    def advance(self, seconds, *, wall=None):
        self.tick += seconds
        self.wall += seconds if wall is None else wall


def sample(clock, identity="ses_original", *, epoch="a" * 64):
    return row(identity).model_copy(update={"observed_at": clock.wall, "owner_epoch": epoch})


def wire_response(clock, rows):
    return InspectionResponse(
        status="ok",
        observed_at=clock.wall,
        bridge_ready=True,
        bridge_lease_current=True,
        rows=tuple(rows),
        coverage=(
            InspectionCoverage(
                backend_id="backend", complete=True, scanned=len(rows), reason="exhausted"
            ),
        ),
    )


def closing_owner(monkeypatch, backend, clock, epoch="a" * 64):
    async def owner():
        return SimpleNamespace(owner_epoch=epoch, pid=321, observed_at=clock.wall)

    monkeypatch.setattr(backend, "original_owner", owner)


@pytest.mark.parametrize("slew", [0.0, 0.003, -0.003])
async def test_normal_slow_second_row_expires_only_early_native_observation(db, monkeypatch, slew):
    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock)
    early = sample(clock, "ses_early")
    late = sample(clock, "ses_late")
    backend.pages = {None: ((early, late), None)}
    first_finished = asyncio.Event()

    async def state(value):
        if value.session_id == early.session_id:
            first_finished.set()
            return value
        await first_finished.wait()
        clock.advance(6.0, wall=6.0 + slew)
        return value.model_copy(update={"observed_at": clock.wall})

    monkeypatch.setattr(backend, "state", state)
    result = await inspector.query(InspectionQuery())
    assert result.status == "partial" and len(result.rows) == 2
    assert result.rows[0].state is ExecutionState.UNKNOWN
    assert result.rows[0].observed_at == early.observed_at and result.rows[0].owner_epoch is None
    assert result.rows[1].state is ExecutionState.IDLE and result.rows[1].owner_epoch == "a" * 64
    assert result.rows[1].observed_at == clock.wall
    assert result.observed_at == clock.wall  # Summary completion, not a refreshed row.
    assert result.coverage[0].scanned == 2 and not result.coverage[0].complete
    assert "stale_observation" in {issue.code for issue in result.issues}


async def test_post_native_sql_delay_never_restamps_idle_as_fresh(db, monkeypatch):
    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock)
    original = sample(clock)
    backend.pages = {None: ((original,), None)}
    metadata = inspector.local_metadata

    async def slow_sql(rows):
        value = await metadata(rows)
        if rows:
            clock.advance(6.0)
        return value

    monkeypatch.setattr(inspector, "local_metadata", slow_sql)
    result = await inspector.query(InspectionQuery())
    assert result.status == "partial" and result.rows[0].state is ExecutionState.UNKNOWN
    assert result.rows[0].observed_at == original.observed_at
    assert result.rows[0].bindings == (await metadata([original]))[0][0].bindings
    assert "stale_observation" in {issue.code for issue in result.issues}


async def test_closing_owner_change_does_not_erase_other_fresh_same_backend_row(db, monkeypatch):
    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock, "b" * 64)
    old, current = sample(clock, "ses_old"), sample(clock, "ses_current", epoch="b" * 64)
    backend.pages = {None: ((old, current), None)}
    result = await inspector.query(InspectionQuery())
    assert result.status == "partial" and result.rows[0].state is ExecutionState.UNKNOWN
    assert result.rows[0].owner_epoch is None and result.rows[0].observed_at == old.observed_at
    assert result.rows[1].state is ExecutionState.IDLE and result.rows[1].owner_epoch == "b" * 64
    assert result.rows[1].observed_at == current.observed_at


@pytest.mark.parametrize("change", ["holder", "fencing", "expiry"])
async def test_final_lease_change_clears_bridge_current_without_inventing_native_state(
    db, monkeypatch, change
):
    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock)
    backend.pages = {None: ((sample(clock),), None)}
    metadata = inspector.local_metadata

    async def change_after_metadata(rows):
        result = await metadata(rows)
        if rows:
            values = (
                {"holder": "different-owner"}
                if change == "holder"
                else {"fencing": WorkerLease.fencing + 1}
                if change == "fencing"
                else {"expires_at": clock.wall - 1.0}
            )
            async with db.sessions.begin() as session:
                await session.execute(
                    update(WorkerLease).where(WorkerLease.role == "consumer").values(**values)
                )
        return result

    monkeypatch.setattr(inspector, "local_metadata", change_after_metadata)
    result = await inspector.query(InspectionQuery())
    assert (
        result.status == "partial" and not result.bridge_ready and not result.bridge_lease_current
    )
    assert result.rows[0].state is ExecutionState.IDLE  # Independent fresh Native observation.
    assert "bridge_unavailable" in {issue.code for issue in result.issues}


@pytest.mark.parametrize(
    "end,observed,expected",
    [
        ((106.003, 16.0, 106.003), 105.99, True),  # Normal500ppm slew over6s.
        ((106.003, 16.0, 106.003), 101.005, False),  # Slew consumes remainingTTL.
        ((105.0, 16.0, 105.0), 101.0, False),  # Backstep cannot extend a five-second fact.
        ((99.0, 16.0, 99.0), 98.9, False),
        ((106.0, 9.0, 106.0), 105.9, False),
        ((106.0, 16.0, 106.0), 106.1, False),
        ((math.nan, 16.0, math.nan), 105.9, False),
    ],
)
def test_wall_monotonic_uncertainty_consumes_ttl_and_accepts_normal_slew(end, observed, expected):
    started = InspectionClock(100.0, 10.0, 100.0)
    ended = InspectionClock(*end)
    assert ended.fresh(observed, ended.uncertainty_since(started)) is expected


@pytest.mark.parametrize("age", [5.0, 5.001])
def test_exact_five_second_boundary_is_not_current_and_keeps_partial_metadata(age):
    clock = Clock()
    original = sample(clock).model_copy(update={"observed_at": clock.wall - age})
    response = wire_response(clock, [original])
    point = InspectionClock(clock.wall, clock.tick, clock.wall)
    result = fresh_inspection_response(response, point, point)
    assert result.status == "partial" and result.rows[0].state is ExecutionState.UNKNOWN
    assert result.rows[0].observed_at == original.observed_at
    assert result.rows[0].session_id == original.session_id and result.coverage[0].scanned == 1
    assert response.rows[0].state is ExecutionState.IDLE  # Pure projection, no mutation.


async def test_closing_owner_reads_are_once_per_backend_with_concurrency_two(db, monkeypatch):
    inspector, _, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    current, peak, calls = 0, 0, {}

    def backend(key):
        async def owner():
            nonlocal current, peak
            calls[key] = calls.get(key, 0) + 1
            current += 1
            peak = max(peak, current)
            try:
                await asyncio.sleep(0)
                return SimpleNamespace(owner_epoch="a" * 64, observed_at=clock.wall)
            finally:
                current -= 1

        return SimpleNamespace(original_owner=owner)

    monkeypatch.setattr(
        inspector, "backends", MappingProxyType({str(i): backend(str(i)) for i in range(20)})
    )
    rows = [
        sample(clock, "ses_" + str(i)).model_copy(update={"backend_id": str(i % 20)})
        for i in range(40)
    ]
    response = wire_response(clock, rows)
    lease = await inspector._lease_identity()
    result = await inspector._finish(
        response, InspectionClock.capture(clock.source.time, clock.source.monotonic), lease
    )
    assert result.status == "ok" and all(
        value.state is ExecutionState.IDLE for value in result.rows
    )
    assert len(calls) == 20 and set(calls.values()) == {1} and peak == 2 and current == 0


async def test_owner_global_deadline_preserves_completed_good_backend(db, monkeypatch):
    inspector, _, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    cancelled = []

    def backend(key):
        async def owner():
            if key == "a":
                return SimpleNamespace(owner_epoch="a" * 64, observed_at=clock.wall)
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.append(key)
                raise

        return SimpleNamespace(original_owner=owner)

    wait_for = asyncio.wait_for

    async def short_budget(task, seconds):
        assert seconds == 2
        return await wait_for(task, 0.02)

    monkeypatch.setattr(
        local_inspection,
        "asyncio",
        SimpleNamespace(
            Semaphore=asyncio.Semaphore,
            gather=asyncio.gather,
            wait_for=short_budget,
            CancelledError=asyncio.CancelledError,
        ),
    )
    monkeypatch.setattr(
        inspector, "backends", MappingProxyType({key: backend(key) for key in ("a", "b", "c")})
    )
    rows = [
        sample(clock, "ses_" + key).model_copy(update={"backend_id": key})
        for key in ("a", "b", "c")
    ]
    lease = await inspector._lease_identity()
    result = await inspector._finish(
        wire_response(clock, rows),
        InspectionClock.capture(clock.source.time, clock.source.monotonic),
        lease,
    )
    assert result.status == "partial" and result.rows[0].state is ExecutionState.IDLE
    assert all(value.state is ExecutionState.UNKNOWN for value in result.rows[1:])
    assert set(cancelled) == {"b", "c"}


async def test_server_serialization_delay_expires_rows_before_wire(socket_path, monkeypatch):
    clock = Clock()
    original = sample(clock)
    monkeypatch.setattr(inspection_socket, "time", clock.source)
    dumps = json.dumps
    first = True

    def slow_dump(*args, **kwargs):
        nonlocal first
        raw = dumps(*args, **kwargs)
        if first:
            first = False
            clock.advance(6.0)
        return raw

    monkeypatch.setattr(inspection_socket, "json", SimpleNamespace(dumps=slow_dump))

    async def handler(query):
        return wire_response(clock, [original])

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda _: 111
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        writer.write((InspectionQuery().model_dump_json() + "\n").encode())
        await writer.drain()
        result = json.loads(await reader.readline())
        writer.close()
        await writer.wait_closed()
        assert result["status"] == "partial" and result["rows"][0]["state"] == "unknown"
        assert result["rows"][0]["observed_at"] == original.observed_at
    finally:
        await server.close()


@pytest.mark.parametrize("delay_close", [False, True])
async def test_client_transport_and_close_scheduling_delay_do_not_claim_idle(
    socket_path, monkeypatch, delay_close
):
    clock = Clock()
    original = sample(clock)
    monkeypatch.setattr(inspection_socket, "time", clock.source)

    async def handler(reader, writer):
        await reader.readline()
        raw = (wire_response(clock, [original]).model_dump_json() + "\n").encode()
        if not delay_close:
            clock.advance(6.0)
        writer.write(raw)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(handler, str(socket_path))
    socket_path.chmod(0o660)
    original_open = asyncio.open_unix_connection

    class Writer:
        def __init__(self, actual):
            self.actual = actual

        def __getattr__(self, key):
            return getattr(self.actual, key)

        async def wait_closed(self):
            await self.actual.wait_closed()
            clock.advance(6.0)

    async def open_connection(*args, **kwargs):
        reader, writer = await original_open(*args, **kwargs)
        return reader, Writer(writer)

    if delay_close:
        monkeypatch.setattr(inspection_socket.asyncio, "open_unix_connection", open_connection)
    try:
        result = await inspect_query(
            socket_path,
            InspectionQuery(),
            expected_uid=os.geteuid(),
            peer_reader=lambda _: os.geteuid(),
        )
        assert result.status == "partial" and result.rows[0].state is ExecutionState.UNKNOWN
        assert result.rows[0].observed_at == original.observed_at
        assert not result.bridge_ready and not result.bridge_lease_current
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("delay", ["return", "format"])
async def test_cli_checks_scheduling_and_formatting_delay_at_display(monkeypatch, capsys, delay):
    clock = Clock()
    original = sample(clock)
    monkeypatch.setattr(local_cli, "time", clock.source)
    monkeypatch.setattr(local_cli, "expected_observer_uid", lambda: 1001)

    async def query(*args, **kwargs):
        result = wire_response(clock, [original])
        if delay == "return":
            clock.advance(6.0)
        return result

    monkeypatch.setattr(local_cli, "inspect_query", query)
    dumps = json.dumps
    first = True

    def slow_dump(*args, **kwargs):
        nonlocal first
        raw = dumps(*args, **kwargs)
        if first and delay == "format":
            first = False
            clock.advance(6.0)
        return raw

    monkeypatch.setattr(local_cli, "json", SimpleNamespace(dumps=slow_dump))
    parser = argparse.ArgumentParser()
    local_cli.add_inspection_commands(parser, parser.add_subparsers(dest="command"))
    args = parser.parse_args(["sessions", "--json"])
    assert await local_cli.run_inspection(args) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["rows"][0]["state"] == "unknown"
    assert result["rows"][0]["observed_at"] == original.observed_at
    assert not result["bridge_ready"] and not result["bridge_lease_current"]


@pytest.mark.parametrize("position", [0, 50, 99])
def test_stale_partial_at_issue_capacity_remains_valid_protocol(position):
    from jt_oz_bridge.domain.inspection import (
        InspectionIssue,
        InspectionResponseV2,
        InspectionSessionV2,
    )

    clock = Clock()
    original = sample(clock).model_copy(update={"observed_at": clock.wall - 6.0})
    projected = InspectionSessionV2.model_validate(
        original.model_dump(mode="json")
        | {
            "runtime_mode": {
                "mode": "strict",
                "reason": "strict-observation",
                "transition_at": clock.wall - 1.0,
                "observed_at": clock.wall,
            }
        }
    )
    # Use the actual strict-mode reason from the domain, without manufacturing a new code.
    issues = [InspectionIssue(code="partial_state") for _ in range(100)]
    issues[position] = InspectionIssue(code="stale_observation")
    response = InspectionResponseV2(
        status="partial", observed_at=clock.wall, rows=(projected,), issues=tuple(issues)
    )
    point = InspectionClock(clock.wall, clock.tick, clock.wall)
    result = fresh_inspection_response(response, point, point)
    roundtrip = InspectionResponseV2.model_validate_json(result.model_dump_json())
    assert roundtrip.status == "partial" and roundtrip.rows[0].state is ExecutionState.UNKNOWN
    assert len(roundtrip.issues) <= 100
    assert {"stale_observation", "runtime_modes_unavailable"} <= {
        issue.code for issue in roundtrip.issues
    }


async def test_final_bridge_health_is_observed_after_normal_native_work(db, monkeypatch):
    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock)
    backend.pages = {None: ((sample(clock),), None)}
    finished = False

    async def state(value):
        nonlocal finished
        finished = True
        return value

    async def ready():
        return not finished

    monkeypatch.setattr(backend, "state", state)
    monkeypatch.setattr(inspector, "bridge_ready", ready)
    result = await inspector.query(InspectionQuery())
    assert result.status == "partial" and not result.bridge_ready
    assert result.rows[0].state is ExecutionState.IDLE
    assert "bridge_unavailable" in {issue.code for issue in result.issues}


@pytest.mark.parametrize("epoch", [None, "b" * 64])
def test_client_requires_owner_presence_but_never_certifies_native_epoch(epoch):
    clock = Clock()
    value = sample(clock).model_copy(update={"owner_epoch": epoch})
    response = wire_response(clock, [value])
    point = InspectionClock(clock.wall, clock.tick, clock.wall)
    result = fresh_inspection_response(response, point, point)
    if epoch is None:
        assert result.status == "partial" and result.rows[0].state is ExecutionState.UNKNOWN
        assert result.rows[0].observed_at == value.observed_at
    else:
        # The client can validate presence/age, not re-certify a real Native owner.
        # Exact closing owner equality is independently tested at Inspector._finish.
        assert result is response and result.rows[0].owner_epoch == epoch


@pytest.mark.parametrize("v2", [False, True])
async def test_final_partial_with_no_issues_is_never_upgraded_to_ok(db, monkeypatch, v2):
    from jt_oz_bridge.domain.inspection import InspectionResponseV2, InspectionSessionV2

    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock)
    response = wire_response(clock, [sample(clock)]).model_copy(update={"status": "partial"})
    if v2:
        projected = InspectionSessionV2.model_validate(
            response.rows[0].model_dump(mode="json")
            | {
                "runtime_mode": {
                    "mode": "strict",
                    "reason": "strict-observation",
                    "transition_at": clock.wall,
                    "observed_at": clock.wall,
                }
            }
        )
        response = InspectionResponseV2.model_validate(
            response.model_dump(mode="json")
            | {"version": "jt-oz-inspector-v2", "rows": [projected.model_dump(mode="json")]}
        )
    lease = await inspector._lease_identity()
    result = await inspector._finish(
        response, InspectionClock.capture(clock.source.time, clock.source.monotonic), lease
    )
    assert result.status == "partial" and not result.issues
    assert result.rows[0].state is ExecutionState.IDLE


async def test_runtime_mode_projection_preserves_partial_without_issues(db, tmp_path):
    from tests.integration.test_inspection_runtime_modes import configured

    inspector, _, _, _ = await configured(db, tmp_path)
    legacy = (await inspector._query(InspectionQuery())).model_copy(
        update={"status": "partial", "issues": ()}
    )
    result = await inspector._runtime_modes(legacy)
    assert result.status == "partial" and not result.issues
    assert result.rows[0].runtime_mode.mode == "readonly-owned-check"


@pytest.mark.parametrize("phase", ["finish", "runtime"])
async def test_hundred_distinct_issues_keep_precise_errors_and_bounded_new_warnings(
    db, tmp_path, monkeypatch, phase
):
    from jt_oz_bridge.domain.inspection import (
        InspectionIssue,
        InspectionResponseV2,
        InspectionSessionV2,
    )

    inspector, backend, _, _ = await setup(db)
    clock = Clock()
    monkeypatch.setattr(local_inspection, "time", clock.source)
    closing_owner(monkeypatch, backend, clock, "b" * 64)
    issues = tuple(
        InspectionIssue(code="native_unavailable", backend_id="scope-" + str(i)) for i in range(99)
    ) + (InspectionIssue(code="unauthorized", backend_id="last-precise-error"),)
    response = wire_response(clock, [sample(clock)]).model_copy(
        update={"status": "partial", "issues": issues}
    )
    if phase == "finish":
        projected = InspectionSessionV2.model_validate(
            response.rows[0].model_dump(mode="json")
            | {
                "runtime_mode": {
                    "mode": "strict",
                    "reason": "strict-observation",
                    "transition_at": clock.wall,
                    "observed_at": clock.wall,
                }
            }
        )
        response = InspectionResponseV2.model_validate(
            response.model_dump(mode="json")
            | {"version": "jt-oz-inspector-v2", "rows": [projected.model_dump(mode="json")]}
        )
        result = await inspector._finish(
            response, InspectionClock.capture(clock.source.time, clock.source.monotonic), None
        )
        assert result.rows[0].state is ExecutionState.UNKNOWN
        assert not result.bridge_lease_current
        assert {"stale_observation", "bridge_unavailable"} <= {
            issue.code for issue in result.issues
        }
    else:
        # Missing diagnostics appends the warning before DTO validation, not just at socket output.
        result = await inspector._runtime_modes(response)
    roundtrip = InspectionResponseV2.model_validate_json(result.model_dump_json())
    assert roundtrip.status == "partial" and len(roundtrip.issues) == 100
    assert InspectionIssue(code="unauthorized", backend_id="last-precise-error") in roundtrip.issues
    assert InspectionIssue(code="native_unavailable", backend_id="scope-0") in roundtrip.issues
    assert {"capacity", "runtime_modes_unavailable"} <= {issue.code for issue in roundtrip.issues}
