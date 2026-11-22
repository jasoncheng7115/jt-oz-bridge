"""Private v2 observer projection; synthetic Native/peer, real read-only metadata/file I/O."""

import argparse
import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import event, update

from jt_oz_bridge import local_cli
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.inspection import (
    InspectionQuery,
    InspectionQueryV2,
    InspectionResponse,
    InspectionResponseV2,
    InspectionRuntimeMode,
    InspectionSession,
)
from jt_oz_bridge.domain.runtime_readiness import (
    RootModeFact,
    RuntimeModeSnapshot,
    lease_fingerprint,
    scope_key,
)
from jt_oz_bridge.services import local_inspection
from jt_oz_bridge.services.inspection_socket import InspectionSocketServer, inspect_query
from jt_oz_bridge.services.local_inspection import InspectionRuntimeScope, LocalSessionInspector
from jt_oz_bridge.services.runtime_status import RuntimeStatusReader, RuntimeStatusWriter
from jt_oz_bridge.storage.control_models import EnrolledProject
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import WorkerLease
from tests.support import REF, SyntheticControl, service


class Backend:
    backend_id = "backend"
    contract_sha256 = SyntheticControl.contract_hash

    def __init__(self, ref):
        self.ref, self.calls = ref, []

    def row(self):
        return InspectionSession(
            backend_id=self.ref.backend_id,
            backend_identity=self.ref.backend_identity,
            session_id=self.ref.upstream_session_id,
            native_project_id="native-project",
            directory=self.ref.canonical_directory,
            title="Original session",
            state=ExecutionState.UNKNOWN,
            state_reason="resource_unavailable",
            observed_at=time.time(),
        )

    async def page(self, limit, cursor, *, project=None):
        self.calls.append(project)
        return (self.row(),), None

    async def detail(self, identity):
        return self.row()

    async def state(self, row):
        return row

    async def original_owner(self):
        return SimpleNamespace(owner_epoch="a" * 64, pid=123, observed_at=time.time())


async def configured(db, tmp_path, *, static=True):
    control = SyntheticControl()
    control.ref = REF.model_copy(update={"upstream_session_id": "ses_original"})
    bindings, _, _ = await service(db, control=control)
    binding = await bindings.bind("realm", 7, 10, "Original topic", control.ref)
    await DurableStore(db).acquire_lease("diagnostic-synthetic-holder", ttl=120)
    async with db.sessions() as session:
        lease = await session.get(WorkerLease, "consumer")
        key = lease_fingerprint(lease.holder, lease.fencing)
    directory = tmp_path / "runtime-modes"
    directory.mkdir(mode=0o700)
    now = time.time()
    snapshot = RuntimeModeSnapshot.create(
        generated_at=now,
        lease_fingerprint=key,
        roots=(
            RootModeFact(
                scope_key=scope_key(control.ref),
                mode="readonly-owned-check",
                reason="owned-check-recovery",
                transition_at=now - 36000.0,
            ),
        ),
    )
    writer = RuntimeStatusWriter(directory, key)
    writer.publish(snapshot)
    writer.close()

    async def read(lease, healthy):
        reader = RuntimeStatusReader(directory)
        try:
            return reader.read(lease, bridge_healthy=healthy)
        finally:
            reader.close()

    async def healthy():
        return True

    backend = Backend(control.ref)
    inspector = LocalSessionInspector(
        db,
        {"backend": backend},
        {"project": ("backend", "native-project", REF.canonical_directory)},
        frozenset({("backend", REF.backend_identity, "ses_original", REF.canonical_directory)}),
        {"realm": "https://zulip.invalid"},
        healthy,
        runtime_references=frozenset({control.ref}) if static else frozenset(),
        runtime_scopes={
            "project": InspectionRuntimeScope(
                "backend", REF.canonical_directory, "realm", frozenset({10})
            )
        },
        runtime_snapshot=read,
    )
    return inspector, backend, binding, snapshot


async def test_v1_default_never_reads_runtime_files_and_keeps_exact_legacy_fields(db, tmp_path):
    inspector, _, _, _ = await configured(db, tmp_path)

    async def forbidden(*args):
        raise AssertionError("v1 must never read runtime snapshot")

    inspector.runtime_snapshot = forbidden
    response = await inspector.query(InspectionQuery())
    assert type(response) is InspectionResponse and response.version == "jt-oz-inspector-v1"
    assert "runtime_mode" not in response.rows[0].model_dump()
    assert "runtime_modes_unavailable" not in [issue.code for issue in response.issues]
    assert "Controller observation" not in local_cli.render(response, "en")


@pytest.mark.parametrize("static", [True, False])
async def test_exact_static_or_current_dynamic_binding_join_keeps_native_unknown(
    db, tmp_path, static
):
    inspector, _, _, snapshot = await configured(db, tmp_path, static=static)
    queries = []

    def capture(conn, cursor, statement, parameters, context, many):
        queries.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", capture)
    try:
        result = await inspector.query(InspectionQueryV2())
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", capture)
    assert type(result) is InspectionResponseV2
    row = result.rows[0]
    assert row.state is ExecutionState.UNKNOWN and row.state_reason == "resource_unavailable"
    assert row.runtime_mode.model_dump() == {
        "mode": "readonly-owned-check",
        "reason": "owned-check-recovery",
        "transition_at": snapshot.roots[0].transition_at,
        "observed_at": snapshot.generated_at,
    }
    raw = result.model_dump_json()
    assert snapshot.lease_fingerprint not in raw and snapshot.roots[0].scope_key not in raw
    assert "diagnostic-synthetic-holder" not in raw
    assert all("payload" not in q.lower() and "check_admissions" not in q.lower() for q in queries)
    assert all(
        not q.lstrip().upper().startswith(("UPDATE ", "INSERT ", "DELETE ")) for q in queries
    )
    assert sum(q.startswith("SELECT worker_leases.holder,") for q in queries) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("backend_id", "other"),
        ("backend_identity", "other"),
        ("upstream_session_id", "ses_other"),
        ("project_id", "other"),
        ("canonical_directory", "/other"),
    ],
)
async def test_fact_for_different_full_reference_cannot_join_by_session_or_directory(
    db, tmp_path, field, value
):
    inspector, backend, _, snapshot = await configured(db, tmp_path)
    foreign = backend.ref.model_copy(update={field: value})

    async def read(lease, healthy):
        return RuntimeModeSnapshot.create(
            generated_at=time.time(),
            lease_fingerprint=lease.lease_fingerprint,
            roots=(snapshot.roots[0].model_copy(update={"scope_key": scope_key(foreign)}),),
        )

    inspector.runtime_snapshot = read
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "not-observed"
    assert result.rows[0].runtime_mode.observed_at is None


async def test_catalog_only_never_guesses_project_from_shared_directory(db, tmp_path):
    inspector, backend, _, _ = await configured(db, tmp_path)
    backend.ref = backend.ref.model_copy(update={"upstream_session_id": "ses_catalog_only"})
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "not-observed"
    assert result.rows[0].execution_registration == "catalog_only" and not result.rows[0].bindings


async def test_dynamic_project_revocation_during_read_revalidates_join(db, tmp_path):
    inspector, _, _, _ = await configured(db, tmp_path, static=False)
    original = inspector.runtime_snapshot

    async def read(lease, healthy):
        result = await original(lease, healthy)
        async with db.engine.begin() as conn:
            await conn.execute(update(EnrolledProject).values(enabled=False))
        return result

    inspector.runtime_snapshot = read
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "not-observed"
    assert result.rows[0].bindings[0].state == "stale"


@pytest.mark.parametrize(
    "fault", ["missing", "exception", "stale", "future", "lease", "hash", "unhealthy", "expired"]
)
async def test_unavailable_diagnostics_never_changes_native_or_claims_strict(db, tmp_path, fault):
    inspector, _, _, snapshot = await configured(db, tmp_path)

    async def read(lease, healthy):
        if fault == "exception":
            raise ValueError("PRIVATE_RUNTIME_SECRET")
        if fault == "expired":
            async with db.engine.begin() as conn:
                await conn.execute(update(WorkerLease).values(expires_at=0.0))
        if fault == "stale":
            return RuntimeModeSnapshot.create(
                generated_at=time.time() - 6, lease_fingerprint=lease.lease_fingerprint, roots=()
            )
        if fault == "future":
            return RuntimeModeSnapshot.create(
                generated_at=time.time() + 6, lease_fingerprint=lease.lease_fingerprint, roots=()
            )
        if fault == "lease":
            return RuntimeModeSnapshot.create(
                generated_at=time.time(), lease_fingerprint="f" * 64, roots=()
            )
        if fault == "hash":
            return snapshot.model_copy(update={"content_sha256": "0" * 64})
        return snapshot

    inspector.runtime_snapshot = None if fault == "missing" else read
    if fault == "unhealthy":

        async def unhealthy():
            return False

        inspector.bridge_ready = unhealthy
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "unavailable"
    assert result.rows[0].runtime_mode.observed_at is None
    assert result.rows[0].state is ExecutionState.UNKNOWN
    assert "PRIVATE_RUNTIME_SECRET" not in result.model_dump_json()


async def test_lease_holder_or_fencing_changed_after_reader_is_not_old_lease(db, tmp_path):
    inspector, _, _, _ = await configured(db, tmp_path)
    original = inspector.runtime_snapshot

    async def read(lease, healthy):
        result = await original(lease, healthy)
        async with db.engine.begin() as conn:
            await conn.execute(update(WorkerLease).values(fencing=99))
        return result

    inspector.runtime_snapshot = read
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "unavailable" and not result.bridge_lease_current


async def test_final_lease_sql_wait_cannot_extend_snapshot_freshness(db, tmp_path, monkeypatch):
    inspector, _, _, _ = await configured(db, tmp_path)
    clock = [time.time()]
    monkeypatch.setattr(
        local_inspection, "time", SimpleNamespace(time=lambda: clock[0], monotonic=time.monotonic)
    )
    count = 0

    def delay(conn, cursor, statement, parameters, context, many):
        nonlocal count
        if statement.startswith("SELECT worker_leases.holder,"):
            count += 1
            if count == 2:
                clock[0] += 6

    event.listen(db.engine.sync_engine, "before_cursor_execute", delay)
    try:
        result = await inspector.query(InspectionQueryV2())
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", delay)
    assert count == 2 and result.rows[0].runtime_mode.mode == "unavailable"


@pytest.mark.parametrize("query_type", [InspectionQuery, InspectionQueryV2])
@pytest.mark.parametrize(
    "fault",
    [
        {"operation": "shell"},
        {"active": 1},
        {"project_id": "PRIVATE", "command": "session", "session_id": "ses_original"},
        {"version": "jt-oz-inspector-v9"},
    ],
)
def test_strict_v1_v2_query_matrix_rejects_unknown_mutations_filters_versions(query_type, fault):
    with pytest.raises(ValidationError):
        query_type.model_validate(fault)


@pytest.mark.parametrize(
    "fault",
    [
        {"mode": "idle", "reason": "strict-observation"},
        {"mode": "strict", "reason": "owned-check-recovery"},
        {"mode": "strict", "reason": "strict-observation", "scope_key": "a" * 64},
        {"mode": "strict", "reason": "strict-observation", "transition_at": 1.0},
        {
            "mode": "strict",
            "reason": "strict-observation",
            "transition_at": 2.0,
            "observed_at": 1.0,
        },
    ],
)
def test_projected_mode_is_allowlisted_without_authority_or_hash(fault):
    with pytest.raises(ValidationError):
        InspectionRuntimeMode.model_validate(fault)


@pytest.fixture
def socket_path():
    with tempfile.TemporaryDirectory(prefix="jtoz-v2-", dir="/tmp") as directory:
        yield Path(directory).resolve() / "observer.sock"


@pytest.mark.parametrize("v2", [False, True])
async def test_actual_unix_v1_v2_peer_filters_and_protocol_match(db, tmp_path, socket_path, v2):
    inspector, _, _, _ = await configured(db, tmp_path)
    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), inspector.query, peer_reader=lambda _: 111
    )
    await server.start()
    try:
        query = (InspectionQueryV2 if v2 else InspectionQuery)(
            project_id="project", backend_id="backend"
        )
        result = await inspect_query(
            socket_path, query, expected_uid=os.geteuid(), peer_reader=lambda _: os.geteuid()
        )
        assert result.version == query.version and len(result.rows) == 1
        if v2:
            assert result.rows[0].runtime_mode.mode == "readonly-owned-check"
        else:
            assert "runtime_mode" not in result.rows[0].model_dump()
        denied = await inspect_query(
            socket_path,
            (InspectionQueryV2 if v2 else InspectionQuery)(project_id="unknown"),
            expected_uid=os.geteuid(),
            peer_reader=lambda _: os.geteuid(),
        )
        assert denied.status == "error" and not denied.rows
    finally:
        await server.close()


@pytest.mark.parametrize("v2", [False, True])
async def test_client_rejects_opposite_protocol_version_without_silent_fallback(socket_path, v2):
    async def old_server(reader, writer):
        await reader.readline()
        response = (InspectionResponse if v2 else InspectionResponseV2)(
            status="ok", observed_at=time.time()
        )
        writer.write((response.model_dump_json() + "\n").encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(old_server, str(socket_path))
    socket_path.chmod(0o660)
    try:
        query = (InspectionQueryV2 if v2 else InspectionQuery)()
        response = await inspect_query(
            socket_path, query, expected_uid=os.geteuid(), peer_reader=lambda _: os.geteuid()
        )
        assert response.version == query.version and response.status == "error"
        assert [issue.code for issue in response.issues] == ["invalid_response"]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("v2", [False, True])
async def test_cli_flag_alone_selects_version_and_json_row_schema(
    db, tmp_path, monkeypatch, capsys, v2
):
    inspector, _, _, _ = await configured(db, tmp_path)
    seen = []

    async def query(path, selection, **kwargs):
        seen.append(selection)
        return await inspector.query(selection)

    monkeypatch.setattr(local_cli, "inspect_query", query)
    monkeypatch.setattr(local_cli, "expected_observer_uid", lambda: 123)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    local_cli.add_inspection_commands(parser, sub)
    args = parser.parse_args(["sessions", "--json"] + (["--runtime-modes"] if v2 else []))
    assert await local_cli.run_inspection(args) == 3  # original Native remains unknown/partial
    output = json.loads(capsys.readouterr().out)
    assert output["version"] == ("jt-oz-inspector-v2" if v2 else "jt-oz-inspector-v1")
    assert ("runtime_mode" in output["rows"][0]) is v2
    assert len(seen) == 1 and isinstance(seen[0], InspectionQueryV2 if v2 else InspectionQuery)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_tty_mode_warning_is_opt_in_and_does_not_claim_native_idle(db, tmp_path, locale):
    inspector, _, _, _ = await configured(db, tmp_path)
    legacy = local_cli.render(await inspector.query(InspectionQuery()), locale)
    projected = local_cli.render(await inspector.query(InspectionQueryV2()), locale)
    labels = local_cli.labels(locale)
    assert labels["mode_warning"] not in legacy
    assert labels["mode_warning"] in projected and "readonly-owned-check" in projected
    assert "[unknown]" in projected


async def test_active_filter_retains_owned_bridge_work_with_readonly_mode_without_native_running(
    db, tmp_path
):
    inspector, _, binding, _ = await configured(db, tmp_path)
    await DurableStore(db).enqueue(
        "queued", binding.id, 1, 7, {"operation": "prompt", "source": {"text": "PRIVATE_PAYLOAD"}}
    )
    result = await inspector.query(InspectionQueryV2(active=True))
    assert len(result.rows) == 1
    assert result.rows[0].state is ExecutionState.UNKNOWN
    assert result.rows[0].bindings[0].counts.queued == 1
    assert result.rows[0].runtime_mode.mode == "readonly-owned-check"
    assert "PRIVATE_PAYLOAD" not in result.model_dump_json()


async def test_different_project_for_same_root_is_ambiguous_not_guessed(db, tmp_path):
    inspector, backend, _, _ = await configured(db, tmp_path)
    # The catalog has no Bridge project discriminator. Even an exact static
    # pair cannot be chosen by matching whichever snapshot happens to exist.
    from types import MappingProxyType

    inspector.projects = MappingProxyType(
        {**inspector.projects, "second": ("backend", "native-project", REF.canonical_directory)}
    )
    inspector.runtime_scopes = {
        **inspector.runtime_scopes,
        "second": inspector.runtime_scopes["project"],
    }
    inspector.runtime_references = frozenset(
        {backend.ref, backend.ref.model_copy(update={"project_id": "second"})}
    )
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "not-observed"


async def test_final_dto_assembly_crossing_ttl_does_not_refresh_observation(
    db, tmp_path, monkeypatch
):
    inspector, _, _, _ = await configured(db, tmp_path)
    clock = [time.time()]
    monkeypatch.setattr(
        local_inspection, "time", SimpleNamespace(time=lambda: clock[0], monotonic=time.monotonic)
    )
    original = InspectionResponseV2.model_validate

    def delayed(*args, **kwargs):
        value = original(*args, **kwargs)
        clock[0] += 6.0
        return value

    monkeypatch.setattr(InspectionResponseV2, "model_validate", delayed)
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "unavailable"
    assert result.rows[0].runtime_mode.observed_at is None


@pytest.mark.parametrize("field", ["transition_at", "observed_at"])
@pytest.mark.parametrize("value", [True, 1, float("inf"), float("nan")])
def test_mode_times_reject_coercion_and_nonfinite_values(field, value):
    data = {
        "mode": "strict",
        "reason": "strict-observation",
        "transition_at": 1.0,
        "observed_at": 2.0,
        field: value,
    }
    with pytest.raises(ValidationError):
        InspectionRuntimeMode.model_validate(data)


@pytest.mark.parametrize("v2", [False, True])
async def test_v2_does_not_bypass_original_peer_uid_authorization(db, tmp_path, socket_path, v2):
    inspector, _, _, _ = await configured(db, tmp_path)
    calls = []

    async def handler(query):
        calls.append(query)
        return await inspector.query(query)

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda _: 999
    )
    await server.start()
    try:
        result = await inspect_query(
            socket_path,
            (InspectionQueryV2 if v2 else InspectionQuery)(),
            expected_uid=os.geteuid(),
            peer_reader=lambda _: os.geteuid(),
        )
        assert result.status == "error" and not result.rows and not calls
    finally:
        await server.close()


def test_v1_frozen_wire_field_inventory_is_unchanged_without_runtime_flag():
    assert tuple(InspectionQuery.model_fields) == (
        "version",
        "command",
        "backend_id",
        "project_id",
        "session_id",
        "association",
        "active",
        "limit",
        "cursor",
        "max_pages",
    )
    assert InspectionQuery().model_dump(mode="json") == {
        "version": "jt-oz-inspector-v1",
        "command": "sessions",
        "backend_id": None,
        "project_id": None,
        "session_id": None,
        "association": "all",
        "active": False,
        "limit": 10,
        "cursor": None,
        "max_pages": 10,
    }
    assert tuple(InspectionResponse.model_fields) == (
        "version",
        "status",
        "observed_at",
        "bridge_ready",
        "bridge_lease_current",
        "rows",
        "coverage",
        "issues",
        "observation_kind",
    )
    assert "runtime_mode" not in InspectionSession.model_fields


@pytest.mark.parametrize(
    "fault",
    [
        "moved-root",
        "prefix-collision",
        "dotdot",
        "noncanonical",
        "missing",
        "backend",
        "realm",
        "channel",
    ],
)
async def test_current_loaded_workspace_scope_is_required_even_for_old_exact_snapshot(
    db, tmp_path, fault
):
    inspector, backend, _, _ = await configured(db, tmp_path, static=False)
    root = REF.canonical_directory
    changes = {
        "backend_id": "backend",
        "workspace_root": root,
        "realm_id": "realm",
        "allowed_channels": frozenset({10}),
    }
    if fault == "moved-root":
        changes["workspace_root"] = "/different-root"
    elif fault == "prefix-collision":
        changes["workspace_root"] = root[:-1]
    elif fault == "dotdot":
        changes["workspace_root"] = root + "/../" + root.rsplit("/", 1)[-1]
    elif fault == "noncanonical":
        changes["workspace_root"] = root + "/"
    elif fault == "backend":
        changes["backend_id"] = "other"
    elif fault == "realm":
        changes["realm_id"] = "other"
    elif fault == "channel":
        changes["allowed_channels"] = frozenset({999})
    inspector.runtime_scopes = (
        {} if fault == "missing" else {"project": InspectionRuntimeScope(**changes)}
    )
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == (
        "unavailable" if fault in {"dotdot", "noncanonical", "missing"} else "not-observed"
    )


@pytest.mark.parametrize(
    "directory,expected",
    [
        ("/", True),
        ("/a", True),
        ("/a/b", True),
        ("//a", False),
        ("/a/../b", False),
        ("/a/./b", False),
        ("/a//b", False),
        ("relative", False),
    ],
)
def test_workspace_slash_boundary_does_not_turn_into_double_slash(directory, expected):
    assert (
        InspectionRuntimeScope("backend", "/", "realm", frozenset({10})).contains(
            "backend", directory
        )
        is expected
    )


async def test_shortened_current_lease_expiry_also_gates_final_dto_assembly(
    db, tmp_path, monkeypatch
):
    inspector, _, _, _ = await configured(db, tmp_path)
    clock = [time.time()]
    monkeypatch.setattr(
        local_inspection, "time", SimpleNamespace(time=lambda: clock[0], monotonic=time.monotonic)
    )
    original_reader = inspector.runtime_snapshot

    async def shorten(lease, healthy):
        snapshot = await original_reader(lease, healthy)
        async with db.engine.begin() as connection:
            await connection.execute(update(WorkerLease).values(expires_at=clock[0] + 0.01))
        return snapshot

    inspector.runtime_snapshot = shorten
    original_validate = InspectionResponseV2.model_validate

    def delayed(*args, **kwargs):
        value = original_validate(*args, **kwargs)
        clock[0] += 0.02
        return value

    monkeypatch.setattr(InspectionResponseV2, "model_validate", delayed)
    result = await inspector.query(InspectionQueryV2())
    assert result.rows[0].runtime_mode.mode == "unavailable"
    assert not result.bridge_lease_current
