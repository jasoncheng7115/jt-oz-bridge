"""Synthetic Native/peer identity with real encrypted Bridge DB and AF_UNIX I/O.

This does not cover peer checks against an installed Linux service or the
installed command line.
"""

import argparse
import asyncio
import json
import os
import struct
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import event, select, update
from sqlalchemy.exc import DBAPIError

from jt_oz_bridge import cli, local_cli
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.inspection import (
    InspectionQuery,
    InspectionResponse,
    InspectionSession,
)
from jt_oz_bridge.services import inspection_socket
from jt_oz_bridge.services.inspection_socket import InspectionSocketServer, inspect_query
from jt_oz_bridge.services.local_inspection import LocalSessionInspector
from jt_oz_bridge.storage.control_models import Binding, EnrolledProject
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import WorkerLease
from tests.support import REF, SyntheticControl, service


@pytest.fixture
def socket_path():
    with tempfile.TemporaryDirectory(prefix="jtoz-", dir="/tmp") as directory:
        yield Path(directory).resolve() / "observer.sock"


def row(identity="ses_original", state=ExecutionState.IDLE, **changes):
    return InspectionSession(
        backend_id="backend",
        backend_identity=REF.backend_identity,
        session_id=identity,
        native_project_id="native-project",
        directory=REF.canonical_directory,
        title="Original native session",
        state=state,
        state_reason="repeated_resources",
        observed_at=time.time(),
        owner_epoch=changes.pop("owner_epoch", "a" * 64),
        **changes,
    )


def response(**changes):
    return InspectionResponse(
        status="ok",
        observed_at=time.time(),
        bridge_ready=True,
        bridge_lease_current=True,
        rows=(row(),),
        **changes,
    )


class Backend:
    backend_id = "backend"
    contract_sha256 = SyntheticControl.contract_hash

    def __init__(self):
        self.pages = {None: ((row(),), None)}
        self.calls = []
        self.fail = False

    async def original_owner(self):
        if self.fail:
            raise ValueError("PRIVATE_NATIVE_ERROR")
        return SimpleNamespace(owner_epoch="a" * 64, pid=321, observed_at=time.time())

    async def page(self, limit, cursor, *, project=None):
        self.calls.append((limit, cursor, project))
        if self.fail:
            raise ValueError("PRIVATE_NATIVE_ERROR")
        return self.pages[cursor]

    async def state(self, value):
        return value

    async def detail(self, identity):
        return row(identity)


async def setup(db):
    control = SyntheticControl()
    control.ref = REF.model_copy(update={"upstream_session_id": "ses_original"})
    bindings, _, audience = await service(db, control=control)
    binding = await bindings.bind("realm", 7, 10, "Original work", control.ref)
    backend = Backend()
    await DurableStore(db).acquire_lease("observer-synthetic", ttl=120)

    async def ready():
        return True

    observer = LocalSessionInspector(
        db,
        {"backend": backend},
        {"project": ("backend", "native-project", REF.canonical_directory)},
        frozenset({("backend", REF.backend_identity, "ses_original", REF.canonical_directory)}),
        {"realm": "https://zulip.invalid"},
        ready,
    )
    return observer, backend, bindings, binding


async def test_safe_binding_counts_are_joined_without_reading_action_payloads_or_mutating(db):
    observer, backend, bindings, binding = await setup(db)
    store = DurableStore(db)
    await store.enqueue(
        "queued", binding.id, 1, 7, {"operation": "prompt", "source": {"text": "PRIVATE_PROMPT"}}
    )
    await store.queue_delivery("pending", binding.id, 1, {"content": "PRIVATE_OUTPUT"})
    queries = []

    def capture(conn, cursor, statement, parameters, context, many):
        queries.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", capture)
    try:
        result = await observer.query(InspectionQuery())
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", capture)
    assert result.status == "ok" and result.rows[0].bound
    mapped = result.rows[0].bindings[0]
    assert (
        mapped.topic == binding.topic
        and mapped.counts.queued == mapped.counts.pending_delivery == 1
    )
    assert mapped.state == "active_record" and not mapped.access_verified
    assert result.rows[0].execution_registration == "enrolled"
    assert "PRIVATE_" not in result.model_dump_json()
    assert all("actions.payload" not in q and "deliveries.payload" not in q for q in queries)
    assert not any(q.lstrip().upper().startswith(("UPDATE", "DELETE", "INSERT")) for q in queries)


async def test_binding_record_with_different_native_contract_is_stale_not_bound(db):
    from jt_oz_bridge.storage.control_models import EnrolledBackend

    observer, backend, bindings, binding = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(EnrolledBackend).values(contract_hash="f" * 64))
    result = await observer.query(InspectionQuery())
    assert result.status == "ok" and result.rows[0].binding_coverage == "complete"
    assert not result.rows[0].bound and result.rows[0].bindings[0].state == "stale"
    filtered = await observer.query(InspectionQuery(association="bound"))
    assert filtered.status == "ok" and not filtered.rows


@pytest.mark.parametrize(
    "kind", ["creating", "inactive", "stale", "foreign-instance", "foreign-directory"]
)
async def test_association_states_and_identity_do_not_leak_between_sessions(db, kind):
    observer, backend, bindings, binding = await setup(db)
    async with db.sessions.begin() as session:
        values = (
            {"state": "creating"}
            if kind == "creating"
            else {"state": "inactive"}
            if kind == "inactive"
            else {"backend_identity": "other"}
            if kind == "foreign-instance"
            else {"canonical_directory": "/other"}
            if kind == "foreign-directory"
            else {}
        )
        if values:
            await session.execute(update(Binding).values(**values))
        else:
            await session.execute(update(EnrolledProject).values(enabled=False))
    result = await observer.query(InspectionQuery())
    assert not result.rows[0].bound
    if kind in {"foreign-instance", "foreign-directory"}:
        assert not result.rows[0].bindings
    else:
        assert result.rows[0].bindings[0].state == kind


async def test_filters_scan_past_empty_match_pages_without_losing_any_page_matches(db):
    observer, backend, bindings, binding = await setup(db)
    backend.pages = {
        None: ((row("ses_idle"),), "next"),
        "next": (
            (row("ses_run", ExecutionState.RUNNING), row("ses_wait", ExecutionState.WAITING_INPUT)),
            "later",
        ),
    }
    result = await observer.query(InspectionQuery(active=True, limit=2))
    assert [r.session_id for r in result.rows] == ["ses_run", "ses_wait"]
    assert result.coverage[0].next_cursor == "later" and result.coverage[0].reason == "page"
    assert backend.calls == [(2, None, None), (2, "next", None)]
    assert not any(r.execution_registration == "enrolled" for r in result.rows)


async def test_empty_scan_capacity_and_unknown_states_are_partial_not_false_empty_success(db):
    observer, backend, bindings, binding = await setup(db)
    backend.pages = {
        None: ((row(state=ExecutionState.UNKNOWN),), "next"),
        "next": ((row("ses_second"),), "more"),
    }
    result = await observer.query(InspectionQuery(active=True, max_pages=2))
    assert result.status == "partial" and not result.rows
    assert result.coverage[0].reason == "scan_limit" and result.coverage[0].next_cursor == "more"
    assert {x.code for x in result.issues} == {"partial_state", "capacity"}


@pytest.mark.parametrize("fault", ["native", "bridge-ready", "lease", "project"])
async def test_unavailable_components_do_not_disguise_disconnection_as_idle(db, fault):
    observer, backend, bindings, binding = await setup(db)
    query = InspectionQuery()
    if fault == "native":
        backend.fail = True
    elif fault == "bridge-ready":

        async def down():
            return False

        observer.bridge_ready = down
    elif fault == "lease":
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=0))
    else:
        query = InspectionQuery(project_id="not-enrolled")
    result = await observer.query(query)
    assert result.status != "ok"
    assert "PRIVATE_" not in result.model_dump_json()
    if fault == "native":
        assert not result.rows and not result.coverage[0].complete
    if fault == "project":
        assert result.status == "error" and backend.calls == []


async def test_actual_socket_roundtrip_uses_peer_scope_and_preserves_literal_json(socket_path):
    calls = []

    async def handler(query):
        calls.append(query)
        return response()

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda connection: 111
    )
    await server.start()
    try:
        result = await inspect_query(
            socket_path,
            InspectionQuery(),
            expected_uid=os.geteuid(),
            peer_reader=lambda connection: os.geteuid(),
        )
        assert (
            result.status == "ok"
            and len(calls) == 1
            and result.rows[0].session_id == "ses_original"
        )
        assert socket_path.stat().st_mode & 0o777 == 0o660
    finally:
        await server.close()
    assert not socket_path.exists() and not server.tasks


async def test_unauthorized_socket_peer_never_reaches_observer_handler(socket_path):
    async def forbidden(query):
        raise AssertionError("must not query")

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), forbidden, peer_reader=lambda connection: 222
    )
    await server.start()
    try:
        result = await inspect_query(
            socket_path,
            InspectionQuery(),
            expected_uid=os.geteuid(),
            peer_reader=lambda connection: os.geteuid(),
        )
        assert result.status == "error" and result.issues[0].code == "unauthorized"
    finally:
        await server.close()


@pytest.mark.parametrize(
    "payload",
    [
        b'{"command":"sessions","command":"doctor"}\n',
        b'{"command":"shell","secret":"PRIVATE_TOKEN"}\n',
        b"x" * 17000 + b"\n",
    ],
)
async def test_malformed_requests_are_bounded_and_not_echoed(socket_path, payload):
    async def forbidden(query):
        raise AssertionError("must not query")

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), forbidden, peer_reader=lambda connection: 111
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        writer.write(payload)
        await writer.drain()
        data = await reader.readline()
        writer.close()
        await writer.wait_closed()
        assert b"PRIVATE_TOKEN" not in data and json.loads(data)["status"] == "error"
    finally:
        await server.close()


async def test_existing_regular_file_is_never_unlinked_or_replaced(socket_path):
    socket_path.write_text("original")

    async def handler(query):
        return response()

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda connection: 111
    )
    with pytest.raises(ValueError):
        await server.start()
    assert socket_path.read_text() == "original"


@pytest.mark.parametrize("fault", ["command", "session-path", "cursor", "boolean", "oversize"])
def test_protocol_rejects_mutations_arbitrary_paths_and_invalid_filters(fault):
    data = (
        {"command": "shell"}
        if fault == "command"
        else {"command": "session", "session_id": "../../etc/passwd"}
        if fault == "session-path"
        else {"cursor": "x"}
        if fault == "cursor"
        else {"active": 1}
        if fault == "boolean"
        else {"limit": 100000}
    )
    with pytest.raises(ValidationError):
        InspectionQuery.model_validate(data)


@pytest.mark.parametrize(
    "value", ["title\x1b]52;c;PRIVATE\x07", "one\ntwo\rthree", "rtl\u202eEND", "term\x9b31m"]
)
def test_terminal_rendering_cannot_execute_control_or_bidi_sequences(value):
    native = row().model_copy(update={"title": value, "directory": "/opt/" + value})
    result = response().model_copy(update={"rows": (native,)})
    rendered = local_cli.render(result, "zh-TW")
    assert (
        "\x1b" not in rendered
        and "\x07" not in rendered
        and "\r" not in rendered
        and "\u202e" not in rendered
        and "\x9b" not in rendered
    )
    assert "\\u" in rendered


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["sessions", "--bound", "--json"],
        ["session", "ses_original", "--locale", "zh-TW"],
        ["doctor", "--json"],
    ],
)
def test_cli_client_does_not_load_bridge_configuration_keys_or_start_runtime(
    monkeypatch, capsys, arguments
):
    def forbidden(*args):
        raise AssertionError("client must not load Bridge config")

    monkeypatch.setattr(cli, "load_settings", forbidden)
    monkeypatch.setattr(local_cli, "expected_observer_uid", lambda: 123)
    seen = []

    async def query(path, selection, **kwargs):
        seen.append(selection)
        return response()

    monkeypatch.setattr(local_cli, "inspect_query", query)
    monkeypatch.setattr("sys.argv", ["jt-oz-bridge"] + arguments)
    with pytest.raises(SystemExit) as exit:
        cli.main()
    assert exit.value.code == 0 and len(seen) == 1
    output = capsys.readouterr().out
    assert output
    if "--json" in arguments:
        assert json.loads(output)["version"] == "jt-oz-inspector-v1"


async def test_watch_json_is_bounded_ndjson_with_no_terminal_escape_and_partial_exit(
    monkeypatch, capsys
):
    monkeypatch.setattr(local_cli, "expected_observer_uid", lambda: 123)

    async def query(*args, **kwargs):
        return response().model_copy(update={"status": "partial"})

    async def sleep(seconds):
        assert seconds == 2

    monkeypatch.setattr(local_cli, "inspect_query", query)
    monkeypatch.setattr(local_cli.asyncio, "sleep", sleep)
    args = argparse.Namespace(
        command="sessions",
        watch=2,
        count=2,
        inspection_socket=Path("/run/test.sock"),
        inspection_json=True,
        inspection_locale="en",
    )
    assert await local_cli.run_inspection(args) == 3
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and all(json.loads(line)["status"] == "partial" for line in lines)


def test_linux_peer_uid_decodes_kernel_credentials_without_using_caller_supplied_uid(monkeypatch):
    monkeypatch.setattr(inspection_socket.socket, "SO_PEERCRED", 17, raising=False)
    fake = SimpleNamespace(getsockopt=lambda *args: struct.pack("3i", 100, 123, 456))
    assert inspection_socket.peer_uid(fake) == 123


async def test_observer_database_is_physically_read_only_without_payload_encryption_key(db):
    from sqlalchemy import text

    from jt_oz_bridge.services.inspection_runtime import ReadOnlyInspectionDatabase

    await setup(db)
    observer_db = ReadOnlyInspectionDatabase(str(db.engine.url))
    try:
        assert observer_db.cipher is None and await observer_db.schema_ready()
        async with observer_db.sessions() as session:
            assert await session.scalar(select(Binding.session_id)) == "ses_original"
        with pytest.raises(DBAPIError, match="readonly"):
            async with observer_db.engine.begin() as connection:
                await connection.execute(text("UPDATE worker_leases SET fencing=999"))
        async with db.sessions() as session:
            assert (await session.get(WorkerLease, "consumer")).fencing != 999
    finally:
        await observer_db.close()


@pytest.mark.parametrize(
    "fault", ["uid-bool", "uid-negative", "socket-path", "operations", "contract", "semantics"]
)
def test_operator_policy_and_observation_evidence_cannot_widen_to_mutations(fault):
    from jt_oz_bridge.adapters.opencode.inspection import INSPECTION_READS
    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
    from jt_oz_bridge.services.inspection_runtime import (
        INSPECTION_SEMANTICS,
        InspectionQualification,
        LocalObserverPolicy,
    )

    policy = {
        "format": "local-session-observer-v1",
        "socket": "/run/jt-oz-observer/observer.sock",
        "allowed_uids": [0, 1000],
        "runtime_enrollment_sha256": "a" * 64,
        "backend_evidence": {"backend": {"path": "/etc/bridge/evidence.json", "sha256": "b" * 64}},
        "operator_review": "local-linux-peer-scope-reviewed-no-public-listener",
    }
    evidence = {
        "format": "native-local-inspection-read-observation-v1",
        "passed": True,
        "backend_id": "backend",
        "backend_identity": "original",
        "contract_sha256": INSTALLED_SCHEMA,
        "upstream_version": "2.0.32",
        "read_scope": "backend-catalog-and-observed-session-state",
        "semantics_sha256": INSPECTION_SEMANTICS,
        "verified_operations": list(INSPECTION_READS),
        "observed_owner_epoch": "c" * 64,
        "operator_review": "read-only-local-observation-scope-reviewed-no-execution-promotion",
    }
    assert LocalObserverPolicy.model_validate(policy) and InspectionQualification.model_validate(
        evidence
    )
    if fault == "uid-bool":
        policy["allowed_uids"] = [True]
    elif fault == "uid-negative":
        policy["allowed_uids"] = [-1]
    elif fault == "socket-path":
        policy["socket"] = "/etc/sudoers"
    elif fault == "operations":
        evidence["verified_operations"].append("session.prompt")
    elif fault == "contract":
        evidence["contract_sha256"] = "f" * 64
    else:
        evidence["semantics_sha256"] = "f" * 64
    with pytest.raises(ValidationError):
        if fault in {"uid-bool", "uid-negative", "socket-path"}:
            LocalObserverPolicy.model_validate(policy)
        else:
            InspectionQualification.model_validate(evidence)


async def test_socket_permission_setup_failure_cleans_owned_socket_and_listener(
    socket_path, monkeypatch
):
    async def handler(query):
        return response()

    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda connection: 111
    )

    def failed(*args):
        raise OSError("synthetic permission failure")

    monkeypatch.setattr(inspection_socket.os, "chown", failed)
    with pytest.raises(OSError):
        await server.start()
    assert server.server is None and not socket_path.exists()


async def test_doctor_reports_fresh_original_owner_separately_from_native_work_state(db):
    observer, backend, bindings, binding = await setup(db)
    result = await observer.query(InspectionQuery(command="doctor"))
    assert result.status == "ok" and not result.rows
    assert result.coverage[0].owner_epoch == "a" * 64 and result.coverage[0].native_pid == 321
    assert backend.calls == []


async def test_multi_backend_failure_keeps_other_results_and_never_returns_success(db):
    observer, backend, bindings, binding = await setup(db)
    backend.fail = True
    other = Backend()
    other.backend_id = "other"
    other.pages = {
        None: (
            (
                row("ses_other").model_copy(
                    update={"backend_id": "other", "backend_identity": "other-instance"}
                ),
            ),
            None,
        )
    }
    observer.backends = {"backend": backend, "other": other}
    result = await observer.query(InspectionQuery())
    assert result.status == "partial" and [r.session_id for r in result.rows] == ["ses_other"]
    assert [c.complete for c in result.coverage] == [False, True]
    assert not result.rows[0].bound and result.rows[0].execution_registration == "catalog_only"


async def test_live_socket_is_not_replaced_by_second_observer(socket_path):
    async def handler(query):
        return response()

    one = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda connection: 111
    )
    two = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), handler, peer_reader=lambda connection: 111
    )
    await one.start()
    inode = socket_path.stat().st_ino
    try:
        with pytest.raises(ValueError, match="already_listening"):
            await two.start()
        assert socket_path.stat().st_ino == inode
    finally:
        await two.close()
        await one.close()


async def test_peer_acl_only_grants_explicit_uids_socket_access_without_group_membership(
    monkeypatch,
):
    from jt_oz_bridge.services.inspection_runtime import grant_peer_access

    calls = []

    async def wait():
        return 0

    async def spawn(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(wait=wait)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    await grant_peer_access(
        Path("/run/jt-oz-observer/observer.sock"), frozenset({0, os.geteuid(), 1000, 1234}), "rw-"
    )
    assert all(
        args[0] == "/usr/bin/setfacl"
        and args[1:2] == ("-m",)
        and args[-2:] == ("--", "/run/jt-oz-observer/observer.sock")
        for args in calls
    )
    assert {args[2] for args in calls} == {f"u:{uid}:rw-" for uid in {1000, 1234} - {os.geteuid()}}
    with pytest.raises(ValueError):
        await grant_peer_access(Path("/run/test"), frozenset({1000}), "rwx")


@pytest.mark.parametrize(
    "watch,count", [(0, None), (float("nan"), None), (float("inf"), None), (None, 2)]
)
async def test_watch_invalid_bounds_are_rejected_before_any_local_service_call(watch, count):
    args = argparse.Namespace(command="sessions", watch=watch, count=count)
    with pytest.raises(ValueError):
        await local_cli.run_inspection(args)


async def test_real_native_adapter_database_join_and_socket_work_together_without_mutations(
    db, socket_path
):
    from jt_oz_bridge.domain.control import SessionSnapshot
    from jt_oz_bridge.services.bindings import BindingService
    from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
    from jt_oz_bridge.storage.models import Grant
    from tests.contract.test_leaf_resources import REF as native_ref
    from tests.contract.test_leaf_resources import finish
    from tests.contract.test_local_inspection_native import setup as native_setup
    from tests.support import SyntheticAudience

    native, proofs, transport, data, pages, calls, writes = await native_setup()

    async def snapshot(ref):
        return SessionSnapshot(
            reference=ref,
            title="Native integration",
            state=ExecutionState.IDLE,
            cursor="synthetic",
            reconciled=True,
        )

    control = SimpleNamespace(contract_for=lambda ref: transport.profile.sha256, snapshot=snapshot)
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=native_ref.backend_id,
                identity=native_ref.backend_identity,
                contract_hash=transport.profile.sha256,
                enabled=True,
                verified=True,
                version="synthetic",
            )
        )
        session.add(
            EnrolledProject(
                id=native_ref.project_id,
                backend_id=native_ref.backend_id,
                realm_id="realm",
                canonical_directory=native_ref.canonical_directory,
                enabled=True,
            )
        )
        for user in (7, 8):
            session.add(
                Grant(
                    realm_id="realm",
                    user_id=user,
                    project_id=native_ref.project_id,
                    role="operator",
                )
            )
    bindings = BindingService(db, control, SyntheticAudience())
    binding = await bindings.bind("realm", 7, 10, "One original Root", native_ref)
    await DurableStore(db).acquire_lease("socket-native-fixture", ttl=120)
    await DurableStore(db).enqueue(
        "queued-private",
        binding.id,
        1,
        7,
        {"operation": "prompt", "source": {"text": "DO_NOT_EXPOSE_PRIVATE_PROMPT"}},
    )

    async def ready():
        return True

    observer = LocalSessionInspector(
        db,
        {native_ref.backend_id: native},
        {native_ref.project_id: (native_ref.backend_id, "global", native_ref.canonical_directory)},
        frozenset(
            {
                (
                    native_ref.backend_id,
                    native_ref.backend_identity,
                    native_ref.upstream_session_id,
                    native_ref.canonical_directory,
                )
            }
        ),
        {"realm": "https://zulip.invalid"},
        ready,
    )
    server = InspectionSocketServer(
        socket_path, os.getegid(), frozenset({111}), observer.query, peer_reader=lambda sock: 111
    )
    await server.start()
    try:
        result = await inspect_query(
            socket_path,
            InspectionQuery(),
            expected_uid=os.geteuid(),
            peer_reader=lambda sock: os.geteuid(),
        )
        assert result.status == "ok" and len(result.rows) == 1
        observed = result.rows[0]
        assert (
            observed.session_id == native_ref.upstream_session_id
            and observed.state == ExecutionState.IDLE
        )
        assert observed.bound and observed.bindings[0].topic == "One original Root"
        assert observed.bindings[0].counts.queued == 1 and observed.owner_epoch == "a" * 64
        assert "DO_NOT_EXPOSE_PRIVATE_PROMPT" not in result.model_dump_json() and not writes
        assert "One original Root" in local_cli.render(result, "zh-TW")
    finally:
        await server.close()
        await finish(proofs, transport)


async def recorded_work(db, binding, state):
    from jt_oz_bridge.storage.models import Action

    action_id = await DurableStore(db).enqueue(
        "inspection-recorded-check",
        binding.id,
        binding.revision,
        7,
        {"operation": "check.run", "source": {"text": "PRIVATE_CHECK_NOT_FOR_OBSERVER"}},
    )
    async with db.sessions.begin() as session:
        await session.execute(update(Action).where(Action.id == action_id).values(state=state))
    return action_id


@pytest.mark.parametrize(
    "state", ["queued", "held", "dispatching", "admitted", "running", "ambiguous"]
)
async def test_active_filter_keeps_recorded_bridge_work_without_inventing_native_state(db, state):
    observer, backend, _bindings, binding = await setup(db)
    await recorded_work(db, binding, state)
    backend.pages = {
        None: (
            (
                row(state=ExecutionState.UNKNOWN).model_copy(
                    update={"state_reason": "resource_unavailable"}
                ),
            ),
            None,
        )
    }
    queries = []

    def capture(conn, cursor, statement, parameters, context, many):
        queries.append(statement)

    event.listen(db.engine.sync_engine, "before_cursor_execute", capture)
    try:
        result = await observer.query(InspectionQuery(active=True))
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", capture)
    assert result.status == "partial" and result.bridge_ready and result.bridge_lease_current
    assert len(result.rows) == 1 and result.rows[0].session_id == "ses_original"
    observed = result.rows[0]
    assert (
        observed.state == ExecutionState.UNKNOWN and observed.state_reason == "resource_unavailable"
    )
    key = state if state in {"queued", "held", "ambiguous"} else "active"
    assert getattr(observed.bindings[0].counts, key) == 1
    assert {issue.code for issue in result.issues} == {"partial_state"}
    encoded = json.loads(result.model_dump_json())
    assert encoded["version"] == "jt-oz-inspector-v1"
    assert encoded["rows"][0]["state"] == "unknown"
    assert encoded["rows"][0]["bindings"][0]["counts"][key] == 1
    assert "PRIVATE_CHECK_NOT_FOR_OBSERVER" not in result.model_dump_json()
    assert all(
        "actions.payload" not in query and "actions.admission" not in query for query in queries
    )
    assert not any(
        query.lstrip().upper().startswith(("UPDATE", "DELETE", "INSERT")) for query in queries
    )
    for locale in ("en", "zh-TW"):
        for details in (False, True):
            rendered = local_cli.render(result, locale, details=details)
            assert (
                "Native execution is unverified" if locale == "en" else "Native 執行狀態待確認"
            ) in rendered
            assert (
                "do not prove that Native is executing"
                if locale == "en"
                else "不等於 Native 正在執行"
            ) in rendered
            assert (
                "not session mutation authority"
                if locale == "en"
                else "不代表此 Root 已取得派送授權"
            ) in rendered


@pytest.mark.parametrize("state", ["completed", "failed", "rejected", "cancelled"])
async def test_active_filter_does_not_promote_terminal_bridge_records_to_work(db, state):
    observer, backend, _bindings, binding = await setup(db)
    await recorded_work(db, binding, state)
    backend.pages = {None: ((row(state=ExecutionState.UNKNOWN),), None)}
    result = await observer.query(InspectionQuery(active=True))
    assert result.status == "partial" and not result.rows
    assert {issue.code for issue in result.issues} == {"partial_state"}


@pytest.mark.parametrize("field", ["backend_identity", "canonical_directory", "session_id"])
async def test_active_filter_never_borrows_another_original_roots_recorded_work(db, field):
    observer, backend, _bindings, binding = await setup(db)
    await recorded_work(db, binding, "running")
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(**{field: "foreign-root"}))
    backend.pages = {None: ((row(state=ExecutionState.UNKNOWN),), None)}
    result = await observer.query(InspectionQuery(active=True))
    assert result.status == "partial" and not result.rows


async def test_active_filter_can_show_bridge_queue_while_native_remains_positive_idle(db):
    observer, _backend, _bindings, binding = await setup(db)
    await recorded_work(db, binding, "queued")
    result = await observer.query(InspectionQuery(active=True))
    assert result.status == "ok" and len(result.rows) == 1
    assert result.rows[0].state == ExecutionState.IDLE
    rendered = local_cli.render(result, "en")
    assert "[idle]" in rendered and '"queued": 1' in rendered
    assert "do not prove that Native is executing" in rendered
    assert "Native execution is unverified" not in rendered


async def test_bridge_recorded_match_retains_original_native_page_and_next_cursor(db):
    observer, backend, _bindings, binding = await setup(db)
    await recorded_work(db, binding, "ambiguous")
    backend.pages = {
        None: ((row(state=ExecutionState.UNKNOWN),), "original-next-cursor"),
        "original-next-cursor": ((row("ses_other", ExecutionState.RUNNING),), None),
    }
    result = await observer.query(InspectionQuery(active=True, limit=1))
    assert [item.session_id for item in result.rows] == ["ses_original"]
    assert result.status == "partial"
    assert result.coverage[0].next_cursor == "original-next-cursor"
    assert result.coverage[0].reason == "page" and not result.coverage[0].complete
    assert backend.calls == [(1, None, None)]
