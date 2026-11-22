"""Local CLI cases through the `jt-oz-bridge` entry point, real AF_UNIX observer and own DB.

Every test parses actual CLI arguments (`cli.main`), crosses the observer socket
(Linux SO_PEERCRED; synthetic peers elsewhere) into `LocalSessionInspector` over an
isolated Bridge database. Native peers are synthetic rows or the installed-schema
fixture. This is automated synthetic coverage of the local CLI, not installed
acceptance, a real Human binding or a check of a real installation.
"""

import argparse
import asyncio
import copy
import functools
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import update

from jt_oz_bridge import cli, local_cli
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.inspection import (
    InspectionBinding,
    InspectionCounts,
    InspectionCoverage,
    InspectionResponse,
    InspectionSession,
)
from jt_oz_bridge.services import inspection_socket
from jt_oz_bridge.services.inspection_socket import InspectionSocketServer, inspect_query
from jt_oz_bridge.services.local_inspection import LocalSessionInspector
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Action, Delivery, WorkerLease
from tests.integration.test_local_inspection import Backend, row
from tests.support import REF, SyntheticControl, service

PEERS = inspection_socket.peer_uid if sys.platform == "linux" else lambda connection: os.geteuid()
FORBIDDEN = ("\x1b", "\x07", "\x9b", "\r", "\x00", "\u202e", "\u2028", "\u2066")
ORIGIN = "https://zulip.invalid"


@pytest.fixture
def socket_path():
    with tempfile.TemporaryDirectory(prefix="jtoz-lcli-", dir="/tmp") as directory:
        yield Path(directory).resolve() / "observer.sock"


@pytest.fixture
def run(monkeypatch, capsys, socket_path):
    """Invoke the installed console entry point in a worker thread.

    The CLI owns its own event loop (`asyncio.run`) while this test loop serves
    the observer socket. Bridge configuration and secret resolution must never run.
    """

    def forbidden(*args, **kwargs):
        raise AssertionError("CLI must not read service configuration or credentials")

    monkeypatch.setattr(cli, "load_settings", forbidden)
    monkeypatch.setattr(cli, "resolve_secret", forbidden)
    monkeypatch.setattr(local_cli, "expected_observer_uid", os.geteuid)
    monkeypatch.setattr(
        local_cli, "inspect_query", functools.partial(inspect_query, peer_reader=PEERS)
    )

    async def invoke(*arguments, socket=None):
        monkeypatch.setattr(
            "sys.argv", ["jt-oz-bridge", "--socket", str(socket or socket_path), *arguments]
        )

        def main():
            try:
                cli.main()
            except SystemExit as exit:
                return exit.code
            raise AssertionError("inspection commands always exit explicitly")

        code = await asyncio.to_thread(main)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return invoke


class Observer:
    """One running socket server around a real observer handler."""

    def __init__(self, path, handler, allowed=None):
        self.server = InspectionSocketServer(
            path,
            os.getegid(),
            allowed or frozenset({os.geteuid()}),
            handler,
            peer_reader=PEERS,
        )

    async def __aenter__(self):
        await self.server.start()
        return self

    async def __aexit__(self, *exc):
        await self.server.close()
        assert not self.server.tasks


class Scenario(SimpleNamespace):
    pass


async def scenario(db, roots=(("ses_original", 10, "Original work", 501),)):
    """Enrolled project, original Roots bound to their own topics and a current lease."""
    control = SyntheticControl()
    bindings, _, _ = await service(db, control=control)
    bound = {}
    for identity, channel, topic, anchor in roots:
        control.ref = REF.model_copy(update={"upstream_session_id": identity})
        bound[identity] = await bindings.bind(
            "realm", 7, channel, topic, control.ref, anchor_message_id=anchor
        )
    backend = Backend()
    await DurableStore(db).acquire_lease("observer-synthetic", ttl=120)
    health = SimpleNamespace(ready=True)

    async def ready():
        return health.ready

    observer = LocalSessionInspector(
        db,
        {"backend": backend},
        {"project": ("backend", "native-project", REF.canonical_directory)},
        frozenset(
            ("backend", REF.backend_identity, identity, REF.canonical_directory)
            for identity in bound
        ),
        {"realm": ORIGIN},
        ready,
    )
    return Scenario(
        observer=observer, backend=backend, bindings=bindings, bound=bound, health=health
    )


def app_row(identity, state=ExecutionState.IDLE, **changes):
    """A session created in the App/TUI outside the enrolled Bridge project."""
    return row(identity, state).model_copy(
        update={
            "native_project_id": "app-native-project",
            "directory": "/opt/app-project",
            "title": "Started in the TUI",
        }
        | changes
    )


def blocks(text):
    """Split rendered text into per-session blocks keyed by the exact session ID."""
    result = {}
    for block in text.split("\n\n")[1:]:
        result[block.split("  ", 1)[0]] = block
    return result


def assert_terminal_safe(text):
    assert not any(character in text for character in FORBIDDEN), repr(text)


# Bound sessions -----------------------------------------------------------


async def test_bound_rows_report_exact_native_ids_and_their_own_channel_topic(db, run, socket_path):
    s = await scenario(
        db,
        (
            ("ses_original", 10, "Original work", 501),
            ("ses_second", 11, "Second work", 777),
            ("ses_missing_from_native", 12, "Gone work", 900),
        ),
    )
    s.backend.pages = {None: ((row("ses_original"), row("ses_second"), app_row("ses_app")), None)}
    async with Observer(socket_path, s.observer.query):
        code, out, err = await run("--json", "sessions", "--bound")
        text_code, text, _ = await run("--locale", "zh-TW", "sessions", "--bound")
        detail_code, detail, _ = await run("session", "ses_second")
    assert (code, text_code, detail_code) == (0, 0, 0) and not err
    data = json.loads(out)
    assert data["status"] == "ok" and data["coverage"][0]["complete"] is True
    rows = {item["session_id"]: item for item in data["rows"]}
    # Only actual Native catalog IDs; a Binding record never fabricates a row.
    assert list(rows) == ["ses_original", "ses_second"]
    for identity, channel, topic, anchor in (
        ("ses_original", 10, "Original work", 501),
        ("ses_second", 11, "Second work", 777),
    ):
        (mapped,) = rows[identity]["bindings"]
        binding = s.bound[identity]
        assert mapped == {
            "binding_id": binding.id,
            "project_id": "project",
            "realm_id": "realm",
            "channel_id": channel,
            "topic": topic,
            "revision": binding.revision,
            "state": "active_record",
            "paused": False,
            "access_verified": False,
            "conversation_url": f"{ORIGIN}/#narrow/channel/{channel}/near/{anchor}",
            "counts": InspectionCounts().model_dump(),
        }
        assert rows[identity]["backend_identity"] == REF.backend_identity
        assert rows[identity]["directory"] == REF.canonical_directory
        assert rows[identity]["execution_registration"] == "enrolled"
    rendered = blocks(text)
    assert set(rendered) == {"ses_original", "ses_second"}
    assert "realm / #10 / Original work [active_record]" in rendered["ses_original"]
    assert "Second work" not in rendered["ses_original"]
    assert "realm / #11 / Second work [active_record]" in rendered["ses_second"]
    assert "Original work" not in rendered["ses_second"]
    assert "[bound-record]" in rendered["ses_second"]
    assert f"{ORIGIN}/#narrow/channel/11/near/777" in detail
    assert f"revision={s.bound['ses_second'].revision}" in detail
    assert "live access not verified" in detail and "Original work" not in detail


# Unbound sessions ---------------------------------------------------------


async def test_unbound_app_sessions_are_listed_with_complete_and_partial_coverage(
    db, run, socket_path
):
    s = await scenario(db)
    s.backend.pages = {
        None: ((row("ses_original"), app_row("ses_app_one")), "opaque-more"),
        "opaque-more": ((app_row("ses_tui_two", ExecutionState.RUNNING),), None),
    }
    async with Observer(socket_path, s.observer.query):
        first_code, first, _ = await run("--json", "sessions", "--unbound")
        second_code, second, _ = await run(
            "--json", "sessions", "--unbound", "--backend", "backend", "--cursor", "opaque-more"
        )
        text_code, text, _ = await run("sessions", "--unbound")
    assert (first_code, second_code, text_code) == (0, 0, 0)
    first, second = json.loads(first), json.loads(second)
    assert [item["session_id"] for item in first["rows"]] == ["ses_app_one"]
    assert first["status"] == "ok" and first["coverage"][0] | {"owner_epoch": None} == {
        "backend_id": "backend",
        "scope": "backend_catalog",
        "owner_epoch": None,
        "native_pid": None,
        "complete": False,
        "scanned": 2,
        "next_cursor": "opaque-more",
        "reason": "page",
    }
    assert [item["session_id"] for item in second["rows"]] == ["ses_tui_two"]
    assert second["coverage"][0]["complete"] is True
    assert second["coverage"][0]["reason"] == "exhausted"
    for item in first["rows"] + second["rows"]:
        assert item["bindings"] == [] and item["binding_coverage"] == "complete"
        assert item["execution_registration"] == "catalog_only"
        assert item["directory"] == "/opt/app-project"
    assert "[unbound]" in blocks(text)["ses_app_one"]
    assert 'Next page: --backend backend --cursor "opaque-more"' in text
    assert "complete=False (page)" in text


async def test_unreadable_bridge_state_never_reports_sessions_as_unbound(db, run, socket_path):
    s = await scenario(db)
    s.backend.pages = {None: ((row("ses_original"), app_row("ses_app_one")), None)}
    original = s.observer.local_metadata

    async def unreadable(rows):
        if rows:
            raise OSError("synthetic bridge database outage")
        return await original(rows)

    s.observer.local_metadata = unreadable
    async with Observer(socket_path, s.observer.query):
        unbound_code, unbound, _ = await run("--json", "sessions", "--unbound")
        listing_code, listing, _ = await run("--json", "sessions")
        text_code, text, _ = await run("sessions")
    assert (unbound_code, listing_code, text_code) == (3, 3, 3)
    unbound, listing = json.loads(unbound), json.loads(listing)
    assert unbound["status"] == "partial" and not unbound["rows"]
    assert "bridge_unavailable" in {issue["code"] for issue in unbound["issues"]}
    assert [item["binding_coverage"] for item in listing["rows"]] == ["unavailable"] * 2
    assert all(not item["bindings"] for item in listing["rows"])
    assert "[unbound]" not in text and text.count("[association-unknown]") == 2


# Native and execution states ----------------------------------------------


async def native_observer(db):
    """Installed-schema Native fixture (real V2SessionInspection) with own-DB enrollment."""
    from tests.contract.test_leaf_resources import REF as native_ref
    from tests.contract.test_local_inspection_native import setup as native_setup

    native, proofs, transport, data, _pages, _calls, writes = await native_setup()
    from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject

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
    await DurableStore(db).acquire_lease("native-state-fixture", ttl=120)

    async def ready():
        return True

    observer = LocalSessionInspector(
        db,
        {native_ref.backend_id: native},
        {native_ref.project_id: (native_ref.backend_id, "global", native_ref.canonical_directory)},
        frozenset(),
        {"realm": ORIGIN},
        ready,
    )
    return observer, native_ref, proofs, transport, data, writes


def native_state(data, ref, kind):
    """The same resource shapes as the contract state matrix; never active absence."""
    from tests.contract.test_public_live_feed import REAL

    if kind in {"running", "waiting_permission", "waiting_input"}:
        data["session.active"]["data"][ref.upstream_session_id] = {"type": "running"}
    if kind in {"waiting_permission", "waiting_input"}:
        wanted = "permission.asked" if kind == "waiting_permission" else "form.created"
        event = next(item for item in REAL if item["type"] == wanted)
        raw = event["data"] if kind == "waiting_permission" else event["data"]["form"]
        listing = "session.permission.list" if kind == "waiting_permission" else "session.form.list"
        data[listing]["data"] = [copy.deepcopy(raw)]
    elif kind == "queued":
        data["session.inbox.list"]["data"] = [
            {
                "id": "msg_queued",
                "sessionID": ref.upstream_session_id,
                "type": "user",
                "payload": {"text": "PRIVATE_QUEUED_INPUT"},
                "delivery": "queue",
                "time": {"created": 4},
            }
        ]
    elif kind == "unknown":
        data["session.get"]["data"]["time"]["idle"] = 999  # Retained, not current, idle.


@pytest.mark.parametrize(
    "kind", ["idle", "running", "queued", "waiting_permission", "waiting_input", "unknown"]
)
async def test_native_resource_states_are_distinguished_by_text_json_and_active(
    db, run, socket_path, kind
):
    from tests.contract.test_leaf_resources import finish

    observer, ref, proofs, transport, data, writes = await native_observer(db)
    native_state(data, ref, kind)
    try:
        async with Observer(socket_path, observer.query):
            code, out, _ = await run("--json", "sessions")
            active_code, active, _ = await run("--json", "sessions", "--active")
            text_code, text, _ = await run("sessions")
            detail_code, detail, _ = await run("--json", "session", ref.upstream_session_id)
    finally:
        await finish(proofs, transport)
    listing, active, detail = json.loads(out), json.loads(active), json.loads(detail)
    (observed,) = listing["rows"]
    assert observed["session_id"] == ref.upstream_session_id and observed["state"] == kind
    assert detail["rows"][0]["state"] == kind
    assert f"[{kind}]" in text
    busy = kind not in {"idle", "unknown"}
    assert [item["session_id"] for item in active["rows"]] == (
        [ref.upstream_session_id] if busy else []
    )
    if kind == "unknown":
        # Unknown is neither idle nor active, and the response says it is partial.
        assert (code, active_code, text_code, detail_code) == (3, 3, 3, 3)
        assert observed["state_reason"] == "resource_unavailable"
        assert {"partial_state"} <= {issue["code"] for issue in listing["issues"]}
        assert "[idle]" not in text
    else:
        assert (code, active_code, text_code, detail_code) == (0, 0, 0, 0)
        assert observed["state_reason"] == "repeated_resources" and observed["owner_epoch"]
    assert "PRIVATE_QUEUED_INPUT" not in out + text and not writes


async def test_every_execution_state_keeps_its_own_label_and_active_class(db, run, socket_path):
    s = await scenario(db)
    states = list(ExecutionState)
    s.backend.pages = {
        None: (tuple(app_row(f"ses_{state.value}", state) for state in states), None)
    }
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions", "--limit", "50")
        _, active, _ = await run("--json", "sessions", "--active")
        _, text, _ = await run("--locale", "zh-TW", "sessions")
    assert code == 3  # The unknown row makes the listing partial, never complete success.
    assert [item["state"] for item in json.loads(out)["rows"]] == [state.value for state in states]
    assert {item["state"] for item in json.loads(active)["rows"]} == {
        "queued",
        "running",
        "waiting_permission",
        "waiting_input",
        "interrupting",
    }
    rendered = blocks(text)
    for state in states:
        assert f"[{state.value}]" in rendered[f"ses_{state.value}"]


# Filters, paging and argument errors --------------------------------------


async def paged(s, db):
    """Five rows over three Native pages: two bound, three App/TUI unbound."""
    s.backend.pages = {
        None: ((row("ses_original"), app_row("ses_b", ExecutionState.RUNNING)), "page-2"),
        "page-2": ((app_row("ses_c"), app_row("ses_d", ExecutionState.WAITING_INPUT)), "page-3"),
        "page-3": ((row("ses_second"),), None),
    }
    await DurableStore(db).enqueue(
        "second-queued",
        s.bound["ses_second"].id,
        s.bound["ses_second"].revision,
        7,
        {"operation": "prompt", "source": {"text": "PRIVATE_PAGED_PROMPT"}},
    )


async def walk(run, *filters):
    seen, cursor, pages = [], None, 0
    while True:
        pages += 1
        assert pages <= 5, "cursor walk must terminate"
        continuation = ("--backend", "backend", "--cursor", cursor) if cursor else ()
        code, out, err = await run("--json", "sessions", "--limit", "2", *filters, *continuation)
        data = json.loads(out)
        assert code == 0 and data["status"] == "ok" and not err, data
        seen += [item["session_id"] for item in data["rows"]]
        (coverage,) = data["coverage"]
        cursor = coverage["next_cursor"]
        if cursor is None:
            assert coverage["complete"] and coverage["reason"] == "exhausted"
            return seen
        assert not coverage["complete"]


async def test_filters_and_cursor_walks_preserve_every_identity_once(db, run, socket_path):
    s = await scenario(
        db, (("ses_original", 10, "Original work", 501), ("ses_second", 11, "Second work", 502))
    )
    await paged(s, db)
    async with Observer(socket_path, s.observer.query):
        everything = await walk(run)
        bound = await walk(run, "--bound")
        unbound = await walk(run, "--unbound")
        active = await walk(run, "--active")
        active_bound = await walk(run, "--active", "--bound")
        project = await walk(run, "--project", "project")
    assert everything == ["ses_original", "ses_b", "ses_c", "ses_d", "ses_second"]
    assert bound == ["ses_original", "ses_second"]
    assert unbound == ["ses_b", "ses_c", "ses_d"]
    assert sorted(bound + unbound) == sorted(everything) and not set(bound) & set(unbound)
    # Busy Native rows plus exact-Root recorded Bridge work (queued prompt on ses_second).
    assert active == ["ses_b", "ses_d", "ses_second"] and active_bound == ["ses_second"]
    assert project == everything  # The synthetic peer ignores the server-side filter.
    assert {limit for limit, _cursor, _project in s.backend.calls} == {2}
    assert {selected for _limit, _cursor, selected in s.backend.calls if selected is not None} == {
        ("native-project", REF.canonical_directory)
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ("--project", "Original native session"),  # A title is never a project identity.
        ("--project", "native-project"),  # Native project IDs are not enrolled Bridge IDs.
        ("--backend", "Original native session"),
    ],
)
async def test_titles_and_unknown_scopes_are_errors_without_native_reads(
    db, run, socket_path, arguments
):
    s = await scenario(db)
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions", *arguments)
        texts = [
            await run("--locale", locale, "sessions", *arguments) for locale in ("en", "zh-TW")
        ]
    data = json.loads(out)
    assert code == 2 and data["status"] == "error" and not data["rows"]
    assert [issue["code"] for issue in data["issues"]] == ["scope_unavailable"]
    assert [text_code for text_code, _, _ in texts] == [2, 2]
    # The observer answered; the text must not misreport the rejection as an outage.
    assert "outside the observer's enrolled scope" in texts[0][1]
    assert "不在 observer 已納管範圍內" in texts[1][1]
    assert not any("observer unavailable" in text for _, text, _ in texts)
    assert s.backend.calls == []


@pytest.mark.parametrize(
    "arguments",
    [
        ("sessions", "--limit", "0"),
        ("sessions", "--limit", "51"),
        ("sessions", "--max-pages", "11"),
        ("sessions", "--cursor", "opaque"),  # A cursor belongs to exactly one backend.
        ("session", "../../etc/passwd"),
        ("doctor", "--backend", ""),
    ],
)
async def test_invalid_bounds_and_paths_exit_2_before_any_observer_query(
    db, run, socket_path, arguments
):
    async def forbidden(query):
        raise AssertionError("invalid local requests must not reach the observer")

    async with Observer(socket_path, forbidden):
        code, out, err = await run("--json", *arguments)
        text_code, text_out, text_err = await run(*arguments)
    assert code == text_code == 2
    assert json.loads(out)["issues"] == [{"code": "invalid_request", "backend_id": None}]
    assert not text_out and "Invalid inspection request" in text_err
    assert "observer unavailable" not in text_err
    assert not err


@pytest.mark.parametrize(
    "arguments", [("sessions", "--bound", "--unbound"), ("session",), ("session", "x", "--active")]
)
async def test_contradictory_or_incomplete_arguments_are_usage_errors(run, arguments):
    code, out, err = await run(*arguments)
    assert code == 2 and not out and "usage:" in err


# Session detail -----------------------------------------------------------


async def test_session_detail_shows_only_its_own_queue_pause_ambiguity_and_delivery(
    db, run, socket_path
):
    s = await scenario(
        db, (("ses_original", 10, "Original work", 501), ("ses_second", 11, "Second work", 502))
    )
    store = DurableStore(db)
    original, second = s.bound["ses_original"], s.bound["ses_second"]
    states = ("queued", "held", "ambiguous", "ambiguous", "running", "failed", "completed")
    for index, state in enumerate(states):
        action = await store.enqueue(
            f"original-{index}-{state}",
            original.id,
            original.revision,
            7,
            {"operation": "prompt", "source": {"text": "PRIVATE_ORIGINAL_PROMPT"}},
        )
        async with db.sessions.begin() as session:
            await session.execute(update(Action).where(Action.id == action).values(state=state))
    for key, state in (("one", "pending"), ("two", "sending"), ("three", "failed")):
        delivery = await store.queue_delivery(
            key, original.id, original.revision, {"content": "PRIVATE_ORIGINAL_OUTPUT"}
        )
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery).where(Delivery.id == delivery).values(state=state)
            )
    await store.enqueue(
        "second-running",
        second.id,
        second.revision,
        7,
        {"operation": "prompt", "source": {"text": "PRIVATE_SECOND_PROMPT"}},
    )
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == original.id).values(dispatch_paused=True)
        )
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "session", "ses_original")
        second_code, second_out, _ = await run("--json", "session", "ses_second")
        texts = [
            (await run("--locale", locale, "session", "ses_original"))[1]
            for locale in ("en", "zh-TW")
        ]
    assert code == second_code == 0
    (observed,) = json.loads(out)["rows"]
    (mapped,) = observed["bindings"]
    assert observed["session_id"] == "ses_original" and mapped["binding_id"] == original.id
    assert mapped["paused"] is True and mapped["topic"] == "Original work"
    assert mapped["counts"] == {
        "queued": 1,
        "held": 1,
        "active": 1,
        "ambiguous": 2,
        "failed": 1,
        "pending_delivery": 2,
        "failed_delivery": 1,
    }
    (other,) = json.loads(second_out)["rows"][0]["bindings"]
    assert other["binding_id"] == second.id and other["paused"] is False
    assert other["counts"] == InspectionCounts(queued=1).model_dump()
    for text in texts:
        assert "ses_second" not in text and "Second work" not in text and second.id not in text
        assert "paused=True" in text and f"revision={original.revision}" in text
        assert '"ambiguous": 2' in text and '"pending_delivery": 2' in text
    for output in (out, second_out, *texts):
        assert "PRIVATE_" not in output
    assert "ses_original" not in second_out and original.id not in second_out


async def test_missing_exact_session_is_partial_without_borrowing_another_root(
    db, run, socket_path
):
    s = await scenario(db)

    async def missing(identity):
        raise ValueError("PRIVATE_NATIVE_NOT_FOUND")

    s.backend.detail = missing
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "session", "ses_absent")
    data = json.loads(out)
    assert code == 3 and data["status"] == "partial" and not data["rows"]
    assert data["issues"] == [{"code": "native_unavailable", "backend_id": "backend"}]
    assert "PRIVATE_" not in out and s.bound["ses_original"].id not in out


# Versioned JSON and exit status -------------------------------------------

RESPONSE_FIELDS = set(InspectionResponse.model_fields)
SESSION_FIELDS = set(InspectionSession.model_fields)
BINDING_FIELDS = set(InspectionBinding.model_fields)
COVERAGE_FIELDS = set(InspectionCoverage.model_fields)


async def test_versioned_json_has_stable_fields_ascii_literals_and_exit_0(db, run, socket_path):
    s = await scenario(db)
    s.backend.pages = {
        None: ((row("ses_original").model_copy(update={"title": '報表 ✓ "quoted"'}),), None)
    }
    async with Observer(socket_path, s.observer.query):
        code, out, err = await run("--json", "sessions")
        doctor_code, doctor, _ = await run("--json", "doctor")
    assert code == doctor_code == 0 and not err and out.isascii() and out.count("\n") == 1
    data = json.loads(out)
    assert data["version"] == "jt-oz-inspector-v1" and set(data) == RESPONSE_FIELDS
    assert data["observation_kind"] == "read_only_local_observer"
    assert set(data["rows"][0]) == SESSION_FIELDS
    assert set(data["rows"][0]["bindings"][0]) == BINDING_FIELDS
    assert set(data["coverage"][0]) == COVERAGE_FIELDS
    assert data["rows"][0]["title"] == '報表 ✓ "quoted"'
    assert isinstance(data["observed_at"], float) and isinstance(
        data["rows"][0]["observed_at"], float
    )
    doctor = json.loads(doctor)
    assert doctor["status"] == "ok" and doctor["rows"] == []
    assert doctor["coverage"][0]["owner_epoch"] == "a" * 64


async def test_valid_empty_results_are_success_not_errors(db, run, socket_path):
    s = await scenario(db)
    s.backend.pages = {None: ((app_row("ses_app"),), None)}
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions", "--bound")
        texts = [
            (await run("--locale", locale, "sessions", "--bound")) for locale in ("en", "zh-TW")
        ]
    data = json.loads(out)
    assert code == 0 and data["status"] == "ok" and data["rows"] == [] and data["issues"] == []
    assert data["coverage"][0]["complete"] is True
    assert texts[0][0] == texts[1][0] == 0
    assert "No matching sessions on this page." in texts[0][1]
    assert "此頁沒有符合的會話。" in texts[1][1]


async def test_partial_multi_backend_keeps_rows_and_exits_3(db, run, socket_path):
    s = await scenario(db)
    s.backend.fail = True
    other = Backend()
    other.backend_id = "other"
    other.pages = {None: ((app_row("ses_other").model_copy(update={"backend_id": "other"}),), None)}
    s.observer.backends = {"backend": s.backend, "other": other}
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions")
        text_code, text, _ = await run("sessions")
    data = json.loads(out)
    assert code == text_code == 3 and data["status"] == "partial"
    assert [item["session_id"] for item in data["rows"]] == ["ses_other"]
    assert {"code": "native_unavailable", "backend_id": "backend"} in data["issues"]
    assert [item["complete"] for item in data["coverage"]] == [False, True]
    assert "Warning: native_unavailable / backend" in text and "PRIVATE_" not in out + text


async def test_unauthorized_peer_exits_4_without_reaching_the_observer(db, run, socket_path):
    async def forbidden(query):
        raise AssertionError("unauthorized peers never reach the observer")

    async with Observer(socket_path, forbidden, allowed=frozenset({os.geteuid() + 1})):
        code, out, _ = await run("--json", "sessions")
        text_code, text, _ = await run("--locale", "zh-TW", "sessions")
    data = json.loads(out)
    assert code == text_code == 4
    assert data["status"] == "error" and data["issues"] == [
        {"code": "unauthorized", "backend_id": None}
    ]
    assert "本機 observer 無法使用" in text and "注意: unauthorized" in text


async def test_runtime_modes_select_versioned_v2_without_changing_v1(db, run, socket_path):
    s = await scenario(db)
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "--runtime-modes", "sessions")
        legacy_code, legacy, _ = await run("--json", "sessions")
    data, legacy = json.loads(out), json.loads(legacy)
    assert data["version"] == "jt-oz-inspector-v2" and legacy["version"] == "jt-oz-inspector-v1"
    # No controller snapshot is wired here: v2 says so instead of inventing a mode.
    assert code == 3 and data["rows"][0]["runtime_mode"] == {
        "mode": "unavailable",
        "reason": "diagnostics-unavailable",
        "transition_at": None,
        "observed_at": None,
    }
    assert legacy_code == 0 and "runtime_mode" not in legacy["rows"][0]


# Outages and stale observations -------------------------------------------


@pytest.mark.parametrize("command", [("sessions",), ("session", "ses_original"), ("doctor",)])
async def test_native_outage_is_partial_and_never_idle(db, run, socket_path, command):
    s = await scenario(db)
    s.backend.fail = True

    async def unavailable(identity):
        raise ValueError("PRIVATE_NATIVE_ERROR")

    s.backend.detail = unavailable
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", *command)
        text_code, text, _ = await run(*command)
    data = json.loads(out)
    assert code == text_code == 3 and data["status"] == "partial" and not data["rows"]
    assert {"code": "native_unavailable", "backend_id": "backend"} in data["issues"]
    assert data["coverage"][0]["complete"] is False
    assert data["coverage"][0]["reason"] == "backend_unavailable"
    assert "[idle]" not in text and "PRIVATE_" not in out + text


@pytest.mark.parametrize("fault", ["bridge-down", "lease-expired", "lease-missing"])
async def test_bridge_outage_is_reported_separately_from_native_state(db, run, socket_path, fault):
    s = await scenario(db)
    if fault == "bridge-down":
        s.health.ready = False
    else:
        async with db.sessions.begin() as session:
            if fault == "lease-expired":
                await session.execute(update(WorkerLease).values(expires_at=0))
            else:
                await session.delete(await session.get(WorkerLease, "consumer"))
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions")
        text_code, text, _ = await run("sessions")
    data = json.loads(out)
    assert code == text_code == 3 and data["status"] == "partial"
    assert data["bridge_ready"] is False
    assert data["bridge_lease_current"] is (fault == "bridge-down")
    assert "bridge_unavailable" in {issue["code"] for issue in data["issues"]}
    # Native evidence is still its own fact; Bridge disconnection is not Native idle.
    assert data["rows"][0]["state"] == "idle"
    assert "Bridge ready / lease current: False" in text
    assert "not session mutation authority" in text


class ReplacedOwner(Backend):
    """The original Native owner is replaced right after the catalog page."""

    replaced = False

    async def page(self, limit, cursor, *, project=None):
        self.replaced = False
        result = await super().page(limit, cursor, project=project)
        self.replaced = True
        return result

    async def original_owner(self):
        epoch = "b" * 64 if self.replaced else "a" * 64
        return SimpleNamespace(owner_epoch=epoch, pid=321, observed_at=time.time())


async def test_owner_change_after_observation_turns_rows_unknown_and_stale(db, run, socket_path):
    s = await scenario(db)
    s.observer.backends = {"backend": ReplacedOwner()}
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions")
        text_code, text, _ = await run("--locale", "zh-TW", "sessions")
    data = json.loads(out)
    assert code == text_code == 3 and data["status"] == "partial"
    (observed,) = data["rows"]
    assert observed["session_id"] == "ses_original" and observed["state"] == "unknown"
    assert observed["owner_epoch"] is None and observed["bindings"][0]["state"] == "active_record"
    assert "stale_observation" in {issue["code"] for issue in data["issues"]}
    assert data["coverage"][0]["reason"] == "state_unknown"
    assert "觀測已過期或時鐘不可信" in text and "[idle]" not in text


async def test_stopped_observer_is_an_error_and_never_replays_old_rows(db, run, socket_path):
    s = await scenario(db)
    async with Observer(socket_path, s.observer.query):
        code, out, _ = await run("--json", "sessions")
        assert code == 0 and json.loads(out)["rows"]
    stopped_code, stopped, _ = await run("--json", "sessions")
    text_code, text, _ = await run("sessions")
    data = json.loads(stopped)
    assert stopped_code == text_code == 2 and data["status"] == "error" and not data["rows"]
    assert data["issues"] == [{"code": "observer_unavailable", "backend_id": None}]
    assert "ses_original" not in text and "Local observer unavailable" in text


async def test_display_delay_expires_a_fresh_idle_row(db, run, socket_path, monkeypatch):
    s = await scenario(db)
    clock = SimpleNamespace(offset=0.0)
    wall = time.time
    monkeypatch.setattr(local_cli.time, "time", lambda: wall() + clock.offset)
    original = local_cli.render

    def slow_render(*args, **kwargs):
        clock.offset = 6.0  # Formatting/scheduling delay beyond the five-second budget.
        return original(*args, **kwargs)

    monkeypatch.setattr(local_cli, "render", slow_render)
    async with Observer(socket_path, s.observer.query):
        code, text, _ = await run("sessions")
    assert code == 3 and "[unknown]" in text and "[idle]" not in text
    assert "Observation expired or clock uncertain" in text


# Hostile text and terminal safety -----------------------------------------

HOSTILE = "evil\x1b]52;c;UFJJVkFURQ==\x07\x1b[2J\r\nfake: [idle]\u202eRTL\x9b31m\u2028\u2066"


async def test_hostile_native_and_zulip_text_cannot_control_the_terminal(db, run, socket_path):
    s = await scenario(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Binding).values(topic="topic " + HOSTILE))
    hostile_cursor = 'next"; rm -rf ~ #' + HOSTILE
    s.backend.pages = {
        None: (
            (
                row("ses_original").model_copy(update={"title": HOSTILE * 5}),
                app_row(
                    "ses_app",
                    directory="/opt/" + HOSTILE,
                    title=HOSTILE,
                    agent_id=HOSTILE,
                    provider_id="p",
                    model_id=HOSTILE,
                ),
            ),
            hostile_cursor,
        ),
    }

    async def detail(identity):
        return row(identity).model_copy(
            update={"title": HOSTILE, "parent_id": HOSTILE, "fork_source_id": HOSTILE}
        )

    s.backend.detail = detail
    await DurableStore(db).enqueue(
        "hostile-private",
        s.bound["ses_original"].id,
        1,
        7,
        {"operation": "prompt", "source": {"text": "PRIVATE_PROMPT " + HOSTILE}},
    )
    async with Observer(socket_path, s.observer.query):
        outputs = [
            await run("--locale", locale, *command)
            for locale in ("en", "zh-TW")
            for command in (("sessions",), ("session", "ses_original"))
        ]
        code, raw, _ = await run("--json", "sessions")
    for text_code, text, err in outputs:
        assert text_code == 0 and not err
        assert_terminal_safe(text)
        assert "\\u001b" in text and "\\u202e" in text and "PRIVATE_" not in text
        # Injected newlines stay escaped; every session still renders on its own lines.
        assert "\nfake: [idle]" not in text
    listing = outputs[0][1]
    assert listing.count("[bound-record]") == 1 and "…" in listing  # Long title truncated.
    assert 'Next page: --backend backend --cursor "next\\"; rm -rf ~ #evil\\u001b' in listing
    assert code == 0 and raw.isascii() and "PRIVATE_" not in raw
    data = json.loads(raw)
    # JSON preserves inert literals exactly instead of rewriting them.
    assert data["rows"][0]["title"] == HOSTILE * 5
    assert data["rows"][0]["bindings"][0]["topic"] == "topic " + HOSTILE
    assert data["rows"][1]["agent_id"] == HOSTILE
    assert data["coverage"][0]["next_cursor"] == hostile_cursor


def test_safe_terminal_escapes_every_control_format_and_separator_character():
    hostile = "".join(chr(code) for code in (*range(0x20), 0x7F, *range(0x80, 0xA0)))
    hostile += "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2028\u2029\u2066\u2069\ufeff"
    escaped = local_cli.safe_terminal(hostile, maximum=1000)
    assert escaped.isprintable() and escaped.isascii()
    assert len(re.findall(r"\\u[0-9a-f]{4}", escaped)) == len(hostile)


# Help and bilingual labels ------------------------------------------------

CJK = re.compile("[\\u3400-\\u9fff\\uff01-\\uff5e]")  # CJK ideographs and full-width forms.


def bilingual(value):
    return bool(value and re.search(r"[A-Za-z]{3}", value) and CJK.search(value))


def test_every_inspection_option_and_command_has_bilingual_help():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    local_cli.add_inspection_commands(parser, sub)
    choices = {action.dest: action for action in sub._get_subactions()}
    assert set(choices) == {"sessions", "session", "doctor"}
    assert all(bilingual(action.help) for action in choices.values())
    for current in (parser, *sub.choices.values()):
        for action in current._actions:
            if isinstance(action, argparse._HelpAction | argparse._SubParsersAction):
                continue
            assert bilingual(action.help), (current.prog, action.option_strings or action.dest)


@pytest.mark.parametrize("command", [(), ("sessions",), ("session",), ("doctor",)])
async def test_entry_point_help_is_bilingual_and_needs_no_observer(run, command):
    code, raw, err = await run(*command, "--help")
    assert code == 0 and not err and raw.startswith("usage: jt-oz-bridge")
    out = " ".join(raw.split())  # Wrapping depends on the terminal width.
    assert "--json" in out and "版本化 JSON" in out and "Versioned JSON" in out
    assert "--locale" in out and "顯示語言" in out
    if not command:
        assert "local session inspector" in out and "本機會話檢視" in out
        assert "列出會話與對應" in out and "唯讀連線診斷" in out
    if command == ("sessions",):
        assert "只列有效 Zulip 綁定紀錄" in out and "只列確認未綁定的會話" in out
    if command == ("session",):
        assert "精確 Native 會話 ID" in out


def test_display_labels_and_modes_exist_in_both_languages():
    english, chinese = local_cli.labels("en"), local_cli.labels("zh-TW")
    assert set(english) == set(chinese)
    assert all(english[key] != chinese[key] for key in english)
    assert all(CJK.search(value) for value in chinese.values())
    assert not any(CJK.search(value) for value in english.values())
    for mode in ("unstarted", "strict", "readonly-owned-check", "readonly-awaiting-idle"):
        assert CJK.search(local_cli.runtime_mode_label(mode, "zh-TW"))
        assert not CJK.search(local_cli.runtime_mode_label(mode, "en"))


def test_console_script_is_the_inspected_entry_point():
    import tomllib

    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert project["project"]["scripts"] == {"jt-oz-bridge": "jt_oz_bridge.cli:main"}
