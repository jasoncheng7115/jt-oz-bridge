"""Synthetic installed-schema observations; no real local CLI qualification."""

import copy
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.inspection import V2SessionInspection
from jt_oz_bridge.domain.control import ExecutionState
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as native_setup
from tests.contract.test_public_live_feed import REAL


async def setup():
    proofs, transport, data, guard, execution, calls, writes = await native_setup()
    epoch = (await proofs.feed.current_owner()).owner_epoch
    owner = SimpleNamespace(read=lambda: None)

    async def read():
        return SimpleNamespace(
            backend_id=REF.backend_id,
            backend_identity=REF.backend_identity,
            version="2.0.32",
            owner_epoch=epoch,
            observed_at=time.time(),
        )

    owner.read = read
    inspector = V2SessionInspection(transport, owner, REF.backend_id, REF.backend_identity)
    original = transport.client._transport
    pages = {None: ([copy.deepcopy(data["session.get"]["data"])], None)}
    page_calls = []

    def handler(request):
        assert request.method == "GET"
        if request.url.path == "/api/session" and "parentID" not in request.url.params:
            page_calls.append(dict(request.url.params))
            items, cursor = pages[request.url.params.get("cursor")]
            return httpx.Response(200, json={"data": items, "cursor": {"next": cursor}})
        return original.handler(request)

    transport.client._transport = httpx.MockTransport(handler)
    return inspector, proofs, transport, data, pages, page_calls, writes


@pytest.mark.parametrize(
    "kind", ["idle", "running", "permission", "form", "queued", "pristine", "stale-idle", "lineage"]
)
async def test_observer_states_are_from_exact_resources_not_active_absence(kind):
    inspector, proofs, t, data, pages, page_calls, writes = await setup()
    expected = ExecutionState.IDLE
    if kind in {"running", "permission", "form"}:
        data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
        expected = {
            "running": ExecutionState.RUNNING,
            "permission": ExecutionState.WAITING_PERMISSION,
            "form": ExecutionState.WAITING_INPUT,
        }[kind]
        if kind != "running":
            event = next(
                e
                for e in REAL
                if e["type"] == ("permission.asked" if kind == "permission" else "form.created")
            )
            raw = event["data"] if kind == "permission" else event["data"]["form"]
            data["session." + kind + ".list"]["data"] = [copy.deepcopy(raw)]
    elif kind == "queued":
        data["session.inbox.list"]["data"] = [
            {
                "id": "msg_queued",
                "sessionID": REF.upstream_session_id,
                "type": "user",
                "payload": {"text": "PRIVATE_INPUT_SHOULD_NOT_APPEAR"},
                "delivery": "queue",
                "time": {"created": 4},
            }
        ]
        expected = ExecutionState.QUEUED
    elif kind == "pristine":
        data["session.get"]["data"].pop("outcome")
        data["session.get"]["data"]["time"].pop("idle")
        data["session.message.list"]["data"] = []
    elif kind == "stale-idle":
        data["session.get"]["data"]["time"]["idle"] = 999
        expected = ExecutionState.UNKNOWN
    elif kind == "lineage":
        data["session.get"]["data"]["parentID"] = "ses_parent"
        expected = ExecutionState.UNKNOWN
    try:
        row = await inspector.detail(REF.upstream_session_id)
        assert row.state == expected
        assert row.execution_registration == "catalog_only" and row.bindings == ()
        assert "PRIVATE_INPUT_SHOULD_NOT_APPEAR" not in row.model_dump_json()
        assert not writes
    finally:
        await finish(proofs, t)


async def test_backend_catalog_can_include_unenrolled_app_session_without_promoting_it():
    inspector, proofs, t, data, pages, page_calls, writes = await setup()
    row = copy.deepcopy(data["session.get"]["data"])
    row.update(
        id="ses_from_app",
        projectID="another-native-project",
        location={"directory": "/opt/another-project"},
        title="App work",
    )
    pages[None] = ([row], "opaque-next")
    pages["opaque-next"] = ([], None)
    try:
        one, cursor = await inspector.page(10, None)
        assert one[0].session_id == "ses_from_app" and one[0].directory == "/opt/another-project"
        assert (
            one[0].state == ExecutionState.UNKNOWN
            and one[0].execution_registration == "catalog_only"
        )
        assert one[0].bindings == () and cursor == "opaque-next"
        assert await inspector.page(10, cursor) == ((), None)
        assert page_calls == [
            {"limit": "10", "order": "desc"},
            {"limit": "10", "order": "desc", "cursor": "opaque-next"},
        ]
        assert not writes
    finally:
        await finish(proofs, t)


@pytest.mark.parametrize(
    "fault",
    [
        "operation",
        "schema",
        "identity",
        "version",
        "owner",
        "duplicate",
        "oversize",
        "foreign-project",
        "cursor",
    ],
)
async def test_unqualified_or_malformed_catalog_cannot_be_reported_as_success(fault):
    inspector, proofs, t, data, pages, page_calls, writes = await setup()
    project = None
    if fault == "operation":
        t.attestation = replace(t.attestation, verified_operations=frozenset({"session.list"}))
    elif fault == "schema":
        t.attestation = replace(t.attestation, schema_sha256="f" * 64)
    elif fault == "identity":
        t.attestation = replace(t.attestation, backend_identity="other")
    elif fault == "version":
        t.attestation = replace(t.attestation, upstream_version="unqualified")
    elif fault == "owner":

        async def other():
            return SimpleNamespace(
                backend_id="other",
                backend_identity=REF.backend_identity,
                version="2.0.32",
                owner_epoch="a" * 64,
                observed_at=time.time(),
            )

        inspector.owner = SimpleNamespace(read=other)
    elif fault == "duplicate":
        pages[None] = (pages[None][0] * 2, None)
    elif fault == "oversize":
        pages[None] = ([dict(pages[None][0][0], id="ses_" + str(i)) for i in range(11)], None)
    elif fault == "foreign-project":
        project = ("foreign", REF.canonical_directory)
    else:
        pages["loop"] = (pages[None][0], "loop")
    try:
        with pytest.raises(ContractError):
            await inspector.page(10, "loop" if fault == "cursor" else None, project=project)
        assert not writes
    finally:
        await finish(proofs, t)


async def test_changed_title_during_state_read_is_not_reported_as_current_old_title():
    inspector, proofs, t, data, pages, page_calls, writes = await setup()
    try:
        rows, _ = await inspector.page(10, None)
        data["session.get"]["data"]["title"] = "New native App title"
        observed = await inspector.state(rows[0])
        assert observed.title == "New native App title" and observed.state == ExecutionState.IDLE
    finally:
        await finish(proofs, t)
