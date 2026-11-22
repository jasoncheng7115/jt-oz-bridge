"""Synthetic existing-session observations; no live adoption/compatibility proof."""

import asyncio
import copy
import time
from dataclasses import replace
from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.existing_sessions import (
    ExistingSessionProtocol,
    V2ExistingSessionObserver,
)
from jt_oz_bridge.adapters.opencode.project_policy import POLICY_READS
from jt_oz_bridge.domain.existing_sessions import ExistingSessionObservation
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup

TARGET = REF.model_copy(update={"upstream_session_id": "ses_original_existing"})
PARENT = REF.model_copy(update={"upstream_session_id": "ses_original_parent"})


async def setup(*, child=False):
    p, t, data, guard, execution, _, writes = await policy_setup()
    epoch = (await p.feed.current_owner()).owner_epoch
    p.feed.owner.read.side_effect = lambda: SimpleNamespace(
        owner_epoch=epoch,
        backend_id=REF.backend_id,
        backend_identity=REF.backend_identity,
        version="2.0.32",
        observed_at=time.time(),
    )
    info = copy.deepcopy(data["session.get"]["data"])
    info.update(
        id=TARGET.upstream_session_id,
        agent="task" if child else "build",
        title="Original TUI work; not created by Bridge",
        permissions=[{"action": "read", "resource": "*", "effect": "allow"}],
    )
    info.pop("metadata", None)
    info["time"].update(created=10, updated=25)
    if child:
        info["parentID"] = PARENT.upstream_session_id
    parent_info = copy.deepcopy(data["session.get"]["data"])
    parent_info.update(id=PARENT.upstream_session_id)
    state = {
        "info": info,
        "parent": parent_info,
        "hook": None,
        "agent": copy.deepcopy(data["agent.get"]),
        "policy_counts": {},
    }
    state["agent"]["data"].update(id="task", mode="subagent")
    calls = []
    original = t.client._transport

    def handle(request):
        calls.append(request)
        assert request.method == "GET"
        path = request.url.path
        if state["hook"] is not None:
            response = state["hook"](request, state, calls)
            if response is not None:
                return response
        if path == "/api/session/" + TARGET.upstream_session_id:
            return httpx.Response(200, json={"data": copy.deepcopy(state["info"])})
        if path == "/api/session/" + PARENT.upstream_session_id:
            return httpx.Response(200, json={"data": copy.deepcopy(state["parent"])})
        if path == "/api/agent/task":
            return httpx.Response(200, json=copy.deepcopy(state["agent"]))
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handle)
    protocol = ExistingSessionProtocol(
        REF.backend_id, REF.backend_identity, t.profile.sha256, "e" * 64, POLICY_READS
    )
    observer = V2ExistingSessionObserver(guard, protocol, REF)
    return p, t, data, observer, state, calls, writes, execution


def assert_observation_reason(error, reason):
    assert type(error) is ContractError
    assert error.args == ("existing_session_original_observation_changed",)
    assert str(error) == "existing_session_original_observation_changed"
    assert error.__notes__ == ["existing_session_observation_guard=" + reason]


async def test_used_root_observation_keeps_actual_policy_without_creation_or_registration():
    p, t, data, observer, state, calls, writes, execution = await setup()
    try:
        enrolled = observer.anchor.enrollments[REF]
        before_refs = p.feed.references
        before_info = copy.deepcopy(data["session.get"])
        value = await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert value.reference == TARGET and value.native_created_at == 10
        assert observer.current(value) and not value.starts_execution
        assert not value.registered_for_execution and value.parent_reference is None
        assert value.policy_sha256 != enrolled.fingerprint_sha256
        assert value.session_info_sha256 == digest(state["info"])
        assert observer.anchor.enrollments[REF] is enrolled
        assert set(observer.anchor.enrollments) == {REF}
        assert p.feed.references is before_refs and TARGET not in p.feed.references
        assert data["session.get"] == before_info
        assert not execution.capabilities(TARGET)["prompt"].supported
        assert len([r for r in calls if r.url.path.endswith(TARGET.upstream_session_id)]) == 2
        assert not writes and all(r.method == "GET" for r in calls)
    finally:
        await finish(p, t)


async def test_existing_child_observes_exact_immediate_parent_and_subagent_without_adopting():
    p, t, data, observer, state, calls, writes, _ = await setup(child=True)
    try:
        value = await observer.observe(
            TARGET, parent=PARENT, authorize=AsyncMock(return_value=True)
        )
        assert value.parent_reference == PARENT and value.parent_created_at == 1
        assert observer.current(value) and set(observer.anchor.enrollments) == {REF}
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "kind", ["root_as_child", "child_as_root", "self", "wrong_parent", "cycle"]
)
async def test_missing_forged_or_cyclic_parent_edges_fail(kind):
    p, t, data, observer, state, calls, writes, _ = await setup(child=kind != "root_as_child")
    try:
        parent = PARENT
        if kind == "child_as_root":
            parent = None
        elif kind == "self":
            parent = TARGET
        elif kind == "wrong_parent":
            state["info"]["parentID"] = "ses_other"
        elif kind == "cycle":
            state["parent"]["parentID"] = TARGET.upstream_session_id
        with pytest.raises(ContractError):
            await observer.observe(TARGET, parent=parent, authorize=AsyncMock(return_value=True))
        assert not writes and not observer._observed
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "field,which",
    [
        (field, which)
        for which in ("target", "parent")
        for field in ("id", "projectID", "location", "created", "archived", "agent")
        if (which, field) != ("parent", "agent")
    ],
)
async def test_original_target_and_parent_scope_must_be_real_unchanged_api_identities(field, which):
    p, t, data, observer, state, calls, writes, _ = await setup(child=True)
    try:
        row = state["info" if which == "target" else "parent"]
        if field == "created":
            row["time"]["created"] = True
        elif field == "archived":
            row["time"]["archived"] = 50
        elif field == "location":
            row[field] = {"directory": "/different/project"}
        else:
            row[field] = "different"
        with pytest.raises((ContractError, ValidationError)):
            await observer.observe(TARGET, parent=PARENT, authorize=AsyncMock(return_value=True))
        assert not writes and not observer._observed
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["created", "policy", "parent_created", "parent_lineage"])
async def test_identity_and_policy_drift_between_target_reads_is_rejected(change):
    p, t, data, observer, state, calls, writes, _ = await setup(child=True)
    target_reads = 0

    def hook(request, state, calls):
        nonlocal target_reads
        if request.url.path == "/api/session/" + TARGET.upstream_session_id:
            target_reads += 1
            if target_reads == 2:
                if change == "created":
                    state["info"]["time"]["created"] += 1
                elif change == "policy":
                    state["info"]["permissions"] = []
                elif change == "parent_created":
                    state["parent"]["time"]["created"] += 1
                else:
                    state["parent"]["parentID"] = "ses_other_ancestor"

    state["hook"] = hook
    authorize = AsyncMock(return_value=True)
    try:
        with pytest.raises(ContractError, match="observation_changed") as caught:
            await observer.observe(TARGET, parent=PARENT, authorize=authorize)
        assert_observation_reason(
            caught.value, "target_policy" if change == "policy" else "target_origin"
        )
        assert authorize.await_count == 1
        assert target_reads == 2 and not writes and not observer._observed
    finally:
        await finish(p, t)


async def test_changing_title_model_usage_or_activity_does_not_require_pristine_or_idle_session():
    p, t, data, observer, state, calls, writes, _ = await setup()
    reads = 0

    def hook(request, state, calls):
        nonlocal reads
        if request.url.path == "/api/session/" + TARGET.upstream_session_id:
            reads += 1
            state["info"]["title"] = f"Still running {reads}"
            state["info"]["time"]["updated"] += 1
            state["info"]["cost"] += 1
            state["info"]["tokens"]["input"] += 10
        if request.url.path == "/api/session/active":
            raise AssertionError("Metadata observation cannot claim idle/running resource proof")

    state["hook"] = hook
    try:
        value = await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert reads == 2 and observer.current(value)
        assert value.session_info_sha256 == digest(state["info"]) and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("global_key", ["plugins", "saved_permissions", "mcp"])
async def test_target_global_policy_must_match_enrolled_project_even_when_target_is_self_consistent(
    global_key,
):
    p, t, data, observer, state, calls, writes, _ = await setup()
    path = {
        "plugins": "/api/plugin",
        "saved_permissions": "/api/permission/saved",
        "mcp": "/api/mcp",
    }[global_key]
    op = {
        "plugins": "plugin.list",
        "saved_permissions": "permission.saved.list",
        "mcp": "mcp.list",
    }[global_key]
    count = 0

    def hook(request, state, calls):
        nonlocal count
        if request.url.path == path:
            count += 1
            if count in {2, 3}:
                response = copy.deepcopy(data[op])
                response["data"] = []
                if global_key == "saved_permissions":
                    response["data"] = [
                        {
                            "id": "perm_fixture",
                            "projectID": "global",
                            "action": "read",
                            "resource": "*",
                            "time": {"created": 1, "updated": 1},
                        }
                    ]
                return httpx.Response(200, json=response)

    state["hook"] = hook
    authorize = AsyncMock(return_value=True)
    try:
        with pytest.raises(ContractError, match="observation_changed") as caught:
            await observer.observe(TARGET, authorize=authorize)
        assert_observation_reason(caught.value, "shared_inventory")
        assert authorize.await_count == 1
        assert count == 4 and not writes and not observer._observed
    finally:
        await finish(p, t)


@pytest.mark.parametrize("point", ["before", "after"])
async def test_current_authority_required_before_and_after_reads(point):
    p, t, data, observer, state, calls, writes, _ = await setup()
    authorize = AsyncMock(side_effect=[False] if point == "before" else [True, False])
    try:
        with pytest.raises(ContractError) as caught:
            await observer.observe(TARGET, authorize=authorize)
        assert not writes and not observer._observed
        if point == "before":
            assert not calls and authorize.await_count == 1
            assert type(caught.value) is ContractError
            assert str(caught.value) == "existing_session_current_authority_required"
            assert not getattr(caught.value, "__notes__", ())
        else:
            assert_observation_reason(caught.value, "authority")
            assert authorize.await_count == 2
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "reason",
    [
        "owner_context",
        "attestation_identity",
        "anchor_fingerprint",
        "anchor_repeat",
        "observation_window",
    ],
)
async def test_original_observation_failure_note_identifies_first_failed_guard(reason, monkeypatch):
    p, t, data, observer, state, calls, writes, _ = await setup()
    target_reads = anchor_reads = owner_reads = 0
    original_owner = observer.owner

    async def owner():
        nonlocal owner_reads
        value = await original_owner()
        owner_reads += 1
        if reason == "observation_window" and owner_reads == 2:
            expired = time.time() + 5
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.existing_sessions.time.time", lambda: expired
            )
        return value

    def hook(request, state, calls):
        nonlocal target_reads, anchor_reads
        if request.url.path == "/api/session/" + TARGET.upstream_session_id:
            target_reads += 1
            if target_reads == 2:
                if reason == "owner_context":
                    p.feed.index.connection_epoch = "changed-connection"
                elif reason == "attestation_identity":
                    t.attestation = replace(t.attestation)
        if request.url.path == "/api/session/" + REF.upstream_session_id:
            anchor_reads += 1
            if (reason, anchor_reads) in {("anchor_fingerprint", 1), ("anchor_repeat", 2)}:
                response = copy.deepcopy(data["session.get"])
                response["data"]["permissions"] = []
                return httpx.Response(200, json=response)

    observer.owner = owner
    state["hook"] = hook
    authorize = AsyncMock(return_value=True)
    try:
        with pytest.raises(ContractError, match="observation_changed") as caught:
            await observer.observe(TARGET, authorize=authorize)
        assert_observation_reason(caught.value, reason)
        # Every early guard still runs after both original bundles; none may
        # execute the final authorizer or construct/retain an observation.
        assert target_reads == anchor_reads == owner_reads == 2
        assert authorize.await_count == 1 and not observer._observed and not writes
    finally:
        monkeypatch.undo()
        await finish(p, t)


@pytest.mark.parametrize(
    "change",
    [
        "copy",
        "json",
        "expired",
        "future",
        "owner",
        "attestation",
        "protocol",
        "enrollment",
        "proofs",
        "anchor",
        "reference",
        "connection",
        "task",
    ],
)
async def test_witness_cannot_be_copied_rebound_or_kept_after_its_original_runtime_boundary_changes(
    change, monkeypatch
):
    p, t, data, observer, state, calls, writes, _ = await setup()
    try:
        value = await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
        if change == "copy":
            value = value.model_copy()
        elif change == "json":
            value = ExistingSessionObservation.model_validate_json(value.model_dump_json())
        elif change in {"expired", "future"}:
            clock = value.expires_at if change == "expired" else value.observed_at - 0.01
            monkeypatch.setattr(
                "jt_oz_bridge.adapters.opencode.existing_sessions.time.time", lambda: clock
            )
        elif change == "owner":
            p.feed.index.owner_epoch = "b" * 64
        elif change == "attestation":
            t.attestation = replace(t.attestation)
        elif change == "protocol":
            observer.protocol = replace(observer.protocol)
        elif change == "enrollment":
            observer.anchor.enrollments = MappingProxyType(
                {REF: observer.anchor.enrollments[REF].model_copy()}
            )
        elif change == "proofs":
            observer.anchor.proofs = copy.copy(observer.anchor.proofs)
        elif change == "anchor":
            observer.anchor = copy.copy(observer.anchor)
        elif change == "reference":
            observer.reference = REF.model_copy()
        elif change == "connection":
            p.feed.index.connection_epoch = "other"
        else:
            p.feed.task.cancel()
            await asyncio.gather(p.feed.task, return_exceptions=True)
        assert not observer.current(value) and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("change", ["backend", "schema", "evidence", "operations"])
async def test_backend_get_protocol_must_be_explicit_and_cover_all_policy_reads(change):
    p, t, data, observer, state, calls, writes, _ = await setup()
    values = {
        "backend": {"backend_identity": "different"},
        "schema": {"schema_sha256": "a" * 64},
        "evidence": {"installed_evidence_sha256": "not-a-digest"},
        "operations": {"operations": POLICY_READS - {"plugin.list"}},
    }
    try:
        with pytest.raises(ContractError):
            V2ExistingSessionObserver(
                observer.anchor, replace(observer.protocol, **values[change]), REF
            )
        assert not calls and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "field", ["backend_id", "backend_identity", "project_id", "canonical_directory"]
)
async def test_foreign_target_reference_is_rejected_without_get(field):
    p, t, data, observer, state, calls, writes, _ = await setup()
    try:
        with pytest.raises(ContractError):
            await observer.observe(
                TARGET.model_copy(update={field: "foreign"}), authorize=AsyncMock(return_value=True)
            )
        assert not calls and not writes
    finally:
        await finish(p, t)


async def test_observation_dto_cannot_claim_registration_execution_or_extended_lifetime():
    p, t, data, observer, state, calls, writes, _ = await setup()
    try:
        value = await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
        for update in (
            {"starts_execution": True},
            {"registered_for_execution": True},
            {"expires_at": value.observed_at + 6},
            {"expires_at": value.observed_at},
            {"native_created_at": True},
            {"parent_reference": PARENT},
            {"parent_created_at": 1},
            {"parent_reference": TARGET, "parent_created_at": 1},
        ):
            with pytest.raises(ValidationError):
                ExistingSessionObservation.model_validate(value.model_dump() | update)
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("phase", ["before", "after"])
async def test_authenticated_get_observation_checks_physical_backend_identity(phase):
    p, t, data, observer, state, calls, writes, _ = await setup()
    try:
        t.verify_identity = AsyncMock(side_effect=[False] if phase == "before" else [True, False])
        with pytest.raises(ContractError, match="backend_identity_unverified"):
            await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert not observer._observed and not writes
        if phase == "before":
            assert not calls
    finally:
        await finish(p, t)


async def test_original_five_second_deadline_cannot_be_renewed_after_slow_reads(monkeypatch):
    p, t, data, observer, state, calls, writes, _ = await setup()
    now = time.time()
    clock = [now]
    reads = 0

    def hook(request, state, calls):
        nonlocal reads
        if request.url.path == "/api/session/" + TARGET.upstream_session_id:
            reads += 1
            if reads == 2:
                clock[0] = now + 5

    state["hook"] = hook
    try:
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.existing_sessions.time.time", lambda: clock[0]
        )
        with pytest.raises(ContractError):
            await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
        assert not observer._observed and not writes
    finally:
        await finish(p, t)


async def test_caller_cancellation_never_retains_partial_observation():
    p, t, data, observer, state, calls, writes, _ = await setup()
    entered, release = asyncio.Event(), asyncio.Event()

    async def authorize():
        entered.set()
        await release.wait()
        return True

    task = asyncio.create_task(observer.observe(TARGET, authorize=authorize))
    try:
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not observer._observed and not writes and not calls
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await finish(p, t)
