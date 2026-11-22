"""Synthetic original-tree resource proofs; never installed descendant evidence."""

import asyncio
import copy
import json
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.lineage_resources import (
    LINEAGE_SEMANTICS,
    LineageResourceAttestation,
    V2LineageResourceProofs,
)
from jt_oz_bridge.adapters.opencode.resources import READS
from jt_oz_bridge.domain.control import ExecutionState
from tests.contract.test_existing_session_graph import CHILD, GRANDCHILD, SIBLING, TARGET
from tests.contract.test_existing_session_graph import setup as metadata_setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_public_live_feed import OWNER, REAL, REF, frame, text_delta


async def setup():
    anchor, transport, metadata, tree, calls, writes = await metadata_setup()
    observation = await metadata.observe(TARGET, authorize=AsyncMock(return_value=True))
    for reference in tree["rows"]:
        await anchor.feed.enroll_reference(reference, authorize=AsyncMock(return_value=True))
    anchor.feed.owner.read.side_effect = lambda: SimpleNamespace(
        owner_epoch=OWNER,
        backend_id=REF.backend_id,
        backend_identity=REF.backend_identity,
        version="2.0.32",
        observed_at=time.time(),
        model_dump=lambda **kw: {"fixture_owner": OWNER},
    )
    resources = {
        reference: {
            "inbox": [],
            "permission": [],
            "form": [],
            "message": [
                {"id": "msg_idle", "type": "idle", "time": {"created": 100}, "outcome": "succeeded"}
            ],
        }
        for reference in tree["rows"]
    }
    for row in tree["rows"].values():
        row["time"].update(updated=100, idle=100)
        row["outcome"] = "succeeded"
    state = {"resources": resources, "active": {}, "hook": None, "resource_calls": []}
    old = transport.client._transport

    def handler(request):
        assert request.method == "GET"
        state["resource_calls"].append(request)
        if state["hook"] is not None:
            response = state["hook"](request, state)
            if response is not None:
                return response
        if request.url.path == "/api/session/active":
            return httpx.Response(200, json={"data": copy.deepcopy(state["active"])})
        for ref, catalog in resources.items():
            prefix = "/api/session/" + ref.upstream_session_id + "/"
            if request.url.path.startswith(prefix):
                suffix = request.url.path.removeprefix(prefix)
                assert suffix in catalog
                value = {"data": copy.deepcopy(catalog[suffix])}
                if suffix == "message":
                    value["cursor"] = {}
                return httpx.Response(200, json=value)
        return old.handler(request)

    transport.client._transport = httpx.MockTransport(handler)
    attestation = LineageResourceAttestation(
        REF.backend_id,
        REF.backend_identity,
        transport.profile.sha256,
        LINEAGE_SEMANTICS,
        "e" * 64,
        READS,
    )
    proofs = V2LineageResourceProofs(
        anchor.feed, anchor.projects, observation, attestation, current=metadata.current
    )
    client = V2ExecutionClient(transport, anchor.projects, proofs=proofs)
    return anchor, transport, proofs, client, tree, state, writes, metadata


async def test_complete_root_and_child_snapshots_keep_exact_original_ids_and_recursive_resources():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        snapshot, proof = await c.qualified_snapshot(TARGET)
        assert snapshot.state == ExecutionState.IDLE and snapshot.reconciled
        assert set(snapshot.descendants) == {CHILD, GRANDCHILD, SIBLING}
        c.current(TARGET, proof)
        assert p.dispatch_owner_epoch(TARGET, proof) == OWNER
        child, child_proof = await c.qualified_snapshot(CHILD)
        assert child.reference == CHILD and child.descendants == (GRANDCHILD,)
        c.current(CHILD, child_proof)
        assert p.dispatch_owner_epoch(CHILD, child_proof) == OWNER
        assert not c.capabilities(CHILD)["prompt"].supported
        assert all(r.method == "GET" for r in state["resource_calls"]) and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("mode", ["running", "permission", "form", "queued"])
async def test_original_child_state_and_request_kind_are_reconciled_without_retargeting_parent(
    mode,
):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        if mode == "queued":
            state["resources"][CHILD]["inbox"] = [
                {
                    "id": "msg_queued",
                    "sessionID": CHILD.upstream_session_id,
                    "type": "user",
                    "payload": {"text": "queued"},
                    "delivery": "queue",
                    "time": {"created": 101},
                }
            ]
            expected = ExecutionState.QUEUED
        else:
            state["active"][CHILD.upstream_session_id] = {"type": "running"}
            expected = ExecutionState.RUNNING
            if mode == "permission":
                raw = copy.deepcopy(
                    next(e["data"] for e in REAL if e["type"] == "permission.asked")
                )
                raw["sessionID"] = CHILD.upstream_session_id
                state["resources"][CHILD]["permission"] = [raw]
                expected = ExecutionState.WAITING_PERMISSION
            elif mode == "form":
                raw = copy.deepcopy(
                    next(e["data"]["form"] for e in REAL if e["type"] == "form.created")
                )
                raw["sessionID"] = CHILD.upstream_session_id
                state["resources"][CHILD]["form"] = [raw]
                expected = ExecutionState.WAITING_INPUT
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        snapshot, proof = await c.qualified_snapshot(CHILD)
        assert snapshot.state == expected and proof.reference == CHILD
        if mode in {"permission", "form"}:
            request = state["resources"][CHILD][mode][0]["id"]
            assert await p.interaction_kind(CHILD, request, proof.connection_epoch) == mode
            assert await p.interaction_kind(TARGET, request, proof.connection_epoch) is None
        parent, parent_proof = await c.qualified_snapshot(TARGET)
        assert parent.state == ExecutionState.IDLE  # Parent state is not fabricated from its child.
        with pytest.raises(ContractError, match="quiescent_graph"):
            p.dispatch_owner_epoch(TARGET, parent_proof)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fault", ["created", "parent", "project", "directory", "archived"])
async def test_subtree_proof_still_checks_the_original_ancestor_identity(fault):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        row = tree["rows"][TARGET]
        if fault == "created":
            row["time"]["created"] += 1
        elif fault == "parent":
            row["parentID"] = "ses_foreign"
        elif fault == "project":
            row["projectID"] = "foreign"
        elif fault == "directory":
            row["location"] = {"directory": "/foreign"}
        else:
            row["time"]["archived"] = 101
        with pytest.raises(ContractError):
            await c.qualified_snapshot(GRANDCHILD)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fault", ["missing", "unknown", "reparented", "recreated"])
async def test_children_cannot_disappear_or_be_replaced_after_metadata_enrollment(fault):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        if fault == "missing":
            tree["edges"][CHILD] = []
        elif fault == "unknown":
            unknown = CHILD.model_copy(update={"upstream_session_id": "ses_unenrolled"})
            row = copy.deepcopy(tree["rows"][GRANDCHILD])
            row["id"] = unknown.upstream_session_id
            tree["rows"][unknown] = row
            tree["edges"][CHILD].append(unknown)
        elif fault == "reparented":
            tree["rows"][GRANDCHILD]["parentID"] = SIBLING.upstream_session_id
        else:
            tree["rows"][GRANDCHILD]["time"]["created"] += 1
        with pytest.raises(ContractError) as refused:
            await p.watch_graph(authorize=AsyncMock(return_value=True))
        # Only a subagent not yet connected is a retryable move; a child that
        # vanished, moved or was recreated stays a typed refusal.
        assert (type(refused.value) is SnapshotBoundaryChanged) is (fault == "unknown")
        assert all(p.certified_epoch(r, t.profile.sha256) is None for r in p._nodes)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_new_subagent_makes_a_watched_tree_snapshot_retryable_until_connected():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        unknown = CHILD.model_copy(update={"upstream_session_id": "ses_unenrolled"})
        row = copy.deepcopy(tree["rows"][GRANDCHILD])
        row["id"], row["parentID"] = unknown.upstream_session_id, TARGET.upstream_session_id
        tree["rows"][unknown] = row
        tree["edges"][TARGET].append(unknown)
        with pytest.raises(SnapshotBoundaryChanged, match="child_not_yet_connected"):
            await c.qualified_snapshot(TARGET)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_unknown_child_arrival_invalidates_a_complete_graph_before_filtered_payload_retention():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        raw = copy.deepcopy(REAL[0])
        raw["id"] = "evt_synthetic_new_child"
        raw = json.loads(json.dumps(raw).replace(REF.upstream_session_id, "ses_unenrolled_child"))
        assert p.feed.index.accept(frame(raw)) is None
        assert not p.valid_fence(TARGET, proof.resource_fence)
        with pytest.raises(ContractError):
            c.current(TARGET, proof)
        assert not p.feed.index._queue and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("located", [True, False])
async def test_another_projects_session_cannot_invalidate_this_complete_graph(located):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        raw = copy.deepcopy(next(e for e in REAL if ("location" in e) == located))
        raw["id"] = "evt_synthetic_other_project"
        raw = json.loads(json.dumps(raw).replace(REF.upstream_session_id, "ses_other_project"))
        if located:
            raw["location"] = {"directory": "/home/opencode/workspaces/another-project"}
        assert p.feed.index.accept(frame(raw)) is None
        # Another directory's arrival cannot be this tree's child; one without
        # a provable directory still might be.
        assert p.valid_fence(TARGET, proof.resource_fence) is located
        assert not p.feed.index._queue and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "field",
    ["backend_identity", "contract_sha256", "semantics", "installed_evidence_sha256", "operations"],
)
async def test_metadata_and_base_read_schema_never_supply_lineage_semantic_qualification(field):
    anchor, t, p, c, tree, state, writes, metadata = await setup()
    changes = {
        "backend_identity": "foreign",
        "contract_sha256": "0" * 64,
        "semantics": "not-the-lineage-semantics",
        "installed_evidence_sha256": "invalid",
        "operations": READS - {"session.list"},
    }
    try:
        fresh = await metadata.observe(TARGET, authorize=AsyncMock(return_value=True))
        with pytest.raises(ContractError):
            V2LineageResourceProofs(
                anchor.feed,
                anchor.projects,
                fresh,
                replace(p.lineage_attestation, **{field: changes[field]}),
                current=metadata.current,
            )
        assert not writes
    finally:
        await finish(anchor, t)


async def test_stale_or_copied_metadata_graph_cannot_initialize_a_resource_provider():
    anchor, t, p, c, tree, state, writes, metadata = await setup()
    try:
        with pytest.raises(ContractError, match="original_metadata"):
            V2LineageResourceProofs(
                anchor.feed,
                anchor.projects,
                p.observation.model_copy(),
                p.lineage_attestation,
                current=metadata.current,
            )
        assert not writes
    finally:
        await finish(anchor, t)


async def test_partial_watch_and_revocation_never_expose_complete_graph_execution():
    anchor, t, p, c, tree, state, writes, _ = await setup()

    async def authorize():
        return CHILD not in p._watched

    try:
        with pytest.raises(ContractError, match="authority"):
            await p.watch_graph(authorize=authorize)
        assert p.certified_epoch(TARGET, t.profile.sha256) is None
        assert not p._watched and not p._graph_proofs and not writes
    finally:
        await finish(anchor, t)


async def test_graph_proof_expires_at_initial_observation_instead_of_last_child_read(monkeypatch):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.lineage_resources.time.time", lambda: proof.expires_at
        )
        assert not p.valid_fence(TARGET, proof.resource_fence)
        with pytest.raises(ContractError):
            p.dispatch_owner_epoch(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_continuous_enrolled_parent_text_does_not_invent_child_activity_or_block_running_proof():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    state["active"][TARGET.upstream_session_id] = {"type": "running"}
    sequence = 0

    def hook(request, state):
        nonlocal sequence
        if request.url.path == "/api/session/" + TARGET.upstream_session_id:
            sequence += 1
            raw = json.loads(
                json.dumps(text_delta(f"evt_lineage_text_{sequence}")).replace(
                    REF.upstream_session_id, TARGET.upstream_session_id
                )
            )
            p.feed.index.accept(frame(raw))

    state["hook"] = hook
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        snapshot, proof = await c.qualified_snapshot(TARGET)
        assert snapshot.state == ExecutionState.RUNNING and sequence > 1
        c.current(TARGET, proof)
        child, child_proof = await c.qualified_snapshot(CHILD)
        assert child.state == ExecutionState.IDLE
        c.current(CHILD, child_proof)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("active", [CHILD, GRANDCHILD])
@pytest.mark.parametrize("change", ["idle_text", "pending", "settled", "unknown_child"])
async def test_idle_ancestor_keeps_each_descendants_qualified_text_boundary(active, change):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    state["active"][active.upstream_session_id] = {"type": "running"}
    sequence = 0

    def emit(reference):
        nonlocal sequence
        sequence += 1
        raw = json.loads(
            json.dumps(text_delta(f"evt_descendant_text_{sequence}")).replace(
                REF.upstream_session_id, reference.upstream_session_id
            )
        )
        p.feed.index.accept(frame(raw))

    def hook(request, state):
        # True feed activity between every authenticated GET, including the
        # first ancestor capture before descendants had a watch in the old order.
        emit(active)

    state["hook"] = hook
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        snapshot, proof = await c.qualified_snapshot(TARGET)
        assert snapshot.state == ExecutionState.IDLE and sequence > 10
        c.current(TARGET, proof)
        emit(active)
        c.current(TARGET, proof)
        with pytest.raises(ContractError, match="quiescent_graph"):
            p.dispatch_owner_epoch(TARGET, proof)

        if change == "idle_text":
            emit(TARGET)
        else:
            kind = "form.replied" if change == "settled" else "permission.asked"
            raw = copy.deepcopy(next(e for e in REAL if e["type"] == kind))
            raw = json.loads(
                json.dumps(raw).replace(
                    REF.upstream_session_id,
                    "ses_unenrolled_child"
                    if change == "unknown_child"
                    else active.upstream_session_id,
                )
            )
            p.feed.index.accept(frame(raw))
        assert not p.valid_fence(TARGET, proof.resource_fence)
        with pytest.raises(ContractError):
            c.current(TARGET, proof)
        assert not writes and all(r.method == "GET" for r in state["resource_calls"])
    finally:
        await finish(anchor, t)


async def test_running_ancestor_cannot_lend_active_text_qualification_to_idle_child():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    state["active"][TARGET.upstream_session_id] = {"type": "running"}
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        raw = json.loads(
            json.dumps(text_delta("evt_idle_child_text")).replace(
                REF.upstream_session_id, CHILD.upstream_session_id
            )
        )
        p.feed.index.accept(frame(raw))
        assert not p.valid_fence(TARGET, proof.resource_fence)
        with pytest.raises(ContractError):
            c.current(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_descendant_active_qualification_cannot_outlive_its_own_capture(monkeypatch):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    state["active"][CHILD.upstream_session_id] = {"type": "running"}
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        child = next(w for w in p._graph_proofs[TARGET][-1].witnesses if w.reference == CHILD)
        assert proof.issued_at <= child.issued_at < p.witnesses[TARGET].issued_at
        before = p.fence(TARGET)
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.lineage_resources.time.time",
            lambda: child.issued_at + 5,
        )
        assert p.fence(TARGET) != before
        assert not p.valid_fence(TARGET, proof.resource_fence)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_another_readers_proof_does_not_withdraw_a_proof_still_in_use():
    """Several readers can prove one tree Root at once. A new proof must not
    withdraw the previous one first, or a prompt checking its own proof finds it
    gone and is refused as "state changed" until it gives up, on an idle Root.
    """
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, first = await c.qualified_snapshot(TARGET)
        entered, release = asyncio.Event(), asyncio.Event()
        real_capture = p.capture

        async def capture(reference, expected_info_sha=None):
            if reference == TARGET:
                entered.set()
                await release.wait()
            return await real_capture(reference, expected_info_sha)

        p.capture = capture
        other = asyncio.create_task(c.qualified_snapshot(TARGET))
        await entered.wait()
        assert p.valid_fence(TARGET, first.resource_fence)
        c.current(TARGET, first)
        assert p.dispatch_owner_epoch(TARGET, first)
        release.set()
        _, second = await other
        assert p.current_proof(TARGET) == second
        assert p.proof_current(TARGET, first) and p.proof_current(TARGET, second)
        assert p.dispatch_owner_epoch(TARGET, first) == p.dispatch_owner_epoch(TARGET, second)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_a_failed_proof_withdraws_every_proof_issued_before_it():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, first = await c.qualified_snapshot(TARGET)
        real_capture = p.capture

        async def capture(reference, expected_info_sha=None):
            raise ContractError("leaf_resource_or_feed_boundary_changed")

        p.capture = capture
        with pytest.raises(ContractError):
            await c.qualified_snapshot(TARGET)
        p.capture = real_capture
        assert p.current_proof(TARGET) is None
        assert not p.valid_fence(TARGET, first.resource_fence)
        with pytest.raises(ContractError):
            p.dispatch_owner_epoch(TARGET, first)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_a_kept_proof_still_expires_and_still_follows_the_resources(monkeypatch):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, first = await c.qualified_snapshot(TARGET)
        _, second = await c.qualified_snapshot(TARGET)
        assert p.valid_fence(TARGET, first.resource_fence)
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.lineage_resources.time.time",
            lambda: first.expires_at,
        )
        assert not p.proof_current(TARGET, first)
        with pytest.raises(ContractError):
            p.dispatch_owner_epoch(TARGET, first)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("initially_active", [False, True])
async def test_descendant_new_resource_mode_invalidates_previous_ancestor_proof(initially_active):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    if initially_active:
        state["active"][CHILD.upstream_session_id] = {"type": "running"}
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        if initially_active:
            del state["active"][CHILD.upstream_session_id]
        else:
            state["active"][CHILD.upstream_session_id] = {"type": "running"}
        await c.qualified_snapshot(CHILD)
        assert not p.valid_fence(TARGET, proof.resource_fence)
        with pytest.raises(ContractError):
            c.current(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_readonly_child_scope_checks_ancestors_but_never_enrolls_execution():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        scope = await p.read_scope(GRANDCHILD)
        assert p.read_epoch(GRANDCHILD, t.profile.sha256) == scope.connection_epoch
        assert p.certified_epoch(GRANDCHILD, t.profile.sha256) is None
        tree["rows"][TARGET]["time"]["created"] += 1
        with pytest.raises(ContractError):
            await p.read_scope(GRANDCHILD)
        assert p.read_epoch(GRANDCHILD, t.profile.sha256) is None
        assert GRANDCHILD not in p._read_watched and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fault", ["owner", "task", "attestation", "enrollment", "semantic_pin"])
async def test_complete_graph_proof_cannot_survive_replaced_runtime_boundaries(fault):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await c.qualified_snapshot(TARGET)
        if fault == "owner":
            p.feed.index.owner_epoch = "b" * 64
        elif fault == "task":
            p.feed.task.cancel()
            await asyncio.gather(p.feed.task, return_exceptions=True)
        elif fault == "attestation":
            t.attestation = replace(t.attestation)
        elif fault == "enrollment":
            p.observation = p.observation.model_copy()
        else:
            p.lineage_attestation = replace(p.lineage_attestation)
        assert not p.valid_fence(TARGET, proof.resource_fence)
        with pytest.raises(ContractError):
            p.dispatch_owner_epoch(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_late_last_node_cannot_renew_the_shared_original_resource_deadline(monkeypatch):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        now = time.time()
        clock = [now]
        real_capture = p.capture

        async def capture(reference, expected_info_sha=None):
            result = await real_capture(reference, expected_info_sha)
            if reference == SIBLING:
                clock[0] = now + 5
            return result

        p.capture = capture
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.lineage_resources.time.time", lambda: clock[0]
        )
        with pytest.raises(ContractError):
            await c.qualified_snapshot(TARGET)
        assert TARGET not in p._graph_proofs and not writes
    finally:
        await finish(anchor, t)


async def test_cancelled_graph_watch_clears_all_partial_execution_membership():
    anchor, t, p, c, tree, state, writes, _ = await setup()
    entered, release = asyncio.Event(), asyncio.Event()
    real_capture = p.capture

    async def capture(reference, expected_info_sha=None):
        if reference == CHILD:
            entered.set()
            await release.wait()
        return await real_capture(reference, expected_info_sha)

    p.capture = capture
    task = asyncio.create_task(p.watch_graph(authorize=AsyncMock(return_value=True)))
    try:
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not p._watched and not p._graph_proofs and not writes
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await finish(anchor, t)
