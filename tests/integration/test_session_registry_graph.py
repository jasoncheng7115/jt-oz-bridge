"""Atomic registry graphs with synthetic execution peers, not Native acceptance."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.enrollment_views import enrollment_union
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.storage.durable import Conflict
from tests.integration.test_session_registry import THIRD, new_entry, pair

ROOT = THIRD
CHILD = ROOT.model_copy(update={"upstream_session_id": "existing-child"})
GRANDCHILD = ROOT.model_copy(update={"upstream_session_id": "existing-grandchild"})
SIBLING = ROOT.model_copy(update={"upstream_session_id": "existing-sibling"})


async def graph():
    registry, originals = pair()
    parents = {ROOT: None, CHILD: ROOT, GRANDCHILD: CHILD, SIBLING: ROOT}
    descendants = {
        ROOT: (CHILD, GRANDCHILD, SIBLING),
        CHILD: (GRANDCHILD,),
        GRANDCHILD: (),
        SIBLING: (),
    }
    entries = {reference: new_entry(reference) for reference in parents}
    for reference, entry in entries.items():
        old = await entry.execution.snapshot(reference)
        entry.execution.snapshot = AsyncMock(
            return_value=old.model_copy(update={"descendants": descendants[reference]})
        )
    return registry, originals, entries, parents


async def test_complete_original_graph_appears_once_with_all_readers_and_original_routes_preserved():
    registry, originals, entries, parents = await graph()
    projection = enrollment_union([registry.transcripts])
    before = registry.reference_snapshot()
    checks = []

    async def authorize():
        assert registry.reference_snapshot() == before
        assert not set(entries) & set(registry.metadata)
        return True

    def current():
        assert registry.reference_snapshot() == before
        checks.append("all-original-proofs-current")
        return True

    await registry.adopt_graph(ROOT, entries, parents, authorize=authorize, current=current)
    assert checks == ["all-original-proofs-current"]
    assert registry.reference_snapshot() == before + tuple(entries)
    assert all(registry.selected(ref) is entry for ref, entry in entries.items())
    assert all(projection[ref] is entry.transcript for ref, entry in entries.items())
    assert all(registry.metadata[ref] is entry.metadata for ref, entry in entries.items())
    assert all(registry.sessions[ref] is entry for ref, entry in originals.items())
    assert set((await registry.snapshot(ROOT)).descendants) == set(entries) - {ROOT}
    assert all(not entry.execution.submitted for entry in [*entries.values(), *originals.values()])


@pytest.mark.parametrize(
    "fault",
    ["missing_root", "missing_parent", "cycle", "second_root", "key_mismatch", "foreign_scope"],
)
async def test_incomplete_or_foreign_lineage_is_rejected_before_any_reader_or_authority(fault):
    registry, originals, entries, parents = await graph()
    if fault == "missing_root":
        entries.pop(ROOT)
    elif fault == "missing_parent":
        parents[CHILD] = ROOT.model_copy(update={"upstream_session_id": "absent"})
    elif fault == "cycle":
        parents[CHILD] = GRANDCHILD
    elif fault == "second_root":
        parents[CHILD] = None
    elif fault == "key_mismatch":
        entries[CHILD] = new_entry(SIBLING)
    else:
        foreign = ROOT.model_copy(
            update={"upstream_session_id": "foreign", "canonical_directory": "/other"}
        )
        entries[foreign], parents[foreign] = new_entry(foreign), ROOT
    authorize = AsyncMock(return_value=True)
    with pytest.raises((AccessDenied, Conflict)):
        await registry.adopt_graph(
            ROOT, entries, parents, authorize=authorize, current=lambda: True
        )
    authorize.assert_not_awaited()
    assert registry.reference_snapshot() == tuple(originals)
    assert all(
        entry.execution.snapshot.await_count == 0
        for entry in entries.values()
        if isinstance(entry.execution.snapshot, AsyncMock)
    )


@pytest.mark.parametrize(
    "fault",
    [
        "unreconciled",
        "unknown",
        "disconnected",
        "wrong_reference",
        "missing_descendant",
        "duplicate_descendant",
        "foreign_descendant",
        "wrong_subtree",
    ],
)
async def test_every_node_requires_exact_complete_recursive_current_resources(fault):
    registry, originals, entries, parents = await graph()
    entry = entries[CHILD]
    good = entry.execution.snapshot.return_value
    update = {
        "unreconciled": {"reconciled": False},
        "unknown": {"state": ExecutionState.UNKNOWN},
        "disconnected": {"state": ExecutionState.DISCONNECTED},
        "wrong_reference": {"reference": ROOT},
        "missing_descendant": {"descendants": ()},
        "duplicate_descendant": {"descendants": (GRANDCHILD, GRANDCHILD)},
        "foreign_descendant": {
            "descendants": (ROOT.model_copy(update={"upstream_session_id": "outside"}),)
        },
        "wrong_subtree": {"descendants": (SIBLING,)},
    }[fault]
    entry.execution.snapshot.return_value = good.model_copy(update=update)
    with pytest.raises(Conflict, match="snapshot_not_complete"):
        await registry.adopt_graph(
            ROOT, entries, parents, authorize=AsyncMock(return_value=True), current=lambda: True
        )
    assert registry.reference_snapshot() == tuple(originals)
    assert not set(entries) & set(registry.transcripts)


@pytest.mark.parametrize(
    "revoke",
    ["before_reads", "after_one_node", "final_source", "final_resource", "truthy_resource"],
)
async def test_source_revocation_or_final_resource_change_leaves_no_partial_graph(revoke):
    registry, originals, entries, parents = await graph()

    async def authorize():
        done = sum(entry.execution.snapshot.await_count for entry in entries.values())
        return not (
            revoke == "before_reads"
            or revoke == "after_one_node"
            and done >= 1
            or revoke == "final_source"
            and done == len(entries)
        )

    def current():
        return False if revoke == "final_resource" else 1 if revoke == "truthy_resource" else True

    with pytest.raises((AccessDenied, Conflict)):
        await registry.adopt_graph(ROOT, entries, parents, authorize=authorize, current=current)
    assert registry.reference_snapshot() == tuple(originals)
    assert not set(entries) & set(registry.metadata)


async def test_cancellation_during_child_proof_never_publishes_parent_or_sibling():
    registry, originals, entries, parents = await graph()
    entered, release = asyncio.Event(), asyncio.Event()

    async def blocked(reference):
        entered.set()
        await release.wait()
        return entries[CHILD].execution.snapshot.return_value

    entries[CHILD].execution.snapshot.side_effect = blocked
    task = asyncio.create_task(
        registry.adopt_graph(
            ROOT, entries, parents, authorize=AsyncMock(return_value=True), current=lambda: True
        )
    )
    try:
        await entered.wait()
        assert registry.reference_snapshot() == tuple(originals)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert registry.reference_snapshot() == tuple(originals)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_current_binding_graph_entries_can_be_reused_but_never_replaced():
    registry, originals, entries, parents = await graph()
    await registry.adopt_graph(
        ROOT, entries, parents, authorize=AsyncMock(return_value=True), current=lambda: True
    )
    await registry.adopt_graph(
        ROOT, entries, parents, authorize=AsyncMock(return_value=True), current=lambda: True
    )
    original = registry.selected(CHILD)
    entries[CHILD] = new_entry(CHILD)
    with pytest.raises(Conflict, match="cannot_be_replaced"):
        await registry.adopt_graph(
            ROOT, entries, parents, authorize=AsyncMock(return_value=True), current=lambda: True
        )
    assert registry.selected(CHILD) is original


async def test_two_competing_complete_graphs_cannot_mix_their_readers():
    registry, originals, first, parents = await graph()
    _, _, second, _ = await graph()
    results = await asyncio.gather(
        registry.adopt_graph(
            ROOT, first, parents, authorize=AsyncMock(return_value=True), current=lambda: True
        ),
        registry.adopt_graph(
            ROOT, second, parents, authorize=AsyncMock(return_value=True), current=lambda: True
        ),
        return_exceptions=True,
    )
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, Conflict) for result in results) == 1
    selected = first if registry.sessions[ROOT] is first[ROOT] else second
    assert all(registry.sessions[ref] is entry for ref, entry in selected.items())
    assert all(registry.sessions[ref] is entry for ref, entry in originals.items())


async def test_authority_callback_cannot_change_the_supplied_parent_mapping_after_validation():
    registry, originals, entries, parents = await graph()

    async def authorize():
        parents[CHILD] = SIBLING
        entries.clear()
        return True

    expected = dict(entries)
    await registry.adopt_graph(ROOT, entries, parents, authorize=authorize, current=lambda: True)
    assert all(registry.sessions[ref] is entry for ref, entry in expected.items())


async def test_contract_drift_at_final_source_check_still_prevents_all_registrations():
    registry, originals, entries, parents = await graph()

    async def authorize():
        done = sum(entry.execution.snapshot.await_count for entry in entries.values())
        if done == len(entries):
            entries[GRANDCHILD].execution.contract_hash = "b" * 64
        return True

    with pytest.raises(AccessDenied):
        await registry.adopt_graph(
            ROOT, entries, parents, authorize=authorize, current=lambda: True
        )
    assert registry.reference_snapshot() == tuple(originals)


async def test_total_registry_capacity_includes_originals_and_the_whole_new_graph():
    registry, originals = pair()
    entries = {ROOT: new_entry(ROOT)}
    parents = {ROOT: None}
    for index in range(998):
        ref = ROOT.model_copy(update={"upstream_session_id": f"existing_capacity_{index}"})
        entries[ref], parents[ref] = new_entry(ref), ROOT
    authority = AsyncMock(return_value=True)
    with pytest.raises(Conflict, match="capacity_reached"):
        await registry.adopt_graph(
            ROOT, entries, parents, authorize=authority, current=lambda: True
        )
    authority.assert_not_awaited()
    assert registry.reference_snapshot() == tuple(originals)


async def test_final_sync_callback_does_not_bypass_original_contract_checks():
    registry, originals, entries, parents = await graph()

    def current():
        entries[GRANDCHILD].execution.contract_hash = "b" * 64
        return True

    with pytest.raises(AccessDenied):
        await registry.adopt_graph(
            ROOT, entries, parents, authorize=AsyncMock(return_value=True), current=current
        )
    assert registry.reference_snapshot() == tuple(originals)
