"""Atomic in-process composition with synthetic peers, never Native authority."""

import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.session_graph_generations import PreparedGraphGeneration
from jt_oz_bridge.storage.durable import Conflict
from tests.integration.test_session_registration_extension import graph, grow
from tests.integration.test_session_registry import SECOND, THIRD, correlation, new_entry, pair
from tests.support import REF

CHILD = REF.model_copy(update={"upstream_session_id": "generation-child"})
GRANDCHILD = REF.model_copy(update={"upstream_session_id": "generation-grandchild"})


def add(old, name="generation-child", *, parent=None):
    enlarged = grow(old, name, parent=parent)
    return graph(enlarged.nodes, contract_sha256=INSTALLED_SCHEMA)


def bootstrap(registry, entries, root=REF):
    value = graph(
        [graph().nodes[0].model_copy(update={"reference": root})],
        contract_sha256=INSTALLED_SCHEMA,
    )
    enrollment = object()
    candidate = registry.prepare_generation(
        value,
        {root: entries[root]},
        expected=registry.publication.generation(root),
        enrollments={root: enrollment},
        context=object(),
        receipt=object(),
    )
    return registry.publish_generation(candidate)


def stage(registry, original, value=None):
    value = value or add(original.record)
    entries = dict(original.entries)
    policies = dict(original.enrollments)
    for node in value.nodes:
        if node.reference not in entries:
            entries[node.reference], policies[node.reference] = new_entry(node.reference), object()
    return registry.prepare_generation(
        value,
        entries,
        expected=original,
        enrollments=policies,
        context=object(),
        receipt=object(),
    )


def test_one_cell_publication_retains_all_readers_policies_and_stable_views():
    registry, originals = pair()
    publication = registry.publication
    sessions, projects = registry.sessions, registry.projects
    transcripts, metadata, live_text = registry.transcripts, registry.metadata, registry.live_text
    models, results, enrollments = registry.models, registry.results, publication.enrollments
    original = bootstrap(registry, originals)
    unrelated = publication.generation(SECOND)
    old = publication.snapshot()
    prepared = stage(registry, original)
    generation = prepared.generation
    assert publication.snapshot() is old and CHILD not in sessions
    assert CHILD not in enrollments and CHILD not in transcripts
    with pytest.raises(AccessDenied):
        registry.selected(CHILD)
    registry.publish_generation(prepared)
    assert publication.snapshot() is not old
    assert registry.sessions is sessions and registry.projects is projects
    assert registry.transcripts is transcripts and registry.metadata is metadata
    assert (
        registry.live_text is live_text
        and registry.models is models
        and registry.results is results
    )
    assert publication.enrollments is enrollments
    assert publication.current(REF, generation) and publication.current(CHILD, generation)
    assert not publication.current(REF, original) and publication.current(SECOND, unrelated)
    assert publication.generation(CHILD) is generation
    assert generation.parents[CHILD] == REF and generation.descendants[REF] == (CHILD,)
    assert generation.entries[REF] is originals[REF]
    assert generation.enrollments[REF] is original.enrollments[REF]
    for ref, entry in generation.entries.items():
        assert registry.selected(ref) is entry
        assert entry.execution is generation.entries[ref].execution
        assert entry.models is generation.entries[ref].models
        assert entry.results is generation.entries[ref].results
        if entry.transcript:
            assert transcripts[ref] is entry.transcript
        if entry.metadata:
            assert metadata[ref] is entry.metadata
    for mapping in (generation.parents, generation.entries, generation.enrollments, old.sessions):
        with pytest.raises(TypeError):
            mapping[REF] = None
    assert all(not entry.execution.submitted for entry in registry.sessions.values())


def test_child_grandchild_growth_preserves_every_original_and_unrelated_root_token():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    first = registry.publish_generation(stage(registry, original))
    other = bootstrap(registry, originals, SECOND)
    prepared = stage(registry, first, add(first.record, "generation-grandchild", parent=CHILD))
    final = registry.publish_generation(prepared)
    assert final.descendants[REF] == (CHILD, GRANDCHILD)
    assert final.descendants[CHILD] == (GRANDCHILD,)
    for ref, entry in first.entries.items():
        assert final.entries[ref] is entry
        assert final.enrollments[ref] is first.enrollments[ref]
    assert registry.publication.current(SECOND, other)
    assert not registry.publication.current(CHILD, first)


def test_competing_prepared_generations_cannot_publish_a_prefix_or_stale_head():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    a = stage(registry, original)
    b = stage(registry, original, add(original.record, "competing-child"))
    assert registry.publication.generation(REF) is original
    registry.publish_generation(a)
    with pytest.raises(Conflict, match="predecessor_changed"):
        registry.publish_generation(b)
    assert "competing-child" not in {ref.upstream_session_id for ref in registry.sessions}
    assert registry.publication.generation(REF) is a.generation
    with pytest.raises(Conflict, match="not_issued"):
        registry.publish_generation(a)


def test_candidate_is_cell_issued_not_forgeable_by_copy_or_other_registry():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    candidate = stage(registry, original)
    with pytest.raises(Conflict, match="not_issued"):
        registry.publish_generation(replace(candidate))
    foreign, _ = pair()
    with pytest.raises(Conflict, match="not_issued"):
        foreign.publish_generation(candidate)
    fabricated = PreparedGraphGeneration(candidate.generation, candidate._base, candidate._next)
    with pytest.raises(Conflict, match="not_issued"):
        registry.publish_generation(fabricated)
    assert registry.publication.generation(REF) is original


@pytest.mark.parametrize(
    "fault",
    [
        "entry",
        "policy",
        "parent",
        "removed",
        "old_policy",
        "contract",
        "qualification",
        "baseline_add",
    ],
)
def test_strict_identity_changes_never_publish_or_expose_candidate(fault):
    registry, originals = pair()
    if fault == "baseline_add":
        original = registry.publication.generation(REF)
        value = add(graph(contract_sha256=INSTALLED_SCHEMA))
        entries, policies = (
            {REF: originals[REF], CHILD: new_entry(CHILD)},
            {REF: object(), CHILD: object()},
        )
    else:
        original = bootstrap(registry, originals)
        first = registry.publish_generation(stage(registry, original))
        original = first
        value = add(first.record, "generation-grandchild", parent=CHILD)
        entries, policies = (
            dict(first.entries) | {GRANDCHILD: new_entry(GRANDCHILD)},
            dict(first.enrollments) | {GRANDCHILD: object()},
        )
        if fault == "entry":
            entries[REF] = new_entry(REF)
        elif fault == "policy":
            policies[REF] = object()
        elif fault == "parent":
            value = graph(
                [
                    node.model_copy(
                        update={
                            "parent_reference": GRANDCHILD,
                            "parent_created_at": value.nodes[-1].native_created_at,
                        }
                    )
                    if node.reference == CHILD
                    else node.model_copy(
                        update={
                            "parent_reference": REF,
                            "parent_created_at": value.nodes[0].native_created_at,
                        }
                    )
                    if node.reference == GRANDCHILD
                    else node
                    for node in value.nodes
                ],
                contract_sha256=INSTALLED_SCHEMA,
            )
        elif fault == "removed":
            value = graph(
                [
                    value.nodes[0],
                    value.nodes[-1].model_copy(
                        update={
                            "parent_reference": REF,
                            "parent_created_at": value.nodes[0].native_created_at,
                        }
                    ),
                ],
                contract_sha256=INSTALLED_SCHEMA,
            )
            entries.pop(CHILD)
            policies.pop(CHILD)
        elif fault == "old_policy":
            value = graph(
                [value.nodes[0].model_copy(update={"policy_sha256": "f" * 64}), *value.nodes[1:]],
                contract_sha256=INSTALLED_SCHEMA,
            )
        elif fault == "contract":
            value = value.model_copy(update={"contract_sha256": "f" * 64})
        else:
            value = value.model_copy(update={"qualification_sha256": "f" * 64})
    before = registry.publication.snapshot()
    with pytest.raises((AccessDenied, Conflict)):
        registry.prepare_generation(value, entries, expected=original, enrollments=policies)
    assert registry.publication.snapshot() is before
    assert GRANDCHILD not in registry.sessions


@pytest.mark.parametrize(
    "fault", ["overlap", "alias", "project", "incomplete_enrollment", "late_other_root"]
)
def test_backend_scope_alias_complete_enrollment_and_late_head_are_enforced(fault):
    registry, originals = pair()
    original = bootstrap(registry, originals)
    if fault == "late_other_root":
        candidate = stage(registry, original)
        bootstrap(registry, originals, SECOND)
        with pytest.raises(Conflict, match="predecessor_changed"):
            registry.publish_generation(candidate)
        assert registry.publication.current(REF, original)
        return
    value = add(original.record)
    entries = dict(original.entries) | {CHILD: new_entry(CHILD)}
    policies = dict(original.enrollments) | {CHILD: object()}
    if fault in {"overlap", "alias", "project"}:
        child = value.nodes[-1]
        reference = (
            SECOND
            if fault == "overlap"
            else CHILD.model_copy(
                update={
                    "upstream_session_id": SECOND.upstream_session_id,
                    "project_id": "alias-project",
                }
            )
            if fault == "alias"
            else CHILD.model_copy(update={"project_id": "foreign-project"})
        )
        value = value.model_copy(
            update={"nodes": (value.nodes[0], child.model_copy(update={"reference": reference}))}
        )
        entries.pop(CHILD)
        policies.pop(CHILD)
        entries[reference], policies[reference] = (
            originals[SECOND] if fault == "overlap" else new_entry(reference),
            object(),
        )
    else:
        policies.pop(CHILD)
    before = registry.publication.snapshot()
    with pytest.raises((AccessDenied, Conflict, ValueError)):
        registry.prepare_generation(value, entries, expected=original, enrollments=policies)
    assert registry.publication.snapshot() is before


@pytest.mark.parametrize("operation", ["snapshot", "pending", "models", "submit", "results"])
async def test_inflight_async_read_or_post_cannot_keep_old_generation(operation):
    registry, originals = pair()
    original = bootstrap(registry, originals)
    candidate = stage(registry, original)
    entered, release = asyncio.Event(), asyncio.Event()
    entry = originals[REF]
    target, method = (
        (entry.execution, operation)
        if operation in {"snapshot", "submit"}
        else (entry.models, "read")
        if operation == "models"
        else (entry.results, "capture")
        if operation == "results"
        else (entry, "pending")
    )
    original_method = getattr(target, method)

    async def blocked(*args):
        value = await original_method(*args)
        entered.set()
        await release.wait()
        return value

    if operation == "pending":
        # RegisteredSession is frozen; its callable peer remains mutable.
        entry.pending.side_effect = blocked_pending = AsyncMock(return_value=())

        async def pending_block(*args):
            entered.set()
            await release.wait()
            return await blocked_pending(*args)

        entry.pending.side_effect = pending_block
    else:
        setattr(target, method, blocked)
    call = (
        registry.snapshot(REF)
        if operation == "snapshot"
        else registry.pending(REF)
        if operation == "pending"
        else registry.models.read(REF)
        if operation == "models"
        else registry.results.capture(correlation(REF, "generation-result"))
        if operation == "results"
        else registry.submit(REF, {"operation": "prompt"}, "already-sent-once")
    )
    task = asyncio.create_task(call)
    try:
        await entered.wait()
        registry.publish_generation(candidate)
        release.set()
        with pytest.raises(Conflict, match="generation_changed"):
            await task
        assert len(entry.execution.submitted) == (1 if operation == "submit" else 0)
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_results_captured_before_publication_expire_only_for_changed_root():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    a = await registry.results.capture(correlation(REF, "a"))
    b = await registry.results.capture(correlation(SECOND, "b"))
    registry.publish_generation(stage(registry, original))
    assert not registry.results.current(a)
    assert registry.results.current(b)


def test_total_backend_cap_1000_includes_unrelated_root_and_all_new_children():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    base = original.record
    nodes = [*base.nodes, *(add(base, f"capacity-{i}").nodes[-1] for i in range(998))]
    value = graph(nodes, contract_sha256=INSTALLED_SCHEMA)
    first = registry.publish_generation(stage(registry, original, value))
    assert len(registry.sessions) == 1000 and len(first.entries) == 999
    larger = add(first.record, "one-too-many-backend-node")
    with pytest.raises(Conflict, match="capacity_reached"):
        stage(registry, first, larger)
    assert len(registry.sessions) == 1000


def test_detached_candidates_have_bounded_issuance_and_do_not_grow_active_graph():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    candidates = [stage(registry, original) for _ in range(1000)]
    with pytest.raises(Conflict, match="candidate_capacity"):
        stage(registry, original)
    assert len(candidates) == 1000 and CHILD not in registry.sessions


async def test_legacy_leaf_readoption_reuses_current_parent_generation_without_splitting_root():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    current = registry.publish_generation(stage(registry, original))
    await registry.adopt(current.entries[CHILD], authorize=AsyncMock(return_value=True))
    assert registry.publication.generation(CHILD) is current
    assert registry.publication.generation(REF) is current
    assert registry.publication.snapshot().roots.keys() == {REF, SECOND}


@pytest.mark.parametrize("failure", ["late_head", "cancel_after_journal", "revoke_after_journal"])
async def test_legacy_controller_hooks_cannot_publish_stale_or_partially_visible_graph(failure):
    registry, originals = pair()
    other = graph(
        [graph().nodes[0].model_copy(update={"reference": SECOND})],
        contract_sha256=INSTALLED_SCHEMA,
    )
    late = registry.prepare_generation(
        other,
        {SECOND: originals[SECOND]},
        expected=registry.publication.generation(SECOND),
        enrollments={SECOND: object()},
    )
    entry = new_entry(THIRD)
    before = registry.reference_snapshot()
    calls = 0

    async def authorize():
        nonlocal calls
        calls += 1
        assert THIRD not in registry.sessions and THIRD not in registry.transcripts
        return not (failure == "revoke_after_journal" and calls >= 3)

    async def before_commit():
        assert registry.reference_snapshot() == before
        if failure == "cancel_after_journal":
            raise asyncio.CancelledError()
        if failure == "late_head":
            registry.publish_generation(late)

    with pytest.raises(
        asyncio.CancelledError if failure == "cancel_after_journal" else (Conflict, AccessDenied)
    ):
        await registry.adopt_graph(
            THIRD,
            {THIRD: entry},
            {THIRD: None},
            authorize=authorize,
            current=lambda: True,
            before_commit=before_commit,
        )
    assert THIRD not in registry.sessions and THIRD not in registry.metadata
    assert registry.sessions[REF] is originals[REF]


def test_same_native_id_alias_in_another_enrolled_project_is_rejected_without_dto_shortcut():
    from jt_oz_bridge.services.session_registry import SessionRegistry

    another = SECOND.model_copy(
        update={"project_id": "second-project", "canonical_directory": "/second-project"}
    )
    entries = {REF: new_entry(REF), another: new_entry(another)}
    registry = SessionRegistry(entries)
    alias = another.model_copy(update={"upstream_session_id": REF.upstream_session_id})
    value = graph(
        [graph().nodes[0].model_copy(update={"reference": alias})], contract_sha256=INSTALLED_SCHEMA
    )
    assert value.root == alias  # Fully valid graph, not a forged graph digest.
    with pytest.raises(AccessDenied):
        registry.prepare_generation(
            value, {alias: new_entry(alias)}, expected=None, enrollments={alias: object()}
        )
    assert registry.reference_snapshot() == (REF, another)


def test_explicit_bootstrap_uses_independent_original_node_and_live_guard_without_fake_leaf_record():
    registry, originals = pair()
    original_node = graph().nodes[0]
    actual_graph = add(graph(contract_sha256=INSTALLED_SCHEMA))
    legacy = registry.publication.generation(REF)

    def original_guard():
        return True  # Explicit synthetic qualification, not Native proof.

    entries = {REF: originals[REF], CHILD: new_entry(CHILD)}
    policies = {REF: object(), CHILD: object()}
    prepared = registry.prepare_bootstrap_generation(
        actual_graph,
        entries,
        expected=legacy,
        original_nodes={REF: original_node},
        baseline_current=original_guard,
        enrollments=policies,
    )
    assert prepared.baseline_current is original_guard
    assert registry.publication.generation(REF) is legacy and CHILD not in registry.sessions
    generation = registry.publish_generation(prepared)
    assert generation.record == actual_graph and generation.entries[REF] is originals[REF]
    assert generation.enrollments[REF] is policies[REF]


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "created",
        "policy",
        "parent",
        "false",
        "truthy",
        "async",
        "cancel",
        "late_head",
        "overlap",
        "replaced_entry",
    ],
)
def test_explicit_bootstrap_rejects_unproved_original_nodes_or_wrong_current_guard(fault):
    registry, originals = pair()
    original = graph().nodes[0]
    value = add(graph(contract_sha256=INSTALLED_SCHEMA))
    baseline = {REF: original}
    entries = {REF: originals[REF], CHILD: new_entry(CHILD)}
    policies = {REF: object(), CHILD: object()}
    legacy = registry.publication.generation(REF)

    def guard():
        if fault == "cancel":
            raise asyncio.CancelledError()
        if fault == "late_head":
            bootstrap(registry, originals, SECOND)
        return False if fault == "false" else 1 if fault == "truthy" else True

    async def invalid_async_guard():
        return True

    if fault == "missing":
        baseline.clear()
    elif fault == "created":
        baseline[REF] = original.model_copy(update={"native_created_at": 124})
    elif fault == "policy":
        baseline[REF] = original.model_copy(update={"policy_sha256": "f" * 64})
    elif fault == "parent":
        baseline[REF] = original.model_copy(
            update={
                "parent_reference": CHILD,
                "parent_created_at": value.nodes[-1].native_created_at,
            }
        )
    elif fault == "overlap":
        value = graph(
            [value.nodes[0], value.nodes[-1].model_copy(update={"reference": SECOND})],
            contract_sha256=INSTALLED_SCHEMA,
        )
        entries, policies = (
            {REF: originals[REF], SECOND: originals[SECOND]},
            {REF: object(), SECOND: object()},
        )
    elif fault == "replaced_entry":
        entries[REF] = new_entry(REF)
    with pytest.raises(asyncio.CancelledError if fault == "cancel" else (Conflict, AccessDenied)):
        registry.prepare_bootstrap_generation(
            value,
            entries,
            expected=legacy,
            original_nodes=baseline,
            baseline_current=invalid_async_guard if fault == "async" else guard,
            enrollments=policies,
        )
    assert registry.publication.generation(REF) is legacy and CHILD not in registry.sessions


def test_bind_receipt_keeps_early_cas_and_every_original_resource_or_context_object():
    registry, originals = pair()
    original = bootstrap(registry, originals)
    candidate = stage(registry, original)
    receipt = object()
    bound = registry.bind_receipt(candidate, receipt)
    old, new = candidate.generation, bound.generation
    assert bound._base is candidate._base and registry.publication.generation(REF) is original
    for field in ("root", "record", "entries", "parents", "descendants", "enrollments", "context"):
        assert getattr(new, field) is getattr(old, field)
    assert new.receipt is receipt
    assert bound._next.sessions is candidate._next.sessions
    assert bound._next.enrollments is candidate._next.enrollments
    with pytest.raises(Conflict, match="not_issued"):
        registry.publish_generation(candidate)
    registry.publish_generation(bound)
    assert registry.publication.generation(CHILD) is new
    assert registry.selected(REF) is originals[REF]


@pytest.mark.parametrize(
    "fault", ["copy", "consumed", "late_head", "competing_receipt", "already_published"]
)
def test_binding_receipt_cannot_reissue_forged_consumed_or_late_candidate(fault):
    registry, originals = pair()
    original = bootstrap(registry, originals)
    candidate = stage(registry, original)
    expected = "not_issued"
    if fault == "copy":
        candidate = replace(candidate)
    elif fault == "consumed":
        bound = registry.bind_receipt(candidate, object())
        with pytest.raises(Conflict, match="not_issued"):
            registry.publish_generation(candidate)
        assert bound.generation.record == candidate.generation.record
    elif fault == "late_head":
        bootstrap(registry, originals, SECOND)
        expected = "predecessor_changed"
    elif fault == "competing_receipt":
        first = registry.bind_receipt(candidate, object())
        assert first.generation.entries[REF] is originals[REF]
    else:
        registry.publish_generation(candidate)
    before = registry.publication.snapshot()
    with pytest.raises(Conflict, match=expected):
        registry.bind_receipt(candidate, object())
    assert registry.publication.snapshot() is before


@pytest.mark.parametrize("resource", ["transcript", "metadata"])
def test_new_candidate_resource_contract_drift_is_not_hidden_by_generation_metadata(resource):
    registry, originals = pair()
    original = bootstrap(registry, originals)
    value = add(original.record)
    child = new_entry(CHILD)
    getattr(child, resource).contract_for = lambda ref: "f" * 64
    with pytest.raises(AccessDenied):
        registry.prepare_generation(
            value,
            dict(original.entries) | {CHILD: child},
            expected=original,
            enrollments=dict(original.enrollments) | {CHILD: object()},
        )
    assert registry.publication.generation(REF) is original and CHILD not in registry.sessions


async def test_pending_interaction_preview_cannot_return_old_root_generation_after_await():
    from jt_oz_bridge.domain.control import InteractionSnapshot

    registry, originals = pair()
    original = bootstrap(registry, originals)
    prepared = stage(registry, original)
    entered, release = asyncio.Event(), asyncio.Event()

    async def preview(reference, request_id):
        entered.set()
        await release.wait()
        return InteractionSnapshot(
            reference=reference,
            upstream_request_id=request_id,
            generation="synthetic-original-preview",
            description="fixture only",
            kind="form",
            pending=True,
        )

    originals[REF].execution.interaction = preview
    task = asyncio.create_task(registry.interaction(REF, "same-request-id"))
    try:
        await entered.wait()
        registry.publish_generation(prepared)
        release.set()
        with pytest.raises(Conflict, match="generation_changed"):
            await task
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def test_bootstrap_guard_contract_change_after_validation_does_not_issue_routable_candidate():
    registry, originals = pair()
    value = add(graph(contract_sha256=INSTALLED_SCHEMA))
    entries = {REF: originals[REF], CHILD: new_entry(CHILD)}

    def guard():
        entries[CHILD].execution.contract_hash = "f" * 64
        return True

    with pytest.raises(AccessDenied):
        registry.prepare_bootstrap_generation(
            value,
            entries,
            expected=registry.publication.generation(REF),
            original_nodes={REF: graph().nodes[0]},
            baseline_current=guard,
            enrollments={REF: object(), CHILD: object()},
        )
    assert CHILD not in registry.sessions and registry.publication.generation(REF).record is None


def test_stale_or_foreign_bootstrap_predecessor_does_not_call_original_guard():
    registry, originals = pair()
    legacy = registry.publication.generation(REF)
    bootstrap(registry, originals)
    guard = AsyncMock(return_value=True)
    value = add(graph(contract_sha256=INSTALLED_SCHEMA))
    with pytest.raises(Conflict, match="predecessor_changed"):
        registry.prepare_bootstrap_generation(
            value,
            {REF: originals[REF], CHILD: new_entry(CHILD)},
            expected=legacy,
            original_nodes={REF: graph().nodes[0]},
            baseline_current=guard,
            enrollments={REF: object(), CHILD: object()},
        )
    guard.assert_not_called()


def test_explicit_refresh_changes_only_observation_context_and_receipt_with_original_entries():
    registry, originals = pair()
    initial = bootstrap(registry, originals)
    original = registry.publish_generation(stage(registry, initial))
    refreshed = graph(
        original.record.nodes, contract_sha256=INSTALLED_SCHEMA, observed_owner_epoch="e" * 64
    )
    unrelated = registry.publication.generation(SECOND)
    prepared = registry.prepare_refresh_generation(
        refreshed,
        original.entries,
        expected=original,
        enrollments=original.enrollments,
        context=object(),
    )
    receipt = object()
    prepared = registry.bind_receipt(prepared, receipt)
    assert registry.publication.generation(REF) is original
    result = registry.publish_generation(prepared)
    assert result.record == refreshed and result.receipt is receipt
    assert all(result.entries[ref] is entry for ref, entry in original.entries.items())
    assert all(result.enrollments[ref] is entry for ref, entry in original.enrollments.items())
    assert not registry.publication.current(REF, original)
    assert registry.publication.current(SECOND, unrelated)


@pytest.mark.parametrize(
    "fault",
    [
        "created",
        "policy",
        "qualification",
        "contract",
        "missing",
        "new_entry",
        "new_enrollment",
        "late_head",
    ],
)
def test_refresh_cannot_change_original_identity_or_bypass_early_backend_cas(fault):
    registry, originals = pair()
    original = registry.publish_generation(stage(registry, bootstrap(registry, originals)))
    value = graph(original.record.nodes, contract_sha256=INSTALLED_SCHEMA)
    entries, policies = dict(original.entries), dict(original.enrollments)
    if fault in {"created", "policy"}:
        last = value.nodes[-1].model_copy(
            update={"native_created_at": 999} if fault == "created" else {"policy_sha256": "f" * 64}
        )
        value = graph([value.nodes[0], last], contract_sha256=INSTALLED_SCHEMA)
    elif fault in {"qualification", "contract"}:
        value = value.model_copy(update={fault + "_sha256": "f" * 64})
    elif fault == "missing":
        value = graph([value.nodes[0]], contract_sha256=INSTALLED_SCHEMA)
        entries.pop(CHILD)
        policies.pop(CHILD)
    elif fault == "new_entry":
        entries[CHILD] = new_entry(CHILD)
    elif fault == "new_enrollment":
        policies[CHILD] = object()
    if fault == "late_head":
        candidate = registry.prepare_refresh_generation(
            value, entries, expected=original, enrollments=policies
        )
        bootstrap(registry, originals, SECOND)
        with pytest.raises(Conflict, match="predecessor_changed"):
            registry.publish_generation(candidate)
    else:
        with pytest.raises((Conflict, AccessDenied)):
            registry.prepare_refresh_generation(
                value, entries, expected=original, enrollments=policies
            )
    assert registry.publication.generation(REF) is original
