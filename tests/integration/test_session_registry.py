"""Independent original Roots in one synthetic backend, with real own DB state."""

import asyncio
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation
from jt_oz_bridge.domain.control import ExecutionState, InteractionSnapshot
from jt_oz_bridge.domain.enrollment_views import enrollment_union
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.resource_execution_results import ResourceResultCollector
from jt_oz_bridge.services.resource_history import ResourceHistory
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_model_commands import Catalog
from tests.integration.test_resource_execution_results import Reader
from tests.integration.test_router import Source, message
from tests.support import REF, SyntheticAudience, service

SECOND = REF.model_copy(update={"upstream_session_id": "second-original-session"})
THIRD = REF.model_copy(update={"upstream_session_id": "new-original-session"})


def pair():
    entries = {}
    for ref in (REF, SECOND):
        execution = SyntheticExecution()
        execution.ref = ref
        execution.contract_hash = INSTALLED_SCHEMA
        pending = AsyncMock(return_value=("pending:" + ref.upstream_session_id,))
        entries[ref] = RegisteredSession(
            ref, INSTALLED_SCHEMA, execution, Catalog(ref, INSTALLED_SCHEMA), Reader(), pending
        )
    return SessionRegistry(entries), entries


def new_entry(ref=THIRD):
    execution = SyntheticExecution()
    execution.ref, execution.contract_hash = ref, INSTALLED_SCHEMA
    resource = SimpleNamespace(contract_for=lambda selected: INSTALLED_SCHEMA)
    return RegisteredSession(
        ref,
        INSTALLED_SCHEMA,
        execution,
        Catalog(ref, INSTALLED_SCHEMA),
        Reader(),
        AsyncMock(return_value=()),
        transcript=resource,
        metadata=resource,
    )


async def test_authorized_adoption_atomically_exposes_all_readers_and_preserves_originals():
    registry, entries = pair()
    candidate = new_entry()
    history, metadata = registry.transcripts, registry.metadata
    combined = enrollment_union([history])
    assert THIRD not in registry.sessions and THIRD not in history and THIRD not in metadata
    authorize = AsyncMock(return_value=True)
    await registry.adopt(candidate, authorize=authorize)
    assert authorize.await_count == 2
    assert registry.selected(THIRD) is candidate
    assert combined[THIRD] is history[THIRD] is candidate.transcript
    assert metadata[THIRD] is candidate.metadata
    assert registry.reference_snapshot() == (REF, SECOND, THIRD)
    assert (await registry.models.read(THIRD)).reference == THIRD
    assert (await registry.snapshot(THIRD)).reference == THIRD
    assert all(registry.sessions[ref] is original for ref, original in entries.items())
    assert all(not original.execution.submitted for original in entries.values())
    assert not candidate.execution.submitted
    with pytest.raises(TypeError):
        history[THIRD] = None


@pytest.mark.parametrize("answers", [[False], [1], [True, False], [True, 1]])
async def test_adoption_rechecks_strict_authority_and_never_publishes_partial_resources(answers):
    registry, entries = pair()
    candidate = new_entry()
    with pytest.raises(AccessDenied, match="authority"):
        await registry.adopt(candidate, authorize=AsyncMock(side_effect=answers))
    assert THIRD not in registry.sessions and THIRD not in registry.transcripts
    assert THIRD not in registry.metadata


@pytest.mark.parametrize(
    "fault", ["foreign", "unreconciled", "unknown", "disconnected", "descendants"]
)
async def test_new_registry_entry_requires_a_current_original_snapshot(fault):
    registry, entries = pair()
    candidate = new_entry()
    snapshot = await candidate.execution.snapshot(THIRD)
    changes = {
        "foreign": {"reference": REF},
        "unreconciled": {"reconciled": False},
        "unknown": {"state": ExecutionState.UNKNOWN},
        "disconnected": {"state": ExecutionState.DISCONNECTED},
        "descendants": {"descendants": (REF,)},
    }[fault]
    candidate.execution.snapshot = AsyncMock(return_value=snapshot.model_copy(update=changes))
    with pytest.raises(Conflict, match="original_snapshot"):
        await registry.adopt(candidate, authorize=AsyncMock(return_value=True))
    assert THIRD not in registry.sessions


@pytest.mark.parametrize(
    "change", ["backend_id", "backend_identity", "project_id", "canonical_directory"]
)
async def test_adoption_cannot_expand_the_existing_backend_or_project_scope(change):
    registry, entries = pair()
    ref = THIRD.model_copy(
        update={change: "/foreign" if change == "canonical_directory" else "foreign"}
    )
    candidate = new_entry(ref)
    with pytest.raises(AccessDenied, match="outside_enrolled_project"):
        await registry.adopt(candidate, authorize=AsyncMock(return_value=True))
    assert ref not in registry.sessions


async def test_adoption_never_replaces_an_existing_original_registration():
    registry, entries = pair()
    candidate = new_entry(REF)
    with pytest.raises(Conflict, match="cannot_be_replaced"):
        await registry.adopt(candidate, authorize=AsyncMock(return_value=True))
    assert registry.sessions[REF] is entries[REF]
    await registry.adopt(entries[REF], authorize=AsyncMock(return_value=True))
    assert registry.sessions[REF] is entries[REF]


async def test_two_competing_adoptions_choose_one_entry_without_replacing_old_roots():
    registry, entries = pair()
    a, b = new_entry(), new_entry()
    results = await asyncio.gather(
        registry.adopt(a, authorize=AsyncMock(return_value=True)),
        registry.adopt(b, authorize=AsyncMock(return_value=True)),
        return_exceptions=True,
    )
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, Conflict) for result in results) == 1
    assert registry.sessions[THIRD] is a or registry.sessions[THIRD] is b
    assert all(registry.sessions[ref] is original for ref, original in entries.items())


async def test_contract_drift_after_snapshot_blocks_registration():
    registry, entries = pair()
    candidate = new_entry()
    calls = 0

    async def authorize():
        nonlocal calls
        calls += 1
        if calls == 2:
            candidate.execution.contract_hash = "f" * 64
        return True

    with pytest.raises(AccessDenied):
        await registry.adopt(candidate, authorize=authorize)
    assert THIRD not in registry.sessions


def correlation(ref, action):
    return TurnCorrelation(
        reference=ref,
        action_id=action,
        operation_digest="a" * 64,
        upstream_id="msg_" + action,
        text="exact " + action,
    )


async def test_exact_original_routes_snapshot_models_pending_and_posts_without_crossing():
    registry, entries = pair()
    for ref in (REF, SECOND):
        assert (await registry.snapshot(ref)).reference == ref
        assert (await registry.models.read(ref)).reference == ref
        assert await registry.pending(ref) == ("pending:" + ref.upstream_session_id,)
        await registry.submit(ref, {"operation": "prompt"}, "action:" + ref.upstream_session_id)
    assert len(entries[REF].execution.submitted) == len(entries[SECOND].execution.submitted) == 1
    assert entries[REF].execution.submitted[0][0] == REF
    assert entries[SECOND].execution.submitted[0][0] == SECOND
    assert registry.sessions[REF] is entries[REF]
    with pytest.raises(TypeError):
        registry.sessions[REF] = entries[SECOND]
    with pytest.raises(FrozenInstanceError):
        registry.sessions = {}


@pytest.mark.parametrize(
    "patch",
    [
        {"upstream_session_id": "unknown"},
        {"backend_id": "other"},
        {"backend_identity": "other"},
        {"project_id": "other"},
        {"canonical_directory": "/other"},
    ],
)
async def test_unknown_or_scope_changed_ref_never_falls_back_to_first_session(patch):
    registry, entries = pair()
    ref = REF.model_copy(update=patch)
    with pytest.raises(AccessDenied):
        await registry.submit(ref, {"operation": "prompt"}, "unknown")
    with pytest.raises(AccessDenied):
        await registry.snapshot(ref)
    with pytest.raises(AccessDenied):
        await registry.models.read(ref)
    assert all(not e.execution.submitted for e in entries.values())


async def test_independent_result_readers_keep_both_current_witnesses_and_reject_copy_or_wrong_scope():
    registry, entries = pair()
    a, b = await asyncio.gather(
        registry.results.capture(correlation(REF, "a")),
        registry.results.capture(correlation(SECOND, "b")),
    )
    assert registry.results.current(a) and registry.results.current(b)
    assert not registry.results.current(a.model_copy())
    assert not registry.results.current(
        a.model_copy(update={"correlation": a.correlation.model_copy(update={"reference": SECOND})})
    )
    entries[SECOND].results.mode = "foreign"
    with pytest.raises(Conflict, match="scope_or_witness"):
        await registry.results.capture(correlation(SECOND, "wrong"))
    assert registry.results.current(a)


async def test_foreign_snapshot_or_interaction_result_never_becomes_this_roots_state():
    registry, entries = pair()
    original = await entries[SECOND].execution.snapshot(SECOND)
    entries[SECOND].execution.snapshot = AsyncMock(
        return_value=original.model_copy(update={"reference": REF})
    )
    with pytest.raises(Conflict, match="snapshot_scope"):
        await registry.snapshot(SECOND)
    entries[SECOND].execution.requests["pending"] = InteractionSnapshot(
        reference=REF,
        upstream_request_id="pending",
        generation="synthetic",
        description="foreign request fixture",
        kind="form",
        pending=True,
    )
    with pytest.raises(Conflict, match="interaction_scope"):
        await registry.interaction(SECOND, "pending")


async def test_post_contract_drift_is_uncertain_and_never_retried_or_rerouted():
    registry, entries = pair()
    target = entries[SECOND].execution
    original = target.submit

    async def drift(ref, payload, action_id):
        result = await original(ref, payload, action_id)
        target.contract_hash = "b" * 64
        return result

    target.submit = drift
    with pytest.raises(Conflict, match="contract_changed"):
        await registry.submit(SECOND, {"operation": "prompt"}, "one-attempt")
    assert len(target.submitted) == 1 and not entries[REF].execution.submitted


@pytest.mark.parametrize("value", [["x"], ("same", "same"), ("valid", []), ("",)])
async def test_bad_pending_catalog_is_not_turned_into_authorized_interactions(value):
    registry, entries = pair()
    entries[SECOND].pending.return_value = value
    with pytest.raises(ValueError, match="pending_ids"):
        await registry.pending(SECOND)


@pytest.mark.parametrize("change", ["owner", "contract", "directory_alias", "same_native_alias"])
def test_registry_rejects_mixed_instance_contract_or_ambiguous_native_alias(change):
    registry, entries = pair()
    other = SECOND
    if change == "owner":
        other = SECOND.model_copy(update={"backend_identity": "other"})
    if change == "contract":
        entries[SECOND].execution.contract_hash = "b" * 64
        entries[SECOND].models.snapshot = entries[SECOND].models.snapshot.model_copy(
            update={"contract_sha256": "b" * 64}
        )
        changed = replace(entries[SECOND], contract_sha256="b" * 64)
    else:
        if change == "directory_alias":
            other = SECOND.model_copy(update={"canonical_directory": "/other"})
        if change == "same_native_alias":
            other = REF.model_copy(update={"project_id": "alias"})
        entries[SECOND].models.snapshot = entries[SECOND].models.snapshot.model_copy(
            update={"reference": other}
        )
        changed = replace(entries[SECOND], reference=other)
    with pytest.raises(ValueError):
        SessionRegistry({REF: entries[REF], other: changed})


async def test_two_topics_keep_queue_admission_results_and_history_on_original_roots(db):
    registry, entries = pair()
    await service(db, entries[REF].execution)
    bindings = BindingService(db, registry, SyntheticAudience())
    a = await bindings.bind("realm", 7, 10, "Original work", REF)
    b = await bindings.bind("realm", 7, 10, "Second work", SECOND)
    number = await DurableStore(db).acquire_lease("two-sessions", ttl=120)
    fence = ConsumerFence("two-sessions", number)
    source = Source()
    source.messages = {
        101: message("Task for first", 101),
        102: message("Task for second", 102, topic="Second work"),
    }
    queue = QueueService(bindings, fence=fence)
    first = await queue.receive(a.id, source.messages[101])
    second = await queue.receive(b.id, source.messages[102])
    dispatcher = Dispatcher(bindings, registry, source, fence.holder, fence.fencing)
    assert await dispatcher.advance(first.action_id) == "admitted"
    assert await dispatcher.advance(second.action_id) == "admitted"
    collector = ResourceResultCollector(bindings, registry.results, fence)
    results = await asyncio.gather(
        collector.collect(first.action_id, "realm"), collector.collect(second.action_id, "realm")
    )
    assert {result.reference for result in results} == {REF, SECOND}
    history = ResourceHistory(bindings)
    first_page = await history.page(a.id, "realm", 7)
    second_page = await history.page(b.id, "realm", 7)
    assert len(first_page.items) == len(second_page.items) == 1
    assert entries[REF].execution.submitted[0][1]["text"] == "Task for first"
    assert entries[SECOND].execution.submitted[0][1]["text"] == "Task for second"
    assert first_page.items[0].record_id != second_page.items[0].record_id
