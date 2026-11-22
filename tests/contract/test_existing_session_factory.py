"""Real adapter assembly against synthetic GET peers; no live/Human acceptance."""

import asyncio
import copy
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from jt_oz_bridge.adapters.opencode.model_catalog import READS as MODEL_READS
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    RESOURCE_TYPES,
    ResourceSemanticAttestation,
    V2TurnResourceReader,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.session_adoption import SessionAdoptionPolicy, SessionAdoptionRecord
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.existing_session_factory import V2ExistingSessionFactory
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.durable import Conflict
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import CHILD, GRANDCHILD, SIBLING, TARGET
from tests.contract.test_lineage_resources import setup as resources_setup
from tests.contract.test_public_live_feed import REF


async def setup(*, leaf=False, tree_qualification=True):
    anchor, t, proofs, client, tree, state, writes, observer = await resources_setup()
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | MODEL_READS
    )
    if leaf:
        for ref in tuple(tree["rows"]):
            if ref != TARGET:
                del tree["rows"][ref]
                del state["resources"][ref]
        tree["edges"].clear()
    execution = observer.observer.anchor.proofs
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient

    native = V2ExecutionClient(
        t, anchor.projects, proofs=execution, scope_guard=observer.observer.anchor
    )
    semantics = ResourceSemanticAttestation(
        REF.backend_id,
        REF.backend_identity,
        t.profile.sha256,
        RESOURCE_SEMANTICS,
        "e" * 64,
        RESOURCE_TYPES,
        frozenset({"succeeded", "failed", "interrupted"}),
    )
    reader = V2TurnResourceReader(native, attestation=semantics)
    original = RegisteredSession(
        REF,
        t.profile.sha256,
        native,
        native.models,
        reader,
        AsyncMock(return_value=()),
        transcript=V2TranscriptReader(reader),
        metadata=V2NativeMetadataReader(native, REF),
    )
    registry = SessionRegistry({REF: original})
    policy = SessionAdoptionPolicy(
        anchor=REF,
        contract_sha256=t.profile.sha256,
        installed_protocol_evidence_sha256=observer.observer.protocol.installed_evidence_sha256,
        protocol_scope="backend",
        operations=frozenset({"prompt", "permission.reply", "form.reply"}),
    )
    factory = V2ExistingSessionFactory(
        observer,
        registry,
        policy,
        lineage=proofs.lineage_attestation if tree_qualification else None,
    )
    return anchor, t, factory, tree, state, writes, original


@pytest.mark.parametrize("leaf", [False, True])
@pytest.mark.parametrize("active", [False, True])
async def test_original_idle_or_running_graph_is_prepared_and_committed_without_native_mutation(
    leaf, active
):
    anchor, t, f, tree, state, writes, original = await setup(
        leaf=leaf, tree_qualification=not leaf
    )
    try:
        if active:
            state["active"][TARGET.upstream_session_id] = {"type": "running"}
        candidate = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        assert tuple(f.registry.sessions) == (REF,)
        before_interest = f._feed.index
        saved = []

        async def journal(record):
            assert record is candidate.record
            assert tuple(f.registry.sessions) == (REF,)
            assert not record.starts_execution and not record.creates_binding
            saved.append(record)

        entries = await f.commit(
            candidate, authorize=AsyncMock(return_value=True), before_commit=journal
        )
        assert saved == [candidate.record] and f.registry.sessions[REF] is original
        assert f._feed.index is before_interest
        assert set(entries) == ({TARGET} if leaf else {TARGET, CHILD, GRANDCHILD, SIBLING})
        assert all(f.registry.sessions[ref] is entry for ref, entry in entries.items())
        current = await f.registry.snapshot(TARGET)
        assert current.state == (ExecutionState.RUNNING if active else ExecutionState.IDLE)
        for ref, entry in entries.items():
            assert entry.execution.transport is t and entry.results.client is entry.execution
            assert (
                entry.metadata.client is entry.execution
                and entry.transcript.qualified is entry.results
            )
            assert (
                entry.execution.attachments is None
                and entry.execution.workspace_attachments is None
            )
            assert entry.execution.capabilities(ref)["check.run"].supported is False
        assert not writes and all(r.method == "GET" for r in state["resource_calls"])
    finally:
        await finish(anchor, t)


async def test_leaf_qualification_cannot_be_borrowed_to_register_nonempty_descendants():
    anchor, t, f, tree, state, writes, original = await setup(tree_qualification=False)
    try:
        before = f._feed.references
        with pytest.raises(Conflict, match="descendant_semantics"):
            await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        assert f._feed.references is before and tuple(f.registry.sessions) == (REF,) and not writes
    finally:
        await finish(anchor, t)


async def test_historic_node_listing_order_is_not_a_change_to_original_identity():
    anchor, t, factory, tree, state, writes, original = await setup()
    try:
        candidate = await factory.prepare(TARGET, authorize=AsyncMock(return_value=True))
        historical = SessionAdoptionRecord.model_validate(
            candidate.record.model_copy(
                update={"nodes": tuple(reversed(candidate.record.nodes))}
            ).model_dump(mode="python")
        )
        assert historical.nodes != candidate.record.nodes
        refreshed = await factory.prepare_record(historical, authorize=AsyncMock(return_value=True))
        assert refreshed.record.graph_sha256 == historical.graph_sha256
        assert {n.reference: n for n in refreshed.record.nodes} == {
            n.reference: n for n in historical.nodes
        }
        assert not writes and TARGET not in factory.registry.sessions
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "fault", ["copied", "expired", "native_attestation", "entries", "proofs", "guard", "record"]
)
async def test_copied_expired_or_replaced_preparation_cannot_activate_any_reader(
    fault, monkeypatch
):
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        candidate = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        if fault == "copied":
            candidate = replace(candidate)
        elif fault == "expired":
            monkeypatch.setattr(
                "jt_oz_bridge.services.existing_session_factory.time.time",
                lambda: candidate.expires_at,
            )
        elif fault == "native_attestation":
            t.attestation = replace(t.attestation)
        elif fault == "entries":
            candidate = replace(candidate, entries=dict(candidate.entries))
        elif fault == "proofs":
            candidate = replace(candidate, proofs=copy.copy(candidate.proofs))
        elif fault == "guard":
            candidate = replace(candidate, guard=copy.copy(candidate.guard))
        else:
            candidate = replace(candidate, record=candidate.record.model_copy())
        with pytest.raises((AccessDenied, Conflict, ValueError)):
            await f.commit(candidate, authorize=AsyncMock(return_value=True))
        assert tuple(f.registry.sessions) == (REF,) and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("failure", ["journal", "revoked_after_journal", "cancelled_journal"])
async def test_journal_preparation_failure_or_late_revocation_never_exposes_half_graph(failure):
    anchor, t, f, tree, state, writes, original = await setup()
    allowed = True

    async def authority():
        return allowed

    try:
        candidate = await f.prepare(TARGET, authorize=authority)

        async def journal(record):
            nonlocal allowed
            assert tuple(f.registry.sessions) == (REF,)
            if failure == "journal":
                raise OSError("synthetic journal unavailable")
            if failure == "cancelled_journal":
                raise asyncio.CancelledError()
            allowed = False

        with pytest.raises((AccessDenied, OSError, asyncio.CancelledError)):
            await f.commit(candidate, authorize=authority, before_commit=journal)
        assert tuple(f.registry.sessions) == (REF,) and TARGET not in f._registered and not writes
    finally:
        await finish(anchor, t)


async def test_repeated_original_registration_reuses_every_reader_and_never_replaces_anchor():
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        first = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        entries = await f.commit(first, authorize=AsyncMock(return_value=True))
        again = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        reused = await f.commit(again, authorize=AsyncMock(return_value=True))
        assert all(reused[r] is e for r, e in entries.items())
        assert f.registry.sessions[REF] is original and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("field", ["created", "policy", "parent"])
async def test_registered_originals_are_not_replaced_when_a_native_identity_or_policy_changes(
    field,
):
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        candidate = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        entries = await f.commit(candidate, authorize=AsyncMock(return_value=True))
        if field == "created":
            tree["rows"][CHILD]["time"]["created"] += 1
        elif field == "policy":
            tree["rows"][CHILD]["permissions"] = []
        else:
            tree["rows"][CHILD]["parentID"] = SIBLING.upstream_session_id
        with pytest.raises(ValueError):
            await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        assert all(f.registry.sessions[r] is e for r, e in entries.items()) and not writes
    finally:
        await finish(anchor, t)


async def test_source_revocation_before_preparation_does_not_read_native_or_register():
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        before = len(state["resource_calls"])
        with pytest.raises(AccessDenied):
            await f.prepare(TARGET, authorize=AsyncMock(return_value=False))
        assert (
            len(state["resource_calls"]) == before
            and tuple(f.registry.sessions) == (REF,)
            and not writes
        )
    finally:
        await finish(anchor, t)


async def test_registration_identity_record_does_not_turn_into_live_execution_authority():
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        candidate = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        record = SessionAdoptionRecord.model_validate_json(candidate.record.model_dump_json())
        assert (
            record == candidate.record
            and not record.starts_execution
            and not record.creates_binding
        )
        for patch in (
            {"starts_execution": True},
            {"creates_binding": True},
            {"nodes": record.nodes[:-1]},
        ):
            with pytest.raises(ValidationError):
                SessionAdoptionRecord.model_validate(record.model_dump() | patch)
        assert tuple(f.registry.sessions) == (REF,) and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("running", [False, True])
async def test_readonly_rehydration_rechecks_same_original_graph_and_current_authority(running):
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        first = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        await f.commit(first, authorize=AsyncMock(return_value=True))
        historical = first.record.model_copy(
            update={"observed_owner_epoch": "b" * 64, "observed_at": 0}
        )
        fresh_registry = SessionRegistry({REF: original})
        restarted = V2ExistingSessionFactory(
            f.observer, fresh_registry, f.policy, lineage=f.lineage
        )
        if running:
            state["active"][TARGET.upstream_session_id] = {"type": "running"}
        ready = await restarted.prepare_record(historical, authorize=AsyncMock(return_value=True))
        assert ready.record.observed_owner_epoch != historical.observed_owner_epoch
        assert tuple(fresh_registry.sessions) == (REF,)
        restored = await restarted.commit(ready, authorize=AsyncMock(return_value=True))
        assert set(restored) == set(first.entries)
        assert all(
            ref.upstream_session_id == restored[ref].reference.upstream_session_id
            for ref in restored
        )
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "change", ["created", "policy", "qualification", "missing_leaf", "revoked"]
)
async def test_historical_registration_material_never_replaces_changed_originals_or_grants_authority(
    change,
):
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        first = await f.prepare(TARGET, authorize=AsyncMock(return_value=True))
        historical = first.record
        if change == "created":
            tree["rows"][TARGET]["time"]["created"] += 1
        elif change == "policy":
            tree["rows"][TARGET]["permissions"] = []
        elif change == "qualification":
            historical = historical.model_copy(update={"qualification_sha256": "b" * 64})
        elif change == "missing_leaf":
            historical = historical.model_copy(update={"nodes": historical.nodes[:-1]})
        with pytest.raises((ValueError, AccessDenied)):
            await f.prepare_record(
                historical, authorize=AsyncMock(return_value=change != "revoked")
            )
        assert tuple(f.registry.sessions) == (REF,) and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "change", ["protocol_evidence", "operations", "anchor_pointer", "lineage_backend"]
)
async def test_assembly_requires_same_explicit_backend_qualification_before_any_native_read(change):
    anchor, t, f, tree, state, writes, original = await setup()
    try:
        policy = f.policy
        lineage = f.lineage
        if change == "protocol_evidence":
            policy = policy.model_copy(update={"installed_protocol_evidence_sha256": "b" * 64})
        elif change == "operations":
            policy = policy.model_copy(update={"operations": frozenset({"check.run"})})
        elif change == "anchor_pointer":
            # Bypass the sealed cell deliberately to model internal assembly
            # tampering, rather than using a removed mutable-registry detail.
            cell = f.registry.publication
            graph_state = cell.snapshot()
            cell._state = replace(
                graph_state,
                sessions=MappingProxyType(dict(graph_state.sessions) | {REF: replace(original)}),
            )
        else:
            lineage = replace(lineage, backend_identity="foreign")
        before = len(state["resource_calls"])
        with pytest.raises((ValueError, Conflict)):
            if change == "anchor_pointer":
                f.selected(TARGET)
            else:
                V2ExistingSessionFactory(f.observer, f.registry, policy, lineage=lineage)
        assert len(state["resource_calls"]) == before and not writes
    finally:
        await finish(anchor, t)
