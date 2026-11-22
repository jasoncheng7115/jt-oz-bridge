"""Original facade identities over synthetic GET/event generations, never live acceptance."""

import asyncio
import copy
import json
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.graph_generation import (
    GraphResourceContext,
    attach_graph_generation,
)
from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs
from jt_oz_bridge.adapters.opencode.model_catalog import READS as MODEL_READS
from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
)
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, V2LeafResourceProofs
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    RESOURCE_TYPES,
    ResourceSemanticAttestation,
    V2TurnResourceReader,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_policy import policies
from tests.contract.test_lineage_resources import CHILD, GRANDCHILD, TARGET, setup
from tests.contract.test_public_live_feed import REAL, REF, frame


def record(observed):
    return SessionAdoptionRecord(
        root=observed.reference,
        native_project_id=observed.nodes[0].native_project_id,
        contract_sha256=INSTALLED_SCHEMA,
        qualification_sha256="f" * 64,
        graph_sha256=observed.graph_sha256,
        nodes=tuple(
            OriginalSessionNode.model_validate(
                n.model_dump(
                    include={
                        "reference",
                        "native_created_at",
                        "parent_reference",
                        "parent_created_at",
                        "policy_sha256",
                    }
                )
            )
            for n in observed.nodes
        ),
        observed_owner_epoch=observed.owner_epoch,
        observed_at=observed.observed_at,
    )


def entry(reference, proofs, guard, semantics):
    client = V2ExecutionClient(
        proofs.feed.transport, proofs.projects, proofs=proofs, scope_guard=guard
    )
    results = V2TurnResourceReader(client, attestation=semantics)

    async def pending(selected):
        return tuple(key for key, _ in (await proofs.capture(selected)).pending)

    return RegisteredSession(
        reference,
        semantics.contract_sha256,
        client,
        client.models,
        results,
        pending,
        transcript=V2TranscriptReader(results),
        metadata=V2NativeMetadataReader(client, reference),
    )


async def baseline(kind, model_scope=None):
    anchor, t, unused, _, tree, state, writes, observer = await setup()
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | MODEL_READS
    )
    previous_transport = t.client._transport

    def native_peer(request):
        if request.url.path == "/api/session" and request.url.params.get("limit") == "1":
            assert request.method == "GET" and request.url.params["order"] == "desc"
            parent = next(
                ref
                for ref in tree["rows"]
                if ref.upstream_session_id == request.url.params["parentID"]
            )
            children = tree["edges"].get(parent, [])
            return httpx.Response(
                200,
                json={
                    "data": [copy.deepcopy(tree["rows"][child]) for child in children[:1]],
                    "cursor": {},
                },
            )
        return previous_transport.handler(request)

    t.client._transport = httpx.MockTransport(native_peer)
    saved = copy.deepcopy((tree["rows"], tree["edges"], state["resources"]))
    for ref in tuple(tree["rows"]):
        if ref != TARGET:
            del tree["rows"][ref]
            del state["resources"][ref]
    tree["edges"].clear()
    observed = await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
    settings = (
        ModelSettingsAttestation(
            TARGET,
            INSTALLED_SCHEMA,
            MODEL_SETTING_SEMANTICS,
            "d" * 64,
            qualification_scope=model_scope,
        )
        if model_scope
        else None
    )
    lineage = V2LineageResourceProofs(
        anchor.feed,
        anchor.projects,
        observed,
        unused.lineage_attestation,
        current=observer.current,
        model_settings=settings,
    )
    original_policies = policies(lineage)
    proofs = (
        V2LeafResourceProofs(anchor.feed, anchor.projects, model_settings=settings)
        if kind == "leaf"
        else lineage
    )
    guard = (
        V2ProjectPolicyGuard(proofs, original_policies)
        if kind == "leaf"
        else V2LineagePolicyGuard(proofs, original_policies)
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
    original = entry(TARGET, proofs, guard, semantics)
    registry = SessionRegistry({TARGET: original})
    attach_graph_generation(proofs, guard, registry.publication, TARGET, unused.lineage_attestation)
    first = registry.prepare_generation(
        record(observed),
        {TARGET: original},
        expected=registry.publication.generation(TARGET),
        enrollments=original_policies,
    )
    registry.publish_generation(first)
    if kind == "leaf":
        await proofs.watch(TARGET)
    else:
        await proofs.watch_graph(authorize=AsyncMock(return_value=True))
    return (
        anchor,
        t,
        proofs,
        guard,
        registry,
        original,
        tree,
        state,
        writes,
        observer,
        saved,
        unused.lineage_attestation,
    )


async def stage(environment, *, active=False):
    anchor, t, stable, guard, registry, original, tree, state, _, observer, saved, attestation = (
        environment
    )
    tree["rows"].update(copy.deepcopy(saved[0]))
    tree["edges"].update(copy.deepcopy(saved[1]))
    state["resources"].update(copy.deepcopy(saved[2]))
    if active:
        state["active"][GRANDCHILD.upstream_session_id] = {"type": "running"}
    observed = await observer.observe(TARGET, authorize=AsyncMock(return_value=True))
    probe = V2LineageResourceProofs(
        anchor.feed,
        anchor.projects,
        observed,
        attestation,
        current=observer.current,
        model_settings=stable.model_settings,
        model_settings_by_reference={
            node.reference: stable.model_settings
            if node.reference == TARGET
            or stable.model_settings is not None
            and stable.model_settings.qualification_scope == "backend"
            else None
            for node in observed.nodes
        },
    )
    selected = policies(probe)
    selected[TARGET] = guard.enrollments[TARGET]
    policy = V2LineagePolicyGuard(probe, selected)
    await probe.watch_graph(authorize=AsyncMock(return_value=True))
    client = V2ExecutionClient(t, anchor.projects, proofs=probe, scope_guard=policy)
    for node in observed.nodes:
        await client.qualified_snapshot(node.reference)
    context = GraphResourceContext(probe, policy, record(observed))
    entries = {TARGET: original}
    for node in observed.nodes:
        if node.reference != TARGET:
            child_proofs, child_guard = stable, guard
            if (
                stable.model_settings is not None
                and stable.model_settings.qualification_scope == "session"
            ):
                child_proofs = V2LeafResourceProofs(anchor.feed, anchor.projects)
                child_guard = V2ProjectPolicyGuard(child_proofs, selected)
                attach_graph_generation(
                    child_proofs, child_guard, registry.publication, TARGET, attestation
                )
            entries[node.reference] = entry(
                node.reference, child_proofs, child_guard, original.results.attestation
            )
    prepared = registry.prepare_generation(
        context.record,
        entries,
        expected=registry.publication.generation(TARGET),
        enrollments=selected,
        context=context,
    )
    return prepared, context


@pytest.mark.parametrize("kind", ["leaf", "lineage"])
@pytest.mark.parametrize("active", [False, True])
async def test_complete_publication_preserves_original_facades_and_routes_new_child_grandchild(
    kind, active
):
    env = await baseline(kind)
    anchor, t, proofs, guard, registry, original, _, _, writes, *_ = env
    try:
        _, old_proof = await original.execution.qualified_snapshot(TARGET)
        old_policy = await guard.authorize(TARGET, "prompt", old_proof)
        old_read = await proofs.read_scope(TARGET)
        selected = guard.enrollments[TARGET]
        prepared, context = await stage(env, active=active)
        assert registry.reference_snapshot() == (TARGET,)
        with pytest.raises(ContractError):
            await original.execution.snapshot(TARGET)
        registry.publish_generation(prepared)
        assert registry.selected(TARGET) is original
        assert original.execution.proofs is proofs and original.execution.scope_guard is guard
        assert guard.enrollments[TARGET] is selected
        assert registry.selected(CHILD).execution.proofs is proofs
        assert registry.selected(GRANDCHILD).execution.scope_guard is guard
        with pytest.raises(ContractError):
            original.execution.current(TARGET, old_proof)
        assert not guard.current(TARGET, "prompt", old_proof, old_policy)
        assert proofs.read_epoch(TARGET, old_read.contract_sha256) is None
        current, proof = await original.execution.qualified_snapshot(TARGET)
        assert set(current.descendants) == set(prepared.generation.entries) - {TARGET}
        descendant = await registry.snapshot(GRANDCHILD)
        assert descendant.state == (ExecutionState.RUNNING if active else ExecutionState.IDLE)
        if active:
            with pytest.raises(ContractError, match="quiescent_graph"):
                proofs.dispatch_owner_epoch(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("kind", ["leaf", "lineage"])
@pytest.mark.parametrize("operation", ["read_scope", "capture", "policy"])
async def test_publication_during_get_never_returns_a_mixed_generation_witness(kind, operation):
    env = await baseline(kind)
    anchor, t, proofs, guard, registry, original, _, state, writes, *_ = env
    try:
        prepared, _ = await stage(env)
        published = False

        def arrival(request, state):
            nonlocal published
            if not published and request.url.path == "/api/session/" + TARGET.upstream_session_id:
                published = True
                registry.publish_generation(prepared)

        state["hook"] = arrival
        with pytest.raises(ContractError):
            if operation == "policy":
                await guard.bundle(TARGET)
            else:
                await getattr(proofs, operation)(TARGET)
        assert published and registry.selected(TARGET) is original
        assert set((await registry.snapshot(TARGET)).descendants) == set(
            prepared.generation.entries
        ) - {TARGET}
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "fault", ["leaf_pin", "second_attach", "probe_record", "probe_guard", "generation_context"]
)
async def test_metadata_or_replaced_composition_cannot_supply_active_resource_authority(fault):
    env = await baseline("leaf")
    anchor, t, proofs, guard, registry, original, _, _, writes, *_ = env
    try:
        prepared, context = await stage(env)
        if fault in {"leaf_pin", "second_attach"}:
            with pytest.raises(ContractError):
                attach_graph_generation(
                    proofs,
                    guard,
                    registry.publication,
                    TARGET,
                    replace(context.proofs.lineage_attestation, qualification_scope="leaf")
                    if fault == "leaf_pin"
                    else context.proofs.lineage_attestation,
                )
        elif fault == "probe_record":
            with pytest.raises(ContractError):
                GraphResourceContext(
                    context.proofs,
                    context.guard,
                    context.record.model_copy(update={"graph_sha256": "0" * 64}),
                )
        elif fault == "probe_guard":
            object.__setattr__(context, "guard", copy.copy(context.guard))
            registry.publish_generation(prepared)
            with pytest.raises(ContractError):
                await original.execution.snapshot(TARGET)
        else:
            object.__setattr__(prepared.generation, "context", object())
            registry.publish_generation(prepared)
            with pytest.raises(ContractError):
                await original.execution.snapshot(TARGET)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_unknown_native_arrival_still_invalidates_original_complete_graph_after_publication():
    env = await baseline("lineage")
    anchor, t, proofs, _, registry, original, _, _, writes, *_ = env
    try:
        prepared, _ = await stage(env)
        registry.publish_generation(prepared)
        _, proof = await original.execution.qualified_snapshot(TARGET)
        raw = json.loads(json.dumps(REAL[0]).replace(REF.upstream_session_id, "ses_unknown_child"))
        assert proofs.feed.index.accept(frame(raw)) is None
        with pytest.raises(ContractError):
            original.execution.current(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("kind", ["leaf", "lineage"])
async def test_unknown_child_state_arrival_invalidates_tree_opted_in_baseline_before_first_extension(
    kind,
):
    env = await baseline(kind)
    anchor, t, proofs, _, _, original, _, _, writes, *_ = env
    try:
        _, proof = await original.execution.qualified_snapshot(TARGET)
        raw = json.loads(
            json.dumps(REAL[0]).replace(REF.upstream_session_id, "ses_prepublication_child")
        )
        assert proofs.feed.index.accept(frame(raw)) is None
        with pytest.raises(ContractError):
            original.execution.current(TARGET, proof)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("kind", ["leaf", "lineage"])
@pytest.mark.parametrize("fault", ["policy", "attestation", "cancel", "probe_attached"])
async def test_active_facade_never_borrows_stale_policy_owner_or_cancelled_resource_result(
    kind, fault
):
    env = await baseline(kind)
    anchor, t, proofs, guard, registry, original, tree, state, writes, *_ = env
    try:
        prepared, context = await stage(env)
        registry.publish_generation(prepared)
        _, proof = await original.execution.qualified_snapshot(TARGET)
        if fault == "policy":
            tree["rows"][TARGET]["permissions"] = []
            with pytest.raises(ContractError):
                await guard.authorize(TARGET, "prompt", proof)
        elif fault == "attestation":
            t.attestation = replace(t.attestation)
            with pytest.raises(ContractError):
                original.execution.current(TARGET, proof)
        elif fault == "probe_attached":
            context.proofs._graph_publication = object()
            with pytest.raises(ContractError, match="assembly_changed"):
                await original.execution.snapshot(TARGET)
        else:

            def cancellation(request, state):
                raise asyncio.CancelledError()

            state["hook"] = cancellation
            with pytest.raises(asyncio.CancelledError):
                await proofs.capture(TARGET)
        assert not writes
    finally:
        await finish(anchor, t)


async def test_default_unattached_leaf_objects_keep_original_generation_and_no_attachment_reads():
    env = await baseline("leaf")
    anchor, t, _, _, registry, _, _, state, writes, *_ = env
    try:
        before = tuple(state["resource_calls"])
        other_watches = dict(anchor._watched)
        other_reads = dict(anchor._read_watched)
        assert other_watches
        prepared, _ = await stage(env)
        registry.publish_generation(prepared)
        assert set(anchor._watched) == set(other_watches)
        assert all(anchor._watched[ref] is value for ref, value in other_watches.items())
        assert anchor._read_watched == other_reads
        assert getattr(anchor, "_graph_publication", None) is None
        assert tuple(state["resource_calls"][: len(before)]) == before
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("kind", ["leaf", "lineage"])
@pytest.mark.parametrize("model_scope", ["session", "backend"])
async def test_each_original_model_codec_is_preserved_without_inheriting_session_scope_into_children(
    kind, model_scope
):
    env = await baseline(kind, model_scope)
    anchor, t, proofs, _, registry, original, _, _, writes, *_ = env
    try:
        qualification = proofs.model_settings
        prepared, context = await stage(env)
        registry.publish_generation(prepared)
        assert original.execution.proofs is proofs and proofs.model_settings is qualification
        assert proofs.model_settings_for(TARGET) is qualification
        child = registry.selected(CHILD)
        if model_scope == "session":
            assert child.execution.proofs is not proofs
            assert child.execution.proofs.model_settings is None
            assert context.proofs.model_settings_for(CHILD) is None
        else:
            assert child.execution.proofs is proofs
            assert context.proofs.model_settings_for(CHILD) is qualification
        current = await registry.snapshot(CHILD)
        assert current.reference == CHILD and current.state == ExecutionState.IDLE
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fault", ["missing", "borrowed_session", "root_copy", "replaced_map"])
async def test_per_node_codecs_require_complete_original_qualifications_without_scope_widening(
    fault,
):
    env = await baseline("leaf", "session")
    anchor, t, stable, _, _, _, _, _, writes, observer, *_ = env
    try:
        _, context = await stage(env)
        selected = {
            ref: stable.model_settings if ref == TARGET else None
            for ref in context.guard.enrollments
        }
        if fault == "missing":
            selected.pop(CHILD)
        elif fault == "borrowed_session":
            selected[CHILD] = stable.model_settings
        elif fault == "root_copy":
            selected[TARGET] = replace(stable.model_settings)
        if fault == "replaced_map":
            context.proofs._node_model_settings = dict(selected)
            with pytest.raises(ContractError):
                context.proofs.model_settings_for(TARGET)
        else:
            with pytest.raises(ContractError):
                V2LineageResourceProofs(
                    anchor.feed,
                    anchor.projects,
                    context.proofs.observation,
                    context.proofs.lineage_attestation,
                    current=observer.current,
                    model_settings=stable.model_settings,
                    model_settings_by_reference=selected,
                )
        assert not writes
    finally:
        await finish(anchor, t)


async def test_unpublished_new_root_can_construct_contracts_but_cannot_watch_or_claim_authority():
    env = await baseline("leaf")
    anchor, t, _, guard, _, original, _, state, writes, observer, _, attestation = env
    try:
        anchor_entry = entry(REF, anchor, observer.observer.anchor, original.results.attestation)
        unpublished_registry = SessionRegistry({REF: anchor_entry})
        new_proofs = V2LeafResourceProofs(anchor.feed, anchor.projects)
        new_guard = V2ProjectPolicyGuard(new_proofs, {TARGET: guard.enrollments[TARGET]})
        before = tuple(state["resource_calls"])
        attach_graph_generation(
            new_proofs, new_guard, unpublished_registry.publication, TARGET, attestation
        )
        candidate_entry = entry(TARGET, new_proofs, new_guard, original.results.attestation)
        assert candidate_entry.reference == TARGET
        assert unpublished_registry.reference_snapshot() == (REF,)
        assert tuple(state["resource_calls"]) == before
        for operation in (new_proofs.watch, new_proofs.capture, new_proofs.read_scope):
            with pytest.raises(ContractError, match="active_generation_required"):
                await operation(TARGET)
        assert tuple(state["resource_calls"]) == before and not writes
    finally:
        await finish(anchor, t)
