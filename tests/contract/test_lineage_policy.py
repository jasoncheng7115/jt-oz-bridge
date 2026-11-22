"""Explicit synthetic per-node policies; no live grants or Native mutations."""

import copy
from types import MappingProxyType
from unittest.mock import AsyncMock

import pytest

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
from jt_oz_bridge.adapters.opencode.project_policy import PERMISSION_SOURCE, NativePolicyEnrollment
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import CHILD, TARGET, setup
from tests.contract.test_public_live_feed import REAL, REF, frame


def policies(proofs):
    return {
        node.reference: NativePolicyEnrollment(
            format="native-project-policy-v1",
            reference=node.reference,
            native_project_id=node.native_project_id,
            contract_sha256=proofs.feed.transport.profile.sha256,
            permission_source_sha256=PERMISSION_SOURCE,
            fingerprint_sha256=node.policy_sha256,
            operations=frozenset({"prompt", "permission.reply", "form.reply"}),
        )
        for node in proofs.observation.nodes
    }


async def test_each_node_keeps_its_own_policy_under_same_original_graph_without_copying_anchor_rules():
    anchor, t, p, bare, tree, state, writes, metadata = await setup()
    try:
        guard = V2LineagePolicyGuard(p, policies(p))
        assert not bare.capabilities(CHILD)["prompt"].supported
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        client = V2ExecutionClient(t, anchor.projects, proofs=p, scope_guard=guard)
        assert client.capabilities(CHILD)["prompt"].supported
        _, proof = await client.qualified_snapshot(CHILD)
        witness = await guard.authorize(CHILD, "prompt", proof)
        assert guard.current(CHILD, "prompt", proof, witness)
        assert witness.fingerprint_sha256 == p.original_node(CHILD).policy_sha256
        assert not guard.current(TARGET, "prompt", proof, witness)
        original = metadata.observer.anchor.enrollments[REF]
        assert all(
            e.fingerprint_sha256 != original.fingerprint_sha256 for e in guard.enrollments.values()
        )
        assert metadata.observer.anchor.enrollments[REF] is original
        assert "check.run" not in guard.enrollments[CHILD].operations
        assert not client.capabilities(CHILD)["check.run"].supported
        assert not writes and all(r.method == "GET" for r in state["resource_calls"])
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "fault", ["missing_child", "copied_anchor_fingerprint", "foreign_project", "foreign_reference"]
)
async def test_metadata_cannot_self_supply_incomplete_or_foreign_operation_policies(fault):
    anchor, t, p, c, tree, state, writes, metadata = await setup()
    try:
        selected = policies(p)
        if fault == "missing_child":
            selected.pop(CHILD)
        elif fault == "copied_anchor_fingerprint":
            selected[CHILD] = selected[CHILD].model_copy(
                update={
                    "fingerprint_sha256": metadata.observer.anchor.enrollments[
                        REF
                    ].fingerprint_sha256
                }
            )
        elif fault == "foreign_project":
            selected[CHILD] = selected[CHILD].model_copy(update={"native_project_id": "foreign"})
        else:
            selected[CHILD] = selected[CHILD].model_copy(update={"reference": TARGET})
        with pytest.raises(ValueError):
            V2LineagePolicyGuard(p, selected)
        assert not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fault", ["session_rules", "agent", "parent", "created"])
async def test_changed_original_node_policy_or_identity_is_rejected_before_any_write(fault):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        guard = V2LineagePolicyGuard(p, policies(p))
        client = V2ExecutionClient(t, anchor.projects, proofs=p, scope_guard=guard)
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await client.qualified_snapshot(CHILD)
        if fault == "session_rules":
            tree["rows"][CHILD]["permissions"] = []
        elif fault == "agent":
            tree["rows"][CHILD]["agent"] = "build"
        elif fault == "parent":
            tree["rows"][CHILD]["parentID"] = "ses_foreign_parent"
        else:
            tree["rows"][CHILD]["time"]["created"] += 1
        with pytest.raises(ContractError):
            await guard.authorize(CHILD, "prompt", proof)
        assert not guard.witnesses and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "fault", ["guard_proofs", "lineage_pointer", "enrollments", "new_child_arrival"]
)
async def test_policy_witness_does_not_survive_replaced_original_graph_or_stream_boundary(fault):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        guard = V2LineagePolicyGuard(p, policies(p))
        client = V2ExecutionClient(t, anchor.projects, proofs=p, scope_guard=guard)
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await client.qualified_snapshot(CHILD)
        witness = await guard.authorize(CHILD, "prompt", proof)
        if fault == "guard_proofs":
            guard.proofs = copy.copy(p)
        elif fault == "lineage_pointer":
            guard.lineage = copy.copy(p)
        elif fault == "enrollments":
            guard.enrollments = MappingProxyType(dict(guard.enrollments))
        else:
            import json

            raw = json.loads(
                json.dumps(REAL[0]).replace(REF.upstream_session_id, "ses_unenrolled_child")
            )
            assert p.feed.index.accept(frame(raw)) is None
        assert not guard.current(CHILD, "prompt", proof, witness) and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "field",
    ["cursor", "ownership_evidence_sha256", "descendants", "issued_at", "session_info_sha256"],
)
async def test_reconstructed_metadata_or_modified_proof_fields_never_supply_original_resource_authority(
    field,
):
    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        guard = V2LineagePolicyGuard(p, policies(p))
        client = V2ExecutionClient(t, anchor.projects, proofs=p, scope_guard=guard)
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await client.qualified_snapshot(CHILD)
        updates = {
            "cursor": "unproven-cursor",
            "ownership_evidence_sha256": "b" * 64,
            "descendants": (),
            "issued_at": proof.issued_at - 0.1,
            "session_info_sha256": "b" * 64,
        }
        forged = proof.model_copy(update={field: updates[field]})
        before = len(state["resource_calls"])
        with pytest.raises(ContractError, match="original_resource_proof_required"):
            await guard.authorize(CHILD, "prompt", forged)
        assert len(state["resource_calls"]) == before and not guard.witnesses and not writes
    finally:
        await finish(anchor, t)


async def test_slow_policy_gets_cannot_renew_an_expired_original_resource_graph(monkeypatch):
    import time

    anchor, t, p, c, tree, state, writes, _ = await setup()
    try:
        guard = V2LineagePolicyGuard(p, policies(p))
        client = V2ExecutionClient(t, anchor.projects, proofs=p, scope_guard=guard)
        await p.watch_graph(authorize=AsyncMock(return_value=True))
        _, proof = await client.qualified_snapshot(CHILD)
        clock = [time.time()]

        def hook(request, state):
            if request.url.path == "/api/session/" + CHILD.upstream_session_id:
                clock[0] = proof.expires_at

        state["hook"] = hook
        monkeypatch.setattr(
            "jt_oz_bridge.adapters.opencode.lineage_policy.time.time", lambda: clock[0]
        )
        with pytest.raises(ContractError):
            await guard.authorize(CHILD, "prompt", proof)
        assert not guard.witnesses and not writes
    finally:
        await finish(anchor, t)
