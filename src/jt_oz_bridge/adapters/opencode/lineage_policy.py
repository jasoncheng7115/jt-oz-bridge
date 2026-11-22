"""Preserve each original node's explicit policy; no inherited tool permissions."""

import asyncio
import time
from collections.abc import Mapping
from typing import Any

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.graph_generation import generation_bound
from jt_oz_bridge.adapters.opencode.lineage_resources import V2LineageResourceProofs
from jt_oz_bridge.adapters.opencode.project_policy import (
    NativePolicyEnrollment,
    NativePolicyWitness,
    V2ProjectPolicyGuard,
    _policy_facts,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest


class V2LineagePolicyGuard(V2ProjectPolicyGuard):
    def __init__(
        self,
        proofs: V2LineageResourceProofs,
        enrollments: Mapping[SessionRef, NativePolicyEnrollment],
    ) -> None:
        if set(enrollments) != {node.reference for node in proofs.observation.nodes}:
            raise ValueError("lineage_complete_explicit_node_policies_required")
        for ref, enrollment in enrollments.items():
            node = proofs.original_node(ref)
            if (
                enrollment.native_project_id != node.native_project_id
                or enrollment.fingerprint_sha256 != node.policy_sha256
            ):
                raise ValueError("lineage_original_node_policy_required")
        super().__init__(proofs, enrollments)
        self.lineage = proofs
        self._lineage = proofs
        self._original_enrollments = self.enrollments

    @generation_bound(policy=True)
    def enrolled(self, ref: SessionRef, operation: str) -> bool:
        return bool(
            self.lineage is self._lineage
            and self.proofs is self._lineage
            and self.enrollments is self._original_enrollments
            and super().enrolled(ref, operation)
        )

    @generation_bound(policy=True)
    async def authorize(
        self, ref: SessionRef, operation: str, proof: OriginalExecutionProof
    ) -> NativePolicyWitness:
        self.witnesses.pop(ref, None)
        if not self.lineage.proof_current(ref, proof):
            raise ContractError("lineage_original_resource_proof_required")
        try:
            async with asyncio.timeout(max(0, proof.expires_at - time.time())):
                witness = await super().authorize(ref, operation, proof)
                if not self.lineage.proof_current(ref, proof):
                    raise ContractError("lineage_original_resource_proof_changed")
                return witness
        except BaseException as exc:
            self.witnesses.pop(ref, None)
            if isinstance(exc, TimeoutError):
                raise ContractError("lineage_original_policy_deadline_expired") from None
            raise

    @generation_bound(policy=True)
    def current(
        self, ref: SessionRef, operation: str, proof: OriginalExecutionProof, witness: Any
    ) -> bool:
        return bool(
            self.lineage.proof_current(ref, proof)
            and super().current(ref, operation, proof, witness)
        )

    async def _bundle_facts(self, ref: SessionRef) -> tuple[dict[str, Any], str]:
        if (
            self.lineage is not self._lineage
            or self.proofs is not self._lineage
            or self.enrollments is not self._original_enrollments
        ):
            raise ContractError("lineage_original_policy_graph_replaced")
        node = self.lineage.original_node(ref)
        t = self.lineage.feed.transport
        info = (await t.request("session.get", path={"sessionID": ref.upstream_session_id}))["data"]
        self.lineage.validate_native_info(ref, info)
        aid = info.get("agent")
        if not isinstance(aid, str) or not aid:
            raise ContractError("lineage_original_explicit_agent_required")
        query = {"location": {"directory": ref.canonical_directory}}
        agent, plugins, saved, mcp = await asyncio.gather(
            t.request("agent.get", path={"agentID": aid}, query=query),
            t.request("plugin.list", query=query),
            t.request("permission.saved.list", query={"projectID": node.native_project_id}),
            t.request("mcp.list", query=query),
        )
        facts = _policy_facts(
            ref,
            node.native_project_id,
            info,
            agent,
            plugins,
            saved,
            mcp,
            expected_parent_id=node.parent_reference.upstream_session_id
            if node.parent_reference
            else None,
        )
        return facts, digest(self.lineage.project_info(ref, info))
