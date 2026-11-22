"""The single Native Agent setter with exact GET-only observation and readback.

A 204 acknowledges the fixed setter only. Readback pins a default configuration,
not a provider attempt. No retry exists here: any uncertainty after the request
may have opened stays with the caller's durable quarantine.
"""

import asyncio
import time
from collections.abc import Mapping
from typing import Any, cast

from jt_oz_bridge.adapters.opencode.aborted_turn import aborted_head, reconcile_aborted_suffix
from jt_oz_bridge.adapters.opencode.agent_settings import (
    AGENT_SETTING_SCHEMA,
    AgentSettingsAttestation,
    agent_catalog,
    agent_policy_endpoint,
    reconcile_agent_settings_tail,
    require_agent_transition,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError, SnapshotBoundaryChanged
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof, V2ExecutionClient
from jt_oz_bridge.adapters.opencode.info_projection import info_fingerprint
from jt_oz_bridge.adapters.opencode.transport import TransportNotSent
from jt_oz_bridge.domain.agent_selection import (
    AgentCandidate,
    AgentObservation,
    AgentPolicyEndpoint,
    AgentReadback,
    AgentSwitchAck,
    AgentTransitionEnrollment,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import MutationNotSent
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest

# Each read below must be separately attested before the setter becomes available.
AGENT_SWITCH_OPERATIONS = (
    "session.get",
    "session.message.list",
    "agent.list",
    "plugin.list",
    "permission.saved.list",
    "mcp.list",
    "session.switchAgent",
)
SETTING_RECORDS = frozenset({"agent-switched", "model-switched"})


class V2AgentSettings:
    """Exact per-Root setter. The transitions tuple is root-managed, never from chat."""

    def __init__(
        self,
        execution: V2ExecutionClient,
        reference: SessionRef,
        attestation: AgentSettingsAttestation,
        transitions: tuple[AgentTransitionEnrollment, ...],
    ) -> None:
        attestation.require(reference, execution.transport.profile.sha256)
        if len(transitions) > 1000 or any(
            item.before.reference != reference
            or item.before.native_project_id != attestation.native_project_id
            for item in transitions
        ):
            raise ValueError("agent_settings_exact_root_transitions_required")
        for item in transitions:
            require_agent_transition(
                item, item.before, item.after, execution.transport.profile.sha256
            )
        self.execution, self.reference = execution, reference
        self.attestation, self.transitions = attestation, transitions

    def _require(self, reference: SessionRef) -> None:
        if reference != self.reference:
            raise ContractError("agent_settings_original_root_required")

    def contract_for(self, reference: SessionRef) -> str:
        self._require(reference)
        return self.execution.contract_for(reference)

    def available(self, reference: SessionRef) -> bool:
        try:
            self._require(reference)
            capability = self.execution.capabilities(reference).get("agent.switch")
            return capability is not None and capability.supported
        except ValueError:
            return False

    def transition(
        self, before: AgentPolicyEndpoint, after: AgentPolicyEndpoint
    ) -> AgentTransitionEnrollment | None:
        return next((item for item in self.transitions if item.matches(before, after)), None)

    async def _observe(
        self, reference: SessionRef
    ) -> tuple[AgentObservation, dict[str, Any], OriginalExecutionProof]:
        self._require(reference)
        execution = self.execution
        transport, profile = execution.transport, execution.transport.profile
        if profile.sha256 != AGENT_SETTING_SCHEMA:
            raise ContractError("native_agent_exact_installed_schema_required")
        snapshot, proof = await execution.qualified_snapshot(reference)
        query = {"location": {"directory": reference.canonical_directory}}
        session, agents, plugins, saved, mcp, tail = await asyncio.gather(
            transport.request("session.get", path={"sessionID": reference.upstream_session_id}),
            transport.request("agent.list", query=query),
            transport.request("plugin.list", query=query),
            transport.request(
                "permission.saved.list", query={"projectID": self.attestation.native_project_id}
            ),
            transport.request("mcp.list", query=query),
            transport.request(
                "session.message.list",
                path={"sessionID": reference.upstream_session_id},
                query={"limit": "51", "order": "desc"},
            ),
        )
        info = session["data"]
        # Running work updates its counters and times. Only an idle read must match
        # the proof exactly; the setter and readback both require that idle state.
        if (
            snapshot.state == ExecutionState.IDLE
            and info_fingerprint(execution.proofs, reference, info) != proof.session_info_sha256
        ):
            raise SnapshotBoundaryChanged("native_agent_observation_session_changed")
        catalog = agent_catalog(profile, reference, agents)
        rows = {row["id"]: row for row in agents["data"]}
        current_id = info.get("agent")
        if not isinstance(current_id, str) or current_id not in rows:
            raise ContractError("native_agent_current_definition_unavailable")

        def endpoint(row: dict[str, Any]) -> AgentPolicyEndpoint:
            # Permission facts depend on the Session rules and that exact Agent row.
            return agent_policy_endpoint(
                profile,
                reference,
                self.attestation.native_project_id,
                {**info, "agent": row["id"]},
                {"location": agents["location"], "data": row},
                plugins,
                saved,
                mcp,
            )

        current = endpoint(rows[current_id])
        candidates = []
        for item in self.transitions:
            row = rows.get(item.after.definition.agent_id)
            if item.before != current or row is None:
                continue
            target = endpoint(row)
            if item.matches(current, target):
                candidates.append(
                    AgentCandidate(endpoint=target, transition_sha256=item.enrollment_sha256)
                )
        execution.current(reference, proof)
        return (
            AgentObservation(
                reference=reference,
                native_project_id=self.attestation.native_project_id,
                native_created_at=info["time"]["created"],
                configured_model_sha256=digest({"model": info.get("model")}),
                endpoint=current,
                catalog=catalog,
                candidates=tuple(candidates),
                state=snapshot.state,
                settings_tail_ready=self._settings_tail_ready(info, tail),
                owner_evidence_sha256=proof.ownership_evidence_sha256,
                session_info_sha256=proof.session_info_sha256,
                observed_at=proof.issued_at,
            ),
            info,
            proof,
        )

    @staticmethod
    def _settings_tail_ready(info: dict[str, Any], tail: dict[str, Any]) -> bool:
        """A following agent-switched record must reach a positive idle in one page."""
        rows = tail["data"][:50]
        newer = info["time"]["updated"]
        for index, row in enumerate(rows):
            if row["type"] == "idle":
                return bool(
                    row.get("outcome") == info.get("outcome")
                    and row["time"]["created"] == info["time"].get("idle")
                )
            if aborted_head(row):
                # The same exact declined-permission tail the settings reader accepts.
                try:
                    turn = reconcile_aborted_suffix(info, rows[index:], tail["cursor"], newer)
                except ContractError:
                    return False
                return turn["idle"] is not None
            if row["type"] not in SETTING_RECORDS:
                return False
            newer = row["time"]["created"]
        return False

    async def observe(self, reference: SessionRef) -> AgentObservation:
        for attempt in range(4):
            try:
                return (await self._observe(reference))[0]
            except SnapshotBoundaryChanged:
                if attempt == 3:
                    raise
                await asyncio.sleep(0.05 * (attempt + 1))
        raise ContractError("native_agent_observation_unavailable")

    async def switch(
        self,
        reference: SessionRef,
        action_id: str,
        before: AgentPolicyEndpoint,
        after: AgentPolicyEndpoint,
    ) -> AgentSwitchAck:
        """Exactly one POST. MutationNotSent is only ever raised before it may open."""
        execution = self.execution
        path = {"sessionID": reference.upstream_session_id}
        body = {"agent": after.definition.agent_id}
        try:
            observation, _info, proof = await self._observe(reference)
            guard = execution.scope_guard
            candidate = observation.candidate(after.definition.agent_id)
            if (
                not self.available(reference)
                or guard is None
                or observation.state != ExecutionState.IDLE
                or not observation.settings_tail_ready
                or observation.endpoint != before
                or candidate is None
                or candidate.endpoint != after
                or self.transition(before, after) is None
            ):
                raise ContractError("native_agent_switch_preflight_changed")
            execution.transport.profile.prepare("session.switchAgent", path=path, body=body)
            witness = await guard.authorize(reference, "agent.switch", proof)
            attestation = execution.transport.attestation
        except Exception:
            raise MutationNotSent("native_agent_switch_preflight_rejected") from None

        def ready() -> None:
            execution.current(reference, proof)
            if (
                execution.transport.attestation is not attestation
                or not self.available(reference)
                or cast(Any, guard).current(reference, "agent.switch", proof, witness) is not True
            ):
                raise ContractError("native_agent_switch_guard_changed")

        try:
            value = await execution.transport.request(
                "session.switchAgent", path=path, body=body, before_send=ready
            )
        except TransportNotSent:
            raise MutationNotSent("native_agent_switch_transport_did_not_send") from None
        if value is not None:
            raise ContractError("native_agent_switch_expected_no_content")
        return AgentSwitchAck(
            action_id=action_id,
            agent_id=after.definition.agent_id,
            ack_sha256=digest({"status": 204, "action_id": action_id, "body": body}),
        )

    async def readback(
        self,
        reference: SessionRef,
        ack: AgentSwitchAck,
        before: AgentPolicyEndpoint,
        after: AgentPolicyEndpoint,
    ) -> AgentReadback:
        """GET only, and bounded. A mismatch is uncertain, never grounds for a retry."""
        started = time.time()
        async with asyncio.timeout(5):
            for attempt in range(4):
                try:
                    observation, info, _proof = await self._observe(reference)
                    second, _second_info, _second_proof = await self._observe(reference)
                except SnapshotBoundaryChanged:
                    if attempt == 3:
                        raise
                    await asyncio.sleep(0.05 * (attempt + 1))
                    continue
                if (
                    observation.endpoint != after
                    or second.endpoint != after
                    or observation.session_info_sha256 != second.session_info_sha256
                    or ack.agent_id != after.definition.agent_id
                    or not started <= time.time() < started + 5
                ):
                    raise ContractError("native_agent_switch_readback_not_verified")
                page = await self.execution.transport.request(
                    "session.message.list",
                    path={"sessionID": reference.upstream_session_id},
                    query={"limit": "51", "order": "desc"},
                )
                tail = reconcile_agent_settings_tail(
                    self.execution.transport.profile,
                    reference,
                    info,
                    page,
                    self.attestation,
                )
                head = tail["controls"][0]
                if (
                    head["type"] != "agent-switched"
                    or head["agent"] != after.definition.agent_id
                    or head["previous"] != before.definition.agent_id
                ):
                    raise ContractError("native_agent_switch_tail_not_attributed")
                return AgentReadback(
                    observation=second,
                    readback_sha256=digest(
                        {
                            "endpoint": after.model_dump(mode="json"),
                            "session_info_sha256": second.session_info_sha256,
                            "tail": tail,
                        }
                    ),
                )
        raise ContractError("native_agent_switch_readback_not_verified")


def agent_settings_by_reference(
    items: Mapping[SessionRef, V2AgentSettings],
) -> Mapping[SessionRef, AgentSettingsAttestation]:
    return {ref: item.attestation for ref, item in items.items()}
