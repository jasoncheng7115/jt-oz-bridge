"""Configuration-aware readiness over SQL heads; GET-only restore, never a Native write.

A stable head names approved defaults and the selected Bridge composition. Fresh
Native observation decides whether the running process may treat it as mutation
ready. Different observed state stays a read-only review; it is never compensated.
"""

import asyncio
import logging
from collections.abc import Mapping
from typing import Any, Literal, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.agent_configuration import (
    AgentConfigurationCell,
    ConfigurationReadiness,
    ReadinessReason,
)
from jt_oz_bridge.adapters.opencode.agent_settings import AgentSettingsAttestation
from jt_oz_bridge.domain.agent_selection import (
    AgentObservation,
    AgentPolicyEndpoint,
    AgentReadback,
    AgentSwitchAck,
    AgentTransitionEnrollment,
)
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.session_configuration_heads import (
    AgentSettingResult,
    AgentSwitchIntent,
    ConfigurationNode,
    ConfigurationOrigin,
    ConfigurationSnapshot,
    EffectiveConfiguration,
    GuardedAgent,
    InitializationProof,
    LockedAuthority,
    SessionConfigurationHeads,
)

LOG = logging.getLogger(__name__)
READ_FAILURES = (ValueError, TimeoutError, ConnectionError)


class AgentSettingsClient(Protocol):
    """Exact per-Root adapter; synthetic tests must not be read as live evidence."""

    attestation: AgentSettingsAttestation
    transitions: tuple[AgentTransitionEnrollment, ...]

    def available(self, reference: SessionRef) -> bool: ...

    async def observe(self, reference: SessionRef) -> AgentObservation: ...

    async def switch(
        self,
        reference: SessionRef,
        action_id: str,
        before: AgentPolicyEndpoint,
        after: AgentPolicyEndpoint,
    ) -> AgentSwitchAck: ...

    async def readback(
        self,
        reference: SessionRef,
        ack: AgentSwitchAck,
        before: AgentPolicyEndpoint,
        after: AgentPolicyEndpoint,
    ) -> AgentReadback: ...


async def no_actor_authority(_session: AsyncSession) -> None:
    """Restore acts for no Human: it only reads, or moves a head toward less trust."""


def always_current() -> bool:
    return True


def effective_configuration(
    observation: AgentObservation,
    endpoint: AgentPolicyEndpoint,
    attestation: AgentSettingsAttestation,
    *,
    guarded: tuple[AgentPolicyEndpoint, ...] = (),
) -> EffectiveConfiguration:
    """Fingerprints only. Definition/system/permission bodies are never stored."""
    agents = {
        item.definition.agent_id: GuardedAgent(
            agent_id=item.definition.agent_id,
            definition_sha256=item.definition.definition_sha256,
            policy_inputs_sha256=item.policy_sha256,
        )
        for item in (*guarded, endpoint)
    }
    node = ConfigurationNode(
        node_key=digest(observation.reference.model_dump(mode="json")),
        policy_sha256=endpoint.policy_sha256,
        reader_qualification_sha256=digest(attestation.model_dump(mode="json")),
    )
    return EffectiveConfiguration(
        agent_id=endpoint.definition.agent_id,
        configured_model_sha256=observation.configured_model_sha256,
        context_qualification_sha256=digest(
            {"attestation": node.reader_qualification_sha256, "policy": endpoint.policy_sha256}
        ),
        node_scope_sha256=digest({"nodes": [node.model_dump(mode="json")]}),
        guarded_agents=tuple(agents.values()),
        nodes=(node,),
    )


def same_configuration(effective: EffectiveConfiguration, endpoint: AgentPolicyEndpoint) -> bool:
    """Exact definition and policy fingerprints; a matching Agent ID alone is never enough."""
    guarded = next((a for a in effective.guarded_agents if a.agent_id == effective.agent_id), None)
    return bool(
        guarded is not None
        and effective.agent_id == endpoint.definition.agent_id
        and guarded.definition_sha256 == endpoint.definition.definition_sha256
        and len(effective.nodes) == 1
        and effective.nodes[0].policy_sha256 == endpoint.policy_sha256
    )


class AgentConfigurationRegistry:
    """Facade selecting one published configuration for each managed original Root."""

    def __init__(
        self,
        heads: SessionConfigurationHeads,
        cell: AgentConfigurationCell,
        clients: Mapping[SessionRef, AgentSettingsClient],
        origins: Mapping[SessionRef, tuple[str, str]],
        original_policies: Mapping[SessionRef, str],
    ) -> None:
        if (
            heads.enabled is not True
            or set(clients) != set(origins)
            or set(clients) != set(original_policies)
        ):
            raise ValueError("agent_configuration_explicit_complete_enrollment_required")
        self.heads, self.cell, self.clients = heads, cell, clients
        self.origins, self.original_policies = origins, original_policies
        self._gates: dict[SessionRef, asyncio.Lock] = {ref: asyncio.Lock() for ref in clients}

    def gate(self, reference: SessionRef) -> asyncio.Lock:
        """Serializes one Root's attempt and its background restore in this process."""
        return self._gates[reference]

    def client(self, reference: SessionRef) -> AgentSettingsClient | None:
        return self.clients.get(reference)

    def origin(self, observation: AgentObservation) -> ConfigurationOrigin:
        client = self.clients[observation.reference]
        identity, payload = self.origins[observation.reference]
        return ConfigurationOrigin(
            root=observation.reference,
            native_created_at=observation.native_created_at,
            original_registration_identity_sha256=identity,
            original_registration_payload_sha256=payload,
            qualification_sha256=digest(client.attestation.model_dump(mode="json")),
        )

    async def snapshot(self, reference: SessionRef) -> ConfigurationSnapshot | None:
        return await self.heads.snapshot_for_reference(
            reference, lock_authority=no_actor_authority, current=always_current
        )

    def publish_snapshot(
        self,
        saved: ConfigurationSnapshot,
        *,
        reason: ReadinessReason | None,
    ) -> ConfigurationReadiness:
        effective = saved.effective
        return self.cell.set(
            ConfigurationReadiness(
                reference=saved.origin.root,
                root_key=saved.token.root_key,
                revision=saved.token.revision,
                effective_sha256=saved.token.effective_sha256,
                agent_id=effective.agent_id,
                policy_sha256=effective.nodes[0].policy_sha256,
                mode="mutation_ready" if reason is None else "read_only",
                reason=reason,
            )
        )

    async def ensure_head(
        self,
        observation: AgentObservation,
        *,
        lock_authority: LockedAuthority,
        current: Any,
    ) -> ConfigurationSnapshot:
        """Explicit first enrollment from a fresh observation of the enrolled policy.

        Only an exact match to the root-enrolled original fingerprint may mint
        revision one. An old registration or Agent label cannot substitute for it.
        """
        reference = observation.reference
        saved = await self.heads.snapshot_for_reference(
            reference, lock_authority=lock_authority, current=current
        )
        if saved is not None:
            return saved
        client = self.clients[reference]
        if observation.endpoint.policy_sha256 != self.original_policies[reference]:
            raise Conflict("agent_configuration_root_changed_before_enrollment")
        origin = self.origin(observation)
        effective = effective_configuration(observation, observation.endpoint, client.attestation)
        created = await self.heads.initialize(
            origin,
            effective,
            InitializationProof(
                kind="qualified_original_root",
                origin_sha256=digest(origin.model_dump(mode="json")),
                effective_sha256=digest(effective.model_dump(mode="json")),
                qualification_sha256=origin.qualification_sha256,
                observed_at=observation.observed_at,
            ),
            lock_authority=lock_authority,
            current=current,
        )
        self.publish_snapshot(created, reason=None)
        return created

    async def restore(self, reference: SessionRef) -> ConfigurationReadiness | None:
        """GET-only reconstruction after restart or drift. It never sends a setter."""
        client = self.clients[reference]
        async with self.gate(reference):
            saved = await self.snapshot(reference)
            if saved is None:
                return None
            if saved.token.phase == "dispatching":
                # This process owns no in-flight attempt under the gate, so an open
                # reservation means an attempt may have opened. Absence of a new
                # record cannot prove otherwise; never reset it to a retryable state.
                saved = await self.heads.settle(
                    saved.token,
                    "quarantined",
                    digest({"restart_uncertain_attempt": saved.token.active_action_id}),
                    lock_authority=no_actor_authority,
                    current=always_current,
                )
            if saved.token.phase == "quarantined":
                return self.publish_snapshot(saved, reason="review_required")
            try:
                observation = await client.observe(reference)
            except READ_FAILURES:
                # A failed read proves nothing. The guard still checks exact policy
                # before each mutation, so do not drop a proven stable readiness.
                current = self.cell.readiness(reference)
                if (
                    saved.token.phase == "stable"
                    and current is not None
                    and current.mode == "mutation_ready"
                    and current.revision == saved.token.revision
                ):
                    return current
                return self.publish_snapshot(saved, reason=self._read_failed(saved))
            phase = saved.token.phase
            if phase == "activation_prepared":
                return await self._restore_prepared(saved, observation)
            matches = same_configuration(saved.effective, observation.endpoint)
            if phase == "external_unqualified":
                if not matches:
                    return self.publish_snapshot(saved, reason="external_change")
                saved = await self.heads.release_external(
                    saved.token, lock_authority=no_actor_authority, current=always_current
                )
                return self.publish_snapshot(saved, reason=None)
            if matches:
                return self.publish_snapshot(saved, reason=None)
            saved = await self.heads.mark_external(
                saved.token, lock_authority=no_actor_authority, current=always_current
            )
            LOG.warning("agent_configuration_external_change root=%s", saved.token.root_key[:12])
            return self.publish_snapshot(saved, reason="external_change")

    @staticmethod
    def _read_failed(saved: ConfigurationSnapshot) -> ReadinessReason:
        phases: dict[str, ReadinessReason] = {
            "activation_prepared": "activation_unverified",
            "external_unqualified": "external_change",
        }
        return phases.get(saved.token.phase, "native_unverified")

    async def _restore_prepared(
        self, saved: ConfigurationSnapshot, observation: AgentObservation
    ) -> ConfigurationReadiness:
        pending = saved.pending
        if pending is None or not same_configuration(pending.after, observation.endpoint):
            return self.publish_snapshot(saved, reason="activation_unverified")
        action = await self.active_result(saved)

        async def hold(session: AsyncSession) -> None:
            from jt_oz_bridge.services.agent_switch_coordinator import hold_unsent_root_work
            from jt_oz_bridge.storage.control_models import Binding

            binding = await session.get(Binding, pending.binding_id)
            if binding is not None:
                await hold_unsent_root_work(session, binding)

        activated = await self.heads.settle(
            saved.token,
            "activated",
            action.evidence_sha256,
            lock_authority=no_actor_authority,
            current=always_current,
            staged_context_sha256=pending.after.context_qualification_sha256,
            staged_context_observed_at=observation.observed_at,
            on_activated=hold,
        )
        return self.publish_snapshot(activated, reason=None)

    async def active_result(self, saved: ConfigurationSnapshot) -> AgentSettingResult:
        from jt_oz_bridge.storage.models import Action

        identity = saved.token.active_action_id
        async with self.heads.db.sessions() as session:
            action = await session.get(Action, identity) if identity else None
        if action is None or not action.native_result:
            raise Conflict("agent_configuration_prepared_result_missing")
        return AgentSettingResult.model_validate(action.native_result)

    async def restore_all(self) -> None:
        for reference in self.clients:
            try:
                await self.restore(reference)
            except Conflict as error:
                # Keep other Roots available; this Root stays closed until it resolves.
                LOG.warning(
                    "agent_configuration_restore_refused root=%s kind=%s",
                    reference.upstream_session_id,
                    type(error).__name__,
                )

    def status(
        self, reference: SessionRef
    ) -> Literal["unmanaged", "mutation_ready"] | ReadinessReason:
        saved = self.cell.readiness(reference)
        if saved is None:
            return "unmanaged"
        return saved.reason if saved.reason is not None else "mutation_ready"

    def published(self, reference: SessionRef, intent: AgentSwitchIntent) -> bool:
        """The committed activation (reserve, prepared, activated) reached this process."""
        saved = self.cell.readiness(reference)
        return (
            saved is not None
            and saved.root_key == intent.root_key
            and saved.revision >= intent.expected_revision + 3
        )
