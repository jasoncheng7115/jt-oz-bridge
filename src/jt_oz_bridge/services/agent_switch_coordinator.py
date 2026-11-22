"""The only path to the Native Agent setter: one durable attempt, never a retry.

Reservation commits before the request may open. A worker crash, lost ACK or
unverified readback stays quarantined. Observed equality never settles it.
"""

import asyncio
import logging
import time
from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.domain.agent_selection import AgentPolicyEndpoint, AgentSettingNotice
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import Admission, HumanMessage, MutationNotSent, SourceReader
from jt_oz_bridge.domain.models import ActionState
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.agent_configuration import (
    AgentConfigurationRegistry,
    always_current,
    no_actor_authority,
)
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from jt_oz_bridge.storage.session_configuration_heads import (
    AgentSettingEvidence,
    AgentSwitchIntent,
    ConfigurationCommitExpectation,
    ConfigurationSnapshot,
    KnownUnsentEvidence,
)

LOG = logging.getLogger(__name__)
CONFIGURATION_HELD = "agent_configuration_changed"
EXPIRED = "agent_confirmation_expired"
HELD_OPERATIONS = (
    "prompt",
    "model.switch",
    "check.run",
    "session.rename",
    "permission.reply",
    "form.reply",
    "form.cancel",
)
ROOT_BUSY_STATES = ("dispatching", "admitted", "running", "ambiguous")


async def root_actions_busy(session: AsyncSession, binding: Binding) -> bool:
    found = await session.scalar(
        select(Action.id)
        .join(Binding, Binding.id == Action.binding_id)
        .where(
            Binding.backend_id == binding.backend_id,
            Binding.backend_identity == binding.backend_identity,
            Binding.session_id == binding.session_id,
            Action.operation.in_(HELD_OPERATIONS),
            Action.state.in_(ROOT_BUSY_STATES),
        )
        .limit(1)
    )
    return found is not None


async def hold_unsent_root_work(session: AsyncSession, binding: Binding) -> None:
    """Unsent work stays visibly held, never silently retagged to a new configuration."""
    await session.execute(
        update(Action)
        .where(
            Action.state == "queued",
            Action.operation.in_(HELD_OPERATIONS),
            Action.binding_id.in_(
                select(Binding.id).where(
                    Binding.backend_id == binding.backend_id,
                    Binding.backend_identity == binding.backend_identity,
                    Binding.session_id == binding.session_id,
                )
            ),
        )
        .values(
            state=ActionState.HELD,
            version=Action.version + 1,
            status_reason=CONFIGURATION_HELD,
        )
        .execution_options(synchronize_session=False)
    )


class AgentSwitchCoordinator:
    def __init__(
        self,
        bindings: BindingService,
        registry: AgentConfigurationRegistry,
        reader: SourceReader,
        fence: ConsumerFence,
        *,
        realm_id: str,
    ) -> None:
        if registry.heads.db is not bindings.db or registry.heads.fence != fence:
            raise ValueError("agent_switch_requires_original_database_and_fence")
        self.bindings, self.db, self.registry = bindings, bindings.db, registry
        self.reader, self.fence, self.realm_id = reader, fence, realm_id

    async def queued(self) -> tuple[str, ...]:
        async with self.db.sessions() as session:
            found = await session.scalars(
                select(Action.id)
                .join(Binding, Binding.id == Action.binding_id)
                .where(
                    Action.operation == "agent.switch",
                    Action.state == "queued",
                    Binding.realm_id == self.realm_id,
                    Binding.state == "active",
                )
                .order_by(Action.created_at, Action.id)
                .limit(16)
            )
            return tuple(str(item) for item in found.all())

    async def _finish_unsent(
        self, action: Action, state: Literal["rejected", "held"], reason: str
    ) -> str:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await session.execute(
                update(Action)
                .where(
                    Action.id == action.id,
                    Action.state == "queued",
                    Action.version == action.version,
                    Action.operation == "agent.switch",
                )
                .values(state=state, version=Action.version + 1, status_reason=reason)
            )
        return state

    async def advance(self, action_id: str) -> str:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
            stored = await session.get(Binding, action.binding_id) if action else None
        if action is None or action.operation != "agent.switch" or stored is None:
            raise Conflict("agent_switch_action_unavailable")
        if action.state != "queued":
            return action.state
        async with self.registry.gate(reference(stored)):
            return await self._advance(action, stored)

    async def _advance(self, action: Action, stored: Binding) -> str:
        ref = reference(stored)
        client = self.registry.client(ref)
        try:
            intent = AgentSwitchIntent.model_validate(action.payload)
            source = HumanMessage.model_validate(intent.source)
            preview = HumanMessage.model_validate(intent.preview_source)
            before = AgentPolicyEndpoint.model_validate(intent.before_endpoint)
            after = AgentPolicyEndpoint.model_validate(intent.after_endpoint)
            if (
                digest(action.payload) != action.operation_digest
                or intent.reference != ref
                or digest(source.model_dump(mode="json")) != intent.source_sha256
                or digest(preview.model_dump(mode="json")) != intent.preview_sha256
            ):
                raise ValueError("agent_switch_intent_changed")
        except ValueError:
            return await self._finish_unsent(action, "rejected", "source_or_identity_changed")
        if intent.confirmation_expires_at is None or time.time() >= intent.confirmation_expires_at:
            return await self._finish_unsent(action, "rejected", EXPIRED)
        if client is None or not client.available(ref):
            # Often just a lost watch. Wait; the short deadline above ends this visibly.
            return "queued"
        try:
            binding = await self.bindings.get(
                action.binding_id, stored.realm_id, action.actor_id, Permission.OPERATE
            )
            if binding.revision != action.binding_revision or reference(binding) != ref:
                raise Conflict("agent_switch_binding_changed")
            for original in (preview, source):
                if await self.reader.read(original.realm_id, original.message_id) != original:
                    raise Conflict("agent_switch_source_changed")
        except (DeliveryRateLimited, ZulipReadUnavailable):
            return "queued"  # Only reads happened; the next pass restarts all checks.
        except AccessDenied:
            return await self._finish_unsent(action, "rejected", "authorization_revoked")
        except (Conflict, ValueError):
            return await self._finish_unsent(action, "rejected", "source_or_identity_changed")
        if binding.dispatch_paused:
            return await self._finish_unsent(action, "held", "queue_paused")
        saved = await self.registry.snapshot(ref)
        if saved is None or saved.token.root_key != intent.root_key:
            return await self._finish_unsent(action, "rejected", "source_or_identity_changed")
        if saved.token.phase != "stable":
            return "queued"

        async def lock_operator(session: AsyncSession) -> None:
            current = await lock_output_scope(self.bindings, session, binding)
            if current.dispatch_paused:
                raise Conflict("agent_switch_queue_paused")
            grant = await session.scalar(
                select(Grant.id)
                .where(
                    Grant.realm_id == current.realm_id,
                    Grant.user_id == action.actor_id,
                    Grant.project_id == current.project_id,
                    Grant.active.is_(True),
                    Grant.role.in_(
                        [r for r, values in ROLES.items() if Permission.OPERATE in values]
                    ),
                )
                .with_for_update()
            )
            if grant is None:
                raise AccessDenied("agent_switch_operate_grant_changed")
            if await root_actions_busy(session, current):
                raise _RootBusy("agent_switch_root_busy")

        try:
            reserved = await self.registry.heads.reserve(
                saved.token,
                action.id,
                action.version,
                lock_authority=lock_operator,
                current=always_current,
            )
        except _RootBusy:
            return "queued"
        except AccessDenied:
            return await self._finish_unsent(action, "rejected", "authorization_revoked")
        except Conflict:
            return await self._finish_unsent(action, "rejected", "agent_configuration_stale")
        except Exception:
            # A lost commit decides nothing about Native: no request has opened.
            return await self._lost_reservation(action, intent, saved)
        self.registry.publish_snapshot(reserved, reason="transition")
        return await self._attempt(action, intent, before, after, reserved)

    async def _lost_reservation(
        self, action: Action, intent: AgentSwitchIntent, saved: ConfigurationSnapshot
    ) -> str:
        expected = self._expectation(saved, "dispatching", action.id, intent, None)
        try:
            result = await self.registry.heads.reconcile_attempt(
                saved.token, expected, lock_authority=no_actor_authority, current=always_current
            )
        except Exception:
            return action.state
        if result.status == "predecessor_locked":
            return "queued"
        await self._settle_unsent(
            action, intent, result.snapshot, {"phase": "reservation_commit_uncertain"}
        )
        return "rejected"

    @staticmethod
    def _expectation(
        saved: ConfigurationSnapshot,
        phase: Literal["dispatching", "quarantined", "stable", "activation_prepared"],
        action_id: str,
        intent: AgentSwitchIntent,
        evidence_sha256: str | None,
        *,
        activated: bool = False,
    ) -> ConfigurationCommitExpectation:
        return ConfigurationCommitExpectation(
            root_key=saved.token.root_key,
            revision=saved.token.revision + 1,
            phase=phase,
            effective_sha256=digest(intent.after.model_dump(mode="json"))
            if activated
            else saved.token.effective_sha256,
            active_action_id=None if phase == "stable" else action_id,
            last_activation_action_id=action_id
            if activated
            else saved.token.last_activation_action_id,
            transition_action_id=action_id,
            transition_intent_sha256=digest(intent.model_dump(mode="json")),
            transition_evidence_sha256=evidence_sha256,
        )

    async def _settle_unsent(
        self,
        action: Action,
        intent: AgentSwitchIntent,
        saved: ConfigurationSnapshot,
        proof: dict[str, str],
    ) -> ConfigurationSnapshot | None:
        evidence = KnownUnsentEvidence(
            kind="native_request_not_opened",
            action_id=action.id,
            intent_sha256=digest(action.payload),
            reserved_revision=saved.token.revision,
            proof_sha256=digest(proof),
        )
        evidence_sha = digest(evidence.model_dump(mode="json"))
        try:
            result = await self.registry.heads.settle(
                saved.token,
                "not_sent",
                evidence_sha,
                lock_authority=no_actor_authority,
                current=always_current,
                not_sent_evidence=evidence,
            )
        except Exception:
            lost = await self._resolve_lost(
                saved, self._expectation(saved, "stable", action.id, intent, evidence_sha)
            )
            if lost is None:
                return None
            result = lost
        self.registry.publish_snapshot(result, reason=None)
        return result

    async def _resolve_lost(
        self, saved: ConfigurationSnapshot, expected: ConfigurationCommitExpectation
    ) -> ConfigurationSnapshot | None:
        """A lost response never permits resending: join SQL and keep what is proven."""
        try:
            result = await self.registry.heads.reconcile_attempt(
                saved.token, expected, lock_authority=no_actor_authority, current=always_current
            )
        except Exception:
            return None
        return result.snapshot if result.status == "exact_committed" else None

    async def _quarantine(
        self, action: Action, intent: AgentSwitchIntent, saved: ConfigurationSnapshot, label: str
    ) -> str:
        evidence_sha = digest({"attempt_uncertain": action.id, "label": label})
        try:
            result = await self.registry.heads.settle(
                saved.token,
                "quarantined",
                evidence_sha,
                lock_authority=no_actor_authority,
                current=always_current,
            )
        except Exception:
            lost = await self._resolve_lost(
                saved, self._expectation(saved, "quarantined", action.id, intent, evidence_sha)
            )
            if lost is None:
                return "dispatching"  # Restart quarantines it; nothing is ever resent.
            result = lost
        self.registry.publish_snapshot(result, reason="review_required")
        return "ambiguous"

    async def _attempt(
        self,
        action: Action,
        intent: AgentSwitchIntent,
        before: AgentPolicyEndpoint,
        after: AgentPolicyEndpoint,
        reserved: ConfigurationSnapshot,
    ) -> str:
        ref = intent.reference
        client = self.registry.clients[ref]
        try:
            ack = await client.switch(ref, action.id, before, after)
        except MutationNotSent:
            await self._settle_unsent(action, intent, reserved, {"phase": "native_preflight"})
            return "rejected"
        except asyncio.CancelledError:
            await asyncio.shield(self._quarantine(action, intent, reserved, "cancelled"))
            raise
        except Exception:
            return await self._quarantine(action, intent, reserved, "outcome_unknown")
        # ACK from here on. Everything still unproven keeps the Root quarantined.
        try:
            readback = await client.readback(ref, ack, before, after)
        except asyncio.CancelledError:
            await asyncio.shield(self._quarantine(action, intent, reserved, "readback_cancelled"))
            raise
        except Exception:
            return await self._quarantine(action, intent, reserved, "readback_unverified")
        evidence = AgentSettingEvidence(
            native_ack_sha256=ack.ack_sha256,
            readback_sha256=readback.readback_sha256,
            after_configuration_sha256=digest(intent.after.model_dump(mode="json")),
            supported_context_sha256=intent.after.context_qualification_sha256,
            observed_at=readback.observation.observed_at,
        )
        evidence_sha = digest(evidence.model_dump(mode="json"))
        receipt = ExecutionReceipt(
            action_id=action.id,
            operation_digest=action.operation_digest,
            reference=ref,
            contract_sha256=self.bindings.control.contract_for(ref),
            admission=Admission(
                status="admitted",
                owner="opencode",
                details={
                    **AgentSettingNotice(
                        before_agent_id=before.definition.agent_id,
                        after_agent_id=after.definition.agent_id,
                    ).model_dump(mode="json"),
                    "agent_setting": evidence.model_dump(mode="json"),
                },
            ),
        )
        try:
            prepared = await self.registry.heads.settle(
                reserved.token,
                "prepared",
                evidence_sha,
                lock_authority=no_actor_authority,
                current=always_current,
                receipt=receipt,
                evidence=evidence,
            )
        except Exception:
            lost = await self._resolve_lost(
                reserved,
                self._expectation(reserved, "activation_prepared", action.id, intent, evidence_sha),
            )
            if lost is None:
                # Restart restores it by GET, without another setter call.
                return "dispatching"
            prepared = lost
        self.registry.publish_snapshot(prepared, reason="transition")

        async def hold(session: AsyncSession) -> None:
            binding = await session.get(Binding, action.binding_id)
            if binding is None:
                raise Conflict("agent_switch_binding_missing")
            await hold_unsent_root_work(session, binding)

        try:
            activated = await self.registry.heads.settle(
                prepared.token,
                "activated",
                evidence_sha,
                lock_authority=no_actor_authority,
                current=always_current,
                staged_context_sha256=intent.after.context_qualification_sha256,
                staged_context_observed_at=readback.observation.observed_at,
                on_activated=hold,
            )
        except Exception:
            lost = await self._resolve_lost(
                prepared,
                self._expectation(
                    prepared, "stable", action.id, intent, evidence_sha, activated=True
                ),
            )
            if lost is None:
                self.registry.publish_snapshot(prepared, reason="activation_unverified")
                return "admitted"
            activated = lost
        self.registry.publish_snapshot(activated, reason=None)
        return "completed"

    async def run_once(self) -> None:
        for identity in await self.queued():
            try:
                await self.advance(identity)
            except (Conflict, AccessDenied):
                # This Action stays closed; other Roots must still make progress.
                LOG.warning("agent_switch_advance_refused action=%s", identity)


class _RootBusy(Conflict):
    """Same-Root work is in flight. This is a wait, not a rejection of the request."""
