"""Fenced configuration persistence only; never a Native call or readiness pointer.

Origin evidence stays immutable. A stable head describes approved defaults and a
Bridge composition, not an in-flight Native attempt or a mutation-ready registry.
All writes require explicit opt-in and caller-owned, current locked authority.
No absent row is implicitly enrolled or treated as qualified legacy revision0.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.session_configuration_models import SessionConfigurationHead

type SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
type Revision = Annotated[StrictInt, Field(ge=1, le=2**63 - 1)]
type LockedAuthority = Callable[[AsyncSession], Awaitable[None]]
type CurrentProof = Callable[[], bool]
type Phase = Literal[
    "stable", "dispatching", "activation_prepared", "quarantined", "external_unqualified"
]
MAX_HEAD_BYTES = 1024**2
MAX_HEADS = 1000


class ConfigurationDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class ConfigurationOrigin(ConfigurationDocument):
    root: SessionRef
    native_created_at: float = Field(ge=0, allow_inf_nan=False)
    original_registration_identity_sha256: SHA256
    original_registration_payload_sha256: SHA256
    qualification_sha256: SHA256

    @model_validator(mode="after")
    def original_root(self) -> ConfigurationOrigin:
        values = self.root.model_dump()
        if any(not v or len(v) > 1024 for v in values.values()):
            raise ValueError("complete_original_root_required")
        directory = PurePosixPath(self.root.canonical_directory)
        if not directory.is_absolute() or ".." in directory.parts:
            raise ValueError("canonical_original_root_directory_required")
        return self


class ConfigurationNode(ConfigurationDocument):
    node_key: SHA256
    policy_sha256: SHA256
    reader_qualification_sha256: SHA256


class GuardedAgent(ConfigurationDocument):
    agent_id: str = Field(min_length=1, max_length=128)
    definition_sha256: SHA256
    policy_inputs_sha256: SHA256


class EffectiveConfiguration(ConfigurationDocument):
    format: Literal["session-effective-configuration-v1"] = "session-effective-configuration-v1"
    agent_id: str = Field(min_length=1, max_length=128)
    configured_model_sha256: SHA256
    context_qualification_sha256: SHA256
    node_scope_sha256: SHA256
    guarded_agents: tuple[GuardedAgent, ...] = Field(min_length=1, max_length=1000)
    nodes: tuple[ConfigurationNode, ...] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def bounded_current_composition(self) -> EffectiveConfiguration:
        if (
            len({n.node_key for n in self.nodes}) != len(self.nodes)
            or len({a.agent_id for a in self.guarded_agents}) != len(self.guarded_agents)
            or self.agent_id not in {a.agent_id for a in self.guarded_agents}
            or digest({"nodes": [n.model_dump(mode="json") for n in self.nodes]})
            != self.node_scope_sha256
        ):
            raise ValueError("unique_exact_current_configuration_scope_required")
        return self


class InitializationProof(ConfigurationDocument):
    kind: Literal["qualified_original_root"]
    origin_sha256: SHA256
    effective_sha256: SHA256
    qualification_sha256: SHA256
    observed_at: float = Field(ge=0, allow_inf_nan=False)


class AgentSwitchIntent(ConfigurationDocument):
    format: Literal["session-agent-switch-intent-v1"] = "session-agent-switch-intent-v1"
    # agent.adopt records a local-only approval of observed Native state. It has no
    # Native attempt and never relabels an earlier ambiguous agent.switch Action.
    operation: Literal["agent.switch", "agent.adopt"] = "agent.switch"
    action_id: str = Field(min_length=1, max_length=36)
    realm_id: str = Field(min_length=1, max_length=255)
    binding_id: str = Field(min_length=1, max_length=36)
    binding_revision: Revision
    actor_id: Revision
    queued_action_version: Revision
    reference: SessionRef
    root_key: SHA256
    origin_sha256: SHA256
    expected_revision: Revision
    before_configuration_sha256: SHA256
    after: EffectiveConfiguration
    source_sha256: SHA256
    preview_sha256: SHA256
    confirmation_sha256: SHA256
    transition_certificate_sha256: SHA256
    affected_scope_sha256: SHA256
    owner_epoch_sha256: SHA256
    # Frozen original Human Sources and exact endpoints for later rereads/rendering.
    source: dict[str, Any] | None = None
    preview_source: dict[str, Any] | None = None
    reply_locale: Literal["en", "zh-TW"] | None = None
    before_endpoint: dict[str, Any] | None = None
    after_endpoint: dict[str, Any] | None = None
    confirmation_expires_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    resolves_action_id: str | None = Field(default=None, min_length=1, max_length=36)


class AgentSettingEvidence(ConfigurationDocument):
    format: Literal["agent-setting-outcome-v1"] = "agent-setting-outcome-v1"
    native_ack_sha256: SHA256
    readback_sha256: SHA256
    after_configuration_sha256: SHA256
    supported_context_sha256: SHA256
    observed_at: float = Field(ge=0, allow_inf_nan=False)


class KnownUnsentEvidence(ConfigurationDocument):
    """Explicit adapter proof; absence of an ACK never supplies this evidence."""

    kind: Literal["native_request_not_opened"]
    action_id: str = Field(min_length=1, max_length=36)
    intent_sha256: SHA256
    reserved_revision: Revision
    proof_sha256: SHA256


class AgentSettingResult(ConfigurationDocument):
    format: Literal["session-agent-activation-result-v1"] = "session-agent-activation-result-v1"
    operation: Literal["agent.switch", "agent.adopt"] = "agent.switch"
    action_id: str = Field(min_length=1, max_length=36)
    root_key: SHA256
    intent_sha256: SHA256
    before_revision: Revision
    head_revision: Revision
    phase: Literal["not_sent", "quarantined", "prepared", "activated"]
    evidence_sha256: SHA256
    # Small authenticated mirror of the existing Action projections. This is
    # deliberately not an ordinary prompt/check ResourceExecutionResult.
    action_projection: dict[str, Any]


class ConfigurationToken(ConfigurationDocument):
    root_key: SHA256
    revision: Revision
    phase: Phase
    payload_hash: SHA256
    effective_sha256: SHA256
    active_action_id: str | None
    last_activation_action_id: str | None


class ConfigurationCommitExpectation(ConfigurationDocument):
    """Caller-known tuple, available even when commit lost the returned head hash."""

    root_key: SHA256
    revision: Revision
    phase: Phase
    effective_sha256: SHA256
    active_action_id: str | None
    last_activation_action_id: str | None
    transition_action_id: str = Field(min_length=1, max_length=36)
    transition_intent_sha256: SHA256
    transition_evidence_sha256: SHA256 | None = None


@dataclass(frozen=True)
class ConfigurationSnapshot:
    token: ConfigurationToken
    origin: ConfigurationOrigin
    effective: EffectiveConfiguration
    pending: AgentSwitchIntent | None


@dataclass(frozen=True)
class ConfigurationReconciliation:
    status: Literal["exact_committed", "predecessor_locked"]
    snapshot: ConfigurationSnapshot
    # Neither result authorizes a send, replay, registry activation or queue resume.
    native_send_authorized: Literal[False] = False


def origin_identity(origin: ConfigurationOrigin) -> str:
    return digest(
        {"root": origin.root.model_dump(mode="json"), "native_created_at": origin.native_created_at}
    )


async def configuration_barrier(session: AsyncSession, reference: SessionRef) -> str | None:
    """Plain projection denial hint for every same-Root mutation claim.

    The result only ever withholds work. A stable or absent head grants nothing.
    """
    phase: str | None = await session.scalar(
        select(SessionConfigurationHead.phase).where(
            SessionConfigurationHead.root_reference_hash
            == digest(reference.model_dump(mode="json")),
            SessionConfigurationHead.phase != "stable",
        )
    )
    return phase


def configuration_root_key(origin: ConfigurationOrigin) -> str:
    return digest(
        {
            "format": "original-root-configuration-key-v1",
            "root": origin.root.model_dump(mode="json"),
            "immutable_origin_sha256": origin_identity(origin),
        }
    )


def _projection(row: SessionConfigurationHead) -> dict[str, Any]:
    return {
        key: getattr(row, key)
        for key in (
            "root_key",
            "root_reference_hash",
            "revision",
            "phase",
            "active_action_id",
            "last_activation_action_id",
            "updated_at",
        )
    }


def _action_projection(action: Action) -> dict[str, Any]:
    return {
        key: getattr(action, key)
        for key in (
            "id",
            "dedupe_key",
            "binding_id",
            "binding_revision",
            "actor_id",
            "operation_digest",
            "operation",
            "state",
            "version",
            "owner",
            "upstream_id",
            "status_reason",
        )
    } | {"admission_sha256": digest(action.admission)}


def _action_link(action: Action) -> dict[str, Any]:
    return _action_projection(action) | {"native_result_sha256": digest(action.native_result)}


def decode_configuration_head(row: SessionConfigurationHead) -> ConfigurationSnapshot:
    try:
        body = row.payload
        if set(body) != {
            "format",
            "origin",
            "effective",
            "pending",
            "projection",
            "active",
            "current",
        }:
            raise ValueError("head_fields")
        origin = ConfigurationOrigin.model_validate(body["origin"])
        effective = EffectiveConfiguration.model_validate(body["effective"])
        pending = AgentSwitchIntent.model_validate(body["pending"]) if body["pending"] else None
        token = ConfigurationToken(
            root_key=row.root_key,
            revision=row.revision,
            phase=cast(Phase, row.phase),  # ConfigurationToken validates the Literal at runtime.
            payload_hash=row.payload_hash,
            effective_sha256=digest(body["effective"]),
            active_action_id=row.active_action_id,
            last_activation_action_id=row.last_activation_action_id,
        )
        active = row.phase in {"dispatching", "activation_prepared", "quarantined"}
        if (
            len(checked_json(body)) > MAX_HEAD_BYTES
            or body["format"] != "session-configuration-head-v1"
            or row.payload_hash != digest(body)
            or body["projection"] != _projection(row)
            or row.root_key != configuration_root_key(origin)
            or row.root_reference_hash != digest(origin.root.model_dump(mode="json"))
            or not math.isfinite(row.updated_at)
            or row.updated_at < 0
            or active != (row.active_action_id is not None)
            or active != (pending is not None)
            or (body["active"] is not None) != active
            or (body["current"] is not None) != (row.last_activation_action_id is not None)
            or pending is not None
            and (
                pending.root_key != row.root_key
                or pending.reference != origin.root
                or pending.origin_sha256 != digest(body["origin"])
                or pending.before_configuration_sha256 != digest(body["effective"])
                or pending.expected_revision >= row.revision
            )
        ):
            raise ValueError("head_projection")
        return ConfigurationSnapshot(token, origin, effective, pending)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Conflict("session_configuration_head_invalid") from None


def _intent(action: Action, snapshot: ConfigurationSnapshot) -> AgentSwitchIntent:
    try:
        value = AgentSwitchIntent.model_validate(action.payload)
        if (
            action.operation != value.operation
            or digest(action.payload) != action.operation_digest
            or action.id != value.action_id
            or action.binding_id != value.binding_id
            or action.binding_revision != value.binding_revision
            or action.actor_id != value.actor_id
            or value.root_key != snapshot.token.root_key
            or value.reference != snapshot.origin.root
            or value.origin_sha256 != digest(snapshot.origin.model_dump(mode="json"))
            or type(action.version) is not int
            or not 1 <= action.version <= 2**63 - 1
        ):
            raise ValueError("action_projection")
        return value
    except (ValueError, TypeError):
        raise Conflict("session_configuration_action_invalid") from None


def _validate_result(action: Action, snapshot: ConfigurationSnapshot) -> None:
    intent = _intent(action, snapshot)
    if not action.native_result:
        if action.admission or action.state != "dispatching":
            raise Conflict("session_configuration_result_missing")
        return
    try:
        value = AgentSettingResult.model_validate(action.native_result)
        if value.operation != action.operation or (
            action.operation == "agent.adopt" and (action.admission or value.phase != "activated")
        ):
            raise ValueError("setting_result_operation")
        expected_state = {
            "not_sent": "rejected",
            "quarantined": "ambiguous",
            "prepared": "admitted",
            "activated": "completed",
        }[value.phase]
        if (
            value.action_id != action.id
            or value.root_key != snapshot.token.root_key
            or value.intent_sha256 != digest(action.payload)
            or value.before_revision != intent.expected_revision
            or value.action_projection != _action_projection(action)
            or action.state != expected_state
        ):
            raise ValueError("setting_result_projection")
        if action.admission:
            receipt = ExecutionReceipt.model_validate(action.admission)
            if (
                receipt.action_id != action.id
                or receipt.operation_digest != action.operation_digest
                or receipt.reference != snapshot.origin.root
                or receipt.admission.owner != action.owner
                or receipt.admission.upstream_id != action.upstream_id
                or receipt.admission.details.get("operation") != "agent.switch"
            ):
                raise ValueError("setting_admission_projection")
    except (ValueError, TypeError, KeyError):
        raise Conflict("session_configuration_result_invalid") from None


class SessionConfigurationHeads:
    """Explicit persistence opt-in; constructor alone changes no legacy behavior."""

    def __init__(self, db: Database, fence: ConsumerFence, *, enabled: bool = False) -> None:
        self.db, self.fence, self.enabled = db, fence, enabled

    async def _ready(self) -> None:
        if self.enabled is not True:
            raise Conflict("session_configuration_feature_disabled")
        if not await self.db.ready():
            raise Conflict("session_configuration_database_not_ready")

    @staticmethod
    def _current(current: CurrentProof) -> None:
        if current() is not True:
            raise Conflict("session_configuration_authority_changed")

    @staticmethod
    def _fresh(observed_at: float | None) -> None:
        now = time.time()
        if (
            observed_at is None
            or not math.isfinite(observed_at)
            or not observed_at <= now < observed_at + 5
        ):
            raise Conflict("session_configuration_qualification_expired")

    async def _locked(
        self,
        session: AsyncSession,
        root_key: str,
        lock_authority: LockedAuthority,
    ) -> tuple[SessionConfigurationHead, ConfigurationSnapshot]:
        await self.fence.lock(session)
        row = await session.scalar(
            select(SessionConfigurationHead)
            .where(SessionConfigurationHead.root_key == root_key)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if row is None:
            raise Conflict("session_configuration_head_absent_not_legacy_authority")
        saved = decode_configuration_head(row)
        await lock_authority(session)
        # Lock order is consumer fence -> exact Root head -> linked Action IDs.
        for name, action_id in (
            ("active", row.active_action_id),
            ("current", row.last_activation_action_id),
        ):
            if action_id is None:
                continue
            action = await self._action(session, action_id)
            _validate_result(action, saved)
            if _action_link(action) != row.payload[name]:
                raise Conflict("session_configuration_action_link_changed")
            if name == "current" and action.state != "completed":
                raise Conflict("session_configuration_current_activation_invalid")
            intent = _intent(action, saved)
            if (
                name == "current"
                and digest(intent.after.model_dump(mode="json")) != saved.token.effective_sha256
            ):
                raise Conflict("session_configuration_current_policy_changed")
            if name == "active" and action.native_result:
                result = AgentSettingResult.model_validate(action.native_result)
                wanted_phase = {"activation_prepared": "prepared", "quarantined": "quarantined"}
                if (
                    result.phase != wanted_phase.get(row.phase)
                    or result.head_revision != row.revision
                ):
                    raise Conflict("session_configuration_active_receipt_revision_changed")
        return row, saved

    @staticmethod
    async def _action(session: AsyncSession, action_id: str) -> Action:
        action = await session.scalar(
            select(Action)
            .where(Action.id == action_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if action is None:
            raise Conflict("session_configuration_action_missing")
        return action

    @staticmethod
    def _expected(saved: ConfigurationSnapshot, expected: ConfigurationToken) -> None:
        if saved.token != expected:
            raise Conflict("session_configuration_compare_and_swap_failed")

    @staticmethod
    def _body(
        row: SessionConfigurationHead,
        origin: ConfigurationOrigin,
        effective: EffectiveConfiguration,
        pending: AgentSwitchIntent | None,
        active: dict[str, Any] | None,
        current: dict[str, Any] | None,
    ) -> dict[str, Any]:
        body = {
            "format": "session-configuration-head-v1",
            "origin": origin.model_dump(mode="json"),
            "effective": effective.model_dump(mode="json"),
            "pending": pending.model_dump(mode="json") if pending else None,
            "projection": _projection(row),
            "active": active,
            "current": current,
        }
        if len(checked_json(body)) > MAX_HEAD_BYTES:
            raise Conflict("session_configuration_head_capacity_exceeded")
        return body

    async def initialize(
        self,
        origin: ConfigurationOrigin,
        effective: EffectiveConfiguration,
        proof: InitializationProof,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationSnapshot:
        """Only a trusted qualified-Root resolver may invoke this explicit enrollment.

        Caller authority must revalidate original enrollment/identity/qualification.
        GET equality, a missing row and an old registration alone are insufficient.
        """
        await self._ready()
        origin = ConfigurationOrigin.model_validate(origin.model_dump(mode="json"))
        effective = EffectiveConfiguration.model_validate(effective.model_dump(mode="json"))
        now = time.time()
        if (
            not proof.observed_at <= now < proof.observed_at + 5
            or proof.origin_sha256 != digest(origin.model_dump(mode="json"))
            or proof.effective_sha256 != digest(effective.model_dump(mode="json"))
            or proof.qualification_sha256 != origin.qualification_sha256
        ):
            raise Conflict("session_configuration_initial_qualification_required")
        self._current(current)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            existing = await session.scalar(
                select(SessionConfigurationHead)
                .where(
                    SessionConfigurationHead.root_reference_hash
                    == digest(origin.root.model_dump(mode="json"))
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            await lock_authority(session)
            self._fresh(proof.observed_at)
            if existing is not None:
                raise Conflict("session_configuration_root_already_enrolled")
            roots = (
                await session.scalars(select(SessionConfigurationHead.root_key).limit(MAX_HEADS))
            ).all()
            if len(roots) >= MAX_HEADS:
                raise Conflict("session_configuration_root_capacity_exceeded")
            row = SessionConfigurationHead(
                root_key=configuration_root_key(origin),
                root_reference_hash=digest(origin.root.model_dump(mode="json")),
                revision=1,
                phase="stable",
                active_action_id=None,
                last_activation_action_id=None,
                updated_at=now,
            )
            row.payload = self._body(row, origin, effective, None, None, None)
            row.payload_hash = digest(row.payload)
            session.add(row)
            await session.flush()
            await self.fence.lock(session)
            self._current(current)
            self._fresh(proof.observed_at)
            return decode_configuration_head(row)

    async def _write(
        self,
        session: AsyncSession,
        row: SessionConfigurationHead,
        saved: ConfigurationSnapshot,
        *,
        phase: Phase,
        effective: EffectiveConfiguration,
        pending: AgentSwitchIntent | None,
        active: Action | None,
        current_action: Action | None = None,
    ) -> ConfigurationSnapshot:
        if saved.token.revision == 2**63 - 1:
            raise Conflict("session_configuration_revision_exhausted")
        successor = SessionConfigurationHead(
            root_key=row.root_key,
            root_reference_hash=row.root_reference_hash,
            revision=row.revision + 1,
            phase=phase,
            active_action_id=active.id if active else None,
            last_activation_action_id=current_action.id
            if current_action
            else row.last_activation_action_id,
            updated_at=max(time.time(), row.updated_at),
        )
        successor.payload = self._body(
            successor,
            saved.origin,
            effective,
            pending,
            _action_link(active) if active else None,
            _action_link(current_action) if current_action else row.payload["current"],
        )
        successor.payload_hash = digest(successor.payload)
        values = _projection(successor) | {
            "payload": successor.payload,
            "payload_hash": successor.payload_hash,
        }
        result = await session.execute(
            update(SessionConfigurationHead)
            .where(
                SessionConfigurationHead.root_key == row.root_key,
                SessionConfigurationHead.revision == saved.token.revision,
                SessionConfigurationHead.payload_hash == saved.token.payload_hash,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:  # type: ignore[attr-defined]
            raise Conflict("session_configuration_compare_and_swap_failed")
        return decode_configuration_head(successor)

    async def reserve(
        self,
        expected: ConfigurationToken,
        action_id: str,
        action_version: int,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationSnapshot:
        """Atomic single attempt reservation only; this method never dispatches it."""
        await self._ready()
        async with self.db.sessions.begin() as session:
            row, saved = await self._locked(session, expected.root_key, lock_authority)
            self._expected(saved, expected)
            if saved.token.phase != "stable":
                raise Conflict("session_configuration_Root_barrier")
            action = await self._action(session, action_id)
            intent = _intent(action, saved)
            if (
                action.state != "queued"
                or action.version != action_version
                or action.version != intent.queued_action_version
                or action.admission
                or action.native_result
                or action.upstream_id is not None
                or action.owner != "bridge"
                or intent.expected_revision != row.revision
                or intent.before_configuration_sha256 != saved.token.effective_sha256
            ):
                raise Conflict("session_configuration_intent_stale_or_attempted")
            self._current(current)
            action.state, action.version = "dispatching", action.version + 1
            await session.flush()
            result = await self._write(
                session,
                row,
                saved,
                phase="dispatching",
                effective=saved.effective,
                pending=intent,
                active=action,
            )
            await self.fence.lock(session)
            self._current(current)
            return result

    async def settle(
        self,
        expected: ConfigurationToken,
        outcome: Literal["not_sent", "quarantined", "prepared", "activated"],
        evidence_sha256: SHA256,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
        receipt: ExecutionReceipt | None = None,
        evidence: AgentSettingEvidence | None = None,
        staged_context_sha256: SHA256 | None = None,
        staged_context_observed_at: float | None = None,
        not_sent_evidence: KnownUnsentEvidence | None = None,
        on_activated: LockedAuthority | None = None,
    ) -> ConfigurationSnapshot:
        """Operation-specific Action/head CAS; no generic queue/retry transition.

        not_sent requires an actual not-opened proof hash from the trusted adapter.
        activated requires a detached qualified context already staged by its owner;
        SQL success still does not publish an in-memory mutation-ready generation.
        """
        await self._ready()
        if outcome not in {"not_sent", "quarantined", "prepared", "activated"}:
            raise Conflict("session_configuration_outcome_invalid")
        # Runtime validation is required even when a caller bypasses type checking.
        if (
            not isinstance(evidence_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None
        ):
            raise Conflict("session_configuration_evidence_hash_invalid")
        async with self.db.sessions.begin() as session:
            row, saved = await self._locked(session, expected.root_key, lock_authority)
            self._expected(saved, expected)
            if saved.pending is None or row.active_action_id is None:
                raise Conflict("session_configuration_no_active_attempt")
            action = await self._action(session, row.active_action_id)
            intent = saved.pending
            required_phase = "activation_prepared" if outcome == "activated" else "dispatching"
            if row.phase != required_phase:
                raise Conflict("session_configuration_attempt_phase_changed")
            if outcome == "not_sent":
                if not_sent_evidence is None:
                    raise Conflict("session_configuration_explicit_not_opened_proof_required")
                not_sent_evidence = KnownUnsentEvidence.model_validate(
                    not_sent_evidence.model_dump(mode="json")
                )
                if (
                    not_sent_evidence.action_id != action.id
                    or not_sent_evidence.intent_sha256 != digest(action.payload)
                    or not_sent_evidence.reserved_revision != row.revision
                    or digest(not_sent_evidence.model_dump(mode="json")) != evidence_sha256
                ):
                    raise Conflict("session_configuration_not_sent_proof_changed")
            elif not_sent_evidence is not None:
                raise Conflict("session_configuration_unexpected_not_sent_proof")
            if outcome == "prepared":
                if receipt is None or evidence is None:
                    raise Conflict("session_configuration_ACK_and_qualified_readback_required")
                receipt = ExecutionReceipt.model_validate(receipt.model_dump(mode="json"))
                evidence = AgentSettingEvidence.model_validate(evidence.model_dump(mode="json"))
                self._fresh(evidence.observed_at)
                if (
                    receipt.action_id != action.id
                    or receipt.operation_digest != action.operation_digest
                    or receipt.reference != saved.origin.root
                    or receipt.admission.status != "admitted"
                    or receipt.admission.owner != "opencode"
                    or receipt.admission.details.get("operation") != "agent.switch"
                    or receipt.admission.details.get("agent_setting")
                    != evidence.model_dump(mode="json")
                    or evidence.after_configuration_sha256
                    != digest(intent.after.model_dump(mode="json"))
                    or evidence.supported_context_sha256
                    != intent.after.context_qualification_sha256
                    or evidence_sha256 != digest(evidence.model_dump(mode="json"))
                ):
                    raise Conflict("session_configuration_setting_receipt_mismatch")
                action.admission = receipt.model_dump(mode="json")
                action.owner, action.upstream_id = (
                    receipt.admission.owner,
                    receipt.admission.upstream_id,
                )
            elif receipt is not None or evidence is not None:
                raise Conflict("session_configuration_unexpected_receipt")
            if (
                outcome == "activated"
                and staged_context_sha256 != intent.after.context_qualification_sha256
            ):
                raise Conflict("session_configuration_detached_context_required")
            if outcome == "activated":
                self._fresh(staged_context_observed_at)
            self._current(current)
            if action.operation != "agent.switch":
                raise Conflict("session_configuration_operation_cannot_settle")
            action.state = {
                "not_sent": "rejected",
                "quarantined": "ambiguous",
                "prepared": "admitted",
                "activated": "completed",
            }[outcome]
            action.version += 1
            action.native_result = AgentSettingResult(
                action_id=action.id,
                root_key=row.root_key,
                intent_sha256=digest(action.payload),
                before_revision=intent.expected_revision,
                head_revision=row.revision + 1,
                phase=outcome,
                evidence_sha256=evidence_sha256,
                action_projection=_action_projection(action),
            ).model_dump(mode="json")
            await session.flush()
            phase: Phase = {
                "not_sent": "stable",
                "quarantined": "quarantined",
                "prepared": "activation_prepared",
                "activated": "stable",
            }[outcome]  # type: ignore[assignment]
            result = await self._write(
                session,
                row,
                saved,
                phase=phase,
                effective=intent.after if outcome == "activated" else saved.effective,
                pending=None if outcome in {"not_sent", "activated"} else intent,
                active=None if outcome in {"not_sent", "activated"} else action,
                current_action=action if outcome == "activated" else None,
            )
            if outcome == "activated" and on_activated is not None:
                await on_activated(session)
            await self.fence.lock(session)
            self._current(current)
            if outcome == "prepared":
                assert evidence is not None
                self._fresh(evidence.observed_at)
            if outcome == "activated":
                self._fresh(staged_context_observed_at)
            return result

    async def mark_external(
        self,
        expected: ConfigurationToken,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationSnapshot:
        """Fresh Native drift ends mutation readiness; read continuity is unaffected.

        No Action is created and the approved effective configuration stays stored.
        Only an explicit local adoption or an exact later observation can release it.
        """
        await self._ready()
        async with self.db.sessions.begin() as session:
            row, saved = await self._locked(session, expected.root_key, lock_authority)
            self._expected(saved, expected)
            if saved.token.phase != "stable":
                raise Conflict("session_configuration_external_requires_stable_head")
            self._current(current)
            result = await self._write(
                session,
                row,
                saved,
                phase="external_unqualified",
                effective=saved.effective,
                pending=None,
                active=None,
            )
            await self.fence.lock(session)
            self._current(current)
            return result

    async def release_external(
        self,
        expected: ConfigurationToken,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationSnapshot:
        """Native returned to the exact approved configuration; no Action is implied."""
        await self._ready()
        async with self.db.sessions.begin() as session:
            row, saved = await self._locked(session, expected.root_key, lock_authority)
            self._expected(saved, expected)
            if saved.token.phase != "external_unqualified":
                raise Conflict("session_configuration_external_release_phase_changed")
            self._current(current)
            result = await self._write(
                session,
                row,
                saved,
                phase="stable",
                effective=saved.effective,
                pending=None,
                active=None,
            )
            await self.fence.lock(session)
            self._current(current)
            return result

    async def adopt_observed(
        self,
        expected: ConfigurationToken,
        intent: AgentSwitchIntent,
        evidence_sha256: SHA256,
        *,
        dedupe_key: str,
        lock_authority: LockedAuthority,
        current: CurrentProof,
        observed_at: float,
        on_activated: LockedAuthority | None = None,
    ) -> tuple[ConfigurationSnapshot, Action]:
        """Local-only review release; the Bridge sends nothing to Native here.

        A prior ambiguous Action stays ambiguous. Its head barrier is released by this
        separate completed record, so history never claims the old write succeeded.
        """
        await self._ready()
        self._fresh(observed_at)
        if intent.operation != "agent.adopt":
            raise Conflict("session_configuration_adoption_intent_required")
        async with self.db.sessions.begin() as session:
            row, saved = await self._locked(session, expected.root_key, lock_authority)
            self._expected(saved, expected)
            active = row.active_action_id
            if (
                saved.token.phase not in {"external_unqualified", "quarantined"}
                or intent.root_key != row.root_key
                or intent.reference != saved.origin.root
                or intent.origin_sha256 != digest(saved.origin.model_dump(mode="json"))
                or intent.expected_revision != row.revision
                or intent.before_configuration_sha256 != saved.token.effective_sha256
                or intent.resolves_action_id != active
            ):
                raise Conflict("session_configuration_adoption_stale")
            self._current(current)
            payload = intent.model_dump(mode="json")
            action = Action(
                id=intent.action_id,
                dedupe_key=dedupe_key,
                binding_id=intent.binding_id,
                binding_revision=intent.binding_revision,
                actor_id=intent.actor_id,
                payload=payload,
                operation="agent.adopt",
                operation_digest=digest(payload),
                state="completed",
                version=intent.queued_action_version,
                owner="bridge",
                upstream_id=None,
                status_reason=None,
                admission={},
            )
            action.native_result = {}
            session.add(action)
            await session.flush()
            action.native_result = AgentSettingResult(
                operation="agent.adopt",
                action_id=action.id,
                root_key=row.root_key,
                intent_sha256=digest(payload),
                before_revision=intent.expected_revision,
                head_revision=row.revision + 1,
                phase="activated",
                evidence_sha256=evidence_sha256,
                action_projection=_action_projection(action),
            ).model_dump(mode="json")
            await session.flush()
            result = await self._write(
                session,
                row,
                saved,
                phase="stable",
                effective=intent.after,
                pending=None,
                active=None,
                current_action=action,
            )
            if on_activated is not None:
                await on_activated(session)
            await self.fence.lock(session)
            self._current(current)
            self._fresh(observed_at)
            return result, action

    async def snapshot_for_reference(
        self,
        reference: SessionRef,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationSnapshot | None:
        """Absence is only absence: it is neither enrollment nor a legacy revision."""
        await self._ready()
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            root_key = await session.scalar(
                select(SessionConfigurationHead.root_key).where(
                    SessionConfigurationHead.root_reference_hash
                    == digest(reference.model_dump(mode="json"))
                )
            )
            if root_key is None:
                return None
            _, saved = await self._locked(session, root_key, lock_authority)
            self._current(current)
            return saved

    async def inspect_locked(
        self,
        root_key: str,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationSnapshot:
        """Fresh fenced/locked validation; decrypt every linked Action before return."""
        await self._ready()
        async with self.db.sessions.begin() as session:
            _, saved = await self._locked(session, root_key, lock_authority)
            self._current(current)
            return saved

    async def reconcile(
        self,
        predecessor: ConfigurationToken,
        expected: ConfigurationToken,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationReconciliation:
        """Join SQL serialization before resolving a previous uncertain commit.

        A still-open prior writer must release the consumer/head lock first.
        Even a locked predecessor is not proof of Native rollback or a retry grant.
        A different tuple, wrong key or tamper fails closed and never clears a head.
        """
        if predecessor.root_key != expected.root_key or expected.revision <= predecessor.revision:
            raise Conflict("session_configuration_reconcile_tuple_invalid")
        saved = await self.inspect_locked(
            expected.root_key, lock_authority=lock_authority, current=current
        )
        if saved.token == expected:
            return ConfigurationReconciliation("exact_committed", saved)
        if saved.token == predecessor:
            return ConfigurationReconciliation("predecessor_locked", saved)
        raise Conflict("session_configuration_commit_unresolved")

    async def reconcile_attempt(
        self,
        predecessor: ConfigurationToken,
        expected: ConfigurationCommitExpectation,
        *,
        lock_authority: LockedAuthority,
        current: CurrentProof,
    ) -> ConfigurationReconciliation:
        """Resolve a lost commit response using caller-known intent/evidence only.

        No resulting timestamp, randomized ciphertext or returned payload hash is
        needed. This also locks the original Action after a not-sent rejection
        cleared active_action_id. Never retry a transaction or Native operation.
        """
        await self._ready()
        if (
            expected.root_key != predecessor.root_key
            or expected.revision != predecessor.revision + 1
        ):
            raise Conflict("session_configuration_reconcile_tuple_invalid")
        async with self.db.sessions.begin() as session:
            _, saved = await self._locked(session, expected.root_key, lock_authority)
            action = await self._action(session, expected.transition_action_id)
            _intent(action, saved)
            if digest(action.payload) != expected.transition_intent_sha256:
                raise Conflict("session_configuration_reconcile_intent_changed")
            self._current(current)
            if saved.token == predecessor:
                return ConfigurationReconciliation("predecessor_locked", saved)
            actual = saved.token.model_dump(exclude={"payload_hash"})
            target = expected.model_dump(
                exclude={
                    "transition_action_id",
                    "transition_intent_sha256",
                    "transition_evidence_sha256",
                }
            )
            if actual != target:
                raise Conflict("session_configuration_commit_unresolved")
            if expected.phase == "dispatching":
                if (
                    action.id != saved.token.active_action_id
                    or action.state != "dispatching"
                    or action.native_result
                    or expected.transition_evidence_sha256 is not None
                ):
                    raise Conflict("session_configuration_reservation_unresolved")
            else:
                _validate_result(action, saved)
                result = AgentSettingResult.model_validate(action.native_result)
                if (
                    result.head_revision != expected.revision
                    or result.evidence_sha256 != expected.transition_evidence_sha256
                ):
                    raise Conflict("session_configuration_commit_evidence_unresolved")
            return ConfigurationReconciliation("exact_committed", saved)
