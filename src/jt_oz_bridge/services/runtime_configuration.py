"""Scoped site presentation defaults; static configuration is never mutated."""

import secrets
import time
import uuid
from typing import Any, Literal, cast

from pydantic import Field, StrictBool, StrictFloat, StrictInt, model_validator
from sqlalchemy import insert, literal, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.services.admin_authority import AdministrativeAuthority
from jt_oz_bridge.services.admin_decisions import MAX_PENDING_DECISIONS, TTL, Key
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AuditEvent, uid
from jt_oz_bridge.storage.runtime_config_models import (
    RuntimeConfigurationState,
    RuntimeSettingDecision,
)

SettingKey = Literal["i18n.default_locale", "rendering.stream_update_min_interval_ms"]
SettingValue = Locale | StrictInt
INTERVAL_KEY: SettingKey = "rendering.stream_update_min_interval_ms"


def valid_value(key: SettingKey, value: Any, *, baseline: bool = False) -> bool:
    if key == "i18n.default_locale":
        return type(value) is str and value in {"en", "zh-TW"}
    return key == INTERVAL_KEY and type(value) is int and value > 0 and (baseline or value <= 60000)


BaseOrigin = Literal["default", "toml", "environment", "not_recorded", "modified_after_load"]
EffectiveOrigin = Literal[
    "default", "toml", "environment", "not_recorded", "modified_after_load", "administrator_runtime"
]


class RuntimeValues(ControlModel):
    format_version: Literal[1] = 1
    revision: StrictInt = Field(ge=0)
    overrides: dict[SettingKey, SettingValue] = Field(max_length=2)

    @model_validator(mode="after")
    def typed_overrides(self) -> "RuntimeValues":
        if any(not valid_value(key, value) for key, value in self.overrides.items()):
            raise ValueError("invalid_runtime_setting_value")
        return self


class SettingView(ControlModel):
    key: SettingKey = "i18n.default_locale"
    value: SettingValue
    origin: EffectiveOrigin
    baseline_value: SettingValue
    baseline_origin: BaseOrigin
    baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    stored_override: SettingValue | None
    configuration_revision: StrictInt = Field(ge=0)
    runtime_allowed: StrictBool
    environment_shadowed: StrictBool

    @model_validator(mode="after")
    def coherent(self) -> "SettingView":
        allowed = self.baseline_origin in {"default", "toml", "environment"}
        runtime = (
            allowed and self.baseline_origin != "environment" and self.stored_override is not None
        )
        if (
            not valid_value(self.key, self.baseline_value, baseline=True)
            or not valid_value(self.key, self.value, baseline=True)
            or self.stored_override is not None
            and not valid_value(self.key, self.stored_override)
            or self.baseline_hash
            != digest(
                {"key": self.key, "value": self.baseline_value, "origin": self.baseline_origin}
            )
            or self.runtime_allowed != allowed
            or self.environment_shadowed
            != (self.baseline_origin == "environment" and self.stored_override is not None)
            or self.value != (self.stored_override if runtime else self.baseline_value)
            or self.origin != ("administrator_runtime" if runtime else self.baseline_origin)
            or (self.configuration_revision == 0 and self.stored_override is not None)
        ):
            raise ValueError("inconsistent_runtime_setting_view")
        return self


class SettingResult(ControlModel):
    state: Literal["confirmed", "cancelled"]
    configuration_revision: StrictInt = Field(ge=0)
    recorded_effect: SettingView
    audit_id: Key
    applied: StrictBool
    upstream_requests: Literal[0] = 0


class SettingIntent(ControlModel):
    principal_kind: Literal["web_administrator"] = "web_administrator"
    decision_id: Key
    admin_id: Key
    session_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    client_action_id: Key
    key: SettingKey
    requested_value: SettingValue | None
    before: SettingView
    holder: Key
    fencing: StrictInt = Field(gt=0)
    confirmation_token: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    expires_at: StrictFloat = Field(gt=0, allow_inf_nan=False)
    result: SettingResult | None = None

    @model_validator(mode="after")
    def coherent_result(self) -> "SettingIntent":
        if self.key != self.before.key or (
            self.requested_value is not None and not valid_value(self.key, self.requested_value)
        ):
            raise ValueError("inconsistent_setting_intent_key_value")
        if self.result is not None:
            cancelled = self.result.state == "cancelled"
            effect = self.result.recorded_effect
            if (
                effect.key != self.key
                or self.result.applied != (not cancelled)
                or self.result.configuration_revision
                != self.before.configuration_revision + (not cancelled)
                or effect.configuration_revision != self.result.configuration_revision
                or (effect.baseline_hash, effect.baseline_value, effect.baseline_origin)
                != (
                    self.before.baseline_hash,
                    self.before.baseline_value,
                    self.before.baseline_origin,
                )
                or (cancelled and effect != self.before)
                or (not cancelled and effect.stored_override != self.requested_value)
            ):
                raise ValueError("inconsistent_runtime_setting_result")
        return self


def read_intent(row: RuntimeSettingDecision) -> SettingIntent:
    try:
        if digest(row.payload) != row.payload_hash:
            raise ValueError("setting_decision_digest_changed")
        intent = SettingIntent.model_validate(row.payload)
        if (
            intent.decision_id,
            intent.admin_id,
            intent.session_hash,
            intent.client_action_id,
            intent.key,
            intent.before.configuration_revision,
            intent.holder,
            intent.fencing,
            intent.expires_at,
            token_hash(intent.confirmation_token),
        ) != (
            row.id,
            row.admin_id,
            row.session_hash,
            row.client_action_id,
            row.setting_key,
            row.configuration_revision,
            row.holder,
            row.fencing,
            row.expires_at,
            row.confirmation_hash,
        ):
            raise ValueError("setting_decision_columns_changed")
        if row.state == "pending":
            if row.version != 1 or intent.result is not None:
                raise ValueError("pending_setting_result")
        elif intent.result is None or row.version != 2 or intent.result.state != row.state:
            raise ValueError("terminal_setting_result")
        return intent
    except ValueError:
        raise Conflict("runtime_setting_evidence_changed") from None


class RuntimeConfiguration(AdministrativeAuthority):
    def _view(self, state: RuntimeValues, key: SettingKey = "i18n.default_locale") -> SettingView:
        origin = self.settings.configuration_origins()[key]
        if origin not in {"default", "toml", "environment", "not_recorded", "modified_after_load"}:
            raise Conflict("invalid_startup_configuration_source")
        section, field = key.split(".")
        baseline = getattr(getattr(self.settings, section), field)
        stored = state.overrides.get(key)
        allowed = origin in {"default", "toml", "environment"}
        use_runtime = allowed and origin != "environment" and stored is not None
        selected = baseline
        if use_runtime:
            assert stored is not None
            selected = stored
        return SettingView(
            key=key,
            value=selected,
            origin="administrator_runtime" if use_runtime else origin,
            baseline_value=baseline,
            baseline_origin=origin,
            baseline_hash=digest({"key": key, "value": baseline, "origin": origin}),
            stored_override=stored,
            configuration_revision=state.revision,
            runtime_allowed=allowed,
            environment_shadowed=origin == "environment" and stored is not None,
        )

    @staticmethod
    async def _state(
        session: AsyncSession, *, lock: bool = False
    ) -> tuple[RuntimeValues, RuntimeConfigurationState | None]:
        statement = (
            select(RuntimeConfigurationState)
            .where(RuntimeConfigurationState.id == "site")
            .execution_options(populate_existing=True)
        )
        if lock:
            statement = statement.with_for_update()
        try:
            row = await session.scalar(statement)
        except ValueError:
            raise Conflict("runtime_configuration_evidence_changed") from None
        if row is None:
            return RuntimeValues(revision=0, overrides={}), None
        try:
            if digest(row.payload) != row.payload_hash:
                raise ValueError("runtime_state_hash_changed")
            state = RuntimeValues.model_validate(row.payload)
            if state.revision != row.revision or row.revision < 1:
                raise ValueError("runtime_revision_changed")
            return state, row
        except ValueError:
            raise Conflict("runtime_configuration_evidence_changed") from None

    async def read(self, key: SettingKey = "i18n.default_locale") -> SettingView:
        async with self.db.sessions() as session:
            state, _ = await self._state(session)
            return self._view(state, key)

    async def views(self) -> dict[SettingKey, SettingView]:
        async with self.db.sessions() as session:
            state, _ = await self._state(session)
            return {key: self._view(state, key) for key in ("i18n.default_locale", INTERVAL_KEY)}

    async def locale(self) -> Locale:
        return cast(Locale, (await self.read()).value)

    async def draft_interval(self, session: AsyncSession) -> float:
        # Called inside the actual fenced publication transaction, never cached.
        state, _ = await self._state(session)
        return cast(int, self._view(state, INTERVAL_KEY).value) / 1000

    @staticmethod
    def _response(row: RuntimeSettingDecision, intent: SettingIntent) -> dict[str, Any]:
        result = {
            "decision_id": row.id,
            "state": row.state,
            "version": row.version,
            "principal_kind": intent.principal_kind,
            "client_action_id": intent.client_action_id,
        }
        if intent.result is not None:
            result["result"] = intent.result.model_dump(mode="json")
        else:
            result.update(
                confirmation_token=intent.confirmation_token,
                expires_at=intent.expires_at,
                preview={
                    "key": intent.key,
                    "requested_value": intent.requested_value,
                    "before": intent.before.model_dump(mode="json"),
                    "upstream_requests": 0,
                },
            )
        return result

    async def preview(
        self,
        token: str,
        admin_id: str,
        fence: ConsumerFence,
        *,
        client_action_id: str,
        key: SettingKey,
        value: SettingValue | None,
        configuration_revision: int,
        baseline_hash: str,
    ) -> dict[str, Any]:
        try:
            if any(str(uuid.UUID(x)) != x for x in (admin_id, client_action_id)):
                raise ValueError("noncanonical")
        except (ValueError, TypeError, AttributeError):
            raise Conflict("admin_canonical_identifier_required") from None
        if (
            key not in {"i18n.default_locale", INTERVAL_KEY}
            or value is not None
            and not valid_value(key, value)
            or type(configuration_revision) is not int
        ):
            raise Conflict("unsupported_runtime_setting")
        async with self.db.sessions.begin() as session:
            session_hash = await self._principal(session, token, admin_id)
            await fence.lock(session)
            try:
                existing = await session.scalar(
                    select(RuntimeSettingDecision)
                    .where(
                        RuntimeSettingDecision.admin_id == admin_id,
                        RuntimeSettingDecision.client_action_id == client_action_id,
                    )
                    .with_for_update()
                )
            except ValueError:
                raise Conflict("runtime_setting_evidence_changed") from None
            if existing is not None:
                intent = read_intent(existing)
                if (
                    intent.session_hash,
                    intent.key,
                    intent.requested_value,
                    intent.before.configuration_revision,
                    intent.before.baseline_hash,
                ) != (session_hash, key, value, configuration_revision, baseline_hash):
                    raise Conflict("runtime_setting_idempotency_changed")
                if existing.state == "pending" and (
                    existing.expires_at <= time.time()
                    or (existing.holder, existing.fencing) != (fence.holder, fence.fencing)
                ):
                    raise Conflict("runtime_setting_preview_expired")
                await self._require_live(session, admin_id, session_hash, fence)
                if (
                    existing.state == "pending"
                    and await session.scalar(
                        select(RuntimeSettingDecision.id).where(
                            RuntimeSettingDecision.id == existing.id,
                            RuntimeSettingDecision.expires_at > self._clock(),
                        )
                    )
                    != existing.id
                ):
                    raise Conflict("runtime_setting_preview_expired_during_replay")
                return self._response(existing, intent)
            if await self._pending_previews(session, admin_id) >= MAX_PENDING_DECISIONS:
                raise Conflict("admin_pending_preview_limit")
            state, _ = await self._state(session, lock=True)
            before = self._view(state, key)
            if (
                not before.runtime_allowed
                or before.configuration_revision != configuration_revision
                or before.baseline_hash != baseline_hash
            ):
                raise Conflict("runtime_setting_source_or_revision_changed")
            intent = SettingIntent(
                decision_id=uid(),
                admin_id=admin_id,
                session_hash=session_hash,
                client_action_id=client_action_id,
                key=key,
                requested_value=value,
                before=before,
                holder=fence.holder,
                fencing=fence.fencing,
                confirmation_token=secrets.token_urlsafe(32),
                expires_at=time.time() + TTL,
            )
            payload = intent.model_dump(mode="json")
            row = RuntimeSettingDecision(
                id=intent.decision_id,
                admin_id=admin_id,
                session_hash=session_hash,
                client_action_id=client_action_id,
                setting_key=key,
                configuration_revision=configuration_revision,
                holder=fence.holder,
                fencing=fence.fencing,
                confirmation_hash=token_hash(intent.confirmation_token),
                payload=payload,
                payload_hash=digest(payload),
                state="pending",
                version=1,
                expires_at=intent.expires_at,
            )
            session.add(row)
            session.add(
                AuditEvent(
                    actor="admin:" + admin_id, event="runtime_setting_previewed", object_id=row.id
                )
            )
            await session.flush()
            await self._require_live(session, admin_id, session_hash, fence)
            if (
                await session.scalar(
                    select(RuntimeSettingDecision.id).where(
                        RuntimeSettingDecision.id == row.id,
                        RuntimeSettingDecision.state == "pending",
                        RuntimeSettingDecision.expires_at > self._clock(),
                    )
                )
                != row.id
            ):
                raise Conflict("runtime_setting_preview_expired_during_issue")
            return self._response(row, intent)

    async def finish(
        self,
        token: str,
        admin_id: str,
        fence: ConsumerFence,
        *,
        decision_id: str,
        confirmation_token: str,
        version: int,
        cancel: bool = False,
    ) -> dict[str, Any]:
        async with self.db.sessions.begin() as session:
            session_hash = await self._principal(session, token, admin_id)
            await fence.lock(session)
            try:
                row = await session.scalar(
                    select(RuntimeSettingDecision)
                    .where(
                        RuntimeSettingDecision.id == decision_id,
                        RuntimeSettingDecision.admin_id == admin_id,
                        RuntimeSettingDecision.session_hash == session_hash,
                    )
                    .with_for_update()
                )
            except ValueError:
                raise Conflict("runtime_setting_evidence_changed") from None
            if row is None:
                raise Conflict("runtime_setting_decision_unavailable")
            intent = read_intent(row)
            if (
                type(version) is not int
                or version != 1
                or not secrets.compare_digest(token_hash(confirmation_token), row.confirmation_hash)
            ):
                raise Conflict("runtime_setting_confirmation_rejected")
            desired: Literal["cancelled", "confirmed"] = "cancelled" if cancel else "confirmed"
            if row.state != "pending":
                if row.state != desired:
                    raise Conflict("runtime_setting_already_finished")
                await self._require_live(session, admin_id, session_hash, fence)
                return self._response(row, intent)
            state, state_row = await self._state(session, lock=True)
            if not cancel and (
                row.expires_at <= time.time()
                or (row.holder, row.fencing) != (fence.holder, fence.fencing)
                or self._view(state, intent.key) != intent.before
            ):
                raise Conflict("runtime_setting_preview_changed_or_expired")
            overrides = dict(state.overrides)
            if intent.requested_value is None:
                overrides.pop(intent.key, None)
            else:
                overrides[intent.key] = intent.requested_value
            next_state = RuntimeValues(revision=state.revision + 1, overrides=overrides)
            effect = intent.before if cancel else self._view(next_state, intent.key)
            event = AuditEvent(
                id=uid(),
                actor="admin:" + admin_id,
                event="runtime_setting_cancelled" if cancel else "runtime_setting_changed",
                object_id=intent.key,
            )
            result = SettingResult(
                state=desired,
                configuration_revision=intent.before.configuration_revision
                if cancel
                else next_state.revision,
                recorded_effect=effect,
                audit_id=event.id,
                applied=not cancel,
            )
            completed = intent.model_copy(update={"result": result})
            payload = completed.model_dump(mode="json")
            authority = self._authority(admin_id, session_hash, fence)
            claim = update(RuntimeSettingDecision).where(
                RuntimeSettingDecision.id == row.id,
                RuntimeSettingDecision.payload_hash == row.payload_hash,
                RuntimeSettingDecision.state == "pending",
                RuntimeSettingDecision.version == 1,
                *authority,
            )
            if not cancel:
                claim = claim.where(
                    RuntimeSettingDecision.expires_at > self._clock(),
                    RuntimeSettingDecision.holder == fence.holder,
                    RuntimeSettingDecision.fencing == fence.fencing,
                )
            claimed = await session.execute(
                claim.values(
                    state=desired, version=2, payload=payload, payload_hash=digest(payload)
                ).execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("runtime_setting_authority_or_deadline_changed")
            if not cancel:
                state_payload = next_state.model_dump(mode="json")
                conditions = (
                    *self._authority(admin_id, session_hash, fence),
                    select(RuntimeSettingDecision.id)
                    .where(
                        RuntimeSettingDecision.id == intent.decision_id,
                        RuntimeSettingDecision.state == "confirmed",
                        RuntimeSettingDecision.version == 2,
                        RuntimeSettingDecision.expires_at > self._clock(),
                        RuntimeSettingDecision.holder == fence.holder,
                        RuntimeSettingDecision.fencing == fence.fencing,
                    )
                    .exists(),
                )
                statement: Any
                if state_row is None:
                    statement = insert(RuntimeConfigurationState).from_select(
                        ["id", "revision", "payload", "payload_hash"],
                        select(
                            literal("site"),
                            literal(next_state.revision),
                            literal(
                                state_payload,
                                type_=RuntimeConfigurationState.__table__.c.payload.type,
                            ),
                            literal(digest(state_payload)),
                        ).where(*conditions),
                    )
                else:
                    statement = (
                        update(RuntimeConfigurationState)
                        .where(
                            RuntimeConfigurationState.id == "site",
                            RuntimeConfigurationState.revision == state.revision,
                            RuntimeConfigurationState.payload_hash == state_row.payload_hash,
                            *conditions,
                        )
                        .values(
                            revision=next_state.revision,
                            payload=state_payload,
                            payload_hash=digest(state_payload),
                        )
                        .execution_options(synchronize_session=False)
                    )
                changed = await session.execute(statement)
                if changed.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("runtime_setting_update_expired_or_changed")
                actual, _ = await self._state(session)
                if actual != next_state:
                    raise Conflict("runtime_setting_readback_changed")
            session.add(event)
            await session.flush()
            await session.refresh(row)
            if read_intent(row) != completed:
                raise Conflict("runtime_setting_receipt_changed")
            return self._response(row, completed)
