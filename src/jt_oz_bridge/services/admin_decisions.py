"""Local web administration; never creates a chat actor or sends a Native request."""

import secrets
import time
from collections import Counter
from typing import Annotated, Any, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt, field_validator, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Settings
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.services.admin_authority import AdministrativeAuthority
from jt_oz_bridge.services.binding_scope_history import scope
from jt_oz_bridge.storage.admin_models import AdminDecision
from jt_oz_bridge.storage.control_models import Binding, PendingInteraction
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob
from jt_oz_bridge.storage.models import (
    Action,
    AuditEvent,
    Delivery,
    uid,
)

UUID_KEY = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
Key = Annotated[str, Field(pattern=UUID_KEY)]
Operation = Literal["pause", "unbind"]
MAX_EFFECT_ROWS = 1000
MAX_PENDING_DECISIONS = 50
TTL = 300
EFFECTS = frozenset({"actions", "interactions", "capture", "deliveries", "transfers"})


class Effect(ControlModel):
    id: str = Field(min_length=1, max_length=255)
    version: StrictInt = Field(gt=0)
    state: str = Field(min_length=1, max_length=32)


class AdminResult(ControlModel):
    decision_id: Key
    operation: Operation
    binding_id: Key
    binding_revision: StrictInt = Field(gt=0)
    queue_revision: StrictInt = Field(ge=0)
    actions_held: StrictInt = Field(ge=0)
    audit_id: Key
    state: Literal["confirmed", "cancelled"]
    native_session_deleted: Literal[False] = False
    upstream_requests: Literal[0] = 0


class AdminIntent(ControlModel):
    principal_kind: Literal["web_administrator"] = "web_administrator"
    decision_id: Key
    admin_id: Key
    session_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    client_action_id: Key
    operation: Operation
    scope: BindingScope
    dispatch_paused: StrictBool
    queue_revision: StrictInt = Field(ge=0)
    effects: dict[str, tuple[Effect, ...]]
    holder: Key
    fencing: StrictInt = Field(gt=0)
    confirmation_token: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    expires_at: StrictFloat = Field(gt=0, allow_inf_nan=False)
    result: AdminResult | None = None

    @field_validator("effects")
    @classmethod
    def bounded_effects(cls, value: dict[str, tuple[Effect, ...]]) -> dict[str, tuple[Effect, ...]]:
        if set(value) != EFFECTS or any(
            len(rows) > MAX_EFFECT_ROWS or [r.id for r in rows] != sorted({r.id for r in rows})
            for rows in value.values()
        ):
            raise ValueError("invalid_admin_effect_snapshot")
        return value

    def payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["scope"]["audience_user_ids"] = sorted(self.scope.audience_user_ids)
        return data

    @model_validator(mode="after")
    def original_result(self) -> "AdminIntent":
        if self.result is not None:
            value = self.result
            cancelled = value.state == "cancelled"
            if (
                value.decision_id,
                value.operation,
                value.binding_id,
                value.binding_revision,
                value.queue_revision,
                value.actions_held,
            ) != (
                self.decision_id,
                self.operation,
                self.scope.binding_id,
                self.scope.revision + (not cancelled and self.operation == "unbind"),
                self.queue_revision + (not cancelled),
                0 if cancelled else sum(e.state == "queued" for e in self.effects["actions"]),
            ):
                raise ValueError("admin_result_original_scope_changed")
        return self


def read_intent(row: AdminDecision) -> AdminIntent:
    try:
        value = AdminIntent.model_validate(row.payload)
        if row.payload_hash != digest(row.payload) or (
            row.id,
            row.admin_id,
            row.session_hash,
            row.client_action_id,
            row.operation,
            row.binding_id,
            row.binding_revision,
            row.queue_revision,
            row.holder,
            row.fencing,
            row.confirmation_hash,
            row.expires_at,
        ) != (
            value.decision_id,
            value.admin_id,
            value.session_hash,
            value.client_action_id,
            value.operation,
            value.scope.binding_id,
            value.scope.revision,
            value.queue_revision,
            value.holder,
            value.fencing,
            token_hash(value.confirmation_token),
            value.expires_at,
        ):
            raise ValueError("admin_intent_scope_changed")
        if row.state == "pending":
            if value.result is not None or row.version != 1:
                raise ValueError("admin_pending_result_changed")
        elif (
            value.result is None
            or row.version != 2
            or (
                value.result.decision_id != row.id
                or value.result.binding_id != row.binding_id
                or value.result.operation != row.operation
                or value.result.state != row.state
            )
        ):
            raise ValueError("admin_terminal_result_changed")
        return value
    except ValueError:
        raise Conflict("admin_decision_evidence_changed") from None


class AdminDecisions(AdministrativeAuthority):
    def __init__(self, db: Database, settings: Settings) -> None:
        super().__init__(db, settings)

    @staticmethod
    async def _binding(session: AsyncSession, identity: str) -> Binding:
        current = await session.scalar(
            select(Binding).where(Binding.id == identity).with_for_update()
        )
        if current is None or current.state != "active":
            raise Conflict("admin_active_binding_required")
        return current

    @staticmethod
    async def _effects(session: AsyncSession, binding_id: str) -> dict[str, tuple[Effect, ...]]:
        tables: dict[str, tuple[Any, Any, Any]] = {
            "actions": (
                Action,
                Action.id,
                Action.state.not_in(("completed", "cancelled", "rejected", "failed")),
            ),
            "interactions": (
                PendingInteraction,
                PendingInteraction.id,
                PendingInteraction.state == "pending",
            ),
            "capture": (
                GeneratedCaptureJob,
                GeneratedCaptureJob.action_id,
                GeneratedCaptureJob.state.in_(("pending", "capturing", "held")),
            ),
            "deliveries": (
                Delivery,
                Delivery.id,
                Delivery.state.not_in(("delivered", "cancelled", "rejected")),
            ),
            "transfers": (
                FileTransfer,
                FileTransfer.id,
                FileTransfer.state.in_(("prepared", "uploading", "uploaded", "verified", "held")),
            ),
        }
        result = {}
        for name, (model, identity, active) in tables.items():
            rows = (
                (
                    await session.execute(
                        select(identity.label("id"), model.version, model.state)
                        .where(model.binding_id == binding_id, active)
                        .order_by(identity)
                        .limit(MAX_EFFECT_ROWS + 1)
                        .with_for_update()
                    )
                )
                .mappings()
                .all()
            )
            if len(rows) > MAX_EFFECT_ROWS:
                raise Conflict("admin_preview_too_many_active_records")
            result[name] = tuple(Effect.model_validate(dict(row)) for row in rows)
        return result

    @staticmethod
    def _response(row: AdminDecision, intent: AdminIntent) -> dict[str, Any]:
        response: dict[str, Any] = {
            "decision_id": row.id,
            "state": row.state,
            "version": row.version,
            "principal_kind": intent.principal_kind,
            "client_action_id": intent.client_action_id,
        }
        if intent.result is not None:
            response["result"] = intent.result.model_dump(mode="json")
        else:
            response.update(
                confirmation_token=intent.confirmation_token,
                expires_at=intent.expires_at,
                preview={
                    "operation": intent.operation,
                    "scope": intent.payload()["scope"],
                    "queue_revision": intent.queue_revision,
                    "dispatch_paused": intent.dispatch_paused,
                    "affected": {
                        name: dict(Counter(e.state for e in rows))
                        for name, rows in intent.effects.items()
                    },
                    "native_session_deleted": False,
                    "upstream_requests": 0,
                },
            )
        return response

    async def preview(
        self,
        token: str,
        admin_id: str,
        fence: ConsumerFence,
        *,
        client_action_id: str,
        operation: Operation,
        binding_id: str,
        binding_revision: int,
        queue_revision: int,
    ) -> dict[str, Any]:
        # Validate canonical IDs even for internal callers; no realm/user ID is accepted.
        import uuid

        try:
            canonical = all(
                str(uuid.UUID(v)) == v for v in (client_action_id, binding_id, admin_id)
            )
        except (ValueError, AttributeError, TypeError):
            canonical = False
        if not canonical:
            raise Conflict("admin_canonical_identifier_required")
        if (
            operation not in {"pause", "unbind"}
            or type(binding_revision) is not int
            or type(queue_revision) is not int
        ):
            raise Conflict("admin_operation_required")
        async with self.db.sessions.begin() as session:
            session_hash = await self._principal(session, token, admin_id)
            await fence.lock(session)
            existing = await session.scalar(
                select(AdminDecision)
                .where(
                    AdminDecision.admin_id == admin_id,
                    AdminDecision.client_action_id == client_action_id,
                )
                .with_for_update()
            )
            if existing is not None:
                intent = read_intent(existing)
                if (
                    existing.session_hash,
                    existing.operation,
                    existing.binding_id,
                    existing.binding_revision,
                    existing.queue_revision,
                ) != (session_hash, operation, binding_id, binding_revision, queue_revision):
                    raise Conflict("admin_idempotency_scope_changed")
                if existing.state == "pending" and (
                    existing.expires_at <= time.time()
                    or (existing.holder, existing.fencing) != (fence.holder, fence.fencing)
                ):
                    raise Conflict("admin_preview_expired_or_process_changed")
                await self._require_live(session, admin_id, session_hash, fence)
                return self._response(existing, intent)
            pending = await self._pending_previews(session, admin_id)
            if pending is not None and pending >= MAX_PENDING_DECISIONS:
                raise Conflict("admin_pending_preview_limit")
            binding = await self._binding(session, binding_id)
            if (binding.revision, binding.queue_revision) != (binding_revision, queue_revision):
                raise Conflict("admin_binding_or_queue_changed")
            intent = AdminIntent(
                decision_id=uid(),
                admin_id=admin_id,
                session_hash=session_hash,
                client_action_id=client_action_id,
                operation=operation,
                scope=scope(binding),
                dispatch_paused=binding.dispatch_paused,
                queue_revision=queue_revision,
                effects=await self._effects(session, binding_id),
                holder=fence.holder,
                fencing=fence.fencing,
                confirmation_token=secrets.token_urlsafe(32),
                expires_at=time.time() + TTL,
            )
            payload = intent.payload()
            row = AdminDecision(
                id=intent.decision_id,
                admin_id=admin_id,
                session_hash=session_hash,
                client_action_id=client_action_id,
                operation=operation,
                binding_id=binding_id,
                binding_revision=binding_revision,
                queue_revision=queue_revision,
                holder=fence.holder,
                fencing=fence.fencing,
                confirmation_hash=token_hash(intent.confirmation_token),
                payload=payload,
                payload_hash=digest(payload),
                expires_at=intent.expires_at,
                state="pending",
                version=1,
            )
            session.add(row)
            session.add(
                AuditEvent(
                    actor="admin:" + admin_id, event="admin_scope_previewed", object_id=row.id
                )
            )
            await session.flush()
            await self._require_live(session, admin_id, session_hash, fence)
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
            # Same lock order as preview and other fenced binding operations.
            await fence.lock(session)
            row = await session.scalar(
                select(AdminDecision)
                .where(
                    AdminDecision.id == decision_id,
                    AdminDecision.admin_id == admin_id,
                    AdminDecision.session_hash == session_hash,
                )
                .with_for_update()
            )
            if row is None:
                raise Conflict("admin_decision_unavailable")
            intent = read_intent(row)
            if (
                type(version) is not int
                or version != 1
                or not secrets.compare_digest(token_hash(confirmation_token), row.confirmation_hash)
            ):
                raise Conflict("admin_confirmation_rejected")
            desired: Literal["cancelled", "confirmed"] = "cancelled" if cancel else "confirmed"
            if row.state != "pending":
                if row.state != desired:
                    raise Conflict("admin_decision_already_finished")
                await self._require_live(session, admin_id, session_hash, fence)
                return self._response(row, intent)
            if not cancel and (
                row.expires_at <= time.time()
                or (row.holder, row.fencing) != (fence.holder, fence.fencing)
            ):
                raise Conflict("admin_preview_expired_or_process_changed")
            binding: Binding | None = None
            held = 0
            if not cancel:
                binding = await self._binding(session, row.binding_id)
                if (scope(binding), binding.queue_revision, binding.dispatch_paused) != (
                    intent.scope,
                    intent.queue_revision,
                    intent.dispatch_paused,
                ) or await self._effects(session, row.binding_id) != intent.effects:
                    raise Conflict("admin_preview_scope_or_work_changed")
                held = sum(e.state == "queued" for e in intent.effects["actions"])
            event = AuditEvent(
                id=uid(),
                actor="admin:" + admin_id,
                event="admin_decision_cancelled"
                if cancel
                else "admin_queue_paused"
                if intent.operation == "pause"
                else "admin_session_unbound",
                object_id=row.binding_id,
            )
            result = AdminResult(
                decision_id=row.id,
                operation=intent.operation,
                binding_id=row.binding_id,
                binding_revision=row.binding_revision
                + (not cancel and intent.operation == "unbind"),
                queue_revision=row.queue_revision + (not cancel),
                actions_held=held,
                audit_id=event.id,
                state=desired,
            )
            completed = intent.model_copy(update={"result": result})
            payload = completed.payload()
            # Consume the one-use decision while all original rows are locked. The
            # statement re-evaluates current database time after potentially slow
            # metadata validation/encoding; failures roll back the nonce and effects.
            claim = update(AdminDecision).where(
                AdminDecision.id == row.id,
                AdminDecision.admin_id == admin_id,
                AdminDecision.session_hash == session_hash,
                AdminDecision.confirmation_hash == token_hash(confirmation_token),
                AdminDecision.payload_hash == row.payload_hash,
                AdminDecision.state == "pending",
                AdminDecision.version == 1,
                *self._authority(admin_id, session_hash, fence),
            )
            if not cancel:
                claim = claim.where(
                    AdminDecision.expires_at > self._clock(),
                    AdminDecision.holder == fence.holder,
                    AdminDecision.fencing == fence.fencing,
                )
            claimed = await session.execute(
                claim.values(
                    state=desired, version=2, payload=payload, payload_hash=digest(payload)
                ).execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("admin_confirmation_expired_or_authority_changed")
            if not cancel:
                assert binding is not None
                changes: dict[str, Any] = {
                    "dispatch_paused": True,
                    "queue_revision": binding.queue_revision + 1,
                }
                if intent.operation == "unbind":
                    changes.update(
                        state="unbound",
                        revision=binding.revision + 1,
                        session_key=None,
                        topic_key=None,
                    )
                changed = await session.execute(
                    update(Binding)
                    .where(
                        Binding.id == row.binding_id,
                        Binding.revision == row.binding_revision,
                        Binding.queue_revision == row.queue_revision,
                        Binding.state == "active",
                    )
                    .values(**changes)
                )
                if changed.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("admin_binding_or_queue_changed")
                changed_actions = await session.execute(
                    update(Action)
                    .where(Action.binding_id == row.binding_id, Action.state == "queued")
                    .values(state="held", version=Action.version + 1)
                )
                if changed_actions.rowcount != held:  # type: ignore[attr-defined]
                    raise Conflict("admin_queued_work_changed")
            session.add(event)
            await session.flush()
            await session.refresh(row)
            if read_intent(row) != completed:
                raise Conflict("admin_confirmation_receipt_changed")
            return self._response(row, completed)
