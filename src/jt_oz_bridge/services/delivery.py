"""Fenced one-attempt outbox delivery and positive-evidence reconciliation."""

import asyncio
import math
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, case, distinct, func, or_, select, update
from sqlalchemy.orm import aliased
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.selectable import Exists

from jt_oz_bridge.adapters.opencode.transcript import TranscriptReader
from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred, request_lane
from jt_oz_bridge.domain.delivery import (
    ChatGateway,
    DeliveryNotSent,
    DeliveryRateLimited,
    DeliveryRejected,
    PostedMessage,
    original_write_witness,
)
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.batch_dependencies import dependency_ready, validate_dependency
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.draft_freshness import original_draft_witness
from jt_oz_bridge.services.file_returns import RENDERER as FILE_RENDERER
from jt_oz_bridge.services.file_returns import FileReturnJournal
from jt_oz_bridge.services.outbox import OutboundPayload, Outbox
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.guards import enrollment
from jt_oz_bridge.storage.models import (
    AuditEvent,
    Delivery,
    DeliveryBatch,
    DeliveryLane,
    Grant,
    WorkerLease,
)
from jt_oz_bridge.storage.output_models import OutputDestination
from jt_oz_bridge.storage.statements import insert

if TYPE_CHECKING:
    from jt_oz_bridge.services.dispatch_feedback import DispatchFeedback


class DeliveryWorker:
    def __init__(
        self,
        outbox: Outbox,
        gateway: ChatGateway,
        holder: str,
        fencing: int,
        *,
        minimum_interval: float = 1,
        draft_readers: Mapping[SessionRef, TranscriptReader] | None = None,
        file_returns: FileReturnJournal | None = None,
        dispatch_feedback: "DispatchFeedback | None" = None,
    ) -> None:
        if not math.isfinite(minimum_interval) or minimum_interval < 0:
            raise ValueError("invalid delivery interval")
        self.outbox, self.db, self.gateway = outbox, outbox.db, gateway
        self.holder, self.fencing, self.interval = holder, fencing, minimum_interval
        self.draft_readers = readonly_enrollment(draft_readers if draft_readers is not None else {})
        if file_returns is not None and (
            file_returns.outbox is not outbox
            or (file_returns.fence.holder, file_returns.fence.fencing) != (holder, fencing)
        ):
            raise ValueError("file_delivery_requires_same_outbox_and_fence")
        self.file_returns = file_returns
        if dispatch_feedback is not None and (
            dispatch_feedback.outbox is not outbox
            or outbox.fence is None
            or (outbox.fence.holder, outbox.fence.fencing) != (holder, fencing)
            or dispatch_feedback.realm_id != gateway.realm_id
        ):
            raise ValueError("unsent_feedback_delivery_requires_same_outbox_and_fence")
        self.dispatch_feedback = dispatch_feedback

    async def feedback_witness(self, saved: Delivery) -> Callable[[], bool] | None:
        if self.dispatch_feedback is not None:
            return await self.dispatch_feedback.delivery_witness(saved)
        if saved.batch_id is not None:
            from jt_oz_bridge.services.dispatch_feedback import PREFIX

            async with self.db.sessions() as session:
                batch = await session.get(DeliveryBatch, saved.batch_id)
            if batch is not None and batch.renderer_version.startswith(PREFIX):
                raise Conflict("unsent_feedback_delivery_guard_not_enrolled")
        return None

    async def file_witness(self, saved: Delivery) -> Callable[[], bool] | None:
        if self.file_returns is not None:
            return await self.file_returns.delivery_witness(saved)
        if saved.batch_id is not None:
            async with self.db.sessions() as session:
                batch = await session.get(DeliveryBatch, saved.batch_id)
                file_id = await session.scalar(
                    select(FileTransfer.id).where(FileTransfer.batch_id == saved.batch_id)
                )
            if file_id is not None or batch is not None and batch.renderer_version == FILE_RENDERER:
                raise Conflict("file_return_delivery_guard_not_enrolled")
        return None

    def lease(self) -> Exists:
        return (
            select(WorkerLease.role)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == self.holder,
                WorkerLease.fencing == self.fencing,
                WorkerLease.expires_at > time.time(),
            )
            .exists()
        )

    @staticmethod
    def page_ready() -> ColumnElement[bool]:
        earlier = aliased(Delivery)
        delivered = (
            select(func.count(earlier.id))
            .where(
                earlier.batch_id == Delivery.batch_id,
                earlier.batch_index < Delivery.batch_index,
                earlier.state == "delivered",
                earlier.posted_message_id > 0,
            )
            .correlate(Delivery)
            .scalar_subquery()
        )
        return and_(
            or_(Delivery.batch_id.is_(None), delivered == Delivery.batch_index), dependency_ready()
        )

    @classmethod
    def next_pending(cls, realm_id: str, now: float) -> Select[tuple[str]]:
        return (
            select(Delivery.id)
            .outerjoin(Binding, Binding.id == Delivery.binding_id)
            .outerjoin(OutputDestination, OutputDestination.id == Delivery.destination_id)
            .where(
                or_(Binding.realm_id == realm_id, OutputDestination.realm_id == realm_id),
                Delivery.state == "pending",
                Delivery.retry_at <= now,
                cls.page_ready(),
            )
            .order_by(Delivery.priority, Delivery.created_at, Delivery.id)
            .limit(1)
        )

    async def payload(self, saved: Delivery) -> OutboundPayload:
        binding_id, revision = self.outbox.bound(saved)
        if saved.batch_id is not None:
            # Validate own immutable metadata first. The one fresh external
            # audience inspector below still performs its two independent
            # rounds after these awaits; no Human/channel ACL is cached.
            async with self.db.sessions() as session:
                stored_binding = await session.get(Binding, binding_id)
                stored_batch = await session.get(DeliveryBatch, saved.batch_id)
            if (
                stored_binding is None
                or stored_batch is None
                or stored_binding.revision != revision
            ):
                raise Conflict("delivery_batch_scope_changed")
            batch = await self.outbox._validated_batch(stored_binding, stored_batch)
            if (
                saved.batch_index is None
                or not 0 <= saved.batch_index < len(batch.deliveries)
                or batch.deliveries[saved.batch_index] != saved.id
            ):
                raise Conflict("delivery_batch_scope_changed")
        elif saved.batch_index is not None:
            raise Conflict("delivery_batch_scope_changed")
        payload = OutboundPayload.model_validate(saved.payload)
        if (
            saved.payload_hash != digest(saved.payload)
            or payload.marker != "jtoz:" + saved.id
            or payload.realm_id != self.gateway.realm_id
            or payload.bot_user_id != self.gateway.bot_user_id
        ):
            raise Conflict("outbound identity or content changed")
        binding = await self.outbox.target(binding_id, revision)
        if (payload.realm_id, payload.channel_id, payload.topic) != (
            binding.realm_id,
            binding.channel_id,
            binding.topic,
        ):
            raise Conflict("outbound target changed")
        return payload

    async def hold(self, saved: Delivery, reason: str) -> str:
        async with self.db.sessions.begin() as session:
            await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.state == "pending",
                    Delivery.version == saved.version,
                    self.lease(),
                )
                .values(
                    state="held",
                    status_reason=reason,
                    version=Delivery.version + 1,
                    updated_at=time.time(),
                )
            )
        return (await self.outbox.load(saved.id)).state

    async def claim(self, saved: Delivery, payload: OutboundPayload) -> bool:
        now = time.time()
        async with self.db.sessions.begin() as session:
            lease = await session.execute(
                update(WorkerLease)
                .where(
                    WorkerLease.role == "consumer",
                    WorkerLease.holder == self.holder,
                    WorkerLease.fencing == self.fencing,
                    WorkerLease.expires_at > now,
                )
                .values(expires_at=WorkerLease.expires_at)
            )
            if lease.rowcount != 1:  # type: ignore[attr-defined]
                return False
            await session.execute(
                insert(self.db, DeliveryLane)
                .values(realm_id=payload.realm_id)
                .on_conflict_do_nothing(index_elements=["realm_id"])
            )
            lane = await session.get(DeliveryLane, payload.realm_id)
            if lane is None or lane.not_before > now or saved.retry_at > now:
                return False
            next_id = await session.scalar(self.next_pending(payload.realm_id, now))
            if next_id != saved.id:
                return False
            if self.file_returns is not None:
                await self.file_returns.lock_delivery(session, saved)
            if self.dispatch_feedback is not None:
                await self.dispatch_feedback.lock_delivery(session, saved)
            current_binding = await session.get(Binding, saved.binding_id)
            if not current_binding or not current_binding.audience_user_ids:
                return False
            if saved.batch_id is not None:
                await validate_dependency(
                    session, saved.batch_id, current_binding, self.outbox.bot_user_id
                )
            audience = current_binding.audience_user_ids
            viewers = select(func.count(distinct(Grant.user_id))).where(
                Grant.realm_id == payload.realm_id,
                Grant.project_id == current_binding.project_id,
                Grant.user_id.in_(audience),
                Grant.active.is_(True),
                Grant.role.in_(
                    [role for role, permissions in ROLES.items() if Permission.VIEW in permissions]
                ),
            ).scalar_subquery() == len(set(audience))
            binding = (
                select(Binding.id)
                .where(
                    Binding.id == saved.binding_id,
                    Binding.state == "active",
                    Binding.revision == saved.binding_revision,
                    Binding.realm_id == payload.realm_id,
                    Binding.channel_id == payload.channel_id,
                    Binding.topic == payload.topic,
                    Binding.audience_revision == current_binding.audience_revision,
                )
                .exists()
            )
            result = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.state == "pending",
                    Delivery.version == saved.version,
                    Delivery.binding_id == saved.binding_id,
                    Delivery.binding_revision == saved.binding_revision,
                    Delivery.destination_id.is_(None),
                    Delivery.payload_hash == digest(saved.payload),
                    binding,
                    self.page_ready(),
                    self.lease(),
                    viewers,
                    *enrollment(
                        current_binding,
                        self.outbox.bindings.control.contract_for(reference(current_binding)),
                    ),
                )
                .values(
                    state="sending",
                    attempts=Delivery.attempts + 1,
                    version=Delivery.version + 1,
                    status_reason=None,
                    updated_at=now,
                )
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                return False
            lane.not_before = now + max(self.interval, lane.backoff)
            session.add(
                AuditEvent(actor="worker", event="delivery_dispatching", object_id=saved.id)
            )
            return True

    async def finish(
        self,
        saved: Delivery,
        state: str,
        *,
        message_id: int | None = None,
        reason: str | None = None,
        from_state: str = "sending",
    ) -> str:
        expected_version = saved.version + 1 if from_state == "sending" else saved.version
        values: dict[str, Any] = {
            "state": state,
            "status_reason": reason,
            "version": expected_version + 1,
            "updated_at": time.time(),
        }
        if message_id is not None:
            values["posted_message_id"] = message_id
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.state == from_state,
                    Delivery.version == expected_version,
                    self.lease(),
                )
                .values(**values)
            )
            if result.rowcount == 1 and state == "delivered":  # type: ignore[attr-defined]
                await session.execute(
                    update(DeliveryLane)
                    .where(DeliveryLane.realm_id == self.gateway.realm_id)
                    .values(backoff=DeliveryLane.backoff / 2)
                )
            if result.rowcount == 1:  # type: ignore[attr-defined]
                session.add(
                    AuditEvent(actor="worker", event="delivery_" + state, object_id=saved.id)
                )
        return (await self.outbox.load(saved.id)).state

    async def rate_limit(
        self,
        saved: Delivery,
        retry_after: float,
        *,
        before_send: bool = False,
        local_budget: bool = False,
        refill_window: float | None = None,
    ) -> str:
        if refill_window is not None and (
            not local_budget
            or type(refill_window) not in {int, float}
            or not math.isfinite(refill_window)
            or not 1 <= refill_window <= 3600
        ):
            raise ValueError("invalid_delivery_budget_refill_window")
        delay = max(1, min(3600, retry_after)) if math.isfinite(retry_after) else 60
        if local_budget and refill_window is not None:
            # Every retry restarts complete Source/audience reads. A single
            # newly freed rolling-window slot cannot complete that attempt.
            # Wait this budget's actual window without delaying other outputs.
            delay = max(delay, refill_window)
        retry_at = time.time() + delay
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.state == ("pending" if before_send else "sending"),
                    Delivery.version == saved.version + (0 if before_send else 1),
                    self.lease(),
                )
                .values(
                    state="pending",
                    version=Delivery.version + 1,
                    retry_at=retry_at,
                    attempts=saved.attempts if local_budget else Delivery.attempts,
                    status_reason="request_budget_deferred"
                    if local_budget
                    else "scope_rate_limited"
                    if before_send
                    else "rate_limited",
                    updated_at=time.time(),
                )
            )
            if result.rowcount == 1:  # type: ignore[attr-defined]
                session.add(
                    AuditEvent(
                        actor="worker",
                        event="delivery_request_budget_deferred"
                        if local_budget
                        else "delivery_scope_rate_limited"
                        if before_send
                        else "delivery_rate_limited",
                        object_id=saved.id,
                    )
                )
                if local_budget:
                    return "pending"  # Reserve headroom for other control/final items.
                await session.execute(
                    insert(self.db, DeliveryLane)
                    .values(realm_id=self.gateway.realm_id)
                    .on_conflict_do_nothing(index_elements=["realm_id"])
                )
                await session.execute(
                    update(DeliveryLane)
                    .where(DeliveryLane.realm_id == self.gateway.realm_id)
                    .values(
                        not_before=case(
                            (DeliveryLane.not_before < retry_at, retry_at),
                            else_=DeliveryLane.not_before,
                        ),
                        backoff=case(
                            (DeliveryLane.backoff < delay, delay), else_=DeliveryLane.backoff
                        ),
                    )
                )
        return (await self.outbox.load(saved.id)).state

    def matches(self, message: PostedMessage, payload: OutboundPayload) -> bool:
        return (
            message.realm_id == payload.realm_id
            and message.channel_id == payload.channel_id
            and message.topic == payload.topic
            and message.sender_id == payload.bot_user_id
            and message.content == payload.content
        )

    async def abort_unsent_claim(self, saved: Delivery) -> str:
        """Release a claim whose HTTP write never started, with positive local evidence."""
        async with self.db.sessions.begin() as session:
            result = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.state == "sending",
                    Delivery.version == saved.version + 1,
                    Delivery.attempts == saved.attempts + 1,
                    Delivery.posted_message_id.is_(None),
                    self.lease(),
                )
                .values(
                    state="held",
                    version=Delivery.version + 1,
                    attempts=saved.attempts,
                    status_reason="draft_original_witness_expired_before_http",
                    updated_at=time.time(),
                )
            )
            if result.rowcount == 1:  # type: ignore[attr-defined]
                session.add(
                    AuditEvent(
                        actor="worker",
                        event="delivery_claim_aborted_before_http",
                        object_id=saved.id,
                    )
                )
        return (await self.outbox.load(saved.id)).state

    async def advance(self, delivery_id: str) -> str:
        saved = await self.outbox.load(delivery_id)
        with request_lane(
            "control"
            if saved.priority <= 10
            else "final"
            if saved.priority <= 100
            else "draft"
            if saved.priority >= 200
            else "normal"
        ):
            return await self.advance_saved(saved)

    async def advance_saved(self, saved: Delivery) -> str:
        if saved.state != "pending":
            return saved.state
        async with self.db.sessions() as session:
            lane = await session.get(DeliveryLane, self.gateway.realm_id)
        if saved.retry_at > time.time() or (lane is not None and lane.not_before > time.time()):
            return saved.state  # Scheduling only; a later actual attempt rechecks the ACL.
        try:
            draft_witness = await original_draft_witness(self.outbox, saved, self.draft_readers)
            file_witness = await self.file_witness(saved)
            feedback_witness = await self.feedback_witness(saved)
            witness = (
                (
                    lambda: (
                        (draft_witness is None or draft_witness())
                        and (file_witness is None or file_witness())
                        and (feedback_witness is None or feedback_witness())
                    )
                )
                if draft_witness is not None
                or file_witness is not None
                or feedback_witness is not None
                else None
            )
            payload = await self.payload(saved)
            if not self.gateway.writes_enabled:
                return await self.hold(saved, "zulip_message_contract_not_attested")
            if payload.operation == "edit":
                base = await self.outbox.load(payload.target_delivery_id or "")
                base_payload = OutboundPayload.model_validate(base.payload)
                current = await self.gateway.get(payload.target_message_id or 0)
                if (
                    base.state != "delivered"
                    or base.posted_message_id != current.id
                    or base.binding_id != saved.binding_id
                    or base.binding_revision != saved.binding_revision
                    or base.payload_hash != digest(base.payload)
                    or not self.matches(current, base_payload)
                    or digest({"content": current.content}) != payload.previous_content_hash
                ):
                    return await self.hold(saved, "edit_source_changed")
        except RequestBudgetDeferred as error:
            return await self.rate_limit(
                saved,
                error.retry_after,
                before_send=True,
                local_budget=True,
                refill_window=error.refill_window,
            )
        except DeliveryRateLimited as error:
            return await self.rate_limit(saved, error.retry_after, before_send=True)
        except (AccessDenied, Conflict, ValueError):
            return await self.hold(saved, "output_authorization_or_identity_changed")
        if witness is not None and not witness():
            return await self.hold(saved, "draft_original_witness_expired_before_claim")
        try:
            claimed = await self.claim(saved, payload)
        except (AccessDenied, Conflict, ValueError):
            return await self.hold(saved, "output_dependency_or_scope_changed_before_claim")
        if not claimed:
            return (await self.outbox.load(saved.id)).state
        if witness is not None and not witness():
            return await self.abort_unsent_claim(saved)
        try:
            with original_write_witness(witness):
                if payload.operation == "post":
                    message_id = await self.gateway.send(
                        payload.channel_id,
                        payload.topic,
                        payload.content,
                        payload.marker,
                        **({"widget": payload.widget} if payload.widget is not None else {}),
                    )
                    if (
                        isinstance(message_id, bool)
                        or not isinstance(message_id, int)
                        or message_id <= 0
                    ):
                        raise ValueError("invalid admission")
                else:
                    await self.gateway.edit(payload.target_message_id or 0, payload.content)
                    assert payload.target_message_id is not None
                    message_id = payload.target_message_id
        except DeliveryNotSent:
            return await self.abort_unsent_claim(saved)
        except RequestBudgetDeferred as error:
            return await self.rate_limit(
                saved, error.retry_after, local_budget=True, refill_window=error.refill_window
            )
        except DeliveryRateLimited as error:
            return await self.rate_limit(saved, error.retry_after)
        except DeliveryRejected:
            return await self.finish(saved, "rejected", reason="upstream_rejected")
        except asyncio.CancelledError:
            await asyncio.shield(self.finish(saved, "ambiguous", reason="cancelled_during_send"))
            raise
        except Exception:
            return await self.finish(saved, "ambiguous", reason="outcome_unknown")
        return await self.finish(saved, "delivered", message_id=message_id)

    async def reconcile(self, delivery_id: str) -> str:
        saved = await self.outbox.load(delivery_id)
        if saved.state != "ambiguous":
            return saved.state
        try:
            payload = await self.payload(saved)
            candidates: tuple[PostedMessage, ...]
            if payload.operation == "edit":
                candidates = (await self.gateway.get(payload.target_message_id or 0),)
            else:
                candidates = await self.gateway.find(
                    payload.channel_id, payload.topic, payload.marker
                )
            matches = [item for item in candidates if self.matches(item, payload)]
            if len(matches) != 1:
                return "ambiguous"  # Absence/duplicates never justify a fresh POST.
        except (AccessDenied, Conflict, ValueError):
            return "ambiguous"
        return await self.finish(
            saved, "delivered", message_id=matches[0].id, from_state="ambiguous"
        )
