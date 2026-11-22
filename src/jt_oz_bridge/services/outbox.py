"""Immutable outbound content/targets and explicit recovery of unsent output."""

import time
from dataclasses import dataclass
from typing import Any, Literal, Self

from pydantic import Field, StrictInt, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.control import AudienceSnapshot, ControlModel
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE, with_marker, without_marker
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.batch_dependencies import store_dependency, validate_dependency
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import AuditEvent, Delivery, DeliveryBatch, uid
from jt_oz_bridge.storage.statements import insert


class OutboundPayload(ControlModel):
    operation: Literal["post", "edit"]
    realm_id: str
    channel_id: StrictInt = Field(gt=0)
    topic: str
    bot_user_id: StrictInt = Field(gt=0)
    content: str = Field(min_length=1, max_length=1000000)
    marker: str = Field(pattern=r"^jtoz:[0-9a-f-]{36}$")
    target_delivery_id: str | None = None
    target_message_id: StrictInt | None = Field(default=None, gt=0)
    widget: str | None = Field(default=None, max_length=65536)
    previous_content_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent(self) -> Self:
        edit = (
            self.target_delivery_id is not None
            and self.target_message_id is not None
            and self.previous_content_hash is not None
        )
        if (self.operation == "edit") != edit:
            raise ValueError("edit target proof required")
        if self.operation == "post" and any(
            value is not None
            for value in (
                self.target_delivery_id,
                self.target_message_id,
                self.previous_content_hash,
            )
        ):
            raise ValueError("post cannot include an edit target")
        if without_marker(self.content, self.marker) is None:
            raise ValueError("delivery marker missing")
        return self


@dataclass(frozen=True)
class QueuedBatch:
    id: str
    deliveries: tuple[str, ...]


class BatchEdit(ControlModel):
    target_delivery_id: str
    target_message_id: StrictInt = Field(gt=0)
    previous_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def batch_digest(
    pages: tuple[str, ...],
    renderer: str,
    message_limit: int,
    topic_limit: int,
    edit: BatchEdit | None = None,
    widget: str | None = None,
) -> str:
    value: dict[str, Any] = {
        "pages": list(pages),
        "renderer": renderer,
        "message_limit": message_limit,
        "topic_limit": topic_limit,
    }
    if edit is not None:
        value["edit"] = edit.model_dump(mode="json")
    if widget is not None:
        value["widget"] = widget
    return digest(value)


class Outbox:
    def __init__(
        self, bindings: BindingService, bot_user_id: int, *, fence: ConsumerFence | None = None
    ) -> None:
        if isinstance(bot_user_id, bool) or not isinstance(bot_user_id, int) or bot_user_id <= 0:
            raise ValueError("dedicated Bot numeric identity required")
        self.bindings, self.db, self.bot_user_id = bindings, bindings.db, bot_user_id
        self.fence = fence

    async def load(self, delivery_id: str) -> Delivery:
        async with self.db.sessions() as session:
            saved = await session.get(Delivery, delivery_id)
        if not saved:
            raise Conflict("delivery unavailable")
        return saved

    async def edit_source(
        self, session: AsyncSession, binding: Binding, edit_of: str | None
    ) -> BatchEdit | None:
        if edit_of is None:
            return None
        previous = await session.get(Delivery, edit_of)
        if previous is None or (
            previous.state != "delivered"
            or previous.posted_message_id is None
            or previous.destination_id is not None
            or (previous.binding_id, previous.binding_revision) != (binding.id, binding.revision)
            or digest(previous.payload) != previous.payload_hash
        ):
            raise Conflict("batch_edit_target_not_verified_delivered")
        payload = OutboundPayload.model_validate(previous.payload)
        if (
            payload.realm_id,
            payload.channel_id,
            payload.topic,
            payload.bot_user_id,
            payload.marker,
        ) != (
            binding.realm_id,
            binding.channel_id,
            binding.topic,
            self.bot_user_id,
            "jtoz:" + previous.id,
        ):
            raise Conflict("batch_edit_target_scope_changed")
        if previous.batch_id is not None:
            await validate_dependency(session, previous.batch_id, binding, self.bot_user_id)
        return BatchEdit(
            target_delivery_id=previous.id,
            target_message_id=previous.posted_message_id,
            previous_content_hash=digest({"content": payload.content}),
        )

    @staticmethod
    def bound(saved: Delivery) -> tuple[str, int]:
        if (
            saved.destination_id is not None
            or saved.binding_id is None
            or saved.binding_revision is None
        ):
            raise Conflict("delivery_requires_bound_authorization")
        return saved.binding_id, saved.binding_revision

    async def target(
        self, binding_id: str, revision: int, *, audience: AudienceSnapshot | None = None
    ) -> Binding:
        """Current binding for output; reads Zulip in full unless ``audience`` is given.

        ``audience`` is only for a caller that read Zulip in full for this same
        decision moments ago and reads it in full again before its commit; the
        owned SQL scope is still re-checked against it here.
        """
        async with self.db.sessions() as session:
            binding = await session.get(Binding, binding_id)
        if not binding or binding.state != "active" or binding.revision != revision:
            raise Conflict("delivery binding changed")
        await self.bindings.enrolled(reference(binding), binding.realm_id)
        if audience is None:
            await self.bindings.audience_for_output(binding)
        else:
            await self.bindings.require_output_audience(binding, audience)
        return binding

    async def queue(
        self,
        key: str,
        binding_id: str,
        revision: int,
        text: str,
        *,
        priority: int = 100,
        edit_of: str | None = None,
    ) -> str:
        if not text or not 0 <= priority <= 1000:
            raise ValueError("invalid output content or priority")
        binding = await self.target(binding_id, revision)
        previous = await self.load(edit_of) if edit_of else None
        if previous and (
            previous.state != "delivered"
            or not previous.posted_message_id
            or previous.binding_id != binding_id
            or previous.binding_revision != revision
            or previous.payload_hash != digest(previous.payload)
        ):
            raise Conflict("edit target not a verified delivered message")
        previous_payload = OutboundPayload.model_validate(previous.payload) if previous else None
        if previous_payload and previous_payload.bot_user_id != self.bot_user_id:
            raise Conflict("edit target Bot changed")
        dedupe = "outbound:" + digest({"key": key, "binding": binding_id, "revision": revision})

        def payload(delivery_id: str) -> dict[str, Any]:
            marker = "jtoz:" + delivery_id
            return OutboundPayload(
                operation="edit" if previous else "post",
                realm_id=binding.realm_id,
                channel_id=binding.channel_id,
                topic=binding.topic,
                bot_user_id=self.bot_user_id,
                content=with_marker(text, marker),
                marker=marker,
                target_delivery_id=edit_of,
                target_message_id=previous.posted_message_id if previous else None,
                previous_content_hash=digest({"content": previous_payload.content})
                if previous_payload
                else None,
            ).model_dump(mode="json")

        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            identity = uid()
            values = payload(identity)
            saved_id = (
                await session.execute(
                    insert(self.db, Delivery)
                    .values(
                        id=identity,
                        dedupe_key=dedupe,
                        binding_id=binding_id,
                        binding_revision=revision,
                        payload=values,
                        payload_hash=digest(values),
                        priority=priority,
                    )
                    .on_conflict_do_nothing(index_elements=["dedupe_key"])
                    .returning(Delivery.id)
                )
            ).scalar_one_or_none()
            if saved_id:
                return str(saved_id)
            saved = (
                await session.scalars(select(Delivery).where(Delivery.dedupe_key == dedupe))
            ).one()
            if saved.payload_hash != digest(payload(saved.id)) or saved.priority != priority:
                raise Conflict("output identity reused with different content or target")
            return saved.id

    async def resume(
        self, delivery_id: str, realm: str, actor_id: int, expected_version: int
    ) -> None:
        saved = await self.load(delivery_id)
        binding_id, revision = self.bound(saved)
        await self.bindings.get(binding_id, realm, actor_id, Permission.MANAGE)
        await self.target(binding_id, revision)
        if saved.payload_hash != digest(saved.payload):
            raise Conflict("delivery content changed")
        OutboundPayload.model_validate(saved.payload)
        async with self.db.sessions.begin() as session:
            if self.fence is not None:
                await self.fence.lock(session)
            result = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.version == expected_version,
                    Delivery.state == "held",
                )
                .values(
                    state="pending",
                    version=Delivery.version + 1,
                    retry_at=0,
                    updated_at=time.time(),
                    status_reason=None,
                )
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("delivery recovery revision changed")
            session.add(
                AuditEvent(
                    actor=f"{realm}:{actor_id}", event="delivery_resumed", object_id=saved.id
                )
            )

    async def queue_batch(
        self,
        key: str,
        binding_id: str,
        revision: int,
        pages: tuple[str, ...],
        *,
        renderer_version: str,
        message_limit: int,
        topic_limit: int,
        priority: int = 10,
        after_batch_id: str | None = None,
        edit_of: str | None = None,
        widget: str | None = None,
    ) -> QueuedBatch:
        if self.fence is None:
            raise ValueError("reply_batch_requires_consumer_fence")
        if not 1 <= len(pages) <= 100:
            raise ValueError("invalid_reply_batch")
        frozen = tuple(pages)
        binding = await self.target(binding_id, revision)
        async with self.db.sessions.begin() as session:
            return await self.queue_batch_in_session(
                session,
                key,
                binding,
                frozen,
                renderer_version=renderer_version,
                message_limit=message_limit,
                topic_limit=topic_limit,
                priority=priority,
                after_batch_id=after_batch_id,
                edit_of=edit_of,
                widget=widget,
            )

    async def queue_batch_in_session(
        self,
        session: AsyncSession,
        key: str,
        binding: Binding,
        pages: tuple[str, ...],
        *,
        renderer_version: str,
        message_limit: int,
        topic_limit: int,
        priority: int = 10,
        after_batch_id: str | None = None,
        edit_of: str | None = None,
        widget: str | None = None,
    ) -> QueuedBatch:
        """No network I/O; caller joins immutable source + batch/page writes."""
        binding_id, revision = binding.id, binding.revision
        pages = tuple(pages)
        if self.fence is None:
            raise ValueError("reply_batch_requires_consumer_fence")
        if (
            not 1 <= len(pages) <= 100
            or sum(len(page) for page in pages) > 1000000
            or not 0 <= priority <= 1000
        ):
            raise ValueError("invalid_reply_batch")
        if (
            not isinstance(message_limit, int)
            or isinstance(message_limit, bool)
            or not isinstance(topic_limit, int)
            or isinstance(topic_limit, bool)
            or message_limit < 173
            or topic_limit < 1
            or not renderer_version
            or len(renderer_version) > 64
        ):
            raise ValueError("invalid_reply_render_contract")
        if len(binding.topic) > topic_limit:
            raise ValueError("topic_exceeds_reported_limit")
        footer_size = MARKER_FOOTER_SIZE
        if any(
            not isinstance(page, str) or not page or len(page) + footer_size > message_limit
            for page in pages
        ):
            raise ValueError("page_exceeds_reported_limit")
        dedupe = "reply-batch:" + digest({"key": key, "binding": binding_id, "revision": revision})
        await self.fence.lock(session)
        await lock_output_scope(self.bindings, session, binding)
        if edit_of is not None and len(pages) != 1:
            raise ValueError("batch_edit_requires_single_page")
        if widget is not None and edit_of is not None:
            raise ValueError("batch_widget_requires_new_post")
        edit = await self.edit_source(session, binding, edit_of)
        checksum = batch_digest(pages, renderer_version, message_limit, topic_limit, edit, widget)

        def outbound(identity: str, page: str, last: bool) -> dict[str, Any]:
            return OutboundPayload(
                operation="edit" if edit else "post",
                realm_id=binding.realm_id,
                channel_id=binding.channel_id,
                topic=binding.topic,
                bot_user_id=self.bot_user_id,
                content=with_marker(page, "jtoz:" + identity),
                marker="jtoz:" + identity,
                widget=widget if last else None,
                **(edit.model_dump() if edit else {}),
            ).model_dump(mode="json")

        batch_id = (
            await session.execute(
                insert(self.db, DeliveryBatch)
                .values(
                    dedupe_key=dedupe,
                    binding_id=binding_id,
                    binding_revision=revision,
                    plan_hash=checksum,
                    renderer_version=renderer_version,
                    message_limit=message_limit,
                    topic_limit=topic_limit,
                    page_count=len(pages),
                    priority=priority,
                )
                .on_conflict_do_nothing(index_elements=["dedupe_key"])
                .returning(DeliveryBatch.id)
            )
        ).scalar_one_or_none()
        if batch_id is None:
            batch = (
                await session.scalars(
                    select(DeliveryBatch).where(DeliveryBatch.dedupe_key == dedupe)
                )
            ).one()
            if (
                batch.plan_hash,
                batch.page_count,
                batch.priority,
                batch.binding_id,
                batch.binding_revision,
            ) != (checksum, len(pages), priority, binding_id, revision):
                raise Conflict("reply_plan_changed")
            dependency = await validate_dependency(session, batch.id, binding, self.bot_user_id)
            if (dependency.before_batch_id if dependency else None) != after_batch_id:
                raise Conflict("reply_batch_dependency_changed")
            existing = list(
                (
                    await session.scalars(
                        select(Delivery)
                        .where(Delivery.batch_id == batch.id)
                        .order_by(Delivery.batch_index)
                    )
                ).all()
            )
            if len(existing) != len(pages):
                raise Conflict("reply_batch_incomplete")
            for index, saved in enumerate(existing):
                expected = outbound(saved.id, pages[index], index == len(pages) - 1)
                if (
                    saved.binding_id,
                    saved.binding_revision,
                    saved.batch_index,
                    saved.priority,
                    saved.payload_hash,
                ) != (
                    binding_id,
                    revision,
                    index,
                    priority,
                    digest(expected),
                ) or saved.payload != expected:
                    raise Conflict("reply_batch_content_changed")
            return QueuedBatch(batch.id, tuple(saved.id for saved in existing))
        if after_batch_id is not None:
            await store_dependency(
                session, str(batch_id), after_batch_id, binding, self.bot_user_id
            )
        identities = []
        for index, page in enumerate(pages):
            identity = uid()
            values = outbound(identity, page, index == len(pages) - 1)
            session.add(
                Delivery(
                    id=identity,
                    dedupe_key=f"batch:{batch_id}:{index}",
                    binding_id=binding_id,
                    binding_revision=revision,
                    payload=values,
                    payload_hash=digest(values),
                    priority=priority,
                    batch_id=batch_id,
                    batch_index=index,
                )
            )
            identities.append(identity)
        await session.flush()
        return QueuedBatch(str(batch_id), tuple(identities))

    async def cached_batch(
        self,
        key: str,
        binding_id: str,
        revision: int,
        *,
        audience: AudienceSnapshot | None = None,
    ) -> QueuedBatch | None:
        """An already projected event keeps its original pages, not a newly rendered plan."""
        binding = await self.target(binding_id, revision, audience=audience)
        dedupe = "reply-batch:" + digest({"key": key, "binding": binding_id, "revision": revision})
        async with self.db.sessions() as session:
            batch = await session.scalar(
                select(DeliveryBatch).where(DeliveryBatch.dedupe_key == dedupe)
            )
        return await self._validated_batch(binding, batch) if batch is not None else None

    async def batch_by_id(self, batch_id: str, binding_id: str, revision: int) -> QueuedBatch:
        binding = await self.target(binding_id, revision)
        async with self.db.sessions() as session:
            batch = await session.get(DeliveryBatch, batch_id)
        if batch is None:
            raise Conflict("reply_batch_unavailable")
        return await self._validated_batch(binding, batch)

    async def _validated_batch(self, binding: Binding, batch: DeliveryBatch) -> QueuedBatch:
        async with self.db.sessions() as session:
            deliveries = list(
                (
                    await session.scalars(
                        select(Delivery)
                        .where(Delivery.batch_id == batch.id)
                        .order_by(Delivery.batch_index)
                        .limit(101)
                    )
                ).all()
            )
        if (
            batch.destination_id is not None
            or not 1 <= batch.page_count <= 100
            or len(deliveries) != batch.page_count
            or (batch.binding_id, batch.binding_revision) != (binding.id, binding.revision)
        ):
            raise Conflict("reply_batch_incomplete")
        async with self.db.sessions() as session:
            await validate_dependency(session, batch.id, binding, self.bot_user_id)
        pages = []
        edit = None
        widget: str | None = None
        for index, saved in enumerate(deliveries):
            if saved.destination_id is not None:
                raise Conflict("reply_batch_authorization_changed")
            payload = OutboundPayload.model_validate(saved.payload)
            if (
                saved.binding_id,
                saved.binding_revision,
                saved.batch_index,
                saved.priority,
                saved.payload_hash,
                payload.realm_id,
                payload.channel_id,
                payload.topic,
                payload.bot_user_id,
                payload.marker,
            ) != (
                binding.id,
                binding.revision,
                index,
                batch.priority,
                digest(saved.payload),
                binding.realm_id,
                binding.channel_id,
                binding.topic,
                self.bot_user_id,
                "jtoz:" + saved.id,
            ):
                raise Conflict("reply_batch_content_changed")
            if payload.operation == "edit":
                if batch.page_count != 1:
                    raise Conflict("batch_edit_requires_single_page")
                async with self.db.sessions() as session:
                    edit = await self.edit_source(session, binding, payload.target_delivery_id)
                if edit is None or (payload.target_message_id, payload.previous_content_hash) != (
                    edit.target_message_id,
                    edit.previous_content_hash,
                ):
                    raise Conflict("reply_batch_edit_source_changed")
            page = without_marker(payload.content, "jtoz:" + saved.id)
            if (
                page is None
                or len(payload.content) > batch.message_limit
                or len(payload.topic) > batch.topic_limit
            ):
                raise Conflict("reply_batch_contract_changed")
            if payload.widget is not None and index != batch.page_count - 1:
                raise Conflict("reply_batch_contract_changed")
            pages.append(page)
            widget = payload.widget
        if (
            batch_digest(
                tuple(pages),
                batch.renderer_version,
                batch.message_limit,
                batch.topic_limit,
                edit,
                widget,
            )
            != batch.plan_hash
        ):
            raise Conflict("reply_batch_plan_changed")
        return QueuedBatch(batch.id, tuple(saved.id for saved in deliveries))
