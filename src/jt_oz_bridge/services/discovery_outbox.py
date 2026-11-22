"""Atomic immutable discovery replies tied to independent encrypted authorization."""

import time
from uuid import UUID

from pydantic import Field, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE, with_marker, without_marker
from jt_oz_bridge.domain.output_target import (
    DiscoveryTarget,
    WorktreeSwitchPreviewTarget,
    output_target,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.outbox import OutboundPayload, Outbox, QueuedBatch
from jt_oz_bridge.services.output_destinations import OutputDestinations
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import AuditEvent, Delivery, DeliveryBatch, uid
from jt_oz_bridge.storage.output_models import OutputDestination


class DiscoveryPayload(OutboundPayload):
    authorization_id: UUID
    authorization_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def post_only(self) -> "DiscoveryPayload":
        if self.operation != "post":
            raise ValueError("discovery_reply_cannot_edit_another_message")
        return self


class DiscoveryOutbox(Outbox):
    def __init__(self, destinations: OutputDestinations, bot_user_id: int) -> None:
        super().__init__(destinations.discovery.bindings, bot_user_id, fence=destinations.fence)
        self.destinations = destinations

    @staticmethod
    def dedupe(key: str, target: DiscoveryTarget) -> str:
        return "discovery-batch:" + digest({"key": key, "realm": target.source.realm_id})

    @staticmethod
    def scope_key(key: str, realm: str) -> str:
        return "discovery-output:" + digest({"key": key, "realm": realm})

    @staticmethod
    def checksum(
        target: DiscoveryTarget,
        pages: tuple[str, ...],
        renderer: str,
        message_limit: int,
        topic_limit: int,
    ) -> str:
        return digest(
            {
                "pages": list(pages),
                "renderer": renderer,
                "message_limit": message_limit,
                "topic_limit": topic_limit,
                "authorization": str(target.id),
                "authorization_hash": digest(target.model_dump(mode="json")),
            }
        )

    async def cached_scope_batch(self, key: str, target: DiscoveryTarget) -> QueuedBatch | None:
        async with self.db.sessions() as session:
            batch = await session.scalar(
                select(DeliveryBatch).where(DeliveryBatch.dedupe_key == self.dedupe(key, target))
            )
        if batch is not None:
            await self.destinations.authorize(target)
            if await self.destinations.load(str(target.id)) != target:
                raise Conflict("discovery_reply_authorization_changed")
            return await self.validated_scope_batch(target, batch)
        return None

    async def scope_batch_by_id(self, identity: str, target: DiscoveryTarget) -> QueuedBatch:
        await self.destinations.authorize(target)
        async with self.db.sessions() as session:
            batch = await session.get(DeliveryBatch, identity)
        if batch is None:
            raise Conflict("discovery_reply_batch_missing")
        return await self.validated_scope_batch(target, batch)

    def _scope_plan(
        self,
        key: str,
        target: DiscoveryTarget,
        pages: tuple[str, ...],
        renderer_version: str,
        message_limit: int,
        topic_limit: int,
        priority: int,
    ) -> tuple[DiscoveryTarget, str]:
        checked = output_target(target.model_dump(mode="json"))
        if type(target) is WorktreeSwitchPreviewTarget:
            if checked != target:
                raise Conflict("worktree_preview_target_changed")
        else:
            target = checked
        self.destinations.validate_source_kind(target)
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 255
            or type(pages) is not tuple
            or not 1 <= len(pages) <= 100
            or any(not isinstance(page, str) for page in pages)
            or sum(map(len, pages)) > 1000000
            or type(message_limit) is not int
            or message_limit < 173
            or type(topic_limit) is not int
            or topic_limit < 1
            or type(priority) is not int
            or not 0 <= priority <= 1000
            or not isinstance(renderer_version, str)
            or not renderer_version
            or len(renderer_version) > 64
        ):
            raise ValueError("invalid_discovery_reply_plan")
        footer = MARKER_FOOTER_SIZE
        if len(target.source.topic) > topic_limit or any(
            not page or len(page) + footer > message_limit for page in pages
        ):
            raise ValueError("discovery_reply_exceeds_verified_limit")
        return target, self.checksum(target, pages, renderer_version, message_limit, topic_limit)

    async def queue_scope_batch(
        self,
        key: str,
        target: DiscoveryTarget,
        pages: tuple[str, ...],
        *,
        renderer_version: str,
        message_limit: int,
        topic_limit: int,
        priority: int = 10,
        widget: str | None = None,
    ) -> QueuedBatch:
        target, _checksum = self._scope_plan(
            key, target, pages, renderer_version, message_limit, topic_limit, priority
        )
        # Public entry point always rechecks current Source/audience before SQL.
        await self.destinations.authorize(target)
        async with self.db.sessions.begin() as session:
            return await self.queue_scope_batch_in_session(
                session,
                key,
                target,
                pages,
                renderer_version=renderer_version,
                message_limit=message_limit,
                topic_limit=topic_limit,
                priority=priority,
                widget=widget,
            )

    async def queue_scope_batch_in_session(
        self,
        session: AsyncSession,
        key: str,
        target: DiscoveryTarget,
        pages: tuple[str, ...],
        *,
        renderer_version: str,
        message_limit: int,
        topic_limit: int,
        priority: int = 10,
        widget: str | None = None,
    ) -> QueuedBatch:
        """Internal atomic writer, not independent Source/audience authorization.

        The producer must close its current remote observation before entering
        this transaction. Delivery independently authorizes again. This helper
        performs only local SQL and never opens/commits another transaction.
        """
        target, checksum = self._scope_plan(
            key, target, pages, renderer_version, message_limit, topic_limit, priority
        )
        source_key = self.scope_key(key, target.source.realm_id)
        await self.destinations.persist_in_session(session, source_key, target)
        parent = await session.scalar(
            select(DeliveryBatch)
            .where(DeliveryBatch.dedupe_key == self.dedupe(key, target))
            .execution_options(populate_existing=True)
        )
        if parent is not None:
            if parent.plan_hash != checksum or parent.priority != priority:
                raise Conflict("discovery_reply_plan_changed")
        else:
            parent = DeliveryBatch(
                id=uid(),
                dedupe_key=self.dedupe(key, target),
                binding_id=None,
                binding_revision=None,
                destination_id=str(target.id),
                plan_hash=checksum,
                renderer_version=renderer_version,
                message_limit=message_limit,
                topic_limit=topic_limit,
                page_count=len(pages),
                priority=priority,
            )
            session.add(parent)
            await session.flush()
            authorization_hash = digest(target.model_dump(mode="json"))
            for index, page in enumerate(pages):
                identity = uid()
                payload = DiscoveryPayload(
                    operation="post",
                    realm_id=target.source.realm_id,
                    channel_id=target.source.channel_id,
                    topic=target.source.topic,
                    bot_user_id=self.bot_user_id,
                    content=with_marker(page, "jtoz:" + identity),
                    marker="jtoz:" + identity,
                    widget=widget if index == len(pages) - 1 else None,
                    authorization_id=target.id,
                    authorization_hash=authorization_hash,
                ).model_dump(mode="json")
                session.add(
                    Delivery(
                        id=identity,
                        dedupe_key=f"discovery-page:{parent.id}:{index}",
                        binding_id=None,
                        binding_revision=None,
                        destination_id=str(target.id),
                        payload=payload,
                        payload_hash=digest(payload),
                        priority=priority,
                        batch_id=parent.id,
                        batch_index=index,
                    )
                )
            await session.flush()
        result = await self.validated_scope_batch_in_session(session, target, parent)
        # Recheck even on cache hit and after every page flush. Any late lease,
        # grant, enrollment, expiry or bound-topic change rolls the producer's
        # entire transaction back, including its receipt/tokens and all pages.
        await self.destinations.persist_in_session(session, source_key, target)
        return result

    async def resume(
        self, delivery_id: str, realm: str, actor_id: int, expected_version: int
    ) -> None:
        saved = await self.load(delivery_id)
        if saved.destination_id is None or saved.batch_id is None:
            raise Conflict("discovery_delivery_authorization_missing")
        target = await self.destinations.load(saved.destination_id)
        if (realm, actor_id) != (target.source.realm_id, target.source.author_id):
            raise AccessDenied("discovery_recovery_requires_original_actor")
        await self.scope_batch_by_id(saved.batch_id, target)
        async with self.db.sessions.begin() as session:
            await self.destinations.fence.lock(session)
            scope = (
                select(OutputDestination.id)
                .where(
                    OutputDestination.id == str(target.id),
                    OutputDestination.state == "active",
                    OutputDestination.expires_at > time.time(),
                    OutputDestination.authorization_hash == digest(target.model_dump(mode="json")),
                )
                .exists()
            )
            changed = await session.execute(
                update(Delivery)
                .where(
                    Delivery.id == saved.id,
                    Delivery.destination_id == str(target.id),
                    Delivery.state == "held",
                    Delivery.version == expected_version,
                    Delivery.payload_hash == digest(saved.payload),
                    scope,
                    *self.destinations.guards(target),
                )
                .values(
                    state="pending",
                    version=Delivery.version + 1,
                    retry_at=0,
                    status_reason=None,
                    updated_at=time.time(),
                )
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("discovery_recovery_state_changed")
            session.add(
                AuditEvent(
                    actor=f"{realm}:{actor_id}",
                    event="discovery_delivery_resumed",
                    object_id=saved.id,
                )
            )

    async def validated_scope_batch(
        self, target: DiscoveryTarget, batch: DeliveryBatch
    ) -> QueuedBatch:
        async with self.db.sessions() as session:
            return await self.validated_scope_batch_in_session(session, target, batch)

    async def validated_scope_batch_in_session(
        self, session: AsyncSession, target: DiscoveryTarget, batch: DeliveryBatch
    ) -> QueuedBatch:
        """Verify complete immutable local evidence; does not authorize disclosure."""
        target = output_target(target.model_dump(mode="json"))
        self.destinations.validate_source_kind(target)
        stored = await session.get(OutputDestination, str(target.id), populate_existing=True)
        if stored is None or self.destinations.decode(stored) != target:
            raise Conflict("discovery_reply_authorization_changed")
        current = await session.get(DeliveryBatch, batch.id, populate_existing=True)
        if current is None:
            raise Conflict("discovery_reply_batch_missing")
        batch = current
        if (
            batch.destination_id != str(target.id)
            or batch.binding_id is not None
            or batch.binding_revision is not None
            or not 1 <= batch.page_count <= 100
            or batch.message_limit < 173
            or batch.topic_limit < 1
            or not batch.renderer_version
            or len(batch.renderer_version) > 64
            or not 0 <= batch.priority <= 1000
        ):
            raise Conflict("discovery_reply_batch_scope_changed")
        rows = list(
            (
                await session.scalars(
                    select(Delivery)
                    .where(Delivery.batch_id == batch.id)
                    .order_by(Delivery.batch_index)
                    .limit(101)
                    .execution_options(populate_existing=True)
                )
            ).all()
        )
        if len(rows) != batch.page_count:
            raise Conflict("discovery_reply_batch_incomplete")
        pages = []
        expected_hash = digest(target.model_dump(mode="json"))
        for index, row in enumerate(rows):
            payload = DiscoveryPayload.model_validate(row.payload)
            if (
                (
                    row.binding_id,
                    row.binding_revision,
                    row.destination_id,
                    row.batch_index,
                    row.priority,
                    row.payload_hash,
                    row.dedupe_key,
                )
                != (
                    None,
                    None,
                    str(target.id),
                    index,
                    batch.priority,
                    digest(row.payload),
                    f"discovery-page:{batch.id}:{index}",
                )
                or payload.authorization_id != target.id
                or payload.authorization_hash != expected_hash
                or (
                    payload.realm_id,
                    payload.channel_id,
                    payload.topic,
                    payload.bot_user_id,
                    payload.marker,
                )
                != (
                    target.source.realm_id,
                    target.source.channel_id,
                    target.source.topic,
                    self.bot_user_id,
                    "jtoz:" + row.id,
                )
                or len(payload.content) > batch.message_limit
                or len(payload.topic) > batch.topic_limit
            ):
                raise Conflict("discovery_reply_page_changed")
            page = without_marker(payload.content, "jtoz:" + row.id)
            if page is None:
                raise Conflict("discovery_reply_page_changed")
            pages.append(page)
        if (
            sum(map(len, pages)) > 1000000
            or self.checksum(
                target, tuple(pages), batch.renderer_version, batch.message_limit, batch.topic_limit
            )
            != batch.plan_hash
        ):
            raise Conflict("discovery_reply_manifest_changed")
        return QueuedBatch(batch.id, tuple(row.id for row in rows))


class DiscoveryReplyPublisher:
    def __init__(
        self, outbox: DiscoveryOutbox, *, realm_id: str, message_limit: int, topic_limit: int
    ) -> None:
        if (
            not realm_id
            or type(message_limit) is not int
            or message_limit < 173
            or type(topic_limit) is not int
            or topic_limit < 1
        ):
            raise ValueError("verified_discovery_reply_contract_required")
        self.outbox, self.realm_id, self.message_limit, self.topic_limit = (
            outbox,
            realm_id,
            message_limit,
            topic_limit,
        )
        self.tr = Translator()

    async def publish(
        self,
        key: str,
        target: DiscoveryTarget,
        text: str,
        locale: Locale = "en",
        *,
        widget: str | None = None,
    ) -> QueuedBatch:
        if target.source.realm_id != self.realm_id or not text:
            raise Conflict("discovery_reply_realm_or_content_invalid")
        cached = await self.outbox.cached_scope_batch(key, target)
        if cached is not None:
            return cached
        header = self.tr.page_prefix(locale, 100, 100)
        footer = MARKER_FOOTER_SIZE
        rendered = MobileMarkdown(locale=locale).render(
            text, self.message_limit, reserved_characters=footer + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise ValueError("discovery_reply_requires_authorized_full_output")
        pages = (
            tuple(rendered.pages)
            if len(rendered.pages) == 1
            else tuple(
                self.tr.page_prefix(locale, index, len(rendered.pages)) + page
                for index, page in enumerate(rendered.pages, 1)
            )
        )
        return await self.outbox.queue_scope_batch(
            key,
            target,
            pages,
            renderer_version="discovery-mobile-markdown-v2",
            message_limit=self.message_limit,
            topic_limit=self.topic_limit,
            priority=10,
            widget=widget,
        )
