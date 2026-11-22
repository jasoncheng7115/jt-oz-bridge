"""Select exactly one already-authorized output path; never manufacture a binding."""

import time
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE, with_marker
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.domain.routing import RoutedInput
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.policy import ROLES, AccessDenied, Permission
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.discovery_outbox import DiscoveryReplyPublisher
from jt_oz_bridge.services.outbox import OutboundPayload, QueuedBatch, batch_digest
from jt_oz_bridge.services.routed_output import RENDERER_VERSION, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch, Grant
from jt_oz_bridge.storage.output_models import OutputDestination

if TYPE_CHECKING:
    from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue
    from jt_oz_bridge.services.worktree_switch import WorktreeSwitchCommands


class ReplyPublisher:
    def __init__(self, bound: RoutedOutbox, discovery: DiscoveryReplyPublisher) -> None:
        if (
            bound.outbox.db is not discovery.outbox.db
            or bound.realm_id != discovery.realm_id
            or bound.outbox.bot_user_id != discovery.outbox.bot_user_id
        ):
            raise ValueError("reply_publishers_must_share_database_realm_and_bot")
        self.bound, self.discovery = bound, discovery
        self.worktree_switch: WorktreeSwitchCommands | None = None

        self.closed_bound: ClosedBoundQueue | None = None

    async def publish(self, routed: RoutedInput) -> QueuedBatch | None:
        if routed.state == "ignore":
            return None
        if (routed.delivery_key or "").startswith("worktree-command:"):
            if self.worktree_switch is None or routed.queued_batch_id is None:
                raise Conflict("worktree_switch_committed_reply_unavailable")
            return await self.worktree_switch.committed(routed)
        if routed.delivery_key and routed.delivery_key.startswith("bound-local:"):
            if self.closed_bound is None or routed.queued_batch_id is None:
                raise Conflict("closed_bound_committed_publisher_not_configured")
            return await self.closed_bound.committed(routed)
        if routed.queued_batch_id is not None:
            return await self._committed(routed)
        if routed.discovery_target is not None:
            if (
                routed.binding_id is not None
                or routed.binding_revision is not None
                or not routed.delivery_key
            ):
                raise ValueError("reply_cannot_mix_authorization_sources")
            return await self.discovery.publish(
                routed.delivery_key,
                routed.discovery_target,
                routed.text,
                routed.locale,
                widget=routed.widget,
            )
        if routed.binding_id is not None:
            return await self.bound.publish(routed)
        # Duplicate in-progress or unauthorized output has no safe destination.
        # It must never be posted using a guessed session/topic.
        return None

    async def _committed(self, routed: RoutedInput) -> QueuedBatch:
        """Return existing work only; this is neither an ACL proof nor a writer."""
        if routed.binding_id is not None:
            return await self._committed_bound(routed)
        if (
            routed.state != "reply"
            or routed.binding_id is not None
            or routed.binding_revision is not None
            or routed.action_id is not None
            or routed.discovery_target is None
            or not routed.delivery_key
            or not routed.delivery_key.startswith("command:")
            or not isinstance(routed.text, str)
            or not 0 < len(routed.text) <= 1000000
        ):
            raise Conflict("committed_discovery_reply_scope_invalid")
        identity = routed.delivery_key.removeprefix("command:")
        if (
            str(UUID(identity)) != identity
            or str(UUID(routed.queued_batch_id or "")) != routed.queued_batch_id
        ):
            raise Conflict("committed_discovery_reply_identity_invalid")
        target = DiscoveryTarget.model_validate(routed.discovery_target.model_dump(mode="json"))
        if target.source.realm_id != self.discovery.realm_id:
            raise Conflict("committed_discovery_reply_realm_changed")
        outbox, publisher = self.discovery.outbox, self.discovery
        header = publisher.tr.page_prefix(routed.locale, 100, 100)
        rendered = MobileMarkdown(locale=routed.locale).render(
            routed.text,
            publisher.message_limit,
            reserved_characters=len(header) + MARKER_FOOTER_SIZE,
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("committed_discovery_reply_page_count_changed")
        pages = tuple(
            publisher.tr.page_prefix(routed.locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )
        expected_plan = outbox.checksum(
            target,
            pages,
            "discovery-mobile-markdown-v2",
            publisher.message_limit,
            publisher.topic_limit,
        )
        async with outbox.db.sessions.begin() as session:
            await outbox.destinations.fence.lock(session)
            parent = await self._committed_evidence(
                session, routed, target, identity, expected_plan
            )
            result = await outbox.validated_scope_batch_in_session(session, target, parent)
            # Re-read local evidence and current authority after the last-page
            # read. This never creates a target, batch, receipt, or delivery.
            await outbox.destinations.fence.lock(session)
            await self._committed_evidence(session, routed, target, identity, expected_plan)
            return result

    async def _committed_evidence(
        self,
        session: AsyncSession,
        routed: RoutedInput,
        target: DiscoveryTarget,
        identity: str,
        expected_plan: str,
    ) -> DeliveryBatch:
        from jt_oz_bridge.services.unbound_router import SavedDiscoveryReply

        outbox, publisher = self.discovery.outbox, self.discovery
        outbox.destinations.validate_source_kind(target)
        receipt = await session.scalar(
            select(CommandReceipt)
            .where(CommandReceipt.id == identity)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if receipt is None:
            raise Conflict("committed_discovery_reply_receipt_missing")
        saved = SavedDiscoveryReply.model_validate(receipt.response)
        source = target.source
        if (
            receipt.state != "completed"
            or receipt.binding_id is not None
            or receipt.binding_revision is not None
            or (
                receipt.realm_id,
                receipt.message_id,
                receipt.actor_id,
                receipt.channel_id,
                receipt.topic,
                receipt.source_revision,
                receipt.source_hash,
            )
            != (
                source.realm_id,
                source.message_id,
                source.author_id,
                source.channel_id,
                source.topic,
                source.revision,
                digest(source.model_dump(mode="json")),
            )
            or saved.origin != "discovery"
            or saved.target != target
            or saved.text != routed.text
            or saved.locale != routed.locale
            or saved.queued_batch_id != routed.queued_batch_id
            or saved.binding_id is not None
            or saved.binding_revision is not None
        ):
            raise Conflict("committed_discovery_reply_receipt_changed")
        destination = await session.scalar(
            select(OutputDestination)
            .where(OutputDestination.id == str(target.id))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            destination is None
            or destination.dedupe_key
            != outbox.scope_key(routed.delivery_key or "", source.realm_id)
            or outbox.destinations.decode(destination) != target
        ):
            raise Conflict("committed_discovery_reply_destination_changed")
        parent = await session.scalar(
            select(DeliveryBatch)
            .where(DeliveryBatch.id == routed.queued_batch_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            parent is None
            or parent.dedupe_key != outbox.dedupe(routed.delivery_key or "", target)
            or parent.destination_id != str(target.id)
            or parent.renderer_version != "discovery-mobile-markdown-v2"
            or parent.message_limit != publisher.message_limit
            or parent.topic_limit != publisher.topic_limit
            or parent.priority != 10
            or parent.plan_hash != expected_plan
        ):
            raise Conflict("committed_discovery_reply_batch_changed")
        if saved.shortcuts is not None and saved.shortcuts.confirm is not None:
            if not target.projects:
                raise Conflict("committed_discovery_preview_project_missing")
            for project in target.projects:
                roles = await session.scalars(
                    select(Grant.role).where(
                        Grant.realm_id == source.realm_id,
                        Grant.project_id == project.scope.project_id,
                        Grant.user_id == source.author_id,
                        Grant.active.is_(True),
                    )
                )
                if not any(Permission.OPERATE in ROLES.get(role, set()) for role in roles):
                    raise AccessDenied("committed_discovery_preview_operate_revoked")
        if not await session.scalar(select(and_(*outbox.destinations.guards(target)))):
            raise AccessDenied("committed_discovery_reply_local_authority_changed")
        if target.expires_at <= time.time() or target.issued_at > time.time() + 5:
            raise Conflict("committed_discovery_reply_expired")
        return parent

    async def _committed_bound(self, routed: RoutedInput) -> QueuedBatch:
        """Validate an already committed original-binding ACK without requeueing."""
        from jt_oz_bridge.services.unbound_router import SavedDiscoveryReply

        outbox, publisher = self.bound.outbox, self.bound
        if (
            routed.state != "reply"
            or routed.binding_id is None
            or routed.binding_revision != 1
            or routed.action_id is not None
            or routed.discovery_target is not None
            or not routed.delivery_key
            or not routed.delivery_key.startswith("command:")
            or not 0 < len(routed.text) <= 1000000
            or outbox.fence is None
        ):
            raise Conflict("committed_binding_reply_scope_invalid")
        identity = routed.delivery_key.removeprefix("command:")
        for value in (identity, routed.binding_id, routed.queued_batch_id):
            if value is None or str(UUID(value)) != value:
                raise Conflict("committed_binding_reply_identity_invalid")
        header = publisher.tr.page_prefix(routed.locale, 100, 100)
        rendered = MobileMarkdown(locale=routed.locale).render(
            routed.text,
            publisher.message_limit,
            reserved_characters=MARKER_FOOTER_SIZE + len(header),
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("committed_binding_reply_output_bounds")
        pages = tuple(
            publisher.tr.page_prefix(routed.locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )
        expected_plan = batch_digest(
            pages, RENDERER_VERSION, publisher.message_limit, publisher.topic_limit
        )
        async with outbox.db.sessions.begin() as session:
            await outbox.fence.lock(session)
            receipt = await session.scalar(
                select(CommandReceipt)
                .where(CommandReceipt.id == identity)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            binding = await session.scalar(
                select(Binding)
                .where(Binding.id == routed.binding_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if receipt is None or binding is None:
                raise Conflict("committed_binding_reply_receipt_missing")
            saved = SavedDiscoveryReply.model_validate(receipt.response)
            source = saved.confirmation_source
            if source is None:
                raise Conflict("committed_binding_reply_original_source_missing")
            parsed = parse_input(source.text)
            if (
                receipt.state != "completed"
                or receipt.command != "confirm"
                or receipt.binding_id is not None
                or receipt.binding_revision is not None
                or source.is_bot
                or source.deleted
                or source.revision != 0
                or parsed.kind != "command"
                or parsed.command != "confirm"
                or parsed.arguments
                or (
                    receipt.realm_id,
                    receipt.message_id,
                    receipt.actor_id,
                    receipt.channel_id,
                    receipt.topic,
                    receipt.source_revision,
                    receipt.source_hash,
                )
                != (
                    source.realm_id,
                    source.message_id,
                    source.author_id,
                    source.channel_id,
                    source.topic,
                    source.revision,
                    digest(source.model_dump(mode="json")),
                )
                or source.realm_id != publisher.realm_id
                or saved.text != routed.text
                or saved.locale != routed.locale
                or saved.binding_id != routed.binding_id
                or saved.binding_revision != routed.binding_revision
                or saved.queued_batch_id != routed.queued_batch_id
                or saved.target is not None
                or saved.shortcuts is not None
                or saved.confirmed_reference != reference(binding)
                or saved.confirmed_title != binding.title
                or (
                    binding.realm_id,
                    binding.anchor_message_id,
                    binding.owner_id,
                    binding.channel_id,
                    binding.topic,
                    binding.revision,
                )
                != (
                    source.realm_id,
                    source.message_id,
                    source.author_id,
                    source.channel_id,
                    source.topic,
                    routed.binding_revision,
                )
            ):
                raise Conflict("committed_binding_reply_receipt_changed")
            await lock_output_scope(outbox.bindings, session, binding)
            roles = await session.scalars(
                select(Grant.role)
                .where(
                    Grant.realm_id == source.realm_id,
                    Grant.project_id == binding.project_id,
                    Grant.user_id == source.author_id,
                    Grant.active.is_(True),
                )
                .with_for_update()
            )
            if not any(Permission.OPERATE in ROLES.get(role, set()) for role in roles):
                raise AccessDenied("committed_binding_reply_operate_revoked")
            parent = await session.scalar(
                select(DeliveryBatch)
                .where(DeliveryBatch.id == routed.queued_batch_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if parent is None or (
                parent.binding_id,
                parent.binding_revision,
                parent.destination_id,
                parent.dedupe_key,
                parent.plan_hash,
                parent.renderer_version,
                parent.message_limit,
                parent.topic_limit,
                parent.page_count,
                parent.priority,
            ) != (
                binding.id,
                binding.revision,
                None,
                "reply-batch:"
                + digest(
                    {
                        "key": routed.delivery_key,
                        "binding": binding.id,
                        "revision": binding.revision,
                    }
                ),
                expected_plan,
                RENDERER_VERSION,
                publisher.message_limit,
                publisher.topic_limit,
                len(pages),
                10,
            ):
                raise Conflict("committed_binding_reply_manifest_changed")
            rows = list(
                (
                    await session.scalars(
                        select(Delivery)
                        .where(Delivery.batch_id == parent.id)
                        .order_by(Delivery.batch_index)
                        .limit(101)
                        .with_for_update()
                        .execution_options(populate_existing=True)
                    )
                ).all()
            )
            if len(rows) != len(pages):
                raise Conflict("committed_binding_reply_incomplete")
            for index, row in enumerate(rows):
                expected = OutboundPayload(
                    operation="post",
                    realm_id=source.realm_id,
                    channel_id=source.channel_id,
                    topic=source.topic,
                    bot_user_id=outbox.bot_user_id,
                    content=with_marker(pages[index], "jtoz:" + row.id),
                    marker="jtoz:" + row.id,
                ).model_dump(mode="json")
                if (
                    row.binding_id,
                    row.binding_revision,
                    row.destination_id,
                    row.batch_index,
                    row.dedupe_key,
                    row.priority,
                    row.payload_hash,
                    row.payload,
                ) != (
                    binding.id,
                    binding.revision,
                    None,
                    index,
                    f"batch:{parent.id}:{index}",
                    10,
                    digest(expected),
                    expected,
                ):
                    raise Conflict("committed_binding_reply_page_changed")
            await lock_output_scope(outbox.bindings, session, binding)
            final_roles = await session.scalars(
                select(Grant.role)
                .where(
                    Grant.realm_id == source.realm_id,
                    Grant.project_id == binding.project_id,
                    Grant.user_id == source.author_id,
                    Grant.active.is_(True),
                )
                .with_for_update()
            )
            if not any(Permission.OPERATE in ROLES.get(role, set()) for role in final_roles):
                raise AccessDenied("committed_binding_reply_operate_revoked")
            await outbox.fence.lock(session)
            return QueuedBatch(parent.id, tuple(row.id for row in rows))
