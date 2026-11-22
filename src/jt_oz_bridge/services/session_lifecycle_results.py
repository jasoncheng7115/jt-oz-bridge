"""One durable notice for each confirmed fork/compact/revert, including an unknown result.

The shared publication table already stores generic action/hash/batch pointers,
so there is no schema change. A notice never claims more than the sealed receipt.
"""

from sqlalchemy import select

from jt_oz_bridge.domain.session_lifecycle import (
    LIFECYCLE_OPERATIONS,
    SessionLifecycleOutcome,
    SessionLifecycleRequest,
)
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.outbox import QueuedBatch
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.publication_models import ModelSettingPublication

RENDERER_VERSION = "session-lifecycle-notice-v1"
NOTICE_STATES = ("completed", "ambiguous")


class SessionLifecycleResultPublisher:
    def __init__(self, replies: RoutedOutbox) -> None:
        self.replies, self.db = replies, replies.outbox.db
        self.tr = Translator()
        for locale in ("en", "zh-TW"):
            header = self.tr.page_prefix(locale, 100, 100)
            if replies.message_limit - FOOTER_SIZE - len(header) < 128:
                raise ValueError("session_lifecycle_notice_render_contract_too_small")

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            found = await session.scalar(
                select(Action.id)
                .join(Binding, Binding.id == Action.binding_id)
                .outerjoin(
                    ModelSettingPublication,
                    ModelSettingPublication.action_id == Action.id,
                )
                .where(
                    Action.operation.in_(sorted(LIFECYCLE_OPERATIONS)),
                    Action.state.in_(NOTICE_STATES),
                    Binding.state == "active",
                    Binding.revision == Action.binding_revision,
                    Binding.realm_id == self.replies.realm_id,
                    ModelSettingPublication.action_id.is_(None),
                )
                .order_by(Action.created_at, Action.id)
                .limit(1)
            )
            return str(found) if found is not None else None

    def _evidence(self, action: Action, binding: Binding) -> tuple[str, str]:
        """(notice text, checksum), from the sealed Action and nothing newer."""
        request = SessionLifecycleRequest.model_validate(action.payload)
        source = request.source
        if (
            action.operation != request.operation
            or action.operation_digest != digest(action.payload)
            or request.reference != reference(binding)
            or (source.realm_id, source.channel_id, source.topic, source.author_id)
            != (binding.realm_id, binding.channel_id, binding.topic, action.actor_id)
        ):
            raise Conflict("session_lifecycle_notice_source_changed")
        locale = request.reply_locale
        if action.state == "ambiguous":
            return (
                self.tr.render("lifecycle.unknown_result", locale),
                digest({"action": action.id, "state": "ambiguous"}),
            )
        receipt = native_receipt(action)
        if (
            action.state != "completed"
            or receipt is None
            or receipt.reference != reference(binding)
            or receipt.admission.status != "completed"
            or receipt.admission.owner != "opencode"
            or receipt.admission.upstream_id is not None
            or receipt.contract_sha256
            != self.replies.outbox.bindings.control.contract_for(reference(binding))
        ):
            raise Conflict("session_lifecycle_positive_native_receipt_required")
        outcome = SessionLifecycleOutcome.model_validate(receipt.admission.details)
        if (
            outcome.operation != request.operation
            or outcome.change != request.change
            or outcome.session_id != reference(binding).upstream_session_id
        ):
            raise Conflict("session_lifecycle_notice_outcome_changed")
        if outcome.operation == "session.fork":
            text = self.tr.render(
                "lifecycle.forked", locale, session_id=visible(str(outcome.new_session_id))
            )
        elif outcome.operation == "session.compact":
            text = self.tr.render("lifecycle.compact_accepted", locale)
        elif outcome.operation == "session.revert.stage":
            text = self.tr.render(
                "lifecycle.revert_staged_files"
                if outcome.change.files
                else "lifecycle.revert_staged",
                locale,
                message=visible(outcome.change.message_preview),
            )
        elif outcome.operation == "session.revert.clear":
            text = self.tr.render("lifecycle.revert_cleared", locale)
        else:
            text = self.tr.render("lifecycle.revert_committed", locale)
        return text, digest(receipt.model_dump(mode="json"))

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if (
            action is None
            or action.operation not in LIFECYCLE_OPERATIONS
            or action.state not in NOTICE_STATES
        ):
            raise Conflict("session_lifecycle_terminal_action_required")
        binding = await self.replies.outbox.target(action.binding_id, action.binding_revision)
        if binding.realm_id != self.replies.realm_id:
            raise Conflict("session_lifecycle_publication_realm_changed")
        text, checksum = self._evidence(action, binding)
        async with self.db.sessions() as session:
            cached = await session.get(ModelSettingPublication, action.id)
        if cached is not None:
            if (cached.binding_id, cached.binding_revision, cached.source_hash) != (
                binding.id,
                binding.revision,
                checksum,
            ):
                raise Conflict("session_lifecycle_publication_source_changed")
            return await self.replies.outbox.batch_by_id(
                cached.batch_id, binding.id, binding.revision
            )
        locale = SessionLifecycleRequest.model_validate(action.payload).reply_locale
        header = self.tr.page_prefix(locale, 100, 100)
        rendered = MobileMarkdown(locale=locale).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("session_lifecycle_notice_size_unavailable")
        pages = tuple(
            self.tr.page_prefix(locale, i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )
        fence = self.replies.outbox.fence
        assert fence is not None
        async with self.db.sessions.begin() as session:
            await fence.lock(session)
            await lock_output_scope(self.replies.outbox.bindings, session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            if (
                current is None
                or (current.state, current.operation) != (action.state, action.operation)
                or current.admission != action.admission
            ):
                raise Conflict("session_lifecycle_state_changed_before_publication")
            planned = await session.get(ModelSettingPublication, action.id)
            if planned is not None:
                if (planned.binding_id, planned.binding_revision, planned.source_hash) != (
                    binding.id,
                    binding.revision,
                    checksum,
                ):
                    raise Conflict("session_lifecycle_publication_source_changed")
                batch_id = planned.batch_id
            else:
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    "session-lifecycle-result:" + action.id,
                    binding,
                    pages,
                    renderer_version=RENDERER_VERSION,
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=10,
                )
                session.add(
                    ModelSettingPublication(
                        action_id=action.id,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                        source_hash=checksum,
                        batch_id=batch.id,
                    )
                )
                batch_id = batch.id
        return await self.replies.outbox.batch_by_id(batch_id, binding.id, binding.revision)
