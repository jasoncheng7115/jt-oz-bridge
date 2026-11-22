"""Original title readback confirmations, including when Native transcript mirroring is enabled.

The historical model_setting_publications table already stores generic sealed
admission/action/batch pointers; no Native model fields or schema change is needed.
"""

from typing import cast

from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.session_lifecycle import SessionRename, SessionRenameOutcome
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.commands import parse_input
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

RENDERER_VERSION = "session-rename-notice-v1"


class SessionRenamePublisher:
    def __init__(self, replies: RoutedOutbox) -> None:
        self.replies, self.db = replies, replies.outbox.db
        self.tr = Translator()
        for locale in ("en", "zh-TW"):
            header = self.tr.page_prefix(locale, 100, 100)
            if replies.message_limit - FOOTER_SIZE - len(header) < 128:
                raise ValueError("session_rename_confirmation_render_contract_too_small")

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
                    Action.operation == "session.rename",
                    Action.state == "completed",
                    Binding.state == "active",
                    Binding.revision == Action.binding_revision,
                    Binding.realm_id == self.replies.realm_id,
                    ModelSettingPublication.action_id.is_(None),
                )
                .order_by(Action.created_at, Action.id)
                .limit(1)
            )
            return str(found) if found is not None else None

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None or action.operation != "session.rename" or action.state != "completed":
            raise Conflict("session_rename_completed_admission_required")
        binding = await self.replies.outbox.target(action.binding_id, action.binding_revision)
        if binding.realm_id != self.replies.realm_id:
            raise Conflict("session_rename_publication_realm_changed")
        receipt = native_receipt(action)
        if (
            receipt is None
            or receipt.reference != reference(binding)
            or receipt.admission.status != "completed"
            or receipt.admission.owner != "opencode"
            or receipt.admission.upstream_id is not None
            or receipt.contract_sha256
            != self.replies.outbox.bindings.control.contract_for(reference(binding))
            or action.payload.get("operation") != "session.rename"
        ):
            raise Conflict("session_rename_positive_native_receipt_required")
        key = "session-rename-result:" + action.id
        checksum = digest(receipt.model_dump(mode="json"))
        async with self.db.sessions() as session:
            cached = await session.get(ModelSettingPublication, action.id)
        if cached is not None:
            if (cached.binding_id, cached.binding_revision, cached.source_hash) != (
                binding.id,
                binding.revision,
                checksum,
            ):
                raise Conflict("session_rename_publication_source_changed")
            return await self.replies.outbox.batch_by_id(
                cached.batch_id, binding.id, binding.revision
            )
        change = SessionRename.model_validate(action.payload.get("change"))
        outcome = SessionRenameOutcome.model_validate(receipt.admission.details)
        source = HumanMessage.model_validate(action.payload.get("source"))
        parsed = parse_input(source.text, bound=True)
        if (
            source.is_bot
            or source.deleted
            or source.revision != 0
            or (source.realm_id, source.channel_id, source.topic, source.author_id)
            != (binding.realm_id, binding.channel_id, binding.topic, action.actor_id)
            or parsed.kind != "command"
            or parsed.command != "rename"
            or parsed.arguments.strip() != change.target_title
            or outcome.change != change
        ):
            raise Conflict("session_rename_confirmation_source_or_outcome_changed")
        locale = action.payload.get("reply_locale", "en")
        if locale not in {"en", "zh-TW"}:
            raise Conflict("session_rename_reply_locale_invalid")
        text = self.tr.render(
            "lifecycle.renamed",
            cast(Locale, locale),
            title=visible(outcome.observed_title),
        )
        header = self.tr.page_prefix(cast(Locale, locale), 100, 100)
        rendered = MobileMarkdown(locale=cast(Locale, locale)).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("session_rename_confirmation_size_unavailable")
        pages = tuple(
            self.tr.page_prefix(cast(Locale, locale), i, len(rendered.pages)) + page
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
            current_receipt = native_receipt(current) if current is not None else None
            if (
                current is None
                or current.state != "completed"
                or current.operation != "session.rename"
                or current_receipt is None
                or digest(current_receipt.model_dump(mode="json")) != checksum
            ):
                raise Conflict("session_rename_admission_changed_before_publication")
            planned = await session.get(ModelSettingPublication, action.id)
            if planned is not None:
                if (planned.binding_id, planned.binding_revision, planned.source_hash) != (
                    binding.id,
                    binding.revision,
                    checksum,
                ):
                    raise Conflict("session_rename_publication_source_changed")
                batch_id = planned.batch_id
            else:
                batch = await self.replies.outbox.queue_batch_in_session(
                    session,
                    key,
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
