"""Recoverable setting confirmations from sealed admissions, never fake turns."""

from collections.abc import Set
from typing import cast

from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SCHEMA,
    MODEL_SETTING_SEMANTICS,
)
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment_keys
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.model_catalog import ModelSelection, ModelSettingOutcome
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown
from jt_oz_bridge.security.admin import token_hash
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.menu_shortcuts import expand
from jt_oz_bridge.services.model_commands import visible
from jt_oz_bridge.services.outbox import QueuedBatch
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_records import mirrored_bindings, refuse_transcript_output
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.publication_models import ModelSettingPublication

RENDERER_VERSION = "model-setting-notice-v2"


class ModelSettingPublisher:
    def __init__(
        self, replies: RoutedOutbox, *, excluded_references: Set[SessionRef] = frozenset()
    ) -> None:
        self.replies, self.db = replies, replies.outbox.db
        self.tr = Translator()
        self.excluded_references = readonly_enrollment_keys(excluded_references)
        for locale in ("en", "zh-TW"):
            header = self.tr.page_prefix(locale, 100, 100)
            if replies.message_limit - FOOTER_SIZE - len(header) < 128:
                raise ValueError("model_setting_confirmation_render_contract_too_small")

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
                    Action.operation == "model.switch",
                    Action.state == "completed",
                    Binding.state == "active",
                    Binding.revision == Action.binding_revision,
                    Binding.realm_id == self.replies.realm_id,
                    ~mirrored_bindings(self.excluded_references),
                    ModelSettingPublication.action_id.is_(None),
                )
                .order_by(Action.created_at, Action.id)
                .limit(1)
            )
            return str(found) if found is not None else None

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None or action.operation != "model.switch" or action.state != "completed":
            raise Conflict("model_setting_completed_admission_required")
        binding = await self.replies.outbox.target(action.binding_id, action.binding_revision)
        if reference(binding) in self.excluded_references:
            raise Conflict("output_owned_by_native_transcript")
        async with self.db.sessions() as session:
            await refuse_transcript_output(session, binding)
        if binding.realm_id != self.replies.realm_id:
            raise Conflict("model_setting_publication_realm_changed")
        receipt = native_receipt(action)
        if (
            receipt is None
            or receipt.reference != reference(binding)
            or receipt.admission.status != "completed"
            or receipt.admission.owner != "opencode"
            or receipt.admission.upstream_id is not None
            or receipt.contract_sha256 != MODEL_SETTING_SCHEMA
            or action.payload.get("operation") != "model.switch"
        ):
            raise Conflict("model_setting_positive_native_receipt_required")
        key = "model-setting:" + action.id
        checksum = digest(receipt.model_dump(mode="json"))
        async with self.db.sessions() as session:
            cached = await session.get(ModelSettingPublication, action.id)
        if cached is not None:
            if (cached.binding_id, cached.binding_revision, cached.source_hash) != (
                binding.id,
                binding.revision,
                checksum,
            ):
                raise Conflict("model_setting_publication_source_changed")
            return await self.replies.outbox.batch_by_id(
                cached.batch_id, binding.id, binding.revision
            )
        choice = ModelSelection.model_validate(action.payload.get("selection"))
        outcome = ModelSettingOutcome.model_validate(receipt.admission.details)
        source = HumanMessage.model_validate(action.payload.get("source"))
        parsed = expand(source.text, action.payload.get("shortcut"))
        parts = parsed.arguments.split()
        if (
            source.is_bot
            or source.deleted
            or source.revision != 0
            or (source.realm_id, source.channel_id, source.topic, source.author_id)
            != (binding.realm_id, binding.channel_id, binding.topic, action.actor_id)
            or parsed.kind != "command"
            or parsed.command != choice.origin
            or len(parts) != 1
            or token_hash(parts[0]) != action.payload.get("selection_token_sha256")
            or outcome.target != choice.target
            or outcome.catalog_before_sha256 != choice.catalog_sha256
            or outcome.model_settings_semantics_sha256 != MODEL_SETTING_SEMANTICS
        ):
            raise Conflict("model_setting_confirmation_source_or_outcome_changed")
        locale = action.payload.get("reply_locale", "en")
        if locale not in {"en", "zh-TW"}:
            raise Conflict("model_setting_reply_locale_invalid")
        observed = outcome.observed
        selection = visible(
            observed.provider_id
            + "/"
            + observed.model_id
            + ("#" + observed.variant if observed.variant is not None else "")
        )
        text = self.tr.render("models.applied", cast(Locale, locale), selection=selection)
        header = self.tr.page_prefix(cast(Locale, locale), 100, 100)
        rendered = MobileMarkdown(locale=cast(Locale, locale)).render(
            text, self.replies.message_limit, reserved_characters=FOOTER_SIZE + len(header)
        )
        if not 1 <= len(rendered.pages) <= 100:
            raise Conflict("model_setting_confirmation_size_unavailable")
        pages = tuple(
            self.tr.page_prefix(cast(Locale, locale), i, len(rendered.pages)) + page
            for i, page in enumerate(rendered.pages, 1)
        )
        fence = self.replies.outbox.fence
        assert fence is not None
        async with self.db.sessions.begin() as session:
            await fence.lock(session)
            await lock_output_scope(self.replies.outbox.bindings, session, binding)
            await refuse_transcript_output(session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            current_receipt = native_receipt(current) if current is not None else None
            if (
                current is None
                or current.state != "completed"
                or current.operation != "model.switch"
                or current_receipt is None
                or digest(current_receipt.model_dump(mode="json")) != checksum
            ):
                raise Conflict("model_setting_admission_changed_before_publication")
            planned = await session.get(ModelSettingPublication, action.id)
            if planned is not None:
                if (planned.binding_id, planned.binding_revision, planned.source_hash) != (
                    binding.id,
                    binding.revision,
                    checksum,
                ):
                    raise Conflict("model_setting_publication_source_changed")
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
