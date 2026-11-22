"""Atomic resource-result publications, without fabricated Native log events."""

from collections.abc import Set
from typing import Literal, cast

from sqlalchemy import select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment_keys
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, sanitize_controls
from jt_oz_bridge.security.redaction import RedactionError, redact_text
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.outbox import QueuedBatch
from jt_oz_bridge.services.publication_records import ResourcePublicationPlan
from jt_oz_bridge.services.publication_records import read_resource_publication as publication_plan
from jt_oz_bridge.services.resource_execution_results import (
    ResourceExecutionResult,
    indexed_result,
)
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_records import mirrored_bindings, refuse_transcript_output
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, DeliveryBatch
from jt_oz_bridge.storage.resource_models import ResourcePublication, ResourceResultRecord

RENDERER_VERSION = "resource-final-markdown-v2"


class ResourcePublisher:
    def __init__(
        self, replies: RoutedOutbox, *, excluded_references: Set[SessionRef] = frozenset()
    ) -> None:
        self.replies, self.outbox, self.db = replies, replies.outbox, replies.outbox.db
        self.tr = Translator()
        self.excluded_references = readonly_enrollment_keys(excluded_references)
        # Fail at bootstrap, rather than strand a result on an impossible cap.
        for locale in ("en", "zh-TW"):
            reserve = (
                max(
                    (
                        self.header(outcome, locale)
                        for outcome in ("completed", "failed", "cancelled")
                    ),
                    key=len,
                )
                + "\n\n"
            )
            maximum = self.tr.render("output.page", locale, index=100, total=100)
            if replies.message_limit - FOOTER_SIZE - len(reserve) - len(maximum) < 128:
                raise ValueError("resource_final_render_contract_too_small")

    def header(self, outcome: str, locale: Locale) -> str:
        return self.tr.render("resource." + outcome, locale)

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            result = await session.scalar(
                select(ResourceResultRecord.action_id)
                .join(Binding, Binding.id == ResourceResultRecord.binding_id)
                .outerjoin(
                    ResourcePublication,
                    ResourcePublication.action_id == ResourceResultRecord.action_id,
                )
                .where(
                    ResourcePublication.action_id.is_(None),
                    Binding.state == "active",
                    Binding.revision == ResourceResultRecord.binding_revision,
                    Binding.realm_id == self.replies.realm_id,
                    ~mirrored_bindings(self.excluded_references),
                )
                .order_by(ResourceResultRecord.ordinal)
                .limit(1)
            )
        return str(result) if result is not None else None

    def pages(self, result: ResourceExecutionResult, locale: Locale) -> tuple[str, tuple[str, ...]]:
        header = self.header(result.outcome, locale)
        maximum = self.tr.render("output.page", locale, index=100, total=100)
        state = "queued"
        note = ""
        try:
            text = "\n\n".join(part.text for part in result.evidence.turn.text)
            normalized, _ = sanitize_controls(text)
            text, redactions = redact_text(normalized)
            note = self.tr.render("native.redacted", locale) if redactions else ""
            text = text or self.tr.render("resource.no_text", locale)
            rendered = MobileMarkdown(locale=locale).render(
                text,
                self.replies.message_limit,
                reserved_characters=FOOTER_SIZE + len(header) + len(maximum) + len(note) + 12,
            )
            if not 1 <= len(rendered.pages) <= 100 or sum(map(len, rendered.pages)) > 900000:
                raise ValueError("resource_output_requires_full_transfer")
        except (ValueError, RedactionError):
            state, note = "needs_full_output", ""
            rendered = MobileMarkdown(locale=locale).render(
                self.tr.render("native.full_output", locale),
                self.replies.message_limit,
                reserved_characters=FOOTER_SIZE + len(header) + len(maximum) + 12,
            )
        pages = tuple(
            header
            + "\n\n"
            + self.tr.page_prefix(locale, i, len(rendered.pages))
            + page
            + ("\n\n" + note if note else "")
            for i, page in enumerate(rendered.pages, 1)
        )
        return state, pages

    async def cached(
        self,
        row: ResourcePublication,
        index: ResourceResultRecord,
        result: ResourceExecutionResult,
    ) -> QueuedBatch:
        plan = publication_plan(row)
        if (
            plan.action_id,
            plan.own_result_ordinal,
            plan.source_hash,
            plan.result_sha256,
            plan.binding_id,
            plan.binding_revision,
            plan.realm_id,
            plan.channel_id,
            plan.topic,
            plan.reference,
            plan.outcome,
            plan.bot_user_id,
        ) != (
            result.action_id,
            index.ordinal,
            index.source_hash,
            digest(result.model_dump(mode="json")),
            result.binding_id,
            result.binding_revision,
            result.realm_id,
            result.channel_id,
            result.topic,
            result.reference,
            result.outcome,
            self.outbox.bot_user_id,
        ):
            raise Conflict("resource_publication_source_changed")
        batch = await self.outbox.batch_by_id(
            plan.batch_id, result.binding_id, result.binding_revision
        )
        async with self.db.sessions() as session:
            parent = await session.get(DeliveryBatch, batch.id)
        if parent is None or (
            parent.plan_hash,
            parent.renderer_version,
            parent.message_limit,
            parent.topic_limit,
        ) != (plan.plan_hash, plan.renderer_version, plan.message_limit, plan.topic_limit):
            raise Conflict("resource_publication_batch_plan_changed")
        return batch

    async def publish(self, action_id: str) -> QueuedBatch:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
            index = await session.get(ResourceResultRecord, action_id)
        if action is None or index is None:
            raise Conflict("resource_publication_result_missing")
        result = indexed_result(index, action)
        binding = await self.outbox.target(result.binding_id, result.binding_revision)
        if reference(binding) in self.excluded_references:
            raise Conflict("output_owned_by_native_transcript")
        async with self.db.sessions() as session:
            await refuse_transcript_output(session, binding)
        if (
            result.realm_id != self.replies.realm_id
            or result.reference != reference(binding)
            or (result.realm_id, result.channel_id, result.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
        ):
            raise Conflict("resource_publication_scope_changed")
        async with self.db.sessions() as session:
            existing = await session.get(ResourcePublication, action_id)
        if existing is not None:
            return await self.cached(existing, index, result)
        locale = action.payload.get("reply_locale", binding.locale)
        if locale not in {"en", "zh-TW"}:
            raise Conflict("resource_publication_locale_invalid")
        state, pages = self.pages(result, cast(Locale, locale))
        fence = self.outbox.fence
        assert fence is not None
        async with self.db.sessions.begin() as session:
            await fence.lock(session)
            await lock_output_scope(self.outbox.bindings, session, binding)
            await refuse_transcript_output(session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action_id).with_for_update()
            )
            current_index = await session.get(ResourceResultRecord, action_id)
            if (
                current is None
                or current_index is None
                or indexed_result(current_index, current) != result
                or (current_index.ordinal, current_index.source_hash)
                != (index.ordinal, index.source_hash)
            ):
                raise Conflict("resource_publication_result_changed_before_commit")
            existing = await session.get(ResourcePublication, action_id)
            if existing is None:
                earlier = await session.scalar(
                    select(ResourceResultRecord.action_id)
                    .outerjoin(
                        ResourcePublication,
                        ResourcePublication.action_id == ResourceResultRecord.action_id,
                    )
                    .where(
                        ResourceResultRecord.binding_id == binding.id,
                        ResourceResultRecord.binding_revision == binding.revision,
                        ResourceResultRecord.ordinal < index.ordinal,
                        ResourcePublication.action_id.is_(None),
                    )
                    .limit(1)
                )
                if earlier is not None:
                    raise Conflict("resource_publication_earlier_result_pending")
                previous = await session.scalar(
                    select(ResourcePublication.batch_id)
                    .join(
                        ResourceResultRecord,
                        ResourceResultRecord.action_id == ResourcePublication.action_id,
                    )
                    .where(
                        ResourcePublication.binding_id == binding.id,
                        ResourcePublication.binding_revision == binding.revision,
                        ResourceResultRecord.ordinal < index.ordinal,
                    )
                    .order_by(ResourceResultRecord.ordinal.desc())
                    .limit(1)
                )
                batch = await self.outbox.queue_batch_in_session(
                    session,
                    "resource-result:" + action_id,
                    binding,
                    pages,
                    renderer_version=RENDERER_VERSION,
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    priority=100,
                    after_batch_id=previous,
                )
                parent = await session.get(DeliveryBatch, batch.id)
                if parent is None:
                    raise Conflict("resource_publication_batch_unavailable")
                plan = ResourcePublicationPlan(
                    action_id=action_id,
                    own_result_ordinal=index.ordinal,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    realm_id=binding.realm_id,
                    channel_id=binding.channel_id,
                    topic=binding.topic,
                    reference=result.reference,
                    source_hash=index.source_hash,
                    result_sha256=digest(result.model_dump(mode="json")),
                    outcome=result.outcome,
                    state=cast(Literal["queued", "needs_full_output"], state),
                    batch_id=batch.id,
                    previous_batch_id=previous,
                    plan_hash=parent.plan_hash,
                    bot_user_id=self.outbox.bot_user_id,
                    locale=cast(Locale, locale),
                    message_limit=self.replies.message_limit,
                    topic_limit=self.replies.topic_limit,
                    renderer_version=RENDERER_VERSION,
                )
                payload = plan.model_dump(mode="json")
                existing = ResourcePublication(
                    action_id=action_id,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    source_hash=index.source_hash,
                    batch_id=batch.id,
                    payload=payload,
                    payload_hash=digest(payload),
                )
                session.add(existing)
                await session.flush()
        return await self.cached(existing, index, result)
