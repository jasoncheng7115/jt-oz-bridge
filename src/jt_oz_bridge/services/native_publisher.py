"""Exactly-once local native publication planning; delivery remains one-attempt."""

from dataclasses import dataclass
from typing import Literal, Self, cast

from sqlalchemy import func, select

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.delivery import MARKER_FOOTER_SIZE
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, sanitize_controls
from jt_oz_bridge.security.redaction import redact_text
from jt_oz_bridge.services.native_projection import NativeProjector
from jt_oz_bridge.services.outbox import Outbox, QueuedBatch
from jt_oz_bridge.services.projection_records import ProjectedRecord
from jt_oz_bridge.services.publication_records import NativePublicationPlan, read_publication
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import DeliveryBatch
from jt_oz_bridge.storage.projection_models import (
    NativeLogIndex,
    NativeProjection,
    NativeProjectionRecord,
)
from jt_oz_bridge.storage.publication_models import NativePublication

RENDERER_VERSION = "native-final-markdown-v2"
FOOTER_SIZE = MARKER_FOOTER_SIZE


@dataclass(frozen=True)
class PublicationResult:
    state: Literal["queued", "history", "empty", "recovery", "needs_full_output", "waiting"]
    batch: QueuedBatch | None = None


class NativePublisher:
    def __init__(
        self,
        projector: NativeProjector,
        outbox: Outbox,
        *,
        realm_id: str,
        message_limit: int,
        topic_limit: int,
        recovery_floor: int,
    ) -> None:
        if (
            outbox.bindings is not projector.bindings
            or outbox.fence != projector.fence
            or not realm_id
            or type(message_limit) is not int
            or not 173 <= message_limit <= 1000000
            or type(topic_limit) is not int
            or not 1 <= topic_limit <= 1000000
            or type(recovery_floor) is not int
            or recovery_floor < 0
        ):
            raise ValueError("qualified_native_publication_scope_contract_and_fence_required")
        self.projector, self.outbox, self.db, self.fence = (
            projector,
            outbox,
            outbox.db,
            projector.fence,
        )
        self.realm_id, self.message_limit, self.topic_limit, self.recovery_floor = (
            realm_id,
            message_limit,
            topic_limit,
            recovery_floor,
        )
        self.tr = Translator()

    @classmethod
    async def open(
        cls,
        projector: NativeProjector,
        outbox: Outbox,
        *,
        realm_id: str,
        message_limit: int,
        topic_limit: int,
    ) -> Self:
        if projector.attestation is None:
            raise ValueError("installed_native_publication_semantics_required")
        async with projector.db.sessions.begin() as session:
            await projector.fence.lock(session)
            floor = await session.scalar(select(func.max(NativeLogIndex.ordinal)))
        return cls(
            projector,
            outbox,
            realm_id=realm_id,
            message_limit=message_limit,
            topic_limit=topic_limit,
            recovery_floor=int(floor or 0),
        )

    async def next_pending(self) -> str | None:
        if self.projector.attestation is None:
            return None
        async with self.db.sessions() as session:
            result = await session.scalar(
                select(NativeProjectionRecord.input_event_id)
                .join(NativeProjection, NativeProjection.key == NativeProjectionRecord.scope_key)
                .join(Binding, Binding.id == NativeProjection.binding_id)
                .outerjoin(
                    NativePublication,
                    NativePublication.input_event_id == NativeProjectionRecord.input_event_id,
                )
                .where(
                    NativePublication.input_event_id.is_(None),
                    NativeProjectionRecord.native_type == "session.text.ended",
                    Binding.state == "active",
                    Binding.revision == NativeProjection.binding_revision,
                    Binding.realm_id == self.realm_id,
                    Binding.backend_id == self.projector.attestation.backend_id,
                    Binding.backend_identity == self.projector.attestation.backend_identity,
                )
                .order_by(NativeProjectionRecord.ordinal)
                .limit(1)
            )
        return str(result) if result is not None else None

    def pages(
        self, source: ProjectedRecord, locale: Locale
    ) -> tuple[Literal["queued", "empty", "needs_full_output"], tuple[str, ...]]:
        text = source.change.text
        if text is None:
            raise Conflict("native_publication_source_is_not_text")
        header = self.tr.render("native.reply", locale)
        maximum = self.tr.render("output.page", locale, index=100, total=100)
        try:
            normalized, _ = sanitize_controls(text.text)
            displayed, redactions = redact_text(normalized)
            note = self.tr.render("native.redacted", locale) if redactions else ""
            reserve = FOOTER_SIZE + len(maximum) + len(header) + len(note) + 12
            rendered = MobileMarkdown(locale=locale).render(
                displayed, self.message_limit, reserved_characters=reserve
            )
            if not rendered.pages:
                return "empty", ()
            if len(rendered.pages) > 100:
                raise ValueError("native_output_requires_full_transfer")
            pages = tuple(
                header
                + "\n\n"
                + self.tr.page_prefix(locale, i, len(rendered.pages))
                + page
                + ("\n\n" + note if note else "")
                for i, page in enumerate(rendered.pages, 1)
            )
            if sum(len(page) for page in pages) > 1000000:
                raise ValueError("native_output_requires_full_transfer")
            return "queued", pages
        except ValueError:
            notice = self.tr.render("native.full_output", locale)
            rendered = MobileMarkdown(locale=locale).render(
                notice, self.message_limit, reserved_characters=FOOTER_SIZE + len(maximum) + 4
            )
            return "needs_full_output", tuple(
                self.tr.page_prefix(locale, i, len(rendered.pages)) + page
                for i, page in enumerate(rendered.pages, 1)
            )

    async def source(
        self, input_event_id: str
    ) -> tuple[NativeProjectionRecord, ProjectedRecord, Binding]:
        async with self.db.sessions() as session:
            row = await session.get(NativeProjectionRecord, input_event_id)
            if row is None:
                raise Conflict("native_publication_source_missing")
            source = await self.projector.evidence(session, row)
        if source.change.text is None:
            raise Conflict("native_publication_source_is_not_text")
        binding = await self.projector.preflight(source.event.provenance)
        if binding.realm_id != self.realm_id:
            raise Conflict("native_publication_realm_changed")
        return row, source, binding

    async def cached(
        self, row: NativePublication, source_row: NativeProjectionRecord, source: ProjectedRecord
    ) -> PublicationResult:
        plan = read_publication(row)
        ctx = source.event.provenance
        if (
            plan.input_event_id,
            plan.source_hash,
            plan.ordinal,
            plan.binding_id,
            plan.binding_revision,
            plan.realm_id,
            plan.reference,
            plan.bot_user_id,
        ) != (
            source_row.input_event_id,
            source_row.payload_hash,
            source_row.ordinal,
            ctx.binding_id,
            ctx.binding_revision,
            ctx.realm_id,
            ctx.reference,
            self.outbox.bot_user_id,
        ):
            raise Conflict("native_publication_source_changed")
        if plan.batch_id is None:
            return PublicationResult(plan.state)
        batch = await self.outbox.batch_by_id(plan.batch_id, plan.binding_id, plan.binding_revision)
        async with self.db.sessions() as session:
            parent = await session.get(DeliveryBatch, batch.id)
        if parent is None or (
            parent.plan_hash,
            parent.renderer_version,
            parent.message_limit,
            parent.topic_limit,
        ) != (plan.plan_hash, plan.renderer_version, plan.message_limit, plan.topic_limit):
            raise Conflict("native_publication_plan_changed")
        return PublicationResult(plan.state, batch)

    async def advance(self, input_event_id: str) -> PublicationResult:
        source_row, source, binding = await self.source(input_event_id)
        async with self.db.sessions() as session:
            existing = await session.get(NativePublication, input_event_id)
        if existing is not None:
            return await self.cached(existing, source_row, source)
        text = source.change.text
        if text is None:
            raise Conflict("native_publication_source_is_not_text")
        locale = cast(Locale, binding.locale) if binding.locale in {"en", "zh-TW"} else "en"
        state: Literal["queued", "history", "empty", "recovery", "needs_full_output"]
        pages: tuple[str, ...]
        if text.historical:
            state, pages = "history", ()
        elif source_row.ordinal <= self.recovery_floor:
            state, pages = "recovery", ()
        else:
            state, pages = self.pages(source, locale)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.projector.bindings, session, binding)
            self.projector.qualify(source.event.provenance)
            current = await session.get(NativeProjectionRecord, input_event_id)
            if (
                current is None
                or current.payload_hash != source_row.payload_hash
                or await self.projector.evidence(session, current) != source
            ):
                raise Conflict("native_publication_source_changed_before_commit")
            existing = await session.get(NativePublication, input_event_id)
            if existing is None:
                earlier = await session.scalar(
                    select(NativeProjectionRecord.input_event_id)
                    .join(
                        NativeProjection, NativeProjection.key == NativeProjectionRecord.scope_key
                    )
                    .outerjoin(
                        NativePublication,
                        NativePublication.input_event_id == NativeProjectionRecord.input_event_id,
                    )
                    .where(
                        NativeProjection.binding_id == binding.id,
                        NativeProjection.binding_revision == binding.revision,
                        NativeProjection.source
                        == "v2-log:" + digest(source.event.provenance.reference.model_dump()),
                        NativeProjectionRecord.native_type == "session.text.ended",
                        NativeProjectionRecord.ordinal < source_row.ordinal,
                        NativePublication.input_event_id.is_(None),
                    )
                    .limit(1)
                )
                if earlier is not None:
                    return PublicationResult("waiting")
                previous = None
                batch_id = None
                plan_hash = None
                if pages:
                    previous = await session.scalar(
                        select(NativePublication.batch_id)
                        .where(
                            NativePublication.binding_id == binding.id,
                            NativePublication.binding_revision == binding.revision,
                            NativePublication.ordinal < source_row.ordinal,
                            NativePublication.batch_id.is_not(None),
                        )
                        .order_by(NativePublication.ordinal.desc())
                        .limit(1)
                    )
                    batch = await self.outbox.queue_batch_in_session(
                        session,
                        "native-text:" + input_event_id,
                        binding,
                        pages,
                        renderer_version=RENDERER_VERSION,
                        message_limit=self.message_limit,
                        topic_limit=self.topic_limit,
                        priority=100,
                        after_batch_id=previous,
                    )
                    batch_id = batch.id
                    parent = await session.get(DeliveryBatch, batch_id)
                    if parent is None:
                        raise Conflict("native_publication_batch_unavailable")
                    plan_hash = parent.plan_hash
                plan = NativePublicationPlan(
                    input_event_id=input_event_id,
                    ordinal=source_row.ordinal,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    realm_id=binding.realm_id,
                    reference=source.event.provenance.reference,
                    source_hash=source_row.payload_hash,
                    state=state,
                    batch_id=batch_id,
                    previous_batch_id=previous,
                    plan_hash=plan_hash,
                    bot_user_id=self.outbox.bot_user_id,
                    locale=locale,
                    message_limit=self.message_limit,
                    topic_limit=self.topic_limit,
                    renderer_version=RENDERER_VERSION,
                    recovery_floor=self.recovery_floor,
                )
                payload = plan.model_dump(mode="json")
                existing = NativePublication(
                    input_event_id=input_event_id,
                    ordinal=source_row.ordinal,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    source_hash=source_row.payload_hash,
                    state=state,
                    batch_id=batch_id,
                    previous_batch_id=previous,
                    payload=payload,
                    payload_hash=digest(payload),
                )
                session.add(existing)
                await session.flush()
        return await self.cached(existing, source_row, source)
