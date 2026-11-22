"""Coalesced scoped drafts, with independent full replies and terminal notifications."""

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import case, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from jt_oz_bridge.adapters.opencode.live_text import VisibleTextSnapshot
from jt_oz_bridge.adapters.opencode.transcript import TranscriptEntry
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.delivery import without_marker
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.presentation.markdown import MobileMarkdown, sanitize_controls
from jt_oz_bridge.security.redaction import RedactionError, redact_live_text, redact_text
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.draft_records import (
    RENDERER,
    DraftCandidate,
    DraftFrame,
    DraftMode,
    DraftPlan,
    DraftRow,
    candidate_for_batch,
    candidate_row,
    read_candidate,
    read_frame,
    read_plan,
    write_frame,
)
from jt_oz_bridge.services.live_draft_sources import read_joined_capture
from jt_oz_bridge.services.outbox import OutboundPayload
from jt_oz_bridge.services.routed_output import FOOTER_SIZE, RoutedOutbox
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_records import (
    TranscriptSnapshot,
    TranscriptState,
    incomplete,
    read_snapshot,
    read_stream,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.live_models import TranscriptLiveDraftPublication
from jt_oz_bridge.storage.models import AuditEvent, Delivery, DeliveryBatch
from jt_oz_bridge.storage.transcript_models import (
    TranscriptDraft,
    TranscriptDraftPublication,
    TranscriptMessage,
    TranscriptPublication,
    TranscriptStream,
    TranscriptVersion,
)

ACTIVE = {ExecutionState.RUNNING, ExecutionState.WAITING_INPUT, ExecutionState.WAITING_PERMISSION}


@dataclass
class Source:
    row: DraftRow
    candidate: DraftCandidate
    source: TranscriptVersion
    snapshot: TranscriptSnapshot
    target: TranscriptMessage
    binding: Binding
    state: TranscriptState
    frame_row: TranscriptDraft | None
    frame: DraftFrame | None
    live: VisibleTextSnapshot | None
    current_body: TranscriptSnapshot
    latest_live_revision: int


class TranscriptDraftPublisher:
    def __init__(
        self,
        collector: TranscriptCollector,
        replies: RoutedOutbox,
        formatter: Callable[[TranscriptEntry, Locale], str],
        *,
        minimum_interval: float = 1,
        interval_resolver: Callable[[AsyncSession], Awaitable[float]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            replies.outbox.bindings is not collector.bindings
            or replies.outbox.fence != collector.fence
        ):
            raise ValueError("draft_scope_and_fence_required")
        if replies.message_limit < 512:
            raise ValueError("native_draft_message_contract_too_small")
        import math

        if not math.isfinite(minimum_interval) or minimum_interval <= 0:
            raise ValueError("draft_interval_must_be_positive_finite")
        self.collector, self.replies, self.outbox, self.db, self.fence = (
            collector,
            replies,
            replies.outbox,
            collector.db,
            collector.fence,
        )
        self.interval_resolver = interval_resolver
        self.formatter, self.minimum_interval, self.clock, self.tr = (
            formatter,
            minimum_interval,
            clock,
            Translator(),
        )

    async def next_pending(self) -> str | None:
        source_record = aliased(TranscriptMessage)
        async with self.db.sessions() as session:
            result = await session.scalar(
                select(TranscriptDraftPublication.id)
                .join(
                    TranscriptVersion,
                    TranscriptVersion.id == TranscriptDraftPublication.source_version_id,
                )
                .join(source_record, source_record.id == TranscriptVersion.record_id)
                .join(
                    TranscriptStream, TranscriptStream.key == TranscriptDraftPublication.scope_key
                )
                .join(Binding, Binding.id == TranscriptStream.binding_id)
                .where(
                    TranscriptDraftPublication.state == "pending",
                    TranscriptDraftPublication.retry_at <= self.clock(),
                    Binding.state == "active",
                    Binding.realm_id == self.replies.realm_id,
                    Binding.revision == TranscriptStream.binding_revision,
                )
                .order_by(
                    case(
                        (TranscriptVersion.record_id != TranscriptDraftPublication.record_id, 0),
                        else_=1,
                    ),
                    source_record.ordinal.desc(),
                    TranscriptVersion.version.desc(),
                    TranscriptDraftPublication.id,
                )
                .limit(1)
            )
            if result is None:
                live = TranscriptLiveDraftPublication
                latest = (
                    select(
                        live.record_id,
                        live.connection_epoch,
                        func.max(live.observation_revision).label("latest"),
                    )
                    .where(live.state == "pending")
                    .group_by(live.record_id, live.connection_epoch)
                    .subquery()
                )
                sent = (
                    select(live.record_id, func.max(Delivery.updated_at).label("last_sent"))
                    .join(Delivery, Delivery.batch_id == live.batch_id)
                    .where(Delivery.state == "delivered")
                    .group_by(live.record_id)
                    .subquery()
                )
                result = await session.scalar(
                    select(live.id)
                    .join(
                        latest,
                        (latest.c.record_id == live.record_id)
                        & (latest.c.connection_epoch == live.connection_epoch)
                        & (latest.c.latest == live.observation_revision),
                    )
                    .outerjoin(sent, sent.c.record_id == live.record_id)
                    .join(TranscriptStream, TranscriptStream.key == live.scope_key)
                    .join(Binding, Binding.id == TranscriptStream.binding_id)
                    .where(
                        live.state == "pending",
                        live.retry_at <= self.clock(),
                        Binding.state == "active",
                        Binding.realm_id == self.replies.realm_id,
                        Binding.revision == TranscriptStream.binding_revision,
                    )
                    .order_by(
                        func.coalesce(sent.c.last_sent, 0),
                        live.observation_revision.desc(),
                        live.id,
                    )
                    .limit(1)
                )
        return str(result) if result is not None else None

    async def defer(self, identity: str, seconds: float) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            row = await candidate_row(session, identity)
            stream = await session.get(TranscriptStream, row.scope_key) if row else None
            binding = await session.get(Binding, stream.binding_id) if stream else None
            if (
                row
                and binding
                and binding.realm_id == self.replies.realm_id
                and row.state == "pending"
            ):
                row.retry_at = self.clock() + max(1, seconds)

    async def load(self, session: AsyncSession, identity: str) -> Source:
        row = await candidate_row(session, identity)
        source = await session.get(TranscriptVersion, row.source_version_id) if row else None
        target = await session.get(TranscriptMessage, row.record_id) if row else None
        source_record = await session.get(TranscriptMessage, source.record_id) if source else None
        stream = await session.get(TranscriptStream, row.scope_key) if row else None
        binding = await session.get(Binding, stream.binding_id) if stream else None
        if (
            row is None
            or source is None
            or target is None
            or source_record is None
            or stream is None
            or binding is None
        ):
            raise Conflict("draft_source_missing")
        if binding.realm_id != self.replies.realm_id or binding.state != "active":
            raise Conflict("draft_binding_scope_changed")
        state = read_stream(stream, binding)
        snapshot = read_snapshot(source, source_record, state)
        candidate = read_candidate(row, source)
        if candidate.scope_key != state.key or target.scope_key != state.key:
            raise Conflict("draft_candidate_reference_changed")
        frame_row = await session.get(TranscriptDraft, target.id)
        frame = read_frame(frame_row, target, binding, state) if frame_row else None
        if frame and frame.bot_user_id != self.outbox.bot_user_id:
            raise Conflict("draft_bot_identity_changed")
        if snapshot.observation.entry.kind not in {"assistant", "idle"}:
            raise Conflict("draft_source_kind_not_qualified")
        if snapshot.observation.entry.kind == "assistant" and source.record_id != target.id:
            raise Conflict("draft_assistant_record_changed")
        if snapshot.observation.entry.kind == "idle" and (
            frame is None
            or frame.terminal_version_id != source.id
            or source_record.ordinal <= target.ordinal
        ):
            raise Conflict("draft_terminal_reference_changed")
        current_row = await session.scalar(
            select(TranscriptVersion).where(
                TranscriptVersion.record_id == target.id,
                TranscriptVersion.version == target.current_version,
            )
        )
        if current_row is None:
            raise Conflict("draft_current_body_missing")
        current_body = read_snapshot(current_row, target, state)
        live = (
            await read_joined_capture(session, row, candidate, snapshot)
            if candidate.live_capture_id
            else None
        )
        latest_live = (
            await session.scalar(
                select(func.max(TranscriptLiveDraftPublication.observation_revision)).where(
                    TranscriptLiveDraftPublication.record_id == target.id,
                    TranscriptLiveDraftPublication.connection_epoch == live.connection_epoch,
                )
            )
            if live
            else 0
        )
        return Source(
            row,
            candidate,
            source,
            snapshot,
            target,
            binding,
            state,
            frame_row,
            frame,
            live,
            current_body,
            int(latest_live or 0),
        )

    def quick_mode(self, source: Source) -> DraftMode | None:
        entry = source.snapshot.observation.entry
        if entry.kind == "assistant":
            if source.live is not None:
                if (
                    source.live.connection_epoch != source.state.connection_epoch
                    or source.live.observation_revision < source.latest_live_revision
                    or not incomplete(source.current_body.observation.entry)
                    or source.frame is not None
                    and source.frame.last_live_connection_epoch == source.live.connection_epoch
                    and source.live.observation_revision
                    <= source.frame.last_live_observation_revision
                ):
                    return "superseded"
            elif source.source.version < source.target.current_version:
                return "superseded"
            if not incomplete(entry):
                return "empty"  # Full reply is still handled by the main transcript publisher.
            if (
                source.target.ordinal <= source.state.latest_idle_ordinal
                or source.state.native_state not in ACTIVE
            ):
                return "superseded"
            if source.frame and (
                source.frame.finalized or source.frame.terminal_version_id is not None
            ):
                return "superseded"
            if source.live is not None:
                return None if source.live.text.strip() else "empty"
            raw = entry.projection()
            if not any(
                part["type"] == "tool" or (part["type"] == "text" and part["text"].strip())
                for part in raw["content"]
            ):
                return "empty"
        elif source.frame is None or source.frame.finalized:
            return "empty"
        return None

    def locale(self, source: Source) -> Locale:
        value = source.frame.locale if source.frame else source.binding.locale
        if value not in {"en", "zh-TW"}:
            raise Conflict("draft_locale_not_qualified")
        return cast(Locale, value)

    def plan(self, source: Source, mode: DraftMode, **changes: Any) -> DraftPlan:
        frame = source.frame
        return DraftPlan(
            candidate_id=source.row.id,
            source_version_id=source.source.id,
            source_hash=source.source.payload_hash,
            record_id=source.target.id,
            scope_key=source.state.key,
            binding_id=source.binding.id,
            binding_revision=source.binding.revision,
            reference=reference(source.binding),
            bot_user_id=self.outbox.bot_user_id,
            mode=mode,
            live_capture_id=source.candidate.live_capture_id,
            live_capture_hash=source.candidate.live_capture_hash,
            live_header_hash=digest(source.candidate.live_header.model_dump(mode="json"))
            if source.candidate.live_header
            else None,
            locale=self.locale(source),
            message_limit=frame.message_limit if frame else self.replies.message_limit,
            topic_limit=frame.topic_limit if frame else self.replies.topic_limit,
            **changes,
        )

    def settle(self, source: Source, plan: DraftPlan) -> None:
        source.row.state = "settled"
        source.row.batch_id = plan.batch_id
        source.row.plan = plan.model_dump(mode="json")
        source.row.plan_hash = digest(source.row.plan)

    def render(
        self,
        body: TranscriptSnapshot,
        terminal: TranscriptSnapshot | None,
        locale: Locale,
        message_limit: int,
        live: VisibleTextSnapshot | None = None,
    ) -> str:
        header = (
            self.tr.render("draft.running", locale)
            if terminal is None
            else self.tr.render(
                "draft.closed",
                locale,
                outcome=self.tr.render(
                    "transcript.outcome." + terminal.observation.entry.projection()["outcome"],
                    locale,
                ),
            )
        )
        if live is not None:
            header += "\n" + self.tr.render("draft.capture", locale)
        footer = self.tr.render("draft.preview", locale)
        if body.recovering or (terminal and terminal.recovering):
            header += "\n" + self.tr.render("mirror.recovered", locale)
        note = ""
        try:
            text, _ = sanitize_controls(
                live.text if live is not None else self.formatter(body.observation.entry, locale)
            )
            text, redactions = redact_live_text(text) if live is not None else redact_text(text)
            note = self.tr.render("native.redacted", locale) if redactions else ""
            rendered = MobileMarkdown(locale=locale).render(
                text,
                message_limit,
                reserved_characters=FOOTER_SIZE + len(header) + len(footer) + len(note) + 12,
            )
        except (ValueError, RedactionError):
            rendered = MobileMarkdown(locale=locale).render(
                self.tr.render("transcript.unpreviewable", locale),
                message_limit,
                reserved_characters=FOOTER_SIZE + len(header) + len(footer) + 12,
            )
        if not rendered.pages:
            raise Conflict("draft_preview_empty")
        return (
            header + "\n\n" + rendered.pages[0] + "\n\n" + footer + ("\n\n" + note if note else "")
        )

    async def previous(self, session: AsyncSession, source: Source) -> Delivery | None:
        frame = source.frame
        if frame is None:
            return None
        delivery = await session.get(Delivery, frame.last_delivery_id)
        parent = await candidate_row(session, frame.last_candidate_id)
        version = await session.get(TranscriptVersion, parent.source_version_id) if parent else None
        if delivery is None or parent is None or version is None:
            raise Conflict("draft_previous_plan_missing")
        candidate = read_candidate(parent, version)
        plan = read_plan(parent, candidate)
        if (
            parent.record_id,
            parent.scope_key,
            parent.batch_id,
            delivery.batch_id,
            plan.body_hash,
        ) != (
            source.target.id,
            source.state.key,
            frame.last_batch_id,
            frame.last_batch_id,
            frame.body_hash,
        ) or delivery.payload_hash != digest(delivery.payload):
            raise Conflict("draft_previous_lineage_changed")
        body = without_marker(delivery.payload["content"], "jtoz:" + delivery.id)
        if digest({"body": body}) != frame.body_hash:
            raise Conflict("draft_previous_body_changed")
        return delivery

    async def cached(self, source: Source, plan: DraftPlan) -> str | None:
        if (plan.binding_id, plan.binding_revision, plan.reference, plan.bot_user_id) != (
            source.binding.id,
            source.binding.revision,
            reference(source.binding),
            self.outbox.bot_user_id,
        ):
            raise Conflict("draft_cached_scope_changed")
        if plan.batch_id:
            await self.outbox.batch_by_id(plan.batch_id, source.binding.id, source.binding.revision)
        return plan.batch_id

    async def rebase_unsent_edit(
        self, session: AsyncSession, source: Source, previous: Delivery
    ) -> Delivery:
        payload = OutboundPayload.model_validate(previous.payload)
        if payload.operation != "edit" or payload.target_delivery_id is None:
            raise Conflict("draft_rebase_requires_unsent_edit")
        parent = await session.get(Delivery, payload.target_delivery_id)
        if (
            parent is None
            or parent.batch_id is None
            or source.frame is None
            or source.frame_row is None
        ):
            raise Conflict("draft_rebase_parent_missing")
        target = await self.outbox.edit_source(session, source.binding, parent.id)
        if (
            target is None
            or target.target_message_id != payload.target_message_id
            or target.previous_content_hash != payload.previous_content_hash
        ):
            raise Conflict("draft_rebase_verified_parent_changed")
        row = await candidate_for_batch(session, parent.batch_id)
        version = await session.get(TranscriptVersion, row.source_version_id) if row else None
        if row is None or version is None:
            raise Conflict("draft_rebase_parent_plan_missing")
        plan = read_plan(row, read_candidate(row, version))
        if (row.record_id, row.scope_key) != (
            source.target.id,
            source.state.key,
        ) or plan.body_hash is None:
            raise Conflict("draft_rebase_parent_scope_changed")
        source.frame = source.frame.model_copy(
            update={
                "last_candidate_id": row.id,
                "last_batch_id": parent.batch_id,
                "last_delivery_id": parent.id,
                "body_hash": plan.body_hash,
            }
        )
        write_frame(source.frame_row, source.frame)
        return parent

    async def publish(self, identity: str) -> str | None:
        async with self.db.sessions() as session:
            source = await self.load(session, identity)
        if source.row.state == "settled":
            return await self.cached(source, read_plan(source.row, source.candidate))
        potential_output = self.quick_mode(source) is None and source.state.status == "live"
        if potential_output:
            await self.collector.preflight(source.binding)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.collector.bindings, session, source.binding)
            source = await self.load(session, identity)
            if source.row.state == "settled":
                plan = read_plan(source.row, source.candidate)
            elif source.state.status != "live" or source.state.bootstrap_plan is None:
                source.row.retry_at = self.clock() + 1
                return None
            elif (quick := self.quick_mode(source)) is not None:
                plan = self.plan(source, quick)
                self.settle(source, plan)
            else:
                if not potential_output:
                    source.row.retry_at = self.clock() + 0.1
                    return None  # A changed decision needs a new current private-scope check.
                earlier = await session.scalar(
                    select(TranscriptVersion.id)
                    .join(TranscriptMessage, TranscriptMessage.id == TranscriptVersion.record_id)
                    .outerjoin(
                        TranscriptPublication,
                        TranscriptPublication.version_id == TranscriptVersion.id,
                    )
                    .where(
                        TranscriptMessage.scope_key == source.state.key,
                        TranscriptMessage.ordinal < source.target.ordinal,
                        TranscriptPublication.version_id.is_(None),
                    )
                    .limit(1)
                )
                if earlier:
                    source.row.retry_at = self.clock() + 0.1
                    return None
                terminal = source.snapshot.observation.entry.kind == "idle"
                previous = await self.previous(session, source)
                frame = source.frame
                minimum_interval = (
                    await self.interval_resolver(session)
                    if self.interval_resolver is not None
                    else max(self.minimum_interval, frame.minimum_interval if frame else 0)
                )
                import math

                if not math.isfinite(minimum_interval) or minimum_interval <= 0:
                    raise Conflict("invalid_effective_draft_interval")
                if (
                    previous
                    and terminal
                    and (
                        previous.state == "pending"
                        or previous.state == "held"
                        and previous.attempts == 0
                        and previous.posted_message_id is None
                    )
                    and OutboundPayload.model_validate(previous.payload).operation == "edit"
                ):
                    result = await session.execute(
                        update(Delivery)
                        .where(
                            Delivery.id == previous.id,
                            Delivery.state == previous.state,
                            Delivery.version == previous.version,
                        )
                        .values(
                            state="cancelled",
                            version=Delivery.version + 1,
                            status_reason="draft_edit_superseded_by_terminal",
                            updated_at=self.clock(),
                        )
                    )
                    if result.rowcount != 1:  # type: ignore[attr-defined]
                        raise Conflict("draft_edit_cancellation_raced")
                    session.add(
                        AuditEvent(
                            actor="system",
                            event="draft_unsent_edit_cancelled",
                            object_id=previous.id,
                        )
                    )
                    previous = await self.rebase_unsent_edit(session, source, previous)
                    frame = source.frame
                if (
                    previous
                    and terminal
                    and (
                        previous.state == "pending"
                        or previous.state == "held"
                        and previous.attempts == 0
                        and previous.posted_message_id is None
                    )
                ):
                    result = await session.execute(
                        update(Delivery)
                        .where(
                            Delivery.id == previous.id,
                            Delivery.state == previous.state,
                            Delivery.version == previous.version,
                        )
                        .values(
                            state="cancelled",
                            version=Delivery.version + 1,
                            status_reason="draft_superseded_by_terminal",
                            updated_at=self.clock(),
                        )
                    )
                    if result.rowcount != 1:  # type: ignore[attr-defined]
                        raise Conflict("draft_cancellation_raced")
                    assert frame is not None and source.frame_row is not None
                    write_frame(source.frame_row, frame.model_copy(update={"finalized": True}))
                    session.add(
                        AuditEvent(
                            actor="system", event="draft_unsent_cancelled", object_id=previous.id
                        )
                    )
                    plan = self.plan(source, "cancelled_unsent")
                    self.settle(source, plan)
                elif previous and previous.state not in {
                    "delivered",
                    "pending",
                    "sending",
                    "ambiguous",
                    "held",
                }:
                    plan = self.plan(source, "unresolved")
                    self.settle(source, plan)
                    if terminal and frame is not None and source.frame_row is not None:
                        write_frame(source.frame_row, frame.model_copy(update={"finalized": True}))
                elif previous and previous.state != "delivered":
                    source.row.retry_at = self.clock() + 1
                    return None
                elif previous and previous.updated_at + minimum_interval > self.clock():
                    source.row.retry_at = previous.updated_at + minimum_interval
                    return None
                else:
                    body_row = await session.scalar(
                        select(TranscriptVersion).where(
                            TranscriptVersion.record_id == source.target.id,
                            TranscriptVersion.version == source.target.current_version,
                        )
                    )
                    if body_row is None:
                        raise Conflict("draft_current_body_missing")
                    body = read_snapshot(body_row, source.target, source.state)
                    if body.observation.entry.kind != "assistant":
                        raise Conflict("draft_body_not_assistant")
                    locale = self.locale(source)
                    limit = frame.message_limit if frame else self.replies.message_limit
                    if source.live is not None:
                        await read_joined_capture(session, source.row, source.candidate, body)
                    text = self.render(
                        body, source.snapshot if terminal else None, locale, limit, source.live
                    )
                    body_hash = digest({"body": text})
                    if frame and frame.body_hash == body_hash and not terminal:
                        plan = self.plan(source, "unchanged")
                        self.settle(source, plan)
                    else:
                        after = frame.last_batch_id if frame else source.state.last_batch_id
                        edit_of = previous.id if previous else None
                        queued = await self.outbox.queue_batch_in_session(
                            session,
                            "draft:" + source.row.id,
                            source.binding,
                            (text,),
                            renderer_version=RENDERER,
                            message_limit=limit,
                            topic_limit=frame.topic_limit if frame else self.replies.topic_limit,
                            priority=90 if terminal else 250,
                            after_batch_id=after,
                            edit_of=edit_of,
                        )
                        batch = await session.get(DeliveryBatch, queued.id)
                        if batch is None:
                            raise Conflict("draft_batch_missing")
                        plan = self.plan(
                            source,
                            "finalize" if terminal else "draft",
                            batch_id=queued.id,
                            batch_plan_hash=batch.plan_hash,
                            after_batch_id=after,
                            edit_of=edit_of,
                            body_version_id=body_row.id,
                            body_source_hash=body_row.payload_hash,
                            body_hash=body_hash,
                        )
                        self.settle(source, plan)
                        if frame is None:
                            frame = DraftFrame(
                                record_id=source.target.id,
                                scope_key=source.state.key,
                                binding_id=source.binding.id,
                                binding_revision=source.binding.revision,
                                reference=reference(source.binding),
                                native_id=source.target.native_id,
                                bot_user_id=self.outbox.bot_user_id,
                                locale=locale,
                                message_limit=limit,
                                topic_limit=self.replies.topic_limit,
                                minimum_interval=minimum_interval,
                                last_candidate_id=source.row.id,
                                last_batch_id=queued.id,
                                last_delivery_id=queued.deliveries[0],
                                body_hash=body_hash,
                                last_live_connection_epoch=source.live.connection_epoch
                                if source.live
                                else None,
                                last_live_observation_revision=source.live.observation_revision
                                if source.live
                                else 0,
                            )
                            source.frame_row = TranscriptDraft(
                                record_id=source.target.id, scope_key=source.state.key
                            )
                            session.add(source.frame_row)
                        else:
                            frame = frame.model_copy(
                                update={
                                    "minimum_interval": minimum_interval,
                                    "last_candidate_id": source.row.id,
                                    "last_batch_id": queued.id,
                                    "last_delivery_id": queued.deliveries[0],
                                    "body_hash": body_hash,
                                    "finalized": terminal,
                                    **(
                                        {
                                            "last_live_connection_epoch": source.live.connection_epoch,
                                            "last_live_observation_revision": source.live.observation_revision,
                                        }
                                        if source.live
                                        else {}
                                    ),
                                }
                            )
                        assert source.frame_row is not None
                        write_frame(source.frame_row, frame)
        return await self.cached(source, plan)
