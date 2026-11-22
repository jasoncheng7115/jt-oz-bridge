"""Sealed draft lineage and proposals; archived observations are not action authority."""

from typing import Literal
from uuid import uuid4

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.transcript import NativeTranscriptPage, TranscriptEntry
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.delivery import without_marker
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.transcript_records import (
    TranscriptSnapshot,
    TranscriptState,
    incomplete,
    read_snapshot,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.live_models import TranscriptLiveDraftPublication
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch
from jt_oz_bridge.storage.transcript_models import (
    TranscriptDraft,
    TranscriptDraftPublication,
    TranscriptMessage,
    TranscriptVersion,
)

RENDERER: Literal["native-transcript-draft-v2"] = "native-transcript-draft-v2"

type DraftRow = TranscriptDraftPublication | TranscriptLiveDraftPublication


def header_core(entry: TranscriptEntry) -> str:
    value = entry.projection()
    return digest(
        {
            "native_id": entry.native_id,
            "kind": entry.kind,
            "agent": value["agent"],
            "model": value["model"],
            "created": value["time"]["created"],
        }
    )


class LiveDraftHeader(ControlModel):
    """Small facts from a real qualified page; restored facts grant no authority."""

    format: Literal["live-draft-original-header-v1"] = "live-draft-original-header-v1"
    reference: SessionRef
    contract_sha256: str
    owner_epoch: str
    connection_epoch: str
    native_id: str
    core_sha256: str
    projection_sha256: str
    resource_fence: str
    session_info_sha256: str
    state: ExecutionState
    observed_at: float
    expires_at: float

    @classmethod
    def capture(cls, page: NativeTranscriptPage, index: int) -> "LiveDraftHeader":
        entry = page.entries[index]
        if entry.kind != "assistant" or not incomplete(entry):
            raise Conflict("live_draft_header_must_be_incomplete_assistant")
        return cls(
            reference=page.reference,
            contract_sha256=page.contract_sha256,
            owner_epoch=page.owner_epoch,
            connection_epoch=page.connection_epoch,
            native_id=entry.native_id,
            core_sha256=header_core(entry),
            projection_sha256=entry.projection_sha256,
            resource_fence=page.resource_fence,
            session_info_sha256=page.session_info_sha256,
            state=page.state,
            observed_at=page.observed_at,
            expires_at=page.expires_at,
        )


class DraftCandidate(ControlModel):
    format: Literal["native-draft-candidate-v1"] = "native-draft-candidate-v1"
    id: str
    source_version_id: str
    source_hash: str
    record_id: str
    scope_key: str
    live_capture_id: str | None = None
    live_capture_hash: str | None = None
    live_header: LiveDraftHeader | None = None


class DraftFrame(ControlModel):
    format: Literal["native-draft-frame-v1"] = "native-draft-frame-v1"
    record_id: str
    scope_key: str
    binding_id: str
    binding_revision: int
    reference: SessionRef
    native_id: str
    bot_user_id: int
    locale: Literal["en", "zh-TW"]
    message_limit: int
    topic_limit: int
    minimum_interval: float = Field(gt=0, allow_inf_nan=False)
    last_candidate_id: str
    last_batch_id: str
    last_delivery_id: str
    body_hash: str
    finalized: bool = False
    terminal_version_id: str | None = None
    last_live_connection_epoch: str | None = None
    last_live_observation_revision: int = 0


type DraftMode = Literal[
    "draft", "finalize", "empty", "superseded", "unchanged", "cancelled_unsent", "unresolved"
]


class DraftPlan(ControlModel):
    format: Literal["native-draft-plan-v1"] = "native-draft-plan-v1"
    candidate_id: str
    source_version_id: str
    source_hash: str
    record_id: str
    scope_key: str
    binding_id: str
    binding_revision: int
    reference: SessionRef
    bot_user_id: int
    mode: DraftMode
    batch_id: str | None = None
    batch_plan_hash: str | None = None
    after_batch_id: str | None = None
    edit_of: str | None = None
    body_version_id: str | None = None
    body_source_hash: str | None = None
    body_hash: str | None = None
    live_capture_id: str | None = None
    live_capture_hash: str | None = None
    live_header_hash: str | None = None
    renderer: Literal["native-transcript-draft-v2"] = RENDERER
    locale: Literal["en", "zh-TW"]
    message_limit: int
    topic_limit: int


def propose(
    session: AsyncSession, value: TranscriptSnapshot, source_hash: str, record_id: str
) -> None:
    candidate = DraftCandidate(
        id=str(uuid4()),
        source_version_id=value.id,
        source_hash=source_hash,
        record_id=record_id,
        scope_key=value.scope_key,
    )
    payload = candidate.model_dump(mode="json")
    session.add(
        TranscriptDraftPublication(
            id=candidate.id,
            source_version_id=value.id,
            record_id=record_id,
            scope_key=value.scope_key,
            state="pending",
            retry_at=0,
            batch_id=None,
            candidate=payload,
            candidate_hash=digest(payload),
            plan=None,
            plan_hash=None,
        )
    )


def read_candidate(row: DraftRow, source: TranscriptVersion) -> DraftCandidate:
    if digest(row.candidate) != row.candidate_hash:
        raise Conflict("draft_candidate_seal_changed")
    value = DraftCandidate.model_validate(row.candidate)
    if (value.id, value.source_version_id, value.source_hash, value.record_id, value.scope_key) != (
        row.id,
        row.source_version_id,
        source.payload_hash,
        row.record_id,
        row.scope_key,
    ) or source.id != row.source_version_id:
        raise Conflict("draft_candidate_scope_changed")
    if row.state not in {"pending", "settled"} or (row.state == "pending") != (row.plan is None):
        raise Conflict("draft_candidate_state_changed")
    if isinstance(row, TranscriptLiveDraftPublication):
        if (
            value.live_capture_id != row.live_capture_id
            or value.live_capture_hash is None
            or value.live_header is None
        ):
            raise Conflict("draft_candidate_live_source_changed")
    elif (
        value.live_capture_id is not None
        or value.live_capture_hash is not None
        or value.live_header is not None
    ):
        raise Conflict("draft_candidate_unexpected_live_source")
    return value


def read_frame(
    row: TranscriptDraft, record: TranscriptMessage, binding: Binding, state: TranscriptState
) -> DraftFrame:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("draft_frame_seal_changed")
    value = DraftFrame.model_validate(row.payload)
    if (
        value.record_id,
        value.scope_key,
        value.binding_id,
        value.binding_revision,
        value.reference,
        value.native_id,
        value.finalized,
        value.terminal_version_id,
    ) != (
        record.id,
        state.key,
        binding.id,
        binding.revision,
        reference(binding),
        record.native_id,
        row.finalized,
        row.terminal_version_id,
    ) or (row.record_id, row.scope_key) != (record.id, state.key):
        raise Conflict("draft_frame_scope_changed")
    return value


def write_frame(row: TranscriptDraft, frame: DraftFrame) -> None:
    row.finalized = frame.finalized
    row.terminal_version_id = frame.terminal_version_id
    row.payload = frame.model_dump(mode="json")
    row.payload_hash = digest(row.payload)


def read_plan(row: DraftRow, candidate: DraftCandidate) -> DraftPlan:
    if row.state != "settled" or row.plan is None or digest(row.plan) != row.plan_hash:
        raise Conflict("draft_plan_seal_changed")
    plan = DraftPlan.model_validate(row.plan)
    if (
        plan.candidate_id,
        plan.source_version_id,
        plan.source_hash,
        plan.record_id,
        plan.scope_key,
        plan.batch_id,
    ) != (
        candidate.id,
        candidate.source_version_id,
        candidate.source_hash,
        candidate.record_id,
        candidate.scope_key,
        row.batch_id,
    ):
        raise Conflict("draft_plan_source_changed")
    if (plan.mode in {"draft", "finalize"}) != (plan.batch_id is not None):
        raise Conflict("draft_plan_output_state_changed")
    if (plan.live_capture_id, plan.live_capture_hash) != (
        candidate.live_capture_id,
        candidate.live_capture_hash,
    ):
        raise Conflict("draft_plan_live_source_changed")
    if plan.live_header_hash != (
        digest(candidate.live_header.model_dump(mode="json")) if candidate.live_header else None
    ):
        raise Conflict("draft_plan_live_header_changed")
    return plan


async def candidate_row(session: AsyncSession, identity: str) -> DraftRow | None:
    normal = await session.get(TranscriptDraftPublication, identity)
    live = await session.get(TranscriptLiveDraftPublication, identity)
    if normal is not None and live is not None:
        raise Conflict("draft_candidate_identity_collision")
    return normal if normal is not None else live


async def candidate_for_batch(session: AsyncSession, batch_id: str) -> DraftRow | None:
    normal = await session.scalar(
        select(TranscriptDraftPublication).where(TranscriptDraftPublication.batch_id == batch_id)
    )
    live = await session.scalar(
        select(TranscriptLiveDraftPublication).where(
            TranscriptLiveDraftPublication.batch_id == batch_id
        )
    )
    if normal is not None and live is not None:
        raise Conflict("draft_batch_source_identity_collision")
    return normal if normal is not None else live


async def validate_draft_batch(
    session: AsyncSession,
    batch_id: str,
    binding: Binding,
    bot_user_id: int,
    before_batch_id: str | None,
) -> None:
    from jt_oz_bridge.services.outbox import OutboundPayload
    from jt_oz_bridge.services.transcript_records import read_stream, scope_key
    from jt_oz_bridge.storage.transcript_models import TranscriptStream

    batch = await session.get(DeliveryBatch, batch_id)
    row: DraftRow | None = await session.scalar(
        select(TranscriptDraftPublication).where(TranscriptDraftPublication.batch_id == batch_id)
    )
    live_row = await session.scalar(
        select(TranscriptLiveDraftPublication).where(
            TranscriptLiveDraftPublication.batch_id == batch_id
        )
    )
    if row is not None and live_row is not None:
        raise Conflict("draft_batch_source_identity_collision")
    selected: DraftRow | None = row if row is not None else live_row
    row = selected
    if batch is None or (batch.renderer_version != RENDERER and row is None):
        return
    if row is None:
        raise Conflict("draft_batch_source_missing")
    source = await session.get(TranscriptVersion, row.source_version_id)
    source_record = await session.get(TranscriptMessage, source.record_id) if source else None
    target = await session.get(TranscriptMessage, row.record_id)
    stream = await session.get(TranscriptStream, scope_key(binding))
    frame_row = await session.get(TranscriptDraft, row.record_id)
    if (
        source is None
        or source_record is None
        or target is None
        or stream is None
        or frame_row is None
    ):
        raise Conflict("draft_batch_scope_missing")
    state = read_stream(stream, binding)
    snapshot = read_snapshot(source, source_record, state)
    frame = read_frame(frame_row, target, binding, state)
    candidate = read_candidate(row, source)
    plan = read_plan(row, candidate)
    if (
        (
            plan.binding_id,
            plan.binding_revision,
            plan.reference,
            plan.scope_key,
            plan.bot_user_id,
            plan.batch_id,
            plan.batch_plan_hash,
            plan.after_batch_id,
            plan.renderer,
            plan.message_limit,
            plan.topic_limit,
            plan.locale,
        )
        != (
            binding.id,
            binding.revision,
            reference(binding),
            state.key,
            bot_user_id,
            batch.id,
            batch.plan_hash,
            before_batch_id,
            batch.renderer_version,
            batch.message_limit,
            batch.topic_limit,
            frame.locale,
        )
        or frame.bot_user_id != bot_user_id
        or (plan.message_limit, plan.topic_limit) != (frame.message_limit, frame.topic_limit)
    ):
        raise Conflict("draft_batch_plan_scope_changed")
    if plan.mode == "draft" and (
        snapshot.record_id != target.id
        or snapshot.observation.entry.kind != "assistant"
        or not incomplete(snapshot.observation.entry)
        or snapshot.observation.state
        not in {
            ExecutionState.RUNNING,
            ExecutionState.WAITING_INPUT,
            ExecutionState.WAITING_PERMISSION,
        }
    ):
        raise Conflict("draft_batch_not_original_assistant")
    if plan.mode == "finalize" and (
        snapshot.observation.entry.kind != "idle"
        or frame.terminal_version_id != source.id
        or source_record.ordinal <= target.ordinal
    ):
        raise Conflict("draft_batch_not_original_terminal")
    body = (
        await session.get(TranscriptVersion, plan.body_version_id) if plan.body_version_id else None
    )
    if body is None or body.record_id != target.id or body.payload_hash != plan.body_source_hash:
        raise Conflict("draft_body_source_changed")
    body_snapshot = read_snapshot(body, target, state)
    if body_snapshot.observation.entry.kind != "assistant":
        raise Conflict("draft_body_not_original_assistant")
    if candidate.live_capture_id is not None:
        from jt_oz_bridge.services.live_draft_sources import read_joined_capture

        live = await read_joined_capture(session, row, candidate, snapshot)
        await read_joined_capture(session, row, candidate, body_snapshot)
        if plan.mode != "draft" or live.id != plan.live_capture_id:
            raise Conflict("draft_live_body_source_changed")
    deliveries = (
        await session.scalars(select(Delivery).where(Delivery.batch_id == batch_id))
    ).all()
    if len(deliveries) != 1 or batch.page_count != 1:
        raise Conflict("draft_requires_single_page")
    payload = OutboundPayload.model_validate(deliveries[0].payload)
    if (
        payload.operation != ("edit" if plan.edit_of else "post")
        or payload.target_delivery_id != plan.edit_of
    ):
        raise Conflict("draft_edit_lineage_changed")
    if (
        digest({"body": without_marker(payload.content, "jtoz:" + deliveries[0].id)})
        != plan.body_hash
    ):
        raise Conflict("draft_body_projection_changed")
    if plan.mode == "draft" and deliveries[0].state == "pending":
        current = await session.scalar(
            select(TranscriptVersion).where(
                TranscriptVersion.record_id == target.id,
                TranscriptVersion.version == target.current_version,
            )
        )
        if (
            state.status != "live"
            or state.native_state
            not in {
                ExecutionState.RUNNING,
                ExecutionState.WAITING_INPUT,
                ExecutionState.WAITING_PERMISSION,
            }
            or target.ordinal <= state.latest_idle_ordinal
            or frame.terminal_version_id is not None
            or frame.finalized
            or current is None
            or not incomplete(read_snapshot(current, target, state).observation.entry)
            or candidate.live_capture_id is not None
            and live.connection_epoch != state.connection_epoch
        ):
            raise Conflict("draft_no_longer_active_before_send")
