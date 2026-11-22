"""Join captured fragments to actual Native headers without inventing history."""

from collections.abc import Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.live_text import VisibleTextSnapshot
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.draft_records import (
    DraftCandidate,
    DraftRow,
    LiveDraftHeader,
    header_core,
)
from jt_oz_bridge.services.live_capture import (
    LiveTextSource,
    read_live_capture,
    validate_capture_receipt,
)
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_collector import TranscriptCollector
from jt_oz_bridge.services.transcript_records import (
    TranscriptSnapshot,
    incomplete,
    read_snapshot,
    read_stream,
    scope_key,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.live_models import NativeLiveCapture, TranscriptLiveDraftPublication
from jt_oz_bridge.storage.transcript_models import (
    TranscriptMessage,
    TranscriptStream,
    TranscriptVersion,
)

ACTIVE = {ExecutionState.RUNNING, ExecutionState.WAITING_INPUT, ExecutionState.WAITING_PERMISSION}


async def read_joined_capture(
    session: AsyncSession, row: DraftRow, candidate: DraftCandidate, header: TranscriptSnapshot
) -> VisibleTextSnapshot:
    if not isinstance(row, TranscriptLiveDraftPublication):
        raise Conflict("live_draft_requires_separate_source_record")
    captured = await session.get(NativeLiveCapture, candidate.live_capture_id)
    if captured is None or captured.payload_hash != candidate.live_capture_hash:
        raise Conflict("live_draft_capture_source_changed")
    value = read_live_capture(captured)
    observation = header.observation
    fresh = candidate.live_header
    if (
        value.reference != observation.reference
        or value.contract_sha256 != observation.contract_sha256
        or value.owner_epoch != observation.owner_epoch
        or value.connection_epoch != observation.connection_epoch
        or value.assistant_id != observation.entry.native_id
        or row.observation_revision != value.observation_revision
        or row.connection_epoch != value.connection_epoch
        or header.record_id != row.record_id
        or observation.entry.kind != "assistant"
        or not incomplete(observation.entry)
        or observation.state not in ACTIVE
        or fresh is None
    ):
        raise Conflict("live_draft_original_header_join_changed")
    assert fresh is not None
    if (
        (
            fresh.reference,
            fresh.contract_sha256,
            fresh.owner_epoch,
            fresh.connection_epoch,
            fresh.native_id,
            "assistant",
        )
        != (
            value.reference,
            value.contract_sha256,
            value.owner_epoch,
            value.connection_epoch,
            value.assistant_id,
            "assistant",
        )
        or fresh.state not in ACTIVE
        or fresh.core_sha256 != header_core(observation.entry)
        or not fresh.observed_at < fresh.expires_at
    ):
        raise Conflict("live_draft_current_header_join_changed")
    await validate_capture_receipt(session, value)
    return value


class LiveDraftCollector:
    def __init__(
        self, collector: TranscriptCollector, sources: Mapping[SessionRef, LiveTextSource]
    ) -> None:
        self.collector, self.db, self.fence = collector, collector.db, collector.fence
        self.sources = readonly_enrollment(sources)
        if not collector.drafts_enabled or not set(sources) <= set(collector.readers):
            raise ValueError("live_drafts_require_enrolled_mirror_sources")

    async def collect(self, binding: Binding) -> int:
        ref = reference(binding)
        source = self.sources.get(ref)
        if source is None:
            return 0
        await self.collector.bindings.enrolled(ref, binding.realm_id)
        identities = await source.available(ref)
        if (
            len(identities) > 128
            or len(set(identities)) != len(identities)
            or any(
                not isinstance(identity, str)
                or len(identity) != 64
                or any(c not in "0123456789abcdef" for c in identity)
                for identity in identities
            )
        ):
            raise Conflict("live_draft_capture_window_invalid")
        if not identities:
            return 0
        # Capture the actual current original page without a chat RPC. The old
        # transcript version stays immutable; the separate header observation
        # records this real API read, never delta text masquerading as history.
        reader = self.collector.readers[ref]
        page = await reader.capture(ref, limit=20)
        if not reader.current(page) or page.state not in ACTIVE:
            return 0
        current_headers = {
            entry.native_id: index
            for index, entry in enumerate(page.entries)
            if entry.kind == "assistant" and incomplete(entry)
        }
        count = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.collector.bindings, session, binding)
            stream = await session.get(TranscriptStream, scope_key(binding))
            if stream is None:
                return 0
            state = read_stream(stream, binding)
            if (
                state.status != "live"
                or state.bootstrap_plan is None
                or state.native_state not in ACTIVE
            ):
                return 0
            for identity in identities:
                if not source.current(ref, identity):
                    continue
                captured = await session.get(NativeLiveCapture, identity)
                if captured is None:
                    raise Conflict("live_draft_current_capture_missing")
                value = read_live_capture(captured)
                if value.reference != ref:
                    raise Conflict("live_draft_reference_changed")
                if not value.text.strip() or (value.owner_epoch, value.connection_epoch) != (
                    state.owner_epoch,
                    state.connection_epoch,
                ):
                    continue
                target = await session.scalar(
                    select(TranscriptMessage).where(
                        TranscriptMessage.scope_key == state.key,
                        TranscriptMessage.native_id == value.assistant_id,
                    )
                )
                if target is None or target.ordinal <= state.latest_idle_ordinal:
                    continue  # The actual mirror must first observe the original header.
                version = await session.scalar(
                    select(TranscriptVersion).where(
                        TranscriptVersion.record_id == target.id,
                        TranscriptVersion.version == target.current_version,
                    )
                )
                if version is None:
                    raise Conflict("live_draft_original_header_missing")
                header = read_snapshot(version, target, state)
                if not incomplete(header.observation.entry):
                    continue
                if value.assistant_id not in current_headers:
                    continue
                fresh_header = LiveDraftHeader.capture(page, current_headers[value.assistant_id])
                found = await session.scalar(
                    select(TranscriptLiveDraftPublication.id).where(
                        TranscriptLiveDraftPublication.live_capture_id == identity,
                        TranscriptLiveDraftPublication.record_id == target.id,
                    )
                )
                if found:
                    continue
                candidate = DraftCandidate(
                    id=str(uuid4()),
                    source_version_id=version.id,
                    source_hash=version.payload_hash,
                    record_id=target.id,
                    scope_key=state.key,
                    live_capture_id=captured.id,
                    live_capture_hash=captured.payload_hash,
                    live_header=fresh_header,
                )
                payload = candidate.model_dump(mode="json")
                row = TranscriptLiveDraftPublication(
                    id=candidate.id,
                    source_version_id=version.id,
                    live_capture_id=captured.id,
                    observation_revision=value.observation_revision,
                    connection_epoch=value.connection_epoch,
                    record_id=target.id,
                    scope_key=state.key,
                    state="pending",
                    retry_at=0,
                    batch_id=None,
                    candidate=payload,
                    candidate_hash=digest(payload),
                    plan=None,
                    plan_hash=None,
                )
                await read_joined_capture(session, row, candidate, header)
                if not source.current(ref, identity) or not reader.current(page):
                    continue
                session.add(row)
                count += 1
            if not reader.current(page):
                raise Conflict("live_draft_original_header_changed_before_commit")
        return count
