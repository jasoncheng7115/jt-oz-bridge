"""Durable scoped resource scans. No Human or native Action is manufactured."""

from collections.abc import Mapping
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.transcript import (
    NativeTranscriptPage,
    TranscriptReader,
    same_message,
)
from jt_oz_bridge.adapters.opencode.transport import TransportError
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.draft_records import propose, read_frame, write_frame
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.transcript_records import (
    TranscriptObservation,
    TranscriptScan,
    TranscriptSnapshot,
    TranscriptState,
    incomplete,
    read_snapshot,
    read_stream,
    scope_key,
    write_stream,
)
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent
from jt_oz_bridge.storage.transcript_models import (
    TranscriptCandidate,
    TranscriptDraft,
    TranscriptDraftPublication,
    TranscriptMessage,
    TranscriptStream,
    TranscriptVersion,
)


class TranscriptCollector:
    def __init__(
        self,
        bindings: BindingService,
        readers: Mapping[SessionRef, TranscriptReader],
        fence: ConsumerFence,
        *,
        drafts_enabled: bool = False,
    ) -> None:
        self.bindings, self.db, self.fence = bindings, bindings.db, fence
        self.readers = readonly_enrollment(readers)
        self.drafts_enabled = drafts_enabled

    async def load(self, binding: Binding) -> tuple[TranscriptState | None, str | None]:
        async with self.db.sessions() as session:
            row = await session.get(TranscriptStream, scope_key(binding))
        return (read_stream(row, binding), row.payload_hash) if row else (None, None)

    async def preflight(self, binding: Binding) -> None:
        if reference(binding) not in self.readers:
            raise Conflict("transcript_reference_not_enrolled")
        await self.bindings.enrolled(reference(binding), binding.realm_id)
        await self.bindings.audience_for_output(binding)

    async def origin(
        self, session: AsyncSession, binding: Binding, observation: TranscriptObservation
    ) -> str | None:
        entry = observation.entry
        if entry.kind != "user":
            return None
        candidates = (
            await session.scalars(
                select(Action).where(
                    Action.binding_id == binding.id,
                    Action.binding_revision == binding.revision,
                    Action.operation == "prompt",
                    Action.owner == "opencode",
                    Action.upstream_id == entry.native_id,
                )
            )
        ).all()
        found = []
        value = entry.projection()
        for action in candidates:
            receipt = native_receipt(action)
            if receipt is None or receipt.admission.status != "admitted":
                continue
            source = HumanMessage.model_validate(action.payload.get("source"))
            if (
                receipt.reference == reference(binding)
                and not source.is_bot
                and not source.deleted
                and (source.realm_id, source.channel_id, source.topic)
                == (binding.realm_id, binding.channel_id, binding.topic)
                and source.author_id == action.actor_id
                and action.payload.get("text") == value["text"]
                and not value.get("attachments_present")
            ):
                found.append(action.id)
        if len(found) > 1:
            raise Conflict("transcript_origin_is_not_unique")
        return found[0] if found else None

    async def upsert(
        self,
        session: AsyncSession,
        binding: Binding,
        state: TranscriptState,
        observation: TranscriptObservation,
        *,
        historical: bool,
        recovering: bool,
        allow_new: bool,
        ordinal: int,
        context: str | None,
    ) -> tuple[str | None, int, str | None, bool]:
        entry = observation.entry
        record = await session.scalar(
            select(TranscriptMessage).where(
                TranscriptMessage.scope_key == state.key,
                TranscriptMessage.native_id == entry.native_id,
            )
        )
        previous = None
        if record is not None:
            old = await session.scalar(
                select(TranscriptVersion).where(
                    TranscriptVersion.record_id == record.id,
                    TranscriptVersion.version == record.current_version,
                )
            )
            if old is None:
                raise Conflict("transcript_current_version_missing")
            previous = read_snapshot(old, record, state)
            if record.current_hash != old.payload_hash:
                raise Conflict("transcript_message_current_hash_changed")
            if same_message(previous.observation.entry, entry):
                seed = (
                    self.drafts_enabled
                    and incomplete(entry)
                    and entry.kind == "assistant"
                    and observation.state
                    in {
                        ExecutionState.RUNNING,
                        ExecutionState.WAITING_INPUT,
                        ExecutionState.WAITING_PERMISSION,
                    }
                    and (
                        previous.observation.connection_epoch != observation.connection_epoch
                        or await session.scalar(
                            select(TranscriptDraftPublication.id)
                            .where(TranscriptDraftPublication.record_id == record.id)
                            .limit(1)
                        )
                        is None
                    )
                )
                if not seed:
                    return None, ordinal, context, True
        elif not allow_new:
            return None, ordinal, context, False
        else:
            ordinal += 1
            record = TranscriptMessage(
                id=str(uuid4()),
                scope_key=state.key,
                native_id=entry.native_id,
                ordinal=ordinal,
                current_version=0,
                current_hash="",
            )
            session.add(record)
            await session.flush()
        origin = await self.origin(session, binding, observation)
        if previous is None:
            if entry.kind == "user":
                context = origin
            elif entry.kind in {"synthetic", "system", "skill", "compaction", "location-switched"}:
                context = None
            selected_context = context
            if entry.kind == "idle":
                context = None
        else:
            selected_context = previous.context_action_id
        value = TranscriptSnapshot(
            format="native-transcript-snapshot-v2"
            if state.owner_transitions
            else "native-transcript-snapshot-v1",
            owner_generation=len(state.owner_transitions) if state.owner_transitions else None,
            id=str(uuid4()),
            record_id=record.id,
            scope_key=state.key,
            own_ordinal=record.ordinal,
            version=record.current_version + 1,
            observation=observation,
            historical=historical,
            recovering=recovering,
            source_action_id=origin,
            context_action_id=selected_context,
        )
        payload = value.model_dump(mode="json")
        checksum = digest(payload)
        session.add(
            TranscriptVersion(
                id=value.id,
                record_id=record.id,
                version=value.version,
                source_action_id=origin,
                context_action_id=selected_context,
                payload=payload,
                payload_hash=checksum,
            )
        )
        record.current_version = value.version
        record.current_hash = checksum
        if self.drafts_enabled:
            await session.flush()
            if entry.kind == "assistant" and (
                not historical
                or (
                    incomplete(entry)
                    and observation.state
                    in {
                        ExecutionState.RUNNING,
                        ExecutionState.WAITING_INPUT,
                        ExecutionState.WAITING_PERMISSION,
                    }
                )
            ):
                propose(session, value, checksum, record.id)
            elif entry.kind == "idle" and not historical:
                frames = (
                    await session.scalars(
                        select(TranscriptDraft).where(
                            TranscriptDraft.scope_key == state.key,
                            TranscriptDraft.finalized.is_(False),
                            TranscriptDraft.terminal_version_id.is_(None),
                        )
                    )
                ).all()
                for frame_row in frames:
                    target = await session.get(TranscriptMessage, frame_row.record_id)
                    if target is None or target.ordinal >= record.ordinal:
                        raise Conflict("draft_terminal_order_changed")
                    frame = read_frame(frame_row, target, binding, state)
                    write_frame(
                        frame_row, frame.model_copy(update={"terminal_version_id": value.id})
                    )
                    propose(session, value, checksum, target.id)
        return value.id, ordinal, context, True

    async def initialize(
        self, session: AsyncSession, binding: Binding, page: NativeTranscriptPage
    ) -> TranscriptState:
        state = TranscriptState(
            key=scope_key(binding),
            binding_id=binding.id,
            binding_revision=binding.revision,
            realm_id=binding.realm_id,
            channel_id=binding.channel_id,
            topic=binding.topic,
            reference=page.reference,
            contract_sha256=page.contract_sha256,
            semantics_sha256=page.semantics_sha256,
            owner_epoch=page.owner_epoch,
            connection_epoch=page.connection_epoch,
            anchor=page.entries[0].native_id if page.entries else None,
            native_state=page.state,
        )
        row = TranscriptStream(
            key=state.key,
            binding_id=binding.id,
            binding_revision=binding.revision,
            payload=state.model_dump(mode="json"),
            payload_hash=digest(state.model_dump(mode="json")),
        )
        session.add(row)
        await session.flush()
        ordinal = int(await session.scalar(select(func.max(TranscriptMessage.ordinal))) or 0)
        versions = []
        open_ids = []
        context = None
        latest_idle = 0
        for index in reversed(range(len(page.entries))):
            observation = TranscriptObservation.capture(page, index)
            identity, ordinal, context, _ = await self.upsert(
                session,
                binding,
                state,
                observation,
                historical=True,
                recovering=False,
                allow_new=True,
                ordinal=ordinal,
                context=context,
            )
            if identity:
                versions.append(identity)
            if incomplete(observation.entry):
                open_ids.append(observation.entry.native_id)
            if observation.entry.kind == "idle":
                latest_idle = ordinal
        state = state.model_copy(
            update={
                "bootstrap_versions": tuple(versions),
                "open_ids": tuple(open_ids),
                "last_input_action_id": context,
                "latest_idle_ordinal": latest_idle,
            }
        )
        state = write_stream(row, state)
        return state

    async def gap(self, binding: Binding, expected: str, reason: str) -> None:
        await self.preflight(binding)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            current = await lock_output_scope(self.bindings, session, binding)
            row = await session.get(TranscriptStream, scope_key(binding), with_for_update=True)
            if row is None or row.payload_hash != expected:
                raise Conflict("transcript_gap_state_changed")
            state = read_stream(row, binding)
            if state.scan:
                await session.execute(
                    delete(TranscriptCandidate).where(TranscriptCandidate.scan_id == state.scan.id)
                )
            state = state.model_copy(
                update={
                    "status": "gap",
                    "scan": None,
                    "gap_reason": reason,
                    "gap_resume_revision": None
                    if current.dispatch_paused
                    else current.queue_revision,
                }
            )
            state = write_stream(row, state)
            current.dispatch_paused = True
            session.add(
                AuditEvent(
                    actor="system",
                    event="transcript.gap",
                    object_id=binding.id,
                )
            )

    async def finalize(
        self,
        session: AsyncSession,
        binding: Binding,
        state: TranscriptState,
        scan: TranscriptScan,
        page: NativeTranscriptPage,
    ) -> TranscriptState:
        rows = (
            await session.scalars(
                select(TranscriptCandidate)
                .where(TranscriptCandidate.scan_id == scan.id)
                .order_by(TranscriptCandidate.offset.desc())
            )
        ).all()
        if len(rows) != scan.offset:
            raise Conflict("transcript_scan_candidates_missing")
        ordinal = int(await session.scalar(select(func.max(TranscriptMessage.ordinal))) or 0)
        context = state.last_input_action_id
        open_ids = set(state.open_ids)
        latest_idle = state.latest_idle_ordinal
        for row in rows:
            if row.scope_key != state.key or digest(row.payload) != row.payload_hash:
                raise Conflict("transcript_candidate_seal_changed")
            envelope = row.payload
            observation = TranscriptObservation.model_validate(envelope["observation"])
            if (
                envelope["scope_key"],
                envelope["scan_id"],
                envelope["offset"],
                observation.entry.native_id,
                observation.reference,
                observation.owner_epoch,
                observation.contract_sha256,
                observation.semantics_sha256,
            ) != (
                state.key,
                scan.id,
                row.offset,
                row.native_id,
                state.reference,
                state.owner_epoch,
                state.contract_sha256,
                state.semantics_sha256,
            ):
                raise Conflict("transcript_candidate_scope_changed")
            _, ordinal, context, tracked = await self.upsert(
                session,
                binding,
                state,
                observation,
                historical=False,
                recovering=scan.recovering,
                allow_new=envelope["new"],
                ordinal=ordinal,
                context=context,
            )
            if tracked and incomplete(observation.entry):
                open_ids.add(row.native_id)
            else:
                open_ids.discard(row.native_id)
            if tracked and observation.entry.kind == "idle":
                own_ordinal = await session.scalar(
                    select(TranscriptMessage.ordinal).where(
                        TranscriptMessage.scope_key == state.key,
                        TranscriptMessage.native_id == row.native_id,
                    )
                )
                if own_ordinal is None:
                    raise Conflict("transcript_terminal_record_missing")
                latest_idle = max(latest_idle, own_ordinal)
        await session.execute(
            delete(TranscriptCandidate).where(TranscriptCandidate.scan_id == scan.id)
        )
        return state.model_copy(
            update={
                "anchor": scan.head_id,
                "open_ids": tuple(sorted(open_ids)),
                "last_input_action_id": context,
                "connection_epoch": page.connection_epoch,
                "scan": None,
                "status": "live",
                "native_state": page.state,
                "latest_idle_ordinal": latest_idle,
            }
        )

    async def collect(self, binding: Binding) -> TranscriptState:
        state, expected = await self.load(binding)
        if state is not None and state.status == "gap":
            return state
        bracketed = self.bindings.supports_read_capture()
        if bracketed:
            if reference(binding) not in self.readers:
                raise Conflict("transcript_reference_not_enrolled")
        else:
            await self.preflight(binding)
        reader = self.readers[reference(binding)]
        cursor = state.scan.cursor if state and state.scan else None
        try:
            if bracketed:
                page = await self.bindings.capture_output(
                    binding, lambda: reader.capture(reference(binding), cursor=cursor, limit=20)
                )
            else:
                page = await reader.capture(reference(binding), cursor=cursor, limit=20)
        except TransportError as error:
            if (
                state
                and expected
                and cursor is not None
                and str(error) == "upstream_rejected_request"
            ):
                await self.gap(binding, expected, "cursor_source_rejected")
            raise
        if (
            page.reference != reference(binding)
            or page.contract_sha256 != self.bindings.control.contract_for(reference(binding))
            or page.cursor != cursor
            or page.limit != 20
            or not reader.current(page)
        ):
            raise Conflict("transcript_capture_scope_changed")
        if state and (state.contract_sha256, state.semantics_sha256, state.owner_epoch) != (
            page.contract_sha256,
            page.semantics_sha256,
            page.owner_epoch,
        ):
            assert expected is not None
            await self.gap(binding, expected, "original_owner_or_semantics_changed")
            raise Conflict("transcript_original_owner_or_semantics_changed")
        if not bracketed:
            await self.preflight(binding)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            current = await lock_output_scope(self.bindings, session, binding)
            row = await session.get(TranscriptStream, scope_key(binding), with_for_update=True)
            if (row.payload_hash if row else None) != expected:
                raise Conflict("transcript_stream_changed_during_capture")
            if not reader.current(page):
                raise Conflict("transcript_witness_expired_before_commit")
            if row is None:
                return await self.initialize(session, binding, page)
            state = read_stream(row, binding)
            scan = state.scan or TranscriptScan(
                id=str(uuid4()),
                anchor=state.anchor,
                remaining_open=state.open_ids,
                recovering=state.connection_epoch != page.connection_epoch,
            )
            remaining = set(scan.remaining_open)
            found = scan.found_anchor
            offset = scan.offset
            total = scan.total_bytes
            head = scan.head_id
            if offset == 0:
                head = page.entries[0].native_id if page.entries else state.anchor
            failure = None
            for index, entry in enumerate(page.entries):
                if entry.native_id == scan.anchor:
                    found = True
                remaining.discard(entry.native_id)
                observation = TranscriptObservation.capture(page, index)
                payload = {
                    "scope_key": state.key,
                    "scan_id": scan.id,
                    "offset": offset,
                    "observation": observation.model_dump(mode="json"),
                    "new": not found,
                }
                total += len(checked_json(payload))
                if offset >= 10000 or total > 16 * 1024 * 1024:
                    failure = "scan_capacity_exceeded"
                    break
                duplicate = await session.get(TranscriptCandidate, (scan.id, entry.native_id))
                if duplicate is not None:
                    failure = "native_page_identity_repeated"
                    break
                session.add(
                    TranscriptCandidate(
                        scan_id=scan.id,
                        native_id=entry.native_id,
                        scope_key=state.key,
                        offset=offset,
                        payload=payload,
                        payload_hash=digest(payload),
                    )
                )
                offset += 1
            if scan.anchor is None and page.next_cursor is None:
                found = True
            complete = found and not remaining
            if not complete and page.next_cursor is None:
                failure = "native_history_anchor_or_open_message_missing"
            cursor_hash = (
                digest({"cursor": page.next_cursor}) if page.next_cursor is not None else None
            )
            if not complete and cursor_hash in scan.cursor_hashes:
                failure = "native_cursor_repeated"
            scan = scan.model_copy(
                update={
                    "head_id": head,
                    "offset": offset,
                    "total_bytes": min(total, 16 * 1024 * 1024),
                    "found_anchor": found,
                    "remaining_open": tuple(sorted(remaining)),
                    "cursor": page.next_cursor,
                    "cursor_hashes": (*scan.cursor_hashes, cursor_hash)
                    if cursor_hash
                    else scan.cursor_hashes,
                    "recovering": scan.recovering
                    or state.connection_epoch != page.connection_epoch,
                }
            )
            if failure:
                await session.execute(
                    delete(TranscriptCandidate).where(TranscriptCandidate.scan_id == scan.id)
                )
                state = state.model_copy(
                    update={
                        "status": "gap",
                        "gap_reason": failure,
                        "scan": None,
                        "gap_resume_revision": None
                        if current.dispatch_paused
                        else current.queue_revision,
                    }
                )
                current.dispatch_paused = True
                session.add(
                    AuditEvent(
                        actor="system",
                        event="transcript.gap",
                        object_id=binding.id,
                    )
                )
            elif complete:
                await session.flush()
                state = await self.finalize(session, binding, state, scan, page)
            else:
                state = state.model_copy(update={"status": "scanning", "scan": scan})
            state = write_stream(row, state)
            return state

    async def require_continuity(self, binding: Binding, *, ready: bool = False) -> None:
        async with self.db.sessions() as session:
            await self._require_continuity_in_session(session, binding, ready=ready)

    async def _require_continuity_in_session(
        self, session: AsyncSession, binding: Binding, *, ready: bool = False
    ) -> None:
        """Same authenticated stream guard, usable in the owned control transaction."""
        row = await session.get(TranscriptStream, scope_key(binding))
        state = read_stream(row, binding) if row is not None else None
        if ready and (state is None or state.status == "scanning"):
            raise Conflict("transcript_context_not_ready")
        if state is not None and state.status == "gap":
            raise Conflict("transcript_gap_requires_review_and_rebind")
