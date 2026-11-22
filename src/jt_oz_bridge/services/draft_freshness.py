"""Actual original-page witnesses for unsent previews; never restored SQL facts."""

from collections.abc import Callable, Mapping

from jt_oz_bridge.adapters.opencode.transcript import TranscriptReader
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.draft_records import (
    RENDERER,
    candidate_for_batch,
    header_core,
    read_candidate,
    read_plan,
)
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.transcript_records import TranscriptSnapshot, incomplete
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch
from jt_oz_bridge.storage.transcript_models import TranscriptVersion


async def original_draft_witness(
    outbox: Outbox, saved: Delivery, readers: Mapping[SessionRef, TranscriptReader]
) -> Callable[[], bool] | None:
    if saved.batch_id is None:
        return None
    async with outbox.db.sessions() as session:
        batch = await session.get(DeliveryBatch, saved.batch_id)
        if batch is None:
            raise Conflict("draft_send_batch_missing")
        if batch.renderer_version != RENDERER:
            return None
        binding = await session.get(Binding, saved.binding_id)
    if binding is None:
        raise Conflict("draft_send_binding_missing")
    # Validate encrypted provenance and immutable lineage before a Native RPC.
    await outbox._validated_batch(binding, batch)
    async with outbox.db.sessions() as session:
        row = await candidate_for_batch(session, batch.id)
        version = await session.get(TranscriptVersion, row.source_version_id) if row else None
        if row is None or version is None:
            raise Conflict("draft_send_source_missing")
        candidate = read_candidate(row, version)
        plan = read_plan(row, candidate)
        if plan.mode != "draft":
            return None  # Closing edits have independent real-terminal evidence.
        snapshot = TranscriptSnapshot.model_validate(version.payload)
    expected = snapshot.observation
    ref = expected.reference
    reader = readers.get(ref)
    if reader is None:
        raise Conflict("draft_send_original_reader_unavailable")
    page = await reader.capture(ref, limit=20)
    matches = [entry for entry in page.entries if entry.native_id == expected.entry.native_id]
    newer_terminal = any(
        entry.kind == "idle"
        for entry in page.entries[
            : next(
                (
                    i
                    for i, entry in enumerate(page.entries)
                    if entry.native_id == expected.entry.native_id
                ),
                0,
            )
        ]
    )
    active = {
        ExecutionState.RUNNING,
        ExecutionState.WAITING_INPUT,
        ExecutionState.WAITING_PERMISSION,
    }
    if (
        not reader.current(page)
        or page.reference != ref
        or page.contract_sha256 != expected.contract_sha256
        or page.semantics_sha256 != expected.semantics_sha256
        or page.installed_evidence_sha256 != expected.installed_evidence_sha256
        or page.owner_epoch != expected.owner_epoch
        or page.connection_epoch != expected.connection_epoch
        or reader.contract_for(ref) != page.contract_sha256
        or page.state not in active
        or page.cursor is not None
        or newer_terminal
        or len(matches) != 1
        or matches[0].kind != "assistant"
        or not incomplete(matches[0])
        or header_core(matches[0]) != header_core(expected.entry)
    ):
        raise Conflict("draft_send_original_no_longer_active")
    # Only the reader retaining this actual object supplies authority. Check it
    # again after external ACL/edit-source reads and after the fenced SQL claim.
    return lambda: reader.current(page)
