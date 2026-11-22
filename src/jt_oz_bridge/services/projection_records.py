"""Authenticated projection record layout and indexed-field crosschecks."""

from pydantic import Field, StrictInt

from jt_oz_bridge.adapters.opencode.event_semantics import (
    SEMANTICS_SHA256,
    ProjectionChange,
    ProjectionState,
    SemanticEvent,
    normalize,
    reduce,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.native_events import QualifiedLogRecord
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import InputEvent
from jt_oz_bridge.storage.projection_models import NativeLogIndex, NativeProjectionRecord


class ProjectedRecord(ControlModel):
    input_event_id: str
    ordinal: StrictInt = Field(ge=1)
    scope_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_semantic_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event: SemanticEvent
    before: ProjectionState
    change: ProjectionChange


def window_key(scope: str, start_id: str) -> str:
    return digest({"scope": scope, "native_start_id": start_id})


def validate_capture(
    row: InputEvent, index: NativeLogIndex
) -> tuple[QualifiedLogRecord, SemanticEvent]:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("native_capture_payload_hash_changed")
    record = QualifiedLogRecord.model_validate(row.payload)
    event = normalize(record)
    sequence = event.sequence
    source = "v2-log:" + digest(record.provenance.reference.model_dump())
    revision = 0 if event.native_type == "log.synced" else record.native["durable"]["version"]
    if (
        row.id != index.input_event_id
        or row.source != index.source
        or row.source != source
        or row.source_id != event.native_id
        or row.revision != revision
        or index.binding_id != record.provenance.binding_id
        or index.binding_revision != record.provenance.binding_revision
        or record.capture_epoch != index.capture_epoch
        or sequence != index.native_sequence
        or record.provenance.scope_key() != index.scope_key
    ):
        raise Conflict("native_capture_index_or_identity_changed")
    return record, event


def read_record(
    row: NativeProjectionRecord, captured: InputEvent, index: NativeLogIndex
) -> ProjectedRecord:
    record, event = validate_capture(captured, index)
    if digest(row.payload) != row.payload_hash:
        raise Conflict("native_projection_record_hash_changed")
    saved = ProjectedRecord.model_validate(row.payload)
    change = reduce(saved.before, event)
    window = (
        change.delivery.window
        if change.delivery
        else change.terminal.window
        if change.terminal
        else None
    )
    if (
        saved.input_event_id != row.input_event_id
        or saved.input_event_id != captured.id
        or saved.ordinal != row.ordinal
        or saved.ordinal != index.ordinal
        or saved.scope_key != row.scope_key
        or saved.scope_key != index.scope_key
        or saved.event != event
        or saved.change != change
        or saved.event.semantics_sha256 != SEMANTICS_SHA256
        or row.native_type != event.native_type
        or row.native_inbox_id != (change.delivery.native_inbox_id if change.delivery else None)
        or row.window_key
        != (window_key(saved.scope_key, window.native_start_id) if window else None)
        or row.assistant_message_id != (change.text.assistant_message_id if change.text else None)
        or row.part_ordinal != (change.text.ordinal if change.text else None)
    ):
        raise Conflict("native_projection_record_evidence_changed")
    return saved
