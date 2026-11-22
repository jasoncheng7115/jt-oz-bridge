"""Source-tag-qualified durable event facts; mapping is not installed certification.

Native terminal events cover busy periods, never arbitrary queued prompt IDs.
No state/action/database/output mutation is performed in this module.
"""

from typing import Any, Literal, Self, cast

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.log import LogSynced, decode_log
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.native_events import LogProvenance, QualifiedLogRecord
from jt_oz_bridge.services.execution_receipts import ExecutionReceipt
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

# Hash of the preserved official tag source manifest's ordered path/hash mapping.
SEMANTICS_SHA256 = "29b55aaf5d02a2be12cb0f51601c61ab9edbfd17cced6988ad65babe37c60d68"


class SessionData(ControlModel):
    sessionID: str = Field(pattern=r"^ses_", max_length=255)


class InboxData(SessionData):
    inboxID: str = Field(pattern=r"^msg_", max_length=255)


class InterruptedData(SessionData):
    reason: Literal["user", "shutdown", "superseded", "inactivity"]


class FailedData(SessionData):
    error: dict[str, Any]


class TextData(SessionData):
    assistantMessageID: str = Field(pattern=r"^msg_", max_length=255)
    ordinal: StrictInt = Field(ge=0, le=2**53 - 1)
    text: str = Field(max_length=2 * 1024 * 1024)
    state: Any = None


class RenameData(SessionData):
    title: str = Field(max_length=100000)


DATA: dict[str, type[SessionData]] = {
    "session.execution.started": SessionData,
    "session.execution.succeeded": SessionData,
    "session.execution.failed": FailedData,
    "session.execution.interrupted": InterruptedData,
    "session.inbox.delivered": InboxData,
    "session.text.ended": TextData,
    "session.renamed": RenameData,
}


class SemanticEvent(ControlModel):
    provenance: LogProvenance
    capture_epoch: str
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_id: str
    native_type: str
    sequence: StrictInt | None = Field(ge=0, le=2**53 - 1)
    data: dict[str, Any]
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.native_type == "log.synced":
            if self.data or self.native_id != "sync:" + self.capture_epoch:
                raise ValueError("invalid_semantic_sync_marker")
        else:
            if not self.native_id.startswith("evt_") or self.sequence is None:
                raise ValueError("invalid_semantic_native_identity")
            model = DATA.get(self.native_type)
            if model is not None:
                decoded = model.model_validate(self.data)
                if decoded.sessionID != self.provenance.reference.upstream_session_id:
                    raise ValueError("semantic_session_identity_changed")
            elif self.native_type.startswith("session.execution."):
                raise ValueError("unknown_execution_semantics")
        return self


def normalize(record: QualifiedLogRecord) -> SemanticEvent:
    record = QualifiedLogRecord.model_validate(record.model_dump(mode="python"))
    native = decode_log(
        SSEFrame("message", checked_json(record.native).decode()), record.provenance.reference
    )
    kind: str
    if isinstance(native, LogSynced):
        native_id, kind, seq, data = "sync:" + record.capture_epoch, native.type, native.seq, {}
    else:
        native_id, kind, seq, data = native.id, native.type, native.durable.seq, native.data
        model = DATA.get(kind)
        if model is not None:
            if native.durable.version != 1:
                raise ContractError("native_event_semantics_version_unqualified")
            try:
                data = model.model_validate(data).model_dump(mode="json")
            except ValueError:
                raise ContractError("native_event_data_contract_mismatch") from None
        elif kind.startswith("session.execution."):
            raise ContractError("native_execution_event_semantics_unknown")
    return SemanticEvent(
        provenance=record.provenance,
        capture_epoch=record.capture_epoch,
        semantics_sha256=SEMANTICS_SHA256,
        native_id=native_id,
        native_type=kind,
        sequence=seq,
        data=data,
        source_hash=digest(record.model_dump(mode="json")),
    )


class BusyWindow(ControlModel):
    native_start_id: str = Field(pattern=r"^evt_", max_length=255)
    started_sequence: StrictInt = Field(ge=0, le=2**53 - 1)


class ProjectionState(ControlModel):
    provenance: LogProvenance
    semantics_sha256: str = SEMANTICS_SHA256
    sequence: StrictInt | None = Field(default=None, ge=0, le=2**53 - 1)
    capture_epoch: str | None = None
    active: BusyWindow | None = None
    status: ExecutionState = ExecutionState.UNKNOWN
    replay_synced: bool = False


class DeliveryFact(ControlModel):
    provenance: LogProvenance
    semantics_sha256: str
    native_inbox_id: str = Field(pattern=r"^msg_", max_length=255)
    native_event_id: str = Field(pattern=r"^evt_", max_length=255)
    delivered_sequence: StrictInt = Field(ge=0, le=2**53 - 1)
    window: BusyWindow | None


class TerminalFact(ControlModel):
    provenance: LogProvenance
    semantics_sha256: str
    native_event_id: str = Field(pattern=r"^evt_", max_length=255)
    terminal_sequence: StrictInt = Field(ge=0, le=2**53 - 1)
    outcome: Literal["succeeded", "failed", "interrupted"]
    reason: Literal["user", "shutdown", "superseded", "inactivity"] | None
    window: BusyWindow | None

    @model_validator(mode="after")
    def outcome_reason(self) -> Self:
        if (self.outcome == "interrupted") != (self.reason is not None):
            raise ValueError("terminal_reason_outcome_mismatch")
        return self


class TextFact(ControlModel):
    provenance: LogProvenance
    semantics_sha256: str
    native_event_id: str
    assistant_message_id: str
    ordinal: int
    text: str
    historical: bool


class ProjectionChange(ControlModel):
    state: ProjectionState
    delivery: DeliveryFact | None = None
    terminal: TerminalFact | None = None
    text: TextFact | None = None
    title: str | None = None
    continuity_gap: bool = False


def scope(provenance: LogProvenance) -> dict[str, Any]:
    # A fresh snapshot may change evidence/native-info digests without changing
    # the certified continuous execution epoch or authorization scope.
    return provenance.scope_data()


def reduce(state: ProjectionState, event: SemanticEvent) -> ProjectionChange:
    state = ProjectionState.model_validate(state.model_dump(mode="python"))
    event = SemanticEvent.model_validate(event.model_dump(mode="python"))
    if (
        scope(state.provenance) != scope(event.provenance)
        or state.semantics_sha256 != SEMANTICS_SHA256
        or event.semantics_sha256 != SEMANTICS_SHA256
    ):
        raise ContractError("native_projection_scope_or_epoch_requires_reconciliation")
    same_capture = state.capture_epoch == event.capture_epoch
    replay_synced = state.replay_synced if same_capture else False
    sequence = event.sequence
    changes: dict[str, Any] = {
        "sequence": sequence,
        "capture_epoch": event.capture_epoch,
        "provenance": event.provenance,
        "replay_synced": replay_synced,
    }
    if event.native_type == "log.synced":
        if (
            replay_synced
            or sequence is None
            and state.sequence is not None
            or sequence is not None
            and state.sequence is not None
            and sequence < state.sequence
        ):
            raise ContractError("native_projection_sync_marker_inconsistent")
        changes["replay_synced"] = True
        return ProjectionChange(state=state.model_copy(update=changes))
    if sequence is None or state.sequence is not None and sequence <= state.sequence:
        raise ContractError("native_projection_sequence_not_increasing")
    facts: dict[str, Any] = {}
    if event.native_type == "session.execution.started":
        changes.update(
            active=BusyWindow(native_start_id=event.native_id, started_sequence=sequence),
            status=ExecutionState.RUNNING,
        )
        facts["continuity_gap"] = state.active is not None
    elif event.native_type == "session.inbox.delivered":
        facts["delivery"] = DeliveryFact(
            provenance=event.provenance,
            semantics_sha256=SEMANTICS_SHA256,
            native_inbox_id=event.data["inboxID"],
            native_event_id=event.native_id,
            delivered_sequence=sequence,
            window=state.active,
        )
    elif event.native_type in {
        "session.execution.succeeded",
        "session.execution.failed",
        "session.execution.interrupted",
    }:
        outcome = event.native_type.rsplit(".", 1)[1]
        reason = event.data.get("reason")
        facts["terminal"] = TerminalFact(
            provenance=event.provenance,
            semantics_sha256=SEMANTICS_SHA256,
            native_event_id=event.native_id,
            terminal_sequence=sequence,
            outcome=cast(Literal["succeeded", "failed", "interrupted"], outcome),
            reason=reason,
            window=state.active,
        )
        changes.update(
            active=None,
            status=ExecutionState.DISCONNECTED
            if reason == "shutdown"
            else ExecutionState.FAILED
            if outcome == "failed"
            else ExecutionState.IDLE,
        )
    elif event.native_type == "session.text.ended":
        facts["text"] = TextFact(
            provenance=event.provenance,
            semantics_sha256=SEMANTICS_SHA256,
            native_event_id=event.native_id,
            assistant_message_id=event.data["assistantMessageID"],
            ordinal=event.data["ordinal"],
            text=event.data["text"],
            historical=not replay_synced,
        )
    elif event.native_type == "session.renamed":
        facts["title"] = event.data["title"]
    return ProjectionChange(state=state.model_copy(update=changes), **facts)


def completion(
    receipt: ExecutionReceipt, delivered: DeliveryFact, terminal: TerminalFact
) -> Literal["completed", "failed", "cancelled"] | None:
    """Candidate correlation only; caller must authenticate all rows/current scope.

    This does not update actions or grant output/mutation authority.
    """
    try:
        receipt = ExecutionReceipt.model_validate(receipt.model_dump(mode="python"))
        delivered = DeliveryFact.model_validate(delivered.model_dump(mode="python"))
        terminal = TerminalFact.model_validate(terminal.model_dump(mode="python"))
    except ValueError:
        return None
    if (
        scope(delivered.provenance) != scope(terminal.provenance)
        or delivered.semantics_sha256 != terminal.semantics_sha256
        or delivered.semantics_sha256 != SEMANTICS_SHA256
        or receipt.reference != delivered.provenance.reference
        or receipt.contract_sha256 != delivered.provenance.contract_sha256
        or receipt.admission.owner != "opencode"
        or receipt.admission.status != "admitted"
        or receipt.admission.details.get("operation") != "prompt"
        # A steer is delivered inside the running busy period it joins; its
        # delivery event and that period's one terminal correlate the same way.
        or receipt.admission.details.get("delivery") not in {"queue", "steer"}
        or receipt.admission.upstream_id != delivered.native_inbox_id
        or delivered.window is None
        or delivered.window != terminal.window
        or not delivered.window.started_sequence
        < delivered.delivered_sequence
        < terminal.terminal_sequence
        or terminal.reason == "shutdown"
    ):
        return None
    return (
        "completed"
        if terminal.outcome == "succeeded"
        else "failed"
        if terminal.outcome == "failed"
        else "cancelled"
    )
