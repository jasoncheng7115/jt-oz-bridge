"""Source-qualified V2 durable-log envelopes; not a live compatibility claim."""

from typing import Any, Literal

from pydantic import Field, StrictFloat, StrictInt, ValidationError

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads


class LogPosition(ControlModel):
    aggregateID: str
    seq: StrictInt = Field(ge=0, le=2**53 - 1)
    version: StrictInt = Field(ge=1)


class DurableLogItem(ControlModel):
    id: str = Field(pattern=r"^evt_", max_length=255)
    type: str = Field(min_length=1, max_length=255)
    created: StrictFloat = Field(allow_inf_nan=False)
    data: dict[str, Any]
    durable: LogPosition
    location: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class LogSynced(ControlModel):
    type: Literal["log.synced"]
    aggregateID: str
    seq: StrictInt | None = Field(default=None, ge=0, le=2**53 - 1)


LogItem = DurableLogItem | LogSynced


def decode_log(frame: SSEFrame, reference: SessionRef) -> LogItem:
    """SSE data is one JSON object, not a guessed double-encoded string."""
    try:
        raw = strict_loads(frame.data)
        if not isinstance(raw, dict):
            raise ValueError("object required")
        if raw.get("type") == "log.synced":
            marker = LogSynced.model_validate(raw)
            item: LogItem = marker
            aggregate = marker.aggregateID
        else:
            item = DurableLogItem.model_validate(raw)
            aggregate = item.durable.aggregateID
            if item.data.get("sessionID") != reference.upstream_session_id:
                raise ValueError("session mismatch")
            if item.location and item.location.get("directory") != reference.canonical_directory:
                raise ValueError("location mismatch")
        if aggregate != reference.upstream_session_id:
            raise ValueError("aggregate mismatch")
        return item
    except (ValueError, TypeError, RecursionError, ValidationError):
        raise ContractError("session_log_envelope_or_identity_mismatch") from None


class LogRead:
    """Track one stream, advancing only positions supplied by that stream.

    Sequence gaps are valid: non-public durable events share the same aggregate.
    A synced marker can be beyond the last public event. It closes only replay,
    not the independent session snapshot/owner checks required by a connector.
    """

    def __init__(self, reference: SessionRef, after: int | None = None) -> None:
        if after is not None and (
            isinstance(after, bool) or not isinstance(after, int) or not 0 <= after <= 2**53 - 1
        ):
            raise ValueError("invalid stored log position")
        self.reference, self.position = reference, after
        self.synced = False

    def accept(self, frame: SSEFrame) -> LogItem:
        item = decode_log(frame, self.reference)
        if isinstance(item, LogSynced):
            if self.synced or (item.seq is None and self.position is not None):
                raise ContractError("session_log_sync_marker_inconsistent")
            if item.seq is not None:
                if self.position is not None and item.seq < self.position:
                    raise ContractError("session_log_watermark_regressed")
                self.position = item.seq
            self.synced = True
        else:
            if self.position is not None and item.durable.seq <= self.position:
                raise ContractError("session_log_position_not_increasing")
            self.position = item.durable.seq
        return item
