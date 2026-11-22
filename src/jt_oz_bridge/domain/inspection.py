"""Read-only local observer protocol; no execution capability or message payload."""

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, Self

from pydantic import Field, StrictBool, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.runtime_readiness import REASONS, ModeReason, RootMode


class _InspectionQueryFields(ControlModel):
    version: str
    command: Literal["sessions", "session", "doctor"] = "sessions"
    backend_id: str | None = Field(default=None, min_length=1, max_length=255)
    project_id: str | None = Field(default=None, min_length=1, max_length=255)
    session_id: str | None = Field(default=None, pattern=r"^ses[A-Za-z0-9_-]{1,251}$")
    association: Literal["all", "bound", "unbound"] = "all"
    active: StrictBool = False
    limit: int = Field(default=10, strict=True, ge=1, le=50)
    cursor: str | None = Field(default=None, min_length=1, max_length=8192)
    max_pages: int = Field(default=10, strict=True, ge=1, le=10)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if (self.command == "session") != (self.session_id is not None):
            raise ValueError("exact_session_id_required_only_for_detail")
        if self.cursor and (not self.backend_id or self.command != "sessions"):
            raise ValueError("cursor_requires_one_backend_session_list")
        if self.command != "sessions" and (
            self.active or self.association != "all" or self.project_id
        ):
            raise ValueError("list_filters_require_session_list")
        return self


class InspectionQuery(_InspectionQueryFields):
    version: Literal["jt-oz-inspector-v1"] = "jt-oz-inspector-v1"


class InspectionQueryV2(_InspectionQueryFields):
    version: Literal["jt-oz-inspector-v2"] = "jt-oz-inspector-v2"


class InspectionCounts(ControlModel):
    queued: int = Field(default=0, ge=0, strict=True)
    held: int = Field(default=0, ge=0, strict=True)
    active: int = Field(default=0, ge=0, strict=True)
    ambiguous: int = Field(default=0, ge=0, strict=True)
    failed: int = Field(default=0, ge=0, strict=True)
    pending_delivery: int = Field(default=0, ge=0, strict=True)
    failed_delivery: int = Field(default=0, ge=0, strict=True)


class InspectionBinding(ControlModel):
    binding_id: str = Field(min_length=1, max_length=36)
    project_id: str = Field(min_length=1, max_length=255)
    realm_id: str = Field(min_length=1, max_length=255)
    channel_id: int = Field(strict=True, gt=0)
    topic: str = Field(max_length=10000)
    revision: int = Field(strict=True, ge=1)
    state: Literal["active_record", "creating", "stale", "inactive"]
    paused: StrictBool
    access_verified: Literal[False] = False
    conversation_url: str | None = Field(default=None, max_length=4096)
    counts: InspectionCounts = Field(default_factory=InspectionCounts)


class InspectionSession(ControlModel):
    backend_id: str = Field(min_length=1, max_length=255)
    backend_identity: str = Field(min_length=1, max_length=255)
    session_id: str = Field(pattern=r"^ses[A-Za-z0-9_-]{1,251}$")
    native_project_id: str = Field(min_length=1, max_length=255)
    directory: str = Field(min_length=1, max_length=4096)
    title: str = Field(max_length=10000)
    title_truncated: StrictBool = False
    agent_id: str | None = Field(default=None, max_length=255)
    provider_id: str | None = Field(default=None, max_length=255)
    model_id: str | None = Field(default=None, max_length=8192)
    variant: str | None = Field(default=None, max_length=8192)
    parent_id: str | None = Field(default=None, max_length=255)
    fork_source_id: str | None = Field(default=None, max_length=255)
    state: ExecutionState = ExecutionState.UNKNOWN
    state_reason: Literal[
        "repeated_resources",
        "resource_changed",
        "resource_unavailable",
        "lineage_unqualified",
        "catalog_only",
    ] = "catalog_only"
    coordinator_active: StrictBool | None = None
    last_outcome: Literal["succeeded", "failed", "interrupted"] | None = None
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    owner_epoch: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    bindings: tuple[InspectionBinding, ...] = Field(default=(), max_length=100)
    execution_registration: Literal["enrolled", "catalog_only"] = "catalog_only"
    binding_coverage: Literal["complete", "unavailable"] = "unavailable"

    @property
    def bound(self) -> bool:
        return any(b.state == "active_record" for b in self.bindings)


class InspectionCoverage(ControlModel):
    backend_id: str = Field(min_length=1, max_length=255)
    scope: Literal["backend_catalog"] = "backend_catalog"
    owner_epoch: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    native_pid: int | None = Field(default=None, strict=True, gt=0)
    complete: StrictBool
    scanned: int = Field(ge=0, strict=True)
    next_cursor: str | None = Field(default=None, max_length=8192)
    reason: Literal[
        "exhausted", "page", "scan_limit", "backend_unavailable", "deadline", "state_unknown"
    ]


InspectionIssueCode = Literal[
    "observer_unavailable",
    "unauthorized",
    "invalid_request",
    "invalid_response",
    "scope_unavailable",
    "native_unavailable",
    "partial_state",
    "capacity",
    "deadline",
    "bridge_unavailable",
    "runtime_modes_unavailable",
    "stale_observation",
]


class InspectionIssue(ControlModel):
    code: InspectionIssueCode
    backend_id: str | None = Field(default=None, max_length=255)


def bounded_inspection_issues(
    *batches: Iterable[InspectionIssue],
) -> tuple[InspectionIssue, ...]:
    """Deduplicate exact issues, retaining every precise code within the100 cap.

    At capacity, keep the first original scope for each code, including late
    authorization/protocol errors, plus as many remaining scopes as fit in order.
    New freshness/mode warnings cannot erase a distinct prior error code.
    """
    unique: dict[tuple[str, str | None], InspectionIssue] = {}
    for batch in batches:
        for issue in batch:
            unique.setdefault((issue.code, issue.backend_id), issue)
    values = list(unique.values())
    if len(values) <= 100:
        return tuple(values)
    if not any(issue.code == "capacity" for issue in values):
        values.append(InspectionIssue(code="capacity"))
    representatives: dict[str, int] = {}
    for index, issue in enumerate(values):
        representatives.setdefault(issue.code, index)
    selected = set(representatives.values())
    for index in range(len(values)):
        if len(selected) == 100:
            break
        selected.add(index)
    return tuple(issue for index, issue in enumerate(values) if index in selected)


class InspectionResponse(ControlModel):
    version: Literal["jt-oz-inspector-v1"] = "jt-oz-inspector-v1"
    status: Literal["ok", "partial", "error"]
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    bridge_ready: StrictBool = False
    bridge_lease_current: StrictBool = False
    rows: tuple[InspectionSession, ...] = Field(default=(), max_length=1000)
    coverage: tuple[InspectionCoverage, ...] = Field(default=(), max_length=20)
    issues: tuple[InspectionIssue, ...] = Field(default=(), max_length=100)
    # These are separate operator observations, never a certified continuation.
    observation_kind: Literal["read_only_local_observer"] = "read_only_local_observer"


class InspectionRuntimeMode(ControlModel):
    """Controller observation only; never Native state or operation authority."""

    mode: RootMode
    reason: ModeReason
    transition_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    observed_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @field_validator("transition_at", "observed_at", mode="before")
    @classmethod
    def real_observation_time(cls, value: object) -> object:
        if value is not None and type(value) is not float:
            raise ValueError("runtime_mode_timestamp_must_be_float")
        return value

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.reason not in REASONS[self.mode]:
            raise ValueError("runtime_mode_reason_mismatch")
        if self.transition_at is None or self.observed_at is None:
            if (
                self.transition_at is not None
                or self.observed_at is not None
                or self.mode not in {"unavailable", "not-observed"}
            ):
                raise ValueError("runtime_mode_observation_times_required")
        elif self.transition_at > self.observed_at:
            raise ValueError("runtime_mode_future_transition")
        return self


class InspectionSessionV2(InspectionSession):
    runtime_mode: InspectionRuntimeMode


class InspectionResponseV2(ControlModel):
    version: Literal["jt-oz-inspector-v2"] = "jt-oz-inspector-v2"
    status: Literal["ok", "partial", "error"]
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    bridge_ready: StrictBool = False
    bridge_lease_current: StrictBool = False
    rows: tuple[InspectionSessionV2, ...] = Field(default=(), max_length=1000)
    coverage: tuple[InspectionCoverage, ...] = Field(default=(), max_length=20)
    issues: tuple[InspectionIssue, ...] = Field(default=(), max_length=100)
    observation_kind: Literal["read_only_local_observer"] = "read_only_local_observer"


type InspectionProtocolQuery = InspectionQuery | InspectionQueryV2
type InspectionProtocolResponse = InspectionResponse | InspectionResponseV2


@dataclass(frozen=True)
class InspectionClock:
    """Wall/monotonic bracket, never a new timestamp for an existing fact."""

    before: float
    monotonic: float
    after: float

    @classmethod
    def capture(cls, wall: Callable[[], float], monotonic: Callable[[], float]) -> Self:
        before = wall()
        tick = monotonic()
        return cls(before, tick, wall())

    def uncertainty_since(self, started: Self) -> float:
        values = (
            started.before,
            started.monotonic,
            started.after,
            self.before,
            self.monotonic,
            self.after,
        )
        if not all(math.isfinite(value) for value in values):
            return math.inf
        elapsed = self.monotonic - started.monotonic
        low, high = self.before - started.after, self.after - started.before
        if (
            started.after < started.before
            or self.after < self.before
            or elapsed < 0
            or low < 0
            or high < 0
        ):
            return math.inf
        # Slew, steps and sampling uncertainty consume the original five seconds.
        # They never extend a deadline, even when wall time moves backwards.
        return max(abs(low - elapsed), abs(high - elapsed))

    def fresh(self, observed_at: float, uncertainty: float = 0.0) -> bool:
        return (
            math.isfinite(observed_at)
            and math.isfinite(uncertainty)
            and 0 <= self.before - observed_at
            and self.after - observed_at + uncertainty < 5.0
        )


def unknown_inspection_row(row: InspectionSession) -> InspectionSession:
    """Preserve identity, metadata and original time; remove expired state claims."""
    updates: dict[str, object] = {
        "state": ExecutionState.UNKNOWN,
        "state_reason": "resource_unavailable",
        "owner_epoch": None,
        "coordinator_active": None,
    }
    if isinstance(row, InspectionSessionV2):
        updates["runtime_mode"] = InspectionRuntimeMode(
            mode="unavailable", reason="diagnostics-unavailable"
        )
    return row.model_copy(update=updates)


def fresh_inspection_response(
    response: InspectionProtocolResponse,
    started: InspectionClock,
    ended: InspectionClock,
) -> InspectionProtocolResponse:
    """Final send/receive/display projection; no I/O and no refreshed old facts."""
    uncertainty = ended.uncertainty_since(started)
    envelope_current = ended.fresh(response.observed_at, uncertainty)
    stale_backends = {
        row.backend_id
        for row in response.rows
        if not envelope_current
        or not ended.fresh(row.observed_at, uncertainty)
        or row.state != ExecutionState.UNKNOWN
        and row.owner_epoch is None
    }
    rows = []
    mode_stale = False
    for row in response.rows:
        if (
            not envelope_current
            or not ended.fresh(row.observed_at, uncertainty)
            or row.state != ExecutionState.UNKNOWN
            and row.owner_epoch is None
        ):
            rows.append(unknown_inspection_row(row))
            mode_stale |= isinstance(row, InspectionSessionV2)
        elif isinstance(row, InspectionSessionV2) and row.runtime_mode.observed_at is not None:
            if not ended.fresh(row.runtime_mode.observed_at, uncertainty):
                rows.append(
                    row.model_copy(
                        update={
                            "runtime_mode": InspectionRuntimeMode(
                                mode="unavailable", reason="diagnostics-unavailable"
                            )
                        }
                    )
                )
                mode_stale = True
            else:
                rows.append(row)
        else:
            rows.append(row)
    # Existing protocol errors remain errors, including their precise issue code.
    stale = bool(stale_backends or mode_stale or not envelope_current)
    if not stale or response.status == "error" and not response.rows:
        return response
    issues = bounded_inspection_issues(
        response.issues,
        (InspectionIssue(code="stale_observation"),),
        (InspectionIssue(code="runtime_modes_unavailable"),) if mode_stale else (),
    )
    return response.model_copy(
        update={
            "rows": tuple(rows),
            "coverage": tuple(
                item.model_copy(
                    update={
                        "complete": False,
                        "reason": "state_unknown",
                        "owner_epoch": None,
                        "native_pid": None,
                    }
                )
                if not envelope_current or item.backend_id in stale_backends
                else item
                for item in response.coverage
            ),
            "bridge_ready": response.bridge_ready if envelope_current else False,
            "bridge_lease_current": response.bridge_lease_current
            if envelope_current and not mode_stale
            else False,
            "status": "error" if response.status == "error" else "partial",
            "issues": issues,
        }
    )
