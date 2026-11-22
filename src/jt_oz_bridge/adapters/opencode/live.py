"""Bounded original-owner public feed, explicitly volatile and never a replay log.

This reader supplies scoped observations for resource reconciliation. It does not
implement ExecutionProofProvider or turn a connected socket into a state proof.
"""

import asyncio
import json
import logging
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Never, Protocol

from pydantic import Field

from jt_oz_bridge.adapters.opencode.contracts import ContractError, OpenAPIProfile
from jt_oz_bridge.adapters.opencode.host_owner import HostOwnerEvidence, LinuxHostOwnerProbe
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from jt_oz_bridge.adapters.opencode.transport import V2HTTPTransport
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import (
    finite_float,
    reject_constant,
    strict_loads,
    unique_object,
)
from jt_oz_bridge.storage.durable import digest

# The retained v2.0.32 schema/source defines this event as an ephemeral
# fragment. It does not project a message or change execution/permission state.
# No other schema or event inherits that semantic classification by name.
STATE_NEUTRAL_TEXT_SCHEMA = "1c42291edfab54761b7f6cf0f490a262be277d45d1daa926ab3b8de15e658bce"

# Framing room above the per-event payload limit before the reader stops
# buffering a frame. A discarded frame keeps only a bounded prefix.
FRAME_ALLOWANCE = 64 * 1024
LOG = logging.getLogger(__name__)
_SPACE = re.compile(r"[ \t\n\r]*")
_DECODER = json.JSONDecoder(
    parse_constant=reject_constant, parse_float=finite_float, object_pairs_hook=unique_object
)

if TYPE_CHECKING:
    from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture


def _skip(text: str, position: int) -> int:
    match = _SPACE.match(text, position)
    assert match is not None  # The pattern matches the empty string.
    return match.end()


def leading_members(prefix: str) -> dict[str, Any]:
    """Complete leading members of a cut event object, and of its cut ``data``.

    A value counts only when it is complete inside the prefix; a number at the
    cut may itself be cut and is left out. Nothing here validates the event.
    """
    return _members(prefix, 0, nested="data")


def _members(text: str, position: int, *, nested: str | None) -> dict[str, Any]:
    position = _skip(text, position)
    if not text.startswith("{", position):
        raise ValueError("oversized_event_prefix_not_object")
    result: dict[str, Any] = {}
    position += 1
    while True:
        position = _skip(text, position)
        if position >= len(text) or text[position] == "}" and not result:
            return result
        if text[position] != '"':
            raise ValueError("oversized_event_prefix_invalid")
        try:
            key, position = _DECODER.raw_decode(text, position)  # A string: '"' above.
        except json.JSONDecodeError:
            return result
        position = _skip(text, position)
        if position >= len(text):
            return result
        if text[position] != ":" or key in result:
            raise ValueError("oversized_event_prefix_invalid")
        position = _skip(text, position + 1)
        try:
            value, after = _DECODER.raw_decode(text, position)
        except json.JSONDecodeError:
            if key == nested and text.startswith("{", position):
                result[key] = _members(text, position, nested=None)
            return result
        after = _skip(text, after)
        if after >= len(text):
            if type(value) not in {int, float}:
                result[key] = value
            return result
        result[key] = value
        if text[after] == "}":
            return result
        if text[after] != ",":
            raise ValueError("oversized_event_prefix_invalid")
        position = after + 1


@dataclass(frozen=True)
class ScopedLiveEvent:
    reference: SessionRef
    connection_epoch: str
    native_id: str
    native_seq: int | None
    event_type: str
    json_data: str
    observation_revision: int = 0  # Own index order, never a Native/replay position.

    def payload(self) -> dict[str, Any]:
        # Return a fresh tree; callers cannot alter the indexed observation.
        value: dict[str, Any] = strict_loads(self.json_data)
        return value


class FeedEventReceipt(ControlModel):
    """Sealed own dedup metadata, deliberately without the event's text payload."""

    reference: SessionRef
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    connection_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    native_id: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=255)
    native_seq: int | None
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def key(self) -> str:
        return event_receipt_key(
            self.reference, self.owner_epoch, self.connection_epoch, self.native_id
        )


def event_receipt_key(
    reference: SessionRef, owner_epoch: str, connection_epoch: str, native_id: str
) -> str:
    return digest(
        {
            "backend_id": reference.backend_id,
            "backend_identity": reference.backend_identity,
            "owner_epoch": owner_epoch,
            "connection_epoch": connection_epoch,
            "native_id": native_id,
        }
    )


class FeedReceiptStore(Protocol):
    async def record_many(self, values: tuple[FeedEventReceipt, ...]) -> tuple[bool, ...]: ...


@dataclass(frozen=True)
class PreparedEvent:
    item: ScopedLiveEvent
    sha256: str
    size: int


class VolatileFeedIndex:
    """One bounded connection generation. No persisted/replay/idle assertions.

    The full server feed is filtered before retention. Native sequence values are
    observed positions only, never evidence that missing events were recovered.
    Overflow, conflicting scope/identity and EOF permanently invalidate this index.
    """

    def __init__(
        self,
        profile: OpenAPIProfile,
        references: tuple[SessionRef, ...],
        owner_epoch: str,
        *,
        max_events: int = 10000,
        max_bytes: int = 16 * 1024 * 1024,
        max_event_bytes: int = 1024 * 1024,
    ) -> None:
        if (
            not references
            or len(references) > 1000
            or len({r.upstream_session_id for r in references}) != len(references)
            or len({(r.backend_id, r.backend_identity) for r in references}) != 1
            or len(owner_epoch) != 64
            or any(c not in "0123456789abcdef" for c in owner_epoch)
            or any(type(v) is not int or v < 1 for v in (max_events, max_bytes, max_event_bytes))
        ):
            raise ValueError("invalid_volatile_feed_enrollment_or_limits")
        self.profile, self.owner_epoch = profile, owner_epoch
        self.references = MappingProxyType({r.upstream_session_id: r for r in references})
        self.max_events, self.max_bytes, self.max_event_bytes = (
            max_events,
            max_bytes,
            max_event_bytes,
        )
        self.connection_epoch: str | None = None
        self.closed = False
        self.failure: str | None = None
        self.revision = 0
        self._queue: deque[ScopedLiveEvent] = deque()
        self._seen: dict[str, str] = {}
        self._positions: dict[str, int] = {}
        self._revisions: dict[str, int] = {}
        self._state_revisions: dict[str, int] = {}
        self._arrival_revisions: dict[str, int] = {}
        self._arrival_state_revisions: dict[str, int] = {}
        # Payload-free invalidation for future complete-graph providers. An
        # unknown child's first event must not disappear behind enrolled-ID
        # filtering. These are local observations, never Native replay cursors.
        self._stream_arrivals = 0
        self._stream_state_arrivals = 0
        # The same arrivals split by the one directory each can belong to. The
        # None key holds arrivals without a provable directory; every
        # directory's fence includes it.
        self._directory_arrivals: dict[str | None, int] = {}
        self._directory_state_arrivals: dict[str | None, int] = {}
        self._retained_bytes = 0

    def invalidate(self, reason: str) -> None:
        if not self.closed:
            self.failure = reason
        self.closed = True
        self._queue.clear()
        self._seen.clear()
        self._positions.clear()
        self._revisions.clear()
        self._state_revisions.clear()
        self._arrival_revisions.clear()
        self._arrival_state_revisions.clear()
        self._retained_bytes = 0

    def reject(self, reason: str) -> Never:
        self.invalidate(reason)
        raise ContractError(reason)

    def require_live(self) -> str:
        if self.closed or self.connection_epoch is None:
            raise ContractError("volatile_feed_not_live")
        return self.connection_epoch

    def stream_fence(self, *, state_only: bool = False) -> str:
        """Whole-stream invalidation only, not lineage/resource qualification.

        Consumers must additionally pin the original index/task/attestation and
        prove the complete current Native graph/resources. Unenrolled events
        never become scoped messages, retained payloads or execution grants.
        """
        return digest(
            {
                "connection_epoch": self.require_live(),
                "owner_epoch": self.owner_epoch,
                "contract_sha256": self.profile.sha256,
                "arrival_revision": self._stream_state_arrivals
                if state_only
                else self._stream_arrivals,
                "kind": "whole-stream-state" if state_only else "whole-stream",
            }
        )

    def directory_fence(self, directory: str, *, state_only: bool = False) -> str:
        """`stream_fence` limited to arrivals that can belong to one directory.

        A tree's unknown children run in its directory: an enrolled node whose
        event names another directory closes this feed. So another project's
        activity no longer moves this tree's fence, while an arrival with no
        provable directory still moves every directory's fence.
        """
        counts = self._directory_state_arrivals if state_only else self._directory_arrivals
        return digest(
            {
                "connection_epoch": self.require_live(),
                "owner_epoch": self.owner_epoch,
                "contract_sha256": self.profile.sha256,
                "directory": directory,
                "arrival_revision": counts.get(directory, 0),
                "unattributed_revision": counts.get(None, 0),
                "kind": "directory-stream-state" if state_only else "directory-stream",
            }
        )

    def _arrival_directory(self, raw: dict[str, Any]) -> str | None:
        """The one directory an arrival can belong to, or None for all of them."""
        data = raw.get("data")
        candidates = self._candidates(raw) if isinstance(data, dict) else []
        if candidates and all(isinstance(s, str) and s == candidates[0] for s in candidates):
            ref = self.references.get(candidates[0])
            if ref is not None:
                return ref.canonical_directory
        location = raw.get("location")
        directory = location.get("directory") if isinstance(location, dict) else None
        return directory if isinstance(directory, str) and directory else None

    def _count_arrival(self, directory: str | None, *, state: bool) -> None:
        self._stream_arrivals += 1
        self._directory_arrivals[directory] = self._directory_arrivals.get(directory, 0) + 1
        if state:
            self._stream_state_arrivals += 1
            self._directory_state_arrivals[directory] = (
                self._directory_state_arrivals.get(directory, 0) + 1
            )

    def _notice_stream_arrival(self, raw: dict[str, Any]) -> None:
        kind = raw.get("type")
        if not isinstance(kind, str):
            self.reject("volatile_feed_invalid_frame")
        if kind == "server.connected" or ".reasoning." in kind:
            return
        # Invalidation is intentionally conservative. Unknown event kinds and
        # foreign/unenrolled IDs change the graph fence without being retained.
        # A replayed/duplicate arrival may invalidate again; it never certifies
        # progress, deduplication or that an unobserved topology event exists.
        neutral = (
            self.profile.sha256 == STATE_NEUTRAL_TEXT_SCHEMA
            and kind == "session.text.delta"
            and raw.get("durable") is None
            and self._scope(raw) is not None
        )
        self._count_arrival(self._arrival_directory(raw), state=not neutral)

    def revision_for(self, reference: SessionRef) -> int:
        self.require_live()
        if self.references.get(reference.upstream_session_id) != reference:
            raise ContractError("volatile_feed_reference_not_enrolled")
        sid = reference.upstream_session_id
        return self._revisions.get(sid, 0) + self._arrival_revisions.get(sid, 0)

    def observed_position(self, reference: SessionRef) -> int | None:
        self.require_live()
        if self.references.get(reference.upstream_session_id) != reference:
            raise ContractError("volatile_feed_reference_not_enrolled")
        return self._positions.get(reference.upstream_session_id)

    def state_revision_for(self, reference: SessionRef) -> int:
        # Only positive active resource proofs may use this counter. Idle and
        # final-output witnesses still use the full observation revision.
        self.revision_for(reference)
        sid = reference.upstream_session_id
        return self._state_revisions.get(sid, 0) + self._arrival_state_revisions.get(sid, 0)

    def pop(self) -> ScopedLiveEvent | None:
        self.require_live()
        if not self._queue:
            return None
        item = self._queue.popleft()
        self._retained_bytes -= len(item.json_data.encode())
        return item

    def owns(self, item: ScopedLiveEvent) -> bool:
        self.require_live()
        return item.connection_epoch == self.connection_epoch and any(
            candidate is item for candidate in self._queue
        )

    @staticmethod
    def _candidates(raw: dict[str, Any]) -> list[Any]:
        kind, data = raw["type"], raw["data"]
        candidates = []
        if "sessionID" in data:
            candidates.append(data["sessionID"])
        if kind == "form.created" and isinstance(data.get("form"), dict):
            candidates.append(data["form"].get("sessionID"))
        durable = raw.get("durable")
        if durable is not None:
            candidates.append(durable.get("aggregateID"))
        return candidates

    def _scope(self, raw: dict[str, Any]) -> SessionRef | None:
        candidates = self._candidates(raw)
        enrolled = [s for s in candidates if isinstance(s, str) and s in self.references]
        if not enrolled:
            return None
        sid = enrolled[0]
        if any(s != sid for s in candidates):
            self.reject("volatile_feed_conflicting_session_scope")
        ref = self.references[sid]
        location = raw.get("location")
        if location is not None and location.get("directory") != ref.canonical_directory:
            self.reject("volatile_feed_conflicting_directory")
        return ref

    def _gap(self, ref: SessionRef | None) -> None:
        """One discarded event changes its Root's fences exactly like an arrival.

        No payload, receipt, position or observation is kept. Proofs taken
        before it stop being current and the next one is a fresh GET. Without
        an attributable session every enrolled Root's fences change.
        """
        for sid in self.references if ref is None else (ref.upstream_session_id,):
            self._arrival_revisions[sid] = self._arrival_revisions.get(sid, 0) + 1
            self._arrival_state_revisions[sid] = self._arrival_state_revisions.get(sid, 0) + 1
        LOG.warning(
            "public_feed_event_discarded reason=oversized session=%s",
            "unattributed" if ref is None else ref.upstream_session_id,
        )

    def discard_oversized(self, raw: dict[str, Any]) -> None:
        """A complete but too large event: exact scope, then a gap for its Root."""
        kind = raw["type"]
        if not kind.startswith(("session.", "permission.", "form.")) or ".reasoning." in kind:
            return
        ref = self._scope(raw)
        if ref is not None:
            self._gap(ref)

    def discard_truncated(self, frame: SSEFrame) -> None:
        """A frame the reader dropped while reading, known only by its prefix.

        Scope comes from the leading members Native writes first (identity,
        type, location, ``data.sessionID``). A conflict hidden in the dropped
        rest cannot be checked; the event is never retained or receipted.
        """
        try:
            raw = leading_members(frame.data)
        except (ValueError, RecursionError):
            self.reject("volatile_feed_invalid_frame")
        kind, data = raw.get("type"), raw.get("data", {})
        if (
            not isinstance(kind, str)
            or kind == "server.connected"
            or not isinstance(raw.get("id"), str)
            or not isinstance(data, dict)
            or not isinstance(raw.get("location"), dict | None)
            or not isinstance(raw.get("durable"), dict | None)
        ):
            self.reject("volatile_feed_invalid_frame")
        # Unclassified: both whole-stream fences change, and every directory's:
        # the dropped rest may name a session the leading location contradicts.
        self._count_arrival(None, state=True)
        if not kind.startswith(("session.", "permission.", "form.")):
            return
        scope = {**raw, "data": data}
        if not self._candidates(scope):
            self._gap(None)
            return
        ref = self._scope(scope)
        if ref is not None:
            self._gap(ref)

    def _notice_arrival(self, raw: dict[str, Any]) -> None:
        # Early invalidation only. No observation/output/admission/position is
        # issued until the receipt commits. A slow SQL writer must not preserve
        # an old before-send state fence for an event already received here.
        self._notice_stream_arrival(raw)
        kind = raw["type"]
        if not kind.startswith(("session.", "permission.", "form.")) or ".reasoning." in kind:
            return
        ref = self._scope(raw)
        if ref is None:
            return
        if raw["id"] in self._seen:
            if digest(raw) != self._seen[raw["id"]]:
                self.reject("volatile_feed_event_identity_changed")
            return
        sid = ref.upstream_session_id
        self._arrival_revisions[sid] = self._arrival_revisions.get(sid, 0) + 1
        if not (
            self.profile.sha256 == STATE_NEUTRAL_TEXT_SCHEMA
            and kind == "session.text.delta"
            and raw.get("durable") is None
        ):
            self._arrival_state_revisions[sid] = self._arrival_state_revisions.get(sid, 0) + 1

    def _prepare(self, frame: SSEFrame) -> PreparedEvent | None:
        if self.closed:
            raise ContractError("volatile_feed_closed")
        try:
            if frame.truncated:
                self.require_live()
                self.discard_truncated(frame)
                return None
            self.profile.sse_frame(
                "event.subscribe", event=frame.event, data=frame.data, event_id=frame.event_id
            )
            raw = strict_loads(frame.data)
            kind, event_id = raw["type"], raw["id"]
            if kind == "server.connected":
                if self.connection_epoch is not None:
                    self.reject("volatile_feed_reconnected_without_reconciliation")
                self.connection_epoch = digest(
                    {"owner_epoch": self.owner_epoch, "native_connected_event": event_id}
                )
                return None
            epoch = self.require_live()
            self._notice_stream_arrival(raw)
            if not kind.startswith(("session.", "permission.", "form.")):
                return None
            ref = self._scope(raw)
            if ref is None:
                return None
            durable = raw.get("durable")
            # Neither raw reasoning nor a hash of it enters the receipt journal.
            if ".reasoning." in kind:
                return None
            seq = durable["seq"] if durable is not None else None
            sha = digest(raw)
            if event_id in self._seen:
                if self._seen[event_id] != sha:
                    self.reject("volatile_feed_event_identity_changed")
                return None
            size = len(frame.data.encode())
            if size > self.max_event_bytes:
                self._gap(ref)
                return None
            return PreparedEvent(
                ScopedLiveEvent(ref, epoch, event_id, seq, kind, frame.data), sha, size
            )
        except (ValueError, TypeError, KeyError, RecursionError):
            if self.closed:
                raise
            self.reject("volatile_feed_invalid_frame")
        return None

    def _commit(
        self, prepared: PreparedEvent, *, receipted: bool = False
    ) -> ScopedLiveEvent | None:
        epoch = self.require_live()
        item, sha, size = prepared.item, prepared.sha256, prepared.size
        if item.connection_epoch != epoch:
            self.reject("volatile_feed_generation_changed")
        if item.native_id in self._seen:
            if self._seen[item.native_id] != sha:
                self.reject("volatile_feed_event_identity_changed")
            return None
        sid, seq = item.reference.upstream_session_id, item.native_seq
        previous = self._positions.get(sid)
        if seq is not None and previous is not None and seq <= previous:
            self.reject("volatile_feed_native_position_regressed")
        if (
            len(self._queue) >= self.max_events
            or (not receipted and len(self._seen) >= self.max_events)
            or self._retained_bytes + size > self.max_bytes
        ):
            self.reject("volatile_feed_capacity_exceeded")
        if receipted and len(self._seen) >= self.max_events:
            del self._seen[next(iter(self._seen))]
        self._seen[item.native_id] = sha
        self.revision += 1
        self._revisions[sid] = self._revisions.get(sid, 0) + 1
        if not (
            self.profile.sha256 == STATE_NEUTRAL_TEXT_SCHEMA
            and item.event_type == "session.text.delta"
            and seq is None
        ):
            self._state_revisions[sid] = self._state_revisions.get(sid, 0) + 1
        if seq is not None:
            self._positions[sid] = seq
        item = replace(item, observation_revision=self.revision)
        self._queue.append(item)
        self._retained_bytes += size
        return item

    def accept(self, frame: SSEFrame) -> ScopedLiveEvent | None:
        prepared = self._prepare(frame)
        return self._commit(prepared) if prepared else None

    async def accept_receipted(
        self, frames: tuple[SSEFrame, ...], receipts: FeedReceiptStore
    ) -> tuple[ScopedLiveEvent, ...]:
        if len(frames) > 128:
            self.reject("volatile_feed_batch_too_large")
        prepared = tuple(p for frame in frames if (p := self._prepare(frame)) is not None)
        if not prepared:
            return ()
        values = tuple(
            FeedEventReceipt(
                reference=p.item.reference,
                owner_epoch=self.owner_epoch,
                connection_epoch=p.item.connection_epoch,
                contract_sha256=self.profile.sha256,
                native_id=p.item.native_id,
                event_type=p.item.event_type,
                native_seq=p.item.native_seq,
                event_sha256=p.sha256,
            )
            for p in prepared
        )
        try:
            new = await receipts.record_many(values)
            self.require_live()
            if len(new) != len(prepared) or any(type(v) is not bool for v in new):
                self.reject("volatile_feed_receipt_result_invalid")
            return tuple(
                item
                for p, accepted in zip(prepared, new, strict=True)
                if accepted and (item := self._commit(p, receipted=True)) is not None
            )
        except BaseException:
            self.invalidate("volatile_feed_receipt_unavailable")
            raise


class V2PublicFeed:
    """One explicitly started feed; no automatic reconnect or native mutation."""

    # Trusted one-time composition only. All detached graph proofs/guards share this
    # feed, so they observe one readiness pointer. Absent means legacy behavior.
    agent_configuration: Any = None

    def __init__(
        self,
        transport: V2HTTPTransport,
        owner: LinuxHostOwnerProbe,
        references: tuple[SessionRef, ...],
        *,
        receipts: FeedReceiptStore | None = None,
        capture_text: bool = False,
    ) -> None:
        if any(
            r.backend_id != owner.enrollment.backend_id
            or r.backend_identity != owner.enrollment.backend_identity
            for r in references
        ):
            raise ValueError("public_feed_owner_scope_mismatch")
        if capture_text and receipts is None:
            raise ValueError("visible_text_requires_durable_dedup")
        self.receipts, self.capture_text = receipts, capture_text
        self.visible_text: VisibleTextCapture | None = None
        self.transport, self.owner, self.references = transport, owner, references
        self.index: VolatileFeedIndex | None = None
        self.task: asyncio.Task[None] | None = None
        self.ready = asyncio.Event()
        self.started_at: float | None = None
        self.buffer_peak_bytes = 0

    async def start(self) -> None:
        if self.task is not None or self.index is not None:
            raise ContractError("public_feed_already_started")
        self.check_contract()
        initial = await self.owner.read()
        self.index = VolatileFeedIndex(self.transport.profile, self.references, initial.owner_epoch)
        if self.capture_text:
            from jt_oz_bridge.adapters.opencode.live_text import VisibleTextCapture

            self.visible_text = VisibleTextCapture(self.index)
        self.task = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self.ready.wait(), timeout=10)
            await self.current_owner()
            self.started_at = time.time()
        except BaseException:
            await self.close()
            raise

    async def _run(self) -> None:
        assert self.index is not None
        frames = self.transport.events(
            "event.subscribe",
            oversized_event_bytes=self.index.max_event_bytes + FRAME_ALLOWANCE,
        )
        try:
            if self.receipts is None:
                async for frame in frames:
                    self.index.accept(frame)
                    if self.index.connection_epoch is not None:
                        self.ready.set()
            else:
                await self._run_receipted(frames)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Do not leak provider payloads through exception logs or tasks.
            self.index.invalidate("public_feed_failed")
        finally:
            self.index.invalidate("public_feed_disconnected")
            if self.visible_text is not None:
                self.visible_text.clear()
            self.ready.set()
            await frames.aclose()

    async def _run_receipted(self, frames: Any) -> None:
        # A bounded reader queue provides backpressure; a 25ms/128-frame batch
        # amortizes SQLite encryption/commit without waiting for the next token.
        queue: asyncio.Queue[tuple[SSEFrame, int] | None] = asyncio.Queue(maxsize=128)
        budget = asyncio.Condition()
        buffered_bytes = 0
        assert self.index is not None
        byte_limit = self.index.max_bytes

        async def read() -> None:
            nonlocal buffered_bytes
            marker_queued = False
            try:
                async for frame in frames:
                    if frame.truncated:
                        assert self.index is not None
                        if not marker_queued:
                            self.index.reject("volatile_feed_not_live")
                        self.index.discard_truncated(frame)
                        del frame
                        continue
                    self.transport.profile.sse_frame(
                        "event.subscribe",
                        event=frame.event,
                        data=frame.data,
                        event_id=frame.event_id,
                    )
                    raw = strict_loads(frame.data)
                    kind = raw.get("type")
                    if (
                        kind == "server.connected"
                        or isinstance(kind, str)
                        and ".reasoning." in kind
                    ):
                        if kind == "server.connected":
                            marker_queued = True
                        else:
                            assert self.index is not None
                            if not marker_queued:
                                self.index.reject("volatile_feed_not_live")
                            self.index._scope(raw)
                            del raw, frame
                            continue  # No private reasoning in our raw batch queue.
                    assert self.index is not None
                    self.index._notice_arrival(raw)
                    size = len(frame.data.encode())
                    if size > self.index.max_event_bytes:
                        self.index.discard_oversized(raw)
                        del raw, frame
                        continue  # Never queued; its Root's fences already changed.
                    del raw
                    if size > byte_limit:
                        assert self.index is not None
                        self.index.reject("volatile_feed_capacity_exceeded")
                    async with budget:
                        while buffered_bytes + size > byte_limit:
                            await budget.wait()
                        buffered_bytes += size
                        self.buffer_peak_bytes = max(self.buffer_peak_bytes, buffered_bytes)
                    await queue.put((frame, size))
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # The consumer sees EOF; never log private provider data.
            await queue.put(None)

        reader = asyncio.create_task(read())
        try:
            done = False
            while not done:
                first = await queue.get()
                if first is None:
                    break
                batch = [first[0]]
                batch_bytes = first[1]
                deadline = asyncio.get_running_loop().time() + 0.025
                while len(batch) < 128:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        break
                    try:
                        following = await asyncio.wait_for(queue.get(), remaining)
                    except TimeoutError:
                        break
                    if following is None:
                        done = True
                        break
                    batch.append(following[0])
                    batch_bytes += following[1]
                assert self.index is not None and self.receipts is not None
                items = await self.index.accept_receipted(tuple(batch), self.receipts)
                if self.visible_text is not None:
                    for item in items:
                        self.visible_text.observe(item)
                if self.index.connection_epoch is not None:
                    self.ready.set()
                async with budget:
                    buffered_bytes -= batch_bytes
                    budget.notify_all()
        finally:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)

    def check_contract(self) -> None:
        a = self.transport.attestation
        if (
            a is None
            or str(self.transport.client.base_url) != self.owner.enrollment.url + "/"
            or a.backend_identity != self.owner.enrollment.backend_identity
            or a.schema_sha256 != self.transport.profile.sha256
            or a.upstream_version != self.owner.enrollment.version
            or "event.subscribe" not in a.verified_operations
        ):
            raise ContractError("public_feed_installed_contract_unattested")

    async def current_owner(self) -> HostOwnerEvidence:
        if self.index is None or self.task is None or self.task.done():
            raise ContractError("public_feed_not_running")
        self.index.require_live()
        try:
            self.check_contract()
            proof = await self.owner.read()
            if proof.owner_epoch != self.index.owner_epoch:
                raise ContractError("public_feed_owner_changed")
            self.check_contract()
            self.index.require_live()
            if self.task.done():
                raise ContractError("public_feed_not_running")
            return proof
        except BaseException:
            self.index.invalidate("public_feed_owner_unavailable")
            raise

    async def enroll_reference(
        self, reference: SessionRef, *, authorize: Callable[[], Awaitable[bool]]
    ) -> None:
        """Append an explicitly authorized same-project Root without reconnecting.

        Missing earlier events are not replayed or synthesized. The enrollment
        controller must still watch fresh resources and qualify the new Root.
        """
        self.check_contract()
        owner = await self.current_owner()
        index = self.index
        assert index is not None
        epoch = index.require_live()
        captured = self.transport.attestation
        if not any(
            (r.backend_id, r.backend_identity, r.project_id, r.canonical_directory)
            == (
                reference.backend_id,
                reference.backend_identity,
                reference.project_id,
                reference.canonical_directory,
            )
            for r in self.references
        ):
            raise ContractError("new_feed_reference_outside_existing_project")
        self.transport.profile.prepare(
            "session.get", path={"sessionID": reference.upstream_session_id}
        )
        if await authorize() is not True:
            raise ContractError("new_feed_reference_authority_changed")
        after = await self.current_owner()
        if (
            self.index is not index
            or index.require_live() != epoch
            or owner.owner_epoch != after.owner_epoch
            or self.transport.attestation is not captured
        ):
            raise ContractError("new_feed_reference_original_connection_changed")
        existing = index.references.get(reference.upstream_session_id)
        if existing is not None:
            if existing != reference or reference not in self.references:
                raise ContractError("new_feed_reference_native_identity_conflict")
            return
        if len(self.references) >= 1000:
            raise ContractError("new_feed_reference_capacity_reached")
        # No await between these two append-only views: existing event fences,
        # receipts, queue positions and references remain exactly as they were.
        index.references = MappingProxyType(
            {**index.references, reference.upstream_session_id: reference}
        )
        self.references = (*self.references, reference)

    async def close(self) -> None:
        if self.index is not None:
            self.index.invalidate("public_feed_closed")
        if self.visible_text is not None:
            self.visible_text.clear()
        if self.task is not None:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
