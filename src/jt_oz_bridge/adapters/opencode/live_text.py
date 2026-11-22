"""Visible-only volatile fragments with provenance distinct from API history."""

from collections import OrderedDict
from typing import Literal

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.live import (
    STATE_NEUTRAL_TEXT_SCHEMA,
    ScopedLiveEvent,
    VolatileFeedIndex,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import digest


class VisibleTextPart(ControlModel):
    ordinal: StrictInt = Field(ge=0)
    text: str
    prefix_missing: bool
    ended: bool = False
    truncated: bool = False


class VisibleTextSnapshot(ControlModel):
    format: Literal["original-visible-text-capture-v1"] = "original-visible-text-capture-v1"
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    connection_epoch: str = Field(pattern=r"^[0-9a-f]{64}$")
    assistant_id: str = Field(min_length=1, max_length=255)
    revision: StrictInt = Field(ge=1)
    observation_revision: StrictInt = Field(ge=1)
    first_event_id: str = Field(min_length=1, max_length=255)
    last_event_id: str = Field(min_length=1, max_length=255)
    last_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_chain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parts: tuple[VisibleTextPart, ...] = Field(max_length=64)
    omitted_parts: bool = False
    may_have_gaps: Literal[True] = True

    @model_validator(mode="after")
    def bounded(self) -> "VisibleTextSnapshot":
        if (
            self.contract_sha256 != STATE_NEUTRAL_TEXT_SCHEMA
            or sum(len(part.text.encode()) for part in self.parts) > 64 * 1024
            or [p.ordinal for p in self.parts] != sorted({p.ordinal for p in self.parts})
        ):
            raise ValueError("visible_text_snapshot_scope_or_bounds_invalid")
        return self

    @property
    def source_key(self) -> str:
        return digest(
            {
                "reference": self.reference.model_dump(mode="json"),
                "owner_epoch": self.owner_epoch,
                "connection_epoch": self.connection_epoch,
                "assistant_id": self.assistant_id,
                "first_event_id": self.first_event_id,
            }
        )

    @property
    def id(self) -> str:
        return digest(self.model_dump(mode="json"))

    @property
    def text(self) -> str:
        return "\n\n".join(part.text for part in self.parts)


class VisibleTextCapture:
    """One index generation, bounded preview memory; no execution/final authority.

    Observe accepts only the original object still owned by this index. Copying
    an event DTO cannot turn it into an admitted stream source. Even snapshots
    restored from own SQL are archival evidence, never current source authority.
    """

    def __init__(
        self,
        index: VolatileFeedIndex,
        *,
        max_messages: int = 32,
        max_parts: int = 64,
        message_bytes: int = 32 * 1024,
    ) -> None:
        if any(type(v) is not int or v < 1 for v in (max_messages, max_parts, message_bytes)):
            raise ValueError("positive_visible_capture_limits_required")
        if max_messages > 128 or max_parts > 64 or message_bytes > 64 * 1024:
            raise ValueError("visible_capture_hard_ceiling_exceeded")
        if index.profile.sha256 != STATE_NEUTRAL_TEXT_SCHEMA:
            raise ContractError("visible_text_installed_schema_required")
        self.index, self.max_messages, self.max_parts, self.message_bytes = (
            index,
            max_messages,
            max_parts,
            message_bytes,
        )
        self._values: OrderedDict[str, VisibleTextSnapshot] = OrderedDict()
        self._observed: dict[str, None] = {}
        self.evictions = 0

    def observe(self, event: ScopedLiveEvent) -> None:
        if not self.index.owns(event):
            raise ContractError("visible_text_event_not_index_owned")
        if self.index.profile.sha256 != STATE_NEUTRAL_TEXT_SCHEMA:
            raise ContractError("visible_text_installed_schema_required")
        if event.event_type not in {
            "session.text.started",
            "session.text.delta",
            "session.text.ended",
        }:
            return
        if event.native_id in self._observed:
            return
        raw = event.payload()
        data = raw["data"]
        assistant, ordinal = data.get("assistantMessageID"), data.get("ordinal")
        if (
            not isinstance(assistant, str)
            or not assistant
            or type(ordinal) is not int
            or ordinal < 0
        ):
            raise ContractError("visible_text_installed_fields_required")
        key = digest({"reference": event.reference.model_dump(mode="json"), "assistant": assistant})
        old = self._values.get(key)
        parts = {part.ordinal: part for part in old.parts} if old else {}
        previous = parts.get(ordinal)
        omitted = old.omitted_parts if old else False
        kind = event.event_type
        if previous is None and len(parts) >= self.max_parts:
            omitted = True
        else:
            if kind == "session.text.started":
                if previous is not None:
                    raise ContractError("visible_text_part_started_twice")
                part = VisibleTextPart(ordinal=ordinal, text="", prefix_missing=False)
            elif kind == "session.text.delta":
                delta = data.get("delta")
                if not isinstance(delta, str) or (previous and previous.ended):
                    raise ContractError("visible_text_delta_boundary_changed")
                part = (
                    previous or VisibleTextPart(ordinal=ordinal, text="", prefix_missing=True)
                ).model_copy(update={"text": (previous.text if previous else "") + delta})
            else:
                text = data.get("text")
                if not isinstance(text, str) or (previous and previous.ended):
                    raise ContractError("visible_text_end_boundary_changed")
                # This is the event's full-value boundary, still not an API
                # snapshot or a claim that the original task succeeded.
                part = VisibleTextPart(ordinal=ordinal, text=text, prefix_missing=False, ended=True)
            other_size = sum(len(v.text.encode()) for n, v in parts.items() if n != ordinal)
            remaining = max(0, self.message_bytes - other_size)
            encoded = part.text.encode()
            if len(encoded) > remaining:
                part = part.model_copy(
                    update={
                        "text": encoded[:remaining].decode("utf-8", errors="ignore"),
                        "truncated": True,
                    }
                )
            parts[ordinal] = part
        value = VisibleTextSnapshot(
            reference=event.reference,
            contract_sha256=self.index.profile.sha256,
            owner_epoch=self.index.owner_epoch,
            connection_epoch=event.connection_epoch,
            assistant_id=assistant,
            revision=(old.revision + 1 if old else 1),
            observation_revision=event.observation_revision,
            first_event_id=old.first_event_id if old else event.native_id,
            last_event_id=event.native_id,
            last_event_sha256=digest(raw),
            event_chain_sha256=digest(
                {
                    "previous": old.event_chain_sha256 if old else None,
                    "event_sha256": digest(raw),
                }
            ),
            parts=tuple(parts[n] for n in sorted(parts)),
            omitted_parts=omitted,
        )
        if key not in self._values and len(self._values) >= self.max_messages:
            self._values.popitem(last=False)
            self.evictions += 1
        self._values[key] = value
        self._values.move_to_end(key)
        if len(self._observed) >= self.index.max_events:
            del self._observed[next(iter(self._observed))]
        self._observed[event.native_id] = None

    def snapshots(self) -> tuple[VisibleTextSnapshot, ...]:
        self.index.require_live()
        if self.index.profile.sha256 != STATE_NEUTRAL_TEXT_SCHEMA:
            raise ContractError("visible_text_installed_schema_required")
        return tuple(self._values.values())

    def current(self, value: VisibleTextSnapshot) -> bool:
        self.index.require_live()
        return value.connection_epoch == self.index.connection_epoch and any(
            item is value for item in self._values.values()
        )

    def clear(self) -> None:
        self._values.clear()
        self._observed.clear()
