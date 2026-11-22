"""Original Native message pages; never synthetic Human inputs or replay events."""

import math
import time
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import OriginalExecutionProof
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    V2TurnResourceReader,
    selected_message,
)
from jt_oz_bridge.domain.control import ControlModel, ExecutionState, SessionSnapshot
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

MessageKind = Literal[
    "user",
    "assistant",
    "idle",
    "agent-switched",
    "model-switched",
    "location-switched",
    "synthetic",
    "system",
    "skill",
    "shell",
    "compaction",
]


class TranscriptEntry(ControlModel):
    native_id: str = Field(min_length=1, max_length=255)
    kind: MessageKind
    projection_json: str = Field(max_length=2 * 1024 * 1024)
    projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent(self) -> "TranscriptEntry":
        value = self.projection()
        if (
            value.get("id") != self.native_id
            or value.get("type") != self.kind
            or digest(value) != self.projection_sha256
        ):
            raise ValueError("native_transcript_projection_identity_changed")
        return self

    def projection(self) -> dict[str, Any]:
        result = strict_loads(self.projection_json)
        if not isinstance(result, dict):
            raise ValueError("native_transcript_projection_object_required")
        return result

    def sha256_before_tool_calls(self) -> str:
        """A record saved before tool names (or token counts) were kept is not a new version."""
        value = self.projection()
        value.pop("tokens", None)
        for part in value.get("content", ()):
            if isinstance(part, dict):
                part.pop("calls", None)
        return digest(value)

    def sha256_without_tokens(self) -> str:
        value = self.projection()
        value.pop("tokens", None)
        return digest(value)

    def context_tokens(self) -> int | None:
        """How much context a finished step read: its input, cached or not."""
        tokens = self.projection().get("tokens")
        if not isinstance(tokens, dict):
            return None
        values = [tokens.get(key) for key in ("input", "cache_read", "cache_write")]
        if not all(type(v) is int for v in values):
            return None
        return sum(cast(list[int], values))


def same_message(old: TranscriptEntry, new: TranscriptEntry) -> bool:
    """Whether ``new`` shows what ``old`` showed: token counts are not content.

    A record saved before tool names or token counts were kept is the same message
    as its re-read that has them.
    """
    return old.projection_sha256 == new.projection_sha256 or old.sha256_without_tokens() in {
        new.sha256_without_tokens(),
        new.sha256_before_tool_calls(),
    }


# A count no real step reaches; a larger one is kept as this.
TOKEN_LIMIT = 10**12


def token_counts(raw: dict[str, Any]) -> dict[str, int] | None:
    """A finished step's token counts, whole numbers only; anything else leaves them out."""
    tokens = raw.get("tokens")
    cache = tokens.get("cache") if isinstance(tokens, dict) else None
    if not isinstance(tokens, dict) or not isinstance(cache, dict):
        return None
    values: dict[str, Any] = {
        "input": tokens.get("input"),
        "output": tokens.get("output"),
        "reasoning": tokens.get("reasoning"),
        "cache_read": cache.get("read"),
        "cache_write": cache.get("write"),
    }
    if any(type(v) not in {int, float} or not math.isfinite(v) or v < 0 for v in values.values()):
        return None
    return {key: min(int(v), TOKEN_LIMIT) for key, v in values.items()}


def tool_calls(part: dict[str, Any]) -> list[dict[str, str]]:
    """Names of the MCP tools a code-mode step ran; their arguments and results stay out."""
    listed = part["state"].get("metadata", {}).get("toolCalls")
    if not isinstance(listed, list):
        return []
    return [
        {"tool": call["tool"][:200], "status": str(call.get("status", ""))[:32]}
        for call in listed[:20]
        if isinstance(call, dict) and isinstance(call.get("tool"), str)
    ]


def project_message(raw: dict[str, Any]) -> TranscriptEntry:
    # The transport already validated the exact installed union. Only selected
    # display fields enter a witness; reasoning/system instructions, metadata,
    # tool arguments/results and shell output never enter this channel.
    value = selected_message(raw)
    value.pop("metadata", None)
    kind = raw["type"]
    if kind == "assistant":
        for part in value["content"]:
            if part["type"] == "tool" and (calls := tool_calls(raw["content"][part["index"]])):
                part["calls"] = calls
        value["agent"] = raw["agent"]
        value["model"] = native_ref(raw["model"]).wire()
        # Numbers only, once the step is finished: how long the context has grown.
        if "completed" in raw["time"] and (tokens := token_counts(raw)) is not None:
            value["tokens"] = tokens
    elif kind == "agent-switched":
        value["agent"] = raw["agent"]
    elif kind in {"shell", "compaction"}:
        value["status"] = raw["status"]
        if type(raw.get("exit")) is int:
            value["exit"] = raw["exit"]
    return TranscriptEntry(
        native_id=raw["id"],
        kind=kind,
        projection_json=checked_json(value).decode(),
        projection_sha256=digest(value),
    )


class NativeTranscriptPage(ControlModel):
    format: Literal["v2-native-transcript-page-v1"] = "v2-native-transcript-page-v1"
    reference: SessionRef
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    owner_epoch: str
    connection_epoch: str
    resource_fence: str
    session_info_sha256: str
    state: ExecutionState
    witness_id: str
    observed_at: float
    expires_at: float
    cursor: str | None
    limit: StrictInt = Field(ge=1, le=20)
    next_cursor: str | None
    entries: tuple[TranscriptEntry, ...] = Field(max_length=20)


class TranscriptReader(Protocol):
    def contract_for(self, reference: SessionRef) -> str: ...
    async def capture(
        self, reference: SessionRef, *, cursor: str | None = None, limit: int = 20
    ) -> NativeTranscriptPage: ...
    def current(self, page: NativeTranscriptPage) -> bool: ...
    async def snapshot(self, reference: SessionRef) -> SessionSnapshot: ...


class V2TranscriptReader:
    def __init__(self, qualified: V2TurnResourceReader) -> None:
        self.qualified, self.client = qualified, qualified.client
        self._pages: dict[
            str, tuple[NativeTranscriptPage, OriginalExecutionProof, object, int]
        ] = {}

    def contract_for(self, reference: SessionRef) -> str:
        self.qualified.qualify(reference)
        return self.client.contract_for(reference)

    def change_token(self, reference: SessionRef) -> str:
        """Scheduling hint only; never an ACL, state or replay authority."""
        self.contract_for(reference)
        feed = self.qualified.proofs.feed
        if feed.index is None:
            raise ContractError("transcript_feed_not_started")
        return digest(
            {
                "epoch": self.qualified.proofs.generation(reference),
                "state_revision": feed.index.state_revision_for(reference),
            }
        )

    def draft_change_token(self, reference: SessionRef) -> str:
        """Wake coalesced resource reads on text too; never supply output authority."""
        self.contract_for(reference)
        feed = self.qualified.proofs.feed
        if feed.index is None:
            raise ContractError("transcript_feed_not_started")
        return digest(
            {
                "epoch": self.qualified.proofs.generation(reference),
                "revision": feed.index.revision_for(reference),
            }
        )

    async def snapshot(self, reference: SessionRef) -> SessionSnapshot:
        self.contract_for(reference)
        return await self.client.snapshot(reference)

    async def read_page(
        self, reference: SessionRef, cursor: str | None, limit: int
    ) -> tuple[tuple[TranscriptEntry, ...], str | None]:
        query = {"limit": str(limit)}
        if cursor is not None:
            query["cursor"] = cursor
        else:
            # The installed operation explicitly forbids order with a cursor;
            # the opaque Native continuation already carries its order.
            query["order"] = "desc"
        value = await self.client.transport.request(
            "session.message.list", path={"sessionID": reference.upstream_session_id}, query=query
        )
        items = value["data"]
        following = value["cursor"].get("next")
        if (
            len(items) > limit
            or len({m["id"] for m in items}) != len(items)
            or following is not None
            and (
                not isinstance(following, str)
                or not 1 <= len(following) <= 8192
                or following == cursor
                or not items
            )
        ):
            raise ContractError("native_transcript_page_boundary_invalid")
        return tuple(project_message(raw) for raw in items), following

    async def capture(
        self, reference: SessionRef, *, cursor: str | None = None, limit: int = 20
    ) -> NativeTranscriptPage:
        if (
            type(limit) is not int
            or not 1 <= limit <= 20
            or cursor is not None
            and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 8192)
        ):
            raise ValueError("native_transcript_page_request_invalid")
        self.contract_for(reference)
        qualification = self.qualified.attestation
        before_owner = await self.qualified.proofs.feed.current_owner()
        _, before = await self.client.qualified_snapshot(reference)
        first = await self.read_page(reference, cursor, limit)
        second = await self.read_page(reference, cursor, limit)
        _, after = await self.client.qualified_snapshot(reference)
        owner = await self.qualified.proofs.feed.current_owner()
        self.contract_for(reference)
        self.client.current(reference, before)
        self.client.current(reference, after)
        if (
            first != second
            or before_owner.owner_epoch != owner.owner_epoch
            or self.qualified.attestation is not qualification
            or (
                before.session_info_sha256,
                before.connection_epoch,
                before.resource_fence,
                before.state,
            )
            != (
                after.session_info_sha256,
                after.connection_epoch,
                after.resource_fence,
                after.state,
            )
        ):
            raise ContractError("native_transcript_page_changed_during_capture")
        assert qualification is not None and after.resource_fence is not None
        now = time.time()
        page = NativeTranscriptPage(
            reference=reference,
            contract_sha256=INSTALLED_SCHEMA,
            semantics_sha256=RESOURCE_SEMANTICS,
            installed_evidence_sha256=qualification.installed_evidence_sha256,
            owner_epoch=owner.owner_epoch,
            connection_epoch=after.connection_epoch,
            resource_fence=after.resource_fence,
            session_info_sha256=after.session_info_sha256,
            state=after.state,
            witness_id=str(uuid4()),
            observed_at=now,
            expires_at=min(before.expires_at, after.expires_at),
            cursor=cursor,
            limit=limit,
            next_cursor=second[1],
            entries=second[0],
        )
        size = len(checked_json(page.model_dump(mode="json")))
        if size > 4 * 1024 * 1024:
            raise ContractError("native_transcript_page_capacity")
        while self._pages and (
            len(self._pages) >= 16
            or sum(v[3] for v in self._pages.values()) + size > 8 * 1024 * 1024
        ):
            self._pages.pop(next(iter(self._pages)))
        self._pages[page.witness_id] = (page, after, qualification, size)
        return page

    def current(self, page: NativeTranscriptPage) -> bool:
        try:
            saved = self._pages.get(page.witness_id)
            if (
                saved is None
                or saved[0] is not page
                or self.qualified.attestation is not saved[2]
                or not page.observed_at <= time.time() < page.expires_at
                or self.contract_for(page.reference) != page.contract_sha256
            ):
                return False
            self.client.current(page.reference, saved[1])
            return True
        except (TypeError, ValueError):
            return False
