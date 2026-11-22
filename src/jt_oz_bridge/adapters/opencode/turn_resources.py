"""Bounded projected-message evidence for a single isolated admitted input.

These are native resources, never invented bus events or replay positions. A
later user/synthetic/control input prevents attributing its idle to an older turn,
except a bridge prompt steered into the same busy period: the input owns the
replies up to that steer, and both share the busy period's one idle.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from jt_oz_bridge.adapters.opencode.attachments import (
    ATTACHMENT_SEMANTICS,
    InlineAttachmentAttestation,
    projected_files,
)
from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.model_catalog import native_ref
from jt_oz_bridge.adapters.opencode.model_settings import MODEL_SETTING_SEMANTICS
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, V2LeafResourceProofs
from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    NativeAttachmentProjection,
)
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.json_data import strict_loads
from jt_oz_bridge.storage.cipher_types import checked_json
from jt_oz_bridge.storage.durable import digest

LOG = logging.getLogger(__name__)
# A refused result is read again about every second; name its cause at most this often.
BOUNDARY_DETAIL_SECONDS = 600

RESOURCE_SOURCES = {
    "projector.ts": "b2145973cd8ae49fdbde760cb4277ed61113669447583805fcbd2669ced304b1",
    "store.ts": "50f2638f6ca183ed39f524003cc646af8308977e134fa2432d9bca0f3798ea06",
    "message-updater.ts": "40d7a2ae2852db7b4c985ed0c2c8cfbebb92a91a3d60e3007b37b4f282703ee2",
}
RESOURCE_SEMANTICS = digest({"version": "2.0.32", "sources": RESOURCE_SOURCES})
RESOURCE_TYPES = frozenset(
    {
        "projected-user-delivery",
        "isolated-idle-terminal",
        "message-store-seq-order",
        "final-assistant-text",
    }
)


class TurnCorrelation(ControlModel):
    reference: SessionRef
    action_id: str = Field(min_length=1, max_length=255)
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    upstream_id: str = Field(min_length=1, max_length=255)
    text: str = Field(max_length=1000000)
    attachments: tuple[NativeAttachmentProjection, ...] = Field(
        default=(), max_length=MAX_ATTACHMENTS
    )
    attachment_semantics_sha256: str | None = None

    workspace_projection_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def qualified_attachment_projection(self) -> "TurnCorrelation":
        if (
            self.workspace_projection_sha256 is not None
            and bool(self.attachments)
            or bool(self.attachments) != (self.attachment_semantics_sha256 is not None)
            or self.attachments
            and self.attachment_semantics_sha256 != ATTACHMENT_SEMANTICS
            or sum(file.size for file in self.attachments) > MAX_ATTACHMENT_BYTES
        ):
            raise ValueError("native_turn_attachment_projection_or_semantics_invalid")
        return self

    @model_serializer(mode="wrap")
    def preserve_text_seals(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if not self.attachments:
            value.pop("attachments", None)
            value.pop("attachment_semantics_sha256", None)
        if self.workspace_projection_sha256 is None:
            value.pop("workspace_projection_sha256", None)
        return value


class ResourceText(ControlModel):
    assistant_id: str
    content_index: int = Field(ge=0)
    text: str = Field(max_length=1000000)


class ResourceTool(ControlModel):
    assistant_id: str
    content_index: int = Field(ge=0)
    tool_id: str
    name: str
    status: Literal["completed", "error"]
    exit_code: int | None = None
    error_sha256: str | None = None


class ProjectedTurn(ControlModel):
    user_id: str
    user_projection_sha256: str
    terminal_id: str
    terminal_projection_sha256: str
    terminal_created: float
    outcome: Literal["succeeded", "failed", "interrupted"]
    terminal_error_sha256: str | None = None
    text: tuple[ResourceText, ...]
    tools: tuple[ResourceTool, ...]
    ordered_message_ids: tuple[str, ...]
    selected_projection_sha256: str
    setting_message_ids: tuple[str, ...] = Field(default=(), max_length=1000)
    # Only when later turns follow this input's own idle: the session's newest idle.
    session_terminal_created: float | None = None
    session_outcome: Literal["succeeded", "failed", "interrupted"] | None = None

    @model_validator(mode="after")
    def session_terminal_pair(self) -> "ProjectedTurn":
        if (self.session_terminal_created is None) != (self.session_outcome is None):
            raise ValueError("native_resource_session_terminal_incomplete")
        return self

    @model_serializer(mode="wrap")
    def preserve_turn_seals(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if self.session_terminal_created is None:
            value.pop("session_terminal_created", None)
            value.pop("session_outcome", None)
        return value

    @property
    def latest_created(self) -> float:
        """The session's current idle time, which a fresh capture must still see."""
        return (
            self.session_terminal_created
            if self.session_terminal_created is not None
            else self.terminal_created
        )

    @property
    def latest_outcome(self) -> str:
        return self.session_outcome if self.session_outcome is not None else self.outcome


def steered_input(message: dict[str, Any], correlation: TurnCorrelation) -> bool:
    """Another bridge prompt delivered into this input's busy period."""
    tag = message.get("metadata", {}).get("jt_oz_bridge")
    return (
        message["type"] == "user"
        and isinstance(tag, dict)
        and set(tag) == {"action_id", "operation_digest"}
        and isinstance(tag["action_id"], str)
        and isinstance(tag["operation_digest"], str)
        and tag["action_id"] != correlation.action_id
    )


class NativeResourceTurn(ControlModel):
    format: Literal["v2-native-resource-turn-v1"] = "v2-native-resource-turn-v1"
    correlation: TurnCorrelation
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    connection_epoch: str
    owner_epoch: str
    ownership_evidence_sha256: str
    session_info_sha256: str
    resource_fence: str
    observed_at: float
    expires_at: float
    turn: ProjectedTurn
    model_settings_semantics_sha256: str | None = None
    model_settings_evidence_sha256: str | None = None
    attachment_semantics_sha256: str | None = None
    attachment_evidence_sha256: str | None = None

    @model_serializer(mode="wrap")
    def preserve_text_seals(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if self.attachment_semantics_sha256 is None and self.attachment_evidence_sha256 is None:
            value.pop("attachment_semantics_sha256", None)
            value.pop("attachment_evidence_sha256", None)
        return value


@dataclass(frozen=True)
class ResourceSemanticAttestation:
    backend_id: str
    backend_identity: str
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    verified_types: frozenset[str]
    verified_outcomes: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "verified_types", frozenset(self.verified_types))
        object.__setattr__(self, "verified_outcomes", frozenset(self.verified_outcomes))


def selected_message(
    message: dict[str, Any], *, with_attachment_receipts: bool = False
) -> dict[str, Any]:
    """Retain no reasoning, agent system data or tool input/output body."""
    safe = {k: message[k] for k in ("id", "type", "time")}
    if message["type"] == "user":
        safe["text"] = message["text"]
        safe["metadata"] = {"jt_oz_bridge": message.get("metadata", {}).get("jt_oz_bridge")}
        safe["attachments_present"] = any(message.get(k) for k in ("files", "agents", "skills"))
        if with_attachment_receipts:
            if message.get("agents") or message.get("skills"):
                raise ContractError("native_resource_unqualified_agent_or_skill_attachment")
            safe["attachments"] = list(
                projected_files(message.get("files"), verify_detected_mime=True)
            )
    elif message["type"] == "idle":
        safe["outcome"] = message["outcome"]
        if "error" in message:
            safe["error_sha256"] = digest(message["error"])
    elif message["type"] == "assistant":
        content = []
        for i, part in enumerate(message["content"]):
            if part["type"] == "text":
                content.append({"type": "text", "index": i, "text": part["text"]})
            elif part["type"] == "tool":
                state = part["state"]
                p = {
                    "type": "tool",
                    "index": i,
                    "id": part["id"],
                    "name": part["name"],
                    "status": state["status"],
                    "time": part["time"],
                }
                if "exit" in state.get("metadata", {}):
                    exit_code = state["metadata"]["exit"]
                    if type(exit_code) is not int or not -(2**31) <= exit_code < 2**31:
                        raise ContractError("native_tool_exit_code_not_integer")
                    p["exit_code"] = exit_code
                if "error" in state:
                    p["error_sha256"] = digest(state["error"])
                content.append(p)
        safe["content"] = content
    elif message["type"] == "model-switched":
        safe["model"] = native_ref(message["model"]).wire()
        safe["previous"] = native_ref(message["previous"]).wire() if "previous" in message else None
    elif message["type"] == "compaction":
        reason = message.get("reason")
        safe["reason"] = reason if isinstance(reason, str) and len(reason) <= 64 else None
    return safe


def housekeeping(message: dict[str, Any]) -> bool:
    """A record OpenCode writes by itself inside a running turn, never a person's input.

    `system` is an instructions refresh (for example after a reload) and an `auto`
    compaction shortens a long context; the turn goes on after both. A compaction
    someone asked for is queued input and still counts as another turn.
    """
    return message["type"] == "system" or (
        message["type"] == "compaction" and message.get("reason") == "auto"
    )


def match_isolated_turn(
    correlation: TurnCorrelation,
    descending: list[dict[str, Any]],
    *,
    allow_model_settings: bool = False,
    allow_agent_settings: bool = False,
    allow_later_steer: bool = False,
) -> ProjectedTurn:
    """Input order is the installed native store order, never IDs or wall time.

    `allow_later_steer` is for a result collector that knows a bridge steer was
    sent after this input: that steer may have started the next busy period.
    """
    terminal_records = descending
    settings = ({"model-switched"} if allow_model_settings else set()) | (
        {"agent-switched"} if allow_agent_settings else set()
    )
    if settings:
        first = 0
        while first < len(descending) and descending[first]["type"] in settings:
            first += 1
        terminal_records = descending[first:]
    if (
        not terminal_records
        or terminal_records[0]["type"] != "idle"
        or terminal_records[-1]["id"] != correlation.upstream_id
    ):
        raise ContractError("native_resource_isolated_turn_boundary_missing")
    ascending = list(reversed(terminal_records))
    user = ascending[0]
    if user["type"] != "user":
        raise ContractError("native_resource_admission_not_projected_user")
    # This input's busy period ends at the first idle after it. Only a bridge
    # steer that arrived as that period ended may start the next one, and only
    # when the caller says one was sent; that later period cannot change this one.
    end = next(i for i, m in enumerate(ascending) if i and m["type"] == "idle")
    ordered = ascending[: end + 1]
    terminal = ordered[-1]
    # Check intervening inputs first: another turn's success cannot close this one.
    harmless = {"assistant"} | settings
    later = [m for m in ascending[end + 1 :] if m["type"] not in settings]
    if any(
        m["type"] not in harmless and not housekeeping(m) and not steered_input(m, correlation)
        for m in ordered[1:-1]
    ) or (later and (not allow_later_steer or not steered_input(later[0], correlation))):
        raise ContractError("native_resource_intervening_input_or_terminal")
    # Replies after a steered input answer that input, not this one.
    own_end = next(
        (i for i, m in enumerate(ordered[1:-1], 1) if m["type"] == "user"), len(ordered) - 1
    )
    own = ordered[1:own_end]
    newest = ascending[-1]
    attachments_match = (
        user.get("attachments_present") is True
        and user.get("attachments")
        == [file.model_dump(mode="json") for file in correlation.attachments]
        if correlation.attachments
        else user.get("attachments_present") is False and "attachments" not in user
    )
    if (
        user.get("text") != correlation.text
        or user.get("metadata", {}).get("jt_oz_bridge")
        != {"action_id": correlation.action_id, "operation_digest": correlation.operation_digest}
        or not attachments_match
    ):
        raise ContractError("native_resource_delivery_correlation_changed")
    texts = []
    tools = []
    for m in own:
        if m["type"] in settings or housekeeping(m):
            continue
        if m["time"].get("completed") is None:
            raise ContractError("native_resource_assistant_not_final")
        for part in m["content"]:
            if part["type"] == "text":
                texts.append(
                    ResourceText(
                        assistant_id=m["id"], content_index=part["index"], text=part["text"]
                    )
                )
            else:
                if (
                    part["status"] not in {"completed", "error"}
                    or part["time"].get("completed") is None
                ):
                    raise ContractError("native_resource_tool_not_terminal")
                tools.append(
                    ResourceTool(
                        assistant_id=m["id"],
                        content_index=part["index"],
                        tool_id=part["id"],
                        name=part["name"],
                        status=part["status"],
                        exit_code=part.get("exit_code"),
                        error_sha256=part.get("error_sha256"),
                    )
                )
    return ProjectedTurn(
        user_id=user["id"],
        user_projection_sha256=digest(user),
        terminal_id=terminal["id"],
        terminal_projection_sha256=digest(terminal),
        terminal_created=terminal["time"]["created"],
        outcome=terminal["outcome"],
        terminal_error_sha256=terminal.get("error_sha256"),
        text=tuple(texts),
        tools=tuple(tools),
        ordered_message_ids=tuple(m["id"] for m in (user, *own, terminal)),
        selected_projection_sha256=digest({"ordered_messages": list(reversed(descending))}),
        setting_message_ids=tuple(m["id"] for m in reversed(descending) if m["type"] in settings),
        session_terminal_created=None if newest is terminal else newest["time"]["created"],
        session_outcome=None if newest is terminal else newest["outcome"],
    )


class V2TurnResourceReader:
    def __init__(
        self,
        client: V2ExecutionClient,
        *,
        attestation: ResourceSemanticAttestation | None = None,
        attachments: InlineAttachmentAttestation | None = None,
    ) -> None:
        if not isinstance(client.proofs, V2LeafResourceProofs):
            raise ValueError("original_leaf_resource_provider_required")
        self.client, self.proofs, self.attestation = client, client.proofs, attestation
        self.attachments = attachments
        self._witnesses: dict[SessionRef, NativeResourceTurn] = {}
        self._sizes: dict[SessionRef, int] = {}
        self._boundary_logged: dict[tuple[str, str], float] = {}

    def qualify(self, ref: SessionRef) -> None:
        self.proofs.select(ref)
        a = self.attestation
        t = self.client.transport.attestation
        if (
            a is None
            or t is None
            or a.backend_id != ref.backend_id
            or a.backend_identity != ref.backend_identity
            or a.contract_sha256 != INSTALLED_SCHEMA
            or a.semantics_sha256 != RESOURCE_SEMANTICS
            or len(a.installed_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in a.installed_evidence_sha256)
            or not RESOURCE_TYPES <= a.verified_types
            or not a.verified_outcomes
            or not a.verified_outcomes <= {"succeeded", "failed", "interrupted"}
            or not {"session.get", "session.message.list"} <= t.verified_operations
            or self.client.transport is not self.proofs.feed.transport
        ):
            raise ContractError("native_projected_turn_semantics_unqualified")
        if self.proofs.model_settings is not None:
            self.proofs.model_settings.require(ref, INSTALLED_SCHEMA)

    async def page_turn(
        self, c: TurnCorrelation, *, allow_later_steer: bool = False
    ) -> ProjectedTurn:
        self.qualify(c.reference)
        self.qualify_attachments(c)
        cursor = None
        seen_cursors = set()
        seen_ids = set()
        selected = []
        total_bytes = 0
        for _ in range(20):
            query = {
                "limit": "50",
                **({"cursor": cursor} if cursor is not None else {"order": "desc"}),
            }
            value = await self.client.transport.request(
                "session.message.list",
                path={"sessionID": c.reference.upstream_session_id},
                query=query,
            )
            messages = value["data"]
            if not 1 <= len(messages) <= 50:
                raise ContractError("native_resource_admission_not_found")
            for raw in messages:
                if raw["id"] in seen_ids:
                    raise ContractError("native_resource_projection_duplicate_id")
                seen_ids.add(raw["id"])
                safe = selected_message(
                    raw, with_attachment_receipts=bool(c.attachments) and raw["id"] == c.upstream_id
                )
                total_bytes += len(checked_json(safe))
                if total_bytes > 4 * 1024 * 1024:
                    raise ContractError("native_resource_turn_capacity")
                selected.append(safe)
                if raw["id"] == c.upstream_id:
                    return match_isolated_turn(
                        c,
                        selected,
                        allow_model_settings=self.proofs.model_settings is not None,
                        allow_agent_settings=self.proofs.agent_settings_for(c.reference)
                        is not None,
                        allow_later_steer=allow_later_steer,
                    )
            cursor = value["cursor"].get("next")
            if not isinstance(cursor, str) or not cursor or len(cursor) > 8192:
                raise ContractError("native_resource_admission_not_found")
            if cursor in seen_cursors:
                raise ContractError("native_resource_cursor_repeated")
            seen_cursors.add(cursor)
        raise ContractError("native_resource_turn_page_capacity")

    def qualify_attachments(self, c: TurnCorrelation) -> None:
        if not c.attachments:
            return
        if self.attachments is None:
            raise ContractError("native_resource_attachment_semantics_unqualified")
        for file in c.attachments:
            self.attachments.require(c.reference, INSTALLED_SCHEMA, mime_type=file.mime_type)

    async def capture(
        self, correlation: TurnCorrelation, *, allow_later_steer: bool = False
    ) -> NativeResourceTurn:
        # Take a private immutable JSON snapshot before any network await.
        c = TurnCorrelation.model_validate(
            strict_loads(checked_json(correlation.model_dump(mode="json")))
        )
        ref = c.reference
        self._witnesses.pop(ref, None)
        self._sizes.pop(ref, None)
        self.qualify(ref)
        self.qualify_attachments(c)
        attestation = self.attestation
        attachments = self.attachments
        model_settings = self.proofs.model_settings
        assert attestation is not None
        before_owner = await self.proofs.feed.current_owner()
        snapshot, before = await self.client.qualified_snapshot(ref)
        if snapshot.state != ExecutionState.IDLE:
            raise ContractError("native_resource_turn_not_idle")
        a = await self.page_turn(c, allow_later_steer=allow_later_steer)
        b = await self.page_turn(c, allow_later_steer=allow_later_steer)
        final, after = await self.client.qualified_snapshot(ref)
        info = (
            await self.client.transport.request(
                "session.get", path={"sessionID": ref.upstream_session_id}
            )
        )["data"]
        last_owner = await self.proofs.feed.current_owner()
        self.qualify(ref)
        self.qualify_attachments(c)
        self.client.current(ref, before)
        self.client.current(ref, after)
        witness = self.proofs.current_witness(ref)
        # Every condition by name, so a refusal that never clears says which one holds.
        checks = (
            ("not_idle", final.state != ExecutionState.IDLE),
            ("pages_differ", a != b),
            ("no_witness", witness is None),
            ("attestation_replaced", self.attestation is not attestation),
            ("attachments_replaced", self.attachments is not attachments),
            ("model_settings_replaced", self.proofs.model_settings is not model_settings),
            ("outcome_unverified", a.outcome not in attestation.verified_outcomes),
            (
                "witness_outcome",
                witness is not None and witness.last_outcome != a.latest_outcome,
            ),
            ("owner_epoch", before_owner.owner_epoch != last_owner.owner_epoch),
            ("session_info", before.session_info_sha256 != after.session_info_sha256),
            ("resource_fence", before.resource_fence != after.resource_fence),
            ("connection_epoch", before.connection_epoch != after.connection_epoch),
            (
                "project_info",
                digest(self.proofs.project_info(ref, info)) != after.session_info_sha256,
            ),
            ("idle_time", info["time"].get("idle") != a.latest_created),
            ("session_outcome", info.get("outcome") != a.latest_outcome),
        )
        failed = [name for name, changed in checks if changed]
        if failed:
            key = (ref.upstream_session_id, failed[0])
            now = time.monotonic()
            if now - self._boundary_logged.get(key, -BOUNDARY_DETAIL_SECONDS) >= (
                BOUNDARY_DETAIL_SECONDS
            ):
                self._boundary_logged[key] = now
                LOG.warning(
                    "native_resource_turn_boundary_detail session=%s checks=%s",
                    ref.upstream_session_id,
                    ",".join(failed),
                )
            raise ContractError("native_resource_turn_boundary_changed")
        now = time.time()
        assert self.attestation is not None and after.resource_fence is not None
        result = NativeResourceTurn(
            correlation=c,
            contract_sha256=INSTALLED_SCHEMA,
            semantics_sha256=RESOURCE_SEMANTICS,
            installed_evidence_sha256=self.attestation.installed_evidence_sha256,
            connection_epoch=after.connection_epoch,
            owner_epoch=last_owner.owner_epoch,
            ownership_evidence_sha256=after.ownership_evidence_sha256,
            session_info_sha256=after.session_info_sha256,
            resource_fence=after.resource_fence,
            observed_at=now,
            expires_at=now + 5,
            turn=a,
            model_settings_semantics_sha256=MODEL_SETTING_SEMANTICS
            if model_settings is not None
            else None,
            model_settings_evidence_sha256=model_settings.installed_evidence_sha256
            if model_settings is not None
            else None,
            attachment_semantics_sha256=ATTACHMENT_SEMANTICS if c.attachments else None,
            attachment_evidence_sha256=attachments.installed_evidence_sha256
            if c.attachments and attachments is not None
            else None,
        )
        size = len(checked_json(result.model_dump(mode="json")))
        while self._witnesses and (
            sum(self._sizes.values()) + size > 8 * 1024 * 1024 or len(self._witnesses) >= 32
        ):
            oldest = next(iter(self._witnesses))
            self._witnesses.pop(oldest)
            self._sizes.pop(oldest)
        self._witnesses[ref] = result
        self._sizes[ref] = size
        return result

    def current(self, evidence: NativeResourceTurn) -> bool:
        try:
            ref = evidence.correlation.reference
            self.qualify(ref)
            self.qualify_attachments(evidence.correlation)
            now = time.time()
            return bool(
                self._witnesses.get(ref) is evidence
                and evidence.observed_at <= now < evidence.expires_at
                and evidence.resource_fence == self.proofs.fence(ref)
                and evidence.connection_epoch == self.proofs.generation(ref)
                and self.attestation is not None
                and evidence.installed_evidence_sha256 == self.attestation.installed_evidence_sha256
                and evidence.turn.outcome in self.attestation.verified_outcomes
                and evidence.attachment_semantics_sha256
                == (ATTACHMENT_SEMANTICS if evidence.correlation.attachments else None)
                and evidence.attachment_evidence_sha256
                == (
                    self.attachments.installed_evidence_sha256
                    if evidence.correlation.attachments and self.attachments is not None
                    else None
                )
                and evidence.model_settings_evidence_sha256
                == (
                    self.proofs.model_settings.installed_evidence_sha256
                    if self.proofs.model_settings is not None
                    else None
                )
                and evidence.model_settings_semantics_sha256
                == (MODEL_SETTING_SEMANTICS if self.proofs.model_settings is not None else None)
            )
        except (ValueError, TypeError):
            return False
