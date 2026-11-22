"""Own durable prompt outcomes from qualified Native resources, never fake logs."""

import time
import uuid
from typing import Any, Literal, Protocol, cast

from pydantic import Field, StrictInt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.attachments import ATTACHMENT_SEMANTICS
from jt_oz_bridge.adapters.opencode.model_settings import MODEL_SETTING_SEMANTICS
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    NativeResourceTurn,
    TurnCorrelation,
)
from jt_oz_bridge.domain.attachments import (
    AdmittedPromptAttachment,
    NativeAttachmentProjection,
    PromptAttachmentManifest,
    WorkspaceAttachmentManifest,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.schedules import scheduled_text
from jt_oz_bridge.domain.workspace_attachments import WorkspacePromptProjection
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent
from jt_oz_bridge.storage.resource_models import ResourceResultRecord, ResourceTextRecord

OUTCOMES: dict[str, Literal["completed", "failed", "cancelled"]] = {
    "succeeded": "completed",
    "failed": "failed",
    "interrupted": "cancelled",
}


class ResourceExecutionResult(ControlModel):
    format: Literal["native-resource-execution-v1"] = "native-resource-execution-v1"
    action_id: str = Field(min_length=1, max_length=255)
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_id: str
    binding_revision: StrictInt = Field(ge=1)
    realm_id: str
    channel_id: StrictInt = Field(gt=0)
    topic: str = Field(min_length=1, max_length=10000)
    reference: SessionRef
    evidence: NativeResourceTurn
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_at: float = Field(ge=0, allow_inf_nan=False)
    outcome: Literal["completed", "failed", "cancelled"]


class ResourceTurnReader(Protocol):
    async def capture(self, correlation: TurnCorrelation) -> NativeResourceTurn: ...

    def current(self, evidence: NativeResourceTurn) -> bool: ...


class ResultCaptureReservation(Protocol):
    bindings: BindingService
    fence: ConsumerFence

    async def reserve_in_session(
        self,
        session: AsyncSession,
        action: Action,
        index: ResourceResultRecord,
        result: ResourceExecutionResult,
    ) -> None: ...


def _expected_text(source: HumanMessage, action: Action) -> str | None:
    """The source's own prompt, or for a timed send the task the source still asks for."""
    if "schedule" not in action.payload:
        return parse_input(source.text, bound=True).arguments
    if "attachments" in action.payload or "workspace_attachments" in action.payload:
        return None
    try:
        return scheduled_text(source.text, action.payload["schedule"])
    except ValueError:
        return None


def correlation(action: Action) -> TurnCorrelation:
    receipt = native_receipt(action)
    source = HumanMessage.model_validate(action.payload.get("source"))
    parsed = parse_input(source.text, bound=True)
    if (
        action.operation != "prompt"
        or action.payload.get("operation") != "prompt"
        or action.owner != "opencode"
        or receipt is None
        or receipt.admission.status != "admitted"
        or receipt.admission.owner != "opencode"
        or receipt.admission.upstream_id is None
        or source.is_bot
        or source.deleted
        or source.author_id != action.actor_id
        or parsed.kind != "prompt"
        or _expected_text(source, action) != action.payload.get("text")
    ):
        raise Conflict("resource_result_positive_prompt_admission_required")
    attachments: tuple[NativeAttachmentProjection, ...] = ()
    workspace_sha256: str | None = None
    prompt_text = action.payload["text"]
    if "workspace_attachments" in action.payload:
        if "attachments" in action.payload:
            raise Conflict("resource_result_attachment_transports_cannot_mix")
        workspace = WorkspaceAttachmentManifest.model_validate(
            action.payload["workspace_attachments"]
        )
        workspace.checked(source)
        projection = WorkspacePromptProjection.model_validate(
            receipt.admission.details.get("workspace_projection")
        )
        prompt_text = projection.checked(receipt.reference, action.id, prompt_text, workspace)
        workspace_sha256 = digest(projection.model_dump(mode="json"))
    elif receipt.admission.details.get("workspace_projection") is not None:
        raise Conflict("resource_result_unexpected_workspace_admission")
    if "attachments" in action.payload:
        manifest = PromptAttachmentManifest.model_validate(action.payload["attachments"])
        manifest.checked(source)
        details = receipt.admission.details
        raw = details.get("attachments")
        if (
            not isinstance(raw, list)
            or len(raw) != len(manifest.files)
            or details.get("attachment_semantics_sha256") != ATTACHMENT_SEMANTICS
        ):
            raise Conflict("resource_result_attachment_admission_required")
        admitted = tuple(AdmittedPromptAttachment.model_validate(file) for file in raw)
        for original, actual in zip(manifest.files, admitted, strict=True):
            if actual.source.model_dump(mode="json") != original.model_dump(
                mode="json", include={"artifact_id", "filename", "mime_type", "size", "sha256"}
            ):
                raise Conflict("resource_result_original_attachment_changed")
        attachments = tuple(file.native for file in admitted)
    elif (
        receipt.admission.details.get("attachments")
        or receipt.admission.details.get("attachment_semantics_sha256") is not None
    ):
        raise Conflict("resource_result_unexpected_attachment_admission")
    return TurnCorrelation(
        reference=receipt.reference,
        action_id=action.id,
        operation_digest=action.operation_digest,
        upstream_id=receipt.admission.upstream_id,
        text=prompt_text,
        workspace_projection_sha256=workspace_sha256,
        attachments=attachments,
        attachment_semantics_sha256=ATTACHMENT_SEMANTICS if attachments else None,
    )


def resource_result(action: Action) -> ResourceExecutionResult:
    """Stored evidence is sealed history, not a fresh owner/feed witness."""
    result = ResourceExecutionResult.model_validate(action.native_result)
    expected = correlation(action)
    source = HumanMessage.model_validate(action.payload["source"])
    evidence = result.evidence
    receipt = native_receipt(action)
    assert receipt is not None
    if (
        result.action_id != action.id
        or result.operation_digest != action.operation_digest
        or result.admission_sha256 != digest(action.admission)
        or result.binding_id != action.binding_id
        or result.binding_revision != action.binding_revision
        or result.realm_id != source.realm_id
        or result.channel_id != source.channel_id
        or result.topic != source.topic
        or result.reference != receipt.reference
        or evidence.correlation != expected
        or evidence.contract_sha256 != receipt.contract_sha256
        or evidence.contract_sha256 != INSTALLED_SCHEMA
        or evidence.semantics_sha256 != RESOURCE_SEMANTICS
        or evidence.attachment_semantics_sha256 != expected.attachment_semantics_sha256
        or bool(expected.attachments) != (evidence.attachment_evidence_sha256 is not None)
        or evidence.attachment_evidence_sha256 is not None
        and (
            len(evidence.attachment_evidence_sha256) != 64
            or any(c not in "0123456789abcdef" for c in evidence.attachment_evidence_sha256)
        )
        or result.evidence_sha256 != digest(evidence.model_dump(mode="json"))
        or evidence.turn.user_id != receipt.admission.upstream_id
        or not evidence.observed_at <= result.verified_at < evidence.expires_at
        or result.outcome != OUTCOMES[evidence.turn.outcome]
        or action.state != result.outcome
        or evidence.turn.setting_message_ids
        and (
            evidence.model_settings_semantics_sha256 != MODEL_SETTING_SEMANTICS
            or evidence.model_settings_evidence_sha256 is None
        )
    ):
        raise Conflict("native_resource_result_identity_or_evidence_changed")
    return result


def result_index_hash(result: ResourceExecutionResult, ordinal: int) -> str:
    return digest({"own_result_ordinal": ordinal, "result": result.model_dump(mode="json")})


def indexed_result(row: ResourceResultRecord, action: Action) -> ResourceExecutionResult:
    result = resource_result(action)
    if row.ordinal < 1 or (
        row.action_id,
        row.binding_id,
        row.binding_revision,
        row.source_hash,
    ) != (
        action.id,
        result.binding_id,
        result.binding_revision,
        result_index_hash(result, row.ordinal),
    ):
        raise Conflict("resource_result_index_changed")
    return result


def text_index_hash(row: ResourceTextRecord, result: ResourceExecutionResult) -> str:
    if not 0 <= row.part_index < len(result.evidence.turn.text) or row.ordinal < 1:
        raise Conflict("resource_text_index_changed")
    return digest(
        {
            "record_id": row.id,
            "own_text_ordinal": row.ordinal,
            "action_id": row.action_id,
            "part_index": row.part_index,
            "result_sha256": digest(result.model_dump(mode="json")),
            "part": result.evidence.turn.text[row.part_index].model_dump(mode="json"),
        }
    )


class ResourceResultCollector:
    def __init__(
        self,
        bindings: BindingService,
        reader: ResourceTurnReader,
        fence: ConsumerFence,
        *,
        capture: ResultCaptureReservation | None = None,
    ) -> None:
        self.bindings, self.db, self.reader, self.fence = bindings, bindings.db, reader, fence
        if capture is not None and (capture.bindings is not bindings or capture.fence != fence):
            raise ValueError("result_capture_original_scope_required")
        self.capture = capture

    async def _later_steer(self, action: Action) -> bool:
        """A later prompt of this topic was admitted as a steer (SQL hint only)."""
        async with self.db.sessions() as session:
            later = (
                await session.scalars(
                    select(Action)
                    .where(
                        Action.binding_id == action.binding_id,
                        Action.binding_revision == action.binding_revision,
                        Action.operation == "prompt",
                        Action.id != action.id,
                        Action.created_at >= action.created_at,
                        Action.upstream_id.is_not(None),
                    )
                    .order_by(Action.created_at, Action.id)
                    .limit(100)
                )
            ).all()
        for row in later:
            try:
                receipt = native_receipt(row)
            except (Conflict, ValueError):
                continue  # Not a usable receipt: never evidence of a steer.
            if receipt is not None and receipt.admission.details.get("delivery") == "steer":
                return True
        return False

    async def collect(self, action_id: str, realm_id: str) -> ResourceExecutionResult:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None:
            raise Conflict("native_resource_result_action_missing")
        bracketed = self.bindings.supports_read_capture() and (
            not action.native_result and action.state in {"admitted", "running"}
        )
        if bracketed:
            # Metadata only. The complete actor/audience/enrollment checks run
            # inside BOTH sides of capture_output, before any Native GET and
            # again before the unchanged fenced SQL/result-witness commit.
            async with self.db.sessions() as session:
                binding = await session.get(Binding, action.binding_id)
            if binding is None or binding.realm_id != realm_id or binding.state != "active":
                raise Conflict("native_resource_result_binding_unavailable")
        else:
            binding = await self.bindings.get(action.binding_id, realm_id, action.actor_id)
        if binding.revision != action.binding_revision:
            raise Conflict("native_resource_result_binding_changed")
        source = HumanMessage.model_validate(action.payload.get("source"))
        if (source.realm_id, source.channel_id, source.topic) != (
            binding.realm_id,
            binding.channel_id,
            binding.topic,
        ):
            raise Conflict("native_resource_result_original_source_scope_changed")
        if action.native_result:
            async with self.db.sessions() as session:
                index = await session.get(ResourceResultRecord, action.id)
            if index is None:
                raise Conflict("resource_result_index_missing")
            return indexed_result(index, action)  # Historical input; no new Native capture.
        if action.state not in {"admitted", "running"}:
            raise Conflict("native_resource_result_admitted_input_required")
        selected = correlation(action)
        if selected.reference != reference(binding):
            raise Conflict("native_resource_result_original_target_changed")
        reader: Any = self.reader
        later_steer = await self._later_steer(action)

        async def capture() -> NativeResourceTurn:
            if later_steer:
                # A steer sent after this input may have started the next busy period.
                return cast(
                    NativeResourceTurn, await reader.capture(selected, allow_later_steer=True)
                )
            return await self.reader.capture(selected)

        if bracketed:
            evidence = await self.bindings.capture_output(
                binding, capture, actor_id=action.actor_id
            )
        else:
            evidence = await capture()
        # Do not accept a deserialized or reconstructed DTO as capture authority.
        if not self.reader.current(evidence) or evidence.correlation != selected:
            raise Conflict("native_resource_result_live_witness_required")
        if not bracketed:
            await self.bindings.get(binding.id, realm_id, action.actor_id)
        result: ResourceExecutionResult | None = None
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            current = await session.scalar(
                select(Action).where(Action.id == action.id).with_for_update()
            )
            if (
                current is None
                or correlation(current) != selected
                or current.admission != action.admission
            ):
                raise Conflict("native_resource_result_admission_changed_before_commit")
            if current.native_result:
                index = await session.get(ResourceResultRecord, current.id)
                if index is None:
                    raise Conflict("resource_result_index_missing")
                result = indexed_result(index, current)
            else:
                if current.state not in {"admitted", "running"} or not self.reader.current(
                    evidence
                ):
                    raise Conflict("native_resource_result_witness_or_state_changed")
                now = time.time()
                if not evidence.observed_at <= now < evidence.expires_at:
                    raise Conflict("native_resource_result_witness_expired")
                result = ResourceExecutionResult(
                    action_id=current.id,
                    operation_digest=current.operation_digest,
                    admission_sha256=digest(current.admission),
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    realm_id=realm_id,
                    channel_id=binding.channel_id,
                    topic=binding.topic,
                    reference=selected.reference,
                    evidence=evidence,
                    evidence_sha256=digest(evidence.model_dump(mode="json")),
                    verified_at=now,
                    outcome=OUTCOMES[evidence.turn.outcome],
                )
                current.native_result = result.model_dump(mode="json")
                current.state, current.version, current.status_reason = (
                    result.outcome,
                    current.version + 1,
                    "native_resource_terminal_verified",
                )
                resource_result(current)
                ordinal = (
                    int(await session.scalar(select(func.max(ResourceResultRecord.ordinal))) or 0)
                    + 1
                )
                result_index = ResourceResultRecord(
                    action_id=current.id,
                    ordinal=ordinal,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    source_hash=result_index_hash(result, ordinal),
                )
                session.add(result_index)
                # Flush the parent before its FK children; all remain in this transaction.
                await session.flush()
                if self.capture is not None:
                    await self.capture.reserve_in_session(session, current, result_index, result)
                part_floor = int(
                    await session.scalar(select(func.max(ResourceTextRecord.ordinal))) or 0
                )
                for i, _part in enumerate(evidence.turn.text):
                    row = ResourceTextRecord(
                        id=str(uuid.uuid4()),
                        action_id=current.id,
                        ordinal=part_floor + i + 1,
                        part_index=i,
                    )
                    row.source_hash = text_index_hash(row, result)
                    session.add(row)
                session.add(
                    AuditEvent(
                        actor="worker",
                        event="native_resource_result_recorded",
                        object_id=current.id,
                    )
                )
        assert result is not None
        return result
