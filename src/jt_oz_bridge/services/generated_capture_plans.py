"""Sealed capture origins and a network-free original-root mutation barrier."""

from typing import Any, Literal
from uuid import UUID

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.generated_files import MAX_OUTPUTS, GeneratedDiscoveryEvidence
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.binding_scope import BindingScope
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob


class CaptureOrigin(ControlModel):
    action_id: str
    binding_id: str
    binding_revision: int = Field(strict=True, gt=0)
    reference: SessionRef
    source: HumanMessage
    action_version: int = Field(strict=True, gt=0)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_ordinal: int = Field(strict=True, gt=0)
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def human(self) -> "CaptureOrigin":
        if self.source.is_bot or self.source.deleted:
            raise ValueError("generated_capture_original_human_required")
        for value in (self.action_id, self.binding_id):
            if str(UUID(value)) != value:
                raise ValueError("generated_capture_canonical_id_required")
        return self


class LossAuthority(ControlModel):
    role: Literal["original_actor", "project_administrator"]
    scope: BindingScope

    @model_serializer(mode="wrap")
    def canonical(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        value["scope"]["audience_user_ids"] = sorted(self.scope.audience_user_ids)
        return value


class CapturePlan(ControlModel):
    format: str = "generated-capture-plan-v1"
    origin: CaptureOrigin
    locale: Locale = "en"
    discovery: GeneratedDiscoveryEvidence | None = None
    next_index: int = Field(default=0, strict=True, ge=0, le=MAX_OUTPUTS)
    acknowledgement: HumanMessage | None = None
    original_scope: BindingScope | None = None
    acknowledgement_authority: LossAuthority | None = None

    @model_validator(mode="after")
    def original(self) -> "CapturePlan":
        if (
            self.format != "generated-capture-plan-v1"
            or self.discovery is None
            and self.next_index != 0
            or self.discovery is not None
            and (
                self.next_index > len(self.discovery.files)
                or self.discovery.turn.correlation.action_id != self.origin.action_id
                or self.discovery.turn.correlation.reference != self.origin.reference
            )
            or self.acknowledgement is not None
            and (
                self.acknowledgement.is_bot
                or self.acknowledgement.deleted
                or self.acknowledgement.realm_id != self.origin.source.realm_id
                or self.acknowledgement.author_id != self.origin.source.author_id
                and (
                    self.acknowledgement_authority is None
                    or self.acknowledgement_authority.role != "project_administrator"
                )
            )
        ):
            raise ValueError("generated_capture_original_plan_changed")
        scopes = [self.original_scope] if self.original_scope is not None else []
        if self.original_scope is not None and (
            self.original_scope.revision != self.origin.binding_revision
            or self.origin.source.author_id not in self.original_scope.audience_user_ids
            or (self.original_scope.channel_id, self.original_scope.topic)
            != (self.origin.source.channel_id, self.origin.source.topic)
        ):
            raise ValueError("generated_capture_original_scope_changed")
        authority = self.acknowledgement_authority
        if authority is not None:
            ack = self.acknowledgement
            if (
                ack is None
                or ack.author_id not in authority.scope.audience_user_ids
                or authority.scope.revision < self.origin.binding_revision
                or (ack.channel_id, ack.topic)
                != (authority.scope.channel_id, authority.scope.topic)
                or (authority.role == "original_actor")
                != (ack.author_id == self.origin.source.author_id)
                or self.original_scope is not None
                and (
                    authority.scope.owner_id,
                    authority.scope.anchor_message_id,
                )
                != (
                    self.original_scope.owner_id,
                    self.original_scope.anchor_message_id,
                )
            ):
                raise ValueError("generated_capture_loss_authority_changed")
            scopes.append(authority.scope)
        for selected in scopes:
            if (selected.binding_id, selected.reference, selected.realm_id) != (
                self.origin.binding_id,
                self.origin.reference,
                self.origin.source.realm_id,
            ):
                raise ValueError("generated_capture_loss_scope_changed")
        return self

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        for key in ("original_scope", "acknowledgement_authority"):
            if value.get(key) is None:
                value.pop(key, None)
        if self.original_scope is not None:
            value["original_scope"]["audience_user_ids"] = sorted(
                self.original_scope.audience_user_ids
            )
        return value


def read_capture(row: GeneratedCaptureJob) -> CapturePlan:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("generated_capture_encrypted_plan_changed")
    value = CapturePlan.model_validate(row.payload)
    if (
        row.action_id != value.origin.action_id
        or row.binding_id != value.origin.binding_id
        or row.version < 1
        or row.state not in {"pending", "capturing", "held", "frozen", "skipped"}
        or (row.state == "skipped") != (value.acknowledgement is not None)
        or row.state == "frozen"
        and (value.discovery is None or value.next_index != len(value.discovery.files))
    ):
        raise Conflict("generated_capture_index_or_state_changed")
    return value


async def capture_blocks(session: AsyncSession, binding: Binding) -> bool:
    """A restarted default-off dispatcher still honors earlier unresolved jobs."""
    # Stream sealed history in bounded batches. Do not materialize an unbounded
    # Root history, or trust a terminal state's plaintext index without checking
    # its encrypted inventory/acknowledgement.
    rows = await session.stream_scalars(
        select(GeneratedCaptureJob)
        .join(Binding, Binding.id == GeneratedCaptureJob.binding_id)
        .where(
            Binding.backend_id == binding.backend_id,
            Binding.backend_identity == binding.backend_identity,
            Binding.session_id == binding.session_id,
        )
        .with_for_update()
        .execution_options(yield_per=32)
    )
    try:
        async for row in rows:
            plan = read_capture(row)
            if plan.origin.reference != reference(binding):
                raise Conflict("generated_capture_original_root_changed")
            if row.state not in {"frozen", "skipped"}:
                return True
        return False
    finally:
        await rows.close()
