"""Sealed immutable native-source publication receipts."""

from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.publication_models import NativePublication
from jt_oz_bridge.storage.resource_models import ResourcePublication


class NativePublicationPlan(ControlModel):
    format: Literal["native-publication-v1"] = "native-publication-v1"
    input_event_id: str
    ordinal: StrictInt = Field(ge=1)
    binding_id: str
    binding_revision: StrictInt = Field(ge=1)
    realm_id: str
    reference: SessionRef
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["queued", "history", "empty", "recovery", "needs_full_output"]
    batch_id: str | None
    previous_batch_id: str | None
    plan_hash: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    bot_user_id: StrictInt = Field(gt=0)
    locale: Locale
    message_limit: StrictInt = Field(ge=173, le=1000000)
    topic_limit: StrictInt = Field(ge=1, le=1000000)
    renderer_version: str
    recovery_floor: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.state in {"queued", "needs_full_output"}:
            if self.batch_id is None or self.plan_hash is None:
                raise ValueError("native_publication_batch_required")
        elif (
            self.batch_id is not None
            or self.plan_hash is not None
            or self.previous_batch_id is not None
        ):
            raise ValueError("native_publication_must_not_send")
        return self


def read_publication(row: NativePublication) -> NativePublicationPlan:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("native_publication_hash_changed")
    plan = NativePublicationPlan.model_validate(row.payload)
    if (
        plan.input_event_id,
        plan.ordinal,
        plan.binding_id,
        plan.binding_revision,
        plan.source_hash,
        plan.state,
        plan.batch_id,
        plan.previous_batch_id,
    ) != (
        row.input_event_id,
        row.ordinal,
        row.binding_id,
        row.binding_revision,
        row.source_hash,
        row.state,
        row.batch_id,
        row.previous_batch_id,
    ):
        raise Conflict("native_publication_identity_changed")
    return plan


class ResourcePublicationPlan(ControlModel):
    format: Literal["resource-publication-v1"] = "resource-publication-v1"
    action_id: str
    own_result_ordinal: StrictInt = Field(ge=1)
    binding_id: str
    binding_revision: StrictInt = Field(ge=1)
    realm_id: str
    channel_id: StrictInt = Field(gt=0)
    topic: str
    reference: SessionRef
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: Literal["completed", "failed", "cancelled"]
    state: Literal["queued", "needs_full_output"]
    batch_id: str
    previous_batch_id: str | None
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    bot_user_id: StrictInt = Field(gt=0)
    locale: Locale
    message_limit: StrictInt = Field(ge=173, le=1000000)
    topic_limit: StrictInt = Field(ge=1, le=1000000)
    renderer_version: str


def read_resource_publication(row: ResourcePublication) -> ResourcePublicationPlan:
    plan = ResourcePublicationPlan.model_validate(row.payload)
    if digest(row.payload) != row.payload_hash or (
        row.action_id,
        row.binding_id,
        row.binding_revision,
        row.source_hash,
        row.batch_id,
    ) != (plan.action_id, plan.binding_id, plan.binding_revision, plan.source_hash, plan.batch_id):
        raise Conflict("resource_publication_seal_changed")
    return plan
