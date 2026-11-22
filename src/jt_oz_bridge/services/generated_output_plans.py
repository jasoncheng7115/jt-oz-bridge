"""Encrypted generated-file provenance, separate from manual !oz file requests."""

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from jt_oz_bridge.adapters.opencode.generated_files import MAX_OUTPUTS, GeneratedByteEvidence
from jt_oz_bridge.adapters.zulip.file_upload import UploadedFileReceipt
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.attachments import NativeAttachmentProjection
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.generated_models import GeneratedOutputRecord


class GeneratedOutputIntent(ControlModel):
    format: Literal["generated-output-intent-v1"] = "generated-output-intent-v1"
    id: str
    action_id: str
    output_index: int = Field(strict=True, ge=0, lt=MAX_OUTPUTS)
    artifact_id: str
    binding_id: str
    binding_revision: int = Field(strict=True, gt=0)
    source: HumanMessage
    action_version: int = Field(strict=True, gt=0)
    action_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_ordinal: int = Field(strict=True, gt=0)
    result_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: GeneratedByteEvidence
    locale: Locale

    @model_validator(mode="after")
    def original(self) -> "GeneratedOutputIntent":
        for value in (self.id, self.action_id, self.artifact_id, self.binding_id):
            if str(UUID(value)) != value:
                raise ValueError("generated_output_canonical_identity_required")
        if (
            self.source.is_bot
            or self.source.deleted
            or self.evidence.turn.correlation.action_id != self.action_id
            or self.output_index >= len(self.evidence.files)
            or self.evidence.files[self.output_index] != self.evidence.selection
        ):
            raise ValueError("generated_output_original_source_or_selection_changed")
        return self


def read_intent(row: GeneratedOutputRecord) -> GeneratedOutputIntent:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("generated_output_encrypted_intent_changed")
    value = GeneratedOutputIntent.model_validate(row.payload)
    if (value.id, value.action_id, value.output_index, value.artifact_id) != (
        row.id,
        row.action_id,
        row.output_index,
        row.reserved_artifact_id,
    ):
        raise Conflict("generated_output_intent_index_changed")
    return value


class GeneratedFileReturnPlan(ControlModel):
    format: Literal["generated-file-return-v1"] = "generated-file-return-v1"
    id: str
    artifact_id: str
    binding_id: str
    binding_revision: int = Field(strict=True, gt=0)
    source: HumanMessage
    reference: SessionRef
    intent_id: str
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: GeneratedByteEvidence
    projection: NativeAttachmentProjection
    locale: Locale
    realm_url: str
    bot_user_id: int = Field(strict=True, gt=0)
    message_limit: int = Field(strict=True, ge=512, le=1000000)
    topic_limit: int = Field(strict=True, ge=1, le=10000)
    upload: UploadedFileReceipt | None = None
    bytes_verified: bool = Field(default=False, strict=True)
    batch_id: str | None = None

    @model_validator(mode="after")
    def exact(self) -> "GeneratedFileReturnPlan":
        for value in (self.id, self.artifact_id, self.binding_id, self.intent_id):
            if str(UUID(value)) != value:
                raise ValueError("generated_return_canonical_identity_required")
        if (
            self.source.is_bot
            or self.source.deleted
            or self.reference != self.evidence.turn.correlation.reference
            or self.projection != self.evidence.projection
            or self.upload is not None
            and (
                self.upload.realm_id,
                self.upload.bot_user_id,
                self.upload.source,
                self.upload.filename_stored,
            )
            != (self.source.realm_id, self.bot_user_id, self.projection, self.projection.filename)
            or self.bytes_verified
            and self.upload is None
            or self.batch_id is not None
            and not self.bytes_verified
        ):
            raise ValueError("generated_return_original_capture_or_upload_changed")
        return self
