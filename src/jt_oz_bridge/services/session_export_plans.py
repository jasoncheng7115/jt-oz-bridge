"""Safe conversation snapshots; these receipts never grant Native or Human authority."""

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from jt_oz_bridge.adapters.zulip.file_upload import UploadedFileReceipt
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.attachments import NativeAttachmentProjection
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.security.admin import token_hash

EXPORT_SCHEMA: Literal["safe-conversation-export-v1"] = "safe-conversation-export-v1"
OMITTED = ("reasoning", "system instructions", "metadata", "tool arguments/results", "shell output")


class ExportContext(ControlModel):
    format: Literal["safe-conversation-export-v1"] = EXPORT_SCHEMA
    artifact_id: str
    preview_source: HumanMessage
    reference: SessionRef
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection: NativeAttachmentProjection
    owner_epoch: str = Field(min_length=1, max_length=4096)
    connection_epoch: str = Field(min_length=1, max_length=4096)
    semantics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    captured_at: float = Field(gt=0, allow_inf_nan=False)
    entry_count: int = Field(strict=True, ge=0, le=200)
    older_omitted: bool = Field(strict=True)
    encoding: Literal["json", "markdown"]

    @model_validator(mode="after")
    def original(self) -> "ExportContext":
        parsed = parse_input(self.preview_source.text, bound=True)
        if (
            parsed.kind != "command"
            or parsed.command != "export"
            or parsed.arguments.strip()
            != (
                "markdown"
                if self.encoding == "markdown"
                else ("json" if parsed.arguments.strip() else "")
            )
            or str(UUID(self.artifact_id)) != self.artifact_id
            or self.preview_source.is_bot
            or self.preview_source.deleted
            or self.preview_source.revision != 0
            or (self.projection.filename, self.projection.mime_type)
            != (
                ("conversation.json", "application/json")
                if self.encoding == "json"
                else ("conversation.md", "text/markdown")
            )
        ):
            raise ValueError("session_export_context_changed")
        return self


class TranscriptExportPlan(ControlModel):
    format: Literal["safe-conversation-return-v1"] = "safe-conversation-return-v1"
    id: str
    artifact_id: str
    binding_id: str
    binding_revision: int = Field(strict=True, gt=0)
    source: HumanMessage
    reference: SessionRef
    preview: ExportContext
    confirmation_id: str
    token_hash: str
    token_context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
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
    def original(self) -> "TranscriptExportPlan":
        parsed = parse_input(self.source.text, bound=True)
        parts = parsed.arguments.strip().split()
        if (
            parsed.kind != "command"
            or parsed.command != "export"
            or len(parts) != 2
            or parts[0] != "confirm"
            or token_hash(parts[1]) != self.token_hash
        ):
            raise ValueError("session_export_original_confirmation_command_changed")
        for value in (self.id, self.artifact_id, self.binding_id, self.confirmation_id):
            if str(UUID(value)) != value:
                raise ValueError("session_export_canonical_identity_required")
        if (
            self.artifact_id != self.preview.artifact_id
            or self.reference != self.preview.reference
            or self.projection != self.preview.projection
            or self.source.is_bot
            or self.source.deleted
            or self.source.revision != 0
            or (
                self.source.realm_id,
                self.source.author_id,
                self.source.channel_id,
                self.source.topic,
            )
            != (
                self.preview.preview_source.realm_id,
                self.preview.preview_source.author_id,
                self.preview.preview_source.channel_id,
                self.preview.preview_source.topic,
            )
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
            raise ValueError("session_export_original_capture_or_upload_changed")
        return self
