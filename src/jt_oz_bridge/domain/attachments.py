"""Bounded immutable attachment receipts; no caller-selected Native paths or URLs."""

import hashlib
from dataclasses import dataclass, field
from typing import ClassVar, Literal, Protocol, Self
from uuid import UUID

from pydantic import Field, StrictInt, field_validator, model_validator

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef

MAX_ATTACHMENT_BYTES = 20 * 1024**2
MAX_ATTACHMENTS = 10


class PromptAttachmentReceipt(ControlModel):
    artifact_id: str
    source_upload: str = Field(min_length=1, max_length=4096)
    source_message_id: StrictInt = Field(gt=0)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(pattern=r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$", max_length=255)
    size: StrictInt = Field(ge=0, le=MAX_ATTACHMENT_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("artifact_id")
    @classmethod
    def canonical_object(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("canonical_artifact_identity_required")
        return value

    @field_validator("filename")
    @classmethod
    def filename_only(cls, value: str) -> str:
        if (
            value in {".", ".."}
            or any(c in value for c in "/\\")
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("attachment_filename_not_path_required")
        return value

    @field_validator("source_upload")
    @classmethod
    def original_upload(cls, value: str) -> str:
        # Canonical percent-encoded paths are additionally checked against the
        # enrolled realm by the Zulip source importer. No signed URL is stored.
        if not value.startswith("/user_uploads/") or any(c in value for c in "?#\\\x00\r\n"):
            raise ValueError("original_zulip_upload_path_required")
        return value


class AttachmentManifestBase(ControlModel):
    """Separate byte transports share source receipts, never byte capacity."""

    maximum_total: ClassVar[int] = MAX_ATTACHMENT_BYTES
    distinct_artifacts: ClassVar[bool] = False
    files: tuple[PromptAttachmentReceipt, ...] = Field(min_length=1, max_length=MAX_ATTACHMENTS)

    @model_validator(mode="after")
    def bounded_manifest(self) -> Self:
        # Revalidate nested model_copy/construct values as well as decoded JSON.
        for file in self.files:
            PromptAttachmentReceipt.model_validate(file.model_dump(mode="json"))
        if (
            not 1 <= len(self.files) <= MAX_ATTACHMENTS
            or sum(f.size for f in self.files) > self.maximum_total
            or len({f.source_upload for f in self.files}) != len(self.files)
            or self.distinct_artifacts
            and len({f.artifact_id for f in self.files}) != len(self.files)
        ):
            raise ValueError("attachment_total_size_or_duplicate_source_invalid")
        return self

    def checked(self, source: HumanMessage) -> None:
        from jt_oz_bridge.storage.durable import digest

        type(self).model_validate(self.model_dump(mode="json"))
        if (
            source.is_bot
            or source.deleted
            or any(
                f.source_message_id != source.message_id
                or f.source_sha256 != digest(source.model_dump(mode="json"))
                for f in self.files
            )
        ):
            raise ValueError("attachment_source_identity_or_total_size_changed")


class PromptAttachmentManifest(AttachmentManifestBase):
    """Inline codec: the existing 20 MiB aggregate bound remains unchanged."""


class WorkspaceAttachmentManifest(AttachmentManifestBase):
    """Ordinary files: ten independent 20 MiB objects, no inline payloads.

    Only the workspace provider may turn these receipts into Native paths after
    checking the original host/workspace. This DTO is not such a qualification.
    """

    format: Literal["original-workspace-attachments-v1"] = "original-workspace-attachments-v1"
    maximum_total: ClassVar[int] = MAX_ATTACHMENTS * MAX_ATTACHMENT_BYTES
    distinct_artifacts: ClassVar[bool] = True


class NativeAttachmentProjection(ControlModel):
    """A bounded checksum receipt, never an attachment body or Native path."""

    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(pattern=r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$", max_length=255)
    size: StrictInt = Field(ge=0, le=MAX_ATTACHMENT_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("filename")
    @classmethod
    def filename_only(cls, value: str) -> str:
        return PromptAttachmentReceipt.filename_only(value)


class AdmittedAttachmentSource(NativeAttachmentProjection):
    artifact_id: str

    @field_validator("artifact_id")
    @classmethod
    def canonical_object(cls, value: str) -> str:
        return PromptAttachmentReceipt.canonical_object(value)


class AdmittedPromptAttachment(ControlModel):
    source: AdmittedAttachmentSource
    native: NativeAttachmentProjection
    normalization: Literal["none", "native-image-normalized"]
    mime_detected_from_bytes: Literal[True]

    @model_validator(mode="after")
    def consistent_projection(self) -> Self:
        unchanged = (self.source.size, self.source.sha256) == (self.native.size, self.native.sha256)
        if (
            self.source.filename != self.native.filename
            or (self.normalization == "none") != unchanged
            or not unchanged
            and self.native.mime_type not in {"image/png", "image/jpeg"}
        ):
            raise ValueError("attachment_admission_projection_inconsistent")
        return self


@dataclass(frozen=True)
class ResolvedPromptAttachment:
    receipt: PromptAttachmentReceipt
    content: bytes = field(repr=False)

    def checked(self) -> None:
        if (
            not isinstance(self.content, bytes)
            or len(self.content) != self.receipt.size
            or hashlib.sha256(self.content).hexdigest() != self.receipt.sha256
        ):
            raise ValueError("attachment_exact_bytes_required")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedPromptAttachments:
    files: tuple[ResolvedPromptAttachment, ...]
    # Set only by the trusted provider after separate installed normalization
    # qualification. It is not a field accepted in a Human/action manifest.
    allow_image_normalization: bool = False

    def checked(self, manifest: PromptAttachmentManifest) -> None:
        if (
            type(self.files) is not tuple
            or type(self.allow_image_normalization) is not bool
            or tuple(f.receipt for f in self.files) != manifest.files
        ):
            raise ValueError("attachment_receipt_order_or_scope_changed")
        for file in self.files:
            file.checked()


class PromptAttachmentProvider(Protocol):
    """Trusted runtime dependency; not a chat-supplied authority assertion."""

    def qualified(self, reference: SessionRef, schema_sha256: str) -> bool: ...

    async def prepare(
        self,
        reference: SessionRef,
        action_id: str,
        source: HumanMessage,
        manifest: PromptAttachmentManifest,
    ) -> PreparedPromptAttachments: ...

    def current(
        self, reference: SessionRef, action_id: str, prepared: PreparedPromptAttachments
    ) -> bool: ...
