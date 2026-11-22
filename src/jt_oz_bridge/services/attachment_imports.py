"""Fenced per-file import progress, committed before the original Native claim."""

import asyncio
from typing import ClassVar, Literal
from weakref import WeakValueDictionary

from pydantic import Field, StrictInt, model_validator
from sqlalchemy import update

from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    AttachmentManifestBase,
    PromptAttachmentManifest,
    PromptAttachmentReceipt,
    WorkspaceAttachmentManifest,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.prompt_attachments import ZulipPromptAttachmentImporter, source_uploads
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent


class ImportProgressBase(ControlModel):
    manifest_type: ClassVar[type[AttachmentManifestBase]] = PromptAttachmentManifest
    format: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_revision: StrictInt = Field(gt=0)
    uploads: tuple[str, ...] = Field(min_length=1, max_length=MAX_ATTACHMENTS)
    completed: tuple[PromptAttachmentReceipt, ...] = Field(default=(), max_length=MAX_ATTACHMENTS)

    @model_validator(mode="after")
    def ordered_prefix(self) -> "ImportProgressBase":
        if (
            len(set(self.uploads)) != len(self.uploads)
            or tuple(f.source_upload for f in self.completed) != self.uploads[: len(self.completed)]
            or any(f.source_sha256 != self.source_sha256 for f in self.completed)
        ):
            raise ValueError("attachment_progress_source_order_or_capacity_invalid")
        if self.completed:
            self.manifest_type(files=self.completed)
        return self


class AttachmentImportProgress(ImportProgressBase):
    format: Literal["original-prompt-attachment-import-v1"] = "original-prompt-attachment-import-v1"


class WorkspaceImportProgress(ImportProgressBase):
    format: Literal["original-workspace-attachment-import-v1"] = (
        "original-workspace-attachment-import-v1"
    )
    manifest_type: ClassVar[type[AttachmentManifestBase]] = WorkspaceAttachmentManifest


class AttachmentImportJournal:
    """No Native mutation or automatic queue resume; never journal signed URLs."""

    def __init__(
        self,
        importer: ZulipPromptAttachmentImporter,
        fence: ConsumerFence,
        *,
        transport: Literal["inline", "workspace"] = "inline",
    ) -> None:
        # This is trusted composition, never a field selected by a chat payload.
        if transport not in {"inline", "workspace"}:
            raise ValueError("attachment_import_transport_unknown")
        self.transport = transport
        self.manifest_type: type[AttachmentManifestBase] = (
            PromptAttachmentManifest if transport == "inline" else WorkspaceAttachmentManifest
        )
        self.progress_type: type[ImportProgressBase] = (
            AttachmentImportProgress if transport == "inline" else WorkspaceImportProgress
        )
        self.progress_format = (
            "original-prompt-attachment-import-v1"
            if transport == "inline"
            else "original-workspace-attachment-import-v1"
        )
        self.manifest_key = "attachments" if transport == "inline" else "workspace_attachments"
        self.progress_key = (
            "_attachment_import" if transport == "inline" else "_workspace_attachment_import"
        )
        if importer.artifacts.fence != fence:
            raise ValueError("attachment_store_requires_same_consumer_fence")
        self.importer, self.artifacts, self.db, self.fence = (
            importer,
            importer.artifacts,
            importer.artifacts.db,
            fence,
        )
        self._locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()

    async def load(self, action_id: str) -> Action:
        async with self.db.sessions() as session:
            action = await session.get(Action, action_id)
        if action is None:
            raise Conflict("attachment_action_unavailable")
        return action

    async def receipt(
        self, action: Action, source: HumanMessage, file: PromptAttachmentReceipt
    ) -> None:
        async with self.db.sessions() as session:
            saved = await session.get(Artifact, file.artifact_id)
        if (
            saved is None
            or saved.state != "ready"
            or saved.kind != "attachment"
            or saved.action_id != action.id
            or saved.binding_id != action.binding_id
            or saved.binding_revision != action.binding_revision
            or saved.actor_id != source.author_id
            or saved.realm_id != source.realm_id
            or saved.source_message_id != source.message_id
            or saved.checksum != file.sha256
            or saved.size_bytes != file.size
        ):
            raise Conflict("attachment_progress_artifact_provenance_changed")
        content = await self.artifacts.read(file.artifact_id, source.realm_id, source.author_id)
        if (content.descriptor.filename, content.descriptor.mime_type, content.sha256) != (
            file.filename,
            file.mime_type,
            file.sha256,
        ):
            raise Conflict("attachment_progress_artifact_descriptor_changed")

    async def publish(
        self,
        action: Action,
        source: HumanMessage,
        progress: ImportProgressBase,
        *,
        complete: bool = False,
    ) -> Action:
        self.check_transport(action)
        if type(progress) is not self.progress_type:
            raise Conflict("attachment_progress_transport_changed")
        progress = self.progress_type.model_validate(progress.model_dump(mode="json"))
        current, binding = await self.importer.current(action.id, source)
        if current.version != action.version or current.operation_digest != action.operation_digest:
            raise Conflict("attachment_progress_action_changed_before_commit")
        payload = dict(action.payload)
        if complete:
            manifest = self.manifest_type(files=progress.completed)
            manifest.checked(source)
            if len(progress.completed) != len(progress.uploads):
                raise Conflict("attachment_progress_incomplete")
            payload.pop(self.progress_key, None)
            payload[self.manifest_key] = manifest.model_dump(mode="json")
        else:
            payload[self.progress_key] = progress.model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            changed = await session.execute(
                update(Action)
                .where(
                    Action.id == action.id,
                    Action.state.in_(["queued", "held"]),
                    Action.version == action.version,
                    Action.operation == "prompt",
                    Action.operation_digest == action.operation_digest,
                    self.artifacts.binding_current(binding),
                    self.artifacts.human(binding, source.author_id, Permission.OPERATE),
                )
                .values(
                    payload=payload,
                    operation_digest=digest(payload),
                    version=Action.version + 1,
                    status_reason=None if complete else "attachment_import_pending",
                )
            )
            if changed.rowcount != 1:  # type: ignore[attr-defined]
                raise Conflict("attachment_progress_claim_or_source_changed")
            session.add(
                AuditEvent(
                    actor="worker",
                    event=(
                        "prompt_attachments_ready"
                        if complete
                        else "prompt_attachment_progress_saved"
                    ),
                    object_id=action.id,
                )
            )
        return await self.load(action.id)

    def check_transport(self, action: Action) -> None:
        keys = {
            "attachments",
            "workspace_attachments",
            "_attachment_import",
            "_workspace_attachment_import",
        }
        if (keys & action.payload.keys()) - {self.manifest_key, self.progress_key}:
            raise Conflict("attachment_import_transport_changed")

    async def stage(self, action_id: str) -> Action:
        lock = self._locks.setdefault(action_id, asyncio.Lock())
        async with lock:
            action = await self.load(action_id)
            self.check_transport(action)
            source = HumanMessage.model_validate(action.payload.get("source"))
            action, _ = await self.importer.current(action_id, source)
            uploads = source_uploads(source, self.importer.zulip.url)
            paths = tuple("/user_uploads/" + upload.path_id for upload in uploads)
            if self.manifest_key in action.payload:
                manifest = self.manifest_type.model_validate(action.payload[self.manifest_key])
                manifest.checked(source)
                if (
                    tuple(f.source_upload for f in manifest.files) != paths
                    or self.progress_key in action.payload
                ):
                    raise Conflict("attachment_ready_manifest_source_changed")
                for receipt in manifest.files:
                    await self.receipt(action, source, receipt)
                return action
            if not uploads:
                if self.progress_key in action.payload:
                    raise Conflict("attachment_source_no_longer_contains_imports")
                return action
            if self.progress_key in action.payload:
                progress = self.progress_type.model_validate(action.payload[self.progress_key])
                if (
                    progress.source_sha256 != digest(source.model_dump(mode="json"))
                    or progress.binding_revision != action.binding_revision
                    or progress.uploads != paths
                ):
                    raise Conflict("attachment_progress_scope_changed")
            else:
                progress = self.progress_type(
                    format=self.progress_format,
                    source_sha256=digest(source.model_dump(mode="json")),
                    binding_revision=action.binding_revision,
                    uploads=paths,
                )
                action = await self.publish(action, source, progress)
            for receipt in progress.completed:
                await self.receipt(action, source, receipt)
            for upload in uploads[len(progress.completed) :]:
                receipt = await self.importer.import_one(
                    action_id,
                    source,
                    upload,
                    remaining=(
                        MAX_ATTACHMENT_BYTES
                        if self.transport == "workspace"
                        else MAX_ATTACHMENT_BYTES - sum(f.size for f in progress.completed)
                    ),
                    excluded_artifact_ids=frozenset(f.artifact_id for f in progress.completed),
                )
                progress = self.progress_type(
                    format=self.progress_format,
                    source_sha256=progress.source_sha256,
                    binding_revision=progress.binding_revision,
                    uploads=paths,
                    completed=(*progress.completed, receipt),
                )
                action = await self.publish(action, source, progress)
            return await self.publish(action, source, progress, complete=True)
