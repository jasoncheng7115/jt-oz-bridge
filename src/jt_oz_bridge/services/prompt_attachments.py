"""Authenticated original-message imports and exact-action attachment resolution.

These dependencies do not start a worker or expose a transfer endpoint. Runtime
composition must separately journal imports and enroll the installed byte codec.
"""

import hashlib
import time
from collections.abc import AsyncIterator, Mapping
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit
from weakref import ReferenceType
from weakref import ref as weakref

from markdown_it import MarkdownIt
from pydantic import Field, StrictInt
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.attachments import InlineAttachmentAttestation, native_mime
from jt_oz_bridge.adapters.zulip.client import ZulipClient
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.uploads import UploadReference, upload_reference
from jt_oz_bridge.domain.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    PreparedPromptAttachments,
    PromptAttachmentManifest,
    PromptAttachmentReceipt,
    ResolvedPromptAttachment,
)
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.services.artifacts import ArtifactService, FileDescriptor
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action


class SourceUploadDescriptor(FileDescriptor):
    upload_path: str = Field(min_length=1, max_length=4096)
    size: StrictInt = Field(ge=0, lt=2**63)


class SourceUploadAssociation(ControlModel):
    """Short-lived installed-server witness, not a link or aggregate attachment flag."""

    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    upload_paths: tuple[str, ...] = Field(min_length=1, max_length=MAX_ATTACHMENTS)
    files: tuple[SourceUploadDescriptor, ...] = Field(min_length=1, max_length=MAX_ATTACHMENTS)
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)


class SourceUploadAssociations(Protocol):
    """Trusted dependency proving every upload belongs to this original message.

    Concrete enrollment must qualify actor access/claim association on the
    installed Zulip server. Bot access, raw Markdown and has_attachment alone
    cannot implement this protocol faithfully.
    """

    async def authorize(
        self, source: HumanMessage, uploads: tuple[UploadReference, ...]
    ) -> SourceUploadAssociation: ...

    def current(self, witness: SourceUploadAssociation) -> bool: ...


def association_current(
    provider: SourceUploadAssociations | None, witness: SourceUploadAssociation
) -> bool:
    now = time.monotonic()
    try:
        return bool(
            provider is not None
            and witness.observed_at <= now < witness.expires_at
            and 0 < witness.expires_at - witness.observed_at <= 5
            and provider.current(witness) is True
        )
    except Exception:
        return False


async def associated_uploads(
    provider: SourceUploadAssociations | None,
    source: HumanMessage,
    uploads: tuple[UploadReference, ...],
) -> SourceUploadAssociation:
    if provider is None or source.is_bot or source.deleted:
        raise AccessDenied("original_message_upload_association_required")
    witness = await provider.authorize(source, uploads)
    if (
        not isinstance(witness, SourceUploadAssociation)
        or witness.source_sha256 != digest(source.model_dump(mode="json"))
        or witness.upload_paths != tuple("/user_uploads/" + upload.path_id for upload in uploads)
        or tuple(file.upload_path for file in witness.files) != witness.upload_paths
        or not association_current(provider, witness)
    ):
        raise AccessDenied("original_message_upload_association_not_current")
    return witness


def source_uploads(source: HumanMessage, realm_url: str) -> tuple[UploadReference, ...]:
    """Only rendered Markdown links/images, never code, raw HTML or remote URLs."""
    found: dict[str, UploadReference] = {}
    tokens = MarkdownIt("commonmark", {"html": False}).parse(source.text)
    if len(tokens) > 10000:
        raise ValueError("attachment_source_markdown_capacity")
    children = [child for token in tokens for child in token.children or ()]
    if len(children) > 10000:
        raise ValueError("attachment_source_markdown_capacity")
    for token in children:
        value = (
            token.attrGet("href")
            if token.type == "link_open"
            else (token.attrGet("src") if token.type == "image" else None)
        )
        if not value:
            continue
        if not isinstance(value, str):
            raise ValueError("attachment_markdown_url_must_be_text")
        path = urlsplit(value).path
        if not path.startswith(("/user_uploads/", "user_uploads/")):
            continue
        uploaded = upload_reference(value, realm_url)
        found.setdefault(uploaded.path_id, uploaded)
        if len(found) > MAX_ATTACHMENTS:
            raise ValueError("attachment_source_count_exceeds_limit")
    return tuple(found.values())


class ZulipPromptAttachmentImporter:
    def __init__(
        self,
        artifacts: ArtifactService,
        source: SourceReader,
        zulip: ZulipClient,
        downloader: SafeDownloader,
        *,
        associations: SourceUploadAssociations | None = None,
    ) -> None:
        self.artifacts, self.source, self.zulip, self.downloader = (
            artifacts,
            source,
            zulip,
            downloader,
        )
        self.associations = associations

    async def current(self, action_id: str, source: HumanMessage) -> tuple[Action, Binding]:
        if source.is_bot or source.deleted:
            raise AccessDenied("attachment_original_human_source_required")
        async with self.artifacts.db.sessions.begin() as session:
            if self.artifacts.fence is not None:
                await self.artifacts.fence.lock(session)
            action = await session.get(Action, action_id)
        if (
            action is None
            or action.state not in {"queued", "held"}
            or action.operation != "prompt"
            or action.actor_id != source.author_id
            or action.payload.get("source") != source.model_dump(mode="json")
            or digest(action.payload) != action.operation_digest
        ):
            raise Conflict("attachment_original_queued_action_required")
        binding = await self.artifacts.bindings.get(
            action.binding_id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (
            binding.revision != action.binding_revision
            or (binding.channel_id, binding.topic) != (source.channel_id, source.topic)
            or action.payload.get("reference") != reference(binding).model_dump(mode="json")
            or await self.source.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("attachment_original_source_or_binding_changed")
        return action, binding

    async def import_one(
        self,
        action_id: str,
        source: HumanMessage,
        upload: UploadReference,
        *,
        remaining: int,
        excluded_artifact_ids: frozenset[str] = frozenset(),
    ) -> PromptAttachmentReceipt:
        if type(remaining) is not int or not 0 <= remaining <= MAX_ATTACHMENT_BYTES:
            raise ValueError("attachment_remaining_total_required")
        if (
            type(excluded_artifact_ids) is not frozenset
            or len(excluded_artifact_ids) >= MAX_ATTACHMENTS
        ):
            raise ValueError("attachment_prior_artifact_capacity")
        for prior_id in excluded_artifact_ids:
            PromptAttachmentReceipt.canonical_object(prior_id)
        if self.associations is None:
            raise AccessDenied("original_message_upload_association_required")
        action, binding = await self.current(action_id, source)
        if upload not in source_uploads(source, self.zulip.url):
            raise AccessDenied("attachment_not_linked_in_original_message")
        association = await associated_uploads(self.associations, source, (upload,))
        metadata = association.files[0]
        if metadata.size > remaining:
            raise ValueError("attachment_total_size_exceeds_limit")
        # This API authenticates the Bot's right to retrieve the referenced
        # upload. Its signed URL is consumed once in a separate auth-free client.
        temporary = await self.zulip.temporary_file_url("/user_uploads/" + upload.path_id)
        async with self.downloader.open(temporary) as stream:
            if stream.declared_size is not None and stream.declared_size > remaining:
                raise ValueError("attachment_total_size_exceeds_limit")
            descriptor = FileDescriptor(filename=metadata.filename, mime_type=metadata.mime_type)
            await self.current(action_id, source)

            received = bytearray()
            async for chunk in stream.chunks():
                if len(received) + len(chunk) > remaining:
                    raise ValueError("attachment_total_size_exceeds_limit")
                received.extend(chunk)
        await self.current(action_id, source)
        current_association = await associated_uploads(self.associations, source, (upload,))
        if current_association.files != association.files or len(received) != metadata.size:
            raise Conflict("attachment_original_metadata_or_size_changed")
        data = bytes(received)
        checksum = hashlib.sha256(data).hexdigest()
        # Recover a crash between encrypted artifact commit and manifest CAS by
        # freshly fetching the authorized source, then matching exact bytes and
        # descriptor. A hash alone is not used as authorization or identity.
        async with self.artifacts.db.sessions() as session:
            candidates = (
                await session.scalars(
                    select(Artifact)
                    .where(
                        Artifact.action_id == action.id,
                        Artifact.binding_id == binding.id,
                        Artifact.binding_revision == binding.revision,
                        Artifact.source_message_id == source.message_id,
                        Artifact.actor_id == source.author_id,
                        Artifact.kind == "attachment",
                        Artifact.state == "ready",
                        Artifact.checksum == checksum,
                        Artifact.size_bytes == len(data),
                    )
                    .order_by(Artifact.created_at, Artifact.id)
                    .limit(21)
                )
            ).all()
        artifact_id = None
        for candidate in candidates:
            if candidate.id in excluded_artifact_ids:
                continue
            existing = await self.artifacts.read(candidate.id, source.realm_id, source.author_id)
            if existing.descriptor == descriptor and existing.content == data:
                artifact_id = existing.id
                break
        if artifact_id is None:
            if len(candidates) > 20:
                raise ValueError("attachment_recovery_candidates_exceed_limit")

            async def original_bytes() -> AsyncIterator[bytes]:
                yield data

            artifact_id = await self.artifacts.create(
                binding.id,
                source.realm_id,
                source.author_id,
                descriptor,
                original_bytes(),
                expected_size=len(data),
                expected_sha256=checksum,
                source_message_id=source.message_id,
                action_id=action.id,
            )
        await self.current(action_id, source)
        current_association = await associated_uploads(self.associations, source, (upload,))
        if current_association.files != association.files:
            raise Conflict("attachment_original_metadata_changed_after_import")
        content = await self.artifacts.read(artifact_id, source.realm_id, source.author_id)
        return PromptAttachmentReceipt(
            artifact_id=artifact_id,
            source_upload="/user_uploads/" + upload.path_id,
            source_message_id=source.message_id,
            source_sha256=digest(source.model_dump(mode="json")),
            filename=content.descriptor.filename,
            mime_type=content.descriptor.mime_type,
            size=len(content.content),
            sha256=content.sha256,
        )


class ArtifactPromptAttachmentProvider:
    """Resolve only a claimed action's frozen manifest with current source/access."""

    def __init__(
        self,
        artifacts: ArtifactService,
        source: SourceReader,
        realm_url: str,
        qualifications: Mapping[SessionRef, InlineAttachmentAttestation],
        *,
        associations: SourceUploadAssociations | None = None,
    ) -> None:
        self.artifacts, self.source, self.realm_url = artifacts, source, realm_url
        self.qualifications = MappingProxyType(dict(qualifications))
        self.associations = associations
        self._prepared: dict[
            str,
            tuple[
                ReferenceType[PreparedPromptAttachments],
                SessionRef,
                float,
                InlineAttachmentAttestation,
                SourceUploadAssociations,
                SourceUploadAssociation,
            ],
        ] = {}

    def qualified(self, ref: SessionRef, schema_sha256: str) -> bool:
        qualification = self.qualifications.get(ref)
        if qualification is None or self.associations is None:
            return False
        try:
            qualification.require(ref, schema_sha256)
            return True
        except ValueError:
            return False

    async def action(
        self,
        ref: SessionRef,
        action_id: str,
        source: HumanMessage,
        manifest: PromptAttachmentManifest,
    ) -> tuple[Action, Binding]:
        manifest.checked(source)
        async with self.artifacts.db.sessions() as session:
            action = await session.get(Action, action_id)
        if (
            action is None
            or action.state != "dispatching"
            or action.actor_id != source.author_id
            or action.operation != "prompt"
            or action.payload.get("operation") != "prompt"
            or action.payload.get("source") != source.model_dump(mode="json")
            or action.payload.get("reference") != ref.model_dump(mode="json")
            or action.payload.get("attachments") != manifest.model_dump(mode="json")
            or digest(action.payload) != action.operation_digest
        ):
            raise Conflict("attachment_claimed_action_identity_changed")
        binding = await self.artifacts.bindings.get(
            action.binding_id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (
            binding.revision != action.binding_revision
            or reference(binding) != ref
            or (binding.channel_id, binding.topic) != (source.channel_id, source.topic)
            or tuple("/user_uploads/" + u.path_id for u in source_uploads(source, self.realm_url))
            != tuple(f.source_upload for f in manifest.files)
            or await self.source.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("attachment_original_message_or_target_changed")
        return action, binding

    async def prepare(
        self,
        ref: SessionRef,
        action_id: str,
        source: HumanMessage,
        manifest: PromptAttachmentManifest,
    ) -> PreparedPromptAttachments:
        qualification = self.qualifications.get(ref)
        if qualification is None:
            raise ValueError("attachment_scope_not_enrolled")
        if self.associations is None:
            raise AccessDenied("original_message_upload_association_required")
        qualification.require(ref, qualification.contract_sha256)
        action, binding = await self.action(ref, action_id, source, manifest)
        files = []
        for receipt in manifest.files:
            async with self.artifacts.db.sessions() as session:
                saved = await session.get(Artifact, receipt.artifact_id)
            if (
                saved is None
                or saved.state != "ready"
                or saved.kind != "attachment"
                or saved.binding_id != binding.id
                or saved.binding_revision != binding.revision
                or saved.action_id != action_id
                or saved.actor_id != source.author_id
                or saved.source_message_id != source.message_id
                or saved.checksum != receipt.sha256
                or saved.size_bytes != receipt.size
            ):
                raise AccessDenied("attachment_not_imported_for_this_action")
            content = await self.artifacts.read(
                receipt.artifact_id, source.realm_id, source.author_id
            )
            if (content.descriptor.filename, content.descriptor.mime_type) != (
                receipt.filename,
                receipt.mime_type,
            ):
                raise Conflict("attachment_encrypted_descriptor_changed")
            qualification.require(
                ref, qualification.contract_sha256, mime_type=native_mime(content.content)
            )
            files.append(ResolvedPromptAttachment(receipt, content.content))
        prepared = PreparedPromptAttachments(
            tuple(files),
            allow_image_normalization=qualification.image_normalization_evidence_sha256 is not None,
        )
        prepared.checked(manifest)
        latest, _ = await self.action(ref, action_id, source, manifest)
        if latest.version != action.version or latest.operation_digest != action.operation_digest:
            raise Conflict("attachment_action_changed_during_resolution")
        associations = self.associations
        witness = await associated_uploads(
            associations,
            source,
            tuple(upload_reference(file.source_upload, self.realm_url) for file in manifest.files),
        )
        if tuple((file.filename, file.mime_type, file.size) for file in witness.files) != tuple(
            (file.filename, file.mime_type, file.size) for file in manifest.files
        ):
            raise Conflict("attachment_original_manifest_descriptor_changed")
        latest, _ = await self.action(ref, action_id, source, manifest)
        if (
            latest.version != action.version
            or latest.operation_digest != action.operation_digest
            or self.associations is not associations
            or not association_current(associations, witness)
        ):
            raise Conflict("attachment_source_or_association_changed_during_resolution")
        now = time.monotonic()
        self._prepared = {k: v for k, v in self._prepared.items() if v[2] > now}
        if len(self._prepared) >= 32:
            raise ValueError("attachment_preparation_capacity")
        self._prepared[action_id] = (
            weakref(prepared),
            ref,
            min(now + 5, witness.expires_at),
            qualification,
            associations,
            witness,
        )
        return prepared

    def current(self, ref: SessionRef, action_id: str, prepared: PreparedPromptAttachments) -> bool:
        saved = self._prepared.get(action_id)
        return bool(
            saved is not None
            and saved[0]() is prepared
            and saved[1] == ref
            and time.monotonic() < saved[2]
            and self.qualifications.get(ref) is saved[3]
            and self.associations is saved[4]
            and association_current(self.associations, saved[5])
        )
