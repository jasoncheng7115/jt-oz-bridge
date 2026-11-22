"""Original artifact-to-workspace preparation; no default runtime enrollment."""

import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from weakref import ReferenceType
from weakref import ref as weakref

from jt_oz_bridge.adapters.opencode.native_workspace import (
    NativeWorkspaceBatch,
    V2SharedWorkspaceHost,
)
from jt_oz_bridge.adapters.zulip.uploads import upload_reference
from jt_oz_bridge.domain.attachments import WorkspaceAttachmentManifest
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.domain.workspace_attachments import (
    PreparedWorkspaceAttachments,
    workspace_projection,
)
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.services.artifacts import ArtifactService
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.prompt_attachments import (
    SourceUploadAssociation,
    SourceUploadAssociations,
    associated_uploads,
    association_current,
    source_uploads,
)
from jt_oz_bridge.services.workspace_journal import WorkspaceJournal
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, WorkerLease


@dataclass(frozen=True)
class _Prepared:
    original: ReferenceType[PreparedWorkspaceAttachments]
    reference: SessionRef
    host: V2SharedWorkspaceHost
    native: NativeWorkspaceBatch
    association_provider: SourceUploadAssociations
    association: SourceUploadAssociation
    deadline: float


class ArtifactWorkspaceAttachmentProvider:
    def __init__(
        self,
        artifacts: ArtifactService,
        source: SourceReader,
        *,
        realm_id: str,
        realm_url: str,
        journals: Mapping[SessionRef, WorkspaceJournal],
        hosts: Mapping[SessionRef, V2SharedWorkspaceHost],
        associations: SourceUploadAssociations,
    ) -> None:
        if (
            artifacts.fence is None
            or not realm_id
            or not journals
            or set(journals) != set(hosts)
            or any(
                j.artifacts is not artifacts
                or j.fence != artifacts.fence
                or hosts[ref].files is not j.files
                or hosts[ref].namespace_sha256 != j.namespace_sha256
                for ref, j in journals.items()
            )
        ):
            raise ValueError("workspace_same_source_artifacts_fence_and_host_required")
        self.artifacts, self.source, self.fence = artifacts, source, artifacts.fence
        self.realm_id, self.realm_url = realm_id, realm_url
        self.journals, self.hosts = MappingProxyType(dict(journals)), MappingProxyType(dict(hosts))
        self.associations = associations
        self._issued: dict[str, _Prepared] = {}
        self._closed = False

    def qualified(self, reference: SessionRef, schema_sha256: str) -> bool:
        host = self.hosts.get(reference)
        return bool(
            not self._closed
            and self.artifacts.fence == self.fence
            and host is not None
            and host.qualified(reference, schema_sha256)
        )

    async def action(
        self,
        ref: SessionRef,
        action_id: str,
        source: HumanMessage,
        manifest: WorkspaceAttachmentManifest,
    ) -> tuple[Action, Binding, float]:
        manifest.checked(source)
        if source.realm_id != self.realm_id or self._closed:
            raise AccessDenied("workspace_original_realm_source_required")
        async with self.artifacts.db.sessions.begin() as session:
            await self.fence.lock(session)
            action = await session.get(Action, action_id)
            lease = await session.get(WorkerLease, "consumer")
            expiry = lease.expires_at if lease is not None else 0
        if action is None:
            raise Conflict("workspace_claimed_action_unavailable")
        WorkspaceJournal.claimed(action, source, manifest)
        if action.payload.get("reference") != ref.model_dump(mode="json"):
            raise Conflict("workspace_original_reference_changed")
        binding = await self.artifacts.bindings.get(
            action.binding_id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (
            binding.revision != action.binding_revision
            or reference(binding) != ref
            or (binding.channel_id, binding.topic) != (source.channel_id, source.topic)
            or tuple(
                "/user_uploads/" + upload.path_id
                for upload in source_uploads(source, self.realm_url)
            )
            != tuple(file.source_upload for file in manifest.files)
            or await self.source.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("workspace_original_source_binding_or_uploads_changed")
        return action, binding, expiry

    async def prepare(
        self,
        ref: SessionRef,
        action_id: str,
        source: HumanMessage,
        manifest: WorkspaceAttachmentManifest,
        original_text: str,
    ) -> PreparedWorkspaceAttachments:
        host, journal = self.hosts.get(ref), self.journals.get(ref)
        if (
            host is None
            or journal is None
            or not self.qualified(ref, host.reader.require(ref).contract_sha256)
        ):
            raise AccessDenied("workspace_native_scope_not_qualified")
        action, _, _ = await self.action(ref, action_id, source, manifest)
        if action.payload.get("text") != original_text:
            raise Conflict("workspace_original_frozen_text_changed")
        initial_associations = self.associations
        initial = await associated_uploads(
            initial_associations,
            source,
            tuple(upload_reference(file.source_upload, self.realm_url) for file in manifest.files),
        )
        if tuple((f.filename, f.mime_type, f.size) for f in initial.files) != tuple(
            (f.filename, f.mime_type, f.size) for f in manifest.files
        ):
            raise Conflict("workspace_original_upload_descriptors_changed_before_staging")
        if self.associations is not initial_associations or not association_current(
            initial_associations, initial
        ):
            raise Conflict("workspace_original_upload_authority_changed_before_staging")
        files = await journal.stage(action_id, source, manifest)
        native = await host.prove(ref, files)
        latest, _, _ = await self.action(ref, action_id, source, manifest)
        if (latest.version, latest.operation_digest) != (action.version, action.operation_digest):
            raise Conflict("workspace_claim_changed_during_staging")
        associations = self.associations
        association = await associated_uploads(
            associations,
            source,
            tuple(upload_reference(file.source_upload, self.realm_url) for file in manifest.files),
        )
        if tuple((f.filename, f.mime_type, f.size) for f in association.files) != tuple(
            (f.filename, f.mime_type, f.size) for f in manifest.files
        ):
            raise Conflict("workspace_current_upload_descriptors_changed")
        latest, _, lease_expiry = await self.action(ref, action_id, source, manifest)
        if (
            (latest.version, latest.operation_digest) != (action.version, action.operation_digest)
            or self.associations is not associations
            or not association_current(associations, association)
            or not host.current(native)
        ):
            raise Conflict("workspace_current_authority_changed_after_staging")
        projection = workspace_projection(
            ref,
            action_id,
            original_text,
            manifest,
            journal.files.namespace.path.name,
            native.evidence_sha256,
        )
        prepared = PreparedWorkspaceAttachments(
            ref,
            action_id,
            source.realm_id,
            digest(source.model_dump(mode="json")),
            action.operation_digest,
            projection,
        )
        prepared.checked(ref, action_id, source, manifest, original_text)
        now = time.monotonic()
        self._issued = {
            key: item
            for key, item in self._issued.items()
            if item.original() is not None and item.deadline > now
        }
        if len(self._issued) >= 32:
            raise ValueError("workspace_preparation_capacity")
        self._issued[action_id] = _Prepared(
            weakref(prepared),
            ref,
            host,
            native,
            associations,
            association,
            min(now + 5, association.expires_at, now + max(0, lease_expiry - time.time())),
        )
        if not self.current(ref, action_id, prepared):
            raise Conflict("workspace_prepared_original_authority_required")
        return prepared

    def current(
        self, ref: SessionRef, action_id: str, prepared: PreparedWorkspaceAttachments
    ) -> bool:
        saved = self._issued.get(action_id)
        return bool(
            not self._closed
            and self.artifacts.fence == self.fence
            and saved is not None
            and saved.original() is prepared
            and saved.reference == ref
            and saved.deadline > time.monotonic()
            and prepared.realm_id == self.realm_id
            and self.hosts.get(ref) is saved.host
            and saved.host.current(saved.native)
            and self.associations is saved.association_provider
            and association_current(self.associations, saved.association)
        )

    async def close(self) -> None:
        self._closed = True
        self._issued.clear()
