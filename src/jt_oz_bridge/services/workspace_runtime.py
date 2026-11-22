"""Shared outgoing/incoming resources; enabled only by explicit trusted composition."""

import time
from collections.abc import Mapping
from types import MappingProxyType

from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.files import V2NativeFileReader
from jt_oz_bridge.adapters.opencode.native_workspace import V2SharedWorkspaceHost
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.services.attachment_imports import AttachmentImportJournal
from jt_oz_bridge.services.file_commands import FileCommands
from jt_oz_bridge.services.prompt_attachments import (
    SourceUploadAssociations,
    ZulipPromptAttachmentImporter,
)
from jt_oz_bridge.services.upload_associations import SSHUploadAssociations
from jt_oz_bridge.services.workspace_journal import WorkspaceJournal
from jt_oz_bridge.services.workspace_provider import ArtifactWorkspaceAttachmentProvider
from jt_oz_bridge.services.workspace_routes import WorkspaceProviderRoutes, WorkspaceRegistration


class WorkspaceIncoming:
    def __init__(
        self,
        files: FileCommands,
        associations: SourceUploadAssociations,
        journals: Mapping[SessionRef, WorkspaceJournal],
    ) -> None:
        outgoing = files.journal
        if (
            not journals
            or outgoing.artifacts.fence != files.fence
            or any(
                j.artifacts is not outgoing.artifacts
                or j.fence != files.fence
                or ref not in files.readers
                or not isinstance(files.readers[ref], V2NativeFileReader)
                for ref, j in journals.items()
            )
        ):
            raise ValueError("incoming_requires_same_artifacts_source_fence_and_original_readers")
        readers: dict[SessionRef, V2NativeFileReader] = {}
        for ref in journals:
            reader = files.readers[ref]
            if not isinstance(reader, V2NativeFileReader):
                raise ValueError("incoming_original_v2_reader_required")
            readers[ref] = reader
        self.readers = MappingProxyType(readers)
        self.original_clients = MappingProxyType(
            {ref: reader.client for ref, reader in readers.items()}
        )
        self.files = files
        self.associations = associations
        self.journals = MappingProxyType(dict(journals))
        self.hosts = {
            ref: V2SharedWorkspaceHost(readers[ref], journal.files)
            for ref, journal in journals.items()
        }
        self.provider = ArtifactWorkspaceAttachmentProvider(
            outgoing.artifacts,
            files.reader,
            realm_id=outgoing.realm_id,
            realm_url=outgoing.uploader.client.url,
            journals=self.journals,
            hosts=self.hosts,
            associations=associations,
        )
        importer = ZulipPromptAttachmentImporter(
            outgoing.artifacts,
            files.reader,
            outgoing.uploader.client,
            outgoing.downloader,
            associations=associations,
        )
        self.imports = AttachmentImportJournal(importer, files.fence, transport="workspace")
        self.clients = tuple(dict.fromkeys(readers[ref].client for ref in journals))
        self._installed: list[
            tuple[V2ExecutionClient, WorkspaceProviderRoutes, WorkspaceRegistration]
        ] = []
        self._closed = False
        self._started = False
        self._prune_at = 0.0

    async def start(self) -> None:
        if self._closed or self._started:
            raise ValueError("incoming_resource_start_once_required")
        try:
            if isinstance(self.associations, SSHUploadAssociations):
                config = self.associations.configuration()
                if (config.realm_id, config.realm_url) != (
                    self.files.journal.realm_id,
                    self.files.journal.uploader.client.url,
                ):
                    raise ValueError("incoming_current_source_configuration_changed")
            for ref, host in self.hosts.items():
                if not host.qualified(ref, host.reader.require(ref).contract_sha256):
                    raise ValueError("incoming_original_shared_namespace_not_qualified")
            for client in self.clients:
                previous = client.workspace_attachments
                if previous is not None and not isinstance(previous, WorkspaceProviderRoutes):
                    raise ValueError("incoming_cannot_replace_an_existing_provider")
                route = (
                    previous
                    if isinstance(previous, WorkspaceProviderRoutes)
                    else WorkspaceProviderRoutes()
                )
                registration = route.register(self.provider.realm_id, self.provider)
                self._installed.append((client, route, registration))
                client.workspace_attachments = route
            self._started = True
        except BaseException:
            await self.close()
            raise

    def qualified(self, ref: SessionRef, schema_sha256: str) -> bool:
        return bool(
            self._started
            and not self._closed
            and self.provider.qualified(ref, schema_sha256)
            and all(
                self.files.readers.get(key) is reader
                and reader.client is self.original_clients[key]
                for key, reader in self.readers.items()
            )
            and all(client.workspace_attachments is route for client, route, _ in self._installed)
        )

    async def prune_once(self) -> None:
        if self._started and not self._closed and time.monotonic() >= self._prune_at:
            for journal in dict.fromkeys(self.journals.values()):
                await journal.prune_expired(limit=10)
            self._prune_at = time.monotonic() + 60

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failures = 0
        try:
            for _client, route, registration in reversed(self._installed):
                try:
                    route.unregister(registration)
                except ValueError:
                    failures += 1
                # Preserve any other trusted realm registrations. A route with
                # no registrations remains a safe inert provider until disposal.
        finally:
            self._installed.clear()
            try:
                await self.provider.close()
            finally:
                for journal in dict.fromkeys(self.journals.values()):
                    journal.files.close()
        if failures:
            raise ValueError("incoming_registration_cleanup_failed")
