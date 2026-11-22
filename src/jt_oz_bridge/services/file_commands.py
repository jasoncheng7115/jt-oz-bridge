"""Capture original workspace files for an owned, immutable Human command.

This handler performs Native reads and encrypted local storage only. The durable
return journal owns later uploads; a command replay never captures a newer file.
"""

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator, Mapping
from typing import Protocol
from weakref import WeakValueDictionary

from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.files import NativeReadFile
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.artifacts import FileDescriptor
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.command_receipts import CommandClaim
from jt_oz_bridge.services.file_choices import FileChoices, file_argument
from jt_oz_bridge.services.file_returns import FileReturnJournal, requested_file
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer


class FileCaptureReader(Protocol):
    async def read(
        self, reference: SessionRef, path: str, *, maximum_bytes: int = MAX_ATTACHMENT_BYTES
    ) -> NativeReadFile: ...

    def current(self, file: NativeReadFile) -> bool: ...


class FileCommands:
    def __init__(
        self,
        journal: FileReturnJournal,
        readers: Mapping[SessionRef, FileCaptureReader],
        *,
        artifact_ttl_seconds: int = 7 * 86400,
        choices: FileChoices | None = None,
    ) -> None:
        if set(readers) != set(journal.readers) or any(
            reader is not journal.readers[ref] for ref, reader in readers.items()
        ):
            raise ValueError("file_capture_requires_original_journal_readers")
        if type(artifact_ttl_seconds) is not int or not 0 < artifact_ttl_seconds < 2**31:
            raise ValueError("file_capture_retention_lifetime_invalid")
        if choices is not None and (
            choices.bindings is not journal.bindings
            or choices.source is not journal.source
            or choices.fence != journal.fence
        ):
            raise ValueError("file_choices_original_source_scope_required")
        self.choices = choices
        self.artifact_ttl_seconds = artifact_ttl_seconds
        self.journal, self.readers = journal, readonly_enrollment(readers)
        self.bindings, self.reader, self.db, self.fence = (
            journal.bindings,
            journal.source,
            journal.db,
            journal.fence,
        )
        self.tr = Translator()
        self._locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
        self._slots = asyncio.Semaphore(2)

    def available(self, binding: Binding) -> bool:
        ref = reference(binding)
        return ref in self.readers and self.journal.readers.get(ref) is self.readers[ref]

    async def current(self, binding: Binding, source: HumanMessage, claim: CommandClaim) -> None:
        file_argument(source)
        if (
            claim.status != "claimed"
            or source.realm_id != self.journal.realm_id
            or (source.realm_id, source.channel_id, source.topic)
            != (binding.realm_id, binding.channel_id, binding.topic)
            or await self.reader.read(source.realm_id, source.message_id) != source
        ):
            raise Conflict("file_capture_original_command_source_changed")
        current = await self.bindings.get(
            binding.id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if current.revision != binding.revision or reference(current) != reference(binding):
            raise Conflict("file_capture_original_binding_changed")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            saved = await session.get(CommandReceipt, claim.id)
        if saved is None or (
            saved.version,
            saved.state,
            saved.holder,
            saved.fencing,
            saved.realm_id,
            saved.message_id,
            saved.actor_id,
            saved.channel_id,
            saved.topic,
            saved.source_revision,
            saved.source_hash,
            saved.command,
            saved.binding_id,
            saved.binding_revision,
        ) != (
            claim.version,
            "processing",
            self.fence.holder,
            self.fence.fencing,
            source.realm_id,
            source.message_id,
            source.author_id,
            source.channel_id,
            source.topic,
            source.revision,
            digest(source.model_dump(mode="json")),
            "file",
            binding.id,
            binding.revision,
        ):
            raise Conflict("file_capture_owned_command_claim_required")
        if not self.available(binding):
            raise Conflict("file_capture_reader_not_enrolled")

    async def existing(self, binding: Binding, source: HumanMessage) -> str | None:
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(FileTransfer)
                    .where(
                        FileTransfer.binding_id == binding.id,
                        FileTransfer.binding_revision == binding.revision,
                        FileTransfer.realm_id == source.realm_id,
                        FileTransfer.source_message_id == source.message_id,
                    )
                    .limit(2)
                )
            ).all()
        if len(rows) > 1:
            raise Conflict("file_capture_multiple_original_transfers")
        if not rows:
            return None
        row, plan = await self.journal.load(rows[0].id)
        if plan.source != source or plan.reference != reference(binding):
            raise Conflict("file_capture_existing_source_changed")
        await self.journal.current(plan)
        await self.journal.content(plan)
        return row.id

    async def artifact(self, binding: Binding, source: HumanMessage, file: NativeReadFile) -> str:
        projection = file.evidence.projection
        descriptor = FileDescriptor(filename=projection.filename, mime_type=projection.mime_type)
        async with self.db.sessions() as session:
            candidates = (
                await session.scalars(
                    select(Artifact)
                    .where(
                        Artifact.binding_id == binding.id,
                        Artifact.binding_revision == binding.revision,
                        Artifact.realm_id == source.realm_id,
                        Artifact.project_id == binding.project_id,
                        Artifact.actor_id == source.author_id,
                        Artifact.source_message_id == source.message_id,
                        Artifact.kind == "output",
                        Artifact.action_id.is_(None),
                        Artifact.state == "ready",
                        Artifact.size_bytes == projection.size,
                        Artifact.checksum == projection.sha256,
                    )
                    .order_by(Artifact.created_at, Artifact.id)
                    .limit(21)
                )
            ).all()
        # A fresh authorized Native read plus exact bytes/descriptor is required
        # to recover an artifact committed before journal preparation. No hash
        # alone and no unrelated actor/source/project artifact grants authority.
        for candidate in candidates:
            content = await self.journal.artifacts.read(
                candidate.id, source.realm_id, source.author_id
            )
            if content.descriptor == descriptor and content.content == file.content:
                return candidate.id
        if len(candidates) > 20:
            raise Conflict("file_capture_recovery_capacity")

        async def chunks() -> AsyncIterator[bytes]:
            for offset in range(0, len(file.content), 65536):
                yield file.content[offset : offset + 65536]

        return await self.journal.artifacts.create(
            binding.id,
            source.realm_id,
            source.author_id,
            descriptor,
            chunks(),
            kind="output",
            expected_size=projection.size,
            expected_sha256=projection.sha256,
            source_message_id=source.message_id,
            ttl_seconds=self.artifact_ttl_seconds,
        )

    async def capture(
        self, binding: Binding, source: HumanMessage, claim: CommandClaim, *, locale: Locale
    ) -> str:
        lock = self._locks.setdefault(claim.id, asyncio.Lock())
        async with lock, self._slots:
            await self.current(binding, source, claim)
            previous = await self.existing(binding, source)
            if previous is not None:
                return previous
            selection = None
            if file_argument(source).startswith("file:"):
                if self.choices is None:
                    raise Conflict("file_choice_provider_unavailable")
                selection = await self.choices.resolve(binding, source, claim)
            ref = reference(binding)
            path = selection.path if selection is not None else requested_file(source)
            selected = self.readers[ref]
            qualification = self.journal.uploader.require()
            enrolled = self.journal.uploader.client.attestation
            if enrolled is None or not {"upload", "download"} <= enrolled.verified_file_operations:
                raise Conflict("file_capture_return_contract_unavailable")
            maximum = min(
                MAX_ATTACHMENT_BYTES,
                self.journal.artifacts.maximum,
                qualification.maximum_file_bytes,
                self.journal.downloader.maximum,
            )
            file = await selected.read(ref, path, maximum_bytes=maximum)
            await self.current(binding, source, claim)
            projection = file.evidence.projection
            if (
                not selected.current(file)
                or file.evidence.reference != ref
                or file.evidence.relative_path != path
                or projection.filename != path.rsplit("/", 1)[-1]
                or file.evidence.contract_sha256 != self.bindings.control.contract_for(ref)
                or not isinstance(file.content, bytes)
                or len(file.content) != projection.size
                or projection.size > maximum
                or hashlib.sha256(file.content).hexdigest() != projection.sha256
            ):
                raise Conflict("file_capture_original_native_bytes_or_scope_changed")
            self.journal.scan_native(file)
            identity = await self.artifact(binding, source, file)
            await self.current(binding, source, claim)
            if not selected.current(file):
                # Storage/inspection can outlive the five-second read proof.
                # One bounded fresh read must re-prove the exact captured bytes;
                # do not widen the expiry or substitute a newer file.
                if (
                    time.time() < file.evidence.expires_at
                    or self.readers.get(ref) is not selected
                    or self.journal.readers.get(ref) is not selected
                ):
                    raise Conflict("file_capture_original_reader_invalidated")
                fresh = await selected.read(ref, path, maximum_bytes=maximum)
                await self.current(binding, source, claim)
                self.journal.rebind_scan(file, fresh)
                file = fresh
            return await self.journal.prepare(
                identity, source, file, locale=locale, selection=selection
            )

    async def route(
        self, binding: Binding, source: HumanMessage, locale: Locale, claim: CommandClaim
    ) -> str:
        identity = await self.capture(binding, source, claim, locale=locale)
        row, _ = await self.journal.load(identity)
        await self.current(binding, source, claim)
        return self.tr.render(
            "file.record",
            locale,
            state=self.tr.render("file.state." + row.state, locale),
        )
