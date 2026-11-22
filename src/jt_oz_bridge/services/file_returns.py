"""Fenced, one-attempt artifact uploads and atomic same-topic file publications.

An acknowledged upload is not a delivered message. Unknown POST results never
become retryable. Signed download URLs are consumed in memory and never saved.
"""

import asyncio
import hashlib
import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4
from weakref import ReferenceType
from weakref import ref as weakref

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.files import NativeFileEvidence, NativeReadFile
from jt_oz_bridge.adapters.zulip.download import SafeDownloader
from jt_oz_bridge.adapters.zulip.file_upload import UploadedFileReceipt, ZulipFileUploader
from jt_oz_bridge.adapters.zulip.uploads import upload_markdown_link, upload_reference
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.attachments import MAX_ATTACHMENT_BYTES, NativeAttachmentProjection
from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.domain.delivery import (
    MARKER_FOOTER_SIZE,
    DeliveryNotSent,
    DeliveryRateLimited,
    DeliveryRejected,
    original_write_witness,
    with_marker,
)
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage, SourceReader
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.i18n import Translator
from jt_oz_bridge.security.policy import AccessDenied, Permission
from jt_oz_bridge.security.redaction import PATTERNS, RedactionError, redact_text
from jt_oz_bridge.security.workspace_paths import disclosed_path
from jt_oz_bridge.services.artifacts import ArtifactContent, ArtifactService
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.file_choices import FileTokenUse, file_argument, verify_file_use
from jt_oz_bridge.services.generated_output_plans import GeneratedFileReturnPlan
from jt_oz_bridge.services.outbox import OutboundPayload, Outbox, QueuedBatch, batch_digest
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.services.session_export_plans import TranscriptExportPlan
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob, GeneratedOutputRecord
from jt_oz_bridge.storage.models import AuditEvent, Delivery, DeliveryBatch, Grant, WorkerLease
from jt_oz_bridge.storage.statements import insert

STATES = {
    "prepared",
    "uploading",
    "uploaded",
    "verified",
    "queued",
    "held",
    "rejected",
    "ambiguous",
}
RENDERER: Literal["original-file-return-v1"] = "original-file-return-v1"
FOOTER_SIZE = MARKER_FOOTER_SIZE


class FileReturnDeferred(Conflict):
    """Capture is still pending; preserve the unsent transfer for its worker."""


def requested_file(source: HumanMessage) -> str:
    value = file_argument(source)
    if value.startswith("file:"):
        raise AccessDenied("file_choice_selection_receipt_required")
    return disclosed_path(value)


def code_reference_projection(text: str) -> str:
    """Scan code values, not names of variables holding values at runtime.

    Only the temporary scanner view changes. Keep the RHS so high-confidence
    token/private-key patterns still inspect it. Original file bytes are intact.
    """

    def project(match: re.Match[str]) -> str:
        prefix = match.group(1)
        value = match.group(0)[len(prefix) :].strip().rstrip(",)]}")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value) or re.match(
            r"^[A-Za-z_][A-Za-z0-9_.]*(?:\[|\()", value
        ):
            return (
                '"datafield": ' + match.group(0)[len(prefix) :]
                if ":" in prefix
                else "datafield=" + match.group(0)[len(prefix) :]
            )
        return match.group(0)

    for pattern, _ in (PATTERNS[0], PATTERNS[-1]):
        text = pattern.sub(project, text)
    return text


def check_content(content: bytes, filename: str = "") -> None:
    # Bounded recognizable-secret check, never rewrite original bytes or unpack
    # archives. This is supplementary to workspace/path authorization, not DLP.
    for offset in range(0, len(content), 65536):
        text = content[max(0, offset - 1024) : offset + 65536].decode("utf-8", errors="ignore")
        if filename.rpartition(".")[2].casefold() in {
            "py",
            "js",
            "ts",
            "tsx",
            "jsx",
            "go",
            "rs",
            "java",
            "cs",
            "c",
            "cpp",
            "h",
            "hpp",
            "html",
            "htm",
        }:
            text = code_reference_projection(text)
        try:
            if redact_text(text)[1]:
                raise AccessDenied("file_return_recognizable_secret_disabled")
        except RedactionError:
            raise AccessDenied("file_return_recognizable_secret_disabled") from None


class NativeFileWitness(Protocol):
    def current(self, file: NativeReadFile) -> bool: ...


class FileReturnPlan(ControlModel):
    format: Literal["original-file-return-v1", "original-file-choice-return-v1"] = RENDERER
    selection: FileTokenUse | None = None
    id: str
    artifact_id: str
    binding_id: str
    binding_revision: int = Field(strict=True, gt=0)
    source: HumanMessage
    reference: SessionRef
    native: NativeFileEvidence
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
    def consistent(self) -> "FileReturnPlan":
        for value in (self.id, self.artifact_id, self.binding_id):
            if str(UUID(value)) != value:
                raise ValueError("canonical_file_return_identity_required")
        if (
            self.reference != self.native.reference
            or self.projection != self.native.projection
            or self.projection.filename != self.native.relative_path.rsplit("/", 1)[-1]
            or (
                self.selection.checked(self.source, self.reference)
                if self.selection is not None
                else requested_file(self.source)
            )
            != self.native.relative_path
            or (self.selection is not None) != (self.format == "original-file-choice-return-v1")
            or not self.native.observed_at < self.native.expires_at <= self.native.observed_at + 5
        ):
            raise ValueError("file_return_original_native_capture_changed")
        if self.upload is not None and (
            self.upload.realm_id,
            self.upload.bot_user_id,
            self.upload.source,
            self.upload.filename_stored,
        ) != (self.source.realm_id, self.bot_user_id, self.projection, self.projection.filename):
            raise ValueError("file_return_upload_scope_changed")
        if (self.bytes_verified and self.upload is None) or (
            self.batch_id is not None and not self.bytes_verified
        ):
            raise ValueError("file_return_incomplete_publication_evidence")
        return self

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value: dict[str, Any] = handler(self)
        if self.selection is None:
            value.pop("selection", None)
        return value


AnyFileReturnPlan = FileReturnPlan | GeneratedFileReturnPlan | TranscriptExportPlan


def artifact_source_id(plan: AnyFileReturnPlan) -> int:
    return (
        plan.preview.preview_source if isinstance(plan, TranscriptExportPlan) else plan.source
    ).message_id


def read_plan(row: FileTransfer) -> AnyFileReturnPlan:
    if digest(row.payload) != row.payload_hash:
        raise Conflict("file_return_encrypted_plan_changed")
    plan = (
        TranscriptExportPlan.model_validate(row.payload)
        if row.payload.get("format") == "safe-conversation-return-v1"
        else GeneratedFileReturnPlan.model_validate(row.payload)
        if row.payload.get("format") == "generated-file-return-v1"
        else FileReturnPlan.model_validate(row.payload)
    )
    if (
        plan.id,
        plan.artifact_id,
        plan.binding_id,
        plan.binding_revision,
        plan.source.realm_id,
        plan.source.message_id,
        plan.source.author_id,
        plan.batch_id,
    ) != (
        row.id,
        row.artifact_id,
        row.binding_id,
        row.binding_revision,
        row.realm_id,
        row.source_message_id,
        row.actor_id,
        row.batch_id,
    ):
        raise Conflict("file_return_index_scope_changed")
    if row.state not in STATES or row.attempts < 0 or row.version < 1:
        raise Conflict("file_return_state_invalid")
    expected = {
        "prepared": (False, False, False),
        "uploading": (False, False, False),
        "ambiguous": (False, False, False),
        "rejected": (False, False, False),
        "uploaded": (True, False, False),
        "verified": (True, True, False),
        "queued": (True, True, True),
    }
    flags = (plan.upload is not None, plan.bytes_verified, plan.batch_id is not None)
    if (
        row.state != "held"
        and flags != expected[row.state]
        or row.state == "held"
        and plan.batch_id is not None
    ):
        raise Conflict("file_return_state_evidence_mismatch")
    return plan


class FileReturnJournal:
    def __init__(
        self,
        artifacts: ArtifactService,
        source: SourceReader,
        outbox: Outbox,
        uploader: ZulipFileUploader,
        downloader: SafeDownloader,
        readers: Mapping[SessionRef, NativeFileWitness],
        *,
        message_limit: int,
        topic_limit: int,
    ) -> None:
        if (
            artifacts.bindings is not outbox.bindings
            or artifacts.fence is None
            or artifacts.fence != outbox.fence
            or type(message_limit) is not int
            or not 512 <= message_limit <= 1000000
            or type(topic_limit) is not int
            or not 1 <= topic_limit <= 10000
            or uploader.client.attestation is None
            or outbox.bot_user_id != uploader.client.attestation.bot_user_id
            or not {"upload", "download"} <= uploader.client.attestation.verified_file_operations
        ):
            raise ValueError("file_return_shared_fence_scope_and_bot_required")
        self.artifacts, self.bindings, self.db, self.fence = (
            artifacts,
            artifacts.bindings,
            artifacts.db,
            artifacts.fence,
        )
        self.source, self.outbox, self.uploader, self.downloader = (
            source,
            outbox,
            uploader,
            downloader,
        )
        self.readers = readonly_enrollment(readers)
        self.message_limit, self.topic_limit = message_limit, topic_limit
        self.tr = Translator()
        self.realm_id = uploader.client.attestation.realm_id
        self._slots = asyncio.Semaphore(2)
        self._scans: dict[
            int, tuple[ReferenceType[NativeReadFile], float, str, str, NativeFileWitness]
        ] = {}

    def scan_native(self, file: NativeReadFile) -> None:
        """Avoid scanning identical original bytes twice during one capture.

        Only an enrolled reader's current original object may start inspection.
        The memo records immutable byte-inspection facts, not Native authority.
        A slow scan may outlive that object's five-second proof; preparation
        still requires a current original witness. Later stages scan anew.
        """
        selected = self.readers.get(file.evidence.reference)
        if selected is None or not selected.current(file):
            raise Conflict("file_return_original_native_scan_witness_required")
        projection = file.evidence.projection
        if (
            not isinstance(file.content, bytes)
            or len(file.content) != projection.size
            or hashlib.sha256(file.content).hexdigest() != projection.sha256
        ):
            raise Conflict("file_return_original_native_scan_bytes_changed")
        check_content(file.content, projection.filename)
        now = time.monotonic()
        self._scans = {k: v for k, v in self._scans.items() if v[0]() is not None and v[1] > now}
        if len(self._scans) >= 32:
            raise Conflict("file_return_original_scan_capacity")
        self._scans[id(file)] = (
            weakref(file),
            now + 30,
            projection.filename,
            projection.sha256,
            selected,
        )

    def rebind_scan(self, original: NativeReadFile, fresh: NativeReadFile) -> None:
        """Reuse inspected identical bytes only with a fresh original read.

        This never renews a Native proof. The reader must have issued the new
        object, and all scope/owner/policy/descriptor/ETag data must agree. The
        resource fence may advance between two reads of the same stable file.
        """
        memo = self._scans.get(id(original))
        selected = self.readers.get(original.evidence.reference)
        if (
            memo is None
            or memo[0]() is not original
            or memo[1] <= time.monotonic()
            or selected is None
            or memo[4] is not selected
            or not selected.current(fresh)
            or original.evidence.model_dump(exclude={"observed_at", "expires_at", "resource_fence"})
            != fresh.evidence.model_dump(exclude={"observed_at", "expires_at", "resource_fence"})
            or (memo[2], memo[3])
            != (fresh.evidence.projection.filename, fresh.evidence.projection.sha256)
            or fresh.content != original.content
        ):
            raise Conflict("file_return_fresh_read_does_not_match_inspected_original")
        self._scans[id(fresh)] = (weakref(fresh), memo[1], memo[2], memo[3], selected)
        if fresh is not original:
            self._scans.pop(id(original), None)

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            identity = await session.scalar(
                select(FileTransfer.id)
                .where(
                    FileTransfer.realm_id == self.realm_id,
                    FileTransfer.state.in_(("prepared", "uploaded", "verified")),
                    FileTransfer.retry_at <= time.time(),
                    ~select(GeneratedCaptureJob.action_id)
                    .join(
                        GeneratedOutputRecord,
                        GeneratedOutputRecord.action_id == GeneratedCaptureJob.action_id,
                    )
                    .where(
                        GeneratedOutputRecord.transfer_id == FileTransfer.id,
                        GeneratedCaptureJob.state != "frozen",
                    )
                    .exists(),
                )
                .order_by(FileTransfer.created_at, FileTransfer.id)
                .limit(1)
            )
        return str(identity) if identity is not None else None

    async def load(self, identity: str) -> tuple[FileTransfer, AnyFileReturnPlan]:
        async with self.db.sessions() as session:
            row = await session.get(FileTransfer, identity)
        if row is None:
            raise Conflict("file_return_unavailable")
        return row, read_plan(row)

    async def authorize_source(self, plan: AnyFileReturnPlan) -> None:
        if isinstance(plan, GeneratedFileReturnPlan):
            raise Conflict("generated_return_authorizer_not_enrolled")
        if isinstance(plan, TranscriptExportPlan):
            raise Conflict("session_export_authorizer_not_enrolled")
        if plan.selection is None:
            requested_file(plan.source)
        else:
            plan.selection.checked(plan.source, plan.reference)
            await verify_file_use(self.bindings, plan.source, plan.selection)
        if plan.source.realm_id != self.realm_id or plan.reference not in self.readers:
            raise Conflict("file_return_reader_or_realm_enrollment_changed")

    async def lock_plan(self, session: AsyncSession, plan: AnyFileReturnPlan) -> None:
        if isinstance(plan, GeneratedFileReturnPlan):
            raise Conflict("generated_return_authorizer_not_enrolled")
        if isinstance(plan, TranscriptExportPlan):
            raise Conflict("session_export_authorizer_not_enrolled")

    async def publishable(self, plan: AnyFileReturnPlan) -> None:
        """Automatic captures can defer network work until every original file freezes."""

    async def current(self, plan: AnyFileReturnPlan) -> Binding:
        await self.authorize_source(plan)
        if await self.source.read(plan.source.realm_id, plan.source.message_id) != plan.source:
            raise Conflict("file_return_original_human_source_changed")
        binding = await self.bindings.get(
            plan.binding_id, plan.source.realm_id, plan.source.author_id, Permission.OPERATE
        )
        if (
            binding.revision,
            reference(binding),
            binding.realm_id,
            binding.channel_id,
            binding.topic,
        ) != (
            plan.binding_revision,
            plan.reference,
            plan.source.realm_id,
            plan.source.channel_id,
            plan.source.topic,
        ):
            raise Conflict("file_return_original_binding_changed")
        attestation = self.uploader.require()
        enrolled = self.uploader.client.attestation
        if enrolled is None or not {"upload", "download"} <= enrolled.verified_file_operations:
            raise Conflict("file_return_upload_and_readback_contract_required")
        if plan.projection.size > min(attestation.maximum_file_bytes, self.downloader.maximum):
            raise Conflict("file_return_actual_transfer_limit_exceeded")
        if (plan.source.realm_id, plan.realm_url, plan.bot_user_id) != (
            attestation.realm_id,
            self.uploader.client.url,
            attestation.bot_user_id,
        ):
            raise Conflict("file_return_original_zulip_identity_changed")
        async with self.db.sessions() as session:
            saved = await session.get(Artifact, plan.artifact_id)
        if (
            saved is None
            or (
                saved.binding_id,
                saved.binding_revision,
                saved.realm_id,
                saved.project_id,
                saved.actor_id,
                saved.source_message_id,
                saved.state,
                saved.size_bytes,
                saved.checksum,
            )
            != (
                binding.id,
                binding.revision,
                binding.realm_id,
                binding.project_id,
                plan.source.author_id,
                artifact_source_id(plan),
                "ready",
                plan.projection.size,
                plan.projection.sha256,
            )
            or saved.kind not in {"output", "tool_output", "export"}
        ):
            raise Conflict("file_return_artifact_provenance_changed")
        if saved.expires_at <= time.time() and not await self.artifacts.protected(saved):
            raise Conflict("file_return_artifact_expired")
        return binding

    async def operator_lock(self, session: AsyncSession, binding: Binding, actor: int) -> None:
        await lock_output_scope(self.bindings, session, binding)
        grant = await session.scalar(
            select(Grant)
            .where(
                Grant.realm_id == binding.realm_id,
                Grant.project_id == binding.project_id,
                Grant.user_id == actor,
                Grant.active.is_(True),
                Grant.role.in_(("operator", "administrator")),
            )
            .with_for_update()
        )
        if grant is None:
            raise AccessDenied("file_return_operator_grant_changed")

    async def content(
        self, plan: AnyFileReturnPlan, *, native: NativeReadFile | None = None
    ) -> ArtifactContent:
        value = await self.artifacts.read(
            plan.artifact_id, plan.source.realm_id, plan.source.author_id
        )
        if (
            value.descriptor.filename,
            value.descriptor.mime_type,
            len(value.content),
            value.sha256,
        ) != (
            plan.projection.filename,
            plan.projection.mime_type,
            plan.projection.size,
            plan.projection.sha256,
        ):
            raise Conflict("file_return_original_artifact_bytes_changed")
        scanned = self._scans.get(id(native)) if native is not None else None
        if not (
            native is not None
            and scanned is not None
            and scanned[0]() is native
            and scanned[4] is self.readers.get(native.evidence.reference)
            and scanned[1] > time.monotonic()
            and (scanned[2], scanned[3]) == (value.descriptor.filename, value.sha256)
            and isinstance(plan, FileReturnPlan)
            and native.evidence == plan.native
            and native.content == value.content
        ):
            check_content(value.content, value.descriptor.filename)
        return value

    async def prepare(
        self,
        artifact_id: str,
        source: HumanMessage,
        file: NativeReadFile,
        *,
        locale: Locale = "en",
        selection: FileTokenUse | None = None,
    ) -> str:
        source = HumanMessage.model_validate(source.model_dump(mode="json"))
        path = (
            selection.checked(source, file.evidence.reference)
            if selection is not None
            else requested_file(source)
        )
        native = NativeFileEvidence.model_validate(file.evidence.model_dump(mode="json"))
        selected = self.readers.get(native.reference)
        if (
            selected is None
            or not selected.current(file)
            or path != native.relative_path
            or native.contract_sha256 != self.bindings.control.contract_for(native.reference)
        ):
            raise Conflict("file_return_original_native_witness_required")
        async with self.db.sessions() as session:
            saved = await session.get(Artifact, artifact_id)
        if saved is None:
            raise Conflict("file_return_artifact_missing")
        plan = FileReturnPlan(
            format="original-file-choice-return-v1" if selection is not None else RENDERER,
            selection=selection,
            id=str(uuid4()),
            artifact_id=artifact_id,
            binding_id=saved.binding_id,
            binding_revision=saved.binding_revision,
            source=source,
            reference=native.reference,
            native=native,
            projection=native.projection,
            locale=locale,
            realm_url=self.uploader.client.url,
            bot_user_id=self.outbox.bot_user_id,
            message_limit=self.message_limit,
            topic_limit=self.topic_limit,
        )
        binding = await self.current(plan)
        content = await self.content(plan, native=file)
        if (
            content.content != file.content
            or not selected.current(file)
            or self.readers.get(native.reference) is not selected
        ):
            raise Conflict("file_return_native_bytes_or_witness_changed")
        key = digest(
            {
                "artifact": artifact_id,
                "source": source.model_dump(mode="json"),
                "binding": binding.id,
                "revision": binding.revision,
                "bot": plan.bot_user_id,
            }
        )
        payload = plan.model_dump(mode="json")
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.operator_lock(session, binding, source.author_id)
            artifact = await session.get(Artifact, artifact_id, with_for_update=True)
            if artifact is None or artifact.version != saved.version or artifact.state != "ready":
                raise Conflict("file_return_artifact_changed_before_prepare_commit")
            if artifact.expires_at <= time.time() and not await self.artifacts.protected_in_session(
                session, artifact
            ):
                raise Conflict("file_return_artifact_expired_before_prepare_commit")
            if not selected.current(file):
                raise Conflict("file_return_native_witness_expired_before_commit")
            created = (
                await session.execute(
                    insert(self.db, FileTransfer)
                    .values(
                        id=plan.id,
                        dedupe_key=key,
                        artifact_id=artifact_id,
                        binding_id=binding.id,
                        binding_revision=binding.revision,
                        realm_id=source.realm_id,
                        source_message_id=source.message_id,
                        actor_id=source.author_id,
                        state="prepared",
                        version=1,
                        attempts=0,
                        retry_at=0,
                        payload=payload,
                        payload_hash=digest(payload),
                    )
                    .on_conflict_do_nothing(index_elements=["dedupe_key"])
                    .returning(FileTransfer.id)
                )
            ).scalar_one_or_none()
            if created is not None:
                session.add(
                    AuditEvent(
                        actor=f"{source.realm_id}:{source.author_id}",
                        event="file_return_prepared",
                        object_id=plan.id,
                    )
                )
                return str(created)
            row = (
                await session.scalars(select(FileTransfer).where(FileTransfer.dedupe_key == key))
            ).one()
            existing = read_plan(row)
            if existing.model_dump(
                exclude={"id", "upload", "bytes_verified", "batch_id", "native"}
            ) != plan.model_dump(exclude={"id", "upload", "bytes_verified", "batch_id", "native"}):
                raise Conflict("file_return_deduplication_scope_changed")
            return row.id

    async def save(
        self,
        expected: FileTransfer,
        plan: AnyFileReturnPlan,
        state: str,
        *,
        reason: str | None = None,
        retry_at: float = 0,
    ) -> FileTransfer:
        # Receipt persistence deliberately does not require still-current grants:
        # preserve a known upstream ACK even if authorization was revoked in flight.
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            row = await session.scalar(
                select(FileTransfer).where(FileTransfer.id == expected.id).with_for_update()
            )
            if row is None or (row.version, row.state, row.payload_hash) != (
                expected.version,
                expected.state,
                expected.payload_hash,
            ):
                raise Conflict("file_return_attempt_changed")
            original = read_plan(row)
            transitions = {
                "prepared": {"prepared", "held"},
                "uploading": {"uploaded", "held", "prepared", "rejected", "ambiguous"},
                "uploaded": {"uploaded", "verified", "held"},
                "verified": {"verified", "held"},
            }
            changing = {"upload", "bytes_verified", "batch_id"}
            if (
                state not in transitions.get(row.state, set())
                or original.model_dump(exclude=changing) != plan.model_dump(exclude=changing)
                or original.batch_id != plan.batch_id
                or original.upload is not None
                and original.upload != plan.upload
                or original.bytes_verified
                and not plan.bytes_verified
            ):
                raise Conflict("file_return_immutable_plan_or_transition_changed")
            row.payload = plan.model_dump(mode="json")
            row.payload_hash = digest(row.payload)
            row.state, row.status_reason, row.retry_at = state, reason, retry_at
            row.version += 1
            row.updated_at = time.time()
            row.batch_id = plan.batch_id
            read_plan(row)
            session.add(AuditEvent(actor="worker", event="file_return_" + state, object_id=row.id))
        return row

    async def claim(
        self, saved: FileTransfer, plan: AnyFileReturnPlan, binding: Binding
    ) -> tuple[FileTransfer, float]:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.operator_lock(session, binding, plan.source.author_id)
            await self.lock_plan(session, plan)
            row = await session.scalar(
                select(FileTransfer).where(FileTransfer.id == saved.id).with_for_update()
            )
            if (
                row is None
                or row.state != "prepared"
                or row.version != saved.version
                or row.payload_hash != saved.payload_hash
                or row.retry_at > time.time()
            ):
                raise Conflict("file_return_upload_already_claimed")
            read_plan(row)
            lease = await session.get(WorkerLease, "consumer")
            assert lease is not None
            deadline = min(time.time() + 5, lease.expires_at)
            row.state, row.holder, row.fencing = "uploading", self.fence.holder, self.fence.fencing
            row.attempts += 1
            row.version += 1
            row.updated_at = time.time()
            session.add(
                AuditEvent(actor="worker", event="file_return_upload_claimed", object_id=row.id)
            )
            if isinstance(plan, TranscriptExportPlan) and not self.export_scope_witness(plan)():
                raise Conflict("session_export_scope_changed_before_upload_claim")
        return row, deadline

    def export_scope_witness(self, plan: TranscriptExportPlan) -> Callable[[], bool]:
        raise Conflict("session_export_current_scope_provider_required")

    async def upload(self, saved: FileTransfer, plan: AnyFileReturnPlan) -> str:
        await self.publishable(plan)
        binding = await self.current(plan)
        content = await self.content(plan)
        # Scope is refreshed after decrypting/scanning, before the durable claim.
        binding = await self.current(plan)
        monotonic_deadline = time.monotonic() + 5
        claimed, deadline = await self.claim(saved, plan, binding)
        # Only export's additional origin needs this Native scope witness.
        # Manual/generated file behavior and their existing guards are unchanged.
        export_current = (
            self.export_scope_witness(plan) if isinstance(plan, TranscriptExportPlan) else None
        )

        def witness() -> bool:
            return (
                time.time() < deadline
                and time.monotonic() < monotonic_deadline
                and (export_current is None or export_current())
            )

        def before_send() -> None:
            if not witness():
                raise DeliveryNotSent("file_return_original_scope_witness_expired")

        try:
            with original_write_witness(witness):
                receipt = await self.uploader.upload(
                    plan.projection, content.content, before_send=before_send
                )
            received = UploadedFileReceipt.model_validate(receipt.model_dump(mode="json"))
            approved = self.uploader.require()
            if (
                received.realm_id,
                received.bot_user_id,
                received.source,
                received.semantics_sha256,
                received.installed_evidence_sha256,
            ) != (
                plan.source.realm_id,
                plan.bot_user_id,
                plan.projection,
                approved.semantics_sha256,
                approved.installed_evidence_sha256,
            ) or not upload_reference(received.upload_url, plan.realm_url).path_id.startswith(
                str(approved.upload_realm_id) + "/"
            ):
                raise Conflict("file_return_upload_receipt_changed")
        except DeliveryNotSent:
            return (await self.save(claimed, plan, "held", reason="known_not_sent")).state
        except DeliveryRateLimited as error:
            return (
                await self.save(
                    claimed,
                    plan,
                    "prepared",
                    reason="explicit_rate_limit",
                    retry_at=time.time() + error.retry_after,
                )
            ).state
        except DeliveryRejected:
            return (
                await self.save(claimed, plan, "rejected", reason="explicit_upload_rejection")
            ).state
        except asyncio.CancelledError:
            try:
                await asyncio.shield(
                    self.save(claimed, plan, "ambiguous", reason="cancelled_during_upload")
                )
            except (ValueError, OSError):
                pass
            raise
        except Exception:
            return (
                await self.save(claimed, plan, "ambiguous", reason="upload_outcome_unknown")
            ).state
        # If this commit fails, leave uploading; recovery must never POST again.
        return (
            await self.save(claimed, plan.model_copy(update={"upload": received}), "uploaded")
        ).state

    async def verify(self, saved: FileTransfer, plan: AnyFileReturnPlan) -> str:
        await self.publishable(plan)
        if saved.state != "uploaded" or plan.upload is None:
            raise Conflict("file_return_upload_ack_required")
        await self.current(plan)
        signed = await self.uploader.client.temporary_file_url(plan.upload.upload_url)
        checksum, count = hashlib.sha256(), 0
        async with self.downloader.open(signed) as download:
            if (
                download.mime_type.casefold() != plan.projection.mime_type.casefold()
                or download.declared_size is not None
                and download.declared_size != plan.projection.size
            ):
                raise Conflict("file_return_uploaded_descriptor_changed")
            async for chunk in download.chunks():
                count += len(chunk)
                if count > min(MAX_ATTACHMENT_BYTES, plan.projection.size):
                    raise Conflict("file_return_uploaded_size_changed")
                checksum.update(chunk)
        if count != plan.projection.size or checksum.hexdigest() != plan.projection.sha256:
            raise Conflict("file_return_uploaded_bytes_changed")
        await self.current(plan)
        return (
            await self.save(saved, plan.model_copy(update={"bytes_verified": True}), "verified")
        ).state

    def page(self, plan: AnyFileReturnPlan) -> str:
        if plan.upload is None or not plan.bytes_verified:
            raise Conflict("file_return_not_verified_for_publication")
        link = upload_markdown_link(
            plan.upload.upload_url, plan.projection.filename, plan.realm_url
        )
        title = self.tr.render("file.ready", plan.locale)
        page = title + "\n\n" + link + "\n\nSHA-256: `" + plan.projection.sha256 + "`"
        if len(page) + FOOTER_SIZE > plan.message_limit:
            # Preserve the original name in the file/receipt; a short visible
            # label avoids overflowing small message caps with entity escapes.
            label = self.tr.render("file.download", plan.locale)
            link = upload_markdown_link(plan.upload.upload_url, label, plan.realm_url)
            page = title + "\n\n" + link + "\n\nSHA-256: `" + plan.projection.sha256 + "`"
        return page

    async def publish(self, saved: FileTransfer, plan: AnyFileReturnPlan) -> QueuedBatch:
        await self.publishable(plan)
        binding = await self.current(plan)
        if saved.state not in {"verified", "queued"}:
            raise Conflict("file_return_not_verified_for_publication")
        page = self.page(plan)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.operator_lock(session, binding, plan.source.author_id)
            await self.lock_plan(session, plan)
            row = await session.scalar(
                select(FileTransfer).where(FileTransfer.id == saved.id).with_for_update()
            )
            if row is None:
                raise Conflict("file_return_publication_unavailable")
            current = read_plan(row)
            if current.model_dump(exclude={"batch_id"}) != plan.model_dump(
                exclude={"batch_id"}
            ) or row.state not in {"verified", "queued"}:
                raise Conflict("file_return_publication_changed")
            batch = await self.outbox.queue_batch_in_session(
                session,
                "file-return:" + row.id,
                binding,
                (page,),
                renderer_version=RENDERER,
                message_limit=plan.message_limit,
                topic_limit=plan.topic_limit,
                priority=100,
            )
            if isinstance(plan, TranscriptExportPlan) and not self.export_scope_witness(plan)():
                raise Conflict("session_export_scope_changed_after_batch_validation")
            if row.state == "queued":
                if current.batch_id != batch.id:
                    raise Conflict("file_return_publication_batch_changed")
                return batch
            changed = plan.model_copy(update={"batch_id": batch.id})
            row.payload = changed.model_dump(mode="json")
            row.payload_hash = digest(row.payload)
            row.batch_id, row.state, row.version, row.updated_at = (
                batch.id,
                "queued",
                row.version + 1,
                time.time(),
            )
            read_plan(row)
            session.add(AuditEvent(actor="worker", event="file_return_queued", object_id=row.id))
            if isinstance(plan, TranscriptExportPlan) and not self.export_scope_witness(plan)():
                raise Conflict("session_export_scope_changed_before_publication_commit")
        return batch

    async def delivery_plan(
        self, session: AsyncSession, saved: Delivery
    ) -> AnyFileReturnPlan | None:
        if saved.batch_id is None:
            return None
        batch = await session.get(DeliveryBatch, saved.batch_id)
        row = await session.scalar(
            select(FileTransfer).where(FileTransfer.batch_id == saved.batch_id)
        )
        if batch is not None and batch.renderer_version != RENDERER and row is None:
            return None
        if (
            row is None
            or batch is None
            or row.state != "queued"
            or batch.renderer_version != RENDERER
        ):
            raise Conflict("file_return_delivery_provenance_missing")
        plan = read_plan(row)
        page = self.page(plan)
        if (
            batch.dedupe_key,
            batch.binding_id,
            batch.binding_revision,
            batch.priority,
            batch.plan_hash,
            batch.message_limit,
            batch.topic_limit,
            batch.page_count,
            saved.binding_id,
            saved.binding_revision,
            saved.batch_index,
        ) != (
            "reply-batch:"
            + digest(
                {
                    "key": "file-return:" + plan.id,
                    "binding": plan.binding_id,
                    "revision": plan.binding_revision,
                }
            ),
            plan.binding_id,
            plan.binding_revision,
            100,
            batch_digest((page,), RENDERER, plan.message_limit, plan.topic_limit),
            plan.message_limit,
            plan.topic_limit,
            1,
            plan.binding_id,
            plan.binding_revision,
            0,
        ):
            raise Conflict("file_return_delivery_batch_changed")
        body = OutboundPayload.model_validate(saved.payload)
        if saved.payload_hash != digest(saved.payload) or (
            body.operation,
            body.realm_id,
            body.channel_id,
            body.topic,
            body.bot_user_id,
            body.content,
            body.marker,
        ) != (
            "post",
            plan.source.realm_id,
            plan.source.channel_id,
            plan.source.topic,
            plan.bot_user_id,
            with_marker(page, "jtoz:" + saved.id),
            "jtoz:" + saved.id,
        ):
            raise Conflict("file_return_delivery_content_changed")
        return plan

    async def delivery_witness(self, saved: Delivery) -> Callable[[], bool] | None:
        async with self.db.sessions() as session:
            plan = await self.delivery_plan(session, saved)
        if plan is None:
            return None
        await self.publishable(plan)
        await self.current(plan)
        async with self.db.sessions() as session:
            lease = await session.get(WorkerLease, "consumer")
        if lease is None or (lease.holder, lease.fencing) != (
            self.fence.holder,
            self.fence.fencing,
        ):
            raise Conflict("file_return_delivery_lease_changed")
        deadline = time.monotonic() + 5
        export_current = (
            self.export_scope_witness(plan) if isinstance(plan, TranscriptExportPlan) else None
        )
        return lambda: (
            time.monotonic() < deadline
            and time.time() < lease.expires_at
            and (export_current is None or export_current())
        )

    async def lock_delivery(self, session: AsyncSession, saved: Delivery) -> None:
        plan = await self.delivery_plan(session, saved)
        if plan is None:
            return
        binding = await session.get(Binding, plan.binding_id)
        if (
            binding is None
            or binding.revision != plan.binding_revision
            or reference(binding) != plan.reference
        ):
            raise Conflict("file_return_delivery_binding_missing")
        await self.operator_lock(session, binding, plan.source.author_id)
        await self.lock_plan(session, plan)
        artifact = await session.scalar(
            select(Artifact).where(Artifact.id == plan.artifact_id).with_for_update()
        )
        if artifact is None or (
            artifact.state,
            artifact.binding_id,
            artifact.binding_revision,
            artifact.realm_id,
            artifact.project_id,
            artifact.actor_id,
            artifact.source_message_id,
            artifact.size_bytes,
            artifact.checksum,
        ) != (
            "ready",
            plan.binding_id,
            plan.binding_revision,
            plan.source.realm_id,
            plan.reference.project_id,
            plan.source.author_id,
            artifact_source_id(plan),
            plan.projection.size,
            plan.projection.sha256,
        ):
            raise Conflict("file_return_delivery_artifact_changed")
        if isinstance(plan, TranscriptExportPlan) and not self.export_scope_witness(plan)():
            raise Conflict("session_export_scope_changed_before_delivery_claim")

    async def advance(self, identity: str) -> str:
        async with self._slots:
            saved, plan = await self.load(identity)
            if saved.retry_at > time.time():
                return saved.state
            try:
                if saved.state == "prepared":
                    return await self.upload(saved, plan)
                if saved.state == "uploaded":
                    return await self.verify(saved, plan)
                if saved.state == "verified":
                    await self.publish(saved, plan)
                    return "queued"
                return saved.state
            except FileReturnDeferred:
                return saved.state
            except ValueError as error:
                latest, _ = await self.load(identity)
                if latest.version != saved.version:
                    return latest.state  # Another worker advanced this record.
                if isinstance(error, DeliveryRateLimited):
                    return (
                        await self.save(
                            saved,
                            plan,
                            saved.state,
                            reason="read_rate_limited",
                            retry_at=time.time() + error.retry_after,
                        )
                    ).state
                return (
                    await self.save(
                        saved, plan, "held", reason="file_return_scope_or_verification_changed"
                    )
                ).state

    async def recover_uploading(self, *, before: float) -> int:
        # Startup successor only: old-fence requests may still finish remotely;
        # mark them ambiguous, never infer failure from absence of a receipt.
        if (
            isinstance(before, bool)
            or not isinstance(before, int | float)
            or not math.isfinite(before)
            or before > time.time()
        ):
            raise ValueError("file_return_recovery_cutoff_invalid")
        changed = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            rows = list(
                (
                    await session.scalars(
                        select(FileTransfer)
                        .where(
                            FileTransfer.realm_id == self.realm_id,
                            FileTransfer.state == "uploading",
                            FileTransfer.updated_at < before,
                        )
                        .with_for_update()
                    )
                ).all()
            )
            for row in rows:
                read_plan(row)
                if (row.holder, row.fencing) == (self.fence.holder, self.fence.fencing):
                    continue
                row.state, row.status_reason = "ambiguous", "previous_upload_outcome_unknown"
                row.version += 1
                row.updated_at = time.time()
                session.add(
                    AuditEvent(
                        actor="worker", event="file_return_recovered_ambiguous", object_id=row.id
                    )
                )
                changed += 1
        return changed
