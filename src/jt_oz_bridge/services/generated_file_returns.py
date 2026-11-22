"""Original-action generated files through the existing one-attempt upload journal.

Not wired to production. Each output ordinal reserves one immutable byte capture
and one artifact identity before storage; uncertain staging is held, not replaced.
"""

import asyncio
from collections.abc import AsyncIterator, Mapping
from typing import Any, Protocol
from uuid import uuid4
from weakref import WeakValueDictionary

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.generated_files import (
    MAX_OUTPUTS,
    GeneratedByteEvidence,
    GeneratedBytesAttestation,
    GeneratedDiscoveryEvidence,
    GeneratedFile,
    GeneratedFileAttestation,
    GeneratedFileBytes,
    GeneratedFiles,
)
from jt_oz_bridge.adapters.opencode.turn_resources import TurnCorrelation
from jt_oz_bridge.adapters.zulip.file_upload import multipart_filename
from jt_oz_bridge.config import Locale
from jt_oz_bridge.domain.attachments import NativeAttachmentProjection
from jt_oz_bridge.domain.enrollment_views import readonly_enrollment
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.domain.models import SessionRef
from jt_oz_bridge.security.policy import Permission
from jt_oz_bridge.services.artifacts import FileDescriptor
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.file_returns import (
    AnyFileReturnPlan,
    FileReturnDeferred,
    FileReturnJournal,
    check_content,
)
from jt_oz_bridge.services.generated_capture_plans import read_capture
from jt_oz_bridge.services.generated_output_plans import (
    GeneratedFileReturnPlan,
    GeneratedOutputIntent,
    read_intent,
)
from jt_oz_bridge.services.resource_execution_results import (
    ResourceExecutionResult,
    correlation,
    indexed_result,
)
from jt_oz_bridge.storage.artifact_models import Artifact
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.file_transfer_models import FileTransfer
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob, GeneratedOutputRecord
from jt_oz_bridge.storage.models import Action, AuditEvent
from jt_oz_bridge.storage.resource_models import ResourceResultRecord
from jt_oz_bridge.storage.statements import insert


class GeneratedReader(Protocol):
    def require(self, reference: SessionRef) -> GeneratedFileAttestation: ...
    def require_bytes(self, reference: SessionRef) -> GeneratedBytesAttestation: ...
    async def capture(self, correlation: TurnCorrelation) -> GeneratedFiles: ...
    def current(self, outputs: GeneratedFiles) -> bool: ...
    def discovery_evidence(self, outputs: GeneratedFiles) -> GeneratedDiscoveryEvidence: ...
    async def read(
        self, outputs: GeneratedFiles, selection: GeneratedFile
    ) -> GeneratedFileBytes: ...
    def current_bytes(self, result: GeneratedFileBytes) -> bool: ...
    def evidence(self, result: GeneratedFileBytes) -> GeneratedByteEvidence: ...


class GeneratedFileReturnJournal(FileReturnJournal):
    def __init__(
        self, *args: Any, generated_readers: Mapping[SessionRef, GeneratedReader], **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.generated_readers = readonly_enrollment(generated_readers)
        self._captures: WeakValueDictionary[tuple[str, int], asyncio.Lock] = WeakValueDictionary()

    async def context(
        self, session: AsyncSession, action_id: str, *, lock: bool = False
    ) -> tuple[Action, ResourceResultRecord, ResourceExecutionResult, HumanMessage]:
        action = await session.get(Action, action_id, with_for_update=lock)
        index = await session.get(ResourceResultRecord, action_id, with_for_update=lock)
        if action is None or index is None:
            raise Conflict("generated_output_original_action_or_result_missing")
        result = indexed_result(index, action)
        source = HumanMessage.model_validate(action.payload.get("source"))
        if source.realm_id != self.realm_id or source.author_id != action.actor_id:
            raise Conflict("generated_output_original_human_realm_changed")
        return action, index, result, source

    @staticmethod
    def check_context(
        intent: GeneratedOutputIntent,
        action: Action,
        index: ResourceResultRecord,
        result: ResourceExecutionResult,
        source: HumanMessage,
    ) -> None:
        e = intent.evidence
        if (
            (
                intent.action_id,
                intent.binding_id,
                intent.binding_revision,
                intent.source,
                intent.action_version,
                intent.action_payload_sha256,
                intent.admission_sha256,
                intent.result_sha256,
                intent.result_ordinal,
                intent.result_index_sha256,
            )
            != (
                action.id,
                action.binding_id,
                action.binding_revision,
                source,
                action.version,
                digest(action.payload),
                digest(action.admission),
                digest(action.native_result),
                index.ordinal,
                index.source_hash,
            )
            or e.turn.correlation != correlation(action)
            or e.turn.turn != result.evidence.turn
            or e.turn.owner_epoch != result.evidence.owner_epoch
            or e.turn.session_info_sha256 != result.evidence.session_info_sha256
        ):
            raise Conflict("generated_output_original_action_or_turn_changed")

    async def original_binding(self, action: Action, source: HumanMessage) -> Binding:
        if await self.source.read(source.realm_id, source.message_id) != source:
            raise Conflict("generated_output_original_human_source_changed")
        binding = await self.bindings.get(
            action.binding_id, source.realm_id, source.author_id, Permission.OPERATE
        )
        if (
            binding.revision,
            reference(binding),
            binding.realm_id,
            binding.channel_id,
            binding.topic,
        ) != (
            action.binding_revision,
            correlation(action).reference,
            source.realm_id,
            source.channel_id,
            source.topic,
        ):
            raise Conflict("generated_output_original_binding_changed")
        return binding

    async def check_plan(
        self, session: AsyncSession, plan: GeneratedFileReturnPlan, *, lock: bool = False
    ) -> None:
        row = await session.get(GeneratedOutputRecord, plan.intent_id, with_for_update=lock)
        if row is None:
            raise Conflict("generated_output_capture_missing")
        intent = read_intent(row)
        action, index, result, source = await self.context(session, intent.action_id, lock=lock)
        self.check_context(intent, action, index, result, source)
        if (
            row.payload_hash != plan.intent_sha256
            or row.transfer_id != plan.id
            or (
                intent.artifact_id,
                intent.binding_id,
                intent.binding_revision,
                intent.source,
                intent.locale,
                intent.evidence.stable_sha256,
            )
            != (
                plan.artifact_id,
                plan.binding_id,
                plan.binding_revision,
                plan.source,
                plan.locale,
                plan.evidence.stable_sha256,
            )
        ):
            raise Conflict("generated_output_transfer_provenance_changed")
        artifact = await session.get(Artifact, plan.artifact_id, with_for_update=lock)
        if artifact is None or artifact.action_id != intent.action_id:
            raise Conflict("generated_output_artifact_action_changed")

    async def authorize_source(self, plan: AnyFileReturnPlan) -> None:
        if not isinstance(plan, GeneratedFileReturnPlan):
            await super().authorize_source(plan)
            return
        selected = self.generated_readers.get(plan.reference)
        if selected is None:
            raise Conflict("generated_output_reader_not_enrolled")
        # This qualifies the configured contract, not the expired captured object.
        a, b = selected.require(plan.reference), selected.require_bytes(plan.reference)
        if (a.installed_evidence_sha256, b.installed_evidence_sha256) != (
            plan.evidence.metadata_attestation_sha256,
            plan.evidence.byte_attestation_sha256,
        ):
            raise Conflict("generated_output_qualification_changed")
        async with self.db.sessions() as session:
            await self.check_plan(session, plan)

    async def lock_plan(self, session: AsyncSession, plan: AnyFileReturnPlan) -> None:
        if isinstance(plan, GeneratedFileReturnPlan):
            await self.check_plan(session, plan, lock=True)
            await self.release_in_session(session, plan, lock=True)
        else:
            await super().lock_plan(session, plan)

    async def release_in_session(
        self, session: AsyncSession, plan: GeneratedFileReturnPlan, *, lock: bool = False
    ) -> None:
        job = await session.get(
            GeneratedCaptureJob, plan.evidence.turn.correlation.action_id, with_for_update=lock
        )
        if job is not None:
            captured = read_capture(job)
            if job.state in {"pending", "capturing"}:
                raise FileReturnDeferred("generated_capture_still_pending")
            if (
                job.state != "frozen"
                or captured.discovery is None
                or (captured.discovery.stable_sha256 != plan.evidence.discovery().stable_sha256)
            ):
                raise Conflict("generated_capture_not_frozen_for_network")

    async def publishable(self, plan: AnyFileReturnPlan) -> None:
        if isinstance(plan, GeneratedFileReturnPlan):
            async with self.db.sessions() as session:
                await self.release_in_session(session, plan)

    async def capture_generated(
        self,
        action_id: str,
        output_index: int,
        *,
        locale: Locale = "en",
        expected: GeneratedDiscoveryEvidence | None = None,
    ) -> str:
        if type(output_index) is not int or not 0 <= output_index < MAX_OUTPUTS:
            raise Conflict("generated_output_ordinal_invalid")
        key = action_id, output_index
        lock = self._captures.setdefault(key, asyncio.Lock())
        async with lock:
            return await self._capture_generated(action_id, output_index, locale, expected)

    async def _capture_generated(
        self,
        action_id: str,
        output_index: int,
        locale: Locale,
        expected: GeneratedDiscoveryEvidence | None,
    ) -> str:
        self.destination()
        async with self.db.sessions() as session:
            action, index, result, source = await self.context(session, action_id)
            previous = await session.scalar(
                select(GeneratedOutputRecord).where(
                    GeneratedOutputRecord.action_id == action_id,
                    GeneratedOutputRecord.output_index == output_index,
                )
            )
        binding = await self.original_binding(action, source)
        selected = self.generated_readers.get(reference(binding))
        if selected is None:
            raise Conflict("generated_output_reader_not_enrolled")
        if previous is not None and previous.transfer_id is not None:
            intent = read_intent(previous)
            self.check_context(intent, action, index, result, source)
            _, plan = await self.load(previous.transfer_id)
            if not isinstance(plan, GeneratedFileReturnPlan) or plan.locale != locale:
                raise Conflict("generated_output_existing_transfer_changed")
            if (
                expected is not None
                and expected.stable_sha256 != plan.evidence.discovery().stable_sha256
            ):
                raise Conflict("generated_output_original_discovery_changed")
            await self.current(plan)
            await self.content(plan)
            async with self.db.sessions.begin() as session:
                await self.fence.lock(session)
                await self.operator_lock(session, binding, source.author_id)
                await self.check_plan(session, plan, lock=True)
            return previous.transfer_id

        output, evidence = await self.read_selected(selected, correlation(action), output_index)
        if expected is not None and expected.stable_sha256 != evidence.discovery().stable_sha256:
            raise Conflict("generated_output_original_discovery_changed")
        self.destination(output.projection)
        proposed = GeneratedOutputIntent(
            id=str(uuid4()),
            action_id=action.id,
            output_index=output_index,
            artifact_id=str(uuid4()),
            binding_id=binding.id,
            binding_revision=binding.revision,
            source=source,
            action_version=action.version,
            action_payload_sha256=digest(action.payload),
            admission_sha256=digest(action.admission),
            result_sha256=digest(action.native_result),
            result_ordinal=index.ordinal,
            result_index_sha256=index.source_hash,
            evidence=evidence,
            locale=locale,
        )
        self.check_context(proposed, action, index, result, source)
        await self.original_binding(action, source)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.operator_lock(session, binding, source.author_id)
            current = await self.context(session, action_id, lock=True)
            self.check_context(proposed, *current)
            if not selected.current_bytes(output):
                raise Conflict("generated_output_original_bytes_expired_before_pin")
            await session.execute(
                insert(self.db, GeneratedOutputRecord)
                .values(
                    id=proposed.id,
                    action_id=action_id,
                    output_index=output_index,
                    reserved_artifact_id=proposed.artifact_id,
                    payload=proposed.model_dump(mode="json"),
                    payload_hash=digest(proposed.model_dump(mode="json")),
                )
                .on_conflict_do_nothing(index_elements=["action_id", "output_index"])
            )
            row = (
                await session.scalars(
                    select(GeneratedOutputRecord)
                    .where(
                        GeneratedOutputRecord.action_id == action_id,
                        GeneratedOutputRecord.output_index == output_index,
                    )
                    .with_for_update()
                )
            ).one()
            intent = read_intent(row)
            self.check_context(intent, *current)
            if intent.evidence.stable_sha256 != evidence.stable_sha256 or intent.locale != locale:
                raise Conflict("generated_output_pinned_origin_or_bytes_changed")
            intent_id = row.id

        async with self.db.sessions() as session:
            artifact = await session.get(Artifact, intent.artifact_id)
        if artifact is None:
            check_content(output.content, output.projection.filename)

            async def chunks() -> AsyncIterator[bytes]:
                for offset in range(0, len(output.content), 65536):
                    yield output.content[offset : offset + 65536]

            await self.artifacts.create(
                binding.id,
                source.realm_id,
                source.author_id,
                FileDescriptor(
                    filename=output.projection.filename, mime_type=output.projection.mime_type
                ),
                chunks(),
                kind="output",
                expected_size=output.projection.size,
                expected_sha256=output.projection.sha256,
                source_message_id=source.message_id,
                action_id=action_id,
                identity=intent.artifact_id,
            )
        elif artifact.state != "ready":
            raise Conflict("generated_output_uncertain_artifact_requires_reconciliation")

        stored = await self.artifacts.read(intent.artifact_id, source.realm_id, source.author_id)
        if (
            stored.descriptor.filename,
            stored.descriptor.mime_type,
            stored.content,
            stored.sha256,
        ) != (
            output.projection.filename,
            output.projection.mime_type,
            output.content,
            output.projection.sha256,
        ):
            raise Conflict("generated_output_pinned_artifact_bytes_changed")
        check_content(stored.content, stored.descriptor.filename)
        if not selected.current_bytes(output):
            # One real same-turn re-read after slow scanning/storage, never renew a DTO.
            fresh, fresh_evidence = await self.read_selected(
                selected, correlation(action), output_index
            )
            if (
                fresh_evidence.stable_sha256 != intent.evidence.stable_sha256
                or fresh.content != stored.content
            ):
                raise Conflict("generated_output_fresh_read_changed_pinned_bytes")
            output, evidence = fresh, fresh_evidence
        await self.original_binding(action, source)
        plan = GeneratedFileReturnPlan(
            id=str(uuid4()),
            artifact_id=intent.artifact_id,
            binding_id=binding.id,
            binding_revision=binding.revision,
            source=source,
            reference=reference(binding),
            intent_id=intent_id,
            intent_sha256=digest(intent.model_dump(mode="json")),
            evidence=evidence,
            projection=output.projection,
            locale=locale,
            realm_url=self.uploader.client.url,
            bot_user_id=self.outbox.bot_user_id,
            message_limit=self.message_limit,
            topic_limit=self.topic_limit,
        )
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.operator_lock(session, binding, source.author_id)
            current = await self.context(session, action_id, lock=True)
            self.check_context(intent, *current)
            final_row = await session.get(GeneratedOutputRecord, intent_id, with_for_update=True)
            if final_row is None or read_intent(final_row) != intent:
                raise Conflict("generated_output_capture_changed_before_prepare")
            if final_row.transfer_id is not None:
                return final_row.transfer_id
            artifact = await session.get(Artifact, intent.artifact_id, with_for_update=True)
            if (
                artifact is None
                or (
                    artifact.state,
                    artifact.action_id,
                    artifact.binding_id,
                    artifact.binding_revision,
                    artifact.realm_id,
                    artifact.project_id,
                    artifact.actor_id,
                    artifact.source_message_id,
                    artifact.size_bytes,
                    artifact.checksum,
                )
                != (
                    "ready",
                    action_id,
                    binding.id,
                    binding.revision,
                    source.realm_id,
                    binding.project_id,
                    source.author_id,
                    source.message_id,
                    output.projection.size,
                    output.projection.sha256,
                )
                or not selected.current_bytes(output)
                or self.generated_readers.get(plan.reference) is not selected
            ):
                raise Conflict(
                    "generated_output_artifact_or_original_witness_changed_before_prepare"
                )
            session.add(
                FileTransfer(
                    id=plan.id,
                    dedupe_key=digest({"generated_intent": intent.id}),
                    artifact_id=plan.artifact_id,
                    binding_id=plan.binding_id,
                    binding_revision=plan.binding_revision,
                    realm_id=source.realm_id,
                    source_message_id=source.message_id,
                    actor_id=source.author_id,
                    state="prepared",
                    version=1,
                    attempts=0,
                    retry_at=0,
                    payload=plan.model_dump(mode="json"),
                    payload_hash=digest(plan.model_dump(mode="json")),
                )
            )
            await session.flush()
            final_row.transfer_id = plan.id
            await session.flush()
            await self.check_plan(session, plan, lock=True)
            session.add(
                AuditEvent(
                    actor=f"{source.realm_id}:{source.author_id}",
                    event="generated_output_prepared",
                    object_id=plan.id,
                )
            )
        await self.current(plan)
        return plan.id

    def destination(self, projection: NativeAttachmentProjection | None = None) -> None:
        """Reject a known unusable destination before Native reads or durable capture."""
        certificate = self.uploader.require()
        enrolled = self.uploader.client.attestation
        if (
            enrolled is None
            or not {"upload", "download"} <= enrolled.verified_file_operations
            or certificate.realm_id != self.realm_id
            or certificate.bot_user_id != self.outbox.bot_user_id
        ):
            raise Conflict("generated_output_destination_scope_unqualified")
        if projection is not None:
            if projection.size > min(
                certificate.maximum_file_bytes, self.downloader.maximum, self.artifacts.maximum
            ):
                raise Conflict("generated_output_actual_transfer_limit_exceeded")
            multipart_filename(projection.filename)

    @staticmethod
    async def read_selected(
        reader: GeneratedReader, c: TurnCorrelation, index: int
    ) -> tuple[GeneratedFileBytes, GeneratedByteEvidence]:
        outputs = await reader.capture(c)
        if index >= len(outputs.files):
            raise Conflict("generated_output_selection_unavailable")
        output = await reader.read(outputs, outputs.files[index])
        evidence = reader.evidence(output)
        if not reader.current_bytes(output) or evidence.turn.correlation != c:
            raise Conflict("generated_output_original_byte_witness_required")
        return output, evidence
