"""Durable original-action automatic capture; no Native POST or replacement backend."""

import asyncio
import math
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.generated_files import GeneratedDiscoveryEvidence
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.services.binding_scope_history import scope
from jt_oz_bridge.services.file_returns import FileReturnJournal
from jt_oz_bridge.services.generated_capture_plans import CaptureOrigin, CapturePlan, read_capture
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.services.generated_output_plans import GeneratedFileReturnPlan, read_intent
from jt_oz_bridge.services.resource_execution_results import (
    ResourceExecutionResult,
    correlation,
    indexed_result,
)
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob, GeneratedOutputRecord
from jt_oz_bridge.storage.models import Action, AuditEvent
from jt_oz_bridge.storage.resource_models import ResourceResultRecord
from jt_oz_bridge.storage.statements import insert


def origin(action: Action, index: ResourceResultRecord) -> CaptureOrigin:
    result = indexed_result(index, action)
    return CaptureOrigin(
        action_id=action.id,
        binding_id=action.binding_id,
        binding_revision=action.binding_revision,
        reference=result.reference,
        source=HumanMessage.model_validate(action.payload.get("source")),
        action_version=action.version,
        payload_sha256=digest(action.payload),
        admission_sha256=digest(action.admission),
        result_sha256=digest(action.native_result),
        result_ordinal=index.ordinal,
        index_sha256=index.source_hash,
    )


class GeneratedCaptureService:
    def __init__(self, journal: FileReturnJournal) -> None:
        if not isinstance(journal, GeneratedFileReturnJournal) or not journal.generated_readers:
            raise ValueError("generated_capture_original_qualified_journal_required")
        self.journal, self.bindings, self.db, self.fence = (
            journal,
            journal.bindings,
            journal.db,
            journal.fence,
        )
        for ref, reader in journal.generated_readers.items():
            a, b = reader.require(ref), reader.require_bytes(ref)
            if (
                a.contract_sha256 != self.bindings.control.contract_for(ref)
                or b.contract_sha256 != a.contract_sha256
            ):
                raise ValueError("generated_capture_original_contract_required")
        # Bound Native JSON/Base64/binary work before reading, not only storage/upload.
        self._slots = asyncio.Semaphore(1)

    async def reserve_in_session(
        self,
        session: AsyncSession,
        action: Action,
        index: ResourceResultRecord,
        result: ResourceExecutionResult,
    ) -> None:
        if result.reference not in self.journal.generated_readers:
            return
        selected = self.journal.generated_readers[result.reference]
        selected.require(result.reference)
        selected.require_bytes(result.reference)
        if indexed_result(index, action) != result:
            raise Conflict("generated_capture_original_completion_changed")
        binding = await session.get(Binding, action.binding_id, with_for_update=True)
        if binding is None:
            raise Conflict("generated_capture_original_binding_missing")
        plan = CapturePlan(
            origin=origin(action, index),
            locale=action.payload.get("reply_locale", "en"),
            original_scope=scope(binding),
        )
        payload = plan.model_dump(mode="json")
        await session.execute(
            insert(self.db, GeneratedCaptureJob)
            .values(
                action_id=action.id,
                binding_id=action.binding_id,
                state="pending",
                version=1,
                retry_at=0,
                payload=payload,
                payload_hash=digest(payload),
            )
            .on_conflict_do_nothing(index_elements=["action_id"])
        )
        row = await session.get(GeneratedCaptureJob, action.id)
        if row is None or read_capture(row).origin != plan.origin:
            raise Conflict("generated_capture_completion_reservation_changed")

    async def load(self, identity: str) -> tuple[GeneratedCaptureJob, CapturePlan]:
        async with self.db.sessions() as session:
            row = await session.get(GeneratedCaptureJob, identity)
        if row is None:
            raise Conflict("generated_capture_unavailable")
        return row, read_capture(row)

    async def context(
        self, session: AsyncSession, plan: CapturePlan, *, lock: bool = False
    ) -> tuple[Action, ResourceResultRecord, ResourceExecutionResult, HumanMessage]:
        value = await self.journal.context(session, plan.origin.action_id, lock=lock)
        if origin(value[0], value[1]) != plan.origin:
            raise Conflict("generated_capture_original_action_changed")
        return value

    async def current(self, plan: CapturePlan) -> Binding:
        async with self.db.sessions() as session:
            action, _, _, source = await self.context(session, plan)
        return await self.journal.original_binding(action, source)

    async def next_pending(self) -> str | None:
        async with self.db.sessions() as session:
            identity = await session.scalar(
                select(GeneratedCaptureJob.action_id)
                .join(Binding, Binding.id == GeneratedCaptureJob.binding_id)
                .where(
                    Binding.realm_id == self.journal.realm_id,
                    GeneratedCaptureJob.state == "pending",
                    GeneratedCaptureJob.retry_at <= time.time(),
                )
                .order_by(
                    GeneratedCaptureJob.updated_at,
                    GeneratedCaptureJob.created_at,
                    GeneratedCaptureJob.action_id,
                )
                .limit(1)
            )
        return str(identity) if identity is not None else None

    async def claim(
        self, saved: GeneratedCaptureJob, plan: CapturePlan, binding: Binding
    ) -> GeneratedCaptureJob:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await self.journal.operator_lock(session, binding, plan.origin.source.author_id)
            await self.context(session, plan, lock=True)
            row = await session.get(GeneratedCaptureJob, saved.action_id, with_for_update=True)
            if row is None or (row.version, row.state, row.payload_hash) != (
                saved.version,
                "pending",
                saved.payload_hash,
            ):
                raise Conflict("generated_capture_claim_changed")
            read_capture(row)
            row.state, row.holder, row.fencing = "capturing", self.fence.holder, self.fence.fencing
            row.version += 1
            row.updated_at = time.time()
        return row

    async def save(
        self,
        saved: GeneratedCaptureJob,
        plan: CapturePlan,
        state: str,
        *,
        binding: Binding | None = None,
        reason: str | None = None,
        retry_at: float = 0,
    ) -> None:
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            if binding is not None:
                await self.journal.operator_lock(session, binding, plan.origin.source.author_id)
                await self.context(session, plan, lock=True)
            row = await session.get(GeneratedCaptureJob, saved.action_id, with_for_update=True)
            if row is None or (row.version, row.state, row.payload_hash) != (
                saved.version,
                saved.state,
                saved.payload_hash,
            ):
                raise Conflict("generated_capture_state_changed")
            previous = read_capture(row)
            if (
                previous.origin != plan.origin
                or previous.original_scope != plan.original_scope
                or previous.acknowledgement_authority != plan.acknowledgement_authority
                or previous.locale != plan.locale
                or previous.discovery is not None
                and previous.discovery != plan.discovery
                or plan.next_index < previous.next_index
            ):
                raise Conflict("generated_capture_immutable_origin_changed")
            row.payload = plan.model_dump(mode="json")
            row.payload_hash = digest(row.payload)
            row.state, row.status_reason, row.retry_at = state, reason, retry_at
            row.version += 1
            row.updated_at = time.time()
            read_capture(row)
            session.add(
                AuditEvent(
                    actor="worker", event="generated_capture_" + state, object_id=row.action_id
                )
            )
            if state == "held" and binding is not None:
                # Commit the recoverable failure and its bounded, path-free
                # notice together. A revoked/moved original scope gets no notice.
                await self.journal.outbox.queue_batch_in_session(
                    session,
                    f"generated-held:{row.action_id}:{row.version}",
                    binding,
                    (self.journal.tr.render("generated.held", plan.locale),),
                    renderer_version="generated-capture-notice-v1",
                    message_limit=self.journal.message_limit,
                    topic_limit=self.journal.topic_limit,
                )

    @staticmethod
    def same_turn(discovery: GeneratedDiscoveryEvidence, result: ResourceExecutionResult) -> None:
        a, b = discovery.turn, result.evidence
        if (a.correlation, a.turn, a.owner_epoch, a.session_info_sha256) != (
            b.correlation,
            b.turn,
            b.owner_epoch,
            b.session_info_sha256,
        ):
            raise Conflict("generated_capture_original_completed_turn_changed")

    async def advance(self, identity: str) -> str:
        async with self._slots:
            saved, plan = await self.load(identity)
            if saved.state != "pending" or saved.retry_at > time.time():
                return saved.state
            try:
                binding = await self.current(plan)
                saved = await self.claim(saved, plan, binding)
                async with self.db.sessions() as session:
                    action, _, result, _ = await self.context(session, plan)
                selected = self.journal.generated_readers.get(plan.origin.reference)
                if selected is None:
                    raise Conflict("generated_capture_original_reader_unavailable")
                if plan.discovery is None:
                    outputs = await selected.capture(correlation(action))
                    discovery = selected.discovery_evidence(outputs)
                    self.same_turn(discovery, result)
                    if not selected.current(outputs):
                        raise Conflict("generated_capture_original_inventory_expired")
                    plan = plan.model_copy(update={"discovery": discovery})
                    binding = await self.current(plan)
                    await self.save(saved, plan, "pending", binding=binding)
                    return "pending"
                if plan.next_index < len(plan.discovery.files):
                    transfer = await self.journal.capture_generated(
                        identity, plan.next_index, locale=plan.locale, expected=plan.discovery
                    )
                    _, captured = await self.journal.load(transfer)
                    if (
                        not isinstance(captured, GeneratedFileReturnPlan)
                        or captured.evidence.discovery().stable_sha256
                        != plan.discovery.stable_sha256
                    ):
                        raise Conflict("generated_capture_original_file_changed")
                    plan = plan.model_copy(update={"next_index": plan.next_index + 1})
                binding = await self.current(plan)
                assert plan.discovery is not None
                frozen = plan.next_index == len(plan.discovery.files)
                if frozen:
                    await self.frozen_files(plan)
                await self.save(saved, plan, "frozen" if frozen else "pending", binding=binding)
                return "frozen" if frozen else "pending"
            except DeliveryRateLimited as error:
                await self.save(
                    saved,
                    plan,
                    "pending",
                    reason="rate_limited",
                    retry_at=time.time() + error.retry_after,
                )
                return "pending"
            except ValueError:
                latest, latest_plan = await self.load(identity)
                if latest.version != saved.version:
                    return latest.state
                try:
                    notice_binding = await self.current(latest_plan)
                except ValueError:
                    notice_binding = None
                await self.save(
                    saved,
                    latest_plan,
                    "held",
                    binding=notice_binding,
                    reason="original_capture_not_current_or_authorized",
                )
                return "held"

    async def frozen_files(self, plan: CapturePlan) -> None:
        if plan.discovery is None:
            raise Conflict("generated_capture_inventory_missing")
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(GeneratedOutputRecord)
                    .where(GeneratedOutputRecord.action_id == plan.origin.action_id)
                    .order_by(GeneratedOutputRecord.output_index)
                )
            ).all()
        if len(rows) != len(plan.discovery.files):
            raise Conflict("generated_capture_complete_file_set_required")
        for index, row in enumerate(rows):
            intent = read_intent(row)
            if (
                row.output_index != index
                or row.transfer_id is None
                or intent.evidence.discovery().stable_sha256 != plan.discovery.stable_sha256
            ):
                raise Conflict("generated_capture_frozen_inventory_changed")
            _, returned = await self.journal.load(row.transfer_id)
            await self.journal.current(returned)

    async def recover(self, *, before: float) -> int:
        if (
            isinstance(before, bool)
            or not isinstance(before, int | float)
            or not math.isfinite(before)
            or before > time.time()
        ):
            raise ValueError("generated_capture_recovery_cutoff_invalid")
        count = 0
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            rows = (
                await session.scalars(
                    select(GeneratedCaptureJob)
                    .join(Binding, Binding.id == GeneratedCaptureJob.binding_id)
                    .where(
                        Binding.realm_id == self.journal.realm_id,
                        GeneratedCaptureJob.state == "capturing",
                        GeneratedCaptureJob.updated_at < before,
                    )
                    .with_for_update()
                )
            ).all()
            for row in rows:
                read_capture(row)
                if (row.holder, row.fencing) != (self.fence.holder, self.fence.fencing):
                    row.state, row.status_reason = "pending", "capture_get_recovery"
                    row.version += 1
                    row.updated_at = time.time()
                    count += 1
        return count
