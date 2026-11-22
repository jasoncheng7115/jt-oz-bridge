"""Fenced ordered native projection; installed semantic evidence is mandatory."""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.event_semantics import (
    DATA,
    SEMANTICS_SHA256,
    ProjectionState,
    completion,
)
from jt_oz_bridge.domain.native_events import LogProvenance
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.execution_results import NativeExecutionResult
from jt_oz_bridge.services.projection_records import (
    ProjectedRecord,
    read_record,
    validate_capture,
    window_key,
)
from jt_oz_bridge.services.scope_lock import lock_output_scope
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, InputEvent
from jt_oz_bridge.storage.projection_models import (
    NativeLogIndex,
    NativeProjection,
    NativeProjectionRecord,
)


@dataclass(frozen=True)
class EventSemanticAttestation:
    """Trusted installed tests, never a chat/config boolean or public-source hash."""

    backend_id: str
    backend_identity: str
    contract_sha256: str
    semantics_sha256: str
    installed_evidence_sha256: str
    verified_types: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "verified_types", frozenset(self.verified_types))


class NativeProjector:
    def __init__(
        self,
        bindings: BindingService,
        fence: ConsumerFence,
        *,
        attestation: EventSemanticAttestation | None = None,
    ) -> None:
        self.bindings, self.db, self.fence = bindings, bindings.db, fence
        self.attestation = attestation

    def qualify(self, provenance: LogProvenance) -> None:
        selected = self.attestation
        if (
            selected is None
            or selected.backend_id != provenance.reference.backend_id
            or selected.backend_identity != provenance.reference.backend_identity
            or selected.contract_sha256 != provenance.contract_sha256
            or selected.semantics_sha256 != SEMANTICS_SHA256
            or len(selected.installed_evidence_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in selected.installed_evidence_sha256
            )
            or not frozenset(DATA) <= selected.verified_types
        ):
            raise Conflict("installed_native_event_semantics_unqualified")

    async def preflight(self, provenance: LogProvenance) -> Binding:
        self.qualify(provenance)
        async with self.db.sessions() as session:
            binding = await session.get(Binding, provenance.binding_id)
        if (
            binding is None
            or binding.state != "active"
            or binding.revision != provenance.binding_revision
            or binding.realm_id != provenance.realm_id
            or reference(binding) != provenance.reference
        ):
            raise Conflict("native_projection_binding_changed")
        await self.bindings.enrolled(reference(binding), binding.realm_id)
        await self.bindings.audience_for_output(binding)
        self.qualify(provenance)
        return binding

    async def next_pending(self) -> str | None:
        if self.attestation is None:
            return None
        async with self.db.sessions() as session:
            pending = await session.scalar(
                select(NativeLogIndex.input_event_id)
                .join(InputEvent, InputEvent.id == NativeLogIndex.input_event_id)
                .join(Binding, Binding.id == NativeLogIndex.binding_id)
                .where(
                    InputEvent.state == "captured",
                    Binding.state == "active",
                    Binding.revision == NativeLogIndex.binding_revision,
                    Binding.backend_id == self.attestation.backend_id,
                    Binding.backend_identity == self.attestation.backend_identity,
                )
                .order_by(NativeLogIndex.ordinal)
                .limit(1)
            )
            return str(pending) if pending is not None else None

    async def evidence(self, session: AsyncSession, row: NativeProjectionRecord) -> ProjectedRecord:
        captured = await session.get(InputEvent, row.input_event_id)
        index = await session.scalar(
            select(NativeLogIndex).where(NativeLogIndex.input_event_id == row.input_event_id)
        )
        if captured is None or index is None or captured.state != "projected":
            raise Conflict("native_projection_source_receipt_unavailable")
        return read_record(row, captured, index)

    async def reconcile_in_session(self, session: AsyncSession, provenance: LogProvenance) -> int:
        """Also handles admissions recorded after their native events were projected."""
        self.qualify(provenance)
        scope = provenance.scope_key()
        actions = list(
            (
                await session.scalars(
                    select(Action)
                    .where(
                        Action.binding_id == provenance.binding_id,
                        Action.binding_revision == provenance.binding_revision,
                        Action.operation == "prompt",
                        Action.state.in_(["admitted", "running"]),
                        Action.owner == "opencode",
                        Action.upstream_id.is_not(None),
                    )
                    .order_by(Action.id)
                    .with_for_update()
                )
            ).all()
        )
        changed = 0
        for action in actions:
            receipt = native_receipt(action)
            if receipt is None or receipt.reference != provenance.reference or action.native_result:
                continue
            delivered_rows = list(
                (
                    await session.scalars(
                        select(NativeProjectionRecord)
                        .where(
                            NativeProjectionRecord.scope_key == scope,
                            NativeProjectionRecord.native_type == "session.inbox.delivered",
                            NativeProjectionRecord.native_inbox_id == action.upstream_id,
                        )
                        .order_by(NativeProjectionRecord.ordinal)
                        .limit(2)
                    )
                ).all()
            )
            if len(delivered_rows) != 1:
                continue  # Missing or duplicate native evidence is not completion.
            delivered_row = delivered_rows[0]
            delivery = (await self.evidence(session, delivered_row)).change.delivery
            if delivery is None or delivery.window is None:
                continue
            key = window_key(scope, delivery.window.native_start_id)
            terminals = list(
                (
                    await session.scalars(
                        select(NativeProjectionRecord)
                        .where(
                            NativeProjectionRecord.scope_key == scope,
                            NativeProjectionRecord.native_type.in_(
                                [
                                    "session.execution.succeeded",
                                    "session.execution.failed",
                                    "session.execution.interrupted",
                                ]
                            ),
                            NativeProjectionRecord.window_key == key,
                        )
                        .order_by(NativeProjectionRecord.ordinal)
                        .limit(2)
                    )
                ).all()
            )
            if not terminals:
                if action.state == "admitted":
                    self.qualify(provenance)
                    action.state, action.version, action.status_reason = (
                        "running",
                        action.version + 1,
                        "native_input_delivered",
                    )
                    changed += 1
                continue
            if len(terminals) != 1:
                continue
            terminal_row = terminals[0]
            terminal = (await self.evidence(session, terminal_row)).change.terminal
            if terminal is None:
                continue
            outcome = completion(receipt, delivery, terminal)
            if outcome is None:
                continue
            self.qualify(provenance)
            result = NativeExecutionResult(
                action_id=action.id,
                operation_digest=action.operation_digest,
                admission_sha256=digest(action.admission),
                binding_id=action.binding_id,
                binding_revision=action.binding_revision,
                realm_id=provenance.realm_id,
                reference=receipt.reference,
                contract_sha256=receipt.contract_sha256,
                semantics_sha256=SEMANTICS_SHA256,
                installed_semantic_evidence_sha256=self.attestation.installed_evidence_sha256
                if self.attestation
                else "",
                scope_key=scope,
                delivery_input_id=delivered_row.input_event_id,
                delivery_sha256=delivered_row.payload_hash,
                terminal_input_id=terminal_row.input_event_id,
                terminal_sha256=terminal_row.payload_hash,
                outcome=outcome,
            )
            action.native_result = result.model_dump(mode="json")
            action.state, action.version, action.status_reason = (
                outcome,
                action.version + 1,
                "native_busy_period_terminal",
            )
            session.add(
                AuditEvent(actor="worker", event="native_prompt_result", object_id=action.id)
            )
            changed += 1
        self.qualify(provenance)
        return changed

    async def reconcile_actions(self, scope_key: str) -> int:
        async with self.db.sessions() as session:
            row = await session.get(NativeProjection, scope_key)
        if row is None or digest(row.payload) != row.payload_hash:
            raise Conflict("native_projection_state_unavailable")
        state = ProjectionState.model_validate(row.payload)
        if state.provenance.scope_key() != row.key or row.semantics_sha256 != SEMANTICS_SHA256:
            raise Conflict("native_projection_state_scope_changed")
        binding = await self.preflight(state.provenance)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            return await self.reconcile_in_session(session, state.provenance)

    async def advance(self, input_event_id: str) -> str:
        async with self.db.sessions() as session:
            captured = await session.get(InputEvent, input_event_id)
            index = await session.scalar(
                select(NativeLogIndex).where(NativeLogIndex.input_event_id == input_event_id)
            )
        if captured is None or index is None:
            raise Conflict("native_capture_has_no_ordered_index")
        if captured.state != "captured":
            return captured.state
        record, event = validate_capture(captured, index)
        binding = await self.preflight(record.provenance)
        async with self.db.sessions.begin() as session:
            await self.fence.lock(session)
            await lock_output_scope(self.bindings, session, binding)
            self.qualify(record.provenance)
            current = await session.scalar(
                select(InputEvent).where(InputEvent.id == input_event_id).with_for_update()
            )
            actual_index = await session.get(NativeLogIndex, index.ordinal)
            if current is None or actual_index is None:
                raise Conflict("native_projection_capture_disappeared")
            if current.state != "captured":
                return current.state
            actual_record, actual_event = validate_capture(current, actual_index)
            if (
                actual_record != record
                or actual_event != event
                or actual_index.scope_key != index.scope_key
            ):
                raise Conflict("native_capture_changed_before_projection")
            earlier = await session.scalar(
                select(NativeLogIndex.ordinal)
                .join(InputEvent, InputEvent.id == NativeLogIndex.input_event_id)
                .where(
                    NativeLogIndex.scope_key == index.scope_key,
                    NativeLogIndex.ordinal < index.ordinal,
                    InputEvent.state != "projected",
                )
                .limit(1)
            )
            if earlier is not None:
                return "waiting"
            projection = await session.scalar(
                select(NativeProjection)
                .where(NativeProjection.key == index.scope_key)
                .with_for_update()
            )
            if projection is None:
                before = ProjectionState(provenance=record.provenance)
                projection = NativeProjection(
                    key=index.scope_key,
                    binding_id=binding.id,
                    binding_revision=binding.revision,
                    source=index.source,
                    semantics_sha256=SEMANTICS_SHA256,
                    last_ordinal=0,
                    version=0,
                    payload=before.model_dump(mode="json"),
                    payload_hash=digest(before.model_dump(mode="json")),
                )
                session.add(projection)
            else:
                if (
                    digest(projection.payload) != projection.payload_hash
                    or projection.semantics_sha256 != SEMANTICS_SHA256
                    or projection.source != index.source
                    or projection.binding_id != binding.id
                    or projection.binding_revision != binding.revision
                    or projection.last_ordinal >= index.ordinal
                ):
                    raise Conflict("native_projection_state_identity_changed")
                before = ProjectionState.model_validate(projection.payload)
                if before.provenance.scope_key() != index.scope_key:
                    raise Conflict("native_projection_state_scope_changed")
            from jt_oz_bridge.adapters.opencode.event_semantics import reduce

            change = reduce(before, event)
            projected = ProjectedRecord(
                input_event_id=input_event_id,
                ordinal=index.ordinal,
                scope_key=index.scope_key,
                installed_semantic_evidence_sha256=self.attestation.installed_evidence_sha256
                if self.attestation
                else "",
                event=event,
                before=before,
                change=change,
            )
            saved = projected.model_dump(mode="json")
            window = (
                change.delivery.window
                if change.delivery
                else change.terminal.window
                if change.terminal
                else None
            )
            row = NativeProjectionRecord(
                input_event_id=input_event_id,
                ordinal=index.ordinal,
                scope_key=index.scope_key,
                native_type=event.native_type,
                native_inbox_id=change.delivery.native_inbox_id if change.delivery else None,
                window_key=window_key(index.scope_key, window.native_start_id) if window else None,
                assistant_message_id=change.text.assistant_message_id if change.text else None,
                part_ordinal=change.text.ordinal if change.text else None,
                payload=saved,
                payload_hash=digest(saved),
            )
            projection.payload = change.state.model_dump(mode="json")
            projection.payload_hash = digest(projection.payload)
            projection.last_ordinal, projection.version = index.ordinal, projection.version + 1
            await session.flush([projection])
            session.add(row)
            current.state = "projected"
            await session.flush()
            await self.reconcile_in_session(session, record.provenance)
        return "projected"
