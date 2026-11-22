"""Fenced, atomic capture of original-session durable events and sync watermarks."""

import asyncio
import time

from sqlalchemy import func, literal, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jt_oz_bridge.adapters.opencode.log import DurableLogItem, LogRead
from jt_oz_bridge.adapters.opencode.sse import SSEFrame
from jt_oz_bridge.domain.native_events import LogProvenance, QualifiedLogRecord
from jt_oz_bridge.security.policy import ROLES, Permission
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Checkpoint, Grant, InputEvent, WorkerLease, uid
from jt_oz_bridge.storage.projection_models import NativeLogIndex


class LogCapture:
    def __init__(
        self,
        bindings: BindingService,
        binding: Binding,
        holder: str,
        fencing: int,
        source: str,
        epoch: str,
        after: int | None,
        provenance: LogProvenance | None = None,
    ) -> None:
        self.bindings, self.db, self.binding = bindings, bindings.db, binding
        self.holder, self.fencing, self.source, self.epoch = holder, fencing, source, epoch
        self.provenance = (
            LogProvenance.model_validate(provenance.model_dump(mode="python"))
            if provenance is not None
            else None
        )
        if self.provenance and (
            self.provenance.binding_id != binding.id
            or self.provenance.binding_revision != binding.revision
            or self.provenance.realm_id != binding.realm_id
            or self.provenance.reference != reference(binding)
            or self.provenance.contract_sha256 != bindings.control.contract_for(reference(binding))
        ):
            raise Conflict("log_provenance_scope_mismatch")
        self.read = LogRead(reference(binding), after)
        self._lock = asyncio.Lock()

    async def guard(self, session: AsyncSession) -> None:
        """Serialize capture with lease takeover, revocation and binding revisions."""
        valid_binding = (
            select(Binding.id)
            .where(
                Binding.id == self.binding.id,
                Binding.state == "active",
                Binding.revision == self.binding.revision,
                Binding.backend_id == self.binding.backend_id,
                Binding.backend_identity == self.binding.backend_identity,
                Binding.session_id == self.binding.session_id,
                Binding.project_id == self.binding.project_id,
                Binding.canonical_directory == self.binding.canonical_directory,
            )
            .exists()
        )
        valid_backend = (
            select(EnrolledBackend.id)
            .where(
                EnrolledBackend.id == self.binding.backend_id,
                EnrolledBackend.identity == self.binding.backend_identity,
                EnrolledBackend.contract_hash
                == self.bindings.control.contract_for(reference(self.binding)),
                EnrolledBackend.verified.is_(True),
                EnrolledBackend.enabled.is_(True),
            )
            .exists()
        )
        valid_project = (
            select(EnrolledProject.id)
            .where(
                EnrolledProject.id == self.binding.project_id,
                EnrolledProject.backend_id == self.binding.backend_id,
                EnrolledProject.realm_id == self.binding.realm_id,
                EnrolledProject.canonical_directory == self.binding.canonical_directory,
                EnrolledProject.enabled.is_(True),
            )
            .exists()
        )
        viewers = (
            select(func.count(func.distinct(Grant.user_id)))
            .where(
                Grant.realm_id == self.binding.realm_id,
                Grant.project_id == self.binding.project_id,
                Grant.user_id.in_(self.binding.audience_user_ids),
                Grant.active.is_(True),
                Grant.role.in_(
                    [role for role, permissions in ROLES.items() if Permission.VIEW in permissions]
                ),
            )
            .scalar_subquery()
        )
        result = await session.execute(
            update(WorkerLease)
            .where(
                WorkerLease.role == "consumer",
                WorkerLease.holder == self.holder,
                WorkerLease.fencing == self.fencing,
                WorkerLease.expires_at > time.time(),
                valid_binding,
                valid_backend,
                valid_project,
                viewers == len(self.binding.audience_user_ids),
                literal(len(self.binding.audience_user_ids) > 0),
            )
            .values(expires_at=WorkerLease.expires_at)
        )
        if result.rowcount != 1:  # type: ignore[attr-defined]
            raise Conflict("log consumer lease, binding or enrollment changed")

    @classmethod
    async def open(
        cls,
        bindings: BindingService,
        binding_id: str,
        holder: str,
        fencing: int,
        *,
        provenance: LogProvenance | None = None,
    ) -> "LogCapture":
        async with bindings.db.sessions() as session:
            binding = await session.get(Binding, binding_id)
        if not binding or binding.state != "active":
            raise Conflict("log binding unavailable")
        await bindings.enrolled(reference(binding), binding.realm_id)
        await bindings.audience_for_output(binding)
        source, epoch = "v2-log:" + digest(reference(binding).model_dump()), uid()
        capture = cls(bindings, binding, holder, fencing, source, epoch, None, provenance)
        async with bindings.db.sessions.begin() as session:
            await capture.guard(session)
            checkpoint = await session.get(Checkpoint, source)
            if checkpoint is None:
                checkpoint = Checkpoint(source=source, queue_id=epoch, event_id=-1)
                session.add(checkpoint)
            else:
                if checkpoint.event_id < -1:
                    raise Conflict("stored log position invalid")
                checkpoint.queue_id, checkpoint.updated_at = epoch, time.time()
            capture.read = LogRead(
                reference(binding), None if checkpoint.event_id == -1 else checkpoint.event_id
            )
        return capture

    async def accept(self, frame: SSEFrame) -> tuple[str, bool]:
        async with self._lock:
            # Preview separately: no in-memory position moves before the DB commit.
            proposed = LogRead(self.read.reference, self.read.position)
            proposed.synced = self.read.synced
            item = proposed.accept(frame)
            payload = item.model_dump(mode="json", exclude_none=True)
            if self.provenance is not None:
                payload = QualifiedLogRecord(
                    provenance=self.provenance, capture_epoch=self.epoch, native=payload
                ).model_dump(mode="json")
            event_id = item.id if isinstance(item, DurableLogItem) else "sync:" + self.epoch
            revision = item.durable.version if isinstance(item, DurableLogItem) else 0
            async with self.db.sessions.begin() as session:
                await self.guard(session)
                updated = await session.execute(
                    update(Checkpoint)
                    .where(
                        Checkpoint.source == self.source,
                        Checkpoint.queue_id == self.epoch,
                        Checkpoint.event_id
                        == (-1 if self.read.position is None else self.read.position),
                    )
                    .values(
                        event_id=-1 if proposed.position is None else proposed.position,
                        updated_at=time.time(),
                    )
                )
                if updated.rowcount != 1:  # type: ignore[attr-defined]
                    raise Conflict("log stream epoch or cursor changed")
                existing = await session.scalar(
                    select(InputEvent).where(
                        InputEvent.source == self.source, InputEvent.source_id == event_id
                    )
                )
                if existing:
                    if existing.payload_hash != digest(payload) or existing.revision != revision:
                        raise Conflict("durable event identity reused")
                    receipt, inserted = existing.id, False
                else:
                    saved = InputEvent(
                        source=self.source,
                        source_id=event_id,
                        revision=revision,
                        payload=payload,
                        payload_hash=digest(payload),
                        state="captured",
                    )
                    session.add(saved)
                    await session.flush()
                    if self.provenance is not None:
                        session.add(
                            NativeLogIndex(
                                input_event_id=saved.id,
                                source=self.source,
                                binding_id=self.binding.id,
                                binding_revision=self.binding.revision,
                                scope_key=self.provenance.scope_key(),
                                native_sequence=proposed.position,
                                capture_epoch=self.epoch,
                            )
                        )
                    receipt, inserted = saved.id, True
            self.read = proposed
            return receipt, inserted
