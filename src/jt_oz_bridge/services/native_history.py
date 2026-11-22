"""Current-authorized reads of stored native state and immutable text parts."""

from typing import Protocol

from pydantic import Field, StrictInt
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.event_semantics import SEMANTICS_SHA256, ProjectionState
from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.native_projection import NativeProjector
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import Database
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.projection_models import NativeProjection, NativeProjectionRecord


class StoredPart(ControlModel):
    record_id: str
    record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    ordinal: StrictInt = Field(ge=1)
    native_message_id: str
    part_ordinal: StrictInt = Field(ge=0)
    text: str


class StoredPartPage(ControlModel):
    items: tuple[StoredPart, ...] = Field(max_length=10)
    next_before: StrictInt | None = Field(default=None, ge=1)


class StoredStatus(Protocol):
    @property
    def status(self) -> ExecutionState: ...


class StoredHistory(Protocol):
    bindings: BindingService
    db: Database

    async def current(self, binding_id: str, realm: str, actor: int) -> Binding: ...

    async def page(
        self, binding_id: str, realm: str, actor: int, *, before: int | None = None
    ) -> StoredPartPage: ...

    async def part(
        self, binding_id: str, realm: str, actor: int, record_id: str, record_hash: str
    ) -> StoredPart: ...

    async def latest_state(
        self, binding_id: str, realm: str, actor: int
    ) -> StoredStatus | None: ...


class NativeHistory:
    def __init__(self, projector: NativeProjector) -> None:
        self.projector, self.bindings, self.db = projector, projector.bindings, projector.db

    async def current(self, binding_id: str, realm: str, actor: int) -> Binding:
        return await self.bindings.get(binding_id, realm, actor)

    async def verify(self, binding: Binding, row: NativeProjectionRecord) -> StoredPart:
        async with self.db.sessions() as session:
            saved = await self.projector.evidence(session, row)
            projection = await session.get(NativeProjection, row.scope_key)
        ctx = saved.event.provenance
        if (
            projection is None
            or (projection.binding_id, projection.binding_revision)
            != (ctx.binding_id, ctx.binding_revision)
            or (ctx.binding_id, ctx.realm_id, ctx.reference)
            != (binding.id, binding.realm_id, reference(binding))
        ):
            raise Conflict("stored_native_part_scope_changed")
        self.projector.qualify(ctx)
        if saved.change.text is None:
            raise Conflict("stored_native_record_is_not_text")
        part = saved.change.text
        return StoredPart(
            record_id=row.input_event_id,
            record_hash=row.payload_hash,
            ordinal=row.ordinal,
            native_message_id=part.assistant_message_id,
            part_ordinal=part.ordinal,
            text=part.text,
        )

    async def page(
        self, binding_id: str, realm: str, actor: int, *, before: int | None = None
    ) -> StoredPartPage:
        if before is not None and (type(before) is not int or not 1 <= before <= 2**63 - 1):
            raise ValueError("invalid_stored_history_cursor")
        binding = await self.current(binding_id, realm, actor)
        statement = (
            select(NativeProjectionRecord)
            .join(NativeProjection, NativeProjection.key == NativeProjectionRecord.scope_key)
            .where(
                NativeProjection.binding_id == binding.id,
                NativeProjection.source == "v2-log:" + digest(reference(binding).model_dump()),
                NativeProjectionRecord.native_type == "session.text.ended",
            )
            .order_by(NativeProjectionRecord.ordinal.desc())
            .limit(11)
        )
        if before is not None:
            statement = statement.where(NativeProjectionRecord.ordinal < before)
        async with self.db.sessions() as session:
            rows = list((await session.scalars(statement)).all())
        parts = [await self.verify(binding, row) for row in rows[:10]]
        latest = await self.current(binding_id, realm, actor)
        if latest.revision != binding.revision:
            raise Conflict("stored_history_binding_changed")
        return StoredPartPage(
            items=tuple(parts), next_before=parts[-1].ordinal if len(rows) > 10 and parts else None
        )

    async def part(
        self, binding_id: str, realm: str, actor: int, record_id: str, record_hash: str
    ) -> StoredPart:
        binding = await self.current(binding_id, realm, actor)
        async with self.db.sessions() as session:
            row = await session.get(NativeProjectionRecord, record_id)
        if row is None or row.payload_hash != record_hash:
            raise Conflict("stored_history_selection_changed")
        part = await self.verify(binding, row)
        latest = await self.current(binding_id, realm, actor)
        if latest.revision != binding.revision:
            raise Conflict("stored_history_binding_changed")
        return part

    async def latest_state(self, binding_id: str, realm: str, actor: int) -> ProjectionState | None:
        binding = await self.current(binding_id, realm, actor)
        async with self.db.sessions() as session:
            row = await session.scalar(
                select(NativeProjection)
                .where(
                    NativeProjection.binding_id == binding.id,
                    NativeProjection.source == "v2-log:" + digest(reference(binding).model_dump()),
                )
                .order_by(NativeProjection.last_ordinal.desc())
                .limit(1)
            )
            last = (
                await session.scalar(
                    select(NativeProjectionRecord).where(
                        NativeProjectionRecord.scope_key == row.key,
                        NativeProjectionRecord.ordinal == row.last_ordinal,
                    )
                )
                if row
                else None
            )
            if row is None:
                return None
            if last is None or digest(row.payload) != row.payload_hash:
                raise Conflict("stored_native_state_evidence_unavailable")
            verified = await self.projector.evidence(session, last)
        state = ProjectionState.model_validate(row.payload)
        ctx = state.provenance
        if (
            row.semantics_sha256 != SEMANTICS_SHA256
            or row.source != "v2-log:" + digest(ctx.reference.model_dump())
            or row.binding_revision != ctx.binding_revision
            or state != verified.change.state
            or ctx.scope_key() != row.key
            or (ctx.binding_id, ctx.realm_id, ctx.reference)
            != (binding.id, binding.realm_id, reference(binding))
        ):
            raise Conflict("stored_native_state_scope_changed")
        self.projector.qualify(ctx)
        latest = await self.current(binding_id, realm, actor)
        if latest.revision != binding.revision:
            raise Conflict("stored_history_binding_changed")
        return state
