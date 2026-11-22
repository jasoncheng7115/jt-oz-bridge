"""Authorized stored resource text; bridge ordinals are not Native replay."""

from typing import Literal

from sqlalchemy import select

from jt_oz_bridge.domain.control import ControlModel, ExecutionState
from jt_oz_bridge.services.bindings import BindingService, reference
from jt_oz_bridge.services.native_history import StoredPart, StoredPartPage
from jt_oz_bridge.services.resource_execution_results import indexed_result, text_index_hash
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action
from jt_oz_bridge.storage.resource_models import ResourceResultRecord, ResourceTextRecord


class StoredResourceStatus(ControlModel):
    source: Literal["stored-resource-result"] = "stored-resource-result"
    status: ExecutionState
    outcome: Literal["completed", "failed", "cancelled"]
    action_id: str


class ResourceHistory:
    def __init__(self, bindings: BindingService) -> None:
        self.bindings, self.db = bindings, bindings.db

    async def current(self, binding_id: str, realm: str, actor: int) -> Binding:
        return await self.bindings.get(binding_id, realm, actor)

    async def verify(self, binding: Binding, row: ResourceTextRecord) -> StoredPart:
        async with self.db.sessions() as session:
            index = await session.get(ResourceResultRecord, row.action_id)
            action = await session.get(Action, row.action_id)
        if index is None or action is None:
            raise Conflict("resource_history_result_missing")
        result = indexed_result(index, action)
        if row.source_hash != text_index_hash(row, result) or (
            result.binding_id,
            result.binding_revision,
            result.realm_id,
            result.channel_id,
            result.topic,
            result.reference,
        ) != (
            binding.id,
            binding.revision,
            binding.realm_id,
            binding.channel_id,
            binding.topic,
            reference(binding),
        ):
            raise Conflict("resource_history_part_scope_or_seal_changed")
        part = result.evidence.turn.text[row.part_index]
        return StoredPart(
            record_id=row.id,
            record_hash=row.source_hash,
            ordinal=row.ordinal,
            native_message_id=part.assistant_id,
            part_ordinal=part.content_index,
            text=part.text,
        )

    async def page(
        self, binding_id: str, realm: str, actor: int, *, before: int | None = None
    ) -> StoredPartPage:
        if before is not None and (type(before) is not int or not 1 <= before <= 2**63 - 1):
            raise ValueError("invalid_stored_resource_history_cursor")
        binding = await self.current(binding_id, realm, actor)
        statement = (
            select(ResourceTextRecord)
            .join(
                ResourceResultRecord, ResourceResultRecord.action_id == ResourceTextRecord.action_id
            )
            .where(
                ResourceResultRecord.binding_id == binding.id,
                ResourceResultRecord.binding_revision == binding.revision,
            )
            .order_by(ResourceTextRecord.ordinal.desc())
            .limit(11)
        )
        if before is not None:
            statement = statement.where(ResourceTextRecord.ordinal < before)
        async with self.db.sessions() as session:
            rows = list((await session.scalars(statement)).all())
        parts = tuple([await self.verify(binding, row) for row in rows[:10]])
        latest = await self.current(binding_id, realm, actor)
        if latest.revision != binding.revision or reference(latest) != reference(binding):
            raise Conflict("stored_resource_history_binding_changed")
        return StoredPartPage(
            items=parts, next_before=parts[-1].ordinal if len(rows) > 10 and parts else None
        )

    async def part(
        self, binding_id: str, realm: str, actor: int, record_id: str, record_hash: str
    ) -> StoredPart:
        binding = await self.current(binding_id, realm, actor)
        async with self.db.sessions() as session:
            row = await session.get(ResourceTextRecord, record_id)
        if row is None or row.source_hash != record_hash:
            raise Conflict("resource_history_selection_changed")
        part = await self.verify(binding, row)
        latest = await self.current(binding_id, realm, actor)
        if latest.revision != binding.revision or reference(latest) != reference(binding):
            raise Conflict("stored_resource_history_binding_changed")
        return part

    async def latest_state(
        self, binding_id: str, realm: str, actor: int
    ) -> StoredResourceStatus | None:
        binding = await self.current(binding_id, realm, actor)
        async with self.db.sessions() as session:
            index = await session.scalar(
                select(ResourceResultRecord)
                .where(
                    ResourceResultRecord.binding_id == binding.id,
                    ResourceResultRecord.binding_revision == binding.revision,
                )
                .order_by(ResourceResultRecord.ordinal.desc())
                .limit(1)
            )
            action = await session.get(Action, index.action_id) if index is not None else None
        if index is None:
            return None
        if action is None:
            raise Conflict("resource_history_result_missing")
        result = indexed_result(index, action)
        if (result.realm_id, result.channel_id, result.topic, result.reference) != (
            binding.realm_id,
            binding.channel_id,
            binding.topic,
            reference(binding),
        ):
            raise Conflict("resource_history_result_scope_changed")
        latest = await self.current(binding_id, realm, actor)
        if latest.revision != binding.revision or reference(latest) != reference(binding):
            raise Conflict("stored_resource_history_binding_changed")
        return StoredResourceStatus(
            status=ExecutionState.FAILED if result.outcome == "failed" else ExecutionState.IDLE,
            outcome=result.outcome,
            action_id=result.action_id,
        )
