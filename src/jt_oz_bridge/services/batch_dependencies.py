"""Encrypted dependency scope validation; callers never guess success from absence."""

from pydantic import Field, StrictInt
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from jt_oz_bridge.domain.control import ControlModel
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.publication_records import read_publication, read_resource_publication
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Delivery, DeliveryBatch
from jt_oz_bridge.storage.publication_models import BatchDependency, NativePublication
from jt_oz_bridge.storage.resource_models import ResourcePublication


class BatchDependencyPlan(ControlModel):
    batch_id: str
    before_batch_id: str
    binding_id: str
    binding_revision: StrictInt = Field(ge=1)
    realm_id: str
    bot_user_id: StrictInt = Field(gt=0)
    before_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


async def validate_dependency(
    session: AsyncSession, batch_id: str, binding: Binding, bot_user_id: int
) -> BatchDependencyPlan | None:
    row = await session.get(BatchDependency, batch_id)
    from jt_oz_bridge.services.transcript_records import validate_transcript_batch

    await validate_transcript_batch(
        session, batch_id, binding, bot_user_id, row.before_batch_id if row else None
    )
    from jt_oz_bridge.services.draft_records import validate_draft_batch

    await validate_draft_batch(
        session, batch_id, binding, bot_user_id, row.before_batch_id if row else None
    )
    publication = await session.scalar(
        select(NativePublication).where(NativePublication.batch_id == batch_id)
    )
    if publication is not None:
        native = read_publication(publication)
        batch = await session.get(DeliveryBatch, batch_id)
        if (
            batch is None
            or (
                native.binding_id,
                native.binding_revision,
                native.realm_id,
                native.reference,
                native.bot_user_id,
                native.plan_hash,
            )
            != (
                binding.id,
                binding.revision,
                binding.realm_id,
                reference(binding),
                bot_user_id,
                batch.plan_hash,
            )
            or native.previous_batch_id != (row.before_batch_id if row else None)
        ):
            raise Conflict("native_publication_batch_evidence_changed")
    resource_publication = await session.scalar(
        select(ResourcePublication).where(ResourcePublication.batch_id == batch_id)
    )
    if resource_publication is not None:
        resource = read_resource_publication(resource_publication)
        batch = await session.get(DeliveryBatch, batch_id)
        if (
            batch is None
            or (
                resource.binding_id,
                resource.binding_revision,
                resource.realm_id,
                resource.channel_id,
                resource.topic,
                resource.reference,
                resource.bot_user_id,
                resource.plan_hash,
            )
            != (
                binding.id,
                binding.revision,
                binding.realm_id,
                binding.channel_id,
                binding.topic,
                reference(binding),
                bot_user_id,
                batch.plan_hash,
            )
            or resource.previous_batch_id != (row.before_batch_id if row else None)
        ):
            raise Conflict("resource_publication_batch_evidence_changed")
    if row is None:
        return None
    if digest(row.payload) != row.payload_hash:
        raise Conflict("batch_dependency_hash_changed")
    plan = BatchDependencyPlan.model_validate(row.payload)
    before = await session.get(DeliveryBatch, row.before_batch_id)
    if (
        before is None
        or row.batch_id == row.before_batch_id
        or (
            plan.batch_id,
            plan.before_batch_id,
            plan.binding_id,
            plan.binding_revision,
            plan.realm_id,
            plan.bot_user_id,
        )
        != (
            row.batch_id,
            row.before_batch_id,
            binding.id,
            binding.revision,
            binding.realm_id,
            bot_user_id,
        )
        or before.destination_id is not None
        or (before.binding_id, before.binding_revision, before.plan_hash)
        != (binding.id, binding.revision, plan.before_plan_hash)
    ):
        raise Conflict("batch_dependency_scope_changed")
    return plan


async def store_dependency(
    session: AsyncSession, batch_id: str, before_batch_id: str, binding: Binding, bot_user_id: int
) -> None:
    before = await session.get(DeliveryBatch, before_batch_id)
    if (
        before is None
        or batch_id == before_batch_id
        or before.destination_id is not None
        or (before.binding_id, before.binding_revision) != (binding.id, binding.revision)
    ):
        raise Conflict("batch_dependency_target_invalid")
    plan = BatchDependencyPlan(
        batch_id=batch_id,
        before_batch_id=before_batch_id,
        binding_id=binding.id,
        binding_revision=binding.revision,
        realm_id=binding.realm_id,
        bot_user_id=bot_user_id,
        before_plan_hash=before.plan_hash,
    )
    payload = plan.model_dump(mode="json")
    session.add(
        BatchDependency(
            batch_id=batch_id,
            before_batch_id=before_batch_id,
            payload=payload,
            payload_hash=digest(payload),
        )
    )


def dependency_ready() -> ColumnElement[bool]:
    dependency = aliased(BatchDependency)
    previous = aliased(DeliveryBatch)
    pages = aliased(Delivery)
    delivered = (
        select(func.count(pages.id))
        .where(
            pages.batch_id == dependency.before_batch_id,
            pages.state == "delivered",
            pages.posted_message_id > 0,
            pages.binding_id == Delivery.binding_id,
            pages.binding_revision == Delivery.binding_revision,
            pages.destination_id.is_(None),
        )
        .correlate(Delivery, dependency)
        .scalar_subquery()
    )
    blocked = (
        select(dependency.batch_id)
        .outerjoin(previous, previous.id == dependency.before_batch_id)
        .where(
            dependency.batch_id == Delivery.batch_id,
            or_(
                previous.id.is_(None),
                previous.destination_id.is_not(None),
                previous.binding_id.is_distinct_from(Delivery.binding_id),
                previous.binding_revision.is_distinct_from(Delivery.binding_revision),
                previous.page_count < 1,
                delivered != previous.page_count,
            ),
        )
        .correlate(Delivery)
        .exists()
    )
    return ~blocked
