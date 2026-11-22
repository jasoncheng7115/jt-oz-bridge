"""Synthetic admissions + real local atomic outbox; no Native/Zulip network writes."""

import asyncio
import copy
from html import unescape

import pytest
from sqlalchemy import event, update

from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SCHEMA,
    MODEL_SETTING_SEMANTICS,
)
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.model_catalog import ModelSelection, ModelSettingOutcome
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.model_setting_publisher import ModelSettingPublisher
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant, WorkerLease
from jt_oz_bridge.storage.publication_models import ModelSettingPublication
from tests.integration.test_model_commands import ModelExecution, model_menu, rows
from tests.integration.test_model_commands import setup as model_setup
from tests.integration.test_router import message, send


class OutcomeExecution(ModelExecution):
    contract_hash = MODEL_SETTING_SCHEMA

    async def submit(self, ref, payload, action_id):
        await super().submit(ref, payload, action_id)
        choice = ModelSelection.model_validate(payload["selection"])
        return Admission(
            status="completed",
            details=ModelSettingOutcome(
                operation="model.switch",
                target=choice.target,
                observed=choice.target.model_copy(
                    update={"variant": choice.target.variant or "default"}
                ),
                effect="subsequent_provider_turns",
                catalog_before_sha256=choice.catalog_sha256,
                model_settings_semantics_sha256=MODEL_SETTING_SEMANTICS,
                model_settings_evidence_sha256="a" * 64,
                owner_evidence_sha256="b" * 64,
                starts_execution=False,
                turn_completed=False,
            ).model_dump(mode="json"),
        )


async def setup(db, *, locale="en", limit=1000):
    router, binding, source, _catalog, execution, commands, worker, audience = await model_setup(
        db, OutcomeExecution()
    )
    if locale != "en":
        await send(router, source, message("!oz lang " + locale, 99))
    _menu, choices = await model_menu(router, source)
    await send(router, source, message(f"!oz model {choices[0]}", 103))
    action = (await rows(db, Action))[0]
    assert await worker.advance(action.id) == "completed"
    outbox = Outbox(worker.bindings, 77, fence=commands.fence)
    replies = RoutedOutbox(outbox, realm_id="realm", message_limit=limit, topic_limit=60)
    return ModelSettingPublisher(replies), binding, action.id, execution, audience


async def test_completed_model_setting_gets_one_sealed_confirmation_not_a_turn_result(db):
    publisher, binding, action_id, execution, _audience = await setup(db)
    assert await publisher.next_pending() == action_id
    batch = await publisher.publish(action_id)
    assert await publisher.next_pending() is None
    publication = (await rows(db, ModelSettingPublication))[0]
    assert publication.action_id == action_id and publication.batch_id == batch.id
    assert publication.binding_id == binding.id
    deliveries = await rows(db, Delivery)
    assert len(deliveries) == 1 and "Model set to" in deliveries[0].payload["content"]
    assert "next model call" in deliveries[0].payload["content"]
    assert action_id not in unescape(deliveries[0].payload["content"])
    assert len(execution.submitted) == 1


async def test_recovery_keeps_original_language_pages_and_marker_even_if_renderer_limits_change(db):
    publisher, _binding, action_id, execution, _audience = await setup(db, locale="zh-TW")
    first = await publisher.publish(action_id)
    original = [(r.payload, r.payload_hash) for r in await rows(db, Delivery)]
    assert "模型已設為" in original[0][0]["content"]
    restarted = ModelSettingPublisher(
        RoutedOutbox(publisher.replies.outbox, realm_id="realm", message_limit=512, topic_limit=60)
    )
    assert await restarted.publish(action_id) == first
    assert [(r.payload, r.payload_hash) for r in await rows(db, Delivery)] == original
    assert len(await rows(db, DeliveryBatch)) == 1 and len(execution.submitted) == 1


async def test_publication_and_every_outbox_page_roll_back_together_and_recover_without_native_retry(
    db,
):
    publisher, _binding, action_id, execution, _audience = await setup(db, limit=240)

    def fail(*args):
        raise OSError("synthetic publication commit failure")

    event.listen(ModelSettingPublication, "before_insert", fail)
    try:
        with pytest.raises(OSError):
            await publisher.publish(action_id)
    finally:
        event.remove(ModelSettingPublication, "before_insert", fail)
    assert not await rows(db, ModelSettingPublication)
    assert not await rows(db, DeliveryBatch) and not await rows(db, Delivery)
    assert (await rows(db, Action))[0].state == "completed"
    assert await publisher.next_pending() == action_id
    batch = await publisher.publish(action_id)
    assert len(batch.deliveries) >= 1 and len(execution.submitted) == 1


async def test_unusable_reported_render_limit_is_rejected_before_worker_bootstrap(db):
    publisher, _binding, _action_id, _execution, _audience = await setup(db)
    with pytest.raises(ValueError, match="render_contract_too_small"):
        ModelSettingPublisher(
            RoutedOutbox(
                publisher.replies.outbox, realm_id="realm", message_limit=173, topic_limit=60
            )
        )


async def test_two_planners_commit_one_confirmation_batch(db):
    publisher, _binding, action_id, _execution, _audience = await setup(db)
    other = ModelSettingPublisher(publisher.replies)
    first, second = await asyncio.gather(publisher.publish(action_id), other.publish(action_id))
    assert first == second and len(await rows(db, ModelSettingPublication)) == 1
    assert len(await rows(db, DeliveryBatch)) == 1


@pytest.mark.parametrize("change", ["audience", "public", "revision", "view-revoked"])
async def test_confirmation_requires_current_private_scope_and_view_authorization(db, change):
    publisher, binding, action_id, _execution, audience = await setup(db)
    if change == "audience":
        audience.users = frozenset({7, 8, 999})
    elif change == "public":
        audience.private = False
    elif change == "revision":
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(revision=2)
            )
    else:
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
    with pytest.raises((Conflict, AccessDenied)):
        await publisher.publish(action_id)
    assert not await rows(db, DeliveryBatch) and not await rows(db, ModelSettingPublication)


async def test_old_lease_cannot_publish_and_successor_recovers_completed_admission(db):
    publisher, _binding, action_id, execution, _audience = await setup(db)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
    with pytest.raises(Conflict):
        await publisher.publish(action_id)
    assert not await rows(db, DeliveryBatch)
    fencing = await DurableStore(db).acquire_lease("successor")
    fresh = Outbox(publisher.replies.outbox.bindings, 77, fence=ConsumerFence("successor", fencing))
    successor = ModelSettingPublisher(
        RoutedOutbox(fresh, realm_id="realm", message_limit=1000, topic_limit=60)
    )
    assert await successor.next_pending() == action_id
    await successor.publish(action_id)
    assert len(execution.submitted) == 1


@pytest.mark.parametrize(
    "change", ["target", "semantics", "contract", "turn-completed", "admitted", "owner"]
)
async def test_unmatched_or_wrong_kind_receipt_is_not_announced_as_an_applied_setting(db, change):
    publisher, _binding, action_id, _execution, _audience = await setup(db)
    async with db.sessions.begin() as session:
        action = await session.get(Action, action_id)
        receipt = copy.deepcopy(action.admission)
        if change == "target":
            receipt["admission"]["details"]["target"]["model_id"] = "foreign-model"
            receipt["admission"]["details"]["observed"]["model_id"] = "foreign-model"
        elif change == "semantics":
            receipt["admission"]["details"]["model_settings_semantics_sha256"] = "c" * 64
        elif change == "contract":
            receipt["contract_sha256"] = "c" * 64
        elif change == "turn-completed":
            receipt["admission"]["details"]["turn_completed"] = True
        elif change == "admitted":
            receipt["admission"]["status"] = "admitted"
        else:
            receipt["admission"]["owner"] = "bridge"
        action.admission = receipt
    with pytest.raises(ValueError):
        await publisher.publish(action_id)
    assert not await rows(db, DeliveryBatch) and not await rows(db, ModelSettingPublication)


async def test_corrupt_or_missing_previously_planned_page_is_held_without_replanning(db):
    publisher, _binding, action_id, execution, _audience = await setup(db)
    batch = await publisher.publish(action_id)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Delivery).where(Delivery.id == batch.deliveries[0]).values(payload_hash="c" * 64)
        )
    with pytest.raises(Conflict):
        await ModelSettingPublisher(publisher.replies).publish(action_id)
    assert len(await rows(db, DeliveryBatch)) == 1 and len(execution.submitted) == 1


async def test_publication_seal_detects_admission_replacement_before_cache_reuse(db):
    publisher, _binding, action_id, execution, _audience = await setup(db)
    await publisher.publish(action_id)
    async with db.sessions.begin() as session:
        action = await session.get(Action, action_id)
        receipt = copy.deepcopy(action.admission)
        receipt["admission"]["details"]["owner_evidence_sha256"] = "c" * 64
        action.admission = receipt
    with pytest.raises(Conflict, match="source_changed"):
        await publisher.publish(action_id)
    assert len(await rows(db, DeliveryBatch)) == 1 and len(execution.submitted) == 1
