"""Original typed Native mock + real pipeline/router/encrypted SQL/outboxes.

All Humans and HTTP peers are synthetic; this is not installed/mobile acceptance.
"""

import asyncio
import copy
import json
import re
from html import unescape

import httpx
import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.orm.attributes import flag_modified

from jt_oz_bridge.services.creation_commands import SavedCreationReply
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from tests.contract.test_public_live_feed import REAL
from tests.integration.test_router import message
from tests.integration.test_session_creation_activation import cleanup, setup, startup_pipeline
from tests.integration.test_session_creation_journal import rows


async def environment(db, *, mode="success"):
    e = await setup(db)
    # Remove only this helper's synthetic pre-admitted reservation. The original
    # typed backend/feed/anchor remains the graph under test, not a substitute.
    async with db.sessions.begin() as session:
        await session.execute(delete(Action))
        await session.execute(delete(Binding))
        await session.execute(update(EnrolledBackend).values(version="2.0.32"))
    pipeline, registry, factory, markers = await startup_pipeline(e)
    pipeline.source.read = e["source"].read
    e.update(pipe=pipeline, registry=registry, current_factory=factory, wire=[], mode=mode)
    original = e["t"].client._transport
    old_id = e["intent"].native_session_id
    base_info = copy.deepcopy(e["state"]["info"])

    def handler(request):
        e["wire"].append((request.method, request.url.path))
        if request.method == "POST":
            assert request.url.path == "/api/session"
            body = json.loads(request.content)
            assert body == factory.creator.body(e["live_intent"])
            e["state"]["info"] = {**copy.deepcopy(base_info), **copy.deepcopy(body)}
            e["state"]["info"]["projectID"] = "global"
            if mode == "lost-ack":
                raise httpx.ReadTimeout("synthetic accepted creation, lost ACK", request=request)
            if mode == "cancel-after-send":
                raise asyncio.CancelledError
            return httpx.Response(200, json={"data": copy.deepcopy(e["state"]["info"])})
        assert request.method == "GET"
        if "live_intent" in e:
            new_id = e["live_intent"].native_session_id
            if request.url.path.startswith("/api/session/" + new_id):
                assert new_id != old_id
                # Reuse the fixture's session-resource responder for this newly
                # allocated mock Root. Production request URLs stay recorded above.
                request = httpx.Request(
                    "GET",
                    request.url.copy_with(path=request.url.path.replace(new_id, old_id)),
                    headers=request.headers,
                )
        return original.handler(request)

    e["t"].client._transport = httpx.MockTransport(handler)
    return e


async def close(e):
    await e["pipe"].scope.client.close()
    await cleanup(e)


def used_root(e, state):
    """Actual typed mock resources; no alternate session, transcript or prompt."""
    identity = e["live_intent"].native_session_id
    e["state"]["info"].update(title="Worked on before Bridge activation", cost=1.5)
    e["state"]["info"]["tokens"]["input"] = 50
    if state in {"running", "waiting", "waiting-input"}:
        e["d"]["session.active"]["data"][identity] = {"type": "running"}
        if state == "waiting":
            item = copy.deepcopy(next(x["data"] for x in REAL if x["type"] == "permission.asked"))
            item["sessionID"] = identity
            e["state"]["permissions"] = [item]
        elif state == "waiting-input":
            item = copy.deepcopy(
                next(x["data"]["form"] for x in REAL if x["type"] == "form.created")
            )
            item["sessionID"] = identity
            e["state"]["forms"] = [item]
    elif state == "queued":
        e["state"]["inbox"] = [
            {
                "id": "msg_queue",
                "sessionID": identity,
                "type": "user",
                "payload": {"text": "synthetic work"},
                "delivery": "queue",
                "time": {"created": 101},
            }
        ]


async def route(e, text, mid, *, recovered=False, **changes):
    item = message(text, mid, **changes)
    e["source"].messages[mid] = item
    result = await e["pipe"].router.route(item, recovered=recovered)
    return item, result


async def reserve(e, mid=201, **changes):
    _, menu = await route(e, "!oz new", mid - 1, **changes)
    assert menu.state == "reply"
    token = re.search(r"!oz new ([A-Za-z0-9_-]{32})", menu.text)[1]
    item, reply = await route(e, "!oz new " + token + " Literal new Root", mid, **changes)
    assert reply.state == "ignore" and reply.action_id
    action, binding = await e["pipe"].creation.journal.load(reply.action_id)
    _, e["live_intent"], _ = e["pipe"].creation.journal.payload(action, binding)
    return item, reply, action, binding


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_live_selection_one_post_activation_and_duplicate_never_queue_unbound_ack(db, locale):
    from jt_oz_bridge.i18n import save_locale

    e = await environment(db)
    try:
        await save_locale(db, "user:realm:7", locale, fence=e["pipe"].fence)
        item, reply, action, binding = await reserve(e)
        assert not e["wire"] or all(m == "GET" for m, _ in e["wire"])
        assert not await rows(db, Delivery)
        receipt = await e["pipe"].inbox.find("realm", item.message_id)
        saved = SavedCreationReply.model_validate(receipt.response)
        assert receipt.state == "completed" and saved.action_id == action.id
        assert saved.locale == locale
        assert await e["pipe"].consumer.publish(reply) is None
        await asyncio.gather(e["pipe"].creation_commands.once(), e["pipe"].creation_commands.once())
        action, active = await e["pipe"].creation.journal.load(action.id)
        assert action.state == "completed" and active.state == "active"
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert all(m == "GET" or p == "/api/session" for m, p in e["wire"])
        assert e["registry"].sessions[e["anchor"].reference] is e["anchor"]
        new_ref = e["current_factory"].selected(e["live_intent"])
        assert new_ref in e["pipe"].backends[new_ref.backend_id].current_references
        assert new_ref in e["pipe"].router.history.readers
        assert new_ref in e["pipe"].router.metadata.readers
        notices = await rows(db, Delivery)
        assert len(notices) == 1 and notices[0].binding_id == active.id
        assert notices[0].destination_id is None and notices[0].payload["topic"] == item.topic
        # The notice names the title and project, never the raw Native session ID.
        notice = unescape(notices[0].payload["content"])
        assert active.session_id not in notice and active.project_id in notice
        again = await e["pipe"].router.route(item)
        assert again.state == "ignore" and again.action_id == action.id
        assert await e["pipe"].consumer.publish(again) is None
        assert len(await rows(db, Delivery)) == 1
        assert len(await rows(db, Action)) == 1
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


@pytest.mark.parametrize("mode", ["lost-ack", "cancel-after-send"])
async def test_uncertain_create_requires_explicit_resume_then_fixed_id_get_not_second_post(
    db, mode
):
    e = await environment(db, mode=mode)
    try:
        _, _, action, _ = await reserve(e)
        if mode == "cancel-after-send":
            with pytest.raises(asyncio.CancelledError):
                await e["pipe"].creation_commands.once()
            await e["pipe"].creation_commands.recover()
        else:
            await e["pipe"].creation_commands.once()
        current, reserved = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "ambiguous"
        # A dispatching recovery has readback authority only; explicitly pause
        # before the user resumes, just as a controlled operator would.
        await route(e, "!oz new pause", 202)
        _, resumed = await route(e, "!oz new resume", 203)
        assert resumed.state == "ignore"
        await e["pipe"].creation_commands.once()
        current, active = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "completed" and active.state == "active"
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert len(await rows(db, Delivery)) == 1
    finally:
        await close(e)


async def test_stop_and_go_in_the_creating_topic_pause_and_resume_an_uncertain_create(db):
    e = await environment(db, mode="lost-ack")
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        current, _ = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "ambiguous"
        _, paused = await route(e, "!stop", 202)
        assert paused.state == "reply" and "!go" in paused.text
        _, resumed = await route(e, "!go", 203)
        assert resumed.state == "ignore" and resumed.action_id == action.id
        await e["pipe"].creation_commands.once()
        current, active = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "completed" and active.state == "active"
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


async def test_no_in_the_creating_topic_cancels_an_unsent_create(db):
    e = await environment(db)
    try:
        _, _, action, binding = await reserve(e)
        _, reply = await route(e, "!no", 202)
        assert reply.state == "reply"
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
        async with db.sessions() as session:
            current, saved = (
                await session.get(Action, action.id),
                await session.get(Binding, binding.id),
            )
        assert current.state == "cancelled" and saved.state == "unbound"
    finally:
        await close(e)


@pytest.mark.parametrize("control", ["pause", "cancel"])
async def test_unsent_pause_cancel_and_duplicate_controls_do_not_start_native(db, control):
    e = await environment(db)
    try:
        original, _, action, binding = await reserve(e)
        item, reply = await route(e, "!oz new " + control, 202)
        assert reply.state == "reply"
        again = await e["pipe"].router.route(item)
        assert again.text == reply.text
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
        async with db.sessions() as session:
            current, saved = (
                await session.get(Action, action.id),
                await session.get(Binding, binding.id),
            )
        if control == "cancel":
            assert current.state == "cancelled" and saved.state == "unbound"
            assert saved.topic_key is None and saved.session_key is None
            duplicate = await e["pipe"].router.route(original)
            assert duplicate.state == "ignore"
        else:
            assert saved.dispatch_paused and saved.state == "creating"
            _, resumed = await route(e, "!oz new resume", 203)
            assert resumed.state == "ignore"
            await e["pipe"].creation_commands.once()
            assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


@pytest.mark.parametrize("fault", ["recovered", "edited", "actor", "topic", "revoked"])
async def test_nonlive_or_foreign_selection_never_reserves_or_creates(db, fault):
    e = await environment(db)
    try:
        _, menu = await route(e, "!oz new", 200)
        token = re.search(r"!oz new ([A-Za-z0-9_-]{32})", menu.text)[1]
        changes = {}
        if fault == "edited":
            changes["revision"] = 1
        if fault == "actor":
            changes["author_id"] = 8
        if fault == "topic":
            changes["topic"] = "Different topic"
        if fault == "revoked":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        await route(e, "!oz new " + token, 201, recovered=fault == "recovered", **changes)
        assert not await rows(db, Action)
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
    finally:
        await close(e)


async def test_startup_holds_old_unsent_intent_until_live_resume_without_changing_native_id(db):
    e = await environment(db)
    try:
        _, _, action, binding = await reserve(e)
        payload = copy.deepcopy(action.payload)
        e["wire"].clear()
        await e["pipe"].creation_commands.recover()
        current, held = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "held" and held.dispatch_paused
        assert current.payload == payload and not current.admission and not e["wire"]
        await e["pipe"].creation_commands.once()
        assert not e["wire"]
        _, status = await route(e, "!oz new status", 202)
        assert status.state == "reply" and "held" in status.text
        _, resumed = await route(e, "!oz new resume", 203)
        assert resumed.state == "ignore" and resumed.action_id == action.id
        await e["pipe"].creation_commands.once()
        current, active = await e["pipe"].creation.journal.load(action.id)
        assert current.payload == payload and active.session_id == binding.session_id
        assert current.state == "completed" and e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "processing",
        "foreign_fence",
        "ambiguous",
        "wrong_action",
        "wrong_source",
        "attempt",
    ],
)
async def test_worker_requires_completed_current_fenced_exact_inert_command_receipt(db, fault):
    e = await environment(db)
    try:
        item, _, action, binding = await reserve(e)
        async with db.sessions.begin() as session:
            receipt = await session.scalar(
                select(CommandReceipt).where(CommandReceipt.message_id == item.message_id)
            )
            if fault == "missing":
                await session.delete(receipt)
            elif fault == "processing":
                receipt.state = "processing"
            elif fault == "foreign_fence":
                receipt.fencing += 1
            elif fault == "ambiguous":
                receipt.state = "ambiguous"
            elif fault in {"wrong_action", "wrong_source"}:
                receipt.response = {
                    **receipt.response,
                    "action_id"
                    if fault == "wrong_action"
                    else "source_sha256": "00000000-0000-0000-0000-000000000001"
                    if fault == "wrong_action"
                    else "0" * 64,
                }
            else:
                saved = await session.get(Action, action.id)
                saved.admission = {"format": "already-attempted"}
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
        current, held = await e["pipe"].creation.journal.load(action.id)
        if fault == "processing":
            assert current.state == "queued" and not held.dispatch_paused
        else:
            assert held.dispatch_paused
    finally:
        await close(e)


@pytest.mark.parametrize(
    "fault", ["source_edit", "source_removed", "grant_revoked", "new_untrusted_reader"]
)
async def test_current_original_authority_is_rechecked_after_reservation_before_native_send(
    db, fault
):
    e = await environment(db)
    try:
        item, _, action, _ = await reserve(e)
        if fault == "source_edit":
            e["source"].messages[item.message_id] = item.model_copy(
                update={"revision": 1, "text": "edited"}
            )
        elif fault == "source_removed":
            e["source"].messages.pop(item.message_id)
            original = e["pipe"].source.read

            async def missing(realm, mid):
                from jt_oz_bridge.adapters.zulip.client import ZulipError

                try:
                    return await original(realm, mid)
                except KeyError:
                    raise ZulipError("synthetic missing source") from None

            e["pipe"].source.read = missing
        elif fault == "grant_revoked":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        else:
            e["audience"].users = frozenset({7, 8, 999})
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
        current, held = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "held" and held.dispatch_paused
    finally:
        await close(e)


async def test_proven_not_sent_can_cancel_but_cannot_resume_or_reuse_an_attempt(db):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.domain.execution import MutationNotSent

    e = await environment(db)
    try:
        _, _, action, binding = await reserve(e)
        e["current_factory"].creator.create = AsyncMock(
            side_effect=MutationNotSent("synthetic before-send rejection")
        )
        await e["pipe"].creation_commands.once()
        current, held = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "rejected" and current.status_reason == "creation_proven_not_sent"
        assert held.dispatch_paused
        await route(e, "!oz new resume", 202)
        assert e["current_factory"].creator.create.await_count == 1
        _, cancelled = await route(e, "!oz new cancel", 203)
        assert cancelled.state == "reply" and "Cancelled" in cancelled.text
        async with db.sessions() as session:
            assert (await session.get(Binding, binding.id)).state == "unbound"
        await e["pipe"].creation_commands.once()
        assert e["current_factory"].creator.create.await_count == 1
    finally:
        await close(e)


async def test_uncertain_native_root_cannot_be_cancelled_or_silently_detached(db):
    e = await environment(db, mode="lost-ack")
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        before, binding = await e["pipe"].creation.journal.load(action.id)
        await route(e, "!oz new cancel", 202)
        after, current = await e["pipe"].creation.journal.load(action.id)
        assert before.state == after.state == "ambiguous"
        assert current.state == "creating" and current.topic_key == binding.topic_key
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert not any(m == "DELETE" for m, _ in e["wire"])
    finally:
        await close(e)


async def test_recovered_resume_control_cannot_enable_an_old_queued_intent(db):
    e = await environment(db)
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.recover()
        _, reply = await route(e, "!oz new resume", 202, recovered=True)
        assert reply.state == "held"
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
        assert (await e["pipe"].creation.journal.load(action.id))[0].state == "held"
    finally:
        await close(e)


@pytest.mark.parametrize("sent", [False, True])
async def test_new_consumer_fence_never_posts_old_queue_and_only_gets_uncertain_original_id(
    db, sent
):
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence

    e = await environment(db, mode="cancel-after-send" if sent else "success")
    try:
        _, _, action, binding = await reserve(e)
        if sent:
            with pytest.raises(asyncio.CancelledError):
                await e["pipe"].creation_commands.once()
        old = e["pipe"]
        old_fence = old.fence
        await old.scope.client.close()
        store = DurableStore(db)
        await store.release_lease(old_fence.holder, old_fence.fencing)
        token = await store.acquire_lease("restarted-creation", ttl=120)
        assert token is not None and token > old_fence.fencing
        e["journal"].fence = ConsumerFence("restarted-creation", token)
        fresh, registry, factory, _ = await startup_pipeline(e)
        fresh.source.read = e["source"].read
        e.update(pipe=fresh, registry=registry, current_factory=factory)
        await fresh.creation_commands.recover()
        if not sent:
            current, pending = await fresh.creation.journal.load(action.id)
            assert current.state == "held" and pending.dispatch_paused
            await fresh.creation_commands.once()
            assert not any(m == "POST" for m, _ in e["wire"])
            await route(e, "!oz new resume", 202)
        before = e["wire"].count(("POST", "/api/session"))
        # The synthetic peer's cancellation applies only to the original send.
        e["mode"] = "success"
        if not sent:
            # This fixture was originally configured for normal successful POST.
            assert before == 0
        await fresh.creation_commands.once()
        current, active = await fresh.creation.journal.load(action.id)
        assert current.state == "completed" and active.session_id == binding.session_id
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert not sent or e["wire"].count(("POST", "/api/session")) == before
    finally:
        await close(e)


@pytest.mark.parametrize("kind", ["unavailable", "rate"])
async def test_transient_original_source_read_is_deferred_without_pausing_or_claiming_send(
    db, kind
):
    from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
    from jt_oz_bridge.domain.delivery import DeliveryRateLimited

    e = await environment(db)
    try:
        item, _, action, _ = await reserve(e)
        original = e["pipe"].source.read
        failed = False

        async def read(realm, mid):
            nonlocal failed
            if mid == item.message_id and not failed:
                failed = True
                if kind == "unavailable":
                    raise ZulipReadUnavailable("zulip_read_service_unavailable")
                raise DeliveryRateLimited(1)
            return await original(realm, mid)

        e["pipe"].source.read = read
        error = ZulipReadUnavailable if kind == "unavailable" else DeliveryRateLimited
        with pytest.raises(error):
            await e["pipe"].creation_commands.once()
        current, pending = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "queued" and not current.admission and not pending.dispatch_paused
        assert not any(m == "POST" for m, _ in e["wire"])
        await e["pipe"].creation_commands.once()
        assert (await e["pipe"].creation.journal.load(action.id))[0].state == "completed"
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


async def test_background_loop_finishes_own_live_intent_and_cancels_without_reposting(db):
    from tests.integration.test_consumer_runtime import until

    e = await environment(db)
    task = None
    try:
        _, _, action, _ = await reserve(e)
        e["pipe"].interval = 0.01
        assert "native-session-creation" in [w.name for w in e["pipe"].runtime().workers]
        task = asyncio.create_task(e["pipe"].create_sessions())

        async def complete():
            return (await e["pipe"].creation.journal.load(action.id))[0].state == "completed"

        await until(complete)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert len(await rows(db, Delivery)) == 1
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await close(e)


async def test_source_edit_after_native_acceptance_keeps_real_root_unbound_without_resend(db):
    e = await environment(db)
    try:
        item, _, action, binding = await reserve(e)
        transport = e["t"].client._transport

        def changed(request):
            response = transport.handler(request)
            if request.method == "POST":
                e["source"].messages[item.message_id] = item.model_copy(
                    update={"revision": 1, "text": "edited after send"}
                )
            return response

        e["t"].client._transport = httpx.MockTransport(changed)
        await e["pipe"].creation_commands.once()
        current, pending = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "ambiguous" and pending.state == "creating"
        assert pending.dispatch_paused and not await rows(db, Delivery)
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert len(e["registry"].sessions) == 1
        await e["pipe"].creation_commands.once()
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert e["state"]["info"]["id"] == binding.session_id
    finally:
        await close(e)


async def test_cancel_between_worker_selection_and_load_does_not_stop_runtime_or_send(db):
    e = await environment(db)
    try:
        _, _, action, _ = await reserve(e)
        journal = e["pipe"].creation.journal
        original = journal.load
        cancelled = False

        async def load(identity):
            nonlocal cancelled
            if not cancelled:
                cancelled = True
                _, reply = await route(e, "!oz new cancel", 202)
                assert "Cancelled" in reply.text
            return await original(identity)

        journal.load = load
        await e["pipe"].creation_commands.once()
        assert await e["pipe"].creation_commands.cancelled(action.id)
        assert not any(m == "POST" for m, _ in e["wire"])
    finally:
        await close(e)


async def test_pause_after_send_preserves_uncertainty_then_resume_only_reads_same_id(db):
    e = await environment(db)
    try:
        _, _, action, _ = await reserve(e)
        creator = e["current_factory"].creator
        create = creator.create

        async def paused(intent, **kwargs):
            result = await create(intent, **kwargs)
            await route(e, "!oz new pause", 202)
            return result

        creator.create = paused
        await e["pipe"].creation_commands.once()
        current, binding = await e["pipe"].creation.journal.load(action.id)
        assert binding.state == "creating" and binding.dispatch_paused
        assert current.state == "dispatching" and not await rows(db, Delivery)
        _, resumed = await route(e, "!oz new resume", 203)
        assert resumed.state == "ignore"
        await e["pipe"].creation_commands.once()
        assert (await e["pipe"].creation.journal.load(action.id))[0].state == "completed"
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


async def test_native_policy_drift_holds_observed_root_and_later_resume_never_recreates(db):
    e = await environment(db)
    try:
        _, _, action, _ = await reserve(e)
        creator = e["current_factory"].creator
        create = creator.create
        old = copy.deepcopy(e["d"]["plugin.list"])

        async def changed(intent, **kwargs):
            result = await create(intent, **kwargs)
            e["d"]["plugin.list"] = {"data": [{"id": "synthetic changed policy"}]}
            return result

        creator.create = changed
        await e["pipe"].creation_commands.once()
        current, binding = await e["pipe"].creation.journal.load(action.id)
        assert (
            current.state == "admitted" and binding.state == "creating" and binding.dispatch_paused
        )
        assert not await rows(db, Delivery)
        e["d"]["plugin.list"] = old
        await route(e, "!oz new resume", 202)
        await e["pipe"].creation_commands.once()
        assert (await e["pipe"].creation.journal.load(action.id))[0].state == "completed"
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


@pytest.mark.parametrize("stage", ["lost-ack", "admitted"])
@pytest.mark.parametrize("native_state", ["idle", "running", "queued", "waiting", "waiting-input"])
@pytest.mark.parametrize("restart", [False, True])
async def test_explicit_resume_adopts_same_used_root_before_first_activation(
    db, stage, native_state, restart
):
    from jt_oz_bridge.domain.control import ExecutionState
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence

    e = await environment(db, mode="lost-ack" if stage == "lost-ack" else "success")
    try:
        _, _, action, binding = await reserve(e)
        journal = e["pipe"].creation.journal
        record = journal.record
        if stage == "admitted":

            async def after_record(*args, **kwargs):
                state = await record(*args, **kwargs)
                used_root(e, native_state)
                return state

            journal.record = after_record
        await e["pipe"].creation_commands.once()
        if stage == "lost-ack":
            used_root(e, native_state)
        current, pending = await journal.load(action.id)
        assert current.state == ("ambiguous" if stage == "lost-ack" else "admitted")
        assert pending.dispatch_paused and not await rows(db, Delivery)
        journal.record = record
        if restart:
            old = e["pipe"]
            await old.scope.client.close()
            store = DurableStore(db)
            await store.release_lease(old.fence.holder, old.fence.fencing)
            token = await store.acquire_lease("used-root-recovery", ttl=120)
            e["journal"].fence = ConsumerFence("used-root-recovery", token)
            fresh, registry, factory, _ = await startup_pipeline(e)
            fresh.source.read = e["source"].read
            e.update(pipe=fresh, registry=registry, current_factory=factory)
            await fresh.creation_commands.recover()
        _, resumed = await route(e, "!oz new resume", 202)
        assert resumed.state == "ignore"
        before = len(e["wire"])
        await e["pipe"].creation_commands.once()
        current, active = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "completed" and active.state == "active"
        assert active.id == binding.id and active.session_id == binding.session_id
        assert all(method == "GET" for method, _ in e["wire"][before:])
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert e["registry"].sessions[e["anchor"].reference] is e["anchor"]
        ref = e["current_factory"].selected(e["live_intent"])
        observed = await e["registry"].snapshot(ref)
        assert (
            observed.state
            == {
                "idle": ExecutionState.IDLE,
                "running": ExecutionState.RUNNING,
                "queued": ExecutionState.QUEUED,
                "waiting": ExecutionState.WAITING_PERMISSION,
                "waiting-input": ExecutionState.WAITING_INPUT,
            }[native_state]
        )
        assert observed.title == "Worked on before Bridge activation"
        assert len(await rows(db, Delivery)) == 1
        after = current.native_result
        await e["pipe"].creation_commands.once()
        assert (await e["pipe"].creation.journal.load(action.id))[0].native_result == after
        assert len(await rows(db, Delivery)) == 1
    finally:
        await close(e)


@pytest.mark.parametrize("stage", ["lost-ack", "admitted"])
@pytest.mark.parametrize(
    "fault", ["missing", "processing", "old_fence", "wrong_source", "edited_source"]
)
async def test_used_root_resume_requires_exact_completed_live_recovery_receipt(db, stage, fault):
    e = await environment(db, mode="lost-ack")
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        if stage == "admitted":
            # Obtain an actual pristine readback receipt before Native work.
            await e["pipe"].creation.journal.advance(action.id, e["current_factory"].creator)
        used_root(e, "running")
        item, _ = await route(e, "!oz new resume", 202)
        receipt = await e["pipe"].inbox.find(item.realm_id, item.message_id)
        async with db.sessions.begin() as session:
            saved = await session.get(CommandReceipt, receipt.id)
            if fault == "missing":
                await session.delete(saved)
            elif fault == "processing":
                saved.state = "processing"
            elif fault == "old_fence":
                saved.fencing -= 1
            elif fault == "wrong_source":
                saved.response = {**saved.response, "source_sha256": "0" * 64}
        if fault == "edited_source":
            e["source"].messages[item.message_id] = item.model_copy(update={"revision": 1})
        before = len(e["wire"])
        await e["pipe"].creation_commands.once()
        current, pending = await e["pipe"].creation.journal.load(action.id)
        assert current.state != "completed" and pending.state == "creating"
        assert len(e["wire"]) == before and not await rows(db, Delivery)
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


async def test_resume_source_change_after_native_recovery_does_not_bind_or_notify(db):
    e = await environment(db, mode="lost-ack")
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        used_root(e, "running")
        item, _ = await route(e, "!oz new resume", 202)
        creator = e["current_factory"].creator
        recover = creator.recover

        async def edited(intent):
            result = await recover(intent)
            e["source"].messages[item.message_id] = item.model_copy(update={"revision": 1})
            return result

        creator.recover = edited
        await e["pipe"].creation_commands.once()
        current, pending = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "admitted" and pending.dispatch_paused
        assert pending.state == "creating" and not await rows(db, Delivery)
        assert e["wire"].count(("POST", "/api/session")) == 1
        assert "activation" not in current.native_result
    finally:
        await close(e)


@pytest.mark.parametrize(
    "fault", ["missing", "wrong_intent", "invalid_fence", "missing_attempt", "missing_holder"]
)
async def test_used_root_recovery_requires_original_committed_send_attempt_before_get(db, fault):
    e = await environment(db, mode="lost-ack")
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        used_root(e, "running")
        await route(e, "!oz new resume", 202)
        async with db.sessions.begin() as session:
            saved = await session.get(Action, action.id)
            admission = dict(saved.admission)
            if fault == "missing":
                admission = {}
            elif fault == "wrong_intent":
                admission["intent_sha256"] = "0" * 64
            elif fault == "invalid_fence":
                admission["fencing"] = True
            elif fault == "missing_attempt":
                admission.pop("attempt_id")
            else:
                admission["holder"] = ""
            saved.admission = admission
            # True compares equal to the original fencing=1; force the faulty
            # JSON write instead of letting ORM equality discard this fixture.
            flag_modified(saved, "admission")
        if fault == "invalid_fence":
            assert (
                type((await e["pipe"].creation.journal.load(action.id))[0].admission["fencing"])
                is bool
            )
        before = len(e["wire"])
        await e["pipe"].creation_commands.once()
        current, pending = await e["pipe"].creation.journal.load(action.id)
        assert current.state == "ambiguous" and pending.dispatch_paused
        assert len(e["wire"]) == before and not await rows(db, Delivery)
    finally:
        await close(e)


@pytest.mark.parametrize("stage", ["lost-ack", "admitted"])
async def test_old_completed_recovery_resume_does_not_survive_consumer_fence_replacement(db, stage):
    from jt_oz_bridge.storage.durable import DurableStore
    from jt_oz_bridge.storage.fencing import ConsumerFence

    e = await environment(db, mode="lost-ack")
    try:
        _, _, action, _ = await reserve(e)
        await e["pipe"].creation_commands.once()
        if stage == "admitted":
            await e["pipe"].creation.journal.advance(action.id, e["current_factory"].creator)
        used_root(e, "running")
        await route(e, "!oz new resume", 202)
        old = e["pipe"]
        await old.scope.client.close()
        store = DurableStore(db)
        await store.release_lease(old.fence.holder, old.fence.fencing)
        token = await store.acquire_lease("new-recovery-fence", ttl=120)
        e["journal"].fence = ConsumerFence("new-recovery-fence", token)
        fresh, registry, factory, _ = await startup_pipeline(e)
        fresh.source.read = e["source"].read
        e.update(pipe=fresh, registry=registry, current_factory=factory)
        await fresh.creation_commands.recover()
        before = len(e["wire"])
        await fresh.creation_commands.once()
        current, pending = await fresh.creation.journal.load(action.id)
        assert current.state != "completed" and pending.dispatch_paused
        assert len(e["wire"]) == before and not await rows(db, Delivery)
        await route(e, "!oz new resume", 203)
        await fresh.creation_commands.once()
        assert (await fresh.creation.journal.load(action.id))[0].state == "completed"
        assert e["wire"].count(("POST", "/api/session")) == 1
    finally:
        await close(e)


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_http_zulip_queue_to_same_native_create_and_canonical_notice_with_bot_echo(
    db, locale
):
    from dataclasses import replace
    from urllib.parse import parse_qs

    from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader, ZulipSourceReader
    from jt_oz_bridge.i18n import save_locale
    from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
    from tests.integration.test_zulip_consumer import Server

    class Chat(Server):
        def __init__(self):
            super().__init__()
            self.bots = {9}
            self.posts = []

        def handle(self, request):
            path = request.url.path.removeprefix("/api/v1/")
            if path == "streams/10/members":
                return httpx.Response(200, json={"result": "success", "subscribers": [7, 8, 9]})
            if path == "messages" and request.method == "POST":
                data = parse_qs(request.content.decode())
                assert json.loads(data["to"][0]) == 10
                mid = 10000 + len(self.posts)
                event = self.event(data["content"][0], len(self.events), mid, 9)
                event["message"]["subject"] = data["topic"][0]
                self.messages[mid]["subject"] = data["topic"][0]
                self.posts.append(copy.deepcopy(self.messages[mid]))
                return httpx.Response(200, json={"result": "success", "id": mid})
            if path in {"messages", "users/me/10/topics"}:
                if path == "messages":
                    narrow = json.loads(request.url.params.get("narrow", "[]"))
                    topic = next(
                        (n["operand"] for n in narrow if n["operator"] == "topic"), "Original work"
                    )
                    data = {
                        "messages": sorted(
                            (m for m in self.messages.values() if m["subject"] == topic),
                            key=lambda m: m["id"],
                        )[-2:]
                    }
                else:
                    topics = {}
                    for m in self.messages.values():
                        topics[m["subject"]] = max(topics.get(m["subject"], 0), m["id"])
                    data = {
                        "topics": [{"name": name, "max_id": mid} for name, mid in topics.items()]
                    }
                return httpx.Response(200, json={"result": "success", **copy.deepcopy(data)})
            return super().handle(request)

    e = await environment(db)
    started = False
    try:
        pipe, chat = e["pipe"], Chat()
        pipe.bound_delivery.interval = pipe.discovery_delivery.interval = 0
        pipe.scope.client.client._transport = httpx.MockTransport(chat.handle)
        attestation = replace(
            pipe.scope.enrolled, verified_event_operations=EVENT_OPERATIONS | {"cleanup"}
        )
        pipe.scope.client.attestation = pipe.scope.enrolled = attestation
        pipe.scope.inspect = ZulipScopeReader.inspect.__get__(pipe.scope, ZulipScopeReader)
        pipe.source.read = ZulipSourceReader.read.__get__(pipe.source, ZulipSourceReader)
        await save_locale(db, "user:realm:7", locale, fence=pipe.fence)
        pipe.gateway.queue_id = await pipe.consumer.start()
        started = True
        chat.event("!oz new", 0, 200)
        await pipe.consumer.poll()
        await pipe.deliver_once()
        assert len(chat.posts) == 1
        token = re.search(r"!oz new ([A-Za-z0-9_-]{32})", unescape(chat.posts[0]["content"]))[1]
        # Echo was generated by the mock server, not submitted as another Human.
        chat.event("!oz new " + token + " HTTP new Root", len(chat.events), 201)
        await pipe.consumer.poll()
        actions = await rows(db, Action)
        assert len(actions) == 1 and actions[0].state == "queued"
        action, binding = await pipe.creation.journal.load(actions[0].id)
        _, e["live_intent"], _ = pipe.creation.journal.payload(action, binding)
        await pipe.creation_commands.once()
        assert (await pipe.creation.journal.load(action.id))[0].state == "completed"
        await pipe.deliver_once()
        assert len(chat.posts) == 2 and chat.posts[-1]["subject"] == "Original work"
        assert e["wire"].count(("POST", "/api/session")) == 1
        await pipe.consumer.poll()
        await pipe.creation_commands.once()
        assert len(await rows(db, Action)) == 1 and len(chat.posts) == 2
        current, active = await pipe.creation.journal.load(action.id)
        assert current.state == "completed" and active.state == "active"
        deliveries = await rows(db, Delivery)
        assert len(deliveries) == 2 and all(d.state == "delivered" for d in deliveries)
    finally:
        if started:
            await e["pipe"].consumer.close()
        await close(e)


@pytest.mark.parametrize("change", ["remove_reader", "add_authorized_reader"])
async def test_changed_current_audience_can_cancel_unsent_but_cannot_resume_old_selection(
    db, change
):
    e = await environment(db)
    try:
        _, _, action, _ = await reserve(e)
        if change == "remove_reader":
            e["audience"].users = frozenset({7})
        else:
            async with db.sessions.begin() as session:
                session.add(
                    Grant(
                        realm_id="realm",
                        user_id=42,
                        project_id=e["anchor"].reference.project_id,
                        role="operator",
                    )
                )
            e["audience"].users = frozenset({7, 8, 42})
        await route(e, "!oz new resume", 202)
        await e["pipe"].creation_commands.once()
        assert not any(m == "POST" for m, _ in e["wire"])
        _, status = await route(e, "!oz new status", 203)
        assert status.state == "reply"
        _, cancelled = await route(e, "!oz new cancel", 204)
        assert "Cancelled" in cancelled.text
        assert await e["pipe"].creation_commands.cancelled(action.id)
    finally:
        await close(e)


@pytest.mark.parametrize("fault", ["none", "actor", "topic", "project_change"])
async def test_menu_pagination_tokens_bind_operator_audience_topic_and_exact_project_configuration(
    db, fault
):
    from types import MappingProxyType

    from jt_oz_bridge.storage.control_models import EnrolledProject

    e = await environment(db)
    try:
        journal = e["pipe"].creation.journal
        base = next(iter(journal.projects.values()))
        projects = {}
        # Synthetic trusted enrollment inputs exercise menu/token policy only;
        # no activation factories or Native resources for extra projects are claimed.
        async with db.sessions.begin() as session:
            for index in range(21):
                key = f"pagination-project-{index:02}"
                scope = base.template.scope.model_copy(
                    update={"project_id": key, "canonical_directory": f"/synthetic/page/{index}"}
                )
                project = base.model_copy(
                    update={"template": base.template.model_copy(update={"scope": scope})}
                )
                projects[key] = project
                session.add(
                    EnrolledProject(
                        id=key,
                        realm_id="realm",
                        backend_id=scope.backend_id,
                        canonical_directory=scope.canonical_directory,
                        enabled=True,
                    )
                )
                for user in (7, 8):
                    session.add(
                        Grant(realm_id="realm", user_id=user, project_id=key, role="operator")
                    )
        journal.projects = MappingProxyType(projects)
        first = message("!oz new", 300)
        e["source"].messages[300] = first
        menu = await e["pipe"].creation_commands.menu(first, "en")
        assert (
            len(menu.projects) == 10
            and len(re.findall(r"!oz new [A-Za-z0-9_-]{32}", menu.text)) == 10
        )
        token = re.search(r"!oz new page ([A-Za-z0-9_-]{32})", menu.text)[1]
        second = message(
            "!oz new page " + token,
            301,
            author_id=8 if fault == "actor" else 7,
            topic="Different topic" if fault == "topic" else "Original work",
        )
        e["source"].messages[301] = second
        if fault == "project_change":
            projects.pop(next(iter(projects)))
            journal.projects = MappingProxyType(projects)
        if fault != "none":
            from jt_oz_bridge.security.policy import AccessDenied

            with pytest.raises((Conflict, AccessDenied)):
                await e["pipe"].creation_commands.menu(second, "en", token)
        else:
            page2 = await e["pipe"].creation_commands.menu(second, "en", token)
            assert len(page2.projects) == 10 and not set(menu.projects) & set(page2.projects)
            last = re.search(r"!oz new page ([A-Za-z0-9_-]{32})", page2.text)[1]
            third = message("!oz new page " + last, 302)
            e["source"].messages[302] = third
            page3 = await e["pipe"].creation_commands.menu(third, "en", last)
            assert len(page3.projects) == 1 and "!oz new page " not in page3.text
        assert not any(m == "POST" for m, _ in e["wire"])
        assert not await rows(db, Action)
    finally:
        await close(e)
