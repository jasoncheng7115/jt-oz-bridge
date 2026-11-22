"""Atomic journal/index/fencing, including actual harmless Bot event shapes."""

import copy
import json
import logging
from pathlib import Path

import pytest
from sqlalchemy import func, select, update

from jt_oz_bridge.services.zulip_events import ZulipEventJournal
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import InputEvent, WorkerLease
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex
from tests.support import bound

ROOT = Path("tests/fixtures/installed/zulip-12.3")
EVENTS = json.loads((ROOT / "bot-message-lifecycle.json").read_text())["events"]


async def journal(db, *, realm="2", channel=4, holder="events"):
    f = await DurableStore(db).acquire_lease(holder)
    assert f is not None
    j = ZulipEventJournal(
        db,
        ConsumerFence(holder, f),
        realm_id=realm,
        bot_user_id=11,
        url="https://chat.example.invalid",
        channel_ids=frozenset({channel}),
    )
    await j.enroll("native-q1", -1)
    return j


async def count(db, model):
    async with db.sessions() as s:
        return await s.scalar(select(func.count()).select_from(model))


async def row(db, rid):
    async with db.sessions() as s:
        return await s.get(InputEvent, rid)


def event(n, **changes):
    result = copy.deepcopy(EVENTS[n])
    result.update(changes)
    return result


async def test_actual_bot_create_edit_delete_index_checkpoint_and_encrypted_payload(db):
    j = await journal(db)
    ids = await j.capture("native-q1", [event(0)])
    assert await j.expected_channel("2", 20) == 4
    assert await j.cursor("native-q1") == 0
    edit = (await j.capture("native-q1", [event(1)]))[0]
    assert await j.expected_channel("2", 20) == 4
    assert "content" not in (await row(db, edit)).payload["wire"]
    await j.capture("native-q1", [event(2)])
    assert await j.expected_channel("2", 20) is None
    assert await j.cursor("native-q1") == 2 and await count(db, InputEvent) == 3
    own = await row(db, ids[0])
    assert own.payload["wire"]["message"]["sender_id"] == 11
    for p in Path(db.engine.url.database).parent.glob("test.db*"):
        assert EVENTS[0]["message"]["content"].encode() not in p.read_bytes()


async def test_replay_deduplicates_and_changed_native_id_never_reapplies_or_advances(db):
    j = await journal(db)
    ids = await j.capture("native-q1", [event(0)])
    assert await j.capture("native-q1", [event(0)]) == ids
    changed = event(0)
    changed["message"]["content"] = "changed source"
    with pytest.raises(Conflict, match="identity_reused"):
        await j.capture("native-q1", [changed])
    assert await count(db, InputEvent) == 1 and await j.cursor("native-q1") == 0


async def test_entire_batch_and_index_rollback_on_later_malformed_event(db):
    j = await journal(db)
    with pytest.raises(ValueError):
        await j.capture("native-q1", [event(0), {"id": 1, "type": "message", "message": {}}])
    assert await j.cursor("native-q1") == -1
    assert await count(db, InputEvent) == 0 and await count(db, ZulipMessageIndex) == 0


async def test_foreign_and_unknown_source_payloads_are_discarded_before_retention(db):
    j = await journal(db)
    e = event(0)
    e["message"]["stream_id"] = 99
    e["message"]["content"] = "FOREIGN_PRIVATE_CONTENT"
    ids = await j.capture("native-q1", [e, event(1), event(2)])
    for rid in ids:
        r = await row(db, rid)
        assert r.payload["wire"]["type"] == "ignored"
        assert r.payload["raw_sha256"] is None
        assert "FOREIGN_PRIVATE_CONTENT" not in json.dumps(r.payload)
    assert await count(db, ZulipMessageIndex) == 0
    assert await j.expected_channel("other", 20) is None


async def test_unknown_message_has_no_trusted_read_scope_and_dm_is_not_enrolled(db):
    j = await journal(db)
    e = event(0)
    e["message"]["type"] = "private"
    await j.capture("native-q1", [e])
    assert await j.expected_channel("2", 20) is None
    assert await j.expected_channel("2", 999) is None


@pytest.mark.parametrize(
    "bad",
    [
        [{"id": True, "type": "heartbeat"}],
        [{"id": -1, "type": "heartbeat"}],
        [{"id": 1, "type": "heartbeat"}, {"id": 0, "type": "heartbeat"}],
        [{"id": 0, "type": "heartbeat"}, {"id": 0, "type": "heartbeat"}],
        [{"id": 0, "type": "update_message", "message_ids": [True]}],
        [{"id": 0, "type": "update_message", "message_ids": [1, 1]}],
        [{"id": 0, "type": "update_message", "message_ids": []}],
        [
            {
                "id": 0,
                "type": "message",
                "message": {
                    "type": "stream",
                    "stream_id": 4,
                    "id": 1,
                    "sender_id": 8,
                    "subject": "x",
                    "content": "x",
                    "content_type": "text/html",
                },
            }
        ],
    ],
)
async def test_invalid_native_batch_numbers_order_and_raw_body_fail_without_commit(db, bad):
    j = await journal(db)
    with pytest.raises(ValueError):
        await j.capture("native-q1", bad)
    assert await j.cursor("native-q1") == -1 and await count(db, InputEvent) == 0


async def test_registration_retries_never_rewind_committed_cursor_and_rotation_holds_bindings(db):
    bindings, b, control, _ = await bound(db)
    j = await journal(db, realm="realm", channel=10)
    await j.capture("native-q1", [{"id": 0, "type": "heartbeat"}])
    await j.enroll("native-q1", -1)
    assert await j.cursor("native-q1") == 0
    assert await j.enroll("native-q2", 17) == 2
    async with db.sessions() as s:
        latest = await s.get(Binding, b.id)
    assert latest.dispatch_paused and latest.session_id == b.session_id
    assert await j.cursor("native-q2") == 17
    with pytest.raises(Conflict):
        await j.capture("native-q1", [{"id": 1, "type": "heartbeat"}])


async def test_deleted_and_moved_originals_do_not_resurrect_or_rebind(db):
    bindings, b, control, _ = await bound(db)
    j = await journal(db, realm="realm", channel=10)
    e = event(0)
    e["message"].update(stream_id=10, subject="Original work")
    await j.capture("native-q1", [e])
    move = {
        "id": 1,
        "type": "update_message",
        "message_ids": [20],
        "stream_id": 10,
        "new_stream_id": 99,
        "orig_subject": "Original work",
        "subject": "Moved",
    }
    await j.capture("native-q1", [move])
    assert await j.expected_channel("realm", 20) is None
    late = copy.deepcopy(e)
    late["id"] = 2
    await j.capture("native-q1", [late])
    assert await j.expected_channel("realm", 20) is None
    async with db.sessions() as s:
        latest = await s.get(Binding, b.id)
    assert latest.dispatch_paused and latest.channel_id == 10 and latest.topic == "Original work"


async def test_content_edit_does_not_pause_an_unrelated_binding_but_topic_move_does(db):
    _, b, _, _ = await bound(db)
    j = await journal(db, realm="realm", channel=10)
    e = event(0)
    e["message"].update(stream_id=10, subject="Original work")
    await j.capture("native-q1", [e, event(1)])
    async with db.sessions() as s:
        assert not (await s.get(Binding, b.id)).dispatch_paused
    await j.capture(
        "native-q1",
        [
            {
                "id": 2,
                "type": "update_message",
                "message_ids": [20],
                "orig_subject": "Original work",
                "subject": "Moved",
            }
        ],
    )
    async with db.sessions() as s:
        assert (await s.get(Binding, b.id)).dispatch_paused


async def paused(db, binding_id):
    async with db.sessions() as s:
        return (await s.get(Binding, binding_id)).dispatch_paused


@pytest.mark.parametrize(
    "change",
    [
        {"type": "realm_user", "op": "update", "person": {"user_id": 8, "full_name": "New"}},
        {"type": "realm_user", "op": "update", "person": {"user_id": 9, "avatar_url": "x"}},
        {"type": "realm_user", "op": "add", "person": {"user_id": 30, "full_name": "Newcomer"}},
        {"type": "subscription", "op": "peer_add", "stream_ids": [99], "user_ids": [8]},
        {"type": "subscription", "op": "peer_remove", "stream_ids": [98, 99], "user_ids": [9]},
        {"type": "subscription", "op": "update", "stream_id": 10, "property": "color"},
        {"type": "subscription", "op": "add", "subscriptions": [{"stream_id": 99}]},
        {"type": "stream", "op": "update", "stream_id": 99, "property": "description"},
        {"type": "stream", "op": "create", "streams": [{"stream_id": 99}]},
        {"type": "realm", "op": "update", "property": "name", "value": "x"},
        {"type": "realm", "op": "update_dict", "property": "icon", "data": {}},
    ],
)
async def test_changes_elsewhere_or_display_only_do_not_pause_topics(db, caplog, change):
    caplog.set_level(logging.WARNING, logger="jt_oz_bridge.services.zulip_events")
    _, b, _, _ = await bound(db)
    j = await journal(db, realm="realm", channel=10)
    caplog.clear()
    rid = (await j.capture("native-q1", [{"id": 0, **change}]))[0]
    assert (await row(db, rid)).payload["wire"]["type"] == "ignored"
    assert not await paused(db, b.id)
    assert "zulip_change_paused" not in caplog.text


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (
            {"type": "subscription", "op": "peer_remove", "stream_ids": [99, 10], "user_ids": [9]},
            "subscription:peer_remove scope=channels",
        ),
        (
            {"type": "subscription", "op": "remove", "subscriptions": [{"stream_id": 10}]},
            "subscription:remove scope=channels",
        ),
        (
            {"type": "stream", "op": "update", "stream_id": 10, "property": "invite_only"},
            "stream:update scope=channels",
        ),
        (
            {"type": "realm_user", "op": "update", "person": {"user_id": 9, "role": 400}},
            "realm_user:update scope=all",
        ),
        (
            {"type": "realm_user", "op": "update", "person": {"user_id": 9, "new_email": "x"}},
            "realm_user:update scope=all",
        ),
        ({"type": "realm_user", "op": "remove", "person": {"user_id": 9}}, "realm_user:remove"),
        ({"type": "realm", "op": "update_dict", "property": "default"}, "realm:update_dict"),
        ({"type": "realm", "op": "deactivated"}, "realm:deactivated scope=all"),
        # A shape we cannot read pauses everything, as before.
        ({"type": "stream", "op": "delete", "streams": [{"name": "x"}]}, "stream:delete scope=all"),
        ({"type": "subscription", "op": "surprise", "stream_ids": "4"}, "subscription:other"),
        ({"type": "realm", "op": ["update"], "property": ["name"]}, "realm:other scope=all"),
    ],
)
async def test_changes_to_our_channels_or_people_pause_and_say_why(db, caplog, change, reason):
    caplog.set_level(logging.WARNING, logger="jt_oz_bridge.services.zulip_events")
    _, b, _, _ = await bound(db)
    j = await journal(db, realm="realm", channel=10)
    caplog.clear()
    rid = (await j.capture("native-q1", [{"id": 0, **change}]))[0]
    wire = (await row(db, rid)).payload["wire"]
    assert wire["type"] == change["type"] and "person" not in wire
    assert await paused(db, b.id)
    assert f"zulip_change_paused reason={reason}" in caplog.text
    assert "bindings=1" in caplog.text


async def test_a_receipt_saved_before_channel_lists_still_pauses_its_one_channel(db):
    _, b, _, _ = await bound(db)
    j = await journal(db, realm="realm", channel=10)
    async with db.sessions.begin() as s:
        await j.apply_index(s, {"id": 0, "type": "stream", "channel_id": 99}, "r")
    assert not await paused(db, b.id)
    async with db.sessions.begin() as s:
        await j.apply_index(s, {"id": 1, "type": "stream", "channel_id": 10}, "r")
    assert await paused(db, b.id)


async def test_claim_is_exclusive_copies_wire_and_replays_cannot_issue_another_claim(db):
    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    c = await j.claim(rid)
    assert c and not c.recovered
    c.wire["message"]["content"] = "mutated local copy"
    assert (await row(db, rid)).payload["wire"]["message"]["content"] != c.wire["message"][
        "content"
    ]
    assert await j.claim(rid) is None
    await j.finish(rid, state="ignored")
    assert await j.claim(rid) is None
    assert await j.capture("native-q1", [event(0)]) == (rid,)


async def test_new_fenced_worker_recovers_processing_once_and_old_worker_cannot_finish(db):
    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    await j.claim(rid)
    async with db.sessions.begin() as s:
        await s.execute(update(WorkerLease).values(expires_at=0))
    f = await DurableStore(db).acquire_lease("new")
    assert f > j.fence.fencing
    n = ZulipEventJournal(
        db,
        ConsumerFence("new", f),
        realm_id="2",
        bot_user_id=11,
        url=j.url,
        channel_ids=frozenset({4}),
    )
    c = await n.claim(rid)
    assert c and c.recovered
    assert await n.claim(rid) is None
    with pytest.raises(Conflict):
        await j.finish(rid)
    with pytest.raises(Conflict):
        await n.enroll("native-q1", -1)
    await n.finish(rid)
    assert (await row(db, rid)).state == "zulip_done"


async def test_expired_queue_cannot_be_polled_or_reused(db):
    j = await journal(db)
    await j.expire("native-q1")
    with pytest.raises(Conflict):
        await j.cursor("native-q1")
    with pytest.raises(Conflict):
        await j.enroll("native-q1", -1)
    assert await j.enroll("native-q2", -1) == 2


async def test_receipt_integrity_and_scope_are_checked_before_claim(db):
    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    async with db.sessions.begin() as s:
        await s.execute(
            update(InputEvent).where(InputEvent.id == rid).values(payload_hash="0" * 64)
        )
    with pytest.raises(Conflict):
        await j.claim(rid)


def test_actual_benign_wire_fixture_manifest_is_not_a_human_or_phone_certificate():
    import hashlib

    m = json.loads((ROOT / "manifest.json").read_text())
    for c in m["captures"]:
        assert hashlib.sha256((ROOT / c["path"]).read_bytes()).hexdigest() == c["sha256"]
    assert not m["original_human_messages_captured"] and not m["mobile_acceptance"]


async def test_unprocessed_old_queue_receipt_is_recovered_even_with_same_lease(db):
    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    await j.enroll("native-q2", -1)
    assert (await j.claim(rid)).recovered


async def test_deferred_route_result_survives_fenced_recovery_as_encrypted_output_only(db):
    from sqlalchemy import text

    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    assert await j.claim(rid)
    routed = RoutedInput("reply", text="PRIVATE_CACHED_REPLY", delivery_key="stable-output-key")
    await j.record_route(rid, routed)
    await j.defer(rid, 1, recovered=False)
    assert await j.waiting(rid) and await j.claim(rid) is None
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
        await session.execute(update(ZulipReceiptRetry).values(retry_at=0))
    f = await DurableStore(db).acquire_lease("recovered-reply")
    n = ZulipEventJournal(
        db,
        ConsumerFence("recovered-reply", f),
        realm_id="2",
        bot_user_id=11,
        url=j.url,
        channel_ids=frozenset({4}),
    )
    claim = await n.claim(rid)
    assert claim.recovered and claim.routed == routed
    assert await count(db, ZulipReceiptRetry) == 0
    with pytest.raises(Conflict):
        await j.finish(rid)
    await n.finish(rid, routed=routed)
    async with db.engine.connect() as connection:
        raw = await connection.scalar(
            text("SELECT payload FROM input_events WHERE id=:id"), {"id": rid}
        )
        assert isinstance(raw, bytes) and b"PRIVATE_CACHED_REPLY" not in raw
    assert (await row(db, rid)).state == "zulip_done"


async def test_deferred_source_resume_does_not_misclassify_a_new_fenced_owner_as_fresh_intent(db):
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    await j.claim(rid)
    await j.defer(rid, 1, recovered=False)
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=0))
        await session.execute(update(ZulipReceiptRetry).values(retry_at=0))
    f = await DurableStore(db).acquire_lease("new-source-owner")
    n = ZulipEventJournal(
        db,
        ConsumerFence("new-source-owner", f),
        realm_id="2",
        bot_user_id=11,
        url=j.url,
        channel_ids=frozenset({4}),
    )
    claim = await n.claim(rid)
    assert claim.recovered and claim.routed is None


async def test_recorded_route_is_immutable_and_a_corrupt_retry_cannot_silently_stall(db):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.storage.zulip_models import ZulipReceiptRetry

    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    await j.claim(rid)
    await j.record_route(rid, RoutedInput("reply", text="original"))
    with pytest.raises(Conflict, match="saved_route_changed"):
        await j.record_route(rid, RoutedInput("reply", text="changed"))
    await j.defer(rid, 1, recovered=False)
    async with db.sessions.begin() as session:
        await session.execute(update(ZulipReceiptRetry).values(retry_at=float("inf")))
    with pytest.raises(Conflict, match="retry_schedule_changed"):
        await j.waiting(rid)


@pytest.mark.parametrize("old_format", [False, True])
def test_saved_route_accepts_only_the_one_missing_new_default(old_format):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.zulip_events import ROUTED, saved_route

    routed = RoutedInput(
        "reply", text="original encrypted output", delivery_key="old-stable-output"
    )
    raw = ROUTED.dump_python(routed, mode="json")
    if old_format:
        del raw["queued_batch_id"]
    original = copy.deepcopy(raw)
    assert saved_route({"routed_reply": raw}) == routed
    assert raw == original  # Reading does not rewrite the encrypted legacy representation.


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "other-missing",
        "coerced-revision",
        "invalid-locale",
        "bad-queue-id",
        "empty-queue-id",
        "uppercase-queue-id",
        "queue-id-object",
    ],
)
def test_legacy_route_normalization_does_not_accept_other_schema_changes(fault):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.zulip_events import ROUTED, saved_route

    raw = ROUTED.dump_python(RoutedInput("reply", text="exact-original"), mode="json")
    raw.pop("queued_batch_id")
    if fault == "unknown":
        raw["unknown-authority"] = True
    elif fault == "other-missing":
        raw.pop("action_id")
    elif fault == "coerced-revision":
        raw["binding_revision"] = "1"
    elif fault == "invalid-locale":
        raw["locale"] = "zh-tw"
    elif fault == "bad-queue-id":
        raw["queued_batch_id"] = "not-a-batch-id"
    elif fault == "empty-queue-id":
        raw["queued_batch_id"] = ""
    elif fault == "uppercase-queue-id":
        raw["queued_batch_id"] = "A5380957-6BA2-47F2-83AB-771EB08A2146"
    else:
        raw["queued_batch_id"] = {"id": "a5380957-6ba2-47f2-83ab-771eb08a2146"}
    with pytest.raises((Conflict, ValueError)):
        saved_route({"routed_reply": raw})


async def test_old_persisted_route_recovers_output_only_without_reroute_queue_or_repost(db):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.adapters.zulip.scope import ZulipSourceReader
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.command_receipts import CommandInbox
    from jt_oz_bridge.services.router import CommandRouter
    from jt_oz_bridge.services.zulip_consumer import ZulipCommandConsumer
    from jt_oz_bridge.services.zulip_events import ROUTED
    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.durable import digest
    from jt_oz_bridge.storage.models import Action, Delivery
    from tests.integration.test_zulip_consumer import setup

    consumer, server, binding, native = await setup(db)
    try:
        wire = server.event("!oz help", eid=0, mid=101)
        rid = (await consumer.journal.capture("native-queue", [wire]))[0]
        assert await consumer.journal.claim(rid)
        routed = RoutedInput(
            "reply",
            binding.id,
            binding.revision,
            text="already-produced-private-reply",
            delivery_key="original-stable-output",
        )
        await consumer.journal.record_route(rid, routed)
        old_route = ROUTED.dump_python(routed, mode="json")
        old_route.pop("queued_batch_id")
        async with db.sessions.begin() as session:
            current = await session.get(InputEvent, rid)
            payload = {**current.payload, "routed_reply": old_route}
            current.payload, current.payload_hash = payload, digest(payload)
            await session.execute(update(WorkerLease).values(expires_at=0))
        fence = await DurableStore(db).acquire_lease("legacy-output-recovery")
        recovered = ZulipEventJournal(
            db,
            ConsumerFence("legacy-output-recovery", fence),
            realm_id="realm",
            bot_user_id=11,
            url=consumer.journal.url,
            channel_ids=frozenset({10}),
        )
        reader = ZulipSourceReader(consumer.scope, recovered.expected_channel)
        router = CommandRouter(
            consumer.router.bindings, reader, CommandInbox(db, "legacy-output-recovery", fence)
        )
        router.route = AsyncMock(
            side_effect=AssertionError("must not reroute an old produced reply")
        )
        router.route_closed_menu_event = AsyncMock(
            side_effect=AssertionError("must not admit recovered wire")
        )
        publish = AsyncMock(return_value=None)  # Output-only hook, not an outbox or POST.
        restored = ZulipCommandConsumer(consumer.scope, reader, recovered, router, publish=publish)
        claims = []
        original_claim = recovered.claim

        async def observed_claim(identity):
            claim = await original_claim(identity)
            claims.append(claim)
            return claim

        recovered.claim = observed_claim
        native_before = list(native.calls)
        assert await restored.process_receipt(rid) == "reply"
        assert claims[0].recovered and claims[0].routed == routed
        router.route.assert_not_awaited()
        router.route_closed_menu_event.assert_not_awaited()
        publish.assert_awaited_once_with(routed)
        assert (await row(db, rid)).payload["routed_reply"] == old_route
        assert (await row(db, rid)).state == "zulip_done"
        assert await restored.process_receipt(rid) == "already_claimed_or_settled"
        assert publish.await_count == 1 and native.calls == native_before
        assert (
            await count(db, Delivery)
            == await count(db, Action)
            == await count(db, ControlToken)
            == 0
        )
        assert not any(method == "POST" and path == "messages" for method, path in server.calls)
    finally:
        await consumer.scope.client.close()


async def test_legacy_saved_route_record_and_finish_keep_strict_immutability(db):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.zulip_events import ROUTED
    from jt_oz_bridge.storage.durable import digest

    j = await journal(db)
    rid = (await j.capture("native-q1", [event(0)]))[0]
    await j.claim(rid)
    routed = RoutedInput("reply", text="one immutable legacy reply", delivery_key="legacy")
    await j.record_route(rid, routed)
    legacy = ROUTED.dump_python(routed, mode="json")
    legacy.pop("queued_batch_id")
    async with db.sessions.begin() as session:
        r = await session.get(InputEvent, rid)
        payload = {**r.payload, "routed_reply": legacy}
        r.payload, r.payload_hash = payload, digest(payload)
    await j.record_route(rid, routed)
    assert (await row(db, rid)).payload["routed_reply"] == legacy
    with pytest.raises(Conflict):
        await j.record_route(rid, RoutedInput("reply", text="replacement"))
    await j.finish(rid, routed=routed)
    assert (await row(db, rid)).payload["routed_reply"] == legacy


async def test_five_synthetic_held_legacy_receipts_remain_unchanged_and_unclaimable(db):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.zulip_events import ROUTED
    from jt_oz_bridge.storage.durable import digest

    j = await journal(db)
    ids = await j.capture("native-q1", [{"id": index, "type": "heartbeat"} for index in range(5)])
    legacy = ROUTED.dump_python(RoutedInput("held", text="synthetic held output"), mode="json")
    legacy.pop("queued_batch_id")
    for rid in ids:
        await j.claim(rid)
        await j.finish(rid, state="held")
    async with db.sessions.begin() as session:
        for rid in ids:
            r = await session.get(InputEvent, rid)
            payload = {**r.payload, "routed_reply": legacy}
            r.payload, r.payload_hash = payload, digest(payload)
    before = [(await row(db, rid)).payload_hash for rid in ids]
    claims = [await j.claim(rid) for rid in ids]
    assert all(claim is None for claim in claims)
    assert [(await row(db, rid)).payload_hash for rid in ids] == before
    states = [(await row(db, rid)).state for rid in ids]
    assert states == ["zulip_held"] * 5
