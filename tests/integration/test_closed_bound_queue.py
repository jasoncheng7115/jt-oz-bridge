"""Synthetic Human events through the real service pipeline; no Native submit.

Virtual time advances only Bot budget/identity scheduling, never Source proofs,
Native proofs or the consumer lease. Private HTTP mocks are not mobile evidence.
"""

import json
import os
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget, request_lane
from jt_oz_bridge.services import runtime_enrollment as identity_module
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, Grant, InputEvent
from tests.integration.test_consumer_runtime import rows, setup


async def live_identity(db, monkeypatch, *, initial_prompts=1, background=0):
    pipeline, server, native, _, binding, _ = await setup(db)
    await pipeline.consumer.start()
    for n in range(initial_prompts):
        mid = max(server.messages) + 1
        server.next_mid = mid + 1
        server.input(f"synthetic existing prompt {n}", mid, topic=binding.topic)
        # An accepted prompt queues silently: typing and the reply show its progress.
        assert (await pipeline.consumer.poll())[-1] == "ignore"
        await pipeline.deliver_once()
    client = pipeline.scope.client
    original = client.client._transport
    clock, calls = [100.0], []
    budget = ZulipRequestBudget(monotonic=lambda: clock[0])
    client.budget = budget

    def peer(request):
        route = request.url.path.removeprefix("/api/v1/")
        if route == "users/me":
            data = {
                "user_id": 11,
                "is_bot": True,
                "is_active": True,
                "bot_owner_id": 7,
                "role": 400,
            }
        elif route == "server_settings":
            data = {"realm_url": client.url, "zulip_version": "12.3", "zulip_feature_level": 500}
        else:
            return original.handler(request)
        return httpx.Response(200, json={"result": "success", **data})

    async def elapsed(request):
        clock[0] += 0.15
        calls.append((request.method, request.url.path))

    client.client._transport = httpx.MockTransport(peer)
    client.client.event_hooks["request"].append(elapsed)
    monkeypatch.setattr(identity_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    client.verify_identity = identity_module.ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11,
            bot_owner_id=7,
            url=client.url,
            zulip_version="12.3",
            feature_level=500,
        ),
    )
    for _ in range(background):
        await pipeline.scope.inspect("realm", 10, binding.topic)
    assert len(calls) == background * 16
    pipeline._test_http_calls = calls
    pipeline._test_phase_costs = []
    return pipeline, server, native, binding, budget, clock, calls


async def send(pipeline, server, binding, text):
    mid = max(server.messages) + 1
    server.next_mid = mid + 1
    server.input(text, mid, topic=binding.topic)
    before = len(pipeline._test_http_calls)
    with request_lane("control"):
        outcome = await pipeline.consumer.poll()
    after_route = len(pipeline._test_http_calls)
    await pipeline.deliver_once()
    pipeline._test_phase_costs.append(
        {
            "source_and_atomic_ack": after_route - before,
            "independent_delivery": len(pipeline._test_http_calls) - after_route,
        }
    )
    return mid, outcome


def report(name, p, calls, clock, budget):
    if os.environ.get("PROBE_OUT"):
        data = {
            "calls": len(calls),
            "phase_costs": p._test_phase_costs,
            "http_elapsed": clock[0] - 100,
            "request_counts": dict(Counter(method + " " + path for method, path in calls)),
            "deferrals": budget.deferred,
            "budget": {"limit": budget.limit, "window": budget.window, "reserved": budget.reserved},
            "native_submit": False,
            "synthetic": True,
        }
        with (Path(os.environ["PROBE_OUT"]) / (name + ".json")).open("x") as output:
            json.dump(data, output, indent=2)


@pytest.mark.parametrize("background", [0, 5])
async def test_cancel_commits_complete_ack_within_original_remaining_budget(
    db, monkeypatch, background
):
    p, server, native, b, budget, clock, calls = await live_identity(
        db, monkeypatch, background=background
    )
    action = (await rows(db, Action))[0]
    before = len(server.posts)
    try:
        mid, outcome = await send(p, server, b, "!oz cancel " + action.id)
        assert outcome[-1] == "reply"
        assert (await rows(db, Action))[0].state == "cancelled"
        receipt = next(r for r in await rows(db, CommandReceipt) if r.message_id == mid)
        assert receipt.state == "completed"
        assert len(server.posts) == before + 1
        assert all(d.state == "delivered" for d in await rows(db, Delivery))
        assert len(calls) - background * 16 <= 64
        assert budget.deferred == 0 and clock[0] < 160
        assert not native.submitted
        report("cancel-background-" + str(background), p, calls, clock, budget)
    finally:
        await p.scope.client.close()


async def test_two_cancels_resume_prompt_and_all_acks_share_original_window(db, monkeypatch):
    p, server, native, b, budget, clock, calls = await live_identity(
        db, monkeypatch, initial_prompts=2
    )
    actions = await rows(db, Action)
    errors = []
    original_route = p.router.route_closed_menu_event

    async def record_error(*args, **kwargs):
        try:
            return await original_route(*args, **kwargs)
        except BaseException as error:
            errors.append(repr(error))
            raise

    monkeypatch.setattr(p.router, "route_closed_menu_event", record_error)
    async with db.sessions.begin() as s:
        await s.execute(
            update(Binding)
            .where(Binding.id == b.id)
            .values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
        )
    try:
        for text in [
            "!oz cancel " + actions[0].id,
            "!oz cancel " + actions[1].id,
            "!oz queue resume",
            "new synthetic prompt",
        ]:
            _, outcome = await send(p, server, b, text)
            expected = "ignore" if text == "new synthetic prompt" else "reply"
            assert outcome[-1] == expected, (text, errors)
        saved = await rows(db, Action)
        assert [a.state for a in saved].count("cancelled") == 2
        assert [a.state for a in saved].count("queued") == 1
        async with db.sessions() as s:
            assert not (await s.get(Binding, b.id)).dispatch_paused
        assert len(calls) <= 180 and budget.deferred == 0 and clock[0] < 160
        assert len(server.posts) == 3  # The three controls ack; prompts queue silently.
        assert all(d.state == "delivered" for d in await rows(db, Delivery))
        assert not native.submitted
        report("four-controls", p, calls, clock, budget)
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize("change", ["source", "private", "actor", "client", "transport"])
async def test_final_source_or_issuer_change_cannot_mutate_or_create_ack(db, monkeypatch, change):
    p, server, native, b, _, _, _ = await live_identity(db, monkeypatch)
    original = p.scope.observe_sources
    action = (await rows(db, Action))[0]
    before_posts, before_deliveries = len(server.posts), len(await rows(db, Delivery))
    original_transport = p.scope.client.client._transport

    async def observe(reader, sources, *, read_only):
        async def callback(audience):
            value = await read_only(audience)
            if change == "source":
                server.messages[sources[0].message_id]["content"] += " edited"
            elif change == "private":
                server.private = False
            elif change == "actor":
                server.bots.add(7)
            elif change == "client":
                import copy

                p.scope.client = copy.copy(p.scope.client)
            else:
                p.scope.client.client._transport = httpx.MockTransport(server.handle)
            return value

        return await original(reader, sources, read_only=callback)

    monkeypatch.setattr(p.scope, "observe_sources", observe)
    try:
        await send(p, server, b, "!oz cancel " + action.id)
        assert (await rows(db, Action))[0].state == "queued"
        assert len(server.posts) == before_posts
        assert len(await rows(db, Delivery)) == before_deliveries
        assert not await rows(db, CommandReceipt)
        assert not native.submitted
    finally:
        p.scope.client.client._transport = original_transport
        await p.scope.client.close()


@pytest.mark.parametrize("failure", ["grant", "ack", "cancel"])
async def test_post_queue_failure_rolls_back_effect_and_whole_ack(db, monkeypatch, failure):
    p, server, native, b, _, _, _ = await live_identity(db, monkeypatch)
    action = (await rows(db, Action))[0]
    original = p.bound_outbox.queue_batch_in_session
    before_posts, before_deliveries = len(server.posts), len(await rows(db, Delivery))

    async def changed(session, *args, **kwargs):
        value = await original(session, *args, **kwargs)
        if failure == "grant":
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        elif failure == "ack":
            raise ValueError("synthetic_ack_commit_failure")
        else:
            import asyncio

            raise asyncio.CancelledError
        return value

    monkeypatch.setattr(p.bound_outbox, "queue_batch_in_session", changed)
    try:
        if failure == "cancel":
            import asyncio

            with pytest.raises(asyncio.CancelledError):
                await send(p, server, b, "!oz cancel " + action.id)
        else:
            await send(p, server, b, "!oz cancel " + action.id)
        assert (await rows(db, Action))[0].state == "queued"
        assert len(server.posts) == before_posts
        assert len(await rows(db, Delivery)) == before_deliveries
        receipts = await rows(db, CommandReceipt)
        assert len(receipts) == 1 and receipts[0].state == "ambiguous"
        assert not native.submitted
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize("component", ["reader", "queue", "outbox", "audience"])
async def test_composition_rejects_same_values_from_another_original_runtime(db, component):
    import copy

    from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue

    p, _, _, _, _, _ = await setup(db)
    reader, queue, outbox = p.source, p.router.queue, p.bound_outbox
    if component == "reader":
        reader = copy.copy(reader)
        reader.scope = copy.copy(reader.scope)
    elif component == "queue":
        queue = copy.copy(queue)
        queue.bindings = copy.copy(p.bindings)
    elif component == "outbox":
        outbox = copy.copy(outbox)
        outbox.bindings = copy.copy(p.bindings)
    else:
        p.bindings.audience = copy.copy(p.scope)
    try:
        with pytest.raises(ValueError, match="original_runtime_composition"):
            ClosedBoundQueue(
                p.bindings,
                reader,
                p.inbox,
                queue,
                outbox,
                message_limit=10000,
                topic_limit=60,
                continuity=None,
                journal=p.journal,
            )
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize(
    "field",
    ["capture_fencing", "processing_fencing", "defer_recovered", "recovery_run_id", "historical"],
)
async def test_actual_capture_provenance_cannot_be_replaced_by_a_fresh_dto(db, monkeypatch, field):
    import copy

    from jt_oz_bridge.storage.durable import digest
    from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex

    p, server, native, b, _, _, _ = await live_identity(db, monkeypatch)
    action = (await rows(db, Action))[0]
    original = p.scope.observe_sources
    before = len(server.posts)

    async def observe(reader, sources, *, read_only):
        async def changed(audience):
            result = await read_only(audience)
            async with db.sessions.begin() as s:
                index = await s.get(ZulipMessageIndex, ("realm", sources[0].message_id))
                event = await s.get(InputEvent, index.input_event_id)
                payload = copy.deepcopy(event.payload)
                if field == "historical":
                    payload["wire"]["historical"] = True
                else:
                    payload[field] = {
                        "capture_fencing": p.fence.fencing - 1,
                        "processing_fencing": p.fence.fencing + 1,
                        "defer_recovered": True,
                        "recovery_run_id": "synthetic-recovery",
                    }[field]
                event.payload, event.payload_hash = payload, digest(payload)
            return result

        return await original(reader, sources, read_only=changed)

    monkeypatch.setattr(p.scope, "observe_sources", observe)
    try:
        if field in {"capture_fencing", "processing_fencing"}:
            from jt_oz_bridge.storage.durable import Conflict

            with pytest.raises(Conflict):
                await send(p, server, b, "!oz cancel " + action.id)
        else:
            await send(p, server, b, "!oz cancel " + action.id)
        assert (await rows(db, Action))[0].state == "queued"
        assert len(server.posts) == before
        assert all(r.state != "completed" for r in await rows(db, CommandReceipt))
        assert not native.submitted
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize("field", ["dedupe_key", "priority", "source_revision", "command", "body"])
async def test_committed_fast_path_requires_original_receipt_and_full_batch(db, monkeypatch, field):
    from jt_oz_bridge.domain.routing import RoutedInput
    from jt_oz_bridge.services.closed_bound_queue import SavedBoundQueueReply
    from jt_oz_bridge.storage.durable import Conflict
    from jt_oz_bridge.storage.models import DeliveryBatch

    p, server, native, b, _, _, calls = await live_identity(db, monkeypatch)
    action = (await rows(db, Action))[0]
    try:
        mid, _ = await send(p, server, b, "!oz cancel " + action.id)
        receipt = next(r for r in await rows(db, CommandReceipt) if r.message_id == mid)
        saved = SavedBoundQueueReply.model_validate(receipt.response)
        routed = p.closed_bound._routed(saved, receipt.id)
        before = len(calls)
        assert (await p.closed_bound.committed(routed)).id == saved.queued_batch_id
        assert len(calls) == before
        async with db.sessions.begin() as s:
            if field in {"dedupe_key", "priority"}:
                batch = await s.get(DeliveryBatch, saved.queued_batch_id)
                if field == "dedupe_key":
                    batch.dedupe_key = "same-body-different-original-receipt"
                else:
                    batch.priority = 11
            else:
                row = await s.get(CommandReceipt, receipt.id)
                if field == "source_revision":
                    row.source_revision += 1
                elif field == "command":
                    row.command = "queue"
                else:
                    payload = dict(row.response)
                    payload["text"] += " changed"
                    row.response = payload
                    routed = RoutedInput(**{**routed.__dict__, "text": payload["text"]})
        with pytest.raises((Conflict, ValueError)):
            await p.closed_bound.committed(routed)
        assert len(calls) == before and not native.submitted
    finally:
        await p.scope.client.close()


async def pause_topic(db, binding, event=None):
    async with db.sessions.begin() as s:
        await s.execute(
            update(Binding)
            .where(Binding.id == binding.id)
            .values(dispatch_paused=True, queue_revision=Binding.queue_revision + 1)
        )
        if event is not None:
            s.add(AuditEvent(actor="realm:7", event=event, object_id=binding.id))


async def topic_paused(db, binding):
    async with db.sessions() as s:
        return (await s.get(Binding, binding.id)).dispatch_paused


@pytest.mark.parametrize("earlier", [None, "queue_resumed"])
async def test_new_prompt_continues_a_pause_no_person_chose(db, monkeypatch, earlier):
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    if earlier is not None:
        await pause_topic(db, b, "queue_paused")
        await pause_topic(db, b, earlier)
    await pause_topic(db, b)  # A restart or outage pauses without an audit choice.
    before = len(server.posts)
    try:
        _, outcome = await send(p, server, b, "continue after the restart")
        assert outcome[-1] == "ignore"
        assert [a.state for a in await rows(db, Action)] == ["queued"]
        assert not await topic_paused(db, b)
        assert "queue_resumed" in [e.event for e in await rows(db, AuditEvent)]
        assert len(server.posts) == before and not native.submitted
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize(("chosen", "continues"), [(None, True), ("queue_paused", False)])
async def test_a_steer_on_the_original_router_follows_the_same_pause_rule(
    db, monkeypatch, chosen, continues
):
    # `!steer` takes the original router to say where its text goes; a restart
    # pause still ends for it exactly as for a plain message, and `!oz queue pause` does not.
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    await pause_topic(db, b, chosen)
    try:
        _, outcome = await send(p, server, b, "!steer -- continue after the restart")
        assert outcome[-1] == "reply"
        assert [a.state for a in await rows(db, Action)] == ["queued" if continues else "held"]
        assert await topic_paused(db, b) is not continues
        assert ("queue_resumed" in [e.event for e in await rows(db, AuditEvent)]) is continues
        assert ("!go" in server.posts[-1]["content"]) is not continues
        assert not native.submitted
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize("event", ["queue_paused", "queue_paused_background_stop_unqualified"])
async def test_a_pause_a_person_chose_keeps_the_new_prompt_held(db, monkeypatch, event):
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    await pause_topic(db, b, event)
    before = len(server.posts)
    try:
        _, outcome = await send(p, server, b, "please wait for me")
        assert outcome[-1] == "reply"
        assert [a.state for a in await rows(db, Action)] == ["held"]
        assert await topic_paused(db, b)
        assert len(server.posts) == before + 1
        assert "!go" in server.posts[-1]["content"]
        # Desktop also gets buttons for the two commands the notice names.
        widget = json.loads(server.posts[-1]["widget_content"])
        assert [c["reply"] for c in widget["extra_data"]["choices"]] == ["!go", "!no"]
        receipts = await rows(db, CommandReceipt)
        assert receipts[-1].response["widget"] == server.posts[-1]["widget_content"]
    finally:
        await p.scope.client.close()


async def test_a_message_typed_after_a_settled_stop_goes_like_after_esc(db, monkeypatch):
    """After `!stop`, new messages must not all be held with `!no` unable to help."""
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    await pause_topic(db, b, "interrupt_queued")
    before = len(server.posts)
    try:
        _, outcome = await send(p, server, b, "create the VM instead")
        assert outcome[-1] == "ignore"
        assert [a.state for a in await rows(db, Action)] == ["queued"]
        assert not await topic_paused(db, b)
        assert "queue_resumed" in [e.event for e in await rows(db, AuditEvent)]
        assert len(server.posts) == before and not native.submitted
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize("left", ["held", "running"])
async def test_what_a_stop_held_back_or_has_not_ended_keeps_the_new_message_held(
    db, monkeypatch, left
):
    # Messages queued before `!stop` never go along unasked, and while the stop
    # itself has not settled the turn may still be running.
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=1)
    await pause_topic(db, b, "interrupt_queued")
    async with db.sessions.begin() as s:
        await s.execute(update(Action).values(state=left, status_reason=None))
    try:
        _, outcome = await send(p, server, b, "newer prompt")
        assert outcome[-1] == "reply"
        saved = sorted(await rows(db, Action), key=lambda a: a.created_at)
        assert [a.state for a in saved] == [left, "held"]
        assert await topic_paused(db, b)
        assert "!go" in server.posts[-1]["content"]
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize(
    ("earlier", "reason"),
    [("queued", None), ("held", None), ("held", "queue_paused")],
)
async def test_prompts_sent_during_the_pause_go_along_in_order(db, monkeypatch, earlier, reason):
    # The dispatcher's own pause hold ("queue_paused") is no person's choice either.
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=1)
    await pause_topic(db, b)
    async with db.sessions.begin() as s:
        await s.execute(update(Action).values(state=earlier, status_reason=reason))
    try:
        _, outcome = await send(p, server, b, "newer prompt")
        assert outcome[-1] == "ignore"
        saved = sorted(await rows(db, Action), key=lambda a: a.created_at)
        assert [a.state for a in saved] == ["queued", "queued"]
        assert saved[-1].payload["text"] == "newer prompt"
        assert not await topic_paused(db, b)
    finally:
        await p.scope.client.close()


async def test_an_old_held_prompt_is_never_sent_along_and_go_new_drops_it(db, monkeypatch):
    # A days-old "ok" would otherwise reach the AI as if just typed, ahead of "hi".
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=1)
    await pause_topic(db, b)
    async with db.sessions.begin() as s:
        await s.execute(
            update(Action).values(state="held", status_reason=None, created_at=time.time() - 7200)
        )
    try:
        _, outcome = await send(p, server, b, "newer prompt")
        assert outcome[-1] == "reply"
        assert [a.state for a in await rows(db, Action)] == ["held", "held"]
        assert await topic_paused(db, b)
        assert "!go new" in server.posts[-1]["content"]
        widget = json.loads(server.posts[-1]["widget_content"])
        assert [c["reply"] for c in widget["extra_data"]["choices"]] == ["!go new", "!go", "!no"]
        _, outcome = await send(p, server, b, "!go new")
        saved = sorted(await rows(db, Action), key=lambda a: a.created_at)
        assert [a.state for a in saved] == ["cancelled", "queued"]
        assert saved[-1].payload["text"] == "newer prompt"
        assert not await topic_paused(db, b)
        assert not native.submitted
    finally:
        await p.scope.client.close()


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("dispatching", None),
        ("ambiguous", None),
        ("held", "source_or_identity_changed"),
    ],
)
async def test_unclear_or_specially_held_work_keeps_the_pause(db, monkeypatch, state, reason):
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=1)
    await pause_topic(db, b)
    async with db.sessions.begin() as s:
        await s.execute(update(Action).values(state=state, status_reason=reason))
    try:
        _, outcome = await send(p, server, b, "newer prompt")
        assert outcome[-1] == "reply"
        assert sorted(a.state for a in await rows(db, Action)) == sorted([state, "held"])
        assert await topic_paused(db, b)
    finally:
        await p.scope.client.close()


async def test_a_stream_gap_holds_the_prompt_before_any_continuation(db, monkeypatch):
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    await pause_topic(db, b)

    async def gap(session, binding, *, ready=False):
        raise Conflict("transcript_gap_requires_review_and_rebind")

    if p.closed_bound.continuity is None:
        monkeypatch.setattr(
            p.closed_bound, "continuity", SimpleNamespace(_require_continuity_in_session=gap)
        )
    else:
        monkeypatch.setattr(p.closed_bound.continuity, "_require_continuity_in_session", gap)
    try:
        _, outcome = await send(p, server, b, "after a gap")
        assert outcome[-1] == "held"
        assert "queued" not in [a.state for a in await rows(db, Action)]
        assert await topic_paused(db, b)
        assert "queue_resumed" not in [e.event for e in await rows(db, AuditEvent)]
    finally:
        await p.scope.client.close()


async def test_a_refused_resume_leaves_the_prompt_held_and_written_once(db, monkeypatch):
    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    await pause_topic(db, b)

    async def review(*args, **kwargs):
        raise Conflict("recovery_owned_pause_requires_selected_review")

    monkeypatch.setattr(p.closed_bound.queue, "_resume_in_session", review)
    before = len(server.posts)
    try:
        _, outcome = await send(p, server, b, "after an outage")
        assert outcome[-1] == "reply"
        assert [a.state for a in await rows(db, Action)] == ["held"]
        assert await topic_paused(db, b)
        assert len(server.posts) == before + 1
    finally:
        await p.scope.client.close()


async def test_a_message_sent_while_bridge_was_down_takes_the_closed_path(db, monkeypatch):
    import time

    p, server, native, b, *_ = await live_identity(db, monkeypatch, initial_prompts=0)
    mid = max(server.messages) + 1
    server.next_mid = mid + 1
    server.message("sent while Bridge was down", mid)
    server.messages[mid]["subject"] = b.topic
    server.messages[mid]["timestamp"] = int(time.time()) - 30
    before = len(server.posts)
    try:
        p.consumer.queue_id = "queue-after-restart"
        await p.consumer.journal.enroll("queue-after-restart", -1)
        assert await topic_paused(db, b)
        await p.consumer._release_restart_pauses()
        assert not await topic_paused(db, b)
        with request_lane("control"):
            await p.consumer.poll()
        await p.deliver_once()
        saved = await rows(db, Action)
        assert [(a.state, a.payload["source"]["message_id"]) for a in saved] == [("queued", mid)]
        receipt = next(r for r in await rows(db, CommandReceipt) if r.message_id == mid)
        assert receipt.response["format"] == "closed-bound-queue-v1"
        assert not native.submitted
        # The fixture's older, never-captured message 90 is only reported, never sent.
        assert [post["id"] for post in server.posts[before:]] != []
        assert all("offline" in post["content"] for post in server.posts[before:])
    finally:
        await p.scope.client.close()
