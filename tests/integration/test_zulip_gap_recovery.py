"""Real Source/ownSQLite/outbox composition; entirely synthetic, not Human acceptance."""

import copy
import html
import json
import re
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline, RuntimeBackend
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
from jt_oz_bridge.storage.control_models import Binding
from jt_oz_bridge.storage.database import CURRENT_REVISION
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, InputEvent
from jt_oz_bridge.storage.zulip_recovery_models import ZulipRecoveryCheckpoint, ZulipRecoveryItem
from tests.integration.test_consumer_runtime import (
    INSTALLED_SCHEMA,
    Sessions,
    SyntheticExecution,
    WholeServer,
)
from tests.integration.test_model_commands import Catalog
from tests.integration.test_resource_execution_results import Reader
from tests.support import REF, service

URL = "https://chat.example.invalid"


class RecoveryServer(WholeServer):
    def __init__(self):
        super().__init__()
        self.registration = 0
        self.expired_queues = set()
        self.queue_after = {}
        self.history_hook = None
        self.event_hook = None

    def handle(self, request):
        route = request.url.path.removeprefix("/api/v1/")
        if route in {"users/me", "server_settings"}:
            self.calls.append((request.method, route))
            data = (
                {"user_id": 11, "is_bot": True, "is_active": True, "bot_owner_id": 8, "role": 400}
                if route == "users/me"
                else {"realm_url": URL, "zulip_version": "12.3", "zulip_feature_level": 500}
            )
            return httpx.Response(200, json={"result": "success", **data})
        if request.method == "POST" and route == "register":
            self.calls.append((request.method, route))
            self.registration += 1
            q = f"queue-{self.registration}"
            last = max([e["id"] for e in self.events], default=-1)
            self.queue_after[q] = last
            return httpx.Response(
                200, json={"result": "success", "queue_id": q, "last_event_id": last}
            )
        if route == "events" and request.method == "GET":
            self.calls.append((request.method, route))
            if self.event_hook is not None:
                self.event_hook(request)
            q = request.url.params["queue_id"]
            if q in self.expired_queues:
                return httpx.Response(400, json={"result": "error", "code": "BAD_EVENT_QUEUE_ID"})
            last = int(request.url.params["last_event_id"])
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "events": [copy.deepcopy(e) for e in self.events if e["id"] > last],
                },
            )
        if route == "messages" and request.method == "GET" and "num_after" in request.url.params:
            self.calls.append((request.method, route))
            if self.history_hook:
                self.history_hook(request)
            narrow = json.loads(request.url.params["narrow"])
            channel = int(next(v["operand"] for v in narrow if v["operator"] == "channel"))
            rows = sorted(
                [
                    copy.deepcopy(m)
                    for m in self.messages.values()
                    if m["stream_id"] == channel and m["id"] not in self.deleted
                ],
                key=lambda m: m["id"],
            )
            anchor = request.url.params["anchor"]
            if anchor == "newest":
                selected = rows[-2:]
            else:
                selected = [m for m in rows if m["id"] > int(anchor)][
                    : int(request.url.params["num_after"])
                ]
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "messages": selected,
                    "found_newest": not rows
                    or not selected
                    or selected[-1]["id"] == rows[-1]["id"],
                    "found_oldest": not rows or not selected or selected[0]["id"] == rows[0]["id"],
                    "found_anchor": False,
                    "history_limited": False,
                },
            )
        return super().handle(request)


async def setup_recovery(db):
    server, execution, results = RecoveryServer(), SyntheticExecution(), Reader()
    execution.contract_hash = INSTALLED_SCHEMA
    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic",
        attestation=ZulipAttestation(
            URL,
            "realm",
            11,
            500,
            10000,
            60,
            verified_scope_operations=SCOPE_OPERATIONS,
            verified_event_operations=EVENT_OPERATIONS | {"cleanup"},
        ),
        transport=httpx.MockTransport(server.handle),
    )
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
        ),
    )
    audience = ZulipScopeReader(client, channel_ids=frozenset({10}))
    await service(db, control=execution, audience=audience)
    store = DurableStore(db)
    f = await store.acquire_lease("recovery-pipeline", ttl=120)
    projects = {REF.project_id: REF.canonical_directory}

    async def pending(ref):
        return ()

    async def pulse():
        return None

    backend = RuntimeBackend(
        RegisteredBackend(REF.backend_identity, INSTALLED_SCHEMA, projects, execution),
        RegisteredCatalog(REF.backend_identity, INSTALLED_SCHEMA, projects, Sessions()),
        Catalog(REF, INSTALLED_SCHEMA),
        results,
        (REF,),
        pending,
        pulse,
        (),
    )
    p = ConsumerPipeline(
        db,
        ConsumerFence("recovery-pipeline", f),
        audience,
        {REF.backend_id: backend},
        zulip_recovery_enabled=True,
        delivery_interval=0,
    )
    p.recovery_errors = []
    real_route = p.router.recovery.route

    async def trace_route(*args, **kwargs):
        try:
            return await real_route(*args, **kwargs)
        except BaseException as error:
            p.recovery_errors.append(repr(error))
            raise

    p.router.recovery.route = trace_route
    b = await p.bindings.bind("realm", 7, 10, "Original work", REF)
    await p.consumer.start()
    for _ in range(5):
        await p.consumer.poll()
    assert not p.consumer.recovery.capturing
    return p, server, execution, b


async def rows(db, model):
    async with db.sessions() as s:
        return list((await s.scalars(select(model))).all())


async def outage(p, s, text="offline prompt", mid=101):
    s.message(text, mid)
    s.expired_queues.add(p.consumer.queue_id)
    assert await p.consumer.poll() == ("recovering",)
    for _ in range(8):
        await p.consumer.poll()
    return [a for a in await rows(p.db, Action) if a.dedupe_key == f"human:realm:{mid}"][0]


async def command(p, s, text, mid):
    s.input(text, mid)
    for _ in range(3):
        await p.consumer.poll()
        await p.deliver_once()


@pytest.mark.asyncio
async def test_actual_queue_expiry_history_held_review_and_exact_original_action_dispatch(db):
    p, s, native, b = await setup_recovery(db)
    try:
        # Explicit fresh start anchor is not a claim of pre-feature recovery.
        cp = (await rows(db, ZulipRecoveryCheckpoint))[0]
        assert cp.message_id == 90 and cp.coverage == "unknown_before_anchor"
        action = await outage(p, s)
        assert action.state == "held" and not native.submitted
        original = copy.deepcopy(action.payload)
        assert s.registration == 2 and p.consumer.queue_id == "queue-2"
        assert any(
            e.source.startswith("zulip-history:") and "event_id" not in e.payload
            for e in await rows(db, InputEvent)
        )
        await command(p, s, "!oz recovery", 110)
        await command(p, s, "!oz recovery preview 101", 111)
        match = re.search(r"!oz recovery confirm ([A-Za-z0-9_-]+)", s.posts[-1]["content"])
        assert match is not None, (p.recovery_errors, [m["content"] for m in s.posts])
        token = match.group(1)
        await command(p, s, "!oz recovery confirm " + token, 112)
        approved = next(a for a in await rows(db, Action) if a.id == action.id)
        assert approved.state == "queued" and approved.payload == original
        assert await p.dispatcher.advance(action.id) == "admitted"
        assert len(native.submitted) == 1 and native.submitted[0][0] == REF
        assert len([i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id]) == 1
        assert await p.dispatcher.advance(action.id) == "admitted" and len(native.submitted) == 1
        assert all(m["subject"] == b.topic for m in s.posts)
    finally:
        await p.consumer.close()
        await p.scope.client.close()


async def preview(p, s, ids="101", mid=111):
    await command(p, s, "!oz recovery preview " + ids, mid)
    matches = [re.search(r"!oz recovery confirm ([A-Za-z0-9_-]+)", m["content"]) for m in s.posts]
    return next((m.group(1) for m in reversed(matches) if m), None)


async def close(p):
    await p.consumer.close()
    await p.scope.client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "!help",
        "!confirm",
        "!oz stop",
        "!oz approve oldtoken",
        "!oz git commit",
        "!oz queue resume",
        "!oz recovery confirm oldtoken",
    ],
)
async def test_every_historical_control_is_held_without_execution_or_new_approval(db, text):
    from jt_oz_bridge.storage.command_models import CommandReceipt

    p, s, n, b = await setup_recovery(db)
    try:
        s.message(text, 101)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        for _ in range(8):
            await p.consumer.poll()
        assert not n.submitted and not await rows(db, Action)
        receipts = await rows(db, CommandReceipt)
        assert len(receipts) == 1 and receipts[0].state == "held"
        assert (await rows(db, ZulipRecoveryItem))[0].state == "command_held"
        assert (await rows(db, Binding))[0].dispatch_paused
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_initial_anchor_has_no_historical_binding_authority_and_no_past_coverage_claim(db):
    p, s, n, b = await setup_recovery(db)
    try:
        async with db.sessions.begin() as session:
            checkpoint = await session.get(ZulipRecoveryCheckpoint, (p.consumer.journal.source, 10))
            checkpoint.binding_scopes = {}
        s.message("before provable binding", 101)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        for _ in range(8):
            await p.consumer.poll()
        assert (
            not await rows(db, Action) and not await rows(db, ZulipRecoveryItem) and not n.submitted
        )
        await command(p, s, "!oz recovery", 110)
        assert "unknown_before_anchor" in html.unescape(s.posts[-1]["content"])
        assert (await rows(db, ZulipRecoveryCheckpoint))[0].coverage == "unknown_before_anchor"
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_scope_revision_changed_since_proven_anchor_never_borrows_new_binding(db):
    p, s, n, b = await setup_recovery(db)
    try:
        async with db.sessions.begin() as session:
            current = await session.get(Binding, b.id)
            current.revision += 1
        s.message("old scope cannot authorize new", 101)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        for _ in range(8):
            await p.consumer.poll()
        assert (
            not await rows(db, Action) and not await rows(db, ZulipRecoveryItem) and not n.submitted
        )
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_pause_is_absolute_and_bulk_resume_cannot_release_recovery_work(db):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s)
        current = (await rows(db, Binding))[0]
        with pytest.raises(Conflict, match="recovery"):
            await p.dispatcher.queue.resume(
                b.id, "realm", 7, current.revision, current.queue_revision
            )
        async with db.sessions.begin() as session:
            a = await session.get(Action, action.id)
            a.state = "queued"
        assert await p.dispatcher.advance(action.id) == "queued"
        assert not n.submitted and (await rows(db, Binding))[0].dispatch_paused
        assert (await rows(db, Action))[0].payload == action.payload
    finally:
        await close(p)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["source", "audience", "grant", "pause", "fence", "wrong_actor"])
async def test_preview_confirmation_refuses_changed_authority_without_native_write(db, change):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s)
        token = await preview(p, s)
        assert token
        if change == "source":
            s.messages[101]["content"] = "edited old instruction"
        if change == "audience":
            s.private = False
        if change == "grant":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        if change == "pause":
            async with db.sessions.begin() as session:
                current = await session.get(Binding, b.id)
                current.queue_revision += 1
        if change == "fence":
            from jt_oz_bridge.storage.models import WorkerLease

            async with db.sessions.begin() as session:
                await session.execute(update(WorkerLease).values(fencing=999))
        if change == "wrong_actor":
            s.input("!oz recovery confirm " + token, 112, author=8)
        else:
            s.input("!oz recovery confirm " + token, 112)
        try:
            for _ in range(3):
                await p.consumer.poll()
        except (Conflict, ValueError):
            if change not in {"fence", "audience"}:
                raise
        current = next(a for a in await rows(db, Action) if a.id == action.id)
        assert current.state == "held" and current.payload == action.payload and not n.submitted
        assert (await rows(db, Binding))[0].dispatch_paused
    finally:
        if change in {"fence", "audience"}:
            await p.scope.client.close()
        else:
            await close(p)


@pytest.mark.asyncio
async def test_new_human_confirmation_source_is_rechecked_at_final_dispatch(db):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s)
        token = await preview(p, s)
        assert token
        await command(p, s, "!oz recovery confirm " + token, 112)
        assert (await rows(db, Action))[0].state == "queued"
        s.messages[112]["content"] = "revoked confirmation"
        # Refused, never sent; held it would stop every later message in the topic.
        assert await p.dispatcher.advance(action.id) == "rejected"
        assert not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_duplicate_history_and_queue_buffer_keep_one_original_action(db):
    p, s, n, b = await setup_recovery(db)
    try:
        s.message("same message via GET and events", 101)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        s.input("same message via GET and events", 101)
        for _ in range(8):
            await p.consumer.poll()
        actions = await rows(db, Action)
        assert len(actions) == 1 and actions[0].state == "held"
        assert len(await rows(db, ZulipRecoveryItem)) == 1 and not n.submitted
        await p.consumer.recovery.process_history_one()
        await p.consumer.drain()
        assert len(await rows(db, Action)) == 1
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_real_native_adapter_original_root_policy_and_one_attempt_survive_recovery(db):
    from jt_oz_bridge.services.zulip_gap_recovery import ZulipGapRecovery
    from jt_oz_bridge.services.zulip_recovery_review import ZulipRecoveryReview
    from tests.contract.test_leaf_resources import finish
    from tests.integration.test_consumer_runtime import original_graph_pipeline

    p, factory, state, writes, anchor, native, client = await original_graph_pipeline(
        db, enabled=False, tree=False
    )
    s = RecoveryServer()
    client.client._transport = httpx.MockTransport(s.handle)
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
        ),
    )
    p.consumer.recovery = ZulipGapRecovery(p.consumer)
    p.router.recovery = ZulipRecoveryReview(p.consumer.recovery)
    root = factory.policy.anchor
    native_peer = native.client._transport

    def prompt_peer(request):
        if request.method == "POST":
            assert request.url.path == "/api/session/" + root.upstream_session_id + "/prompt"
            body = json.loads(request.content)
            writes.append(request)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "msg_recovered_original",
                        "sessionID": root.upstream_session_id,
                        "time": {"created": 100},
                        "type": "user",
                        "payload": {"text": body["text"]},
                        "delivery": body["delivery"],
                    }
                },
            )
        return native_peer.handler(request)

    native.client._transport = httpx.MockTransport(prompt_peer)
    original = factory.registry.selected(root)
    try:
        await original.execution.proofs.watch(root)
        await p.bindings.bind("realm", 7, 10, "Original work", root)
        await p.consumer.start()
        for _ in range(5):
            await p.consumer.poll()
        action = await outage(p, s)
        assert action.payload["reference"] == root.model_dump(mode="json") and not writes
        token = await preview(p, s)
        assert token
        await command(p, s, "!oz recovery confirm " + token, 112)
        result = await p.dispatcher.advance(action.id)
        assert result == "admitted"
        assert len(writes) == 1 and writes[0].method == "POST"
        assert root.upstream_session_id in writes[0].url.path
        assert factory.registry.selected(root) is original
        await p.dispatcher.advance(action.id)
        assert len(writes) == 1
    finally:
        await p.consumer.close()
        await client.close()
        await finish(anchor, native)


@pytest.mark.asyncio
async def test_explicit_none_unpauses_only_owned_empty_selection_and_keeps_original_held(db):
    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s)
        token = await preview(p, s, "none")
        assert token
        await command(p, s, "!oz recovery confirm " + token, 112)
        current = (await rows(db, Binding))[0]
        assert not current.dispatch_paused
        retained = (await rows(db, Action))[0]
        assert (
            retained.id == action.id
            and retained.state == "held"
            and retained.payload == action.payload
        )
        with pytest.raises(Conflict, match="recovered_prompts"):
            await p.dispatcher.queue.resume(
                b.id, "realm", 7, current.revision, current.queue_revision
            )
        assert not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_previous_user_pause_and_old_ambiguous_actions_are_never_released(db):
    p, s, n, b = await setup_recovery(db)
    try:
        async with db.sessions.begin() as session:
            current = await session.get(Binding, b.id)
            current.queue_revision += 1
        action = await outage(p, s)
        async with db.sessions.begin() as session:
            a = Action(
                dedupe_key="isolated-ambiguous",
                binding_id=b.id,
                binding_revision=b.revision,
                actor_id=7,
                payload=action.payload,
                operation="prompt",
                operation_digest=action.operation_digest,
                state="ambiguous",
            )
            session.add(a)
        prior = next(a for a in await rows(db, Action) if a.dedupe_key == "isolated-ambiguous")
        token = await preview(p, s)
        assert token
        await command(p, s, "!oz recovery confirm " + token, 112)
        assert (await rows(db, Binding))[0].dispatch_paused
        actual = next(a for a in await rows(db, Action) if a.id == action.id)
        ambiguous = next(a for a in await rows(db, Action) if a.id == prior.id)
        assert (
            actual.state == "held"
            and all(
                getattr(ambiguous, c.name) == getattr(prior, c.name)
                for c in Action.__table__.columns
            )
            and not n.submitted
        )
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_original_live_queued_action_is_safety_held_without_body_rewrite(db):
    p, s, n, b = await setup_recovery(db)
    try:
        token = await preview(p, s, "none", 110)
        assert token
        await command(p, s, "!oz recovery confirm " + token, 111)
        await command(p, s, "original live queued", 112)
        prior = (await rows(db, Action))[0]
        assert prior.state == "queued"
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        after = next(a for a in await rows(db, Action) if a.id == prior.id)
        assert (
            after.state == "held"
            and after.version == prior.version + 1
            and after.payload == prior.payload
        )
        assert len([i for i in await rows(db, ZulipRecoveryItem) if i.action_id == prior.id]) == 1
        assert not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_history_more_than_one_page_preserves_every_actual_original_id(db):
    p, s, n, b = await setup_recovery(db)
    try:
        for mid in range(101, 251):
            s.message("original " + str(mid), mid)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        for _ in range(4):
            await p.consumer.poll()
        captured = [e for e in await rows(db, InputEvent) if e.source.startswith("zulip-history:")]
        assert {e.payload["message"]["id"] for e in captured} == set(range(101, 251))
        assert len(captured) == 150
        assert all(
            "canonical_response_sha256" in e.payload and "event_id" not in e.payload
            for e in captured
        )
        assert (await rows(db, ZulipRecoveryCheckpoint))[0].message_id == 250
        assert not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_recovery_page_cap_retains_pause_and_never_claims_complete(db):
    from jt_oz_bridge.storage.durable import digest

    p, s, n, b = await setup_recovery(db)
    try:
        s.message("beyond cap", 101)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        await p.consumer.poll()  # freeze genuine GET newest upper bound
        async with db.sessions.begin() as session:
            run = await session.get(InputEvent, p.consumer.recovery.run_id)
            body = copy.deepcopy(run.payload)
            body["channels"]["10"]["pages"] = 100
            run.payload, run.payload_hash = body, digest(body)
        before = len([c for c in s.calls if c == ("GET", "messages")])
        await p.consumer.poll()
        run = next(e for e in await rows(db, InputEvent) if e.id == p.consumer.recovery.run_id)
        assert run.state == "zulip_recovery_partial" and p.consumer.recovery.capturing
        assert len([c for c in s.calls if c == ("GET", "messages")]) == before
        assert (await rows(db, Binding))[0].dispatch_paused and not n.submitted
    finally:
        await close(p)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["timeout", "wait"])
async def test_unknown_native_effect_or_cancel_is_never_reposted(db, mode):
    import asyncio

    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s)
        token = await preview(p, s)
        assert token
        await command(p, s, "!oz recovery confirm " + token, 112)
        n.mode = mode
        if mode == "wait":
            task = asyncio.create_task(p.dispatcher.advance(action.id))
            await asyncio.wait_for(n.entered.wait(), timeout=3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert await p.dispatcher.advance(action.id) == "ambiguous"
        assert len(n.submitted) == 1
        assert await p.dispatcher.advance(action.id) == "ambiguous"
        assert len(n.submitted) == 1 and (await rows(db, Action))[0].payload == action.payload
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_fresh_prompt_while_recovery_paused_is_not_running_and_cannot_bulk_resume(db):
    p, s, n, b = await setup_recovery(db)
    try:
        await command(p, s, "new prompt while paused", 101)
        action = (await rows(db, Action))[0]
        assert action.state == "held" and not n.submitted
        assert "has not run" in html.unescape(s.posts[-1]["content"])
        assert "!recovery" in s.posts[-1]["content"]
        assert len([i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id]) == 1
        current = (await rows(db, Binding))[0]
        with pytest.raises(Conflict, match="recovery"):
            await p.dispatcher.queue.resume(
                b.id, "realm", 7, current.revision, current.queue_revision
            )
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_cancelled_review_joins_exact_uncertainty_cleanup_and_never_replays(db):
    import asyncio

    from jt_oz_bridge.storage.command_models import CommandReceipt

    p, s, n, b = await setup_recovery(db)
    try:
        await outage(p, s)
        token = await preview(p, s)
        assert token
        entered, release, cleanup_entered, cleanup_release = [asyncio.Event() for _ in range(4)]
        original_items = p.router.recovery.source_items

        async def blocked_items(*args, **kwargs):
            result = await original_items(*args, **kwargs)
            entered.set()
            await release.wait()
            return result

        original_abandon = p.router.inbox.abandon

        async def blocked_abandon(claim):
            cleanup_entered.set()
            await cleanup_release.wait()
            await original_abandon(claim)

        p.router.recovery.source_items = blocked_items
        p.router.inbox.abandon = blocked_abandon
        s.input("!oz recovery confirm " + token, 112)
        task = asyncio.create_task(p.consumer.poll())
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        await asyncio.wait_for(cleanup_entered.wait(), 3)
        task.cancel()
        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        receipt = next(v for v in await rows(db, CommandReceipt) if v.message_id == 112)
        assert receipt.state == "ambiguous"
        assert (await rows(db, Action))[0].state == "held" and not n.submitted
        assert not p.consumer._polling
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_actual_schema33_upgrade_preserves_every_old_row_and_ciphertext(tmp_path):
    import os
    from pathlib import Path

    from alembic import command as alembic
    from alembic.config import Config
    from sqlalchemy import text

    from jt_oz_bridge.security.cipher import EnvelopeCipher
    from jt_oz_bridge.storage.database import Database, migrate

    cipher = EnvelopeCipher({"test": os.urandom(32)}, "test")
    database = Database("sqlite+aiosqlite:///" + str(tmp_path / "upgrade.db"), cipher=cipher)

    def previous(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path("src/jt_oz_bridge/storage/migrations").resolve())
        )
        config.attributes["connection"] = connection
        alembic.upgrade(config, "0033_payload_retention")

    async def snapshot():
        async with database.engine.connect() as connection:
            names = (
                (
                    await connection.execute(
                        text(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                        )
                    )
                )
                .scalars()
                .all()
            )
            return {
                name: (await connection.execute(text('SELECT * FROM "' + name + '"'))).all()
                for name in names
            }

    try:
        async with database.engine.begin() as connection:
            await connection.run_sync(previous)
        from jt_oz_bridge.storage.payload_keys import verify_keys

        async with database.engine.begin() as connection:
            await connection.run_sync(lambda c: verify_keys(c, initialize=True))
        async with database.sessions.begin() as session:
            from jt_oz_bridge.storage.models import WorkerLease

            session.add(
                WorkerLease(
                    role="consumer",
                    holder="00000000-0000-4000-8000-000000000007",
                    expires_at=0,
                    fencing=7,
                )
            )
            session.add(
                WorkerLease(role="observer", holder="preserved-observer", expires_at=0, fencing=9)
            )
            session.add(
                InputEvent(
                    source="zulip-history:preserved",
                    source_id="original",
                    revision=0,
                    payload={"private": "unchanged"},
                    payload_hash="a" * 64,
                    state="held",
                )
            )
        before = await snapshot()
        await migrate(database.engine)
        after = await snapshot()
        assert set(after) - set(before) == {
            "zulip_recovery_checkpoints",
            "zulip_recovery_items",
            "session_configuration_heads",
            "prompt_schedules",
        }
        for name in before:
            if name not in {"alembic_version", "worker_leases"}:
                assert after[name] == before[name]
        leases = {row[0]: row for row in after["worker_leases"]}
        assert leases["observer"] == next(
            row for row in before["worker_leases"] if row[0] == "observer"
        )
        assert set(leases) == {"consumer", "observer"}
        assert leases["consumer"][1] != "00000000-0000-4000-8000-000000000007"
        import uuid

        assert str(uuid.UUID(leases["consumer"][1])) == leases["consumer"][1]
        assert leases["consumer"][2:] == (0, 8)
        assert not after["zulip_recovery_checkpoints"] and not after["zulip_recovery_items"]
        assert after["alembic_version"] == [(CURRENT_REVISION,)]
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_no_normal_routing_until_a_genuine_final_empty_queue_barrier(db):
    p, s, n, b = await setup_recovery(db)
    try:
        s.message("recover original", 101)

        def busy_queue(request):
            eid = max((e["id"] for e in s.events), default=-1) + 1
            s.events.append({"id": eid, "type": "heartbeat"})

        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        s.event_hook = busy_queue
        for _ in range(6):
            await p.consumer.poll()
        assert p.consumer.recovery.capturing
        run = next(v for v in await rows(db, InputEvent) if v.id == p.consumer.recovery.run_id)
        assert run.state == "zulip_recovery_running" and not n.submitted
        assert (await rows(db, Binding))[0].dispatch_paused
        s.event_hook = None
        await p.consumer.poll()
        assert not p.consumer.recovery.capturing
        run = next(v for v in await rows(db, InputEvent) if v.id == p.consumer.recovery.run_id)
        assert run.state == "zulip_recovery_captured"
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_late_message_below_committed_anchor_is_never_a_fresh_control(db):
    p, s, n, b = await setup_recovery(db)
    try:
        # Genuine queue event identity, but the original message is older than
        # the trusted initial anchor. It must not enter closed or legacy controls.
        s.input("!oz stop", 90)
        for _ in range(3):
            await p.consumer.poll()
        assert not await rows(db, Action) and not n.submitted
        events = [v for v in await rows(db, InputEvent) if v.source.startswith("zulip:")]
        assert len(events) == 1 and events[0].state == "zulip_held"
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_ungranted_historical_actor_is_terminally_denied_without_stalling_capture(db):
    p, s, n, b = await setup_recovery(db)
    try:
        s.message("unauthorized historical instruction", 101, author=13)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        for _ in range(8):
            await p.consumer.poll()
        assert not await rows(db, Action) and not n.submitted
        assert (await rows(db, ZulipRecoveryItem))[0].state == "rejected"
        assert not p.consumer.recovery.capturing
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_actual_history_source_http401_remains_fatal_authentication_denial(db):
    from jt_oz_bridge.adapters.zulip.client import ZulipAuthenticationFailed

    p, s, n, b = await setup_recovery(db)
    try:
        s.message("not authorized through expired credentials", 101)
        s.expired_queues.add(p.consumer.queue_id)
        await p.consumer.poll()
        original = p.scope.client.client._transport

        def rejected(request):
            if request.url.path.endswith("/messages/101"):
                return httpx.Response(401, json={"result": "error", "code": "UNAUTHORIZED"})
            return original.handler(request)

        p.scope.client.client._transport = httpx.MockTransport(rejected)
        with pytest.raises(ZulipAuthenticationFailed):
            for _ in range(5):
                await p.consumer.poll()
        assert not await rows(db, Action) and not n.submitted
        assert any(v.state == "zulip_history_received" for v in await rows(db, InputEvent))
    finally:
        await p.scope.client.close()


@pytest.mark.asyncio
async def test_consumed_review_survives_native_wait_beyond_preview_expiry(db, monkeypatch):
    import time

    from jt_oz_bridge.storage.control_models import ControlToken
    from jt_oz_bridge.storage.models import WorkerLease

    p, s, n, b = await setup_recovery(db)
    try:
        action = await outage(p, s)
        token = await preview(p, s)
        assert token
        await command(p, s, "!oz recovery confirm " + token, 130)
        now = time.time()
        async with db.sessions.begin() as session:
            await session.execute(update(WorkerLease).values(expires_at=now + 2000))
        stored = next(v for v in await rows(db, ControlToken) if v.kind == "zulip-recovery-review")
        assert stored.used and stored.expires_at < now + 301
        monkeypatch.setattr(time, "time", lambda: now + 301)
        assert await p.dispatcher.advance(action.id) == "admitted"
        assert len(n.submitted) == 1
        assert await p.dispatcher.advance(action.id) == "admitted" and len(n.submitted) == 1
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_unconsumed_expired_preview_cannot_confirm_original_action(db):
    import time

    from jt_oz_bridge.storage.control_models import ControlToken

    p, s, n, b = await setup_recovery(db)
    try:
        await outage(p, s)
        token = await preview(p, s)
        assert token
        async with db.sessions.begin() as session:
            await session.execute(
                update(ControlToken)
                .where(ControlToken.kind == "zulip-recovery-review")
                .values(expires_at=time.time() - 1)
            )
        await command(p, s, "!oz recovery confirm " + token, 130)
        assert (await rows(db, Action))[0].state == "held" and not n.submitted
        assert (await rows(db, Binding))[0].dispatch_paused
        assert not next(
            v for v in await rows(db, ControlToken) if v.kind == "zulip-recovery-review"
        ).used
    finally:
        await close(p)


@pytest.mark.asyncio
async def test_spent_confirmation_cannot_release_another_original_action(db):
    p, s, n, b = await setup_recovery(db)
    try:
        s.message("different original prompt", 102)
        original = await outage(p, s)
        token = await preview(p, s, "101")
        assert token
        await command(p, s, "!oz recovery confirm " + token, 130)
        await command(p, s, "!oz recovery confirm " + token, 134)
        actions = await rows(db, Action)
        assert next(a for a in actions if a.id == original.id).state == "queued"
        assert next(a for a in actions if a.payload["source"]["message_id"] == 102).state == "held"
        assert not n.submitted and len(await rows(db, Action)) == 2
    finally:
        await close(p)


async def restart_consumer_on_independent_connection(p, server):
    """Synthetic process boundary: same durable file/key, fresh pool and services."""
    from jt_oz_bridge.storage.database import Database

    await p.consumer.close()
    await DurableStore(p.db).release_lease(p.fence.holder, p.fence.fencing)
    reopened = Database(str(p.db.engine.url), cipher=p.db.cipher)
    assert reopened.engine is not p.db.engine and await reopened.ready()
    holder = "independently-restarted-consumer"
    fencing = await DurableStore(reopened).acquire_lease(holder, ttl=120)
    assert fencing == p.fence.fencing + 1
    client = ZulipClient(
        URL,
        "bot@example.invalid",
        "synthetic",
        attestation=p.scope.client.attestation,
        transport=httpx.MockTransport(server.handle),
    )
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
        ),
    )
    restarted = ConsumerPipeline(
        reopened,
        ConsumerFence(holder, fencing),
        ZulipScopeReader(client, channel_ids=frozenset({10})),
        p.backends,
        zulip_recovery_enabled=True,
        delivery_interval=0,
    )
    assert restarted.consumer.recovery is not p.consumer.recovery
    await restarted.consumer.start()
    return restarted, reopened


@pytest.mark.asyncio
async def test_persisted_history_before_action_survives_new_connection_consumer_and_fence(db):
    p, s, native, binding = await setup_recovery(db)
    restarted = reopened = None
    try:
        s.message("persisted before action", 101)
        s.expired_queues.add(p.consumer.queue_id)
        assert await p.consumer.poll() == ("recovering",)
        await p.consumer.recovery.step()  # Actual bounded newest GET.
        await p.consumer.recovery.step()  # Actual page -> encrypted receipt/item SQL commit.
        item = next(i for i in await rows(db, ZulipRecoveryItem) if i.message_id == 101)
        source = next(i for i in await rows(db, InputEvent) if i.id == item.input_event_id)
        assert item.action_id is None and not await rows(db, Action)
        restarted, reopened = await restart_consumer_on_independent_connection(p, s)
        with pytest.raises(Conflict, match="consumer_lease_unavailable"):
            async with reopened.sessions.begin() as session:
                await p.fence.lock(session)
        for _ in range(10):
            await restarted.consumer.poll()
        recovered_item = next(i for i in await rows(reopened, ZulipRecoveryItem) if i.id == item.id)
        recovered_source = next(i for i in await rows(reopened, InputEvent) if i.id == source.id)
        actions = await rows(reopened, Action)
        assert len(actions) == 1 and actions[0].id == recovered_item.action_id
        assert actions[0].state == "held" and actions[0].binding_id == binding.id
        assert actions[0].payload["source"]["message_id"] == 101 and not native.submitted
        assert (
            recovered_source.payload == source.payload
            and recovered_source.payload_hash == source.payload_hash
        )
    finally:
        if restarted is not None:
            await close(restarted)
        await p.scope.client.close()
        if reopened is not None:
            await reopened.close()


@pytest.mark.asyncio
async def test_persisted_held_review_restart_preserves_action_and_posts_original_native_once(db):
    from jt_oz_bridge.services.zulip_gap_recovery import ZulipGapRecovery
    from jt_oz_bridge.services.zulip_recovery_review import ZulipRecoveryReview
    from tests.contract.test_leaf_resources import finish
    from tests.integration.test_consumer_runtime import original_graph_pipeline

    p, factory, state, writes, anchor, native, client = await original_graph_pipeline(
        db, enabled=False, tree=False
    )
    s = RecoveryServer()
    client.client._transport = httpx.MockTransport(s.handle)
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=8, url=URL, zulip_version="12.3", feature_level=500
        ),
    )
    p.consumer.recovery = ZulipGapRecovery(p.consumer)
    p.router.recovery = ZulipRecoveryReview(p.consumer.recovery)
    root = factory.policy.anchor
    peer = native.client._transport

    def native_http(request):
        if request.method == "POST":
            assert request.url.path == "/api/session/" + root.upstream_session_id + "/prompt"
            body = json.loads(request.content)
            writes.append(request)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "msg_restart_original",
                        "sessionID": root.upstream_session_id,
                        "time": {"created": 100},
                        "type": "user",
                        "payload": {"text": body["text"]},
                        "delivery": body["delivery"],
                    }
                },
            )
        return peer.handler(request)

    native.client._transport = httpx.MockTransport(native_http)
    original = factory.registry.selected(root)
    restarted = reopened = None
    try:
        await original.execution.proofs.watch(root)
        b = await p.bindings.bind("realm", 7, 10, "Original work", root)
        await p.consumer.start()
        for _ in range(5):
            await p.consumer.poll()
        action = await outage(p, s)
        token = await preview(p, s)
        assert token
        item = next(i for i in await rows(db, ZulipRecoveryItem) if i.action_id == action.id)
        source = next(i for i in await rows(db, InputEvent) if i.id == item.input_event_id)
        async with db.sessions.begin() as session:
            for status in ("held", "ambiguous"):
                # An uncertain prompt on this same Root correctly blocks ALL
                # later prompts. Preserve an unrelated uncertain interrupt here;
                # never pretend that recovery clears uncertain Native work.
                from jt_oz_bridge.storage.durable import digest

                retained_payload = copy.deepcopy(action.payload)
                retained_payload["operation"] = "interrupt" if status == "ambiguous" else "prompt"
                session.add(
                    Action(
                        dedupe_key="unrelated-existing-" + status,
                        binding_id=b.id,
                        binding_revision=b.revision,
                        actor_id=7,
                        payload=retained_payload,
                        operation=retained_payload["operation"],
                        operation_digest=digest(retained_payload),
                        state=status,
                    )
                )
        untouched = {
            a.id: {c.name: copy.deepcopy(getattr(a, c.name)) for c in Action.__table__.columns}
            for a in await rows(db, Action)
            if a.id != action.id
        }
        restarted, reopened = await restart_consumer_on_independent_connection(p, s)
        for _ in range(10):
            await restarted.consumer.poll()
        with pytest.raises(Conflict, match="consumer_lease_unavailable"):
            async with reopened.sessions.begin() as session:
                await p.fence.lock(session)
        # New Human messages must follow the restart's real committed watermark,
        # including previously published Bot messages, as the real server does.
        mid = max(s.messages) + 1
        s.next_mid = mid + 1
        await command(restarted, s, "!oz recovery confirm " + token, mid)
        assert next(a for a in await rows(reopened, Action) if a.id == action.id).state == "held"
        mid = max(s.messages) + 1
        s.next_mid = mid + 1
        fresh = await preview(restarted, s, mid=mid)
        assert fresh and fresh != token
        mid = max(s.messages) + 1
        s.next_mid = mid + 1
        await command(restarted, s, "!oz recovery confirm " + fresh, mid)
        actual = next(a for a in await rows(reopened, Action) if a.id == action.id)
        assert actual.state == "queued" and actual.payload == action.payload
        assert (
            next(e for e in await rows(reopened, InputEvent) if e.id == source.id).payload
            == source.payload
        )
        result = await restarted.dispatcher.advance(action.id)
        assert result == "admitted", [
            (a.id, a.state, a.created_at, a.status_reason) for a in await rows(reopened, Action)
        ]
        assert await restarted.dispatcher.advance(action.id) == "admitted" and len(writes) == 1
        assert factory.registry.selected(root) is original
        for a in await rows(reopened, Action):
            if a.id in untouched:
                assert {c.name: getattr(a, c.name) for c in Action.__table__.columns} == untouched[
                    a.id
                ]
    finally:
        if restarted is not None:
            await close(restarted)
        await client.close()
        if reopened is not None:
            await reopened.close()
        await finish(anchor, native)
