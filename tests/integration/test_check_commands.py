"""Real isolated action/outbox transactions, synthetic Human and original-shell fixtures."""

import asyncio
import re
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.checks import (
    ApprovedCheck,
    CheckCatalog,
    CheckObservation,
    check_message_id,
)
from jt_oz_bridge.domain.execution import Admission
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.check_commands import CheckCommands
from jt_oz_bridge.services.check_results import (
    CheckResultCollector,
    CheckResultPublisher,
    check_result,
)
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.execution_receipts import native_receipt
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message, send
from tests.support import bound

CHECK = ApprovedCheck(
    id="unit", title="Approved @**all** unit suite", command="python -m pytest tests"
)


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


def choice(text):
    return re.search(r"!oz check ([A-Za-z0-9_-]{32})", text)[1]


class CheckExecution(SyntheticExecution):
    def __init__(self):
        super().__init__()
        self.checks = (CHECK,)
        self.observations = {}
        self.hook = None
        self.before_send = None
        self.after_authority = None
        self.owner_epoch = "e" * 64
        self.preflights = []

    def capabilities(self, ref):
        return super().capabilities(ref) | {
            "check.run": Capability(
                supported=True,
                scope="session",
                reason="synthetic check qualification",
                verification="synthetic_test",
            )
        }

    def catalog(self, ref):
        return CheckCatalog(
            reference=ref, contract_sha256=self.contract_for(ref), checks=self.checks
        )

    def qualification_for(self, ref):
        return "d" * 64

    async def observe(self, ref, identity, check):
        if self.hook:
            await self.hook()
        return self.observations.get(identity)

    async def submit_check(self, ref, payload, identity, authority):
        from jt_oz_bridge.domain.execution import MutationNotSent

        if self.before_send:
            await self.before_send()
        import time

        from jt_oz_bridge.domain.check_dispatch import CheckDispatchPreflight
        from jt_oz_bridge.storage.durable import digest

        now = time.time()
        context = CheckDispatchPreflight(
            action_id=identity,
            operation_digest=digest(payload),
            reference=ref,
            binding_id=payload["binding_id"],
            binding_revision=payload["binding_revision"],
            contract_sha256=self.contract_for(ref),
            qualification_sha256=self.qualification_for(ref),
            message_id=check_message_id(identity),
            owner_epoch=self.owner_epoch,
            connection_epoch="synthetic-original-feed-generation",
            ownership_evidence_sha256="c" * 64,
            issued_at=now,
            expires_at=now + 5,
        )
        self.preflights.append(context)
        try:
            await authority(context)
        except Exception:
            raise MutationNotSent("synthetic final human authority rejected") from None
        if self.after_authority:
            await self.after_authority(context)
        return await self.submit(ref, payload, identity)

    async def submit(self, ref, payload, identity):
        assert ref == self.ref and payload["operation"] == "check.run"
        self.submitted.append((ref, payload, identity))
        self.observations[identity] = CheckObservation(
            reference=ref,
            action_id=identity,
            check=CHECK,
            message_id=check_message_id(identity),
            shell_id="sh_original",
            status="exited",
            exit_code=0,
            started_at=100,
            completed_at=200,
            evidence_sha256="c" * 64,
            qualification_sha256="d" * 64,
            output="2 passed @**all** <script>alert(1)</script>",
        )
        if self.mode == "lost-ack":
            raise TimeoutError("synthetic ACK loss after original shell started")
        return Admission(
            status="admitted",
            upstream_id=check_message_id(identity),
            details={"operation": "check.run", "check_passed": False, "turn_completed": False},
        )


async def setup(db, maximum=1000):
    execution = CheckExecution()
    bindings, binding, _, audience = await bound(db, control=execution)
    lease = await DurableStore(db).acquire_lease("checks", ttl=120)
    inbox = CommandInbox(db, "checks", lease)
    source = Source()
    tokens = TokenService(db, fence=inbox.fence)
    commands = CheckCommands(
        bindings,
        {execution.ref: execution},
        tokens,
        source,
        execution.capabilities,
        message_limit=maximum,
    )
    router = CommandRouter(bindings, source, inbox, checks=commands)
    worker = Dispatcher(bindings, execution, source, "checks", lease)
    replies = RoutedOutbox(
        Outbox(bindings, 77, fence=inbox.fence),
        realm_id="realm",
        message_limit=maximum,
        topic_limit=60,
    )
    return (
        router,
        binding,
        source,
        execution,
        commands,
        worker,
        CheckResultCollector(bindings, {execution.ref: execution}, inbox.fence),
        CheckResultPublisher(replies),
        audience,
    )


async def queued(values, locale="en"):
    router, binding, source, execution, commands, worker, collector, publisher, audience = values
    if locale != "en":
        await send(router, source, message("!oz lang " + locale, 99))
    menu = await send(router, source, message("!oz checks", 101))
    token = choice(menu.text)
    reply = await send(router, source, message("!oz check " + token, 102))
    action = (await rows(commands.db, Action))[0]
    assert action.id not in reply.text and reply.text.strip()
    return action


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_original_check_routes_once_admission_is_not_pass_and_real_result_publishes_same_topic(
    db, locale
):
    values = await setup(db)
    router, binding, source, execution, commands, worker, collector, publisher, audience = values
    action = await queued(values, locale)
    assert await router.route(source.messages[102]) == await router.route(source.messages[102])
    assert await worker.advance(action.id) == "admitted"
    saved = (await rows(db, Action))[0]
    assert (
        not saved.native_result and native_receipt(saved).admission.details["check_passed"] is False
    )
    assert await collector.collect(action.id, "realm")
    assert check_result((await rows(db, Action))[0]).observation.outcome == "passed"
    one, two = await asyncio.gather(publisher.publish(action.id), publisher.publish(action.id))
    assert one == two and await publisher.next_pending() is None
    assert len(await rows(db, DeliveryBatch)) == 1 and len(execution.submitted) == 1
    texts = "\n".join(d.payload["content"] for d in await rows(db, Delivery))
    assert ("通過" if locale == "zh-TW" else "Passed") in unescape(texts)
    assert "@**all**" not in texts and "<script>" not in texts


async def test_lost_ack_reconciles_exact_original_shell_without_a_second_submit(db):
    values = await setup(db)
    action = await queued(values)
    worker, collector, publisher = values[5:8]
    execution = values[3]
    execution.mode = "lost-ack"
    assert (
        await worker.advance(action.id) == "ambiguous"
        and await worker.advance(action.id) == "ambiguous"
    )
    assert len(execution.submitted) == 1 and not (await rows(db, Action))[0].admission
    assert await collector.collect(action.id, "realm")
    saved = (await rows(db, Action))[0]
    assert (
        saved.state == "completed"
        and native_receipt(saved).admission.details["reconciled_original_shell"] is True
    )
    await publisher.publish(action.id)
    assert len(execution.submitted) == 1


@pytest.mark.parametrize(
    ("status", "exit_code", "outcome", "state"),
    [
        ("exited", 1, "failed", "failed"),
        ("exited", None, "unknown", "ambiguous"),
        ("timeout", None, "timeout", "failed"),
        ("killed", None, "killed", "cancelled"),
    ],
)
async def test_nonpass_outcomes_are_truthful_and_unknown_can_later_reconcile_without_resubmit(
    db, status, exit_code, outcome, state
):
    values = await setup(db)
    action = await queued(values)
    execution, worker, collector, publisher = values[3], *values[5:8]
    await worker.advance(action.id)
    observation = execution.observations[action.id]
    execution.observations[action.id] = observation.model_copy(
        update={"status": status, "exit_code": exit_code}
    )
    assert await collector.collect(action.id, "realm")
    saved = (await rows(db, Action))[0]
    assert saved.state == state and check_result(saved).observation.outcome == outcome
    await publisher.publish(action.id)
    if outcome == "unknown":
        execution.observations[action.id] = observation
        assert await collector.collect(action.id, "realm")
        await publisher.publish(action.id)
        assert (
            len(await rows(db, DeliveryBatch)) == 2
            and (await rows(db, Action))[0].state == "completed"
        )
    assert len(execution.submitted) == 1


@pytest.mark.parametrize("change", ["source", "grant", "expiry", "binding"])
async def test_changed_authority_or_expired_choice_is_never_dispatched(db, change):
    values = await setup(db)
    action = await queued(values)
    source, execution, worker = values[2], values[3], values[5]
    if change == "source":
        source.messages[102] = source.messages[102].model_copy(
            update={"text": "!oz check replacement", "revision": 1}
        )
    else:
        async with db.sessions.begin() as session:
            if change == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            if change == "expiry":
                await session.execute(update(ControlToken).values(expires_at=0))
            if change == "binding":
                await session.execute(update(Binding).values(revision=Binding.revision + 1))
    assert await worker.advance(action.id) in {"held", "rejected"} and not execution.submitted


async def test_catalog_drift_wrong_actor_arbitrary_text_and_racing_choice_do_not_grant_execution(
    db,
):
    values = await setup(db)
    router, binding, source, execution, commands, worker, *_ = values
    menu = await send(router, source, message("!oz checks", 101))
    token = choice(menu.text)
    await send(router, source, message("!oz check " + token, 102, author_id=8))
    assert not await rows(db, Action)
    await send(router, source, message("!oz check rm -rf /", 103))
    assert not await rows(db, Action)
    execution.checks = (CHECK.model_copy(update={"command": "echo changed"}),)
    await send(router, source, message("!oz check " + token, 104))
    assert not await rows(db, Action)
    execution.checks = (CHECK,)
    await asyncio.gather(
        send(router, source, message("!oz check " + token, 105)),
        send(router, source, message("!oz check " + token, 106)),
    )
    assert len(await rows(db, Action)) == 1


async def test_active_check_blocks_next_check_and_original_prompt_on_same_root(db):
    values = await setup(db)
    first = await queued(values)
    router, binding, source, execution, commands, worker, *_ = values
    assert await worker.advance(first.id) == "admitted"
    menu = await send(router, source, message("!oz checks", 103))
    await send(router, source, message("!oz check " + choice(menu.text), 104))
    second = next(a for a in await rows(db, Action) if a.id != first.id)
    assert await worker.advance(second.id) == "queued"
    await send(router, source, message("next prompt", 105))
    third = next(a for a in await rows(db, Action) if a.operation == "prompt")
    assert await worker.advance(third.id) == "queued" and len(execution.submitted) == 1


async def test_audience_revocation_during_readback_keeps_result_and_publication_uncommitted(db):
    values = await setup(db)
    action = await queued(values)
    execution, worker, collector, _publisher, audience = values[3], *values[5:]
    await worker.advance(action.id)

    async def revoke():
        audience.users = frozenset({7, 8, 99})

    execution.hook = revoke
    with pytest.raises((AccessDenied, Conflict)):
        await collector.collect(action.id, "realm")
    assert not (await rows(db, Action))[0].native_result and not await rows(db, DeliveryBatch)


@pytest.mark.parametrize("maximum", [512, 700, 1000])
async def test_menu_page_tokens_and_hostile_titles_fit_actual_output_budget(db, maximum):
    values = await setup(db, maximum)
    router, binding, source, execution, *_ = values
    execution.checks = (
        CHECK.model_copy(update={"title": "[*<>] " * 20}),
        CHECK.model_copy(update={"id": "second"}),
    )
    menu = await send(router, source, message("!oz checks", 101))
    assert len(menu.text) <= maximum - 100
    page = re.search(r"!oz checks ([A-Za-z0-9_-]{32})", menu.text)[1]
    second = await send(router, source, message("!oz checks " + page, 102))
    assert choice(second.text)
    replay = await send(router, source, message("!oz checks " + page, 103))
    assert "expired" in replay.text
    assert not await rows(db, Action)


async def _check_runtime_timeout_diagnostics(pipeline, runtime, server):
    """Bounded synthetic metadata after failure, before runtime cleanup; no payloads."""
    import json
    import time
    from dataclasses import asdict

    from sqlalchemy import func

    from jt_oz_bridge.storage.command_models import CommandReceipt
    from jt_oz_bridge.storage.models import InputEvent, WorkerLease
    from jt_oz_bridge.storage.zulip_models import ZulipQueue

    value = {
        "healthy": runtime.healthy,
        "failure_code": runtime.failure_code,
        "failure_detail": asdict(runtime.failure_detail) if runtime.failure_detail else None,
        "deferred": {key: count for key, count in sorted(pipeline.deferred.items())[:32]},
        "post_count": len(server.posts),
        "own_db_states": {},
    }
    try:
        async with asyncio.timeout(0.5):
            async with pipeline.db.sessions() as session:
                for model in (InputEvent, CommandReceipt, Action, Delivery, ZulipQueue):
                    result = await session.execute(
                        select(model.state, func.count()).group_by(model.state).limit(32)
                    )
                    value["own_db_states"][model.__tablename__] = [list(row) for row in result]
                value["delivery_batches"] = await session.scalar(
                    select(func.count()).select_from(DeliveryBatch)
                )
                value["control_tokens"] = await session.scalar(
                    select(func.count()).select_from(ControlToken)
                )
                value["queue_numeric_watermarks"] = [
                    list(row)
                    for row in (
                        await session.execute(
                            select(ZulipQueue.generation, ZulipQueue.event_id).limit(2)
                        )
                    ).all()
                ]
                value["consumer_lease_current"] = list(
                    (
                        await session.execute(
                            select(WorkerLease.fencing, WorkerLease.expires_at > time.time())
                            .where(WorkerLease.role == "consumer")
                            .limit(2)
                        )
                    ).all()
                )
    except Exception as error:
        value["diagnostic_db_error_type"] = type(error).__name__
    # Await chains expose only source filename/function/line; never frame locals,
    # exception values, HTTP bodies, source commands or encrypted database fields.
    tasks = []
    for task in sorted(asyncio.all_tasks(), key=lambda item: item.get_name()):
        if not task.get_name().startswith("jtoz:") or len(tasks) == 32:
            continue
        row = {
            "name": task.get_name(),
            "done": task.done(),
            "cancelling": task.cancelling(),
            "awaits": [],
        }
        coro, seen = task.get_coro(), set()
        while coro is not None and id(coro) not in seen and len(row["awaits"]) < 20:
            seen.add(id(coro))
            frame = (
                getattr(coro, "cr_frame", None)
                or getattr(coro, "gi_frame", None)
                or getattr(coro, "ag_frame", None)
            )
            if frame is not None:
                row["awaits"].append(
                    [frame.f_code.co_filename, frame.f_code.co_name, frame.f_lineno]
                )
            coro = (
                getattr(coro, "cr_await", None)
                or getattr(coro, "gi_yieldfrom", None)
                or getattr(coro, "ag_await", None)
            )
        tasks.append(row)
    value["tasks"] = tasks
    # SQL Rows are converted explicitly; no ORM/entity/payload serialization.
    if "consumer_lease_current" in value:
        value["consumer_lease_current"] = [list(row) for row in value["consumer_lease_current"]]
    print("check_runtime_timeout_diagnostics", json.dumps(value, sort_keys=True), flush=True)


async def test_whole_consumer_wires_menu_one_attempt_and_same_topic_result(db):
    from dataclasses import replace

    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
    from tests.integration.test_consumer_runtime import post_containing
    from tests.integration.test_consumer_runtime import setup as graph_setup

    previous, server, old_native, results, binding, pulse = await graph_setup(db)
    execution = CheckExecution()
    execution.contract_hash = old_native.contract_hash
    original = previous.backends[execution.ref.backend_id]
    backend = replace(
        original,
        registered=replace(original.registered, client=execution),
        checks={execution.ref: execution},
    )
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {execution.ref.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!oz checks", 101)
        menu = await post_containing(server, "Approved project checks")
        server.input("!oz check " + choice(menu["content"]), 102)
        result = await post_containing(server, "Passed")
        assert result["sender_id"] == 11 and result["subject"] == binding.topic and runtime.healthy
        assert len(execution.submitted) == 1 and not old_native.submitted
        assert len(await rows(db, Action)) == 1 and (await rows(db, Action))[0].state == "completed"
    except TimeoutError:
        try:
            await _check_runtime_timeout_diagnostics(pipeline, runtime, server)
        except Exception as error:
            # Diagnostic failure must not replace the original timeout; no
            # exception values or upstream data are included in this label.
            try:
                print("check_runtime_diagnostic_error_type", type(error).__name__, flush=True)
            except Exception:
                # Even diagnostic output failure must preserve the timeout.
                pass
        raise
    finally:
        await runtime.close()


async def test_expiry_while_sql_driver_waits_rolls_back_choice_and_action(db):
    import time

    from sqlalchemy import event

    values = await setup(db)
    router, binding, source, execution, commands, *_ = values
    menu = await send(router, source, message("!oz checks", 101))
    token = choice(menu.text)
    async with db.sessions.begin() as session:
        await session.execute(update(ControlToken).values(expires_at=time.time() + 1))
    delayed = []

    def before_cursor(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("UPDATE CONTROL_TOKENS") and not delayed:
            delayed.append(True)
            time.sleep(1.1)

    event.listen(db.engine.sync_engine, "before_cursor_execute", before_cursor)
    try:
        result = await send(router, source, message("!oz check " + token, 102))
        assert "expired" in result.text
        assert delayed and not await rows(db, Action) and not execution.submitted
        assert not any(t.used for t in await rows(db, ControlToken))
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", before_cursor)


async def test_changed_execution_qualification_invalidates_an_existing_choice(db):
    values = await setup(db)
    router, binding, source, execution, *_ = values
    menu = await send(router, source, message("!oz checks", 101))
    token = choice(menu.text)
    execution.qualification_for = lambda ref: "f" * 64
    result = await send(router, source, message("!oz check " + token, 102))
    assert "expired" in result.text and not await rows(db, Action)


async def test_completed_result_survives_choice_expiry_and_operator_role_becoming_view_only(db):
    values = await setup(db)
    action = await queued(values)
    execution, worker, collector, publisher = values[3], *values[5:8]
    await worker.advance(action.id)
    async with db.sessions.begin() as session:
        await session.execute(update(ControlToken).values(expires_at=0))
        await session.execute(
            update(Grant).where(Grant.user_id == 7, Grant.role == "operator").values(role="viewer")
        )
        await session.execute(
            update(Grant).where(Grant.user_id == 7, Grant.role != "viewer").values(active=False)
        )
    assert await collector.collect(action.id, "realm")
    await publisher.publish(action.id)
    assert (
        len(execution.submitted) == 1
        and check_result((await rows(db, Action))[0]).observation.outcome == "passed"
    )


async def test_terminal_unknown_observation_cannot_regress_to_running(db):
    values = await setup(db)
    action = await queued(values)
    execution, worker, collector, publisher = values[3], *values[5:8]
    await worker.advance(action.id)
    original = execution.observations[action.id]
    execution.observations[action.id] = original.model_copy(update={"exit_code": None})
    await collector.collect(action.id, "realm")
    await publisher.publish(action.id)
    execution.observations[action.id] = original.model_copy(
        update={"status": "running", "exit_code": None, "completed_at": None}
    )
    with pytest.raises(Conflict, match="cannot_regress"):
        await collector.collect(action.id, "realm")
    assert (await rows(db, Action))[0].state == "ambiguous"


async def test_choice_expiry_during_final_source_read_prevents_dispatch_claim(db):
    import time

    from jt_oz_bridge.storage.durable import digest

    values = await setup(db)
    action = await queued(values)
    source, execution, worker = values[2], values[3], values[5]
    deadline = time.time() + 1
    async with db.sessions.begin() as session:
        current = await session.get(Action, action.id)
        payload = dict(current.payload)
        payload["choice_expires_at"] = deadline
        current.payload, current.operation_digest = payload, digest(payload)
        await session.execute(update(ControlToken).values(expires_at=deadline))
    original = source.read

    async def delayed(realm, identity):
        await asyncio.sleep(1.1)
        return await original(realm, identity)

    source.read = delayed
    assert await worker.advance(action.id) == "queued"
    assert not execution.submitted
    assert await worker.advance(action.id) == "held"


@pytest.mark.parametrize("lost_ack", [False, True])
async def test_idle_tail_recognition_uses_existing_sealed_action_or_exact_consumed_choice(
    db, lost_ack
):
    from types import SimpleNamespace

    from jt_oz_bridge.services.check_results import known_check_tail

    values = await setup(db)
    action = await queued(values)
    execution, worker = values[3], values[5]
    if lost_ack:
        execution.mode = "lost-ack"
    await worker.advance(action.id)
    certificate = SimpleNamespace(
        catalog=execution.catalog(execution.ref),
        enrollment_sha256=execution.qualification_for(execution.ref),
    )
    found = await known_check_tail(db, execution.ref, certificate, check_message_id(action.id))
    assert found.action_id == action.id and found.check == CHECK
    with pytest.raises(Conflict):
        await known_check_tail(db, execution.ref, certificate, "msg_unowned")
    assert len(execution.submitted) == 1


async def test_approved_but_never_dispatched_choice_is_not_an_idle_tail_certificate(db):
    from types import SimpleNamespace

    from jt_oz_bridge.services.check_results import known_check_tail

    values = await setup(db)
    action = await queued(values)
    execution = values[3]
    certificate = SimpleNamespace(
        catalog=execution.catalog(execution.ref),
        enrollment_sha256=execution.qualification_for(execution.ref),
    )
    with pytest.raises(Conflict):
        await known_check_tail(db, execution.ref, certificate, check_message_id(action.id))
    assert not execution.submitted


@pytest.mark.parametrize(
    "change", ["source", "grant", "audience", "binding", "pause", "lease", "token", "action"]
)
async def test_final_authority_rejects_changes_after_native_preflight_without_post_or_stale_lease_write(
    db, change
):
    from jt_oz_bridge.storage.models import WorkerLease

    values = await setup(db)
    action = await queued(values)
    router, binding, source, execution, commands, worker, collector, publisher, audience = values

    async def late_change():
        if change == "source":
            source.messages[102] = source.messages[102].model_copy(
                update={"text": "!oz check other", "revision": 1}
            )
        if change == "audience":
            audience.users = frozenset({7, 8, 99})
        async with db.sessions.begin() as session:
            if change == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            if change == "binding":
                await session.execute(
                    update(Binding)
                    .where(Binding.id == binding.id)
                    .values(revision=Binding.revision + 1)
                )
            if change == "pause":
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
                )
            if change == "lease":
                await session.execute(update(WorkerLease).values(fencing=WorkerLease.fencing + 1))
            if change == "token":
                await session.execute(update(ControlToken).values(expires_at=0))
            if change == "action":
                await session.execute(
                    update(Action)
                    .where(Action.id == action.id)
                    .values(version=Action.version + 1, state="ambiguous")
                )

    execution.before_send = late_change
    state = await worker.advance(action.id)
    assert not execution.submitted and not await rows(db, DeliveryBatch)
    if change == "lease":
        assert state == (await rows(db, Action))[0].state == "dispatching"
    elif change == "action":
        assert state == "ambiguous"
    else:
        assert state == "rejected"


async def test_final_authority_commits_exact_owner_preflight_before_the_single_native_post(db):
    from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords
    from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord

    values = await setup(db)
    _, binding, _, execution, commands, worker, collector, *_ = values
    action = await queued(values)
    observed = []

    async def before_post(context):
        async with db.sessions() as session:
            saved = await session.get(Action, action.id)
            record = await session.get(CheckDispatchRecord, action.id)
        assert saved.state == "dispatching" and not saved.admission and not saved.native_result
        assert saved.upstream_id is None and not execution.submitted
        assert record.payload == context.model_dump(mode="json")
        assert context.operation_digest == action.operation_digest
        assert context.binding_id == binding.id and context.binding_revision == binding.revision
        observed.append(context)

    execution.after_authority = before_post
    assert await worker.advance(action.id) == "admitted"
    assert len(observed) == len(execution.submitted) == 1
    journal = CheckDispatchRecords(commands.bindings, commands.fence)
    stored = await journal.owner_for(
        action.id,
        action.operation_digest,
        execution.ref,
        execution.qualification_for(execution.ref),
    )
    assert stored == observed[0]
    execution.owner_epoch = "f" * 64
    assert (
        await journal.owner_for(
            action.id,
            action.operation_digest,
            execution.ref,
            execution.qualification_for(execution.ref),
        )
        == stored
    )
    assert await collector.collect(action.id, "realm")
    assert len(execution.submitted) == 1


async def test_crash_after_owner_record_before_send_never_becomes_admission_or_retry(db):
    from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords
    from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord

    values = await setup(db)
    _, _, _, execution, commands, worker, collector, *_ = values
    action = await queued(values)

    async def crash(context):
        raise asyncio.CancelledError

    execution.after_authority = crash
    with pytest.raises(asyncio.CancelledError):
        await worker.advance(action.id)
    saved = (await rows(db, Action))[0]
    assert saved.state == "ambiguous" and not saved.admission and not saved.native_result
    assert not execution.submitted and len(await rows(db, CheckDispatchRecord)) == 1
    original = await CheckDispatchRecords(commands.bindings, commands.fence).owner_for(
        action.id,
        action.operation_digest,
        execution.ref,
        execution.qualification_for(execution.ref),
    )
    assert original.owner_epoch == "e" * 64
    assert await worker.advance(action.id) == "ambiguous"
    assert not await collector.collect(action.id, "realm")
    assert not execution.submitted and not (await rows(db, Action))[0].admission


@pytest.mark.parametrize(
    "field",
    [
        "action_id",
        "operation_digest",
        "reference",
        "binding_id",
        "binding_revision",
        "qualification_sha256",
        "contract_sha256",
        "expired",
        "future",
        "state",
    ],
)
async def test_final_context_mismatch_or_expiry_cannot_create_owner_record_or_post(db, field):
    import time

    from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord

    values = await setup(db)
    _, _, _, execution, _, worker, *_ = values
    action = await queued(values)
    submit = execution.submit_check

    async def tampered(ref, payload, identity, authority):
        async def altered(context):
            changes = {
                "action_id": "foreign-action",
                "operation_digest": "a" * 64,
                "reference": ref.model_copy(update={"upstream_session_id": "foreign-root"}),
                "binding_id": "foreign-binding",
                "binding_revision": 99,
                "qualification_sha256": "a" * 64,
                "contract_sha256": "0" * 64,
                "state": "running",
            }
            if field == "expired":
                update = {"issued_at": time.time() - 10, "expires_at": time.time() - 5}
            elif field == "future":
                update = {"issued_at": time.time() + 5, "expires_at": time.time() + 10}
            else:
                update = {field: changes[field]}
            await authority(context.model_copy(update=update))

        return await submit(ref, payload, identity, altered)

    execution.submit_check = tampered
    assert await worker.advance(action.id) == "rejected"
    assert not execution.submitted and not await rows(db, CheckDispatchRecord)
    assert not (await rows(db, Action))[0].admission


async def test_lost_ack_keeps_original_owner_record_and_never_posts_a_second_check(db):
    from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords
    from jt_oz_bridge.storage.check_dispatch_models import CheckDispatchRecord

    values = await setup(db)
    _, _, _, execution, commands, worker, collector, *_ = values
    execution.mode = "lost-ack"
    action = await queued(values)
    assert await worker.advance(action.id) == "ambiguous"
    original = await CheckDispatchRecords(commands.bindings, commands.fence).owner_for(
        action.id,
        action.operation_digest,
        execution.ref,
        execution.qualification_for(execution.ref),
    )
    assert original.owner_epoch == execution.owner_epoch
    assert len(await rows(db, CheckDispatchRecord)) == 1
    assert await collector.collect(action.id, "realm")
    assert await worker.advance(action.id) == "completed"
    assert len(execution.submitted) == 1


async def test_old_action_without_pre_send_record_cannot_borrow_current_native_owner(db):
    from jt_oz_bridge.services.check_dispatch_records import CheckDispatchRecords

    values = await setup(db)
    _, _, _, execution, commands, _, *_ = values
    action = await queued(values)
    with pytest.raises(Conflict, match="original_owner_"):
        await CheckDispatchRecords(commands.bindings, commands.fence).owner_for(
            action.id,
            action.operation_digest,
            execution.ref,
            execution.qualification_for(execution.ref),
        )
    assert not execution.submitted and not (await rows(db, Action))[0].admission
