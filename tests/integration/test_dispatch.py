import asyncio
import logging
import time
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.zulip.budget import RequestBudgetDeferred
from jt_oz_bridge.adapters.zulip.client import ZulipReadUnavailable
from jt_oz_bridge.domain.control import (
    ExecutionState,
    FieldAnswer,
    InteractionSnapshot,
    QuestionField,
)
from jt_oz_bridge.domain.delivery import DeliveryRateLimited
from jt_oz_bridge.domain.execution import (
    Admission,
    AnswerRejected,
    HumanMessage,
    MutationNotSent,
    MutationRejected,
)
from jt_oz_bridge.domain.models import ActionState, Capability
from jt_oz_bridge.services import dispatch as dispatch_module
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.interactions import InteractionService
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.storage.control_models import (
    Binding,
    EnrolledBackend,
    EnrolledProject,
    PendingInteraction,
)
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, WorkerLease
from tests.support import REF, SyntheticControl, bound


class SyntheticExecution(SyntheticControl):
    def __init__(self):
        super().__init__()
        self.state = ExecutionState.IDLE
        self.submitted = []
        self.mode = "success"
        self.entered = asyncio.Event()

    async def snapshot(self, reference):
        result = await super().snapshot(reference)
        return result.model_copy(update={"reference": reference, "state": self.state})

    def capabilities(self, reference):
        return {
            kind: Capability(
                supported=True,
                scope="session",
                reason="synthetic domain test only",
                verification="synthetic_test",
            )
            for kind in ("prompt", "permission.reply", "form.reply", "interrupt")
        }

    async def submit(self, reference, payload, action_id):
        self.submitted.append((reference, payload, action_id))
        self.entered.set()
        if self.mode == "timeout":
            raise TimeoutError("synthetic accepted-request/lost-response")
        if self.mode == "reject":
            raise MutationRejected("synthetic proven rejection")
        if self.mode == "not-sent":
            raise MutationNotSent("synthetic proven unsent operation")
        if self.mode == "invalid-answer":
            raise AnswerRejected("synthetic verified invalid answer")
        if self.mode == "wait":
            await asyncio.Event().wait()
        return Admission(
            status="admitted" if payload["operation"] == "prompt" else "completed",
            upstream_id="fixture:" + action_id,
        )


class SyntheticReader:
    def __init__(self):
        self.messages = {}

    async def read(self, realm, message_id):
        return self.messages[message_id]


@pytest.mark.parametrize("typed_unsent", [True, False])
async def test_only_typed_unsent_rejection_records_fixed_feedback_reason(db, typed_unsent):
    from jt_oz_bridge.domain.execution import MutationNotSent

    worker, binding, native, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await worker.queue.receive(binding.id, message())
    attempts = []

    async def rejected(*args):
        attempts.append(args)
        error = MutationNotSent if typed_unsent else MutationRejected
        raise error("private-backend-token://DO_NOT_DISCLOSE")

    native.submit = rejected
    assert await worker.advance(queued.action_id) == "rejected"
    saved = await worker.load(queued.action_id)
    assert saved.status_reason == ("native_mutation_not_sent" if typed_unsent else None)
    assert not saved.admission and not saved.native_result and saved.upstream_id is None
    assert saved.version == 3
    await DurableStore(db).recover()
    assert await worker.advance(queued.action_id) == "rejected" and len(attempts) == 1


async def test_unsent_reason_is_not_recorded_by_a_replaced_consumer(db):
    from jt_oz_bridge.domain.execution import MutationNotSent

    worker, binding, native, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await worker.queue.receive(binding.id, message())

    async def refused(*args):
        await DurableStore(db).release_lease(worker.holder, worker.fencing)
        assert await DurableStore(db).acquire_lease("replacement")
        raise MutationNotSent("private-reason")

    native.submit = refused
    assert await worker.advance(queued.action_id) == "dispatching"
    saved = await worker.load(queued.action_id)
    assert saved.version == 2 and saved.status_reason is None


def message(message_id=101, revision=1, text="Original text"):
    return HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic="Original work",
        message_id=message_id,
        revision=revision,
        author_id=7,
        text=text,
    )


async def dispatcher(db, **limits):
    execution, reader = SyntheticExecution(), SyntheticReader()
    bindings, binding, _, audience = await bound(db, control=execution)
    holder = "synthetic-dispatcher"
    fence = await DurableStore(db).acquire_lease(holder)
    assert fence is not None
    limits.setdefault(
        "require_control_source", False
    )  # Pure domain fixtures; production default stays strict.
    worker = Dispatcher(bindings, execution, reader, holder, fence, **limits)
    return worker, binding, execution, reader


@pytest.mark.parametrize("outcome", ["success", "reject", "not-sent", "timeout", "cancel"])
async def test_processing_context_clears_after_each_dispatch_outcome(db, outcome):
    observed = []

    @asynccontextmanager
    async def processing(binding):
        observed.append((binding.id, "start"))
        try:
            yield
        finally:
            observed.append((binding.id, "stop"))

    worker, binding, execution, reader = await dispatcher(db, processing=processing)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    execution.mode = "wait" if outcome == "cancel" else outcome
    task = asyncio.create_task(worker.advance(receipt.action_id))
    if outcome == "cancel":
        await execution.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await task
    assert observed == [(binding.id, "start"), (binding.id, "stop")]
    assert len(execution.submitted) == 1


def watch_pending(execution):
    from jt_oz_bridge.domain.models import WATCH_PENDING

    watched = execution.capabilities

    def pending(reference):
        return {
            kind: value.model_copy(update={"supported": False, "reason": WATCH_PENDING})
            for kind, value in watched(reference).items()
        }

    execution.capabilities = pending
    return watched


async def test_a_root_without_its_watch_yet_waits_instead_of_holding(db):
    worker, binding, execution, reader = await dispatcher(db)
    watched = watch_pending(execution)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    # Right after connecting: the prompt stays queued and nothing is sent.
    assert await worker.advance(receipt.action_id) == "queued"
    assert not execution.submitted
    # Watched again: the same prompt goes out.
    execution.capabilities = watched
    assert await worker.advance(receipt.action_id) == "admitted"
    assert len(execution.submitted) == 1


async def test_a_root_still_unwatched_after_the_grace_period_holds_the_prompt(db):
    from jt_oz_bridge.services.dispatch import WATCH_GRACE_SECONDS

    worker, binding, execution, reader = await dispatcher(db)
    watch_pending(execution)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == receipt.action_id)
            .values(created_at=Action.created_at - WATCH_GRACE_SECONDS - 1)
        )
    assert await worker.advance(receipt.action_id) == "held"
    assert not execution.submitted


async def test_paused_dispatch_does_not_start_processing_indicator(db):
    @asynccontextmanager
    async def processing(binding):
        pytest.fail("paused work must not report active processing")
        yield

    worker, binding, execution, reader = await dispatcher(db, processing=processing)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    assert await worker.advance(receipt.action_id) == "held"
    assert not execution.submitted


@pytest.mark.parametrize(
    "failure",
    [RequestBudgetDeferred(60), DeliveryRateLimited(3), ZulipReadUnavailable("read_unavailable")],
)
@pytest.mark.parametrize("phase", ["binding", "source", "queue", "snapshot"])
async def test_typed_preclaim_read_failure_keeps_action_queued_and_rechecks(db, failure, phase):
    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    subject, attribute = {
        "binding": (worker.bindings, "get"),
        "source": (reader, "read"),
        "queue": (worker.queue, "receive"),
        "snapshot": (execution, "snapshot"),
    }[phase]
    original = getattr(subject, attribute)

    async def unavailable(*args, **kwargs):
        raise failure

    setattr(subject, attribute, unavailable)
    with pytest.raises(type(failure)):
        await worker.advance(receipt.action_id)
    saved = await worker.load(receipt.action_id)
    assert saved.state == "queued" and saved.version == 1 and saved.status_reason is None
    assert not execution.submitted
    setattr(subject, attribute, original)
    # A fresh attempt must read the source again; a later edit cannot bypass
    # admission just because the first, unsent attempt ran out of quota.
    reader.messages[101] = message(revision=2, text="Fresh text after read recovery")
    assert await worker.advance(receipt.action_id) == "admitted"
    assert len(execution.submitted) == 1
    assert execution.submitted[0][1]["text"] == "Fresh text after read recovery"


@pytest.mark.parametrize(
    "failure",
    [RequestBudgetDeferred(60), DeliveryRateLimited(3), ZulipReadUnavailable("read_unavailable")],
)
async def test_same_typed_failure_after_native_attempt_is_not_requeued(db, failure):
    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    submit = execution.submit

    async def uncertain(*args):
        await submit(*args)
        raise failure

    execution.submit = uncertain
    assert await worker.advance(receipt.action_id) == "ambiguous"
    assert await worker.advance(receipt.action_id) == "ambiguous"
    assert len(execution.submitted) == 1


async def test_preflight_diagnostic_contains_only_fixed_phase_and_type(db, caplog):
    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())

    async def invalid(*args):
        raise ValueError("private-provider-content-and-credential-fixture")

    reader.read = invalid
    assert await worker.advance(receipt.action_id) == "rejected"
    assert "dispatch_preflight_held phase=source kind=ValueError" in caplog.text
    assert "private-provider-content" not in caplog.text
    assert not execution.submitted


async def test_latest_edit_is_read_before_dispatch_and_admission_is_not_completion(db):
    worker, binding, execution, reader = await dispatcher(db)
    queue = QueueService(worker.bindings)
    first = await queue.receive(binding.id, message())
    duplicate = await queue.receive(binding.id, message())
    assert duplicate.action_id == first.action_id
    await queue.receive(binding.id, message(revision=2, text="Edited queued text"))
    reader.messages[101] = message(revision=3, text="Exact latest text\n  keep spaces  ")
    assert await worker.advance(first.action_id) == "admitted"
    assert len(execution.submitted) == 1
    assert execution.submitted[0][1]["text"] == "Exact latest text\n  keep spaces  "
    assert await worker.advance(first.action_id) == "admitted"
    after = await queue.receive(binding.id, message(revision=4, text="Edit after admission"))
    assert after.already_dispatched and after.state == "admitted"
    assert not await queue.cancel(first.action_id, "realm", 7)
    assert len(execution.submitted) == 1


async def test_deleted_queued_message_cancels_without_upstream_call(db):
    worker, binding, execution, reader = await dispatcher(db)
    queued = await QueueService(worker.bindings).receive(binding.id, message())
    reader.messages[101] = message(revision=2).model_copy(update={"deleted": True})
    assert await worker.advance(queued.action_id) == "cancelled"
    assert execution.submitted == []


async def test_timeout_after_submission_is_ambiguous_and_never_replayed(db):
    worker, binding, execution, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await QueueService(worker.bindings).receive(binding.id, message())
    execution.mode = "timeout"
    assert await worker.advance(queued.action_id) == "ambiguous"
    await DurableStore(db).recover()
    assert await worker.advance(queued.action_id) == "ambiguous"
    assert len(execution.submitted) == 1


async def test_cancel_during_post_persists_ambiguity(db):
    worker, binding, execution, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await QueueService(worker.bindings).receive(binding.id, message())
    execution.mode = "wait"
    pending = asyncio.create_task(worker.advance(queued.action_id))
    await asyncio.wait_for(execution.entered.wait(), 5)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert (await worker.load(queued.action_id)).state == "ambiguous"


async def test_stop_holds_queue_and_old_stop_cannot_pause_a_resumed_queue(db):
    worker, binding, execution, reader = await dispatcher(db)
    queue = QueueService(worker.bindings)
    reader.messages[101] = message()
    queued = await queue.receive(binding.id, message())
    stop = await queue.stop(binding.id, "realm", 7, "stop-event-1")
    assert (await worker.load(queued.action_id)).state == "held"
    execution.state = ExecutionState.RUNNING
    assert await worker.advance(stop) == "completed"
    with pytest.raises(Conflict, match="stale"):
        await queue.resume(binding.id, "realm", 7, 1, 0)
    await queue.resume(binding.id, "realm", 7, 1, 1)
    assert await queue.stop(binding.id, "realm", 7, "stop-event-1") == stop
    async with db.sessions() as session:
        assert not (await session.get(Binding, binding.id)).dispatch_paused
    execution.state = ExecutionState.IDLE
    assert await worker.advance(queued.action_id) == "admitted"


async def test_revoked_actor_and_expired_consumer_lease_cannot_dispatch(db):
    worker, binding, execution, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await QueueService(worker.bindings).receive(binding.id, message())
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
    assert await worker.advance(queued.action_id) == "queued"
    assert execution.submitted == []
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
    assert (
        await worker.advance(queued.action_id) == "queued"
    )  # The expired owner cannot even reject.
    renewed = await DurableStore(db).acquire_lease(worker.holder)
    assert renewed and renewed > worker.fencing
    worker = Dispatcher(
        worker.bindings, execution, reader, worker.holder, renewed, require_control_source=False
    )
    assert await worker.advance(queued.action_id) == "rejected"
    assert execution.submitted == []


async def test_global_session_limit_reserves_before_network_dispatch(db):
    worker, binding, execution, reader = await dispatcher(db, max_global=1, max_backend=1)
    second_ref = REF.model_copy(update={"upstream_session_id": "second-original-session"})
    # This test double acknowledges both references; no live ownership claim is made.
    second = await worker.bindings.bind("realm", 7, 10, "Second topic", second_ref)
    one = message()
    two = message(102).model_copy(update={"topic": "Second topic"})
    reader.messages = {101: one, 102: two}
    queue = QueueService(worker.bindings)
    a, b = await queue.receive(binding.id, one), await queue.receive(second.id, two)
    results = await asyncio.gather(worker.advance(a.action_id), worker.advance(b.action_id))
    assert sorted(results) == ["admitted", "queued"]
    assert len(execution.submitted) == 1
    admitted_id = a.action_id if results[0] == "admitted" else b.action_id
    waiting_id = b.action_id if results[0] == "admitted" else a.action_id
    admitted = await worker.load(admitted_id)
    assert await DurableStore(db).transition(
        admitted_id, ActionState.ADMITTED, ActionState.COMPLETED, admitted.version
    )
    assert await worker.advance(waiting_id) == "admitted"


async def test_independent_dispatcher_instances_cannot_overlap_one_upstream_session(db):
    worker, binding, execution, reader = await dispatcher(db)
    another = Dispatcher(worker.bindings, execution, reader, worker.holder, worker.fencing)
    reader.messages = {101: message(), 102: message(102, text="Second instruction")}
    queue = QueueService(worker.bindings)
    first = await queue.receive(binding.id, reader.messages[101])
    second = await queue.receive(binding.id, reader.messages[102])
    states = await asyncio.gather(
        worker.advance(first.action_id), another.advance(second.action_id)
    )
    assert sorted(states) == ["admitted", "queued"]
    assert len(execution.submitted) == 1


async def test_expired_interaction_reply_held_before_any_post(db):
    worker, binding, execution, reader = await dispatcher(db)
    interactions = InteractionService(worker.bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="pending-1",
        generation="g1",
        kind="permission",
        pending=True,
        description="write",
    )
    execution.requests["pending-1"] = snapshot
    pending = await interactions.observe(binding, snapshot)
    token = await interactions.issue(pending, "realm", 7)
    action_id = await interactions.reply(token, "realm", 7, decision="once")
    async with db.sessions.begin() as session:
        await session.execute(
            update(PendingInteraction)
            .where(PendingInteraction.id == pending)
            .values(expires_at=time.time() - 1)
        )
    assert await worker.advance(action_id) == "held"
    assert execution.submitted == []


async def test_genuine_connector_ack_is_required_to_mark_reply_resolved(db):
    worker, binding, execution, reader = await dispatcher(db)
    interactions = InteractionService(worker.bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="pending-1",
        generation="g1",
        kind="permission",
        pending=True,
        description="write",
    )
    execution.requests["pending-1"] = snapshot
    pending = await interactions.observe(binding, snapshot)
    token = await interactions.issue(pending, "realm", 7)
    action_id = await interactions.reply(token, "realm", 7, decision="once")
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, pending)).state == "reply_queued"
    assert await worker.advance(action_id) == "completed"
    async with db.sessions() as session:
        assert (await session.get(PendingInteraction, pending)).state == "resolved"
        assert (await session.get(Action, action_id)).owner == "opencode"


@pytest.mark.parametrize("revocation", ["backend", "project"])
async def test_prompt_enrollment_revoked_during_snapshot_cannot_reach_post(db, revocation):
    worker, binding, execution, reader = await dispatcher(db)
    reader.messages[101] = message()
    queued = await QueueService(worker.bindings).receive(binding.id, message())
    original = execution.snapshot

    async def snapshot(reference):
        result = await original(reference)
        async with db.sessions.begin() as session:
            if revocation == "backend":
                await session.execute(update(EnrolledBackend).values(enabled=False))
            else:
                await session.execute(update(EnrolledProject).values(enabled=False))
        return result

    execution.snapshot = snapshot
    assert await worker.advance(queued.action_id) == "queued"
    assert execution.submitted == []


@pytest.mark.parametrize(
    "mode,reopen",
    [("invalid-answer", True), ("not-sent", True), ("reject", False), ("timeout", False)],
)
async def test_form_rejection_requires_fresh_token_and_explicit_corrected_reply(db, mode, reopen):
    worker, binding, execution, reader = await dispatcher(db)
    interactions = InteractionService(worker.bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="form-original",
        generation="g1",
        kind="form",
        pending=True,
        description="Original form",
        fields=(QuestionField(id="note", label="Note", kind="text", pattern="upstream-only"),),
    )
    execution.requests[snapshot.upstream_request_id] = snapshot
    pending = await interactions.observe(binding, snapshot)
    token = await interactions.issue(pending, "realm", 7)
    stale = await interactions.issue(pending, "realm", 8)
    action = await interactions.reply(
        token, "realm", 7, answers={"note": FieldAnswer(text="first")}
    )
    execution.mode = mode
    assert await worker.advance(action) == ("ambiguous" if mode == "timeout" else "rejected")
    assert len(execution.submitted) == 1
    async with db.sessions() as session:
        saved = await session.get(PendingInteraction, pending)
        assert saved.state == ("pending" if reopen else "reply_queued")
    with pytest.raises(Conflict):
        await interactions.reply(stale, "realm", 8, answers={"note": FieldAnswer(text="stale")})
    if reopen:
        fresh = await interactions.issue(pending, "realm", 7)
        corrected = await interactions.reply(
            fresh, "realm", 7, answers={"note": FieldAnswer(text="explicit corrected answer")}
        )
        assert corrected != action
        execution.mode = "success"
        assert await worker.advance(corrected) == "completed"
        assert len(execution.submitted) == 2
        assert await worker.advance(action) == "rejected"


async def test_literal_send_is_unwrapped_without_losing_fresh_source_identity(db):
    worker, binding, execution, reader = await dispatcher(db)
    original = message(text='!oz send --   ```python\nprint("!oz stop")\n```\n')
    reader.messages[original.message_id] = original
    receipt = await worker.queue.receive(binding.id, original)
    assert await worker.advance(receipt.action_id) == "admitted"
    sent = execution.submitted[0][1]
    assert sent["text"] == '  ```python\nprint("!oz stop")\n```\n'
    assert sent["source"]["text"] == original.text


async def test_prompt_edited_to_control_command_is_cancelled_without_execution(db):
    worker, binding, execution, reader = await dispatcher(db)
    original = message()
    receipt = await worker.queue.receive(binding.id, original)
    reader.messages[original.message_id] = original.model_copy(
        update={"revision": 2, "text": "!oz stop"}
    )
    assert await worker.advance(receipt.action_id) == "cancelled"
    assert execution.submitted == []


async def test_stale_source_reader_cannot_dispatch_newer_queued_text(db):
    worker, binding, execution, reader = await dispatcher(db)
    original = message()
    receipt = await worker.queue.receive(
        binding.id, original.model_copy(update={"revision": 2, "text": "newer text"})
    )
    reader.messages[original.message_id] = original
    # Refused rather than held, so it cannot stop later messages in the topic.
    assert await worker.advance(receipt.action_id) == "rejected"
    assert (await worker.load(receipt.action_id)).status_reason == "source_or_identity_changed"
    assert execution.submitted == []


@pytest.mark.parametrize(
    "change", [{"revision": 1, "text": "edited control"}, {"deleted": True}, {"author_id": 8}]
)
async def test_changed_permission_source_never_posts_and_fresh_decision_is_required(db, change):
    worker, binding, execution, reader = await dispatcher(db, require_control_source=True)
    interactions = InteractionService(worker.bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="source-permission",
        generation="g1",
        kind="permission",
        pending=True,
        description="inspect source",
    )
    execution.requests[snapshot.upstream_request_id] = snapshot
    identity = await interactions.observe(binding, snapshot)
    token = await interactions.issue(identity, "realm", 7)
    source = message(text="!oz approve " + token + " once", revision=0)
    action = await interactions.reply(token, "realm", 7, decision="once", source=source)
    reader.messages[101] = source.model_copy(update=change)
    assert await worker.advance(action) == "held"
    assert execution.submitted == []
    async with db.sessions() as session:
        request = await session.get(PendingInteraction, identity)
        assert request.state == "pending" and request.action_id is None
    # An original token is consumed; a conscious fresh command is mandatory.
    with pytest.raises(Conflict):
        await interactions.reply(token, "realm", 7, decision="once")
    fresh = await interactions.issue(identity, "realm", 7)
    fresh_source = message(message_id=102, revision=0, text="!oz approve " + fresh + " once")
    reader.messages[102] = fresh_source
    next_action = await interactions.reply(fresh, "realm", 7, decision="once", source=fresh_source)
    assert await worker.advance(next_action) == "completed"
    assert len(execution.submitted) == 1


async def test_strict_dispatch_requires_control_source_and_reports_hold_race_truthfully(db):
    worker, binding, execution, reader = await dispatcher(db, require_control_source=True)
    action_id = await QueueService(worker.bindings).stop(binding.id, "realm", 7, "no-source")
    assert await worker.advance(action_id) == "held"
    assert execution.submitted == []
    # A stale preflight cannot claim it held a concurrently dispatched action.
    receipt = await QueueService(worker.bindings).receive(binding.id, message())
    stale = await worker.load(receipt.action_id)
    assert (
        await DurableStore(db).transition(
            stale.id, ActionState.HELD, ActionState.QUEUED, stale.version
        )
        if stale.state == "held"
        else True
    )
    stale = await worker.load(receipt.action_id)
    assert await DurableStore(db).transition(
        stale.id, ActionState.QUEUED, ActionState.DISPATCHING, stale.version
    )
    assert await worker.held(stale, "stale-preflight") == "dispatching"


async def test_ambiguous_prompt_blocks_later_prompts_even_if_backend_snapshot_is_idle(db):
    worker, binding, execution, reader = await dispatcher(db)
    first = message()
    reader.messages[101] = first
    one = await worker.queue.receive(binding.id, first)
    execution.mode = "timeout"
    assert await worker.advance(one.action_id) == "ambiguous"
    reader.messages[102] = message(message_id=102, text="later prompt")
    two = await worker.queue.receive(binding.id, reader.messages[102])
    execution.mode = "success"
    assert await worker.advance(two.action_id) == "queued"
    assert len(execution.submitted) == 1


async def test_unadmitted_expired_decision_returns_to_visible_expired_state_without_renewal(db):
    worker, binding, execution, reader = await dispatcher(db, require_control_source=True)
    interactions = InteractionService(worker.bindings)
    snapshot = InteractionSnapshot(
        reference=REF,
        upstream_request_id="expired-before-dispatch",
        generation="g1",
        kind="permission",
        pending=True,
        description="pending",
    )
    execution.requests[snapshot.upstream_request_id] = snapshot
    identity = await interactions.observe(binding, snapshot)
    token = await interactions.issue(identity, "realm", 7)
    source = message(revision=0, text="!oz approve " + token + " once")
    reader.messages[101] = source
    action = await interactions.reply(token, "realm", 7, decision="once", source=source)
    async with db.sessions.begin() as session:
        await session.execute(
            update(PendingInteraction).where(PendingInteraction.id == identity).values(expires_at=0)
        )
    assert await worker.advance(action) == "held"
    assert execution.submitted == []
    async with db.sessions() as session:
        request = await session.get(PendingInteraction, identity)
        assert request.state == "pending" and request.expires_at == 0 and request.action_id is None
    with pytest.raises(Conflict, match="expired"):
        await interactions.issue(identity, "realm", 7)


async def _fifo_raw_row(db, action_id):
    """Ciphertext and every original SQL column, not a re-encrypted ORM copy."""
    from sqlalchemy import text

    async with db.sessions() as session:
        result = await session.execute(
            text("SELECT * FROM actions WHERE id = :identity"), {"identity": action_id}
        )
        return tuple(result.one())


@pytest.mark.parametrize("earlier_operation", ["prompt", "model.switch", "check.run"])
@pytest.mark.parametrize("earlier_state", ["queued", "held"])
async def test_fifo_denial_hint_precedes_every_direct_remote_and_processing(
    db, monkeypatch, earlier_operation, earlier_state
):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.storage.durable import digest

    processing_events = []

    @asynccontextmanager
    async def processing(binding):
        processing_events.append(binding.id)
        yield

    worker, binding, execution, reader = await dispatcher(db, processing=processing)
    earlier = await worker.queue.receive(binding.id, message(), recovered=earlier_state == "held")
    later = await worker.queue.receive(binding.id, message(102, text="Later original work"))
    # Test only the existing indexed FIFO predicate; these synthetic barrier
    # rows do not claim a certified Native check/model selection.
    async with db.sessions.begin() as session:
        row = await session.get(Action, earlier.action_id)
        payload = {**row.payload, "operation": earlier_operation}
        row.payload, row.operation, row.operation_digest = (
            payload,
            earlier_operation,
            digest(payload),
        )
    original = await _fifo_raw_row(db, earlier.action_id)
    remote = AsyncMock(side_effect=AssertionError("blocked work must perform zero remote reads"))
    with monkeypatch.context() as patch:
        patch.setattr(worker.bindings, "get", remote)
        patch.setattr(reader, "read", remote)
        patch.setattr(execution, "snapshot", remote)
        assert await worker.advance(later.action_id) == "queued"
    remote.assert_not_awaited()
    assert not processing_events and not execution.submitted
    assert (await worker.load(later.action_id)).state == "queued"
    assert await _fifo_raw_row(db, earlier.action_id) == original


async def test_explicit_fifo_cancel_then_fresh_preflight_submits_only_later_original_once(
    db, monkeypatch
):
    from unittest.mock import AsyncMock

    from jt_oz_bridge.storage.fencing import ConsumerFence

    worker, binding, execution, reader = await dispatcher(db)
    old = await worker.queue.receive(binding.id, message(), recovered=True)
    current = message(102, text="Fresh work after explicit cancellation")
    new = await worker.queue.receive(binding.id, current)
    reader.messages[102] = current
    original = await _fifo_raw_row(db, old.action_id)
    assert await worker.advance(new.action_id) == "queued"
    assert await _fifo_raw_row(db, old.action_id) == original and not execution.submitted
    queue = QueueService(worker.bindings, fence=ConsumerFence(worker.holder, worker.fencing))
    assert await queue.cancel(old.action_id, "realm", 7)
    source = AsyncMock(wraps=reader.read)
    native = AsyncMock(wraps=execution.snapshot)
    with monkeypatch.context() as patch:
        patch.setattr(reader, "read", source)
        patch.setattr(execution, "snapshot", native)
        assert await worker.advance(new.action_id) == "admitted"
        assert await worker.advance(new.action_id) == "admitted"
    assert source.await_count == native.await_count == 1
    assert len(execution.submitted) == 1 and execution.submitted[0][2] == new.action_id
    cancelled = await worker.load(old.action_id)
    assert cancelled.state == "cancelled" and cancelled.upstream_id is None


async def test_fifo_earlier_queued_original_keeps_order_until_its_terminal_result(db):
    worker, binding, execution, reader = await dispatcher(db)
    reader.messages = {101: message(), 102: message(102, text="Second original")}
    first = await worker.queue.receive(binding.id, reader.messages[101])
    second = await worker.queue.receive(binding.id, reader.messages[102])
    assert await worker.advance(second.action_id) == "queued"
    assert not execution.submitted
    assert await worker.advance(first.action_id) == "admitted"
    assert await worker.advance(second.action_id) == "queued"  # admitted owner is still active
    saved = await worker.load(first.action_id)
    assert await worker.store.transition(
        first.action_id, ActionState.ADMITTED, ActionState.COMPLETED, saved.version
    )
    assert await worker.advance(second.action_id) == "admitted"
    assert [item[2] for item in execution.submitted] == [first.action_id, second.action_id]


async def test_fifo_hint_false_is_not_authority_when_another_session_wins_final_capacity(
    db, monkeypatch
):
    from unittest.mock import AsyncMock

    worker, binding, execution, reader = await dispatcher(db, max_global=1, max_backend=1)
    second_ref = REF.model_copy(update={"upstream_session_id": "other-original-session"})
    other_binding = await worker.bindings.bind("realm", 7, 10, "Other topic", second_ref)
    reader.messages = {
        101: message(),
        102: message(102).model_copy(update={"topic": "Other topic"}),
    }
    first = await worker.queue.receive(binding.id, reader.messages[101])
    other = await worker.queue.receive(other_binding.id, reader.messages[102])
    competitor = Dispatcher(
        worker.bindings,
        execution,
        reader,
        worker.holder,
        worker.fencing,
        max_global=1,
        max_backend=1,
        require_control_source=False,
    )
    original_read = reader.read
    raced = False

    async def read_after_hint(realm, identity):
        nonlocal raced
        if identity == 101 and not raced:
            raced = True
            assert await competitor.advance(other.action_id) == "admitted"
        return await original_read(realm, identity)

    claim = AsyncMock(wraps=worker.claim)
    with monkeypatch.context() as patch:
        patch.setattr(reader, "read", read_after_hint)
        patch.setattr(worker, "claim", claim)
        assert await worker.advance(first.action_id) == "queued"
    assert raced and claim.await_count == 1
    assert len(execution.submitted) == 1 and execution.submitted[0][2] == other.action_id
    assert (await worker.load(first.action_id)).state == "queued"


async def test_a_refused_prompt_does_not_stop_the_next_one(db):
    worker, binding, execution, reader = await dispatcher(db)
    original = message()
    first = await worker.queue.receive(
        binding.id, original.model_copy(update={"revision": 2, "text": "newer text"})
    )
    reader.messages[101] = original  # The reader cannot confirm the queued text.
    second = await worker.queue.receive(binding.id, message(message_id=102))
    reader.messages[102] = message(message_id=102)
    assert await worker.blocked_by_fifo(second.action_id)
    assert await worker.advance(first.action_id) == "rejected"
    assert not await worker.blocked_by_fifo(second.action_id)
    assert await worker.advance(second.action_id) == "admitted"
    assert [item[2] for item in execution.submitted] == [second.action_id]


async def test_an_older_topic_revision_never_blocks_the_current_queue(db):
    worker, binding, execution, reader = await dispatcher(db)
    stale = await worker.queue.receive(binding.id, message())
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == stale.action_id)
            .values(state="held", binding_revision=binding.revision - 1)
        )
    current = await worker.queue.receive(binding.id, message(message_id=102))
    reader.messages[102] = message(message_id=102)
    assert not await worker.blocked_by_fifo(current.action_id)
    assert await worker.advance(current.action_id) == "admitted"
    # The same held action in the current revision still keeps the order.
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == stale.action_id)
            .values(binding_revision=binding.revision)
        )
    later = await worker.queue.receive(binding.id, message(message_id=103))
    assert await worker.blocked_by_fifo(later.action_id)


@pytest.mark.parametrize("kind", ["transport", "boundary", "unreconciled"])
async def test_a_briefly_unreachable_backend_is_retried_not_held(db, caplog, kind):
    from jt_oz_bridge.adapters.opencode.contracts import SnapshotBoundaryChanged
    from jt_oz_bridge.adapters.opencode.transport import TransportError

    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    snapshot = execution.snapshot

    async def unavailable(reference):
        if kind == "transport":
            raise TransportError("upstream_transport_or_encoding_error")
        if kind == "boundary":
            raise SnapshotBoundaryChanged("snapshot_boundary_changed")
        result = await snapshot(reference)
        return result.model_copy(update={"reconciled": False})

    execution.snapshot = unavailable
    assert await worker.advance(receipt.action_id) == "queued"
    assert await worker.advance(receipt.action_id) == "queued"
    saved = await worker.load(receipt.action_id)
    assert saved.status_reason is None and not execution.submitted
    assert "dispatch_preflight_retry phase=" in caplog.text
    assert "dispatch_preflight_held" not in caplog.text
    execution.snapshot = snapshot
    assert await worker.advance(receipt.action_id) == "admitted"
    assert receipt.action_id not in worker._transient


async def test_a_backend_unreachable_for_too_long_refuses_the_prompt(db):
    from jt_oz_bridge.adapters.opencode.transport import TransportError
    from jt_oz_bridge.services.dispatch import TRANSIENT_RETRY_SECONDS

    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()

    async def unavailable(reference):
        raise TransportError("upstream_transport_or_encoding_error")

    execution.snapshot = unavailable
    assert await worker.advance(receipt.action_id) == "queued"
    worker._transient[receipt.action_id] -= TRANSIENT_RETRY_SECONDS + 1
    assert await worker.advance(receipt.action_id) == "rejected"
    saved = await worker.load(receipt.action_id)
    assert saved.status_reason == "preflight_unavailable" and not execution.submitted
    assert receipt.action_id not in worker._transient


async def test_an_opencode_state_refusal_is_read_again_then_named_plainly(db, caplog):
    # Right after `!ok` reconnects a topic, the next prompts can meet a contract
    # refusal reading OpenCode's state while a reply is still running. They must
    # not be refused at once as "changed or could not be confirmed" when the
    # messages are untouched and a later read would pass.
    from jt_oz_bridge.adapters.opencode.contracts import ContractError
    from jt_oz_bridge.services.dispatch import TRANSIENT_RETRY_SECONDS

    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    snapshot = execution.snapshot

    async def refused(reference):
        raise ContractError("leaf_pending_scope_changed")

    execution.snapshot = refused
    assert await worker.advance(receipt.action_id) == "queued"
    assert (await worker.load(receipt.action_id)).status_reason is None
    assert "phase=native_snapshot kind=ContractError code=leaf_pending_scope_changed" in (
        caplog.text
    )
    execution.snapshot = snapshot
    assert await worker.advance(receipt.action_id) == "admitted" and execution.submitted
    assert receipt.action_id not in worker._transient

    second = await worker.queue.receive(binding.id, message(message_id=102))
    reader.messages[102] = message(message_id=102)
    execution.snapshot = refused
    assert await worker.advance(second.action_id) == "queued"
    worker._transient[second.action_id] -= TRANSIENT_RETRY_SECONDS + 1
    assert await worker.advance(second.action_id) == "rejected"
    assert (await worker.load(second.action_id)).status_reason == "native_state_unconfirmed"


async def test_a_passing_read_that_is_not_claimed_keeps_the_retry_window(db):
    # A prompt behind an uncollected turn can be refused, read once more
    # successfully but not claimed, then refused again. A passing read must not
    # restart the five-minute window, or the prompt would never be refused.
    from jt_oz_bridge.adapters.opencode.contracts import ContractError

    worker, binding, execution, reader = await dispatcher(db)
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    snapshot = execution.snapshot

    async def refused(reference):
        raise ContractError("leaf_pending_scope_changed")

    execution.snapshot = refused
    assert await worker.advance(receipt.action_id) == "queued"
    first = worker._transient[receipt.action_id]
    execution.snapshot = snapshot
    claim = worker.claim

    async def not_yet(*args, **kwargs):
        return False

    worker.claim = not_yet
    assert await worker.advance(receipt.action_id) == "queued"
    assert worker._transient[receipt.action_id] == first
    worker.claim = claim
    assert await worker.advance(receipt.action_id) == "admitted"
    assert receipt.action_id not in worker._transient


def test_only_a_code_shaped_refusal_is_logged():
    from jt_oz_bridge.services.dispatch import error_code

    assert error_code(ValueError("leaf_pending_scope_changed")) == "leaf_pending_scope_changed"
    assert error_code(ValueError("text with Source words")) == "-"
    assert error_code(ValueError("x" * 81)) == "-"


@pytest.mark.parametrize("restored", [True, False])
async def test_a_root_waiting_for_its_restore_retry_keeps_the_prompt_then_says_so(
    db, caplog, restored
):
    # A chat-created Root that cannot be restored at startup stays unregistered
    # and is retried; its topic's prompt must not vanish silently meanwhile.
    from jt_oz_bridge.security.policy import AccessDenied
    from jt_oz_bridge.services.dispatch import TRANSIENT_RETRY_SECONDS

    worker, binding, execution, reader = await dispatcher(db)
    capabilities = execution.capabilities

    def unregistered(reference):
        raise AccessDenied("original_session_not_registered")

    execution.capabilities = unregistered
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    assert await worker.advance(receipt.action_id) == "queued"
    assert (await worker.load(receipt.action_id)).status_reason is None
    assert "dispatch_preflight_retry phase=" in caplog.text
    if restored:
        execution.capabilities = capabilities
        assert await worker.advance(receipt.action_id) == "admitted" and execution.submitted
    else:
        worker._transient[receipt.action_id] -= TRANSIENT_RETRY_SECONDS + 1
        assert await worker.advance(receipt.action_id) == "rejected"
        saved = await worker.load(receipt.action_id)
        assert saved.status_reason == "session_unavailable" and not execution.submitted
    assert receipt.action_id not in worker._transient


async def test_other_refusals_are_not_retried_as_an_unregistered_root(db):
    from jt_oz_bridge.security.policy import AccessDenied

    worker, binding, execution, reader = await dispatcher(db)

    def revoked(reference):
        raise AccessDenied("permission denied")

    execution.capabilities = revoked
    receipt = await worker.queue.receive(binding.id, message())
    reader.messages[101] = message()
    assert await worker.advance(receipt.action_id) == "rejected"
    saved = await worker.load(receipt.action_id)
    assert saved.status_reason == "authorization_revoked" and not execution.submitted
    assert receipt.action_id not in worker._transient


class SteeringExecution(SyntheticExecution):
    """A synthetic adapter that can join a running turn; never installed evidence."""

    def __init__(self):
        super().__init__()
        self.steered = []
        self.steer_ready = True

    def steer_supported(self, reference):
        return True

    async def submit(self, reference, payload, action_id, *, steer=False):
        if not steer:
            return await super().submit(reference, payload, action_id)
        self.steered.append(action_id)
        if not self.steer_ready:
            from jt_oz_bridge.domain.execution import SteerNotReady

            raise SteerNotReady("synthetic: the running turn ended before the post")
        return Admission(
            status="admitted",
            upstream_id="fixture:" + action_id,
            details={"operation": "prompt", "delivery": "steer", "turn_completed": False},
        )


@pytest.fixture
def steering(monkeypatch):
    """Steering into a running turn, the release default, pinned on for these tests."""
    monkeypatch.setattr(dispatch_module, "STEER_INTO_RUNNING_TURNS", True)


async def steering_dispatcher(db):
    execution, reader = SteeringExecution(), SyntheticReader()
    bindings, binding, _, _audience = await bound(db, control=execution)
    holder = "synthetic-dispatcher"
    fence = await DurableStore(db).acquire_lease(holder)
    worker = Dispatcher(bindings, execution, reader, holder, fence, require_control_source=False)
    return worker, binding, execution, reader


async def queued_prompt(worker, binding, reader, identity, text):
    reader.messages[identity] = message(identity, text=text)
    return (await worker.queue.receive(binding.id, reader.messages[identity])).action_id


async def test_with_steering_off_a_message_sent_while_a_turn_runs_waits(db, monkeypatch):
    """With steering switched off: the ordinary queue, no steer."""
    monkeypatch.setattr(dispatch_module, "STEER_INTO_RUNNING_TURNS", False)
    worker, binding, execution, reader = await steering_dispatcher(db)
    first = await queued_prompt(worker, binding, reader, 101, "Write the report")
    assert await worker.advance(first) == "admitted"
    execution.state = ExecutionState.RUNNING
    second = await queued_prompt(worker, binding, reader, 102, "Make it shorter")
    assert await worker.advance(second) == "queued"
    assert execution.steered == [] and len(execution.submitted) == 1
    assert (await worker.load(second)).status_reason is None


async def test_an_uncertain_send_says_why_in_codes_only(db, steering, caplog):
    worker, binding, execution, reader = await steering_dispatcher(db)
    first = await queued_prompt(worker, binding, reader, 101, "Write the report")
    assert await worker.advance(first) == "admitted"
    execution.state = ExecutionState.RUNNING

    async def unknown(reference, payload, action_id, *, steer=False):
        from jt_oz_bridge.adapters.opencode.transport import TransportError

        raise TransportError("native_mutation_write_outcome_unknown")

    execution.submit = unknown
    second = await queued_prompt(worker, binding, reader, 102, "Make it shorter")
    with caplog.at_level(logging.WARNING, logger="jt_oz_bridge.services.dispatch"):
        assert await worker.advance(second) == "ambiguous"
    assert (
        "dispatch_outcome_uncertain operation=prompt steer=True kind=TransportError "
        "code=native_mutation_write_outcome_unknown"
    ) in caplog.text
    assert "Make it shorter" not in caplog.text


async def test_a_prompt_whose_proof_moved_at_the_wire_goes_again_after_a_fresh_preflight(
    db, caplog
):
    from jt_oz_bridge.domain.execution import SEND_PROOF_MOVED, MutationNotSent

    worker, binding, execution, reader = await steering_dispatcher(db)
    calls = []
    ordinary = execution.submit

    async def moved(reference, payload, action_id, *, steer=False):
        calls.append(action_id)
        if len(calls) < 3:
            raise MutationNotSent(SEND_PROOF_MOVED)
        return await ordinary(reference, payload, action_id)

    execution.submit = moved
    first = await queued_prompt(worker, binding, reader, 101, "Write the report")
    with caplog.at_level(logging.WARNING, logger="jt_oz_bridge.services.dispatch"):
        # Proven unsent twice: each time back in its place, then sent after a fresh preflight.
        assert await worker.advance(first) == "queued"
        saved = await worker.load(first)
        assert (saved.status_reason, saved.version) == (dispatch_module.SEND_RETRY, 3)
        assert await worker.advance(first) == "queued"
        assert await worker.advance(first) == "admitted"
    assert calls == [first] * 3 and first not in worker._unsent
    assert caplog.text.count(f"dispatch_send_retry operation=prompt code={SEND_PROOF_MOVED}") == 2
    assert "Write the report" not in caplog.text


async def test_a_prompt_whose_proof_keeps_moving_is_refused_after_the_window(db, monkeypatch):
    from jt_oz_bridge.domain.execution import SEND_PROOF_MOVED, MutationNotSent

    worker, binding, execution, reader = await steering_dispatcher(db)

    async def always_moved(reference, payload, action_id, *, steer=False):
        raise MutationNotSent(SEND_PROOF_MOVED)

    execution.submit = always_moved
    clock = [0.0]
    monkeypatch.setattr(dispatch_module.time, "monotonic", lambda: clock[0])
    prompt = await queued_prompt(worker, binding, reader, 102, "Make it shorter")
    assert await worker.advance(prompt) == "queued"
    clock[0] = dispatch_module.TRANSIENT_RETRY_SECONDS - 1
    assert await worker.advance(prompt) == "queued"  # The window runs from the first try.
    clock[0] = dispatch_module.TRANSIENT_RETRY_SECONDS
    assert await worker.advance(prompt) == "rejected"
    assert prompt not in worker._unsent


async def test_busy_session_new_messages_steer_into_the_running_turn_one_by_one(
    db, steering, caplog
):
    worker, binding, execution, reader = await steering_dispatcher(db)
    first = await queued_prompt(worker, binding, reader, 101, "Write the report")
    assert await worker.advance(first) == "admitted"
    assert execution.steered == [] and len(execution.submitted) == 1  # Idle: its own turn.
    execution.state = ExecutionState.RUNNING
    second = await queued_prompt(worker, binding, reader, 102, "Make it shorter")
    third = await queued_prompt(worker, binding, reader, 103, "And in English")
    # FIFO: the newer message waits while the older one is not yet sent.
    assert await worker.blocked_by_fifo(third)
    with caplog.at_level(logging.WARNING, logger="jt_oz_bridge.services.dispatch"):
        assert await worker.advance(second) == "admitted"
        assert await worker.advance(third) == "admitted"
    assert execution.steered == [second, third] and len(execution.submitted) == 1
    assert [r.getMessage() for r in caplog.records] == ["dispatch_steered"] * 2
    for identity in (second, third):
        saved = await worker.load(identity)
        assert saved.admission["admission"]["details"]["delivery"] == "steer"
        assert saved.upstream_id == "fixture:" + identity  # Its own inbox ID correlates it.
    # Idle again but earlier turns are not collected yet: wait, as before steering.
    execution.state = ExecutionState.IDLE
    later = await queued_prompt(worker, binding, reader, 104, "Next task")
    assert await worker.advance(later) == "queued"
    assert execution.steered == [second, third] and len(execution.submitted) == 1


async def test_a_prompt_that_cannot_steer_now_is_not_attempted_while_busy(db, steering):
    worker, binding, execution, reader = await steering_dispatcher(db)
    first = await queued_prompt(worker, binding, reader, 101, "Write the report")
    assert await worker.advance(first) == "admitted"
    second = await queued_prompt(worker, binding, reader, 102, "Make it shorter")
    row = await worker.load(second)
    assert await worker.join_hint(row, binding) == frozenset({"running", "queued"})
    # An uncertain turn is in flight: the poll waits for idle instead of re-reading
    # the message's source every pass. A stop's parked inputs may still be woken.
    async with db.sessions.begin() as session:
        await session.execute(update(Action).where(Action.id == first).values(state="ambiguous"))
    assert await worker.join_hint(row, binding) == frozenset({"queued"})
    # An adapter that cannot read the inbox never steers.
    execution.steer_supported = lambda reference: False
    assert await worker.join_hint(row, binding) == frozenset()


async def test_idle_session_keeps_the_ordinary_queued_turn_with_a_steering_adapter(db):
    worker, binding, execution, reader = await steering_dispatcher(db)
    identity = await queued_prompt(worker, binding, reader, 101, "Hello")
    assert await worker.advance(identity) == "admitted"
    assert execution.steered == [] and [s[2] for s in execution.submitted] == [identity]


@pytest.mark.parametrize("state", [ExecutionState.WAITING_PERMISSION, ExecutionState.WAITING_INPUT])
async def test_waiting_on_a_question_or_permission_does_not_steer(db, state):
    worker, binding, execution, reader = await steering_dispatcher(db)
    execution.state = state
    identity = await queued_prompt(worker, binding, reader, 101, "Hello")
    assert await worker.advance(identity) == "queued"
    assert not execution.steered and not execution.submitted


async def test_a_steer_the_turn_missed_keeps_its_place_for_its_own_turn(db, steering, caplog):
    worker, binding, execution, reader = await steering_dispatcher(db)
    execution.state, execution.steer_ready = ExecutionState.RUNNING, False
    identity = await queued_prompt(worker, binding, reader, 101, "Hello")
    with caplog.at_level(logging.WARNING, logger="jt_oz_bridge.services.dispatch"):
        assert await worker.advance(identity) == "queued"
    # Code-shaped only; this synthetic reason is prose, so it shows as "-".
    assert [r.getMessage() for r in caplog.records] == ["dispatch_steer_deferred code=-"]
    saved = await worker.load(identity)
    assert saved.version == 3 and saved.upstream_id is None
    assert saved.status_reason == "steer_not_ready"
    # Never offered as a steer again: it waits for an idle session and its own turn.
    execution.steer_ready = True
    assert await worker.advance(identity) == "queued" and execution.steered == [identity]
    execution.state = ExecutionState.QUEUED
    assert await worker.advance(identity) == "queued" and execution.steered == [identity]
    execution.state = ExecutionState.IDLE
    assert await worker.advance(identity) == "admitted"
    assert [s[2] for s in execution.submitted] == [identity]


async def test_held_and_resumed_prompts_never_steer(db):
    worker, binding, execution, reader = await steering_dispatcher(db)
    execution.state = ExecutionState.RUNNING
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
        )
    held = await queued_prompt(worker, binding, reader, 101, "Sent while paused")
    assert (await worker.load(held)).state == "held"
    current = await worker.bindings.get(binding.id, "realm", 7)
    await worker.queue.resume(binding.id, "realm", 7, current.revision, current.queue_revision)
    assert (await worker.load(held)).state == "queued"
    assert await worker.advance(held) == "queued"  # Resumed: only an ordinary turn.
    assert not execution.steered and not execution.submitted


def test_attachments_schedules_and_changed_rows_are_not_steer_candidates():
    def row(**changes):
        payload = {"operation": "prompt", "text": "x", **changes.pop("payload", {})}
        values = {
            "operation": "prompt",
            "payload": payload,
            "state": "queued",
            "version": 1,
            "status_reason": None,
        }
        return Action(**{**values, **changes})

    assert Dispatcher.steer_candidate(row())
    for extra in (
        "attachments",
        "workspace_attachments",
        "_attachment_import",
        "_workspace_attachment_import",
        "schedule",
    ):
        assert not Dispatcher.steer_candidate(row(payload={extra: {}}))
    assert not Dispatcher.steer_candidate(row(version=2))
    assert not Dispatcher.steer_candidate(row(status_reason="queue_paused"))
    assert not Dispatcher.steer_candidate(row(operation="check.run"))
    assert not Dispatcher.steer_candidate(row(state="held"))


async def test_stop_while_a_steer_is_pending_stops_once_and_the_steer_stays_sent(db, steering):
    worker, binding, execution, reader = await steering_dispatcher(db)
    first = await queued_prompt(worker, binding, reader, 101, "Long task")
    assert await worker.advance(first) == "admitted"
    execution.state = ExecutionState.RUNNING
    steer = await queued_prompt(worker, binding, reader, 102, "Change of plan")
    assert await worker.advance(steer) == "admitted"
    stop = await worker.queue.request_stop(binding.id, "realm", 7, "stop-during-steer")
    assert await worker.advance(stop.interrupt_action_id) == "completed"
    interrupt = [s for s in execution.submitted if s[1]["operation"] == "interrupt"]
    assert len(interrupt) == 1  # One stop; the steer is never resent or cancelled here.
    assert (await worker.load(steer)).state == "admitted"
    # A steer OpenCode had not read yet stays parked in its inbox; the topic is paused.
    execution.state = ExecutionState.QUEUED
    after = await queued_prompt(worker, binding, reader, 103, "Go on")
    assert (await worker.load(after)).state == "held"
    assert await worker.advance(after) == "held" and execution.steered == [steer]
    current = await worker.bindings.get(binding.id, "realm", 7)
    await worker.queue.resume(binding.id, "realm", 7, current.revision, current.queue_revision)
    # After `!go` the resumed message wakes the parked steer and runs after it.
    assert await worker.advance(after) == "admitted" and execution.steered == [steer, after]


async def test_a_fresh_message_wakes_steers_parked_by_a_stop(db, steering):
    worker, binding, execution, reader = await steering_dispatcher(db)
    first = await queued_prompt(worker, binding, reader, 101, "Long task")
    assert await worker.advance(first) == "admitted"
    execution.state = ExecutionState.RUNNING
    parked = await queued_prompt(worker, binding, reader, 102, "Change of plan")
    assert await worker.advance(parked) == "admitted"
    # Stopped before OpenCode read it: no execution, only the parked steer waits.
    execution.state = ExecutionState.QUEUED
    fresh = await queued_prompt(worker, binding, reader, 103, "Now continue")
    assert await worker.advance(fresh) == "admitted"
    assert execution.steered == [parked, fresh]


async def test_a_busy_snapshot_that_moves_keeps_a_steerable_prompt_queued_not_held(db, steering):
    from jt_oz_bridge.adapters.opencode.contracts import SnapshotBoundaryChanged

    worker, binding, execution, reader = await steering_dispatcher(db)
    execution.state = ExecutionState.RUNNING
    identity = await queued_prompt(worker, binding, reader, 101, "Hello")
    original = execution.snapshot

    async def moved(reference):
        raise SnapshotBoundaryChanged("leaf_resource_or_feed_boundary_changed")

    execution.snapshot = moved
    assert await worker.advance(identity) == "queued"
    saved = await worker.load(identity)
    assert saved.version == 1 and saved.status_reason is None
    execution.snapshot = original
    assert await worker.advance(identity) == "admitted" and execution.steered == [identity]


async def test_an_exclusive_workspace_still_lets_a_steer_join_its_own_running_turn(db, steering):
    from jt_oz_bridge.domain.worktree_switch import WorkspaceConcurrencyPolicy

    worker, binding, execution, reader = await steering_dispatcher(db)
    worker.configure_workspace_policies(
        (
            WorkspaceConcurrencyPolicy(
                backend_id=REF.backend_id,
                backend_identity=REF.backend_identity,
                canonical_directory=REF.canonical_directory,
                device=1,
                inode=2,
                mode="exclusive",
            ),
        )
    )
    first = await queued_prompt(worker, binding, reader, 101, "Long task")
    assert await worker.advance(first) == "admitted"
    execution.state = ExecutionState.RUNNING
    steer = await queued_prompt(worker, binding, reader, 102, "Change of plan")
    assert await worker.advance(steer) == "admitted" and execution.steered == [steer]
    # An idle turn still waits for the workspace like before.
    execution.state = ExecutionState.IDLE
    later = await queued_prompt(worker, binding, reader, 103, "Next")
    assert await worker.advance(later) == "queued"


class ReadbackExecution(SyntheticExecution):
    """An OpenCode session that holds the user messages listed in `landed`."""

    def __init__(self):
        super().__init__()
        self.landed = {}
        self.readbacks = []
        self.absent = False

    async def prompt_readback(self, reference, action_id, operation_digest, text):
        self.readbacks.append(action_id)
        found = self.landed.get((action_id, operation_digest))
        if found is not None and found[1] != text:
            raise ContractError("v2_prompt_readback_mismatch")
        return found[0] if found is not None else None

    async def prompt_never_arrived(self, reference, action_id, operation_digest, sent_after):
        return self.absent


async def uncertain_prompt(db, monkeypatch, **payload):
    monkeypatch.setattr("jt_oz_bridge.services.dispatch.UNCERTAIN_PROMPT_SETTLE_SECONDS", 0)
    execution, reader = ReadbackExecution(), SyntheticReader()
    bindings, binding, _, audience = await bound(db, control=execution)
    fence = await DurableStore(db).acquire_lease("synthetic-dispatcher")
    worker = Dispatcher(
        bindings, execution, reader, "synthetic-dispatcher", fence, require_control_source=False
    )
    reader.messages[101] = message()
    one = await worker.queue.receive(binding.id, message())
    execution.mode = "timeout"
    assert await worker.advance(one.action_id) == "ambiguous"
    execution.mode = "success"
    if payload:
        async with db.sessions.begin() as session:
            saved = await session.get(Action, one.action_id)
            changed = {**saved.payload, **payload}
            await session.execute(
                update(Action)
                .where(Action.id == one.action_id)
                .values(payload=changed, operation_digest=digest(changed))
            )
    return worker, binding, execution, await worker.load(one.action_id)


async def test_an_uncertain_prompt_opencode_holds_is_admitted_from_its_own_message(db, monkeypatch):
    """A prompt whose send failed after reaching OpenCode must not stay uncertain
    once OpenCode has answered it, holding every later message of the topic. Its
    own tagged user message is the admission it lost.
    """
    from jt_oz_bridge.services.execution_receipts import native_receipt
    from jt_oz_bridge.services.resource_execution_results import correlation

    worker, binding, execution, action = await uncertain_prompt(db, monkeypatch)
    execution.landed[(action.id, action.operation_digest)] = ("msg_landed01", "Original text")
    assert await worker.reconcile_uncertain_prompts() == 1
    saved = await worker.load(action.id)
    assert saved.state == "admitted" and saved.upstream_id == "msg_landed01"
    assert native_receipt(saved).admission.upstream_id == "msg_landed01"
    assert correlation(saved).upstream_id == "msg_landed01"
    assert len(execution.submitted) == 1  # read back, never sent again
    assert await worker.reconcile_uncertain_prompts() == 0
    async with db.sessions() as session:
        events = (
            await session.scalars(select(AuditEvent.event).where(AuditEvent.object_id == action.id))
        ).all()
    assert "uncertain_prompt_read_back_admitted" in events


async def test_an_uncertain_prompt_not_found_stays_uncertain_and_unsent(db, monkeypatch):
    worker, binding, execution, action = await uncertain_prompt(db, monkeypatch)
    assert await worker.reconcile_uncertain_prompts() == 0
    assert execution.readbacks == [action.id]
    saved = await worker.load(action.id)
    assert saved.state == "ambiguous" and saved.upstream_id is None and not saved.admission
    assert len(execution.submitted) == 1


async def test_a_differing_message_with_the_same_tag_is_not_an_admission(db, monkeypatch, caplog):
    worker, binding, execution, action = await uncertain_prompt(db, monkeypatch)
    execution.landed[(action.id, action.operation_digest)] = ("msg_landed01", "other text")
    with caplog.at_level(logging.WARNING):
        assert await worker.reconcile_uncertain_prompts() == 0
    assert (await worker.load(action.id)).state == "ambiguous"
    assert "code=v2_prompt_readback_mismatch" in caplog.text


async def test_a_fresh_uncertain_prompt_is_not_read_back_yet(db, monkeypatch):
    worker, binding, execution, action = await uncertain_prompt(db, monkeypatch)
    monkeypatch.setattr("jt_oz_bridge.services.dispatch.UNCERTAIN_PROMPT_SETTLE_SECONDS", 60)
    execution.landed[(action.id, action.operation_digest)] = ("msg_landed01", "Original text")
    assert await worker.reconcile_uncertain_prompts() == 0
    assert execution.readbacks == []


async def test_an_uncertain_prompt_with_files_is_left_for_review(db, monkeypatch, caplog):
    worker, binding, execution, action = await uncertain_prompt(
        db, monkeypatch, attachments={"files": []}
    )
    execution.landed[(action.id, action.operation_digest)] = ("msg_landed01", "Original text")
    with caplog.at_level(logging.WARNING):
        assert await worker.reconcile_uncertain_prompts() == 0
        assert await worker.reconcile_uncertain_prompts() == 0
    assert execution.readbacks == [] and (await worker.load(action.id)).state == "ambiguous"
    assert caplog.text.count("uncertain_prompt_left_for_review check=files") == 1


async def test_an_uncertain_prompt_opencode_never_received_is_refused_and_said_once(
    db, monkeypatch
):
    """A message that never reached OpenCode at all, once proven absent and old
    enough, is refused as unsent, never resent, and the topic moves on."""
    from jt_oz_bridge.services.dispatch_feedback import NOTICES

    worker, binding, execution, action = await uncertain_prompt(db, monkeypatch)
    monkeypatch.setattr("jt_oz_bridge.services.dispatch.UNCERTAIN_PROMPT_ABSENT_SECONDS", 0)
    execution.absent = True
    assert await worker.reconcile_uncertain_prompts() == 0
    saved = await worker.load(action.id)
    assert (saved.state, saved.status_reason) == ("rejected", "native_prompt_never_arrived")
    assert (saved.state, saved.status_reason) in NOTICES
    assert saved.upstream_id is None and not saved.admission
    assert len(execution.submitted) == 1


@pytest.mark.parametrize("absent, young", [(False, False), (True, True)])
async def test_an_uncertain_prompt_stays_uncertain_without_proof_or_time(
    db, monkeypatch, absent, young
):
    worker, binding, execution, action = await uncertain_prompt(db, monkeypatch)
    if not young:
        monkeypatch.setattr("jt_oz_bridge.services.dispatch.UNCERTAIN_PROMPT_ABSENT_SECONDS", 0)
    execution.absent = absent
    await worker.reconcile_uncertain_prompts()
    assert (await worker.load(action.id)).state == "ambiguous"
