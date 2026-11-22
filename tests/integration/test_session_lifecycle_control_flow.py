"""Synthetic Humans/Native with a real isolated encrypted DB and durable outbox."""

import asyncio
import time
from html import unescape

import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import Admission, MutationNotSent, MutationRejected
from jt_oz_bridge.domain.models import Capability
from jt_oz_bridge.domain.session_lifecycle import (
    LIFECYCLE_OPERATIONS,
    SessionLifecycleChange,
    SessionLifecycleOutcome,
    SessionLifecycleRequest,
    SessionMessageChoice,
)
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.dispatch_feedback import DispatchFeedback
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.session_lifecycle_controls import SessionLifecycleControls
from jt_oz_bridge.services.session_lifecycle_results import SessionLifecycleResultPublisher
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from jt_oz_bridge.storage.publication_models import ModelSettingPublication
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_router import Source, message, send
from tests.support import bound


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


class LifecycleExecution(SyntheticExecution):
    def __init__(self):
        super().__init__()
        self.state = ExecutionState.IDLE
        self.enabled = set(LIFECYCLE_OPERATIONS)
        self.pending = None
        self.turns = (
            SessionMessageChoice(message_id="msg_b", preview="second @**all** turn"),
            SessionMessageChoice(message_id="msg_a", preview="first turn"),
        )
        self.hook = None

    def capabilities(self, ref):
        result = super().capabilities(ref)
        for name in LIFECYCLE_OPERATIONS:
            result[name] = Capability(
                supported=name in self.enabled,
                scope="session",
                reason="synthetic only",
                verification="synthetic_test",
            )
        return result

    async def pending_revert(self, ref):
        if self.hook:
            await self.hook()
        return self.pending

    async def recent_user_messages(self, ref):
        return self.turns

    async def submit(self, ref, payload, identity):
        assert ref == self.ref and payload["operation"] in LIFECYCLE_OPERATIONS
        if self.mode == "not-sent":
            raise MutationNotSent("synthetic fixed preflight rejected")
        self.submitted.append((ref, payload, identity))
        if self.mode == "lost-ack":
            raise TimeoutError("synthetic lost reply after Native may have applied it")
        if self.mode == "refused":
            raise MutationRejected("synthetic verified HTTP 404")
        request = SessionLifecycleRequest.model_validate(payload)
        if request.operation == "session.revert.stage":
            self.pending = request.change.message_id
        elif request.operation in {"session.revert.clear", "session.revert.commit"}:
            self.pending = None
        return Admission(
            status="completed",
            details=SessionLifecycleOutcome(
                operation=request.operation,
                change=request.change,
                session_id=ref.upstream_session_id,
                new_session_id="ses_new_fork" if request.operation == "session.fork" else None,
                native_request_id="msg_c" if request.operation == "session.compact" else None,
                owner_evidence_sha256="a" * 64,
                session_info_sha256="b" * 64,
            ).model_dump(mode="json"),
        )


class Harness:
    def __init__(self, db, router, binding, source, execution, worker, publisher, audience):
        self.db, self.router, self.binding, self.source = db, router, binding, source
        self.execution, self.worker, self.publisher = execution, worker, publisher
        self.audience, self.next_id = audience, 100

    async def say(self, text, **changes):
        self.next_id += 1
        item = message(text, self.next_id, **changes)
        return item, await send(self.router, self.source, item)

    async def preview(self, text="!compact"):
        return (await self.say(text))[1]

    async def confirmed(self, text="!compact"):
        await self.preview(text)
        await self.say("!confirm")
        return (await rows(self.db, Action))[-1]


async def harness(db):
    execution = LifecycleExecution()
    bindings, binding, _, audience = await bound(db, control=execution)
    lease = await DurableStore(db).acquire_lease("lifecycle", ttl=120)
    inbox, source = CommandInbox(db, "lifecycle", lease), Source()
    tokens = TokenService(db, fence=inbox.fence)
    controls = SessionLifecycleControls(bindings, tokens, source, execution.capabilities)
    router = CommandRouter(bindings, source, inbox, lifecycle_controls=controls)
    worker = Dispatcher(bindings, execution, source, "lifecycle", lease)
    publisher = SessionLifecycleResultPublisher(
        RoutedOutbox(
            Outbox(bindings, 77, fence=inbox.fence),
            realm_id="realm",
            message_limit=1000,
            topic_limit=60,
        )
    )
    return Harness(db, router, binding, source, execution, worker, publisher, audience)


FLOWS = [
    ("!fork", (), "session.fork", {}, "ses_new_fork", "still connected to the original"),
    ("!compact", (), "session.compact", {"delivery": "queue"}, "accepted", "finished"),
    (
        "!revert",
        ("!1",),
        "session.revert.stage",
        {"messageID": "msg_b", "files": False},
        "second",
        "!discard",
    ),
    (
        "!revert files",
        ("!2",),
        "session.revert.stage",
        {"messageID": "msg_a", "files": True},
        "Project files were included",
        "!redo",
    ),
]


@pytest.mark.parametrize(("opening", "choices", "operation", "body", "one", "two"), FLOWS)
async def test_preview_then_one_confirm_sends_one_action_and_one_notice(
    db, opening, choices, operation, body, one, two
):
    h = await harness(db)
    preview = await h.preview(opening)
    for choice in choices:
        assert "!ok" not in preview.text and "!1" in preview.text
        preview = (await h.say(choice))[1]
    assert "!ok" in preview.text
    assert not await rows(db, Action) and not h.execution.submitted
    confirm, reply = await h.say("!confirm")
    assert "once" in reply.text
    action = (await rows(db, Action))[0]
    assert action.operation == operation and action.state == "queued"
    assert await h.worker.advance(action.id) == "completed"
    assert len(h.execution.submitted) == 1
    sent = SessionLifecycleChange.model_validate(h.execution.submitted[0][1]["change"])
    assert (sent.wire_body() or {}) == body
    assert await h.publisher.next_pending() == action.id
    first, second = await asyncio.gather(
        h.publisher.publish(action.id), h.publisher.publish(action.id)
    )
    assert first == second and await h.publisher.next_pending() is None
    assert len(await rows(db, ModelSettingPublication)) == 1
    content = unescape(" ".join(x.payload["content"] for x in await rows(db, Delivery)))
    assert one in content and two in content
    # The redelivered confirmation replays its reply and creates nothing.
    assert (await send(h.router, h.source, confirm)).text == reply.text
    assert len(await rows(db, Action)) == len(h.execution.submitted) == 1
    await h.worker.advance(action.id)
    assert len(h.execution.submitted) == 1


async def test_fork_never_rebinds_the_topic_or_touches_the_binding(db):
    h = await harness(db)
    before = await rows(db, Binding)
    action = await h.confirmed("!fork")
    assert await h.worker.advance(action.id) == "completed"
    await h.publisher.publish(action.id)
    after = await rows(db, Binding)
    assert len(after) == len(before) == 1
    assert reference(after[0]) == reference(before[0])
    assert after[0].revision == before[0].revision and after[0].topic == before[0].topic


async def test_zh_tw_notices_say_conversation_and_stay_plain(db):
    h = await harness(db)
    await h.say("!oz lang zh-TW")
    preview = await h.preview("!fork")
    assert "新對話" in preview.text and "!ok" in preview.text
    await h.say("!confirm")
    action = (await rows(db, Action))[-1]
    assert await h.worker.advance(action.id) == "completed"
    await h.publisher.publish(action.id)
    content = unescape(" ".join(x.payload["content"] for x in await rows(db, Delivery)))
    assert "已建立新對話" in content and "原本的對話" in content
    assert "session" not in content.lower().replace("ses_new_fork", "")


@pytest.mark.parametrize(
    "command", ["!fork", "!fork pick", "!compact", "!revert", "!revert clear", "!revert commit"]
)
async def test_operation_outside_the_root_policy_is_refused_locally(db, command):
    h = await harness(db)
    h.execution.pending = "msg_b"
    h.execution.enabled = set()
    reply = await h.preview(command)
    assert "Nothing was sent" in reply.text
    assert not await rows(db, Action) and not await rows(db, ControlToken)
    assert not h.execution.submitted


async def test_each_revert_step_needs_its_own_policy_entry(db):
    h = await harness(db)
    h.execution.pending = "msg_b"
    h.execution.enabled = {"session.revert.clear"}
    assert "!ok" in (await h.preview("!redo")).text
    assert "Nothing was sent" in (await h.preview("!discard")).text
    assert "Nothing was sent" in (await h.preview("!revert")).text


@pytest.mark.parametrize("command", ["!archive", "!unarchive", "!oz archive", "!oz unarchive"])
async def test_archive_is_refused_with_the_reason(db, command):
    h = await harness(db)
    reply = await h.preview(command)
    assert "no way to archive" in reply.text and not await rows(db, Action)
    assert not await rows(db, ControlToken) and not h.execution.submitted


@pytest.mark.parametrize("command", ["!oz delete", "!delete", "!oz delete now"])
async def test_delete_is_refused_and_only_unbind_is_offered(db, command):
    h = await harness(db)
    reply = await h.preview(command)
    assert "permanently delete" in reply.text and "`!disconnect`" in reply.text
    assert "Nothing was sent" in reply.text and not h.execution.submitted
    assert not await rows(db, Action) and not await rows(db, ControlToken)
    binding = (await rows(db, Binding))[0]
    assert binding.state == "active" and binding.revision == h.binding.revision


async def test_delete_refusal_is_in_help_and_in_both_languages(db):
    h = await harness(db)
    assert "permanently delete" in (await h.preview("!oz help delete")).text
    await h.say("!oz lang zh-TW")
    assert "永久刪除" in (await h.preview("!oz delete")).text
    assert not await rows(db, Action)


async def test_fork_preview_says_whether_the_copy_gets_its_own_topic(db):
    h = await harness(db)
    assert "isn't connected to any topic" in (await h.preview("!fork")).text
    h.router.lifecycle_controls.fork_topics = frozenset({h.binding.project_id})
    assert "its own topic in this channel" in (await h.preview("!fork")).text


async def test_without_composition_the_commands_stay_not_integrated(db):
    execution = LifecycleExecution()
    bindings, _, _, _ = await bound(db, control=execution)
    lease = await DurableStore(db).acquire_lease("lifecycle", ttl=120)
    source = Source()
    router = CommandRouter(bindings, source, CommandInbox(db, "lifecycle", lease))
    for number, text in enumerate(("!fork", "!compact", "!revert", "!archive"), 101):
        assert "available yet" in (await send(router, source, message(text, number))).text
    assert not await rows(db, Action)


@pytest.mark.parametrize(
    "arguments", ["!fork now", "!compact all", "!revert later", "!revert clear now", "!fork pick 2"]
)
async def test_unknown_arguments_get_usage_and_no_token(db, arguments):
    h = await harness(db)
    reply = await h.preview(arguments)
    assert "right form" in reply.text
    assert not await rows(db, ControlToken) and not await rows(db, Action)


async def test_help_reports_availability_and_usage(db):
    h = await harness(db)
    assert "no way to archive" in (await h.preview("!oz help archive")).text
    assert "!oz revert [files]" in (await h.preview("!oz help revert")).text
    h.execution.enabled = set()
    assert "available yet" in (await h.preview("!oz help compact")).text


@pytest.mark.parametrize("command", ["!revert clear", "!revert commit"])
async def test_clear_and_commit_need_a_waiting_revert(db, command):
    h = await harness(db)
    assert "No rollback" in (await h.preview(command)).text
    assert not await rows(db, ControlToken)


async def test_compact_refuses_over_a_waiting_revert(db):
    h = await harness(db)
    h.execution.pending = "msg_b"
    assert "rollback is waiting" in (await h.preview("!compact")).text


async def test_previews_state_the_irreversible_and_outside_effects(db):
    h = await harness(db)
    await h.preview("!revert")
    stage = (await h.say("!1"))[1].text
    assert "Project files are not changed" in stage and "pushed Git commits" in stage
    await h.preview("!revert files")
    assert "overwrite later edits" in (await h.say("!1"))[1].text
    h.execution.pending = "msg_b"
    commit = (await h.say("!revert commit"))[1].text
    assert "can't be undone" in commit and "pushed Git commits" in commit
    h.execution.pending = None
    assert "can't be undone" in (await h.say("!compact"))[1].text


async def test_native_text_in_a_menu_cannot_mention_or_format(db):
    h = await harness(db)
    menu = await h.preview("!revert")
    assert "second" in menu.text and "@**all**" not in menu.text


@pytest.mark.parametrize(
    "fault", ["edited", "deleted", "grant", "revision", "audience", "capability", "paused", "busy"]
)
async def test_confirm_rechecks_source_authority_and_state(db, fault):
    h = await harness(db)
    item, _ = await h.say("!compact")
    if fault in {"edited", "deleted"}:
        change = {"revision": 1, "text": "!fork"} if fault == "edited" else {"deleted": True}
        h.source.messages[item.message_id] = item.model_copy(update=change)
    elif fault == "audience":
        h.audience.private = False
    elif fault == "capability":
        h.execution.enabled = set()
    elif fault == "busy":
        h.execution.state = ExecutionState.RUNNING
    else:
        async with db.sessions.begin() as session:
            if fault == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            elif fault == "revision":
                await session.execute(
                    update(Binding).where(Binding.id == h.binding.id).values(revision=2)
                )
            else:
                await session.execute(
                    update(Binding).where(Binding.id == h.binding.id).values(dispatch_paused=True)
                )
    if fault in {"audience", "grant"}:
        # The topic itself stopped being usable by this person: no reply is routed there.
        with pytest.raises((AccessDenied, Conflict)):
            await h.say("!confirm")
    else:
        await h.say("!confirm")
    assert not await rows(db, Action) and not h.execution.submitted


async def test_tui_change_between_preview_and_confirm_stops_it(db):
    h = await harness(db)
    await h.preview("!fork")
    h.execution.pending = "msg_from_tui"
    reply = (await h.say("!confirm"))[1]
    assert "expired or is no longer valid" in reply.text and not await rows(db, Action)


async def test_another_persons_confirm_cannot_use_a_preview(db):
    h = await harness(db)
    await h.preview("!compact")
    reply = (await h.say("!confirm", author_id=8))[1]
    assert not await rows(db, Action) and not h.execution.submitted
    assert "expired or is no longer valid" in reply.text
    # The person who previewed it still can.
    await h.say("!confirm")
    assert len(await rows(db, Action)) == 1


async def test_confirmation_is_one_use_and_expires(db):
    h = await harness(db)
    await h.confirmed("!compact")
    assert "expired or is no longer valid" in (await h.say("!ok"))[1].text
    assert len(await rows(db, Action)) == 1
    await h.preview("!fork")
    async with db.sessions.begin() as session:
        await session.execute(update(ControlToken).values(expires_at=time.time() - 1))
    assert "expired or is no longer valid" in (await h.say("!ok"))[1].text
    assert len(await rows(db, Action)) == 1


async def test_a_newer_preview_replaces_the_older_one(db):
    h = await harness(db)
    await h.preview("!compact")
    await h.preview("!fork")
    await h.say("!confirm")
    actions = await rows(db, Action)
    assert [a.operation for a in actions] == ["session.fork"]


async def test_agent_controls_and_lifecycle_controls_replace_each_other(db):
    h = await harness(db)
    await h.preview("!compact")
    async with db.sessions.begin() as session:
        session.add(
            ControlToken(
                token_hash="f" * 64,
                kind="native-agent-confirm",
                realm_id="realm",
                user_id=7,
                binding_id=h.binding.id,
                binding_revision=h.binding.revision,
                context={},
                context_hash="0" * 64,
                expires_at=time.time() + 60,
            )
        )
    await h.preview("!fork")
    async with db.sessions() as session:
        agent = await session.get(ControlToken, "f" * 64)
    assert agent is not None and agent.used is True


async def test_menu_rechecks_native_and_stops_after_a_change(db):
    h = await harness(db)
    await h.preview("!revert")
    h.execution.turns = (SessionMessageChoice(message_id="msg_z", preview="other"),)
    reply = (await h.say("!1"))[1]
    assert "expired or is no longer valid" in reply.text
    assert "!ok" not in reply.text


async def test_menu_number_out_of_range_changes_nothing(db):
    h = await harness(db)
    await h.preview("!fork pick")
    assert "expired or is no longer valid" in (await h.say("!9"))[1].text
    assert "!ok" in (await h.say("!1"))[1].text


async def test_empty_history_offers_nothing(db):
    h = await harness(db)
    h.execution.turns = ()
    assert "no messages" in (await h.preview("!revert")).text
    assert not await rows(db, ControlToken)


@pytest.mark.parametrize(
    ("fault", "state"),
    [
        ("edited-confirm", "held"),
        ("edited-preview", "held"),
        ("deleted-preview", "held"),
        ("grant", "rejected"),
        ("audience", "rejected"),
        ("capability", "rejected"),
        ("busy", "rejected"),
        ("paused", "rejected"),
        ("expired", "rejected"),
        ("digest", "held"),
    ],
)
async def test_dispatch_rechecks_everything_before_the_one_send(db, fault, state):
    h = await harness(db)
    preview, _ = await h.say("!compact")
    confirm, _ = await h.say("!confirm")
    action = (await rows(db, Action))[0]
    if fault == "edited-confirm":
        h.source.messages[confirm.message_id] = confirm.model_copy(
            update={"revision": 1, "text": "edited"}
        )
    elif fault in {"edited-preview", "deleted-preview"}:
        change = {"deleted": True} if fault.startswith("deleted") else {"revision": 1}
        h.source.messages[preview.message_id] = preview.model_copy(update=change)
    elif fault == "audience":
        h.audience.private = False
    elif fault == "capability":
        h.execution.enabled = set()
    elif fault == "busy":
        h.execution.state = ExecutionState.RUNNING
    else:
        async with db.sessions.begin() as session:
            if fault == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            elif fault == "paused":
                await session.execute(
                    update(Binding).where(Binding.id == h.binding.id).values(dispatch_paused=True)
                )
            elif fault == "expired":
                await session.execute(
                    update(Action)
                    .where(Action.id == action.id)
                    .values(
                        payload={**action.payload, "confirm_expires_at": time.time() - 1},
                    )
                )
            else:
                await session.execute(
                    update(Action).where(Action.id == action.id).values(operation_digest="0" * 64)
                )
    assert await h.worker.advance(action.id) == state
    assert not h.execution.submitted and await h.publisher.next_pending() is None


async def test_unknown_result_is_reported_once_and_never_resent(db):
    h = await harness(db)
    h.execution.mode = "lost-ack"
    h.execution.pending = "msg_b"
    action = await h.confirmed("!revert commit")
    assert await h.worker.advance(action.id) == "ambiguous"
    assert await h.worker.advance(action.id) == "ambiguous"
    assert len(h.execution.submitted) == 1
    assert await h.publisher.next_pending() == action.id
    await h.publisher.publish(action.id)
    await h.publisher.publish(action.id)
    assert await h.publisher.next_pending() is None
    content = [unescape(x.payload["content"]) for x in await rows(db, Delivery)]
    assert len(content) == 1 and "won't be sent again" in content[0] and "!history" in content[0]
    # A person may decide again; that takes a new preview that rereads Native.
    h.execution.mode = "success"
    h.execution.pending = None
    assert "No rollback" in (await h.preview("!discard")).text
    assert len(h.execution.submitted) == 1


async def test_a_verified_native_refusal_is_recorded_and_not_retried(db):
    h = await harness(db)
    h.execution.mode = "refused"
    action = await h.confirmed("!fork")
    assert await h.worker.advance(action.id) == "rejected"
    assert await h.worker.advance(action.id) == "rejected"
    current = (await rows(db, Action))[0]
    assert current.status_reason == "lifecycle_native_refused"
    assert len(h.execution.submitted) == 1
    assert await h.publisher.next_pending() is None


@pytest.mark.parametrize("text", ["!revert commit", "!compact", "!confirm", "!fork"])
async def test_messages_recovered_after_an_outage_stay_held(db, text):
    h = await harness(db)
    h.execution.pending = "msg_b"
    await h.preview("!revert commit") if text == "!confirm" else None
    h.next_id += 1
    item = message(text, h.next_id)
    assert (await send(h.router, h.source, item, recovered=True)).state == "held"
    assert not await rows(db, Action) and not h.execution.submitted


async def test_restart_never_replays_a_confirmed_action(db):
    h = await harness(db)
    action = await h.confirmed("!compact")
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action.id)
            .values(
                state="queued",
                payload={**action.payload, "confirm_expires_at": time.time() - 1},
            )
        )
    assert await h.worker.advance(action.id) == "rejected"
    assert not h.execution.submitted


async def test_restart_turns_a_send_in_progress_into_unknown(db):
    h = await harness(db)
    action = await h.confirmed("!compact")
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action.id)
            .values(state="dispatching", version=Action.version + 1)
        )
    await DurableStore(db).recover()
    current = (await rows(db, Action))[0]
    assert current.state == "ambiguous" and await h.publisher.next_pending() == action.id
    assert await h.worker.advance(action.id) == "ambiguous" and not h.execution.submitted


async def test_preflight_rejection_is_not_sent_and_says_so(db):
    h = await harness(db)
    h.execution.mode = "not-sent"
    action = await h.confirmed("!compact")
    assert await h.worker.advance(action.id) == "rejected"
    assert await h.publisher.next_pending() is None


@pytest.mark.parametrize(
    ("state", "operation", "blocked"),
    [
        ("running", "prompt", True),
        ("admitted", "prompt", True),
        ("dispatching", "session.fork", True),
        ("ambiguous", "prompt", False),
        ("completed", "prompt", False),
    ],
)
async def test_one_mutation_at_a_time_on_the_session(db, state, operation, blocked):
    h = await harness(db)
    action = await h.confirmed("!compact")
    async with db.sessions.begin() as session:
        session.add(
            Action(
                dedupe_key="other",
                binding_id=h.binding.id,
                binding_revision=h.binding.revision,
                actor_id=7,
                operation=operation,
                payload={"operation": operation},
                operation_digest="0" * 64,
                state=state,
            )
        )
    result = await h.worker.advance(action.id)
    assert result == ("queued" if blocked else "completed")
    assert bool(h.execution.submitted) is not blocked


async def test_a_prompt_waits_while_a_lifecycle_send_is_in_progress(db):
    h = await harness(db)
    action = await h.confirmed("!compact")
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == action.id).values(state="dispatching")
        )
    async with db.sessions() as session:
        prompt = Action(
            dedupe_key="prompt",
            binding_id=h.binding.id,
            binding_revision=h.binding.revision,
            actor_id=7,
            operation="prompt",
            payload={"operation": "prompt"},
            operation_digest="0" * 64,
            state="queued",
        )
        binding = await session.get(Binding, h.binding.id)
    async with db.sessions() as session:
        assert await Dispatcher._lifecycle_conflict(session, prompt, binding) is True
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == action.id).values(state="ambiguous")
        )
    async with db.sessions() as session:
        assert await Dispatcher._lifecycle_conflict(session, prompt, binding) is False


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        ("lifecycle_confirmation_expired", "wasn't used in time"),
        ("lifecycle_session_busy", "is working"),
        ("lifecycle_queue_paused", "topic is paused"),
        ("lifecycle_not_available", "can't do that"),
        ("lifecycle_native_refused", "refused"),
    ],
)
async def test_every_dispatch_refusal_tells_the_person_once(db, reason, text):
    h = await harness(db)
    action = await h.confirmed("!compact")
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action)
            .where(Action.id == action.id)
            .values(state="rejected", status_reason=reason)
        )
    feedback = DispatchFeedback(
        h.publisher.replies.outbox, h.source, realm_id="realm", message_limit=1000, topic_limit=60
    )
    assert await feedback.next_pending() == action.id
    await feedback.publish(action.id)
    assert await feedback.next_pending() is None
    content = " ".join(unescape(x.payload["content"]) for x in await rows(db, Delivery))
    assert text in content


async def test_registries_read_only_the_selected_original_session():
    from dataclasses import replace

    from jt_oz_bridge.services.session_registry import SessionRegistry
    from tests.integration.test_session_registry import REF, pair

    registry, entries = pair()
    with pytest.raises(Conflict):
        await registry.pending_revert(REF)
    execution = LifecycleExecution()
    execution.ref, execution.contract_hash = REF, entries[REF].execution.contract_hash
    execution.pending = "msg_b"
    registry = SessionRegistry({REF: replace(entries[REF], execution=execution)})
    assert await registry.pending_revert(REF) == "msg_b"
    assert await registry.recent_user_messages(REF) == execution.turns


async def test_whole_consumer_graph_previews_confirms_and_delivers_one_notice(db):
    from dataclasses import replace

    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
    from tests.integration.test_consumer_runtime import post_containing, until
    from tests.integration.test_consumer_runtime import setup as graph_setup

    previous, server, old_native, results, binding, pulse = await graph_setup(db)
    ref = reference(binding)
    backend = previous.backends[ref.backend_id]
    native = LifecycleExecution()
    native.contract_hash = backend.registered.contract_sha256
    native.ref = ref
    backend = replace(backend, registered=replace(backend.registered, client=native))
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {ref.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    runtime = pipeline.runtime()
    await runtime.start()
    try:
        server.input("!fork", 101)
        await post_containing(server, "new conversation")
        assert not await rows(db, Action) and not native.submitted
        server.input("!confirm", 102)
        delivered = await post_containing(server, "ses_new_fork")

        async def all_delivered():
            saved = await rows(db, Delivery)
            return bool(saved) and all(x.state == "delivered" for x in saved)

        await until(all_delivered)
        assert delivered["subject"] == binding.topic and len(native.submitted) == 1
        assert len(await rows(db, Action)) == len(await rows(db, ModelSettingPublication)) == 1
        assert runtime.healthy and not old_native.submitted
    finally:
        await runtime.close()
