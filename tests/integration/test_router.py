import asyncio
import re
from html import unescape

import pytest
from sqlalchemy import func, select, update

from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.i18n import Translator, get_locale
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.models import Action, Grant
from tests.support import bound


class Source:
    def __init__(self):
        self.messages = {}
        self.calls = []

    async def read(self, realm, message_id):
        self.calls.append((realm, message_id))
        return self.messages[message_id]


def message(text="!oz help", message_id=101, **changes):
    return HumanMessage(
        realm_id="realm",
        channel_id=10,
        topic="Original work",
        message_id=message_id,
        revision=0,
        author_id=7,
        text=text,
    ).model_copy(update=changes)


async def router(db):
    bindings, binding, control, audience = await bound(db)
    fence = await DurableStore(db).acquire_lease("router")
    source = Source()
    return (
        CommandRouter(bindings, source, CommandInbox(db, "router", fence)),
        binding,
        source,
        control,
        audience,
    )


async def send(service, source, item, **options):
    source.messages[item.message_id] = item
    return await service.route(item, **options)


async def count(db, model):
    async with db.sessions() as session:
        return await session.scalar(select(func.count()).select_from(model))


async def test_controls_never_fall_through_to_prompt_and_replies_are_durable(db):
    service, binding, source, _control, _audience = await router(db)
    first = await send(service, source, message("!oz help"))
    assert first.state == "reply" and "!stop" in first.text and first.binding_id == binding.id
    replay = await service.route(source.messages[101])
    assert replay == first
    unknown = await send(service, source, message("!oz definitely-unknown", 102))
    assert "nothing was sent to OpenCode" in unknown.text
    unsupported = await send(service, source, message("!oz git push", 103))
    assert "available yet" in unsupported.text
    assert await count(db, Action) == 0 and await count(db, CommandReceipt) == 3


async def test_navigation_token_is_single_use_actor_and_binding_scoped(db):
    service, _binding, source, _control, _audience = await router(db)
    menu = await send(service, source, message("!oz menu"))
    token = re.search(r"!oz choose (\S+) 1", unescape(menu.text))[1]
    assert await count(db, ControlToken) == 1
    # A duplicate menu command must not allocate another opaque token.
    assert await service.route(source.messages[101]) == menu
    assert await count(db, ControlToken) == 1
    denied = await send(service, source, message(f"!oz choose {token} 1", 102, author_id=8))
    assert "expired" in denied.text
    chosen = await send(service, source, message(f"!oz choose {token} 1", 103))
    assert "original-session" in unescape(chosen.text)
    again = await send(service, source, message(f"!oz choose {token} 1", 104))
    assert "expired" in again.text
    assert await count(db, Action) == 0


async def test_plain_prompt_edits_literal_send_and_recovery_are_queued_safely(db):
    service, _binding, source, _control, _audience = await router(db)
    original = message("!oz send -- !oz stop\n exact")
    reply = await send(service, source, original)
    async with db.sessions() as session:
        action = await session.get(Action, reply.action_id)
        assert action.payload["text"] == "!oz stop\n exact"
        assert action.payload["source"]["text"] == original.text
    edited = original.model_copy(update={"revision": 1, "text": "normal edited prompt"})
    second = await send(service, source, edited)
    assert second.action_id == reply.action_id
    async with db.sessions() as session:
        assert (await session.get(Action, reply.action_id)).payload["text"] == edited.text
    held = await send(service, source, message("outage prompt", 102), recovered=True)
    async with db.sessions() as session:
        assert (await session.get(Action, held.action_id)).state == "held"


async def test_edited_commands_and_prompt_to_command_conversion_never_execute_controls(db):
    service, _binding, source, _control, _audience = await router(db)
    await send(service, source, message("!oz info"))
    changed = await send(service, source, message("dangerous ordinary prompt", revision=1))
    assert "edited" in changed.text and await count(db, Action) == 0
    prompt = await send(service, source, message("ordinary prompt", 102))
    changed = await send(service, source, message("!oz stop", 102, revision=1))
    async with db.sessions() as session:
        assert (await session.get(Action, prompt.action_id)).state == "cancelled"
    assert "edited" in changed.text and await count(db, Action) == 1
    historical_edit = await send(service, source, message("!oz stop", 103, revision=1))
    assert historical_edit.state == "held" and await count(db, Action) == 1


async def test_bot_stale_event_unknown_topic_and_untrusted_audience_cannot_execute(db):
    service, _binding, source, _control, audience = await router(db)
    bot = await service.route(message("!oz stop", is_bot=True))
    assert bot.state == "ignore" and source.calls == []
    event = message("safe prompt")
    source.messages[101] = event.model_copy(update={"revision": 1, "text": "!oz stop"})
    assert (await service.route(event)).state == "ignore"
    unknown = await send(service, source, message("ordinary prompt", 102, topic="unknown topic"))
    assert unknown.state == "ignore"
    audience.users = frozenset({7, 8, 999})
    with pytest.raises(Conflict):
        await send(service, source, message("!oz stop", 103))
    assert await count(db, Action) == 0


async def test_recovered_stop_stays_held_and_replay_has_no_effect(db):
    service, binding, source, _control, _audience = await router(db)
    item = message("!oz stop")
    assert (await send(service, source, item, recovered=True)).state == "held"
    assert (await service.route(item)).state == "held"
    async with db.sessions() as session:
        assert not (await session.get(Binding, binding.id)).dispatch_paused
    assert await count(db, Action) == 0


async def test_stop_resume_cancel_and_scope_use_existing_domain_transactions(db):
    service, binding, source, _control, _audience = await router(db)
    queued = await send(service, source, message("instruction"))
    stopped = await send(service, source, message("!oz stop", 102))
    assert "Received" in stopped.text and "just type a new message" in stopped.text
    assert await count(db, Action) == 2
    assert await service.route(source.messages[102]) == stopped
    async with db.sessions() as session:
        assert (await session.get(Action, queued.action_id)).state == "held"
    resumed = await send(service, source, message("!oz queue resume", 103))
    assert "continuing" in resumed.text
    cancelled = await send(service, source, message("!oz cancel " + queued.action_id, 104))
    assert "Cancelled" in cancelled.text
    async with db.sessions() as session:
        assert (await session.get(Action, queued.action_id)).state == "cancelled"
        assert not (await session.get(Binding, binding.id)).dispatch_paused


async def test_status_numbers_held_messages_and_no_drops_them_unsent(db):
    service, _binding, source, _control, _audience = await router(db)
    queued = await send(service, source, message("instruction"))
    await send(service, source, message("!stop", 102))
    status = (await send(service, source, message("!status", 103))).text
    assert queued.action_id not in status
    assert "1. A message “instruction”: not sent" in unescape(status)
    assert "`!go` sends them, `!no` drops them" in unescape(status)
    dropped = await send(service, source, message("!no", 104))
    assert "Dropped 1 unsent message" in dropped.text
    async with db.sessions() as session:
        assert (await session.get(Action, queued.action_id)).state == "cancelled"
    assert "Nothing is waiting" in (await send(service, source, message("!no", 105))).text


async def test_status_shows_the_start_of_a_long_message_on_one_inert_line(db):
    service, _binding, source, _control, _audience = await router(db)
    await send(service, source, message("@**everyone** please\n\n read   the whole deploy log now"))
    await send(service, source, message("!stop", 102))
    status = (await send(service, source, message("!status", 103))).text
    assert "@**" not in status and "\n read" not in status
    assert "1. A message “@**everyone** please read the…”: not sent" in unescape(status)


async def test_languages_persist_and_agent_prompt_language_is_untouched(db):
    service, binding, source, _control, _audience = await router(db)
    changed = await send(service, source, message("!oz lang zh-TW"))
    assert "顯示語言" in changed.text and "不受影響" in changed.text
    assert await get_locale(db, "user:realm:7") == "zh-TW"
    settings = await send(service, source, message("!oz settings", 102))
    assert "你的回覆語言：zh-TW" in settings.text
    topic = await send(service, source, message("!oz topic-lang zh-TW", 103))
    assert "這個話題" in topic.text
    async with db.sessions() as session:
        assert (await session.get(Binding, binding.id)).locale == "zh-TW"
    reply = await send(service, source, message("Do not translate this prompt", 104))
    async with db.sessions() as session:
        assert (await session.get(Action, reply.action_id)).payload[
            "text"
        ] == "Do not translate this prompt"
    assert (
        Translator().render("settings.personal_saved", "zh-TW", locale="en")
        == "你的顯示語言已切換為 en。"
    )


async def test_viewer_can_read_but_cannot_stop_resume_or_mutate_topic_language(db):
    service, binding, source, _control, _audience = await router(db)
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        session.add(Grant(realm_id="realm", user_id=7, project_id="project", role="viewer"))
    status = await send(service, source, message("!oz status"))
    assert "Running" in status.text
    for index, command in enumerate(["!oz stop", "!oz queue resume", "!oz topic-lang zh-TW"], 102):
        assert "have permission" in (await send(service, source, message(command, index))).text
    assert await count(db, Action) == 0
    async with db.sessions() as session:
        assert (await session.get(Binding, binding.id)).locale == "en"
    with pytest.raises(AccessDenied):
        await send(service, source, message("ordinary prompt", 105))


async def test_parallel_router_commands_share_one_receipt_and_one_stop(db):
    service, _binding, source, _control, _audience = await router(db)
    item = message("!oz stop")
    source.messages[101] = item
    responses = await asyncio.gather(*[service.route(item) for _ in range(5)])
    assert any(reply.state == "reply" for reply in responses)
    assert await count(db, Action) == 1 and await count(db, CommandReceipt) == 1


async def test_lost_fence_during_menu_does_not_create_token_or_claim_success(db):
    service, _binding, source, _control, _audience = await router(db)
    original_issue = service.tokens.issue

    async def lose_lease(*args, **kwargs):
        store = DurableStore(db)
        await store.release_lease("router", service.inbox.fencing)
        assert await store.acquire_lease("new-owner")
        return await original_issue(*args, **kwargs)

    service.tokens.issue = lose_lease
    with pytest.raises(Conflict, match="lease"):
        await send(service, source, message("!oz menu"))
    assert await count(db, ControlToken) == 0
    receipt = await service.inbox.find("realm", 101)
    assert receipt.state == "processing"
    replacement = CommandInbox(db, "new-owner", service.inbox.fencing + 1)
    assert await replacement.recover(cutoff=__import__("time").time()) == 1


async def test_lost_fence_blocks_personal_language_write(db, monkeypatch):
    import jt_oz_bridge.services.router as module

    service, _binding, source, _control, _audience = await router(db)
    original_save = module.save_locale

    async def lose_lease(*args, **kwargs):
        assert kwargs.get("fence") == service.inbox.fence
        store = DurableStore(db)
        await store.release_lease("router", service.inbox.fencing)
        assert await store.acquire_lease("new-owner")
        return await original_save(*args, **kwargs)

    monkeypatch.setattr(module, "save_locale", lose_lease)
    with pytest.raises(Conflict, match="lease"):
        await send(service, source, message("!oz lang zh-TW"))
    assert await get_locale(db, "user:realm:7") == "en"


async def test_read_failure_abandons_receipt_and_cannot_be_replayed(db):
    service, _binding, source, control, _audience = await router(db)

    async def interrupted(_reference):
        raise TimeoutError("synthetic private upstream detail")

    control.snapshot = interrupted
    with pytest.raises(TimeoutError):
        await send(service, source, message("!oz status"))
    assert (await service.inbox.find("realm", 101)).state == "ambiguous"
    again = await service.route(source.messages[101])
    assert again.state == "ambiguous" and "private upstream detail" not in again.text


async def test_audience_change_during_status_holds_reply(db):
    service, _binding, source, control, audience = await router(db)
    original_snapshot = control.snapshot

    async def change_audience(reference):
        result = await original_snapshot(reference)
        audience.users = frozenset({7, 8, 999})
        return result

    control.snapshot = change_audience
    with pytest.raises(Conflict):
        await send(service, source, message("!oz status"))
    assert (await service.inbox.find("realm", 101)).state == "ambiguous"


async def test_cancel_cannot_target_another_topic_even_for_same_administrator(db):
    service, _binding, source, _control, _audience = await router(db)
    foreign = await DurableStore(db).enqueue(
        "foreign", "another-binding", 1, 7, {"text": "foreign"}
    )
    result = await send(service, source, message("!oz cancel " + foreign))
    assert "have permission" in result.text
    async with db.sessions() as session:
        assert (await session.get(Action, foreign)).state == "queued"


async def test_post_dispatch_edit_reports_real_state_without_reexecution(db):
    service, _binding, source, _control, _audience = await router(db)
    original = message("ordinary prompt")
    posted = await send(service, source, original)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == posted.action_id).values(state="admitted")
        )
    edited = await send(
        service,
        source,
        original.model_copy(update={"revision": 1, "text": "changed after admission"}),
    )
    assert edited.action_id == posted.action_id
    assert "can no longer be edited" in edited.text and "Received by OpenCode" in edited.text
    async with db.sessions() as session:
        assert (await session.get(Action, posted.action_id)).payload["text"] == "ordinary prompt"
    assert await count(db, Action) == 1


async def test_fenced_queue_cannot_release_or_cancel_work_after_takeover(db):
    service, binding, source, _control, _audience = await router(db)
    queued = await send(service, source, message("queued work"))
    revision = await service.queue.pause(binding.id, "realm", 7, binding.revision)
    store = DurableStore(db)
    await store.release_lease("router", service.inbox.fencing)
    assert await store.acquire_lease("new-owner")
    for operation in [
        service.queue.resume(binding.id, "realm", 7, binding.revision, revision),
        service.queue.cancel(queued.action_id, "realm", 7),
        service.queue.stop(binding.id, "realm", 7, "must-not-stop"),
    ]:
        with pytest.raises(Conflict, match="lease"):
            await operation
    async with db.sessions() as session:
        assert (await session.get(Action, queued.action_id)).state == "held"
        assert (await session.get(Binding, binding.id)).dispatch_paused
    assert await count(db, Action) == 1


async def test_help_shows_literal_argument_grammar_without_running_it(db):
    service, _binding, source, _control, _audience = await router(db)
    result = await send(service, source, message("!oz help send"))
    assert "!oz send -- <literal-text>" in result.text
    assert "Available, depending" in result.text
    assert await count(db, Action) == 0


async def test_cancelled_router_attempt_stays_ambiguous_and_does_not_rerun(db):
    service, _binding, source, control, _audience = await router(db)
    started = asyncio.Event()
    calls = 0

    async def interrupted(_reference):
        nonlocal calls
        calls += 1
        started.set()
        await asyncio.Event().wait()

    control.snapshot = interrupted
    item = message("!oz status")
    source.messages[101] = item
    task = asyncio.create_task(service.route(item))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await service.inbox.find("realm", 101)).state == "ambiguous"
    assert (await service.route(item)).state == "ambiguous"
    assert calls == 1


async def add_check_row(db, binding, state, identity="check-original"):
    # Isolated ownDB metadata, not a synthetic Native admission or live stop proof.
    from jt_oz_bridge.services.bindings import reference
    from jt_oz_bridge.storage.durable import digest

    payload = {"operation": "check.run", "reference": reference(binding).model_dump()}
    async with db.sessions.begin() as session:
        session.add(
            Action(
                id=identity,
                dedupe_key=identity,
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=7,
                operation="check.run",
                operation_digest=digest(payload),
                payload=payload,
                state=state,
                admission={"sentinel": "retained"},
                native_result={"uncertainty": "retained"},
            )
        )
    return identity


@pytest.mark.parametrize("state", ["dispatching", "admitted", "running", "ambiguous"])
@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_stop_of_in_flight_check_pauses_queue_without_interrupt_or_false_kill(
    db, state, locale
):
    service, binding, source, _control, _audience = await router(db)
    if locale == "zh-TW":
        await send(service, source, message("!oz lang zh-TW", 100))
    check_id = await add_check_row(db, binding, state)
    queued = await send(service, source, message("next unsent instruction", 101))
    stopped = await send(service, source, message("!oz stop", 102))
    assert ("stopped from here" if locale == "en" else "無法從這裡停止") in stopped.text
    assert ("No stop request was sent" if locale == "en" else "沒有送出停止要求") in stopped.text
    assert await service.route(source.messages[102]) == stopped
    assert await count(db, Action) == 3
    async with db.sessions() as session:
        current = await session.get(Binding, binding.id)
        check = await session.get(Action, check_id)
        assert current.dispatch_paused and current.queue_revision == 1
        assert check.state == state and check.version == 1
        assert check.admission == {"sentinel": "retained"}
        assert check.native_result == {"uncertainty": "retained"}
        receipt = await session.scalar(
            select(Action).where(Action.status_reason == "background_stop_unqualified")
        )
        assert receipt.state == "rejected" and receipt.upstream_id is None
        assert receipt.admission == {} and receipt.native_result == {}
        assert (await session.get(Action, queued.action_id)).state == "held"
        assert (
            await session.scalar(
                select(func.count())
                .select_from(Action)
                .where(Action.operation == "interrupt", Action.state != "rejected")
            )
            == 0
        )
    cancelled = await send(service, source, message("!oz cancel " + check_id, 103))
    assert ("be cancelled" if locale == "en" else "無法取消") in cancelled.text
    async with db.sessions() as session:
        assert (await session.get(Action, check_id)).state == state
    queued_view = await send(service, source, message("!oz queue", 104))
    status_view = await send(service, source, message("!oz status", 105))
    for view in (queued_view, status_view):
        assert ("stopped from here" if locale == "en" else "無法從這裡停止") in view.text
        assert "!oz check status" not in view.text


@pytest.mark.parametrize("state", ["queued", "held"])
async def test_check_cancel_claim_is_backed_by_original_unsent_transaction(db, state):
    service, binding, source, _control, _audience = await router(db)
    check_id = await add_check_row(db, binding, state)
    reply = await send(service, source, message("!oz cancel " + check_id))
    assert "Cancelled" in reply.text
    async with db.sessions() as session:
        row = await session.get(Action, check_id)
        assert row.state == "cancelled" and row.version == 2
        assert row.native_result == {"uncertainty": "retained"}
    assert (
        "be cancelled" in (await send(service, source, message("!oz cancel " + check_id, 102))).text
    )


async def test_stop_guard_includes_previous_binding_of_same_root_but_not_another_root(db):
    service, binding, source, _control, _audience = await router(db)
    async with db.sessions.begin() as session:
        previous = Binding(
            **{
                column.name: getattr(binding, column.name)
                for column in Binding.__table__.columns
                if column.name not in {"id", "session_key", "topic_key"}
            }
        )
        previous.id = "previous-origin"
        previous.state = "inactive"
        previous.topic = "old destination not disclosed"
        session.add(previous)
    await add_check_row(db, previous, "running")
    reply = await send(service, source, message("!oz stop"))
    assert "stopped from here" in reply.text
    assert "old destination not disclosed" not in reply.text and "previous-origin" not in reply.text
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding).where(Binding.id == previous.id).values(session_id="other-root")
        )
        await session.execute(
            update(Binding).where(Binding.id == binding.id).values(dispatch_paused=False)
        )
    reply = await send(service, source, message("!oz stop", 102))
    assert "Received" in reply.text and "stopped from here" not in reply.text
    async with db.sessions() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(Action)
                .where(Action.operation == "interrupt", Action.state != "rejected")
            )
            == 1
        )


async def test_direct_stop_api_refuses_dispatchable_id_after_committed_safe_check_pause(db):
    from jt_oz_bridge.services.check_stop import UnqualifiedBackgroundStop

    service, binding, _source, _control, _audience = await router(db)
    await add_check_row(db, binding, "ambiguous")
    with pytest.raises(UnqualifiedBackgroundStop, match="not_qualified"):
        await service.queue.stop(binding.id, "realm", 7, "direct-stop")
    async with db.sessions() as session:
        assert (await session.get(Binding, binding.id)).dispatch_paused
        assert await session.scalar(select(func.count()).select_from(Action)) == 2


async def test_stale_consumer_cannot_claim_check_queue_was_paused(db):
    import time

    from jt_oz_bridge.storage.models import WorkerLease

    service, binding, _source, _control, _audience = await router(db)
    await add_check_row(db, binding, "running")
    async with db.sessions.begin() as session:
        await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
    with pytest.raises(Conflict):
        await service.queue.request_stop(binding.id, "realm", 7, "expired-stop")
    async with db.sessions() as session:
        assert not (await session.get(Binding, binding.id)).dispatch_paused
        assert await session.scalar(select(func.count()).select_from(Action)) == 1


async def test_background_stop_requires_actual_consumer_fence(db):
    from jt_oz_bridge.services.queue import QueueService

    service, binding, _source, _control, _audience = await router(db)
    await add_check_row(db, binding, "running")
    with pytest.raises(Conflict, match="requires_consumer_fence"):
        await QueueService(service.bindings).request_stop(binding.id, "realm", 7, "unfenced")
    async with db.sessions() as session:
        assert not (await session.get(Binding, binding.id)).dispatch_paused


@pytest.mark.parametrize("drift", ["grant", "scope"])
async def test_background_stop_rechecks_authority_and_scope_after_awaited_binding_read(db, drift):
    service, binding, _source, _control, _audience = await router(db)
    await add_check_row(db, binding, "running")
    original_get = service.bindings.get

    async def changed(*args, **kwargs):
        value = await original_get(*args, **kwargs)
        async with db.sessions.begin() as session:
            if drift == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            else:
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(topic="changed scope")
                )
        return value

    service.bindings.get = changed
    with pytest.raises((Conflict, AccessDenied)):
        await service.queue.request_stop(binding.id, "realm", 7, "drifting")
    async with db.sessions() as session:
        assert not (await session.get(Binding, binding.id)).dispatch_paused
        assert await session.scalar(select(func.count()).select_from(Action)) == 1


async def test_background_stop_audit_failure_rolls_back_pause_and_hold(db, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession

    from jt_oz_bridge.storage.models import AuditEvent

    service, binding, source, _control, _audience = await router(db)
    await add_check_row(db, binding, "running")
    queued = await send(service, source, message("must stay queued"))
    original_add = AsyncSession.add

    def fail_audit(session, item, **kwargs):
        if (
            isinstance(item, AuditEvent)
            and item.event == "queue_paused_background_stop_unqualified"
        ):
            raise RuntimeError("synthetic audit failure")
        return original_add(session, item, **kwargs)

    monkeypatch.setattr(AsyncSession, "add", fail_audit)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        await service.queue.request_stop(binding.id, "realm", 7, "audit-fails")
    async with db.sessions() as session:
        assert not (await session.get(Binding, binding.id)).dispatch_paused
        assert (await session.get(Action, queued.action_id)).state == "queued"


@pytest.mark.parametrize("check_terminal", [False, True])
async def test_background_stop_replay_after_resume_never_becomes_dispatchable(db, check_terminal):
    from jt_oz_bridge.security.policy import Permission
    from jt_oz_bridge.services.dispatch import Dispatcher
    from tests.integration.test_dispatch import SyntheticExecution

    service, binding, source, _control, _audience = await router(db)
    check_id = await add_check_row(db, binding, "running")
    first = await service.queue.request_stop(binding.id, "realm", 7, "stable-stop-request")
    assert first.interrupt_action_id is None and first.background_stop_unqualified
    async with db.sessions() as session:
        request = await session.scalar(
            select(Action).where(Action.dedupe_key == "stop:realm:stable-stop-request")
        )
        request_id, version = request.id, request.version
    await service.queue.resume(binding.id, "realm", 7, binding.revision, 1)
    if check_terminal:
        async with db.sessions.begin() as session:
            await session.execute(
                update(Action)
                .where(Action.id == check_id)
                .values(state="completed", version=Action.version + 1)
            )
    replay = await service.queue.request_stop(binding.id, "realm", 7, "stable-stop-request")
    assert replay == first
    async with db.sessions() as session:
        current = await session.get(Binding, binding.id)
        request = await session.get(Action, request_id)
        assert not current.dispatch_paused and current.queue_revision == 2
        assert request.state == "rejected" and request.version == version
        assert (
            request.admission == {} and request.native_result == {} and request.upstream_id is None
        )
        assert await session.scalar(select(func.count()).select_from(Action)) == 2
    execution = SyntheticExecution()
    worker = Dispatcher(
        service.bindings, execution, source, service.inbox.holder, service.inbox.fencing
    )
    assert await worker.advance(request_id) == "rejected"
    assert not await worker.claim(request, current, Permission.OPERATE)
    await DurableStore(db).recover()
    assert await worker.advance(request_id) == "rejected"
    assert execution.submitted == []
    async with db.sessions() as session:
        assert (await session.get(Action, request_id)).state == "rejected"
        assert (await session.get(Action, check_id)).state == (
            "completed" if check_terminal else "running"
        )


@pytest.mark.parametrize(
    "conflict", ["source", "actor", "binding_revision", "root", "digest", "admission"]
)
async def test_background_stop_terminal_receipt_rejects_identity_or_provenance_conflicts(
    db, conflict
):
    service, binding, _source, _control, _audience = await router(db)
    check_id = await add_check_row(db, binding, "ambiguous")
    original = message("!oz stop", 301)
    await service.queue.request_stop(binding.id, "realm", 7, "conflicting-stop", source=original)
    actor, changed_source = 7, original
    async with db.sessions.begin() as session:
        if conflict == "actor":
            # The existing fixture already grants user 8 all three roles.
            actor = 8
            changed_source = original.model_copy(update={"author_id": 8})
        elif conflict == "binding_revision":
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(revision=2)
            )
        elif conflict == "root":
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(session_id="another-root")
            )
        elif conflict == "digest":
            await session.execute(
                update(Action)
                .where(Action.dedupe_key == "stop:realm:conflicting-stop")
                .values(operation_digest="0" * 64)
            )
        elif conflict == "admission":
            await session.execute(
                update(Action)
                .where(Action.dedupe_key == "stop:realm:conflicting-stop")
                .values(admission={"unexpected": "must reject"})
            )
        elif conflict == "source":
            changed_source = original.model_copy(update={"message_id": 302})
    with pytest.raises((Conflict, AccessDenied)):
        await service.queue.request_stop(
            binding.id, "realm", actor, "conflicting-stop", source=changed_source
        )
    async with db.sessions() as session:
        assert (await session.get(Binding, binding.id)).queue_revision == 1
        assert (await session.get(Action, check_id)).state == "ambiguous"
        assert await session.scalar(select(func.count()).select_from(Action)) == 2


async def test_public_binding_lookup_keeps_fresh_canonical_inspection_even_when_sql_absent(db):
    service, _binding, _source, _control, audience = await router(db)
    original, calls = audience.inspect, []

    async def inspect(*args):
        calls.append(args)
        return await original(*args)

    audience.inspect = inspect
    assert await service.binding_for(message(topic="Absent topic")) is None
    assert len(calls) == 1

    async def noncanonical(*args):
        return (await original(*args)).model_copy(update={"canonical_topic": "different"})

    audience.inspect = noncanonical
    with pytest.raises(Conflict, match="source_topic_not_canonical"):
        await service.binding_for(message(topic="Absent topic"))


async def test_status_says_when_an_old_waiting_message_was_sent_and_offers_buttons(db):
    import json
    import time

    from sqlalchemy import update

    service, _binding, source, _control, _audience = await router(db)
    old = await send(service, source, message("from three days ago"))
    await send(service, source, message("!stop", 102))
    sent = time.time() - 3 * 86400
    async with db.sessions.begin() as session:
        await session.execute(
            update(Action).where(Action.id == old.action_id).values(created_at=sent)
        )
    reply = await send(service, source, message("!status", 103))
    when = time.strftime("%m/%d %H:%M", time.localtime(sent))
    assert f"“from three days ago”: not sent; waiting for you (sent {when})" in unescape(reply.text)
    choices = json.loads(reply.widget)["extra_data"]["choices"]
    assert [c["reply"] for c in choices] == ["!go", "!no"]
    # A recent one says no time, and nothing waiting means no buttons.
    await send(service, source, message("!no", 104))
    assert (await send(service, source, message("!status", 105))).widget is None


@pytest.mark.parametrize(
    ("names", "note"),
    [
        (["vm_start"], "It is waiting for the tool vm&#95;start to finish."),
        ([], "The model is thinking or writing."),
        (None, None),  # The newest entry does not tell: nothing is said.
    ],
)
async def test_status_of_a_running_turn_says_whether_it_waits_on_a_tool_or_the_model(
    db, monkeypatch, names, note
):
    from jt_oz_bridge.domain.control import ExecutionState
    from jt_oz_bridge.services import router as router_module
    from tests.integration.test_dispatch import SyntheticExecution

    bindings, binding, control, _audience = await bound(db, control=SyntheticExecution())
    fence = await DurableStore(db).acquire_lease("router")
    source = Source()
    service = CommandRouter(bindings, source, CommandInbox(db, "router", fence))
    asked = []

    async def waits_on(session, seen):
        asked.append(seen.id)
        return names

    monkeypatch.setattr(router_module, "waits_on", waits_on)
    idle = (await send(service, source, message("!status", 101))).text
    assert asked == [] and "waiting for the tool" not in idle  # Only a running turn.
    control.state = ExecutionState.RUNNING
    running = (await send(service, source, message("!status", 102))).text
    assert asked == [binding.id]
    assert ("\n\n" + note in running) if note else "waiting for" not in running


async def test_what_a_topic_waits_on_is_read_from_its_own_transcript(db):
    from jt_oz_bridge.services.still_working import waits_on
    from tests.integration.test_transcript_publisher import Turn, step
    from tests.integration.test_typing_status import running_tool, unfinished

    t = await Turn().initialize(db)
    await t.add(unfinished("s1", running_tool("bash")))
    async with db.sessions() as session:
        assert await waits_on(session, t.binding) == ["bash"]
    await t.add(step("s2", "read"))  # A finished step: the model thinks about the next.
    async with db.sessions() as session:
        assert await waits_on(session, t.binding) == []
