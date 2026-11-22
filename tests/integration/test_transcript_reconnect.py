"""Synthetic Native/Source + encrypted own SQL, not live or Human acceptance."""

import copy
import json
import time
from html import unescape

import pytest
from sqlalchemy import func, select, update

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.execution import HumanMessage
from jt_oz_bridge.presentation.commands import parse_input
from jt_oz_bridge.services.command_receipts import CommandInbox
from jt_oz_bridge.services.router import CommandRouter
from jt_oz_bridge.services.tokens import TokenService
from jt_oz_bridge.services.transcript_reconnect import TranscriptReconnectService
from jt_oz_bridge.services.transcript_records import (
    TranscriptSnapshot,
    TranscriptState,
    read_snapshot,
    read_stream,
    validate_transcript_batch,
)
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict, digest
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from jt_oz_bridge.storage.transcript_models import (
    TranscriptCandidate,
    TranscriptMessage,
    TranscriptStream,
    TranscriptVersion,
)
from tests.integration.test_router import Source, message, send
from tests.integration.test_transcript_collector import entry, versions
from tests.integration.test_transcript_collector import setup as collector_setup
from tests.integration.test_transcript_publisher import assistant, baseline, output


async def setup(db, *, open_message=False, publisher=False, empty=False):
    collector, binding, native, audience = await collector_setup(db)
    source = Source()
    inbox = CommandInbox(db, collector.fence.holder, collector.fence.fencing)
    tokens = TokenService(db, fence=collector.fence)
    router = CommandRouter(
        collector.bindings, source, inbox, resume_guard=collector.require_continuity
    )
    reconnect = TranscriptReconnectService(collector, source, inbox, tokens)
    router.reconnect = reconnect
    native_current = native.current
    native.current = lambda page: (
        native_current(page)
        and page.owner_epoch == native.owner_epoch
        and page.observed_at <= time.time() < page.expires_at
    )
    if empty:
        native.messages = []
    if open_message:
        native.messages.insert(0, assistant("original_open", completed=False))
    primary = output(collector, native)
    if publisher:
        await baseline(primary, collector, binding)
    else:
        await collector.collect(binding)
    await restart(collector, binding, native, "1" * 64)
    return router, reconnect, collector, binding, source, native, audience, primary


async def restart(collector, binding, native, owner):
    native.owner_epoch = owner
    native.connection_epoch = "new-process:" + owner
    with pytest.raises(Conflict, match="original_owner"):
        await collector.collect(binding)
    state, _ = await collector.load(binding)
    assert state.status == "gap"


async def visible(db, primary, source, reply, *, posted=150, state="delivered"):
    batch = await primary.replies.publish(reply)
    async with db.sessions.begin() as session:
        rows = list(
            await session.scalars(
                select(Delivery).where(Delivery.batch_id == batch.id).order_by(Delivery.batch_index)
            )
        )
        for index, row in enumerate(rows):
            row.state, row.attempts, row.posted_message_id = state, 1, posted + index
            payload = row.payload
            source.messages[posted + index] = HumanMessage(
                realm_id=payload["realm_id"],
                channel_id=payload["channel_id"],
                topic=payload["topic"],
                message_id=posted + index,
                revision=0,
                author_id=payload["bot_user_id"],
                text=payload["content"],
                is_bot=True,
            )
    return batch


async def preview(v, db, *, command="!reconnect", message_id=101, posted=150):
    router, reconnect, collector, binding, source, native, audience, primary = v
    reply = await send(router, source, message(command, message_id))
    assert "!ok" in reply.text
    await visible(db, primary, source, reply, posted=posted)
    return reply


async def state(v):
    return (await v[2].load(v[3]))[0]


def preview_token(reply):
    """The token the preview names, which its desktop button sends as `!ok <token>`."""
    widget = json.loads(reply.widget)
    (button,) = widget["extra_data"]["choices"]
    command, token = button["reply"].split()
    assert command == "!ok" and f"!ok {token}" in unescape(reply.text)
    return token


async def test_original_owner_reconnect_preserves_binding_history_held_and_ambiguous_work(db):
    v = await setup(db, open_message=True, publisher=True)
    router, reconnect, collector, binding, source, native, audience, primary = v
    old = [copy.deepcopy(row.payload) for row in await versions(db)]
    held = await send(router, source, message("retained original prompt", 90))
    uncertain = await send(router, source, message("uncertain original prompt", 91))
    async with db.sessions.begin() as session:
        row = await session.get(Action, uncertain.action_id)
        row.state = "ambiguous"
    async with db.sessions() as session:
        actions_before = [
            (r.id, r.state, r.version, copy.deepcopy(r.payload))
            for r in await session.scalars(select(Action).order_by(Action.id))
        ]
        saved_binding = await session.get(Binding, binding.id)
        identity_before = (
            saved_binding.id,
            saved_binding.revision,
            saved_binding.session_id,
            saved_binding.backend_identity,
        )
    await preview(v, db)
    native.messages[0] = assistant("original_open", "Finished after restart")
    result = await send(router, source, message("!confirm", 200))
    assert "Reconnected" in result.text and result.delivery_key.startswith("reconnect:")
    recovered = await state(v)
    assert recovered.status == "live" and recovered.owner_epoch == "1" * 64
    assert len(recovered.owner_transitions) == 1 and not recovered.open_ids
    assert not recovered.gap_reason and not recovered.gap_plan
    async with db.sessions() as session:
        saved_binding = await session.get(Binding, binding.id)
        assert identity_before == (
            saved_binding.id,
            saved_binding.revision,
            saved_binding.session_id,
            saved_binding.backend_identity,
        )
        assert saved_binding.dispatch_paused
        assert actions_before == [
            (r.id, r.state, r.version, r.payload)
            for r in await session.scalars(select(Action).order_by(Action.id))
        ]
        assert len(actions_before) == 2 and held.action_id
        assert await session.scalar(select(func.count()).select_from(TranscriptCandidate)) == 0
    rows = await versions(db)
    assert [row.payload for row in rows if row.payload["format"].endswith("v1")] == old
    assert any(row.payload.get("owner_generation") == 1 for row in rows)
    assert all(call[0] == recovered.reference for call in native.calls)
    async with db.sessions() as session:
        for row in rows:
            record = await session.get(TranscriptMessage, row.record_id)
            read_snapshot(row, record, recovered)


@pytest.mark.parametrize("command", ["!reconnect", "!oz reconnect"])
async def test_both_command_forms_have_one_preview_and_no_action(db, command):
    v = await setup(db)
    first = await preview(v, db, command=command)
    assert await v[0].route(v[4].messages[101]) == first
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(ControlToken)) == 1
        assert await session.scalar(select(func.count()).select_from(Action)) == 0


async def test_lost_confirmation_ack_replays_saved_reply_without_scanning_or_reapplying(db):
    v = await setup(db)
    await preview(v, db)
    first = await send(v[0], v[4], message("!confirm", 200))
    before = await state(v)
    calls = len(v[5].calls)
    repeated = await v[0].route(v[4].messages[200])
    assert repeated == first and len(v[5].calls) == calls
    assert (await state(v)) == before
    old_token = await send(v[0], v[4], message("!confirm", 201))
    assert "expired" in old_token.text
    assert len((await state(v)).owner_transitions) == 1


async def test_multiple_owner_generations_keep_old_snapshots_and_pending_notice_sources(db):
    v = await setup(db, publisher=True)
    router, reconnect, collector, binding, source, native, audience, primary = v
    old_state = await state(v)
    first_gap = await primary.scope_notice(old_state.key, "gap")
    await preview(v, db)
    native.messages.insert(0, entry("first_generation_input"))
    await send(router, source, message("!confirm", 200))
    first_state = await state(v)
    assert first_state.owner_transitions[0].previous_gap_plan["batch_id"] == first_gap
    await restart(collector, binding, native, "2" * 64)
    second_gap = await primary.scope_notice(first_state.key, "gap")
    assert second_gap != first_gap
    await preview(v, db, message_id=301, posted=350)
    native.messages.insert(0, entry("second_generation_input"))
    await send(router, source, message("!confirm", 400))
    final = await state(v)
    assert len(final.owner_transitions) == 2
    async with db.sessions() as session:
        for batch in (first_gap, second_gap):
            await validate_transcript_batch(session, batch, binding, 77, None)
        for row in await session.scalars(select(TranscriptVersion)):
            record = await session.get(TranscriptMessage, row.record_id)
            read_snapshot(row, record, final)
    counts = len(await versions(db))
    await collector.collect(binding)
    assert len(await versions(db)) == counts


@pytest.mark.parametrize(
    "damage",
    [
        "anchor-missing",
        "anchor-changed",
        "open-core",
        "open-missing",
        "semantics",
        "contract",
        "foreign-ref",
        "owner-unchanged",
        "unknown-state",
        "repeated-page",
        "closing-head",
    ],
)
async def test_native_history_or_identity_mismatch_cannot_issue_preview(db, damage):
    v = await setup(db, open_message=True)
    native = v[5]
    if damage == "anchor-missing":
        native.messages = native.messages[1:]
    elif damage == "anchor-changed":
        # The closed original anchor is now msg_0 if the open message is removed
        # only after retaining it as another original open ID.
        native.messages[0] = assistant("original_open", completed=False).model_copy(
            update={"kind": "shell"}
        )
    elif damage == "open-core":
        value = native.messages[0].projection()
        value["agent"] = "other-agent"
        from jt_oz_bridge.adapters.opencode.transcript import project_message

        native.messages[0] = project_message(value)
    elif damage == "open-missing":
        native.messages = [entry("other")]
    elif damage == "foreign-ref":
        native.foreign = True
    elif damage == "owner-unchanged":
        native.owner_epoch = "d" * 64
    elif damage == "unknown-state":
        native.state = ExecutionState.UNKNOWN
    elif damage in {"contract", "semantics"}:
        original = native.capture

        async def changed(*args, **kwargs):
            page = (await original(*args, **kwargs)).model_copy(
                update={damage + "_sha256": "9" * 64}
            )
            native.pages.append(page)
            return page

        native.capture = changed
    elif damage == "repeated-page":
        native.messages = [entry("duplicate"), entry("duplicate"), *native.messages]
    else:
        original = native.capture
        calls = 0

        async def changed(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                native.messages.insert(0, entry("changed_closing_frontier"))
            return await original(*args, **kwargs)

        native.capture = changed
    reply = await send(v[0], v[4], message("!reconnect", 101))
    assert "!ok" not in reply.text
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(ControlToken)) == 0
        assert await session.scalar(select(func.count()).select_from(Action)) == 0
    assert (await state(v)).status == "gap"


@pytest.mark.parametrize(
    "damage",
    [
        "actor",
        "topic",
        "realm",
        "source-edit",
        "source-deleted",
        "source-unknown",
        "audience",
        "grant",
        "binding",
        "owner",
        "expired-token",
        "token-kind",
        "token-context",
        "bot-preview-edit",
        "bot-preview-delete",
    ],
)
async def test_confirmation_rechecks_original_source_permission_token_and_owner(db, damage):
    v = await setup(db)
    shown = await preview(v, db)
    # Another allowed person's plain `!ok`, and a plain `!ok` once the preview's two
    # minutes are over, reconnect from a fresh proof (see the one-step tests). Here
    # the preview's own token must still refuse them.
    item = message(
        "!ok " + preview_token(shown) if damage in {"actor", "expired-token"} else "!confirm", 200
    )
    if damage in {"actor", "topic", "realm"}:
        item = item.model_copy(
            update={
                {"actor": "author_id", "topic": "topic", "realm": "realm_id"}[damage]: {
                    "actor": 8,
                    "topic": "another",
                    "realm": "other",
                }[damage]
            }
        )
    elif damage == "source-edit":
        v[4].messages[101] = (
            v[4].messages[101].model_copy(update={"revision": 1, "text": "!oz stop"})
        )
    elif damage == "source-deleted":
        v[4].messages[101] = v[4].messages[101].model_copy(update={"deleted": True})
    elif damage == "source-unknown":
        del v[4].messages[101]
    elif damage in {"bot-preview-edit", "bot-preview-delete"}:
        v[4].messages[150] = (
            v[4]
            .messages[150]
            .model_copy(update={"text": "tampered", "deleted": damage.endswith("delete")})
        )
    elif damage == "audience":
        v[6].users = frozenset({7, 8, 999})
    elif damage == "owner":
        v[5].owner_epoch = "2" * 64
    else:
        async with db.sessions.begin() as session:
            if damage == "grant":
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
            elif damage == "binding":
                await session.execute(
                    update(Binding).where(Binding.id == v[3].id).values(revision=2)
                )
            elif damage == "expired-token":
                await session.execute(update(ControlToken).values(expires_at=time.time() - 1))
            elif damage == "token-kind":
                await session.execute(update(ControlToken).values(kind="form-cancel"))
            elif damage == "token-context":
                await session.execute(update(ControlToken).values(context={"wrong": True}))
    try:
        result = await send(v[0], v[4], item)
        assert "Reconnected" not in result.text
    except (ValueError, KeyError):
        pass
    assert not (await state(v)).owner_transitions
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(Action)) == 0


@pytest.mark.parametrize("delivery", ["pending", "sending", "ambiguous", "late", "missing"])
async def test_shortcut_requires_fully_delivered_preview_before_confirmation(db, delivery):
    v = await setup(db)
    reply = await send(v[0], v[4], message("!reconnect", 101))
    if delivery != "missing":
        await visible(
            db,
            v[7],
            v[4],
            reply,
            posted=250 if delivery == "late" else 150,
            state=delivery if delivery not in {"late"} else "delivered",
        )
    result = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" not in result.text
    assert not (await state(v)).owner_transitions


@pytest.mark.parametrize("point", ["before-finalize", "after-finalize", "after-flush"])
async def test_witness_loss_rolls_back_token_stream_versions_and_command_transition(db, point):
    v = await setup(db)
    await preview(v, db)
    native, collector = v[5], v[2]
    before = [copy.deepcopy(r.payload) for r in await versions(db)]
    original = collector.finalize

    async def fail(*args, **kwargs):
        if point == "before-finalize":
            raise Conflict("synthetic-crash-before-finalize")
        result = await original(*args, **kwargs)
        if point == "after-finalize":
            raise Conflict("synthetic-crash-after-finalize")
        native.alive = False
        return result

    collector.finalize = fail
    reply = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" not in reply.text
    assert [r.payload for r in await versions(db)] == before
    assert not (await state(v)).owner_transitions
    async with db.sessions() as session:
        assert not (await session.scalar(select(ControlToken))).used
        assert await session.scalar(select(func.count()).select_from(TranscriptCandidate)) == 0
        assert (await session.get(Binding, v[3].id)).dispatch_paused


async def test_v1_roundtrip_remains_exact_and_v2_chain_and_generation_are_strict(db):
    v = await setup(db)
    old, _ = await v[2].load(v[3])
    payload = old.model_dump(mode="json")
    assert "owner_transitions" not in payload
    assert TranscriptState.model_validate(payload).model_dump(mode="json") == payload
    first = (await versions(db))[0]
    assert "owner_generation" not in first.payload
    assert TranscriptSnapshot.model_validate(first.payload).model_dump(mode="json") == first.payload
    await preview(v, db)
    await send(v[0], v[4], message("!confirm", 200))
    current = await state(v)
    body = current.model_dump(mode="json")
    for key in ("scope_key", "new_owner", "generation", "previous_hash"):
        corrupt = copy.deepcopy(body)
        corrupt["owner_transitions"][0][key] = "corrupt" if key != "generation" else 2
        with pytest.raises(ValueError):
            TranscriptState.model_validate(corrupt)
    async with db.sessions() as session:
        record = await session.get(TranscriptMessage, first.record_id)
        changed = copy.deepcopy(first.payload)
        changed.update(format="native-transcript-snapshot-v2", owner_generation=1)
        first.payload, first.payload_hash = changed, digest(changed)
        with pytest.raises(Conflict):
            read_snapshot(first, record, current)


@pytest.mark.parametrize("mode", ["recovered", "edited", "bot", "quoted", "invalid-arguments"])
async def test_controls_do_not_replay_or_become_prompts_unexpectedly(db, mode):
    v = await setup(db)
    item = message("!reconnect", 101)
    if mode == "edited":
        item = item.model_copy(update={"revision": 1})
    elif mode == "bot":
        item = item.model_copy(update={"is_bot": True})
    elif mode == "quoted":
        assert parse_input("'!reconnect'", bound=True).kind == "prompt"
        return
    elif mode == "invalid-arguments":
        item = message("!oz reconnect unexpected", 101)
    reply = await send(v[0], v[4], item, recovered=mode == "recovered")
    assert "!ok" not in reply.text
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(ControlToken)) == 0
        assert await session.scalar(select(func.count()).select_from(Action)) == 0


async def test_two_authorized_people_have_separate_latest_previews_but_one_stream_cas(db):
    v = await setup(db)
    first = await preview(v, db)
    second = await send(v[0], v[4], message("!reconnect", 102, author_id=8))
    await visible(db, v[7], v[4], second, posted=160)
    assert "!ok" in first.text and "!ok" in second.text
    answer = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" in answer.text
    loser = await send(v[0], v[4], message("!confirm", 201, author_id=8))
    assert "Reconnected" not in loser.text
    assert len((await state(v)).owner_transitions) == 1


async def test_success_invalidates_stale_native_tokens_and_prior_resume_revision(db):
    v = await setup(db)
    old_revision = v[3].queue_revision
    stale = []
    for kind in ("interaction", "form-step", "form-submit", "form-cancel", "native-git-commit"):
        stale.append(
            await v[1].tokens.issue(
                kind,
                "realm",
                7,
                {"synthetic": True},
                binding_id=v[3].id,
                binding_revision=v[3].revision,
            )
        )
    other = await v[1].tokens.issue("navigation", "realm", 7, {"synthetic": True})
    await preview(v, db)
    await send(v[0], v[4], message("!confirm", 200))
    async with db.sessions() as session:
        current = await session.get(Binding, v[3].id)
        assert current.queue_revision == old_revision + 1 and current.dispatch_paused
        rows = list(
            await session.scalars(select(ControlToken).where(ControlToken.binding_id == current.id))
        )
        assert all(row.used for row in rows)
    for opaque in stale:
        with pytest.raises(Conflict):
            await v[1].tokens.inspect_allowed(
                opaque,
                frozenset(
                    {"interaction", "form-step", "form-submit", "form-cancel", "native-git-commit"}
                ),
                "realm",
                7,
            )
    assert await v[1].tokens.inspect(other, "navigation", "realm", 7)


async def test_queue_revision_change_after_preview_requires_fresh_preview(db):
    v = await setup(db)
    await preview(v, db)
    async with db.sessions.begin() as session:
        await session.execute(
            update(Binding)
            .where(Binding.id == v[3].id)
            .values(queue_revision=Binding.queue_revision + 1)
        )
    result = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" not in result.text
    assert not (await state(v)).owner_transitions


async def test_source_and_owner_change_at_commit_do_not_consume_preview(db):
    v = await setup(db)
    await preview(v, db)
    finish = v[1].inbox.finish

    async def changed(claim, response, *, commit=None):
        # A fresh GET completed; the process is replaced before the transaction.
        if response.get("transition_id"):
            v[5].owner_epoch = "2" * 64
        return await finish(claim, response, commit=commit)

    v[1].inbox.finish = changed
    result = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" not in result.text
    async with db.sessions() as session:
        assert not (await session.scalar(select(ControlToken))).used
    assert not (await state(v)).owner_transitions


async def test_consumer_fence_loss_cannot_commit_reconnect(db):
    from jt_oz_bridge.storage.durable import DurableStore

    v = await setup(db)
    await preview(v, db)
    original = v[5].capture
    lost = False

    async def changed(*args, **kwargs):
        nonlocal lost
        page = await original(*args, **kwargs)
        if not lost:
            lost = True
            async with db.sessions.begin() as session:
                from jt_oz_bridge.storage.models import WorkerLease

                await session.execute(update(WorkerLease).values(expires_at=time.time() - 1))
            assert await DurableStore(db).acquire_lease("new-consumer")
        return page

    v[5].capture = changed
    with pytest.raises(Conflict):
        await send(v[0], v[4], message("!confirm", 200))
    assert not (await state(v)).owner_transitions


async def test_bounded_owner_chain_refuses_more_restarts_with_explicit_message(db):
    from jt_oz_bridge.services.transcript_records import TranscriptOwnerTransition

    v = await setup(db)
    current = await state(v)
    transitions, previous, owner = [], "0" * 64, "d" * 64
    for generation in range(1, 33):
        facts = dict(
            id=f"synthetic-transition-{generation}",
            scope_key=current.key,
            generation=generation,
            old_owner=owner,
            new_owner=f"{generation:064x}",
            previous_hash=previous,
            previous_stream_hash="a" * 64,
            actor_id=7,
            source_message_id=generation,
            source_hash="b" * 64,
            proof_hash="c" * 64,
            previous_gap_plan=None,
        )
        transition = TranscriptOwnerTransition.model_validate({**facts, "checksum": digest(facts)})
        transitions.append(transition)
        previous, owner = transition.checksum, transition.new_owner
    payload = current.model_dump(mode="json")
    payload.update(
        format="native-transcript-stream-v2",
        owner_epoch=owner,
        owner_transitions=[t.model_dump(mode="json") for t in transitions],
    )
    value = TranscriptState.model_validate(payload)
    async with db.sessions.begin() as session:
        row = await session.get(TranscriptStream, current.key)
        row.payload, row.payload_hash = (
            value.model_dump(mode="json"),
            digest(value.model_dump(mode="json")),
        )
    before = len(v[5].calls)
    reply = await send(v[0], v[4], message("!reconnect", 101))
    assert "recovery limit" in reply.text
    assert len(v[5].calls) == before
    assert len((await state(v)).owner_transitions) == 32


async def test_existing_draft_and_pending_publication_remain_valid_after_owner_reconnect(db):
    from jt_oz_bridge.services.transcript_drafts import TranscriptDraftPublisher
    from tests.integration.test_transcript_publisher import drain

    v = await setup(db, publisher=True)
    # Enable original collector drafting; this is a synthetic ownDB fixture.
    v[2].drafts_enabled = True
    await preview(v, db)
    v[5].messages.insert(
        0, assistant("new_owner_partial", "Original resumed draft", completed=False)
    )
    await send(v[0], v[4], message("!confirm", 200))
    await drain(v[7])
    drafts = TranscriptDraftPublisher(v[2], v[7].replies, v[7].formatter)
    pending = await drafts.next_pending()
    assert pending is not None
    batch = await drafts.publish(pending)
    assert batch is not None
    async with db.sessions() as session:
        row = await session.get(TranscriptStream, (await state(v)).key)
        assert read_stream(row, v[3]).owner_epoch == "1" * 64
        assert await session.scalar(select(func.count()).select_from(Action)) == 0


async def test_real_consumer_composition_uses_closed_source_journal_without_native_submit(
    db, monkeypatch
):
    """Real HTTP mock/issuer/journal path; still not live or Human evidence."""
    from dataclasses import replace

    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
    from tests.integration.test_closed_bound_queue import live_identity
    from tests.integration.test_consumer_runtime import rows
    from tests.integration.test_consumer_runtime import visible as body
    from tests.integration.test_transcript_commands import OriginalReader
    from tests.support import REF

    old, server, native, binding, _, _, _ = await live_identity(db, monkeypatch, initial_prompts=0)
    reader = OriginalReader()
    reader.contract_hash = INSTALLED_SCHEMA
    backend = replace(old.backends[REF.backend_id], transcripts={REF: reader})
    old.scope.client.budget = ZulipRequestBudget(requests=1800)
    pipeline = ConsumerPipeline(
        db,
        old.fence,
        old.scope,
        {REF.backend_id: backend},
        mirror_enabled=True,
        interval=0.02,
        delivery_interval=0,
    )
    try:
        assert pipeline.router.reconnect is not None
        await pipeline.consumer.start()
        await pipeline.mirror_once()
        await pipeline.deliver_once()
        await restart(pipeline.mirrors, binding, reader, "1" * 64)
        for text in ("!reconnect", "!confirm"):
            mid = max(server.messages) + 1
            server.next_mid = mid + 1
            server.input(text, mid, topic=binding.topic)
            result = await pipeline.consumer.poll()
            assert result[-1] == "reply"
            await pipeline.deliver_once()
        assert any("Reconnected" in body(post["content"]) for post in server.posts)
        assert not native.submitted and not await rows(db, Action)
        async with db.sessions() as session:
            # The gap set the only pause, so the person's `!ok` lifts it: no `!go`.
            assert not (await session.get(Binding, binding.id)).dispatch_paused
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("flow", ["preview", "one-step"])
@pytest.mark.parametrize("during", ["sent-and-dropped", "paused-by-person"])
async def test_messages_sent_during_the_gap_go_after_ok_unless_a_person_paused(
    db, monkeypatch, during, flow
):
    """After `hi`, `!no`, `ok`, `!reconnect` and `!ok`, nothing should still need `!go`."""
    from dataclasses import replace

    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
    from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
    from jt_oz_bridge.i18n import Translator
    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
    from tests.integration.test_closed_bound_queue import live_identity
    from tests.integration.test_consumer_runtime import rows
    from tests.integration.test_consumer_runtime import visible as body
    from tests.integration.test_transcript_commands import OriginalReader
    from tests.support import REF

    old, server, native, binding, _, _, _ = await live_identity(db, monkeypatch, initial_prompts=0)
    reader = OriginalReader()
    reader.contract_hash = INSTALLED_SCHEMA
    backend = replace(old.backends[REF.backend_id], transcripts={REF: reader})
    old.scope.client.budget = ZulipRequestBudget(requests=1800)
    pipeline = ConsumerPipeline(
        db,
        old.fence,
        old.scope,
        {REF.backend_id: backend},
        mirror_enabled=True,
        interval=0.02,
        delivery_interval=0,
    )
    tr = Translator()

    async def say(text):
        mid = max(server.messages) + 1
        server.next_mid = mid + 1
        server.input(text, mid, topic=binding.topic)
        await pipeline.consumer.poll()
        await pipeline.deliver_once()
        return body(server.posts[-1]["content"])

    try:
        await pipeline.consumer.start()
        await pipeline.mirror_once()
        await pipeline.deliver_once()
        await restart(pipeline.mirrors, binding, reader, "1" * 64)
        # A bare "ok" asks whether `!ok` was meant instead of waiting.
        asked = tr.render("router.bare_answer_ok", "en", word="ok")
        if during == "sent-and-dropped":
            assert tr.render("router.paused_gap", "en") in await say("hi")
            await say("!no")
            assert asked in await say("ok")
            assert tr.render("router.paused_gap", "en") in await say("go on")
        else:
            await say("!stop")
            assert asked in await say("ok")
            assert tr.render("router.paused_gap_stopped", "en") in await say("go on")
        if flow == "preview":
            assert "!ok" in await say("!reconnect")
            done = await say("!confirm")
        else:
            # The paused notice says one `!ok` reconnects: no `!reconnect` first.
            done = await say("!ok")
        assert not native.submitted
        held = [
            a
            for a in await rows(db, Action)
            if a.operation == "prompt" and a.state in {"queued", "held"}
        ]
        assert len(held) == 1
        async with db.sessions() as session:
            paused = (await session.get(Binding, binding.id)).dispatch_paused
            state_now = (await session.get(Action, held[0].id)).state
        if during == "sent-and-dropped":
            # The preview promised waiting messages go in order: no `!go`.
            assert tr.render("reconnect.resumed", "en") in done
            assert not paused and state_now == "queued"
        else:
            assert tr.render("reconnect.completed", "en") in done
            assert paused and state_now == "held"
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("change_source", ["unchanged", "edited", "deleted"])
async def test_held_prompt_requires_fresh_resume_and_original_source_before_dispatch(
    db, change_source
):
    from jt_oz_bridge.services.dispatch import Dispatcher
    from tests.integration.test_dispatch import SyntheticExecution

    v = await setup(db)
    execution = SyntheticExecution()
    v[2].bindings.control = execution
    prompt = message("original held task", 90)
    held = await send(v[0], v[4], prompt)
    worker = Dispatcher(v[2].bindings, execution, v[4], v[2].fence.holder, v[2].fence.fencing)
    await preview(v, db)
    await send(v[0], v[4], message("!confirm", 200))
    assert await worker.advance(held.action_id) == "held" and not execution.submitted
    async with db.sessions() as session:
        before_resume = await session.get(Binding, v[3].id)
        qrev = before_resume.queue_revision
        assert before_resume.dispatch_paused
        assert (await session.get(Action, held.action_id)).state == "held"
    resumed = await send(v[0], v[4], message("!oz queue resume", 201))
    from jt_oz_bridge.i18n import Translator

    assert resumed.text == Translator().render("router.resumed", "en")
    async with db.sessions() as session:
        after_resume = await session.get(Binding, v[3].id)
        assert not after_resume.dispatch_paused and after_resume.queue_revision == qrev + 1
        assert (await session.get(Action, held.action_id)).state == "queued"
    if change_source == "edited":
        v[4].messages[90] = prompt.model_copy(update={"revision": 1, "text": "changed later"})
    elif change_source == "deleted":
        v[4].messages[90] = prompt.model_copy(update={"deleted": True})
    result = await worker.advance(held.action_id)
    if change_source == "deleted":
        assert not execution.submitted and result != "admitted"
    else:
        assert result == "admitted" and len(execution.submitted) == 1
        assert execution.submitted[0][0] == (await state(v)).reference
        assert execution.submitted[0][1]["text"] == (
            "changed later" if change_source == "edited" else "original held task"
        )
        assert await worker.advance(held.action_id) == "admitted"
        assert len(execution.submitted) == 1


async def test_old_live_text_pending_delivery_is_held_across_owner_generation(db):
    from jt_oz_bridge.services.draft_records import validate_draft_batch
    from jt_oz_bridge.storage.live_models import TranscriptLiveDraftPublication
    from tests.integration.test_live_drafts import LiveFixture

    f = await LiveFixture().initialize(db)
    await f.emit("Transient text from the old Native process")
    old_batch = await f.draft_batch()
    async with db.sessions() as session:
        publication = await session.scalar(
            select(TranscriptLiveDraftPublication).where(
                TranscriptLiveDraftPublication.batch_id == old_batch
            )
        )
        old_candidate, old_hash = copy.deepcopy(publication.candidate), publication.candidate_hash
        dependency = publication.plan["after_batch_id"]
    original = f.reader.capture

    async def restarted(*args, **kwargs):
        page = (await original(*args, **kwargs)).model_copy(
            update={"owner_epoch": "1" * 64, "connection_epoch": "synthetic-new-process"}
        )
        f.reader.pages.append(page)
        return page

    f.reader.capture = restarted
    await restart(f.collector, f.binding, f.reader, "1" * 64)
    source = Source()
    inbox = CommandInbox(db, f.collector.fence.holder, f.collector.fence.fencing)
    router = CommandRouter(f.collector.bindings, source, inbox)
    reconnect = TranscriptReconnectService(
        f.collector, source, inbox, TokenService(db, fence=f.collector.fence)
    )
    router.reconnect = reconnect
    v = (router, reconnect, f.collector, f.binding, source, f.reader, f.audience, f.primary)
    await preview(v, db)
    result = await send(router, source, message("!confirm", 200))
    assert "Reconnected" in result.text
    async with db.sessions() as session:
        current = await session.get(TranscriptLiveDraftPublication, publication.id)
        assert (current.candidate, current.candidate_hash) == (old_candidate, old_hash)
        with pytest.raises(Conflict, match="draft_no_longer_active"):
            await validate_draft_batch(session, old_batch, f.binding, 77, dependency)


async def test_native_history_is_paged_without_replaying_new_messages_twice(db):
    v = await setup(db)
    v[5].messages[:0] = [entry(f"during_restart_{i}") for i in range(45)]
    await preview(v, db)
    result = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" in result.text
    assert len([r for r in await versions(db) if not r.payload["historical"]]) == 45
    assert any(call[1] == "opaque:40" for call in v[5].calls)
    before = len(await versions(db))
    await v[2].collect(v[3])
    assert len(await versions(db)) == before


async def test_concurrent_confirmations_have_one_consumed_token_and_transition(db):
    import asyncio

    v = await setup(db)
    await preview(v, db)
    results = await asyncio.gather(
        send(v[0], v[4], message("!confirm", 200)),
        send(v[0], v[4], message("!confirm", 201)),
        return_exceptions=True,
    )
    assert sum(not isinstance(r, BaseException) and "Reconnected" in r.text for r in results) == 1
    assert len((await state(v)).owner_transitions) == 1
    async with db.sessions() as session:
        assert (await session.scalar(select(ControlToken))).used
        assert await session.scalar(select(func.count()).select_from(TranscriptCandidate)) == 0


async def test_completed_anchor_projection_change_is_not_a_restart_reconnect(db):
    v = await setup(db)
    original = v[5].messages[0]
    v[5].messages[0] = entry(original.native_id, "different historical input")
    result = await send(v[0], v[4], message("!reconnect", 101))
    assert "!ok" not in result.text
    assert not (await state(v)).owner_transitions


@pytest.mark.parametrize("new_input", [False, True])
async def test_original_empty_session_reconnect_proves_bounded_history_without_replacement(
    db, new_input
):
    v = await setup(db, empty=True)
    if new_input:
        v[5].messages.insert(0, entry("first_original_input"))
    await preview(v, db)
    result = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" in result.text
    assert len(await versions(db)) == int(new_input)
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(Binding)) == 1
        assert await session.scalar(select(func.count()).select_from(Action)) == 0


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_gap_help_offers_verified_reconnect_without_a_rebind_bypass(locale):
    from jt_oz_bridge.i18n import Translator

    text = Translator().render("mirror.gap", locale)
    assert "!history" in text and "!reconnect" in text
    assert "unbind" not in text and "重新綁定" not in text and "解除綁定" not in text
    assert ("ask an administrator" if locale == "en" else "請找管理員") in text


async def test_explicit_form_confirmation_keeps_its_original_handler_when_reconnect_is_wired(
    db, monkeypatch
):
    from unittest.mock import AsyncMock

    v = await setup(db)
    token = await v[1].tokens.issue(
        "form-cancel",
        "realm",
        7,
        {"synthetic": True},
        binding_id=v[3].id,
        binding_revision=v[3].revision,
    )
    handler = AsyncMock(return_value="Existing form confirmation handler")
    monkeypatch.setattr(v[0].permissions.forms, "confirm_cancel", handler)
    before = len(v[5].calls)
    reply = await send(v[0], v[4], message("!oz confirm " + token, 200))
    assert reply.text == "Existing form confirmation handler"
    handler.assert_awaited_once()
    assert len(v[5].calls) == before and not (await state(v)).owner_transitions


async def test_closed_source_keeps_the_issuers_original_audience_object(db, monkeypatch):
    """Equal final DTOs never substitute the object that issued the permit."""
    from jt_oz_bridge.adapters.zulip.scope import ZulipScopeReader
    from tests.integration.test_transcript_reconnect_provenance import input_control, real_pipeline

    pipeline, server, native, binding = await real_pipeline(db, monkeypatch)
    original_side = ZulipScopeReader._operation_side
    original_require = ZulipScopeReader.require_write_permit
    audiences, checks = [], []

    async def record_side(scope_reader, *args, **kwargs):
        audience = await original_side(scope_reader, *args, **kwargs)
        audiences.append(audience)
        return audience

    def require_original(scope_reader, permit, source_reader, actor, audience):
        phase = scope_reader._local_write_permits.get(permit)
        assert phase is not None and phase.audience is audience
        assert phase.actor is actor and phase.reader is source_reader
        checks.append(phase)
        return original_require(scope_reader, permit, source_reader, actor, audience)

    monkeypatch.setattr(ZulipScopeReader, "_operation_side", record_side)
    monkeypatch.setattr(ZulipScopeReader, "require_write_permit", require_original)
    try:
        _, result = await input_control(pipeline, server, binding, "!reconnect")
        assert result[-1] == "reply"
        assert len(audiences) >= 2 and len(audiences) % 2 == 0
        openings = audiences[::2]
        for opening, closing in zip(openings, audiences[1::2], strict=True):
            assert opening == closing and opening is not closing
        assert checks and all(
            any(phase.audience is opening for opening in openings) for phase in checks
        )
        async with db.sessions() as session:
            tokens = list(await session.scalars(select(ControlToken)))
            assert len(tokens) == 1 and not tokens[0].used
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


def test_owner_transition_kinds_name_a_person_only_when_confirmed():
    from jt_oz_bridge.services.transcript_records import TranscriptOwnerTransition

    def sealed(**changes):
        facts = dict(
            id="synthetic-transition",
            scope_key="a" * 64,
            generation=1,
            old_owner="d" * 64,
            new_owner="1" * 64,
            previous_hash="0" * 64,
            previous_stream_hash="a" * 64,
            actor_id=7,
            source_message_id=200,
            source_hash="b" * 64,
            proof_hash="c" * 64,
            previous_gap_plan=None,
        )
        facts.update(changes)
        return TranscriptOwnerTransition.model_validate({**facts, "checksum": digest(facts)})

    # Records written before automatic reconnect keep their exact bytes and seal.
    confirmed = sealed()
    assert confirmed.kind == "confirmed" and "kind" not in confirmed.model_dump(mode="json")
    automatic = sealed(kind="automatic", actor_id=0, source_message_id=0)
    assert automatic.model_dump(mode="json")["kind"] == "automatic"
    for wrong in (
        dict(actor_id=0, source_message_id=0),
        dict(kind="automatic"),
        dict(kind="automatic", actor_id=0),
    ):
        with pytest.raises(ValueError):
            sealed(**wrong)
    # The kind is sealed: an automatic record cannot be relabelled as confirmed.
    relabelled = automatic.model_dump(mode="json")
    relabelled.pop("kind")
    with pytest.raises(ValueError):
        TranscriptOwnerTransition.model_validate(relabelled)


async def transitions(db):
    from jt_oz_bridge.storage.models import AuditEvent

    async with db.sessions() as session:
        return [
            (row.actor, row.object_id)
            for row in await session.scalars(
                select(AuditEvent).where(AuditEvent.event == "transcript.owner_reconnected")
            )
        ]


@pytest.mark.parametrize("command", ["!ok", "!confirm"])
async def test_one_plain_ok_after_the_restart_reconnects_without_a_preview(db, command):
    """One `!ok` after the restart notice is enough to reconnect."""
    from jt_oz_bridge.i18n import Translator

    v = await setup(db)
    router, source, native = v[0], v[4], v[5]
    held = await send(router, source, message("retained original prompt", 90))
    reply = await send(router, source, message(command, 200))
    assert unescape(reply.text) == Translator().render("reconnect.completed", "en")
    assert reply.delivery_key.startswith("reconnect:")
    # Still paused: desktop gets buttons for the two commands the reply names.
    choices = json.loads(reply.widget)["extra_data"]["choices"]
    assert [c["reply"] for c in choices] == ["!status", "!go"]
    recovered = await state(v)
    assert recovered.status == "live" and recovered.owner_epoch == "1" * 64
    ((transition),) = recovered.owner_transitions
    assert (transition.kind, transition.actor_id, transition.source_message_id) == (
        "confirmed",
        7,
        200,
    )
    assert await transitions(db) == [("realm:7", transition.id)]
    async with db.sessions() as session:
        # No preview was issued, and the held prompt is untouched.
        assert await session.scalar(select(func.count()).select_from(ControlToken)) == 0
        assert (await session.get(Action, held.action_id)).state == "held"
        assert (await session.get(Binding, v[3].id)).dispatch_paused
    # A replayed claim returns the saved reply; nothing is read or applied again.
    calls = len(native.calls)
    assert await router.route(source.messages[200]) == reply
    assert len(native.calls) == calls and await state(v) == recovered
    assert len(await transitions(db)) == 1
    # Now live: a further plain `!ok` is not a reconnect; it says nothing is waiting.
    again = await send(router, source, message(command, 201))
    assert unescape(again.text) == Translator().render("router.nothing_to_confirm", "en")
    assert len((await state(v)).owner_transitions) == 1


@pytest.mark.parametrize("preview_state", ["delivered", "pending", "late", "unclear"])
async def test_a_plain_ok_answers_an_open_preview_as_before(db, preview_state):
    v = await setup(db)
    router, source = v[0], v[4]
    shown = await send(router, source, message("!reconnect", 101))
    if preview_state != "pending":
        await visible(
            db,
            v[7],
            source,
            shown,
            posted=250 if preview_state == "late" else 150,
            state="sending" if preview_state == "unclear" else "delivered",
        )
    result = await send(router, source, message("!ok", 200))
    current = await state(v)
    async with db.sessions() as session:
        (token,) = list(await session.scalars(select(ControlToken)))
    if preview_state == "delivered":
        # The preview's own path: its token is the one used up.
        assert "Reconnected" in result.text and token.used
        assert [t.source_message_id for t in current.owner_transitions] == [200]
    else:
        assert "Reconnected" not in result.text and not token.used
        assert current.status == "gap" and not current.owner_transitions


async def test_a_plain_ok_after_the_preview_expired_reconnects_from_a_fresh_proof(db):
    v = await setup(db)
    shown = await preview(v, db)
    async with db.sessions.begin() as session:
        await session.execute(update(ControlToken).values(expires_at=time.time() - 1))
    stale = await send(v[0], v[4], message("!ok " + preview_token(shown), 200))
    assert "Reconnected" not in stale.text and not (await state(v)).owner_transitions
    result = await send(v[0], v[4], message("!ok", 201))
    assert "Reconnected" in result.text
    assert [t.source_message_id for t in (await state(v)).owner_transitions] == [201]


@pytest.mark.parametrize("who", [7, 8])
async def test_a_person_not_allowed_to_reconnect_cannot_do_it_in_one_step(db, who):
    from jt_oz_bridge.i18n import Translator

    v = await setup(db)
    async with db.sessions.begin() as session:
        # Still a member who may view and approve, but not operate this project.
        await session.execute(
            update(Grant)
            .where(Grant.user_id == who, Grant.role.in_(("operator", "administrator")))
            .values(active=False)
        )
    result = await send(v[0], v[4], message("!ok", 200, author_id=who))
    assert unescape(result.text) == Translator().render("permission.denied", "en")
    current = await state(v)
    assert current.status == "gap" and not current.owner_transitions
    assert not await transitions(db)
    async with db.sessions() as session:
        assert (await session.get(Binding, v[3].id)).dispatch_paused


async def test_a_preview_opened_during_the_one_step_refuses_it(db, monkeypatch):
    v = await setup(db)
    reconnect = v[1]
    original = reconnect._preview_open
    calls = []

    async def opened(session, binding, message):
        calls.append(message.message_id)
        return len(calls) > 1 or await original(session, binding, message)

    monkeypatch.setattr(reconnect, "_preview_open", opened)
    result = await send(v[0], v[4], message("!ok", 200))
    assert calls == [200, 200] and "Reconnected" not in result.text
    assert not (await state(v)).owner_transitions and not await transitions(db)


async def test_a_plain_ok_outside_the_restart_gap_answers_what_else_bridge_asked(db):
    """A wired reconnect must not take every plain `!ok`, even in a live topic."""
    v = await setup(db)
    router = v[0]
    await preview(v, db)
    assert "Reconnected" in (await send(router, v[4], message("!ok", 200))).text

    class Asked:
        def candidate(self, item):
            return False

        async def owns_source(self, item):
            return False

        async def owns_confirm(self, binding, item):
            return True

        async def confirm(self, binding, item, locale):
            return "Schedule set"

    router.schedules = Asked()
    assert (await send(router, v[4], message("!ok", 300))).text == "Schedule set"
    assert len((await state(v)).owner_transitions) == 1


async def test_the_preview_carries_one_confirm_button_for_its_own_token(db):
    from jt_oz_bridge.i18n import Translator

    v = await setup(db)
    reply = await send(v[0], v[4], message("!reconnect", 101))
    widget = json.loads(reply.widget)
    assert widget["widget_type"] == "zform" and widget["extra_data"]["type"] == "choices"
    (button,) = widget["extra_data"]["choices"]
    assert button["long_name"] == Translator().render("reconnect.button_confirm", "en")
    assert Translator().render("reconnect.button_confirm", "zh-TW") == "確認接上"
    token = preview_token(reply)
    # Web clients show the heading instead of the text, so it keeps the facts.
    heading = widget["extra_data"]["heading"]
    assert len(token) >= 16 and token in heading and "`" not in heading
    assert "Conversation:" in heading and "Directory:" in heading
    # The replayed preview repeats the same button.
    assert (await v[0].route(v[4].messages[101])).widget == reply.widget


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
def test_restart_texts_ask_for_one_ok(locale):
    from jt_oz_bridge.i18n import Translator

    tr = Translator()
    for key in (
        "reconnect.automatic_refused",
        "router.paused_gap",
        "router.paused_gap_stopped",
        "router.gap_go",
    ):
        assert "`!ok`" in tr.render(key, locale)
    # Only the notice still names `!reconnect`, as the optional way to see the details.
    assert "`!reconnect`" in tr.render("reconnect.automatic_refused", locale)
    for key in ("router.paused_gap", "router.paused_gap_stopped", "router.gap_go"):
        assert "!reconnect" not in tr.render(key, locale)
    assert "`!go`" in tr.render("router.paused_gap_stopped", locale)
