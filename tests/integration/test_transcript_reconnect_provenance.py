"""Reconnect provenance in synthetic own SQL/HTTP, never live Human acceptance.

Raw SELECTs intentionally bypass EncryptedJSON result processors: preserving a
decoded value is weaker than preserving the original ciphertext and seal cells.
Only Bridge-owned, per-test databases are read; no Native database is accessed.
"""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, text, update

from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.adapters.zulip import scope as scope_module
from jt_oz_bridge.adapters.zulip.budget import ZulipRequestBudget
from jt_oz_bridge.adapters.zulip.scope import ZulipSourceReader
from jt_oz_bridge.services.closed_bound_queue import ClosedBoundQueue
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, Grant
from jt_oz_bridge.storage.zulip_models import ZulipMessageIndex
from tests.integration.test_closed_bound_queue import live_identity, topic_paused
from tests.integration.test_consumer_runtime import rows
from tests.integration.test_router import message, send
from tests.integration.test_transcript_collector import entry
from tests.integration.test_transcript_commands import OriginalReader
from tests.integration.test_transcript_reconnect import preview, restart, setup, state
from tests.support import REF

# Fixed ownDB identifiers, not user-provided SQL. Every selected row includes
# every persisted cell, including encrypted payloads, timestamps and seals.
RAW_TABLES = {
    "bindings": "id",
    "control_tokens": "token_hash",
    "audit_events": "id",
    "command_receipts": "id",
    "transcript_streams": "key",
    "transcript_messages": "id",
    "transcript_versions": "id",
    "transcript_candidates": "scan_id, native_id",
    "transcript_publications": "version_id",
    "actions": "id",
    "grants": "id",
    "zulip_message_index": "realm_id, message_id",
    "input_events": "id",
}


async def raw_cells(db, tables=RAW_TABLES):
    async with db.sessions() as session:
        result = {}
        for table, order in tables.items():
            rows = await session.execute(text(f"SELECT * FROM {table} ORDER BY {order}"))
            result[table] = (tuple(rows.keys()), tuple(tuple(row) for row in rows))
        return result


async def test_v1_snapshot_and_publication_ciphertext_and_seals_are_never_rewritten(db):
    v = await setup(db, publisher=True)
    tables = {name: RAW_TABLES[name] for name in ("transcript_versions", "transcript_publications")}
    before = await raw_cells(db, tables)
    assert all(before[name][1] for name in tables)
    for columns, values in before.values():
        payload = columns.index("payload")
        seal = columns.index("payload_hash")
        assert all(isinstance(row[payload], bytes) and row[payload] for row in values)
        assert all(isinstance(row[seal], str) and len(row[seal]) == 64 for row in values)
    await preview(v, db)
    v[5].messages.insert(0, entry("new_original_input_after_restart"))
    reply = await send(v[0], v[4], message("!confirm", 200))
    assert "Reconnected" in reply.text
    after = await raw_cells(db, tables)
    for table, (columns, values) in before.items():
        assert after[table][0] == columns
        identity = columns.index(RAW_TABLES[table])
        by_id = {row[identity]: row for row in after[table][1]}
        assert all(by_id[row[identity]] == row for row in values)
    assert len(after["transcript_versions"][1]) > len(before["transcript_versions"][1])
    assert len((await state(v)).owner_transitions) == 1


@pytest.mark.parametrize("failure", ["before-finalize", "after-finalize", "after-all-effects"])
async def test_failed_confirmation_rolls_back_every_protected_raw_cell(db, monkeypatch, failure):
    v = await setup(db)
    for kind in ("form-step", "interaction", "native-git-commit"):
        await v[1].tokens.issue(
            kind,
            v[3].realm_id,
            7,
            {"synthetic": True},
            binding_id=v[3].id,
            binding_revision=v[3].revision,
        )
    await preview(v, db)
    v[5].messages.insert(0, entry("new_input_requires_transactional_version"))
    confirmation = message("!confirm", 200)
    v[4].messages[confirmation.message_id] = confirmation
    claim = await v[1].inbox.claim(
        confirmation, "confirm", binding_id=v[3].id, binding_revision=v[3].revision
    )
    assert claim.status == "claimed"
    before = await raw_cells(db)
    async with db.sessions() as session:
        qrev = (await session.get(Binding, v[3].id)).queue_revision
    original_finalize, original_finish = v[2].finalize, v[1].inbox.finish
    reached = []

    async def fail_finalize(*args, **kwargs):
        if failure == "before-finalize":
            reached.append(failure)
            raise Conflict("synthetic_reconnect_atomic_rollback")
        value = await original_finalize(*args, **kwargs)
        if failure == "after-finalize":
            reached.append(failure)
            raise Conflict("synthetic_reconnect_atomic_rollback")
        return value

    async def fail_finish(current_claim, response, *, commit=None):
        assert current_claim == claim and commit is not None

        async def fail_after_effects(session):
            await commit(session)
            binding = await session.get(Binding, v[3].id)
            receipt = await session.get(CommandReceipt, claim.id)
            assert binding.queue_revision == qrev + 1 and binding.dispatch_paused
            assert receipt.state == "completed" and receipt.response["transition_id"]
            assert all(
                row.used
                for row in await session.scalars(
                    select(ControlToken).where(ControlToken.binding_id == v[3].id)
                )
            )
            assert (
                await session.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.event == "transcript.owner_reconnected")
                )
                == 1
            )
            reached.append(failure)
            raise Conflict("synthetic_reconnect_atomic_rollback")

        return await original_finish(current_claim, response, commit=fail_after_effects)

    monkeypatch.setattr(v[2], "finalize", fail_finalize)
    if failure == "after-all-effects":
        monkeypatch.setattr(v[1].inbox, "finish", fail_finish)
    with pytest.raises(Conflict, match="^synthetic_reconnect_atomic_rollback$"):
        # Call the service with an already owned claim: the router's later
        # failure ACK is a separate, legitimate transaction, not rollback.
        await v[1].route(v[3], confirmation, "en", claim)
    assert reached == [failure]
    assert await raw_cells(db) == before
    assert (await state(v)).status == "gap" and not (await state(v)).owner_transitions


async def real_pipeline(db, monkeypatch, *, restarted=True, before_restart=None):
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
    assert isinstance(pipeline.router.reader, ZulipSourceReader)
    assert isinstance(pipeline.router.reconnect.source_guard, ClosedBoundQueue)
    await pipeline.consumer.start()
    await pipeline.mirror_once()
    await pipeline.deliver_once()
    if before_restart is not None:
        await before_restart(pipeline, binding)
    if restarted:
        await restart(pipeline.mirrors, binding, reader, "1" * 64)
    return pipeline, server, native, binding


async def input_control(pipeline, server, binding, text):
    mid = max(server.messages) + 1
    server.next_mid = mid + 1
    server.input(text, mid, topic=binding.topic)
    return mid, await pipeline.consumer.poll()


@pytest.mark.parametrize("flow", ["preview", "one-step"])
@pytest.mark.parametrize(
    ("failure", "code"),
    [
        ("permit-expired", "local_write_permit_not_current_and_consumed"),
        ("journal-index", "closed_bound_original_capture_index_required"),
        ("grant-revoked", "closed_bound_current_actor_permission_required"),
    ],
)
async def test_real_closed_source_rechecks_final_commit_and_rolls_back_raw_cells(
    db, monkeypatch, failure, code, flow
):
    pipeline, server, native, binding = await real_pipeline(db, monkeypatch)
    reconnect = pipeline.router.reconnect
    original_finish = reconnect.inbox.finish
    original_time = scope_module.time
    rejected = []

    async def changed_finish(claim, response, *, commit=None):
        if not response.get("transition_id"):
            return await original_finish(claim, response, commit=commit)
        assert commit is not None
        # This hook is reached after Native history and the final two-sided
        # Source observation. Mutation is confined to this own test transaction.
        before = await raw_cells(db)

        async def changed_commit(session):
            if failure == "permit-expired":
                closed_now = original_time.monotonic()
                monkeypatch.setattr(
                    scope_module, "time", SimpleNamespace(monotonic=lambda: closed_now + 6)
                )
            elif failure == "journal-index":
                changed = await session.execute(
                    update(ZulipMessageIndex)
                    .where(
                        ZulipMessageIndex.realm_id == binding.realm_id,
                        ZulipMessageIndex.message_id == claim_message[0],
                    )
                    .values(state="deleted")
                )
                assert changed.rowcount == 1
            else:
                # Keep the existing approver's VIEW grant, so the exact private
                # audience stays valid while OPERATE is revoked at commit.
                changed = await session.execute(
                    update(Grant)
                    .where(
                        Grant.realm_id == binding.realm_id,
                        Grant.project_id == binding.project_id,
                        Grant.user_id == 7,
                        Grant.role.in_(("operator", "administrator")),
                    )
                    .values(active=False)
                )
                assert changed.rowcount == 2
            await commit(session)

        try:
            return await original_finish(claim, response, commit=changed_commit)
        except ValueError as error:
            monkeypatch.setattr(scope_module, "time", original_time)
            assert str(error) == code
            # Compare before the router legitimately records its failure ACK.
            assert await raw_cells(db) == before
            rejected.append(code)
            raise
        finally:
            monkeypatch.setattr(scope_module, "time", original_time)

    claim_message = [0]
    try:
        if flow == "preview":
            _, outcome = await input_control(pipeline, server, binding, "!reconnect")
            assert outcome[-1] == "reply"
            await pipeline.deliver_once()
        monkeypatch.setattr(reconnect.inbox, "finish", changed_finish)
        claim_message[0] = max(server.messages) + 1
        # One step: the same fresh proof and final commit checks, no preview first.
        await input_control(pipeline, server, binding, "!confirm" if flow == "preview" else "!ok")
        assert rejected == [code]
        current, _ = await pipeline.mirrors.load(binding)
        assert current.status == "gap" and not current.owner_transitions
        async with db.sessions() as session:
            assert (await session.get(Binding, binding.id)).dispatch_paused
            assert not any(row.used for row in await session.scalars(select(ControlToken)))
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


def reconnect_lines(server, since):
    from jt_oz_bridge.i18n import Translator
    from tests.integration.test_consumer_runtime import visible as body

    tr = Translator()
    lifted, paused = tr.render("reconnect.automatic", "en"), "The topic is still paused"
    bodies = [body(post["content"]) for post in server.posts[since:]]
    assert tr.render("reconnect.automatic_paused", "en").startswith(lifted)
    return (
        sum(lifted in text and paused not in text for text in bodies),
        sum(lifted in text and paused in text for text in bodies),
    )


async def test_owner_restart_is_reconnected_in_the_same_pass_with_only_one_line(db, monkeypatch):
    pipeline, server, native, binding = await real_pipeline(db, monkeypatch, restarted=False)
    reader = pipeline.mirrors.readers[REF]
    try:
        posts = len(server.posts)
        reader.owner_epoch = "1" * 64
        reader.connection_epoch = "new-process:" + "1" * 64
        await pipeline.mirror_once()
        current, _ = await pipeline.mirrors.load(binding)
        assert current.status == "live" and current.gap_plan is None
        assert [t.kind for t in current.owner_transitions] == ["automatic"]
        for _ in range(3):
            await pipeline.mirror_once()
            await pipeline.publish_once()
            await pipeline.deliver_once()
        assert reconnect_lines(server, posts) == (1, 0)
        assert not any("doesn't line up" in post["content"] for post in server.posts[posts:])
        assert not await topic_paused(db, binding)
        assert len((await pipeline.mirrors.load(binding))[0].owner_transitions) == 1
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


async def test_automatic_reconnect_lifts_the_gap_pause_and_requeues_held_prompts(db, monkeypatch):
    pipeline, server, native, binding = await real_pipeline(db, monkeypatch)
    try:
        assert await topic_paused(db, binding)
        _, outcome = await input_control(pipeline, server, binding, "sent during the restart")
        assert outcome[-1] == "reply"
        await pipeline.deliver_once()
        assert [a.state for a in await rows(db, Action)] == ["held"]
        async with db.sessions() as session:
            before = (await session.get(Binding, binding.id)).queue_revision
        posts = len(server.posts)
        await pipeline.mirror_once()
        await pipeline.mirror_once()
        await pipeline.deliver_once()
        current, _ = await pipeline.mirrors.load(binding)
        assert current.status == "live" and current.gap_resume_revision is None
        (transition,) = current.owner_transitions
        assert (transition.kind, transition.actor_id, transition.source_message_id) == (
            "automatic",
            0,
            0,
        )
        assert "kind" in transition.model_dump(mode="json")
        assert reconnect_lines(server, posts) == (1, 0)
        async with db.sessions() as session:
            saved = await session.get(Binding, binding.id)
            assert not saved.dispatch_paused and saved.queue_revision == before + 1
        assert [a.state for a in await rows(db, Action)] == ["queued"]
        events = [e.event for e in await rows(db, AuditEvent)]
        assert events.count("transcript.owner_reconnected_automatically") == 1
        assert "transcript.owner_reconnected" not in events
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("flow", ["preview", "one-step"])
@pytest.mark.parametrize("damage", ["installed-evidence", "semantics", "anchor-changed"])
async def test_refused_automatic_reconnect_stays_paused_and_keeps_the_manual_path(
    db, monkeypatch, damage, flow
):
    pipeline, server, native, binding = await real_pipeline(db, monkeypatch)
    reader = pipeline.mirrors.readers[REF]
    if damage == "anchor-changed":
        reader.messages[0] = entry(reader.messages[0].native_id, "different historical input")
    else:
        original = reader.capture
        field = (
            "installed_evidence_sha256" if damage == "installed-evidence" else "semantics_sha256"
        )

        async def changed(*args, **kwargs):
            page = (await original(*args, **kwargs)).model_copy(update={field: "9" * 64})
            reader.pages.append(page)
            return page

        reader.capture = changed
    try:
        posts = len(server.posts)
        for _ in range(3):
            await pipeline.mirror_once()
        await pipeline.deliver_once()
        current, _ = await pipeline.mirrors.load(binding)
        assert current.status == "gap" and not current.owner_transitions
        assert await topic_paused(db, binding)
        assert reconnect_lines(server, posts) == (0, 0)
        # Retries are spaced and bounded; refusals never stop the mirror loop.
        assert pipeline._auto_reconnect[(binding.id, binding.revision)][1] == 1
        assert pipeline.deferred["transcript_auto_reconnect_refused"] == 1
        # Only a changed installation is a definite "needs you": said once per
        # restart, also when the bounded retry runs again.
        from jt_oz_bridge.i18n import Translator
        from tests.integration.test_consumer_runtime import visible as body

        asked = Translator().render("reconnect.automatic_refused", "en")
        pipeline._auto_reconnect.pop((binding.id, binding.revision))
        await pipeline.mirror_once()
        await pipeline.deliver_once()
        told = sum(asked in body(post["content"]) for post in server.posts[posts:])
        assert told == (1 if damage == "installed-evidence" else 0)
        notices = [
            row.payload for row in await rows(db, Delivery) if asked in body(row.payload["content"])
        ]
        assert len(notices) == told
        for notice in notices:
            # Desktop shows one button that sends the same `!ok` the text asks for.
            widget = json.loads(notice["widget"])
            assert widget["widget_type"] == "zform"
            (button,) = widget["extra_data"]["choices"]
            assert (button["long_name"], button["reply"]) == ("Reconnect", "!ok")
            assert "`" not in widget["extra_data"]["heading"]
        for text in ("!reconnect", "!confirm") if flow == "preview" else ("!ok",):
            _, result = await input_control(pipeline, server, binding, text)
            assert result[-1] == "reply"
            await pipeline.deliver_once()
        current, _ = await pipeline.mirrors.load(binding)
        if damage == "installed-evidence":
            # A person may still confirm what Bridge would not prove by itself.
            assert current.status == "live"
            assert [(t.kind, t.actor_id) for t in current.owner_transitions] == [("confirmed", 7)]
        else:
            assert current.status == "gap" and not current.owner_transitions
        # A confirmed reconnect lifts the gap's own pause; a refused one keeps it.
        assert await topic_paused(db, binding) == (damage != "installed-evidence")
        assert not native.submitted and not await rows(db, Action)
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("damage", ["installed-evidence", "semantics"])
async def test_a_restart_notice_waits_for_automatic_reconnect_to_answer_it(db, monkeypatch, damage):
    from jt_oz_bridge.services.consumer_runtime import AUTO_RECONNECT_TRIES

    pipeline, server, _native, binding = await real_pipeline(db, monkeypatch)
    reader = pipeline.mirrors.readers[REF]
    original = reader.capture
    field = "installed_evidence_sha256" if damage == "installed-evidence" else "semantics_sha256"

    async def changed(*args, **kwargs):
        page = (await original(*args, **kwargs)).model_copy(update={field: "9" * 64})
        reader.pages.append(page)
        return page

    reader.capture = changed

    async def gap_notices():
        for _ in range(3):
            await pipeline.mirror_once()
            await pipeline.publish_once()
            await pipeline.deliver_once()
        return sum("doesn't line up" in post["content"] for post in server.posts[posts:])

    try:
        posts = len(server.posts)
        # While automatic reconnect may still answer, the long notice waits.
        assert await gap_notices() == 0
        key = (binding.id, binding.revision)
        expected, _, _ = pipeline._auto_reconnect[key]
        pipeline._auto_reconnect[key] = (expected, AUTO_RECONNECT_TRIES, 0.0)
        # Out of tries: a refusal nobody was told about posts it; a changed
        # installation already asked for `!reconnect` in one line.
        assert await gap_notices() == (0 if damage == "installed-evidence" else 1)
        assert (await pipeline.mirrors.load(binding))[0].status == "gap"
    finally:
        await pipeline.scope.client.close()


async def test_a_held_restart_notice_still_goes_when_nothing_answers_it(db, monkeypatch):
    from jt_oz_bridge.services import consumer_runtime

    pipeline, _server, _native, binding = await real_pipeline(db, monkeypatch)
    try:
        state, _ = await pipeline.mirrors.load(binding)
        due = pipeline.transcript_output.gap_notice_due
        assert due is not None and not due(binding, state.gap_reason)
        assert due(binding, "some_other_gap")
        monkeypatch.setattr(consumer_runtime, "GAP_NOTICE_HOLD", 0.0)
        assert due(binding, state.gap_reason)
    finally:
        await pipeline.scope.client.close()


@pytest.mark.parametrize("when", ["before-restart", "during-gap"])
async def test_a_pause_a_person_chose_survives_automatic_reconnect(db, monkeypatch, when):
    async def stop(pipeline, binding):
        await pipeline.router.queue.pause(binding.id, binding.realm_id, 7, binding.revision)

    pipeline, server, native, binding = await real_pipeline(
        db, monkeypatch, before_restart=stop if when == "before-restart" else None
    )
    try:
        recorded = (await pipeline.mirrors.load(binding))[0].gap_resume_revision
        assert recorded == (None if when == "before-restart" else binding.queue_revision)
        if when == "during-gap":
            await stop(pipeline, binding)
        await input_control(pipeline, server, binding, "kept for the person")
        await pipeline.deliver_once()
        posts = len(server.posts)
        await pipeline.mirror_once()
        await pipeline.deliver_once()
        current, _ = await pipeline.mirrors.load(binding)
        assert current.status == "live"
        assert [t.kind for t in current.owner_transitions] == ["automatic"]
        assert reconnect_lines(server, posts) == (0, 1)
        assert await topic_paused(db, binding)
        assert [a.state for a in await rows(db, Action)] == ["held"]
        assert not native.submitted
    finally:
        await pipeline.scope.client.close()


async def test_automatic_reconnect_keeps_the_pause_for_unclear_work(db, monkeypatch):
    pipeline, server, native, binding = await real_pipeline(db, monkeypatch)
    try:
        await input_control(pipeline, server, binding, "was running when OpenCode restarted")
        await pipeline.deliver_once()
        async with db.sessions.begin() as session:
            await session.execute(update(Action).values(state="ambiguous"))
        posts = len(server.posts)
        await pipeline.mirror_once()
        await pipeline.deliver_once()
        assert (await pipeline.mirrors.load(binding))[0].status == "live"
        assert reconnect_lines(server, posts) == (0, 1)
        assert await topic_paused(db, binding)
        assert [a.state for a in await rows(db, Action)] == ["ambiguous"]
    finally:
        await pipeline.scope.client.close()


async def test_a_notice_already_given_in_older_words_is_not_given_again(db, monkeypatch):
    """After a Bridge upgrade the same restart's notice keeps the words it was sent in."""
    pipeline, server, native, binding = await real_pipeline(db, monkeypatch)
    reader = pipeline.mirrors.readers[REF]
    original = reader.capture

    async def changed(*args, **kwargs):
        page = (await original(*args, **kwargs)).model_copy(
            update={"installed_evidence_sha256": "9" * 64}
        )
        reader.pages.append(page)
        return page

    reader.capture = changed
    key = (binding.id, binding.revision)
    try:
        await pipeline.mirror_once()
        before = len(await rows(db, Delivery))
        assert pipeline._gap_settled[key] is False
        reconnect = pipeline.router.reconnect
        render = reconnect.tr.render

        def older(name, locale, **values):
            if name == "reconnect.automatic_refused":
                return "Older words for the same restart."
            return render(name, locale, **values)

        monkeypatch.setattr(reconnect.tr, "render", older)
        pipeline._auto_reconnect.pop(key)
        pipeline._gap_settled.pop(key)
        await pipeline.mirror_once()
        # Still "the person was asked", not a refusal that would post the long gap notice.
        assert pipeline._gap_settled[key] is False
        assert len(await rows(db, Delivery)) == before
    finally:
        await pipeline.scope.client.close()
