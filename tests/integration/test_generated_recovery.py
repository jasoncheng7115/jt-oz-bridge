"""Scoped capture recovery over synthetic peers and the real encrypted/fenced DB.

These workflows do not certify actual Human, Agent, TUI or mobile behavior.
"""

import re

import pytest
from sqlalchemy import delete, update

from jt_oz_bridge.services.generated_capture import GeneratedCaptureService
from jt_oz_bridge.services.generated_capture_plans import CapturePlan, read_capture
from jt_oz_bridge.services.generated_file_returns import GeneratedFileReturnJournal
from jt_oz_bridge.services.queue import QueueService
from jt_oz_bridge.services.resource_execution_results import ResourceResultCollector
from jt_oz_bridge.storage.control_models import Binding, ControlToken
from jt_oz_bridge.storage.durable import digest
from jt_oz_bridge.storage.generated_models import GeneratedCaptureJob
from jt_oz_bridge.storage.models import Action, AuditEvent, Grant, WorkerLease
from tests.integration.test_file_returns import all_rows
from tests.integration.test_generated_capture import command, held
from tests.integration.test_generated_file_returns import GeneratedReader, setup
from tests.integration.test_resource_execution_results import Reader
from tests.integration.test_router import message
from tests.support import REF


async def control(v, arguments, identity=201, actor=7, *, capture=True):
    controls, source = await command(v, arguments, identity, actor=actor, capture=capture)
    source = source.model_copy(
        update={"channel_id": v.binding.channel_id, "topic": v.binding.topic}
    )
    v.source.messages[identity] = source
    return controls, source


async def challenge(v, actor=7, *, capture=True):
    controls, source = await control(v, "skip " + v.action_id, actor=actor, capture=capture)
    reply = await controls.execute(v.binding, source, "en", "skip " + v.action_id)
    token = re.search(r"outputs confirm ([A-Za-z0-9_-]+)", reply).group(1)
    return token, reply


async def confirm(v, token, actor=7, *, capture=True):
    controls, source = await control(v, "confirm " + token, 202, actor, capture=capture)
    return await controls.execute(v.binding, source, "en", "confirm " + token)


async def move(v):
    await v.store.bindings.move(
        v.binding.id, "realm", 7, v.binding.revision, 20, "Moved work", whole_topic=True
    )
    v.binding = await v.store.bindings.get(v.binding.id, "realm", 7)
    v.source.messages[101] = v.human.model_copy(
        update={"channel_id": 20, "topic": "Moved work", "revision": 2}
    )


async def viewer(db, user):
    async with db.sessions.begin() as session:
        await session.execute(update(Grant).where(Grant.user_id == user).values(active=False))
        session.add(Grant(realm_id="realm", project_id="project", user_id=user, role="viewer"))


@pytest.mark.parametrize("disabled", [False, True])
async def test_project_admin_can_ack_lost_operating_authority_without_impersonating_owner(
    db, tmp_path, disabled
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        original = (await all_rows(db, Action))[0]
        await viewer(db, 7)
        next_source = message("Administrator next task", 104, author_id=8)
        v.source.messages[104] = next_source
        queued = await QueueService(v.store.bindings).receive(v.binding.id, next_source)
        assert await v.dispatcher.advance(queued.action_id) == "queued"
        token, reply = await challenge(v, 8, capture=not disabled)
        assert "administrator" in reply and v.reader.filename not in reply
        await confirm(v, token, 8, capture=not disabled)
        row = (await all_rows(db, GeneratedCaptureJob))[0]
        plan = read_capture(row)
        assert row.state == "skipped" and plan.origin.source.author_id == 7
        assert plan.acknowledgement.author_id == 8
        assert plan.acknowledgement_authority.role == "project_administrator"
        assert plan.acknowledgement_authority.scope.owner_id == 7
        assert (await v.dispatcher.load(original.id)).native_result == original.native_result
        audit = [
            a
            for a in await all_rows(db, AuditEvent)
            if a.event == "generated_capture_admin_loss_acknowledged"
        ]
        assert len(audit) == 1 and audit[0].actor == "realm:8"
        assert await v.dispatcher.advance(queued.action_id) == "admitted"
        assert len(v.execution.submitted) == 2 and not v.remote.posts
        with pytest.raises(ValueError):
            await confirm(v, token, 8, capture=not disabled)


@pytest.mark.parametrize("role", ["operator", "viewer"])
async def test_another_operator_or_viewer_cannot_issue_loss_authority(db, tmp_path, role):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant).where(Grant.user_id == 8, Grant.role != role).values(active=False)
            )
        with pytest.raises(ValueError):
            await challenge(v, 8)
        assert not await all_rows(db, ControlToken)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "held"


async def test_admin_cannot_retry_as_revoked_original_operator(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        await viewer(db, 7)
        controls, source = await control(v, "retry " + v.action_id, actor=8)
        calls = v.reader.calls
        with pytest.raises(ValueError):
            await controls.execute(v.binding, source, "en", "retry " + v.action_id)
        assert v.reader.calls == calls and not v.remote.posts


@pytest.mark.parametrize(
    "change", ["administrator", "source", "lease", "history", "scope", "result"]
)
async def test_scoped_admin_confirmation_rechecks_every_boundary_before_consumption(
    db, tmp_path, change
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        await move(v)
        token, _ = await challenge(v, 8)
        controls, source = await control(v, "confirm " + token, 202, 8)
        if change == "source":
            v.source.messages[202] = source.model_copy(update={"revision": 2, "text": "edited"})
        else:
            async with db.sessions.begin() as session:
                if change == "administrator":
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == 8, Grant.role == "administrator")
                        .values(active=False)
                    )
                elif change == "lease":
                    await session.execute(
                        update(WorkerLease).values(fencing=WorkerLease.fencing + 1)
                    )
                elif change == "history":
                    await session.execute(
                        delete(AuditEvent).where(AuditEvent.event == "binding_rescope_v1")
                    )
                elif change == "scope":
                    await session.execute(update(Binding).values(owner_id=8))
                else:
                    await session.execute(
                        update(Action)
                        .where(Action.id == v.action_id)
                        .values(version=Action.version + 1)
                    )
        with pytest.raises(ValueError):
            await controls.execute(v.binding, source, "en", "confirm " + token)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "held"
        assert not (await all_rows(db, ControlToken))[0].used
        assert not v.remote.posts


@pytest.mark.parametrize("actor", [7, 8])
async def test_qualified_whole_topic_move_allows_loss_ack_and_preserves_explicit_queue_pause(
    db, tmp_path, actor
):
    async with setup(db, tmp_path, automatic=True) as v:
        await move(v)
        assert await v.capture.advance(v.action_id) == "held"
        assert v.reader.calls == 0 and not v.remote.posts
        original = (await v.capture.load(v.action_id))[1]
        token, _ = await challenge(v, actor)
        await confirm(v, token, actor)
        row, plan = await v.capture.load(v.action_id)
        assert row.state == "skipped" and plan.origin == original.origin
        assert plan.original_scope.topic == "Original work"
        assert plan.acknowledgement_authority.scope.topic == "Moved work"
        latest = await v.store.bindings.get(v.binding.id, "realm", actor)
        assert latest.dispatch_paused
        source = message("New scoped task", 105, channel_id=20, topic="Moved work", author_id=actor)
        v.source.messages[105] = source
        queued = await QueueService(v.store.bindings).receive(latest.id, source)
        assert await v.dispatcher.advance(queued.action_id) == "held"
        await QueueService(v.store.bindings).resume(
            latest.id, "realm", actor, latest.revision, latest.queue_revision
        )
        assert await v.dispatcher.advance(queued.action_id) == "admitted"
        assert len(v.execution.submitted) == 2 and not v.remote.posts


@pytest.mark.parametrize("change", ["missing", "coordinate", "unrelated-binding", "legacy"])
async def test_move_cannot_be_inferred_from_current_coordinates_or_matching_root(
    db, tmp_path, change
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        if change == "legacy":
            async with db.sessions.begin() as session:
                row = await session.get(GeneratedCaptureJob, v.action_id)
                payload = {k: value for k, value in row.payload.items() if k != "original_scope"}
                row.payload, row.payload_hash = payload, digest(payload)
        await move(v)
        async with db.sessions.begin() as session:
            if change == "missing":
                await session.execute(
                    delete(AuditEvent).where(AuditEvent.event == "binding_rescope_v1")
                )
            elif change == "coordinate":
                await session.execute(update(Binding).values(topic="Forged destination"))
        if change == "coordinate":
            v.binding = await v.store.bindings.get(v.binding.id, "realm", 7)
        elif change == "unrelated-binding":
            await v.store.bindings.unbind(v.binding.id, "realm", 7, v.binding.revision)
            v.binding = await v.store.bindings.bind("realm", 7, 20, "New binding", REF)
        with pytest.raises(ValueError):
            await challenge(v)
        assert not await all_rows(db, ControlToken)
        assert (await all_rows(db, GeneratedCaptureJob))[0].state == "held"


@pytest.mark.parametrize("actor", [7, 8])
async def test_prescope_legacy_token_only_accepts_original_actor_in_unchanged_scope(
    db, tmp_path, actor
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        async with db.sessions.begin() as session:
            row = await session.get(GeneratedCaptureJob, v.action_id)
            payload = {k: value for k, value in row.payload.items() if k != "original_scope"}
            row.payload, row.payload_hash = payload, digest(payload)
        row, plan = await v.capture.load(v.action_id)
        assert plan.original_scope is None and "original_scope" not in plan.model_dump(mode="json")
        controls, _ = await control(v, "status", actor=actor)
        token = await controls.tokens.issue(
            "generated-skip",
            "realm",
            actor,
            {"action_id": row.action_id, "version": row.version, "payload_hash": row.payload_hash},
            ttl=600,
            binding_id=v.binding.id,
            binding_revision=v.binding.revision,
        )
        if actor == 7:
            await confirm(v, token, actor)
            assert (await v.capture.load(v.action_id))[0].state == "skipped"
        else:
            with pytest.raises(ValueError):
                await confirm(v, token, actor)
            assert (await v.capture.load(v.action_id))[0].state == "held"


@pytest.mark.parametrize("change", ["role", "actor", "realm", "binding", "owner", "audience"])
async def test_loss_history_validates_the_sealed_authority_and_original_identity(
    db, tmp_path, change
):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        token, _ = await challenge(v, 8)
        await confirm(v, token, 8)
        _, plan = await v.capture.load(v.action_id)
        data = plan.model_dump(mode="json")
        if change == "role":
            data["acknowledgement_authority"]["role"] = "original_actor"
        elif change == "actor":
            data["acknowledgement"]["author_id"] = 7
        elif change == "realm":
            data["acknowledgement"]["realm_id"] = "foreign"
        elif change == "binding":
            data["acknowledgement_authority"]["scope"]["binding_id"] = "0" * 36
        elif change == "owner":
            data["acknowledgement_authority"]["scope"]["owner_id"] = 8
        else:
            data["acknowledgement_authority"]["scope"]["audience_user_ids"] = [7]
        with pytest.raises(ValueError):
            CapturePlan.model_validate(data)


async def test_two_original_roots_alternate_capture_before_one_large_job_finishes(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        other = REF.model_copy(update={"upstream_session_id": "other-original-session"})
        binding = await v.store.bindings.bind("realm", 7, 10, "Other work", other)
        reader = GeneratedReader(None, b"other original report", "inline", other)
        journal = GeneratedFileReturnJournal(
            v.store,
            v.source,
            v.outbox,
            v.uploader,
            v.downloader,
            {},
            generated_readers={REF: v.reader, other: reader},
            message_limit=10000,
            topic_limit=60,
        )
        capture = GeneratedCaptureService(journal)
        source = message("Other original report", 103, topic="Other work")
        v.source.messages[103] = source
        queued = await QueueService(v.store.bindings).receive(binding.id, source)
        assert await v.dispatcher.advance(queued.action_id) == "admitted"
        results = Reader()
        collector = ResourceResultCollector(
            v.store.bindings, results, v.store.fence, capture=capture
        )
        reader.result = await collector.collect(queued.action_id, "realm")
        assert await capture.next_pending() == v.action_id
        assert await capture.advance(v.action_id) == "pending"
        assert await capture.next_pending() == queued.action_id
        assert await capture.advance(queued.action_id) == "pending"
        assert await capture.next_pending() == v.action_id
        assert await capture.advance(v.action_id) == "frozen"
        assert await capture.next_pending() == queued.action_id
        assert await capture.advance(queued.action_id) == "frozen"
        assert await capture.next_pending() is None
        assert not v.remote.posts and len(v.execution.submitted) == 2


async def test_losing_all_view_access_does_not_let_admin_bypass_the_private_audience(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        await held(v)
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        with pytest.raises(ValueError):
            await challenge(v, 8)
        assert (await v.capture.load(v.action_id))[0].state == "held"
        assert not await all_rows(db, ControlToken) and not v.remote.posts


async def test_binding_owner_and_original_task_actor_have_distinct_loss_authority(db, tmp_path):
    async with setup(db, tmp_path, automatic=True) as v:
        assert await v.capture.advance(v.action_id) == "pending"
        assert await v.capture.advance(v.action_id) == "frozen"
        source = message("Different task actor", 103, author_id=8)
        v.source.messages[103] = source
        queued = await QueueService(v.store.bindings).receive(v.binding.id, source)
        assert await v.dispatcher.advance(queued.action_id) == "admitted"
        v.reader.result = await v.collector.collect(queued.action_id, "realm")
        v.action_id = queued.action_id
        await held(v)
        token, reply = await challenge(v, 7)
        assert "as an administrator" in reply
        await confirm(v, token, 7)
        _, plan = await v.capture.load(v.action_id)
        assert plan.origin.source.author_id == 8 and plan.original_scope.owner_id == 7
        assert plan.acknowledgement.author_id == 7
        assert plan.acknowledgement_authority.role == "project_administrator"
        assert not v.remote.posts
