"""Real closed Source permits and original Native adapters, isolated ownDB only.

These are synthetic HTTP/Native fixtures, never live Human/mobile acceptance.
No Native writes, manufactured history, or substitute registration receipts.
"""

import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.zulip.client import ZulipError
from jt_oz_bridge.services import session_adoption as module
from jt_oz_bridge.services.session_adoption import ObservedOriginalSelection
from jt_oz_bridge.storage.models import Grant
from jt_oz_bridge.storage.session_registration_models import SessionRegistration
from tests.contract.test_lineage_resources import TARGET
from tests.integration.test_closed_adoption_flow import original_menu
from tests.integration.test_consumer_runtime import rows


async def observed(env, *, inside=None, consume=True):
    """Use actual two-sided Source HTTP and its issuer-owned phase handle."""
    service = env.pipeline.adoption
    assert service is not None
    mid = max(env.server.messages) + 1
    wire = env.server.input(
        "!oz choose synthetic-observation 1", mid, author=7, topic="Original proof"
    )
    env.server.next_mid = mid + 1
    await env.pipeline.journal.capture(env.pipeline.consumer.queue_id, [wire])
    source = await env.pipeline.source.read("realm", mid)

    captured = []

    async def read_only(audience):
        selection = await service.selection_observed(source, TARGET, audience)
        stage = await service.observe_selection(source, selection, audience)
        stage.require_current()  # Native witness is usable before Source close.
        captured.append(stage)
        if inside is not None:
            await inside(stage)
        return stage

    observation = await env.pipeline.scope.observe_sources(
        env.pipeline.source, (source,), read_only=read_only
    )
    if consume:
        result = env.pipeline.scope.consume_observation(observation, env.pipeline.source, (source,))
        return result.value
    return captured[0]


async def test_actual_observation_defers_all_registration_until_source_consumed(db):
    async with original_menu(db) as env:
        service = env.pipeline.adoption
        before = dict(env.registry.sessions)

        async def inspect(stage):
            assert isinstance(stage, ObservedOriginalSelection)
            assert stage.snapshot.reference == TARGET and stage.snapshot.reconciled
            assert env.registry.sessions == before
            assert await rows(db, SessionRegistration) == []
            with pytest.raises(ZulipError):
                await service.commit_observed(stage, mark_write_started=lambda: None)

        stage = await observed(env, inside=inspect)
        calls = len(env.state["resource_calls"])
        started = []
        await service.commit_observed(stage, mark_write_started=lambda: started.append("journal"))
        assert started == ["journal"]
        assert len(env.state["resource_calls"]) == calls
        assert TARGET in env.registry.sessions
        assert all(env.registry.sessions[ref] is entry for ref, entry in before.items())
        saved = await rows(db, SessionRegistration)
        assert len(saved) == 1 and saved[0].state == "active"
        stage.require_current()  # Its own exact publication retains the witness.
        with pytest.raises(ValueError, match="already_consumed"):
            await service.commit_observed(stage, mark_write_started=lambda: started.append("again"))
        assert started == ["journal"] and not env.writes


@pytest.mark.parametrize("fault", ["forged", "other-task", "expired", "transport-verifier"])
async def test_native_stage_identity_task_deadline_and_assembly_cannot_be_reused(
    db, monkeypatch, fault
):
    async with original_menu(db) as env:
        service = env.pipeline.adoption
        stage = await observed(env)
        started = []
        original_verify = env.native.verify_identity
        if fault == "forged":
            stage = ObservedOriginalSelection(service)
        elif fault == "expired":
            now = module.time.monotonic()
            monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: now + 6))
        elif fault == "transport-verifier":
            env.native.verify_identity = lambda: True
        try:

            async def attempt():
                with pytest.raises(ValueError):
                    stage.require_current()
                with pytest.raises(ValueError):
                    await service.commit_observed(
                        stage, mark_write_started=lambda: started.append(1)
                    )

            if fault == "other-task":
                await asyncio.create_task(attempt())
            else:
                await attempt()
            assert not started and TARGET not in env.registry.sessions
            assert await rows(db, SessionRegistration) == [] and not env.writes
        finally:
            env.native.verify_identity = original_verify


async def test_unconsumed_source_cannot_publish_even_with_fresh_native_stage(db):
    async with original_menu(db) as env:
        service = env.pipeline.adoption
        stage = await observed(env, consume=False)
        stage.require_current()
        with pytest.raises(ZulipError):
            await service.commit_observed(stage, mark_write_started=lambda: pytest.fail("write"))
        assert TARGET not in env.registry.sessions
        assert await rows(db, SessionRegistration) == [] and not env.writes


async def test_current_grant_revocation_after_source_close_precedes_any_journal_write(db):
    async with original_menu(db) as env:
        service = env.pipeline.adoption
        stage = await observed(env)
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        stage.require_current()  # A Native proof alone never authorizes Human writes.
        with pytest.raises(ValueError, match="grants_changed"):
            await service.commit_observed(stage, mark_write_started=lambda: pytest.fail("write"))
        assert TARGET not in env.registry.sessions
        assert await rows(db, SessionRegistration) == [] and not env.writes


async def test_registered_unchanged_selection_retains_original_facades_without_journal_update(db):
    async with original_menu(db) as env:
        service = env.pipeline.adoption
        stage = await observed(env)
        await service.commit_observed(stage, mark_write_started=lambda: None)
        entries = dict(env.registry.sessions)
        saved = [
            (row.key, row.revision, row.payload_hash) for row in await rows(db, SessionRegistration)
        ]
        second = await observed(env)
        calls = len(env.state["resource_calls"])
        await service.commit_observed(
            second, mark_write_started=lambda: pytest.fail("redundant journal")
        )
        assert len(env.state["resource_calls"]) == calls
        assert all(env.registry.sessions[ref] is entry for ref, entry in entries.items())
        assert saved == [
            (row.key, row.revision, row.payload_hash) for row in await rows(db, SessionRegistration)
        ]
        assert not env.writes


@pytest.mark.parametrize("field", ["created", "policy"])
async def test_same_registered_references_do_not_accept_recreated_child_or_policy(db, field):
    import copy

    from tests.contract.test_lineage_resources import CHILD

    async with original_menu(db) as env:
        original_rows, original_edges, original_resources = copy.deepcopy(env.saved)
        env.tree["rows"].update(original_rows)
        env.tree["edges"].update(original_edges)
        env.state["resources"].update(original_resources)
        stage = await observed(env)
        await env.pipeline.adoption.commit_observed(stage, mark_write_started=lambda: None)
        old_entries = dict(env.registry.sessions)
        old_head = [
            (row.key, row.revision, row.payload_hash) for row in await rows(db, SessionRegistration)
        ]
        if field == "created":
            env.tree["rows"][CHILD]["time"]["created"] += 1
        else:
            env.tree["rows"][CHILD]["permissions"] = []
        with pytest.raises(ValueError):
            await observed(env)
        assert all(env.registry.sessions[ref] is entry for ref, entry in old_entries.items())
        assert old_head == [
            (row.key, row.revision, row.payload_hash) for row in await rows(db, SessionRegistration)
        ]
        assert not env.writes


async def test_stable_policy_view_cannot_substitute_equal_old_policy_objects(db):
    from jt_oz_bridge.domain.enrollment_views import EnrollmentView

    async with original_menu(db) as env:
        first = await observed(env)
        await env.pipeline.adoption.commit_observed(first, mark_write_started=lambda: None)
        stage = await observed(env)
        entry = env.registry.sessions[TARGET]
        view = entry.execution.scope_guard.enrollments
        assert isinstance(view, EnrollmentView)
        old_read = view._read
        policies = dict(view)
        original = policies[TARGET]
        policies[TARGET] = type(original).model_validate(original.model_dump(mode="python"))
        assert policies[TARGET] == original and policies[TARGET] is not original
        calls = len(env.state["resource_calls"])
        view._read = lambda: policies
        try:
            with pytest.raises(ValueError, match="policy_membership_changed"):
                stage.require_current()
            with pytest.raises(ValueError):
                await env.pipeline.adoption.commit_observed(
                    stage, mark_write_started=lambda: pytest.fail("write")
                )
            assert len(env.state["resource_calls"]) == calls and not env.writes
        finally:
            view._read = old_read
