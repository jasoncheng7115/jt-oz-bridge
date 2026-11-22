"""Synthetic native/semantic evidence, actual SQLite capture/dispatch/projection."""

from pathlib import Path

import pytest
from sqlalchemy import select

from jt_oz_bridge.adapters.opencode.contracts import OpenAPIProfile
from jt_oz_bridge.adapters.opencode.event_semantics import DATA, SEMANTICS_SHA256
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.execution_results import read_result
from jt_oz_bridge.services.native_projection import EventSemanticAttestation, NativeProjector
from jt_oz_bridge.storage.durable import Conflict
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, InputEvent
from jt_oz_bridge.storage.projection_models import (
    NativeLogIndex,
    NativeProjection,
    NativeProjectionRecord,
)
from tests.contract.test_v2_execution import REF
from tests.integration.test_dispatch import SyntheticReader, message
from tests.integration.test_native_log_reader import event, reader, sse, synced


@pytest.fixture(params=["opencode-v2-openapi.json", "opencode-v2.0.30-openapi.json"])
def profile(request):
    return OpenAPIProfile.from_file(Path("tests/fixtures/contracts") / request.param)


def native(kind, seq, **data):
    return event(seq, type=kind, data={"sessionID": REF.upstream_session_id, **data})


async def setup(db, profile, *, outcome="succeeded", reason=None, delivered=True, duplicate=False):
    events = [native("session.execution.started", 1)]
    if delivered:
        events.append(native("session.inbox.delivered", 3, inboxID="msg_original"))
    if duplicate:
        events.append(native("session.inbox.delivered", 4, inboxID="msg_original"))
    events.append(
        native(
            "session.text.ended",
            5,
            assistantMessageID="msg_assistant",
            ordinal=0,
            text="  Original final text\n```python\nprint(0)\n```\n",
        )
    )
    events.append(
        native(
            "session.execution." + outcome,
            7,
            **(
                {"reason": reason}
                if outcome == "interrupted"
                else {"error": {"_tag": "FixtureFailure"}}
                if outcome == "failed"
                else {}
            ),
        )
    )
    events.append(synced(7))
    pump, binding, transport, proof, seen, stream = await reader(
        db, profile, [sse(value) for value in events]
    )
    source = SyntheticReader()
    dispatcher = Dispatcher(pump.bindings, pump.execution, source, pump.holder, pump.fencing)
    source.messages[101] = message(text="Original native task", revision=0)
    queued = await dispatcher.queue.receive(binding.id, source.messages[101])
    projector = NativeProjector(
        pump.bindings,
        ConsumerFence(pump.holder, pump.fencing),
        attestation=EventSemanticAttestation(
            REF.backend_id,
            REF.backend_identity,
            profile.sha256,
            SEMANTICS_SHA256,
            "f" * 64,
            frozenset(DATA),
        ),
    )
    return pump, binding, transport, dispatcher, queued.action_id, projector


async def project_all(projector):
    processed = []
    while (identity := await projector.next_pending()) is not None:
        assert await projector.advance(identity) == "projected"
        processed.append(identity)
    return processed


@pytest.mark.parametrize(
    "outcome,reason,result",
    [
        ("succeeded", None, "completed"),
        ("failed", None, "failed"),
        ("interrupted", "user", "cancelled"),
        ("interrupted", "shutdown", None),
    ],
)
async def test_native_delivery_and_busy_period_terminal_update_action_with_saved_result(
    db, profile, outcome, reason, result
):
    pump, binding, transport, dispatcher, action, projector = await setup(
        db, profile, outcome=outcome, reason=reason
    )
    try:
        assert await dispatcher.advance(action) == "admitted"
        await pump.run(binding.id)
        identities = await project_all(projector)
        assert len(identities) == 5
        saved = await dispatcher.load(action)
        if result is None:
            assert saved.state == "running" and not saved.native_result
        else:
            assert saved.state == result
            evidence = await read_result(pump.bindings, action, "realm", 7)
            assert evidence.outcome == result and evidence.reference == REF
            assert (
                evidence.admission_sha256
                and evidence.delivery_input_id != evidence.terminal_input_id
            )
        assert (
            saved.admission["admission"]["status"] == "admitted"
        )  # Never rewrite initial acknowledgement.
        assert await dispatcher.advance(action) == saved.state
        async with db.sessions() as session:
            projection = (await session.scalars(select(NativeProjection))).one()
            assert projection.last_ordinal == 5 and projection.version == 5
            assert (await session.get(InputEvent, identities[0])).state == "projected"
            records = (await session.scalars(select(NativeProjectionRecord))).all()
            text = next(row for row in records if row.assistant_message_id)
            assert text.payload["change"]["text"]["text"].startswith("  Original final text")
            assert text.payload["change"]["text"]["historical"] is True
        assert await projector.reconcile_actions(projection.key) == 0
        assert await projector.advance(identities[0]) == "projected"
    finally:
        await transport.close()


async def test_no_default_semantic_attestation_projects_or_completes_anything(db, profile):
    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        assert await dispatcher.advance(action) == "admitted"
        await pump.run(binding.id)
        disabled = NativeProjector(pump.bindings, projector.fence)
        assert await disabled.next_pending() is None
        identity = await projector.next_pending()
        with pytest.raises(Conflict, match="unqualified"):
            await disabled.advance(identity)
        assert (await dispatcher.load(action)).state == "admitted"
        async with db.sessions() as session:
            assert await session.scalar(select(NativeProjection.key)) is None
            assert all(
                row.state == "captured" for row in (await session.scalars(select(InputEvent))).all()
            )
    finally:
        await transport.close()


async def test_projection_before_native_acknowledgement_can_reconcile_late_admission_without_resend(
    db, profile
):
    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    original = pump.execution.submit
    scopes = []

    async def accepted_before_response(*args):
        admission = await original(*args)
        await pump.run(binding.id)
        await project_all(projector)
        async with db.sessions() as session:
            scopes.append((await session.scalars(select(NativeProjection.key))).one())
        assert (await dispatcher.load(action)).state == "dispatching"
        return admission

    pump.execution.submit = accepted_before_response
    try:
        assert await dispatcher.advance(action) == "admitted"
        assert await projector.reconcile_actions(scopes[0]) == 1
        assert (await dispatcher.load(action)).state == "completed"
        assert await projector.reconcile_actions(scopes[0]) == 0
    finally:
        await transport.close()


@pytest.mark.parametrize("mode", ["missing", "duplicate"])
async def test_terminal_without_unique_exact_delivered_inbox_keeps_action_uncompleted(
    db, profile, mode
):
    pump, binding, transport, dispatcher, action, projector = await setup(
        db, profile, delivered=mode != "missing", duplicate=mode == "duplicate"
    )
    try:
        await dispatcher.advance(action)
        await pump.run(binding.id)
        await project_all(projector)
        saved = await dispatcher.load(action)
        assert (
            saved.state == ("admitted" if mode == "missing" else "running")
            and saved.native_result == {}
        )
    finally:
        await transport.close()


async def test_out_of_order_projection_waits_for_prior_committed_ordinal(db, profile):
    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await pump.run(binding.id)
        async with db.sessions() as session:
            indices = (
                await session.scalars(select(NativeLogIndex).order_by(NativeLogIndex.ordinal))
            ).all()
        assert await projector.advance(indices[-1].input_event_id) == "waiting"
        async with db.sessions() as session:
            assert await session.scalar(select(NativeProjection.key)) is None
        assert len(await project_all(projector)) == len(indices)
    finally:
        await transport.close()


async def test_commit_failure_rolls_back_projection_receipt_cursor_and_native_result_together(
    db, profile
):
    from sqlalchemy import event as sql_event
    from sqlalchemy.orm import Session

    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await dispatcher.advance(action)
        await pump.run(binding.id)
        async with db.sessions() as session:
            ordered = (
                await session.scalars(select(NativeLogIndex).order_by(NativeLogIndex.ordinal))
            ).all()
        for index in ordered[:3]:
            await projector.advance(index.input_event_id)
        assert (await dispatcher.load(action)).state == "running"

        def fail(_):
            raise RuntimeError("injected projection commit failure")

        sql_event.listen(Session, "before_commit", fail)
        try:
            with pytest.raises(RuntimeError, match="injected"):
                await projector.advance(ordered[3].input_event_id)
        finally:
            sql_event.remove(Session, "before_commit", fail)
        async with db.sessions() as session:
            assert (await session.get(InputEvent, ordered[3].input_event_id)).state == "captured"
            assert await session.get(NativeProjectionRecord, ordered[3].input_event_id) is None
            assert (await session.scalars(select(NativeProjection))).one().last_ordinal == ordered[
                2
            ].ordinal
        assert (await dispatcher.load(action)).native_result == {}
        assert await projector.advance(ordered[3].input_event_id) == "projected"
        assert (await dispatcher.load(action)).state == "completed"
    finally:
        await transport.close()


async def test_concurrent_projection_of_same_receipt_has_one_record_and_action_effect(db, profile):
    import asyncio

    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await dispatcher.advance(action)
        await pump.run(binding.id)
        async with db.sessions() as session:
            ordered = (
                await session.scalars(select(NativeLogIndex).order_by(NativeLogIndex.ordinal))
            ).all()
        for index in ordered[:3]:
            await projector.advance(index.input_event_id)
        second = NativeProjector(pump.bindings, projector.fence, attestation=projector.attestation)
        assert await asyncio.gather(
            projector.advance(ordered[3].input_event_id), second.advance(ordered[3].input_event_id)
        ) == ["projected", "projected"]
        async with db.sessions() as session:
            records = (await session.scalars(select(NativeProjectionRecord))).all()
            assert (
                len(records) == 4
                and (await session.scalars(select(NativeProjection))).one().version == 4
            )
        assert (await dispatcher.load(action)).state == "completed"
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["grant", "binding", "backend", "attestation", "lease"])
async def test_authority_revoked_after_preflight_cannot_commit_projection(db, profile, change):
    from sqlalchemy import update

    from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend
    from jt_oz_bridge.storage.models import Grant, WorkerLease

    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await dispatcher.advance(action)
        await pump.run(binding.id)
        identity = await projector.next_pending()
        original = projector.preflight

        async def revoked(provenance):
            checked = await original(provenance)
            if change == "attestation":
                projector.attestation = None
            else:
                async with db.sessions.begin() as session:
                    if change == "grant":
                        await session.execute(
                            update(Grant).where(Grant.user_id == 8).values(active=False)
                        )
                    elif change == "binding":
                        await session.execute(update(Binding).values(revision=2))
                    elif change == "backend":
                        await session.execute(update(EnrolledBackend).values(enabled=False))
                    else:
                        await session.execute(update(WorkerLease).values(fencing=2))
            return checked

        projector.preflight = revoked
        from jt_oz_bridge.security.policy import AccessDenied

        with pytest.raises((Conflict, AccessDenied)):
            await projector.advance(identity)
        async with db.sessions() as session:
            assert (await session.get(InputEvent, identity)).state == "captured"
            assert await session.scalar(select(NativeProjection.key)) is None
        assert (await dispatcher.load(action)).native_result == {}
    finally:
        await transport.close()


async def test_projector_uses_transactional_ordinal_even_if_wallclock_metadata_runs_backwards(
    db, profile
):
    from sqlalchemy import update

    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await dispatcher.advance(action)
        await pump.run(binding.id)
        async with db.sessions.begin() as session:
            rows = (
                await session.scalars(select(NativeLogIndex).order_by(NativeLogIndex.ordinal))
            ).all()
            for index in rows:
                await session.execute(
                    update(InputEvent)
                    .where(InputEvent.id == index.input_event_id)
                    .values(created_at=1000 - index.ordinal)
                )
        assert await project_all(projector) == [row.input_event_id for row in rows]
        assert (await dispatcher.load(action)).state == "completed"
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["source", "scope", "revision", "hash"])
async def test_capture_index_metadata_or_payload_mismatch_never_projects(db, profile, change):
    from sqlalchemy import update

    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await pump.run(binding.id)
        identity = await projector.next_pending()
        async with db.sessions.begin() as session:
            if change == "source":
                await session.execute(
                    update(InputEvent)
                    .where(InputEvent.id == identity)
                    .values(source_id="evt_other")
                )
            elif change == "hash":
                await session.execute(
                    update(InputEvent)
                    .where(InputEvent.id == identity)
                    .values(payload_hash="0" * 64)
                )
            else:
                await session.execute(
                    update(NativeLogIndex)
                    .where(NativeLogIndex.input_event_id == identity)
                    .values(
                        **(
                            {"scope_key": "0" * 64}
                            if change == "scope"
                            else {"binding_revision": 2}
                        )
                    )
                )
        with pytest.raises(Conflict):
            await projector.advance(identity)
        async with db.sessions() as session:
            assert await session.scalar(select(NativeProjection.key)) is None
    finally:
        await transport.close()


@pytest.mark.parametrize("change", ["actor", "realm", "move", "digest", "outcome"])
async def test_native_result_reads_require_current_view_scope_and_immutable_action_identity(
    db, profile, change
):
    from sqlalchemy import update

    from jt_oz_bridge.security.policy import AccessDenied

    pump, binding, transport, dispatcher, action, projector = await setup(db, profile)
    try:
        await dispatcher.advance(action)
        await pump.run(binding.id)
        await project_all(projector)
        if change == "move":
            await pump.bindings.move(binding.id, "realm", 7, 1, 11, "Moved", whole_topic=True)
        elif change in {"digest", "outcome"}:
            saved = (await dispatcher.load(action)).native_result
            saved["operation_digest" if change == "digest" else "outcome"] = (
                "0" * 64 if change == "digest" else "failed"
            )
            async with db.sessions.begin() as session:
                await session.execute(
                    update(Action).where(Action.id == action).values(native_result=saved)
                )
        with pytest.raises((Conflict, AccessDenied)):
            await read_result(
                pump.bindings,
                action,
                "other" if change == "realm" else "realm",
                99 if change == "actor" else 7,
            )
    finally:
        await transport.close()
