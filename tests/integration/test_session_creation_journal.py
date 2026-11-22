"""Synthetic Humans and Native HTTP with actual isolated encrypted durable state.

These cases are not installed create qualification or a complete !oz new flow.
"""

import asyncio
import copy
import json
import time
from types import MappingProxyType, SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.domain.session_creation import SessionCreationIntent
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.session_creation_journal import CreationProject, SessionCreationJournal
from jt_oz_bridge.storage.control_models import (
    Binding,
    ControlToken,
    EnrolledBackend,
    EnrolledProject,
)
from jt_oz_bridge.storage.durable import Conflict, DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant, WorkerLease
from tests.contract.test_session_creation import setup as native_setup
from tests.integration.test_router import Source, message
from tests.support import SyntheticAudience, SyntheticControl


async def rows(db, model):
    async with db.sessions() as session:
        return list((await session.scalars(select(model))).all())


async def setup(db, mode="success"):
    client, transport, example, native_rows, calls = native_setup(mode=mode)
    scope = example.scope
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=scope.backend_id,
                identity=scope.backend_identity,
                contract_hash=transport.profile.sha256,
                enabled=True,
                verified=True,
                version="synthetic",
            )
        )
        session.add(
            EnrolledProject(
                id=scope.project_id,
                backend_id=scope.backend_id,
                realm_id="realm",
                canonical_directory=scope.canonical_directory,
                enabled=True,
            )
        )
        for user in (7, 8):
            session.add(
                Grant(realm_id="realm", user_id=user, project_id=scope.project_id, role="operator")
            )
    audience, source = SyntheticAudience(), Source()
    service = BindingService(db, SyntheticControl(), audience)
    lease = await DurableStore(db).acquire_lease("creation", ttl=120)
    project = CreationProject(
        template=client.templates[scope.project_id],
        owner_epoch=example.owner_epoch,
        contract_sha256=transport.profile.sha256,
        policy_template_sha256="d" * 64,
    )
    journal = SessionCreationJournal(
        service, source, ConsumerFence("creation", lease), {scope.project_id: project}
    )
    item = message("!oz projects", 100)
    source.messages[100] = item
    token = await journal.offer(scope.project_id, item)
    item = message("!oz new " + token + " Original new project", 101)
    source.messages[101] = item

    # Reuse the actual fixed RPC codec but route GET to the journal-generated ID.
    async def handle(request):
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            body = json.loads(request.content)
            from tests.contract.test_v2_catalog import native

            native_rows[body["id"]] = native(
                id=body["id"],
                location=body["location"],
                agent=body["agent"],
                permissions=body["permissions"],
                metadata=body["metadata"],
                title=body.get("title", "Native default title"),
            )
            if mode == "lost-ack":
                raise httpx.ReadTimeout("synthetic lost ACK", request=request)
            return httpx.Response(200, json={"data": copy.deepcopy(native_rows[body["id"]])})
        identity = request.url.path.rsplit("/", 1)[1]
        if identity not in native_rows:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json={"data": copy.deepcopy(native_rows[identity])})

    transport.client._transport = httpx.MockTransport(handle)
    return journal, client, transport, source, item, native_rows, calls, audience


async def test_reservation_is_encrypted_deduplicated_and_never_active_or_posted(db):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        first, second = await asyncio.gather(journal.reserve(item), journal.reserve(item))
        assert first == second and not calls
        action, binding = await journal.load(first)
        intent = SessionCreationIntent.model_validate(action.payload["intent"])
        assert action.state == "queued" and binding.state == "creating"
        assert binding.session_id == intent.native_session_id and binding.anchor_message_id == 101
        assert (
            binding.topic_key
            and binding.session_key
            and intent.source_sha256 == digest(item.model_dump(mode="json"))
        )
        assert len(await rows(db, Action)) == len(await rows(db, Binding)) == 1
        assert (await rows(db, ControlToken))[0].used
        # SQL payloads are ciphertext, not a copy of the command or title.
        from sqlalchemy import text

        async with db.engine.connect() as connection:
            raw = await connection.scalar(text("SELECT payload FROM actions"))
        assert "Original new project" not in str(raw) and item.text not in str(raw)
    finally:
        await transport.close()


async def test_one_worker_attempt_and_readback_are_durable_but_not_registration(db):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        identity = await journal.reserve(item)
        one, two = await asyncio.gather(
            journal.advance(identity, client), journal.advance(identity, client)
        )
        assert "admitted" in (one, two)
        assert sum(method == "POST" for method, _ in calls) == len(native_rows) == 1
        action, binding = await journal.load(identity)
        assert action.admission["format"] == "creation-one-attempt-v1"
        assert action.state == "admitted" and action.status_reason == "registration_pending"
        assert binding.state == "creating" and binding.observed_cursor == ""
        assert action.native_result["candidate"]["registered_for_execution"] is False
        saved_calls = list(calls)
        assert await journal.advance(identity, client) == "admitted"
        assert calls == saved_calls and await journal.reserve(item) == identity
    finally:
        await transport.close()


async def test_lost_ack_restarts_with_same_id_and_get_only_no_second_post(db):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(
        db, "lost-ack"
    )
    try:
        identity = await journal.reserve(item)
        assert await journal.advance(identity, client) == "ambiguous"
        original, binding = await journal.load(identity)
        restored = SessionCreationJournal(journal.bindings, source, journal.fence, journal.projects)
        assert await restored.advance(identity, client) == "admitted"
        current, binding = await restored.load(identity)
        assert current.payload == original.payload and len(native_rows) == 1
        assert sum(method == "POST" for method, _ in calls) == 1
        assert [path for method, path in calls if method == "GET"] == [
            "/api/session/" + binding.session_id,
            "/api/session/" + binding.session_id,
        ]
    finally:
        await transport.close()


async def test_crash_after_committed_claim_never_resends_even_when_session_absent(db):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        identity = await journal.reserve(item)
        assert await journal.claim(identity)
        assert await journal.claim(identity) is None
        await DurableStore(db).recover()
        with pytest.raises(ValueError):
            await journal.advance(identity, client)
        assert not native_rows and calls == [
            ("GET", "/api/session/" + (await journal.load(identity))[1].session_id)
        ]
        assert (await journal.load(identity))[0].state == "ambiguous"
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault",
    [
        "edited",
        "deleted",
        "bot",
        "viewer",
        "grant",
        "project",
        "backend",
        "audience",
        "public",
        "lease",
        "paused",
    ],
)
async def test_changed_source_authority_enrollment_or_pause_never_posts(db, fault):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        identity = await journal.reserve(item)
        if fault in {"edited", "deleted", "bot"}:
            changes = {
                "edited": {"revision": 1},
                "deleted": {"deleted": True},
                "bot": {"is_bot": True},
            }[fault]
            source.messages[101] = item.model_copy(update=changes)
        elif fault == "audience":
            audience.users = frozenset({7})
        elif fault == "public":
            audience.private = False
        else:
            async with db.sessions.begin() as session:
                if fault in {"viewer", "grant"}:
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == 7)
                        .values(**({"role": "viewer"} if fault == "viewer" else {"active": False}))
                    )
                elif fault == "project":
                    await session.execute(update(EnrolledProject).values(enabled=False))
                elif fault == "backend":
                    await session.execute(update(EnrolledBackend).values(identity="changed"))
                elif fault == "lease":
                    await session.execute(update(WorkerLease).values(fencing=99))
                else:
                    await session.execute(update(Binding).values(dispatch_paused=True))
        if fault == "paused":
            assert await journal.advance(identity, client) == "queued"
        else:
            with pytest.raises((AccessDenied, Conflict)):
                await journal.advance(identity, client)
        assert not calls and not native_rows
    finally:
        await transport.close()


@pytest.mark.parametrize(
    "fault", ["channel", "topic", "actor", "realm", "audience", "template", "expired"]
)
async def test_opaque_project_selection_cannot_be_replayed_in_other_scope(db, fault):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        if fault in {"channel", "topic", "actor", "realm"}:
            item = item.model_copy(
                update={
                    "channel": {"channel_id": 12},
                    "topic": {"topic": "Other"},
                    "actor": {"author_id": 8},
                    "realm": {"realm_id": "other"},
                }[fault]
            )
            source.messages[101] = item
        elif fault == "audience":
            audience.revision = "audience:2"
        elif fault == "template":
            project = next(iter(journal.projects.values()))
            journal.projects = MappingProxyType(
                {
                    project.template.scope.project_id: project.model_copy(
                        update={"policy_template_sha256": "e" * 64}
                    )
                }
            )
        else:
            async with db.sessions.begin() as session:
                await session.execute(update(ControlToken).values(expires_at=0))
        with pytest.raises((AccessDenied, Conflict)):
            await journal.reserve(item)
        assert not calls and not await rows(db, Action) and not await rows(db, Binding)
    finally:
        await transport.close()


async def test_reserved_topic_cannot_replace_existing_binding_and_token_rolls_back(db):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        identity = await journal.reserve(item)
        offer = message("!oz projects", 103)
        source.messages[103] = offer
        token = await journal.offer(next(iter(journal.projects)), offer)
        other = message("!oz new " + token + " Other session", 104)
        source.messages[104] = other
        with pytest.raises(Conflict, match="topic_already"):
            await journal.reserve(other)
        assert len(await rows(db, Action)) == len(await rows(db, Binding)) == 1
        assert await journal.reserve(item) == identity
        assert sum(not x.used for x in await rows(db, ControlToken)) == 1
    finally:
        await transport.close()


async def test_normal_dispatcher_skips_creation_operation(db):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        identity = await journal.reserve(item)
        dispatched = []

        async def advance(value):
            dispatched.append(value)

        # Exercise the real SQL selection without starting unrelated consumer loops.
        pipeline = SimpleNamespace(
            db=db, realm_id="realm", dispatcher=SimpleNamespace(advance=advance)
        )
        await ConsumerPipeline.dispatch_once(pipeline)
        assert not dispatched and (await journal.load(identity))[0].state == "queued"
    finally:
        await transport.close()


async def test_expired_claim_during_identity_await_rejects_without_post(db, monkeypatch):
    journal, client, transport, source, item, native_rows, calls, audience = await setup(db)
    try:
        identity = await journal.reserve(item)
        clock = [time.time()]
        from jt_oz_bridge.services import session_creation_journal

        monkeypatch.setattr(session_creation_journal.time, "time", lambda: clock[0])

        async def identity_check():
            clock[0] += 6
            return True

        transport.verify_identity = identity_check
        assert await journal.advance(identity, client) == "rejected"
        assert not calls and not native_rows
        assert (await journal.load(identity))[0].status_reason == "creation_proven_not_sent"
    finally:
        await transport.close()
