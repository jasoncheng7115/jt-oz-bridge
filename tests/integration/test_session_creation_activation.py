"""Synthetic Human/Native graph, real encrypted SQL and outbox; no live peers."""

import asyncio
import copy
import time
from dataclasses import replace
from html import unescape

import pytest
from sqlalchemy import update

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.session_creation import CreatedRootActivation
from jt_oz_bridge.services.backend_registry import BackendRegistry, RegisteredBackend
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from jt_oz_bridge.services.outbox import Outbox
from jt_oz_bridge.services.routed_output import RoutedOutbox
from jt_oz_bridge.services.session_creation_activation import SessionCreationActivation
from jt_oz_bridge.services.session_creation_journal import CreationProject, SessionCreationJournal
from jt_oz_bridge.services.session_registry import SessionRegistry
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import DurableStore, digest
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, AuditEvent, Delivery, DeliveryBatch, Grant
from tests.contract.test_created_root_factory import setup as factory_setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_public_live_feed import REAL
from tests.integration.test_router import Source, message
from tests.integration.test_session_creation_journal import rows
from tests.support import SyntheticAudience, SyntheticControl


async def setup(db, *, locale="en"):
    env = {}

    async def make_intent(creator, policies, epoch):
        template = policies.template.creation
        scope = template.scope
        async with db.sessions.begin() as session:
            session.add(
                EnrolledBackend(
                    id=scope.backend_id,
                    identity=scope.backend_identity,
                    contract_hash=creator.transport.profile.sha256,
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
                    Grant(
                        realm_id="realm", user_id=user, project_id=scope.project_id, role="operator"
                    )
                )
        audience, source = SyntheticAudience(), Source()
        bindings = BindingService(db, SyntheticControl(), audience)
        lease = await DurableStore(db).acquire_lease("activation", ttl=120)
        project = CreationProject(
            template=template,
            owner_epoch=epoch,
            contract_sha256=creator.transport.profile.sha256,
            policy_template_sha256=policies.template.checksum(),
        )
        journal = SessionCreationJournal(
            bindings, source, ConsumerFence("activation", lease), {scope.project_id: project}
        )
        offer = message("!oz projects", 100)
        source.messages[100] = offer
        token = await journal.offer(scope.project_id, offer)
        item = message("!oz new " + token + " Synthetic activation Root", 101)
        source.messages[101] = item
        identity = await journal.reserve(item, locale)
        claim = await journal.claim(identity)
        assert claim is not None
        action, binding, _ = claim
        _, intent, _ = journal.payload(action, binding)
        env.update(
            journal=journal,
            source=source,
            item=item,
            identity=identity,
            claim=action,
            audience=audience,
        )
        return intent

    p, t, d, factory, intent, candidate, state, calls, writes, anchor = await factory_setup(
        make_intent=make_intent
    )
    journal = env["journal"]
    journal.bindings.control = factory.registry
    # Exercise the real one-attempt claim/readback journal, without a Native POST.
    assert await journal.record(env["claim"], factory.creator, candidate) == "admitted"
    replies = RoutedOutbox(
        Outbox(journal.bindings, 9, fence=journal.fence),
        realm_id="realm",
        message_limit=10000,
        topic_limit=60,
    )
    service = SessionCreationActivation(journal, {intent.scope.project_id: factory}, replies)
    env.update(
        p=p,
        t=t,
        d=d,
        factory=factory,
        intent=intent,
        candidate=candidate,
        state=state,
        calls=calls,
        writes=writes,
        anchor=anchor,
        replies=replies,
        service=service,
    )
    return env


async def cleanup(env):
    await finish(env["p"], env["t"])


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_activation_commits_one_exact_binding_and_notice_without_prompt_or_post(db, locale):
    e = await setup(db, locale=locale)
    try:
        a, b = await asyncio.gather(
            e["service"].reconcile(e["identity"]), e["service"].reconcile(e["identity"])
        )
        assert a.id == b.id and a.state == b.state == "active"
        action, binding = await e["journal"].load(e["identity"])
        receipt = CreatedRootActivation.model_validate(action.native_result["activation"])
        assert action.state == "completed" and action.version == 4
        assert binding.revision == 1 and binding.observed_cursor and not binding.dispatch_paused
        assert receipt.reference.upstream_session_id == e["intent"].native_session_id
        assert receipt.creation_receipt_sha256 == digest(e["candidate"].model_dump(mode="json"))
        assert receipt.starts_execution is False and len(await rows(db, DeliveryBatch)) == 1
        deliveries = await rows(db, Delivery)
        assert len(deliveries) == 1 and deliveries[0].state == "pending"
        assert (
            deliveries[0].binding_id == binding.id
            and deliveries[0].payload["topic"] == e["item"].topic
        )
        # The notice names the title and project, never the raw Native session ID.
        notice = unescape(deliveries[0].payload["content"])
        assert e["intent"].native_session_id not in notice and "fixture-project" in notice
        assert (
            len([r for r in await rows(db, AuditEvent) if r.event == "session_create_activated"])
            == 1
        )
        assert await e["journal"].reserve(e["item"]) == action.id
        assert await e["journal"].advance(action.id, e["factory"].creator) == "completed"
        assert e["factory"].registry.sessions[e["anchor"].reference] is e["anchor"]
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
    finally:
        await cleanup(e)


@pytest.mark.parametrize("mode", ["idle", "running", "queued", "waiting", "waiting-input"])
async def test_fresh_coordinator_restores_same_used_root_and_original_notice_get_only(db, mode):
    e = await setup(db)
    try:
        await e["service"].reconcile(e["identity"])
        before = [r.payload_hash for r in await rows(db, Delivery)]
        e["state"]["info"].update(title="Already used original Root", cost=1.0)
        e["state"]["info"]["tokens"]["input"] = 50
        if mode in {"running", "waiting", "waiting-input"}:
            e["d"]["session.active"]["data"][e["intent"].native_session_id] = {"type": "running"}
            if mode == "waiting":
                permission = copy.deepcopy(
                    next(event["data"] for event in REAL if event["type"] == "permission.asked")
                )
                permission["sessionID"] = e["intent"].native_session_id
                e["state"]["permissions"] = [permission]
            elif mode == "waiting-input":
                form = copy.deepcopy(
                    next(event["data"]["form"] for event in REAL if event["type"] == "form.created")
                )
                form["sessionID"] = e["intent"].native_session_id
                e["state"]["forms"] = [form]
        elif mode == "queued":
            e["state"]["inbox"] = [
                {
                    "id": "msg_queue",
                    "sessionID": e["intent"].native_session_id,
                    "type": "user",
                    "payload": {"text": "synthetic work"},
                    "delivery": "queue",
                    "time": {"created": 101},
                }
            ]
        original_entry = e["factory"].registry.sessions[e["candidate"].reference]
        registry = SessionRegistry({e["anchor"].reference: e["anchor"]})
        factory = V2CreatedRootFactory(e["factory"].creator, e["factory"].policies, registry)
        e["journal"].bindings.control = registry
        service = SessionCreationActivation(
            e["journal"], {e["intent"].scope.project_id: factory}, e["replies"]
        )
        assert await service.restore_active() == (e["identity"],)
        assert registry.sessions[e["candidate"].reference] is not original_entry
        snap = await registry.snapshot(e["candidate"].reference)
        assert (
            snap.state
            == {
                "idle": ExecutionState.IDLE,
                "running": ExecutionState.RUNNING,
                "queued": ExecutionState.QUEUED,
                "waiting": ExecutionState.WAITING_PERMISSION,
                "waiting-input": ExecutionState.WAITING_INPUT,
            }[mode]
        )
        assert snap.title == "Already used original Root"
        assert [r.payload_hash for r in await rows(db, Delivery)] == before
        assert len(await rows(db, DeliveryBatch)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


async def test_fresh_coordinator_restores_root_whose_notice_retention_compacted(db):
    """Retention keeps a tombstone of a posted notice after a week; restore read it as content."""
    from jt_oz_bridge.config import Retention
    from jt_oz_bridge.services.retention import DAY, RetentionExecutor

    e = await setup(db)
    try:
        await e["service"].reconcile(e["identity"])
        async with db.sessions.begin() as session:
            await session.execute(
                update(Delivery).values(
                    state="delivered", posted_message_id=9001, updated_at=time.time() - 8 * DAY
                )
            )
        retention = RetentionExecutor(db, e["journal"].fence, Retention(), batch_size=1000)
        for _ in range(8):
            await retention.sweep()
        (notice,) = await rows(db, Delivery)
        assert notice.payload_compacted_at is not None and "content" not in notice.payload
        registry = SessionRegistry({e["anchor"].reference: e["anchor"]})
        factory = V2CreatedRootFactory(e["factory"].creator, e["factory"].policies, registry)
        e["journal"].bindings.control = registry
        service = SessionCreationActivation(
            e["journal"], {e["intent"].scope.project_id: factory}, e["replies"]
        )
        assert await service.restore_active() == (e["identity"],)
        assert e["candidate"].reference in registry.sessions
        # Still the delivered page of this very batch, by its original hash.
        async with db.sessions.begin() as session:
            row = await session.get(Delivery, notice.id)
            row.payload = {**row.payload, "original_hash": "0" * 64}
        registry = SessionRegistry({e["anchor"].reference: e["anchor"]})
        factory = V2CreatedRootFactory(e["factory"].creator, e["factory"].policies, registry)
        e["journal"].bindings.control = registry
        service = SessionCreationActivation(
            e["journal"], {e["intent"].scope.project_id: factory}, e["replies"]
        )
        with pytest.raises(ValueError, match="retention_tombstone_identity_changed"):
            await service.reconcile(e["identity"], restore=True)
        assert not e["writes"]
    finally:
        await cleanup(e)


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "audience",
        "public",
        "grant",
        "viewer",
        "backend",
        "project",
        "paused",
        "receipt",
        "attempt",
        "topic-key",
        "session-key",
        "owner",
        "anchor",
    ],
)
async def test_revocation_or_tampered_owned_state_never_activates_or_queues_notice(db, fault):
    e = await setup(db)
    try:
        if fault == "source":
            e["source"].messages[101] = e["item"].model_copy(update={"revision": 1})
        elif fault == "audience":
            e["audience"].users = frozenset({7})
        elif fault == "public":
            e["audience"].private = False
        else:
            async with db.sessions.begin() as session:
                if fault in {"grant", "viewer"}:
                    await session.execute(
                        update(Grant)
                        .where(Grant.user_id == 7)
                        .values(**({"active": False} if fault == "grant" else {"role": "viewer"}))
                    )
                elif fault == "backend":
                    await session.execute(update(EnrolledBackend).values(enabled=False))
                elif fault == "project":
                    await session.execute(update(EnrolledProject).values(enabled=False))
                elif fault in {"receipt", "attempt"}:
                    action = await session.get(Action, e["identity"])
                    if fault == "receipt":
                        result = copy.deepcopy(action.native_result)
                        result["candidate"]["native_created_at"] += 1
                        action.native_result = result
                    else:
                        action.admission = {}
                else:
                    await session.execute(
                        update(Binding).values(
                            **{
                                "paused": {"dispatch_paused": True},
                                "topic-key": {"topic_key": "f" * 64},
                                "session-key": {"session_key": "f" * 64},
                                "owner": {"owner_id": 8},
                                "anchor": {"anchor_message_id": 999},
                            }[fault]
                        )
                    )
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        assert not await rows(db, Delivery) and not await rows(db, DeliveryBatch)
        assert (await rows(db, Binding))[0].state == "creating"
        assert (await rows(db, Action))[0].state == "admitted" and not e["writes"]
    finally:
        await cleanup(e)


@pytest.mark.parametrize("failure", ["raise", "cancel", "new-arrival"])
async def test_notice_or_final_fence_failure_rolls_back_binding_action_and_entire_batch(
    db, monkeypatch, failure
):
    e = await setup(db)
    original = e["replies"].outbox.queue_batch_in_session
    try:

        async def fail(*args, **kwargs):
            result = await original(*args, **kwargs)
            if failure == "new-arrival":
                index, sid = e["p"].feed.index, e["intent"].native_session_id
                index._arrival_revisions[sid] = index._arrival_revisions.get(sid, 0) + 1
                return result
            if failure == "cancel":
                raise asyncio.CancelledError()
            raise RuntimeError("synthetic failure after local batch insert")

        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", fail)
        with pytest.raises((ValueError, RuntimeError, asyncio.CancelledError)):
            await e["service"].reconcile(e["identity"])
        action, binding = await e["journal"].load(e["identity"])
        assert action.state == "admitted" and binding.state == "creating"
        assert "activation" not in action.native_result
        assert not await rows(db, DeliveryBatch) and not await rows(db, Delivery)
        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", original)
        assert (await e["service"].reconcile(e["identity"])).state == "active"
        assert len(await rows(db, Delivery)) == 1
    finally:
        await cleanup(e)


async def test_pending_used_root_requires_explicit_owned_recovery_without_recreate(db):
    e = await setup(db)
    try:
        e["state"]["info"]["cost"] = 1.0
        e["d"]["session.active"]["data"][e["intent"].native_session_id] = {"type": "running"}
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        binding = await e["service"].reconcile(e["identity"], restore=True)
        assert binding.state == "active" and len(await rows(db, Delivery)) == 1
        assert (
            await e["factory"].registry.snapshot(e["candidate"].reference)
        ).state == ExecutionState.RUNNING
    finally:
        await cleanup(e)


async def test_completed_receipt_cannot_reactivate_unbound_binding_or_change_notice_pointer(db):
    e = await setup(db)
    try:
        binding = await e["service"].reconcile(e["identity"])
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(state="unbound", revision=2)
            )
        assert await e["service"].restore_active() == ()
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"], restore=True)
        assert len(await rows(db, Delivery)) == 1
    finally:
        await cleanup(e)


async def test_completed_receipt_cannot_point_to_another_valid_batch_in_same_binding(db):
    e = await setup(db)
    try:
        binding = await e["service"].reconcile(e["identity"])
        other = await e["replies"].outbox.queue_batch(
            "unrelated-notice",
            binding.id,
            binding.revision,
            ("Other synthetic notice",),
            renderer_version="unrelated-v1",
            message_limit=10000,
            topic_limit=60,
        )
        async with db.sessions.begin() as session:
            action = await session.get(Action, e["identity"])
            result = copy.deepcopy(action.native_result)
            result["activation"]["notice_batch_id"] = other.id
            action.native_result = result
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        assert len(await rows(db, DeliveryBatch)) == 2
    finally:
        await cleanup(e)


async def test_native_global_policy_drift_after_registration_still_prevents_activation(
    db, monkeypatch
):
    e = await setup(db)
    original = e["factory"].register
    try:

        async def change(*args, **kwargs):
            entry = await original(*args, **kwargs)
            e["d"]["mcp.list"]["data"] = []
            return entry

        monkeypatch.setattr(e["factory"], "register", change)
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        assert (await rows(db, Binding))[0].state == "creating"
        assert not await rows(db, Delivery)
    finally:
        await cleanup(e)


@pytest.mark.parametrize(
    "fault",
    ["execution", "proofs", "guard", "policy", "semantics", "attestation", "policy-observation"],
)
async def test_original_registered_graph_cannot_be_replaced_before_activation_commit(
    db, monkeypatch, fault
):
    e = await setup(db)
    original = e["replies"].outbox.queue_batch_in_session
    try:

        async def change(*args, **kwargs):
            result = await original(*args, **kwargs)
            entry = e["factory"].registry.sessions[e["candidate"].reference]
            if fault == "execution":
                registry = e["factory"].registry
                replacement = replace(entry)
                e["factory"].registry = SessionRegistry(
                    {**registry.sessions, entry.reference: replacement}
                )
                assert replacement.reference == entry.reference
                assert e["factory"].registry.sessions[entry.reference] is not entry
                assert e["factory"].anchor is e["anchor"]
                assert e["factory"].registry.sessions[e["anchor"].reference] is e["anchor"]
            elif fault == "proofs":
                entry.execution.proofs = copy.copy(entry.execution.proofs)
            elif fault == "guard":
                entry.execution.scope_guard = copy.copy(entry.execution.scope_guard)
            elif fault == "policy":
                guard = entry.execution.scope_guard
                guard.enrollments = {
                    entry.reference: guard.enrollments[entry.reference].model_copy(
                        update={"fingerprint_sha256": "f" * 64}
                    )
                }
            elif fault == "semantics":
                entry.results.attestation = replace(entry.results.attestation)
            elif fault == "attestation":
                e["t"].attestation = replace(e["t"].attestation)
            else:
                e["factory"]._policies[entry.reference] = replace(
                    e["factory"]._policies[entry.reference]
                )
            return result

        monkeypatch.setattr(e["replies"].outbox, "queue_batch_in_session", change)
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        assert (await rows(db, Binding))[0].state == "creating"
        assert not await rows(db, Delivery)
        assert not e["writes"]
    finally:
        await cleanup(e)


async def test_revocation_after_registration_keeps_owned_receipt_inert_and_retryable(
    db, monkeypatch
):
    e = await setup(db)
    original = e["factory"].register
    try:

        async def revoke(*args, **kwargs):
            entry = await original(*args, **kwargs)
            e["source"].messages[101] = e["item"].model_copy(update={"deleted": True})
            return entry

        monkeypatch.setattr(e["factory"], "register", revoke)
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        assert e["candidate"].reference in e["factory"].registry.sessions
        assert (await rows(db, Binding))[0].state == "creating" and not await rows(db, Delivery)
        monkeypatch.setattr(e["factory"], "register", original)
        e["source"].messages[101] = e["item"]
        assert (await e["service"].reconcile(e["identity"])).state == "active"
        assert len(await rows(db, Delivery)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


@pytest.mark.parametrize("restore", [False, True])
async def test_slow_zulip_reads_still_fit_the_five_second_creation_readback(
    db, monkeypatch, restore
):
    """A slow Zulip can take about 0.5 s per audience check.

    Registration must not repeat that check so often that it outlives its 5 s
    readback, or a chat-created Root would stay "creating" for good.
    """
    e = await setup(db)
    clock = {"offset": 0.0, "reads": 0}
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + clock["offset"])
    inspect = e["audience"].inspect

    async def slow(*args):
        clock["offset"] += 0.6
        clock["reads"] += 1
        return await inspect(*args)

    monkeypatch.setattr(e["audience"], "inspect", slow)
    try:
        binding = await e["service"].reconcile(e["identity"], restore=restore)
        assert binding.state == "active" and clock["reads"] <= 3
        assert len(await rows(db, Delivery)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


async def test_revocation_during_registration_is_caught_before_the_binding_activates(
    db, monkeypatch
):
    e = await setup(db)
    original = e["factory"].creator.current

    async def revoke(*args, **kwargs):
        e["audience"].users = frozenset({8})
        return await original(*args, **kwargs)

    monkeypatch.setattr(e["factory"].creator, "current", revoke)
    try:
        with pytest.raises(ValueError):
            await e["service"].reconcile(e["identity"])
        assert (await rows(db, Binding))[0].state == "creating" and not await rows(db, Delivery)
        assert (await rows(db, Action))[0].state == "admitted"
    finally:
        await cleanup(e)


async def test_activation_uses_original_registry_through_actual_backend_router(db):
    e = await setup(db)
    try:
        ref = e["anchor"].reference
        routed = BackendRegistry(
            {
                ref.backend_id: RegisteredBackend(
                    ref.backend_identity,
                    e["t"].profile.sha256,
                    {ref.project_id: ref.canonical_directory},
                    e["factory"].registry,
                )
            }
        )
        e["journal"].bindings.control = routed
        service = SessionCreationActivation(
            e["journal"], {ref.project_id: e["factory"]}, e["replies"]
        )
        binding = await service.reconcile(e["identity"])
        assert binding.state == "active"
        assert routed.selected(e["candidate"].reference).client is e["factory"].registry
        assert len(await rows(db, Delivery)) == 1 and not e["writes"]
    finally:
        await cleanup(e)


async def startup_pipeline(e, *, change=None):
    """Real pipeline/activation objects, synthetic Native HTTP and audience only.

    The durable completed receipt survives while the in-memory registry is new.
    No consumer/input worker is run by these startup-boundary tests.
    """
    from unittest.mock import AsyncMock

    import httpx

    from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject, V2SessionCatalog
    from jt_oz_bridge.adapters.zulip.client import ZulipAttestation, ZulipClient
    from jt_oz_bridge.adapters.zulip.scope import SCOPE_OPERATIONS, ZulipScopeReader
    from jt_oz_bridge.domain.catalog import ProjectScope
    from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline, RuntimeBackend
    from jt_oz_bridge.services.discovery import RegisteredCatalog
    from jt_oz_bridge.services.runtime import RuntimeResource
    from jt_oz_bridge.services.zulip_consumer import EVENT_OPERATIONS
    from tests.integration.test_zulip_consumer import URL

    old = e["factory"]
    original = e["anchor"]
    if change == "missing-anchor-transcript":
        original = replace(original, transcript=None)
    elif change == "missing-anchor-metadata":
        original = replace(original, metadata=None)
    ref = original.reference
    registry = SessionRegistry({ref: original})
    factory = V2CreatedRootFactory(old.creator, old.policies, registry)
    scope = ProjectScope(**ref.model_dump(exclude={"upstream_session_id"}))
    catalog = V2SessionCatalog(e["t"], {ref.project_id: V2CatalogProject(scope, "global")})
    markers = []

    async def native_start():
        assert set(registry.sessions) == {ref}
        markers.append("native-start")

    async def native_close():
        markers.append("native-close")

    client = ZulipClient(
        URL,
        "synthetic-startup-bot@example.invalid",
        "synthetic-key",
        attestation=ZulipAttestation(
            URL,
            "realm",
            9,
            500,
            10000,
            60,
            verified_scope_operations=SCOPE_OPERATIONS,
            verified_event_operations=EVENT_OPERATIONS,
        ),
        verify_identity=AsyncMock(return_value=True),
        transport=httpx.MockTransport(lambda request: httpx.Response(500)),
    )
    audience = ZulipScopeReader(client, channel_ids=frozenset({10}))
    # Keep the explicitly synthetic audience which authorized the owned receipt.
    audience.inspect = e["audience"].inspect
    backend = RuntimeBackend(
        RegisteredBackend(ref.backend_identity, e["t"].profile.sha256, registry.projects, registry),
        RegisteredCatalog(ref.backend_identity, e["t"].profile.sha256, registry.projects, catalog),
        registry.models,
        registry.results,
        (ref,),
        registry.pending,
        AsyncMock(),
        (RuntimeResource("native:" + ref.backend_id, native_start, native_close),),
        registry.transcripts,
        registry.live_text,
        registry.metadata,
        reference_provider=registry.reference_snapshot,
    )
    if change == "static-backend":
        backend = replace(backend, reference_provider=None)
    elif change == "copied-provider":
        backend = replace(backend, reference_provider=lambda: registry.reference_snapshot())
    elif change == "static-transcripts":
        backend = replace(backend, transcripts=dict(backend.transcripts))
    elif change == "static-metadata":
        backend = replace(backend, metadata=dict(backend.metadata))
    elif change == "static-live-text":
        backend = replace(backend, live_text=dict(backend.live_text))
    elif change == "copied-view":
        from jt_oz_bridge.domain.enrollment_views import EnrollmentView

        backend = replace(backend, transcripts=EnrollmentView(lambda: registry.transcripts))
    elif change in {"other-provider", "other-pending", "other-models", "other-results"}:
        other = SessionRegistry({ref: original})
        if change == "other-provider":
            backend = replace(backend, reference_provider=other.reference_snapshot)
        elif change == "other-pending":
            backend = replace(backend, pending=other.pending)
        elif change == "other-models":
            backend = replace(backend, models=other.models)
        else:
            backend = replace(backend, results=other.results)

    def make_creation(bindings, source, replies):
        from tests.integration.test_router import Source

        journal = SessionCreationJournal(
            bindings, source, e["journal"].fence, e["journal"].projects
        )
        activation = SessionCreationActivation(journal, {ref.project_id: factory}, replies)
        if change == "source":
            journal.reader = Source()
        elif change == "replies":
            activation.replies = RoutedOutbox(
                replies.outbox, realm_id="realm", message_limit=10000, topic_limit=60
            )
        elif change == "fence":
            journal.fence = ConsumerFence("different-owner", e["journal"].fence.fencing)
        elif change == "none":
            return None
        return activation

    try:
        pipeline = ConsumerPipeline(
            e["journal"].db,
            e["journal"].fence,
            audience,
            {ref.backend_id: backend},
            creation_factory=make_creation,
        )
    except BaseException:
        await client.close()
        raise

    async def consumer_start():
        # This start boundary must see the complete original registration, or the
        # Root explicitly left unregistered alone.
        selected = factory.selected(e["intent"])
        assert selected in registry.sessions or selected in pipeline.creation.unrestored_roots()
        markers.append("consumer-start")

    async def consumer_close():
        markers.append("consumer-close")

    pipeline.start_consumer = consumer_start
    pipeline.consumer.close = consumer_close
    return pipeline, registry, factory, markers


@pytest.mark.parametrize("paused", [False, True])
@pytest.mark.parametrize("native_state", ["idle", "running"])
async def test_pipeline_restores_completed_root_before_consumer_and_workers_without_writes(
    db, paused, native_state
):
    from jt_oz_bridge.services.runtime import RuntimeWorker, SupervisedRuntime

    e = await setup(db)
    pipeline = runtime = None
    try:
        binding = await e["service"].reconcile(e["identity"])
        if paused:
            async with db.sessions.begin() as session:
                await session.execute(
                    update(Binding).where(Binding.id == binding.id).values(dispatch_paused=True)
                )
        e["source"].messages.clear()  # Completed restoration does not reuse old commands.
        if native_state == "running":
            e["d"]["session.active"]["data"][e["intent"].native_session_id] = {"type": "running"}
            e["state"]["info"]["time"]["updated"] = 110
        before_action, before_binding = await e["journal"].load(e["identity"])
        notices_before = [(d.id, d.payload_hash, d.state) for d in await rows(db, Delivery)]
        pipeline, registry, factory, markers = await startup_pipeline(e)
        ref = factory.selected(e["intent"])
        assert ref not in registry.sessions
        graph = pipeline.runtime()
        names = [r.name for r in graph.resources]
        assert names.index("session-restoration") > names.index("native:" + ref.backend_id)
        assert names.index("zulip-client") < names.index("session-restoration")
        assert names.index("session-restoration") < names.index("zulip-consumer")

        async def worker():
            assert ref in registry.sessions and markers == ["native-start", "consumer-start"]
            markers.append("worker-start")
            await asyncio.Event().wait()

        runtime = SupervisedRuntime(
            db, pipeline.fence, graph.resources, (RuntimeWorker("native-dispatch", worker),)
        )
        await runtime.start()
        assert runtime.healthy and markers == ["native-start", "consumer-start", "worker-start"]
        assert registry.sessions[e["anchor"].reference] is e["anchor"]
        assert ref in pipeline.backends[ref.backend_id].current_references
        assert ref in pipeline.router.metadata.readers
        assert ref in pipeline.router.history.readers
        assert pipeline.backends[ref.backend_id].transcripts is registry.transcripts
        assert pipeline.backends[ref.backend_id].metadata is registry.metadata
        assert pipeline.backends[ref.backend_id].live_text is registry.live_text
        assert (await registry.snapshot(ref)).state == (
            ExecutionState.RUNNING if native_state == "running" else ExecutionState.IDLE
        )
        current, saved = await pipeline.creation.journal.load(e["identity"])
        assert (
            current.version == before_action.version
            and current.native_result == before_action.native_result
        )
        assert saved.revision == before_binding.revision and saved.dispatch_paused is paused
        assert [(d.id, d.payload_hash, d.state) for d in await rows(db, Delivery)] == notices_before
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
        await runtime.close()
        assert markers[-2:] == ["consumer-close", "native-close"]
        assert pipeline.scope.client.client.is_closed
    finally:
        if runtime is not None:
            await runtime.close()
        elif pipeline is not None:
            await pipeline.scope.client.close()
        await cleanup(e)


@pytest.mark.parametrize("failure", ["revoked", "replaced-origin"])
async def test_one_created_root_that_cannot_be_restored_waits_alone_and_bridge_starts(db, failure):
    # When one chat-created Root cannot be restored (for example after an OpenCode
    # plugin change), that Root alone stays unregistered and the Bridge still starts.
    from jt_oz_bridge.services.runtime import RuntimeWorker, SupervisedRuntime

    e = await setup(db)
    pipeline = runtime = None
    try:
        await e["service"].reconcile(e["identity"])
        pipeline, registry, factory, markers = await startup_pipeline(e)
        if failure == "revoked":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).values(active=False))
        else:
            e["state"]["info"]["metadata"] = {}
        graph = pipeline.runtime()

        async def worker():
            markers.append("worker-start")
            await asyncio.Event().wait()

        runtime = SupervisedRuntime(
            db, pipeline.fence, graph.resources, (RuntimeWorker("native-dispatch", worker),)
        )
        await runtime.start()
        ref = factory.selected(e["intent"])
        assert runtime.healthy and markers == ["native-start", "consumer-start", "worker-start"]
        assert ref not in registry.sessions
        assert pipeline.creation.unrestored_roots() == frozenset({ref})
        assert registry.sessions[e["anchor"].reference] is e["anchor"]
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
        assert (await e["journal"].load(e["identity"]))[0].state == "completed"
        if failure == "revoked":
            # Once the cause is gone, a GET-only retry restores the same Root.
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).values(active=True))
            pipeline.creation._retry_at.clear()
            await pipeline.creation.retry_restores()
            assert ref in registry.sessions and not pipeline.creation.unrestored_roots()
            assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
    finally:
        if runtime is not None:
            await runtime.close()
        elif pipeline is not None:
            await pipeline.scope.client.close()
        await cleanup(e)


async def test_a_cancelled_restore_still_stops_startup_and_closes_resources(db):
    from jt_oz_bridge.services.runtime import RuntimeWorker, SupervisedRuntime

    e = await setup(db)
    pipeline = runtime = None
    try:
        await e["service"].reconcile(e["identity"])
        pipeline, registry, factory, markers = await startup_pipeline(e)

        def cancel_native_read(request):
            if request.url.path == "/api/session/" + e["intent"].native_session_id:
                raise asyncio.CancelledError

        e["state"]["on_get"] = cancel_native_read
        graph = pipeline.runtime()

        async def worker():
            markers.append("worker-start")
            await asyncio.Event().wait()

        runtime = SupervisedRuntime(
            db, pipeline.fence, graph.resources, (RuntimeWorker("native-dispatch", worker),)
        )
        with pytest.raises(asyncio.CancelledError):
            await runtime.start()
        assert not runtime.healthy and markers == ["native-start", "native-close"]
        assert runtime.failure_detail.component == "session-restoration"
        assert pipeline.scope.client.client.is_closed
        assert factory.selected(e["intent"]) not in registry.sessions
        assert not e["writes"] and all(c.method == "GET" for c in e["calls"])
        assert (await e["journal"].load(e["identity"]))[0].state == "completed"
    finally:
        if runtime is not None:
            await runtime.close()
        elif pipeline is not None:
            await pipeline.scope.client.close()
        await cleanup(e)


@pytest.mark.parametrize(
    "change",
    [
        "static-backend",
        "missing-anchor-transcript",
        "missing-anchor-metadata",
        "copied-provider",
        "static-transcripts",
        "static-metadata",
        "static-live-text",
        "copied-view",
        "other-provider",
        "other-pending",
        "other-models",
        "other-results",
        "source",
        "replies",
        "fence",
        "none",
    ],
)
async def test_pipeline_rejects_creation_composition_without_original_dynamic_objects(db, change):
    e = await setup(db)
    try:
        with pytest.raises(ValueError):
            await startup_pipeline(e, change=change)
        assert not e["writes"]
        assert (await e["journal"].load(e["identity"]))[0].state == "admitted"
    finally:
        await cleanup(e)
