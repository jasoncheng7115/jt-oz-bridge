"""Original typed Native graphs with synthetic GET peers, not live qualification."""

import asyncio
import copy
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from jt_oz_bridge.adapters.opencode.creation_policy import CreationPolicyTemplate, V2CreationPolicy
from jt_oz_bridge.adapters.opencode.model_catalog import READS as MODEL_READS
from jt_oz_bridge.adapters.opencode.native_metadata import V2NativeMetadataReader
from jt_oz_bridge.adapters.opencode.session_creation import V2SessionCreation
from jt_oz_bridge.adapters.opencode.transcript import V2TranscriptReader
from jt_oz_bridge.adapters.opencode.turn_resources import (
    RESOURCE_SEMANTICS,
    RESOURCE_TYPES,
    ResourceSemanticAttestation,
    V2TurnResourceReader,
)
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.domain.session_creation import RootCreationTemplate, SessionCreationIntent
from jt_oz_bridge.services.created_root_factory import V2CreatedRootFactory
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as policy_setup
from tests.contract.test_public_live_feed import REAL
from tests.contract.test_v2_catalog import native


async def setup(*, make_intent=None, permissions=(), reads=None):
    p, t, d, g, execution, _, writes = await policy_setup()
    epoch = (await p.feed.current_owner()).owner_epoch
    p.feed.owner.read.side_effect = lambda: SimpleNamespace(
        owner_epoch=epoch,
        backend_id=REF.backend_id,
        backend_identity=REF.backend_identity,
        version="2.0.32",
        observed_at=time.time(),
        model_dump=lambda **kw: {"owner_epoch": epoch},
    )
    t.attestation = replace(
        t.attestation,
        verified_operations=t.attestation.verified_operations | {"session.create"} | MODEL_READS,
    )
    creation = RootCreationTemplate(
        scope=ProjectScope(**REF.model_dump(exclude={"upstream_session_id"})),
        native_project_id="global",
        agent_id="build",
        permissions=permissions,
    )
    policies = V2CreationPolicy(
        g,
        CreationPolicyTemplate(
            format="native-root-creation-policy-v1",
            source=g.enrollments[REF],
            creation=creation,
            operations=frozenset({"prompt"}),
        ),
    )
    creator = V2SessionCreation(t, p.feed.owner, {REF.project_id: creation})
    intent = (
        await make_intent(creator, policies, epoch)
        if make_intent
        else SessionCreationIntent(
            intent_id="a" * 32,
            scope=creation.scope,
            native_session_id="ses_jtoz_" + "b" * 32,
            source_sha256="c" * 64,
            owner_epoch=epoch,
            title="Synthetic new Root",
        )
    )
    body = creator.body(intent)
    row = native(
        id=intent.native_session_id,
        projectID="global",
        location=body["location"],
        agent=body["agent"],
        permissions=body["permissions"],
        metadata=body["metadata"],
        title=intent.title,
        time={"created": 100, "updated": 100},
    )
    state = {
        "info": row,
        "messages": [],
        "permissions": [],
        "forms": [],
        "inbox": [],
        "children": [],
    }
    original = t.client._transport
    calls = []

    def handle(request):
        assert request.method == "GET"  # The factory never creates or prompts.
        calls.append(request)
        if state.get("on_get") is not None:
            state["on_get"](request)
        path = request.url.path
        if path == "/api/session/" + intent.native_session_id:
            return httpx.Response(200, json={"data": copy.deepcopy(state["info"])})
        prefix = "/api/session/" + intent.native_session_id + "/"
        if path.startswith(prefix):
            suffix = path.removeprefix(prefix)
            key = {
                "message": "messages",
                "permission": "permissions",
                "form": "forms",
                "inbox": "inbox",
            }[suffix]
            result = {"data": copy.deepcopy(state[key])}
            if key == "messages":
                result["cursor"] = {}
            return httpx.Response(200, json=result)
        if (
            path == "/api/session"
            and request.url.params.get("parentID") == intent.native_session_id
        ):
            return httpx.Response(
                200, json={"data": copy.deepcopy(state["children"]), "cursor": {}}
            )
        return original.handler(request)

    t.client._transport = httpx.MockTransport(handle)
    semantics = ResourceSemanticAttestation(
        REF.backend_id,
        REF.backend_identity,
        t.profile.sha256,
        RESOURCE_SEMANTICS,
        "e" * 64,
        RESOURCE_TYPES,
        frozenset({"succeeded", "failed", "interrupted"}),
    )
    reader = V2TurnResourceReader(execution, attestation=semantics)
    anchor = RegisteredSession(
        REF,
        t.profile.sha256,
        execution,
        execution.models,
        reader,
        AsyncMock(return_value=()),
        transcript=V2TranscriptReader(reader),
        metadata=V2NativeMetadataReader(execution, REF),
    )
    registry = SessionRegistry({REF: anchor})
    factory = V2CreatedRootFactory(
        creator, policies, registry, **(reads(execution, t, g) if reads else {})
    )
    candidate = await creator.observe(intent)
    return p, t, d, factory, intent, candidate, state, calls, writes, anchor


async def test_pristine_factory_appends_complete_original_graph_without_reconnecting_or_mutating():
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        index = p.feed.index
        task = p.feed.task
        epoch = p.generation(REF)
        old_fence = p.fence(REF)
        entry = await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        ref = entry.reference
        assert p.feed.index is index and p.feed.task is task and p.generation(REF) == epoch
        assert p.fence(REF) == old_fence and f.registry.sessions[REF] is anchor
        assert f.registry.sessions[ref] is entry and set(f.registry.sessions) == {REF, ref}
        assert entry.execution.transport is t and entry.execution.proofs.feed is p.feed
        assert entry.results.client is entry.execution and entry.metadata.client is entry.execution
        assert entry.transcript.qualified is entry.results
        assert (await f.registry.snapshot(ref)).state == ExecutionState.IDLE
        assert await f.registry.pending(ref) == ()
        assert entry.execution.capabilities(ref)["prompt"].supported
        assert d["session.get"]["data"]["permissions"][0]["effect"] == "deny"
        assert entry.execution.scope_guard.enrollments[ref].reference == ref
        assert not writes and all(c.method == "GET" for c in calls)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("mode", ["idle", "running", "waiting", "waiting-input", "queued"])
async def test_used_root_restore_observes_original_work_and_returns_same_registration(mode):
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        state["info"].update(title="Changed after creation", cost=1.0)
        state["info"]["tokens"]["input"] = 100
        if mode == "idle":
            state["info"].update(outcome="succeeded")
            state["info"]["time"].update(updated=110, idle=110)
            state["messages"] = [
                {"id": "msg_idle", "type": "idle", "time": {"created": 110}, "outcome": "succeeded"}
            ]
        elif mode in {"running", "waiting", "waiting-input"}:
            d["session.active"]["data"][intent.native_session_id] = {"type": "running"}
            if mode == "waiting":
                permission = copy.deepcopy(
                    next(e["data"] for e in REAL if e["type"] == "permission.asked")
                )
                permission["sessionID"] = intent.native_session_id
                state["permissions"] = [permission]
            elif mode == "waiting-input":
                form = copy.deepcopy(
                    next(e["data"]["form"] for e in REAL if e["type"] == "form.created")
                )
                form["sessionID"] = intent.native_session_id
                state["forms"] = [form]
        else:
            state["inbox"] = [
                {
                    "id": "msg_wait",
                    "sessionID": intent.native_session_id,
                    "type": "user",
                    "payload": {"text": "queued synthetic input"},
                    "delivery": "queue",
                    "time": {"created": 101},
                }
            ]
        with pytest.raises(ValueError):
            await f.creator.observe(intent)
        entry = await f.register(
            intent, candidate, authorize=AsyncMock(return_value=True), restore=True
        )
        snapshot = await f.registry.snapshot(entry.reference)
        expected = {
            "idle": ExecutionState.IDLE,
            "running": ExecutionState.RUNNING,
            "waiting": ExecutionState.WAITING_PERMISSION,
            "waiting-input": ExecutionState.WAITING_INPUT,
            "queued": ExecutionState.QUEUED,
        }[mode]
        assert snapshot.state == expected and snapshot.title == "Changed after creation"
        assert (
            await f.register(
                intent, candidate, authorize=AsyncMock(return_value=True), restore=True
            )
            is entry
        )
        assert f.registry.sessions[REF] is anchor and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("answer", [False, None, 1, "yes"])
async def test_no_current_explicit_authority_never_enrolls_a_reference(answer):
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        before = tuple(p.feed.references)
        count = len(calls)
        with pytest.raises(ValueError):
            await f.register(intent, candidate, authorize=AsyncMock(return_value=answer))
        assert (
            tuple(p.feed.references) == before
            and len(calls) == count
            and set(f.registry.sessions) == {REF}
        )
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "origin",
        "created",
        "global-policy",
        "descendant",
        "copied-candidate",
        "foreign-project",
        "changed-template",
    ],
)
async def test_bad_origin_policy_or_authority_never_publishes_a_partial_registration(fault):
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        restore = False
        if fault == "origin":
            state["info"]["metadata"] = {}
            restore = True
        elif fault == "created":
            state["info"]["time"]["created"] += 1
            restore = True
        elif fault == "global-policy":
            d["mcp.list"]["data"] = []
        elif fault == "descendant":
            state["children"] = [native(id="ses_child")]
        elif fault == "copied-candidate":
            candidate = candidate.model_copy()
        elif fault == "foreign-project":
            intent = intent.model_copy(
                update={
                    "scope": intent.scope.model_copy(update={"canonical_directory": "/foreign"})
                }
            )
        else:
            f.policies.template = f.policies.template.model_copy(
                update={"operations": frozenset({"interrupt"})}
            )
        with pytest.raises(ValueError):
            await f.register(
                intent, candidate, authorize=AsyncMock(return_value=True), restore=restore
            )
        assert (
            set(f.registry.sessions) == {REF} and f.registry.sessions[REF] is anchor and not writes
        )
    finally:
        await finish(p, t)


async def test_concurrent_registration_is_idempotent_and_never_replaces_originals():
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        entries = await asyncio.gather(
            *(
                f.register(intent, candidate, authorize=AsyncMock(return_value=True))
                for _ in range(2)
            )
        )
        assert entries[0] is entries[1] and len(f.registry.sessions) == 2 and not writes
    finally:
        await finish(p, t)


async def test_restart_restores_used_root_from_owned_historical_data_without_a_new_create():
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    historical = candidate.model_dump(mode="json")
    worked = copy.deepcopy(state["info"])
    worked.update(cost=2, title="Work after creation")
    await finish(p, t)
    p, t, d, f, intent, unused, state, calls, writes, anchor = await setup()
    try:
        state["info"] = worked
        d["session.active"]["data"][intent.native_session_id] = {"type": "running"}
        receipt = type(unused).model_validate(historical)
        assert not await f.creator.current(intent, receipt)
        entry = await f.register(
            intent, receipt, authorize=AsyncMock(return_value=True), restore=True
        )
        assert entry.reference.upstream_session_id == historical["reference"]["upstream_session_id"]
        assert (await f.registry.snapshot(entry.reference)).state == ExecutionState.RUNNING
        assert not writes and all(r.method == "GET" for r in calls)
    finally:
        await finish(p, t)


async def test_revocation_after_feed_scope_append_keeps_registry_inert_then_retries_safely():
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        allowed = True

        async def authorize():
            return allowed

        def on_get(request):
            nonlocal allowed
            if request.url.path.endswith("/" + intent.native_session_id + "/permission"):
                allowed = False

        state["on_get"] = on_get
        with pytest.raises(ValueError):
            await f.register(intent, candidate, authorize=authorize)
        assert len(p.feed.references) == 2 and set(f.registry.sessions) == {REF}
        assert p.feed.task is not None and not p.feed.task.done()
        allowed = True
        state.pop("on_get")
        entry = await f.register(intent, candidate, authorize=authorize)
        assert f.registry.sessions[entry.reference] is entry and len(p.feed.references) == 2
        assert f.registry.sessions[REF] is anchor and not writes
    finally:
        await finish(p, t)


async def test_cancelled_registration_does_not_close_original_feed_or_publish_partial_readers():
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    entered, blocked = asyncio.Event(), asyncio.Event()
    task = None
    try:

        async def authorize():
            if len(p.feed.references) > 1:
                entered.set()
                await blocked.wait()
            return True

        task = asyncio.create_task(f.register(intent, candidate, authorize=authorize))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert set(f.registry.sessions) == {REF} and f.registry.sessions[REF] is anchor
        assert p.feed.task is not None and not p.feed.task.done()
        blocked.set()
        entry = await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        assert f.registry.sessions[entry.reference] is entry and not writes
    finally:
        blocked.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await finish(p, t)


async def test_second_factory_cannot_replace_an_already_registered_root():
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        entry = await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        other = V2CreatedRootFactory(f.creator, f.policies, f.registry)
        with pytest.raises(ValueError):
            await other.register(
                intent, candidate, authorize=AsyncMock(return_value=True), restore=True
            )
        assert f.registry.sessions[entry.reference] is entry and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault", ["creator-owner", "policy-proof", "source-entry", "semantics", "project-template"]
)
async def test_factory_rejects_a_changed_original_graph(fault):
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        if fault == "creator-owner":
            f.creator.owner = SimpleNamespace()
        elif fault == "policy-proof":
            f.policies.anchor.proofs = copy.copy(p)
        elif fault == "source-entry":
            f.registry = SessionRegistry({REF: replace(anchor)})
            assert f.anchor is anchor
            assert f.registry.sessions[REF] is not anchor
        elif fault == "semantics":
            anchor.results.attestation = replace(anchor.results.attestation)
        else:
            f.creator.templates = {
                REF.project_id: f.creator.templates[REF.project_id].model_copy(
                    update={"agent_id": "other"}
                )
            }
        with pytest.raises(ValueError):
            await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        assert len(f.registry.sessions) == 1 and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("mode", ["queued", "running", "waiting"])
async def test_pristine_registration_requires_positive_idle_when_zero_usage_info_still_matches(
    mode,
):
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        if mode == "queued":
            state["inbox"] = [
                {
                    "id": "msg_new_queue",
                    "sessionID": intent.native_session_id,
                    "type": "user",
                    "payload": {"text": "synthetic pending input"},
                    "delivery": "queue",
                    "time": {"created": 101},
                }
            ]
        else:
            d["session.active"]["data"][intent.native_session_id] = {"type": "running"}
            if mode == "waiting":
                permission = copy.deepcopy(
                    next(e["data"] for e in REAL if e["type"] == "permission.asked")
                )
                permission["sessionID"] = intent.native_session_id
                state["permissions"] = [permission]
        assert await f.creator.current(intent, candidate)  # Native info alone is unchanged.
        with pytest.raises(ValueError):
            await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        assert set(f.registry.sessions) == {REF} and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("existing", [False, True])
async def test_registration_cannot_publish_after_authority_await_invalidates_its_resource_fence(
    monkeypatch,
    existing,
):
    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient

    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    if existing:
        await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
    captured = False
    original = V2ExecutionClient.qualified_snapshot

    async def snapshot(client, ref):
        nonlocal captured
        result = await original(client, ref)
        if ref == candidate.reference:
            captured = True
        return result

    monkeypatch.setattr(V2ExecutionClient, "qualified_snapshot", snapshot)

    async def authorize():
        if captured:
            index = p.feed.index
            sid = intent.native_session_id
            index._arrival_revisions[sid] = index._arrival_revisions.get(sid, 0) + 1
        return True

    try:
        with pytest.raises(ValueError):
            await f.register(intent, candidate, authorize=authorize, restore=existing)
        assert set(f.registry.sessions) == ({REF, candidate.reference} if existing else {REF})
        assert not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("mode", ["queued", "running"])
async def test_repeated_pristine_registration_requires_explicit_recovery_after_work_arrives(mode):
    p, t, d, f, intent, candidate, state, calls, writes, anchor = await setup()
    try:
        entry = await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        if mode == "running":
            d["session.active"]["data"][intent.native_session_id] = {"type": "running"}
        else:
            state["inbox"] = [
                {
                    "id": "msg_later_queue",
                    "sessionID": intent.native_session_id,
                    "type": "user",
                    "payload": {"text": "later input"},
                    "delivery": "queue",
                    "time": {"created": 101},
                }
            ]
        assert await f.creator.current(intent, candidate)
        with pytest.raises(ValueError):
            await f.register(intent, candidate, authorize=AsyncMock(return_value=True))
        assert f.registry.sessions[candidate.reference] is entry
        assert (
            await f.register(
                intent, candidate, authorize=AsyncMock(return_value=True), restore=True
            )
            is entry
        )
        assert not writes
    finally:
        await finish(p, t)


async def staged_graph(db, *, child=False, reverse_nodes=False, **options):
    """Actual typed GET peers/Cell/SQL metadata only; no Business ledger authority."""
    from dataclasses import asdict

    from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
    from jt_oz_bridge.adapters.opencode.existing_session_graph import V2ExistingSessionGraphObserver
    from jt_oz_bridge.adapters.opencode.existing_sessions import (
        ExistingSessionProtocol,
        V2ExistingSessionObserver,
    )
    from jt_oz_bridge.adapters.opencode.graph_generation import (
        GraphResourceContext,
        attach_graph_generation,
    )
    from jt_oz_bridge.adapters.opencode.lineage_policy import V2LineagePolicyGuard
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LINEAGE_SEMANTICS,
        LineageResourceAttestation,
        V2LineageResourceProofs,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import POLICY_READS, V2ProjectPolicyGuard
    from jt_oz_bridge.adapters.opencode.resources import READS, V2LeafResourceProofs
    from jt_oz_bridge.domain.session_adoption import OriginalSessionNode, SessionAdoptionRecord
    from jt_oz_bridge.services.session_registration_journal import SessionRegistrationJournal
    from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
    from jt_oz_bridge.storage.durable import DurableStore, digest
    from jt_oz_bridge.storage.fencing import ConsumerFence

    graph = await setup(**options)
    p, t, d, factory, intent, receipt, state, calls, writes, anchor = graph
    root = receipt.reference
    if child:
        child_ref = root.model_copy(update={"upstream_session_id": "ses_stage_child"})
        row = copy.deepcopy(state["info"])
        row.update(
            id=child_ref.upstream_session_id, parentID=root.upstream_session_id, agent="task"
        )
        row["time"] = {"created": 101, "updated": 101}
        state["children"] = [row]
        original = t.client._transport

        def peer(request):
            assert request.method == "GET"
            if request.url.path == "/api/agent/task":
                agent = copy.deepcopy(d["agent.get"])
                agent["data"].update(id="task", mode="subagent")
                return httpx.Response(200, json=agent)
            if request.url.path == "/api/session/" + child_ref.upstream_session_id:
                return httpx.Response(200, json={"data": copy.deepcopy(row)})
            if (
                request.url.path == "/api/session"
                and request.url.params.get("parentID") == child_ref.upstream_session_id
            ):
                return httpx.Response(200, json={"data": [], "cursor": {}})
            if request.url.path.startswith("/api/session/" + child_ref.upstream_session_id + "/"):
                return httpx.Response(
                    200,
                    json={
                        "data": [],
                        **({"cursor": {}} if request.url.path.endswith("/message") else {}),
                    },
                )
            return original.handler(request)

        t.client._transport = httpx.MockTransport(peer)
    lineage = LineageResourceAttestation(
        REF.backend_id, REF.backend_identity, t.profile.sha256, LINEAGE_SEMANTICS, "e" * 64, READS
    )
    stage = await factory.prepare_restore(
        intent, receipt, authorize=AsyncMock(return_value=True), lineage=lineage
    )
    observer = V2ExistingSessionGraphObserver(
        V2ExistingSessionObserver(
            factory.policies.anchor,
            ExistingSessionProtocol(
                REF.backend_id,
                REF.backend_identity,
                t.profile.sha256,
                "e" * 64,
                POLICY_READS | {"session.list"},
            ),
            REF,
        )
    )
    observation = await observer.observe(root, authorize=AsyncMock(return_value=True))
    for node in observation.nodes:
        await factory.feed.enroll_reference(node.reference, authorize=AsyncMock(return_value=True))
    policies = {
        node.reference: (
            stage.policy
            if node.reference == root
            else stage.policy.model_copy(
                update={
                    "reference": node.reference,
                    "fingerprint_sha256": node.policy_sha256,
                    "operations": frozenset({"form.reply"}),
                }
            )
        )
        for node in observation.nodes
    }
    proofs = V2LineageResourceProofs(
        factory.feed, p.projects, observation, lineage, current=observer.current
    )
    guard = V2LineagePolicyGuard(proofs, policies)
    await proofs.watch_graph(authorize=AsyncMock(return_value=True))
    execution = V2ExecutionClient(t, p.projects, proofs=proofs, scope_guard=guard)
    for node in observation.nodes:
        await execution.qualified_snapshot(node.reference)
    nodes = tuple(
        OriginalSessionNode.model_validate(
            node.model_dump(
                include={
                    "reference",
                    "native_created_at",
                    "parent_reference",
                    "parent_created_at",
                    "policy_sha256",
                }
            )
        )
        for node in observation.nodes
    )
    record = SessionAdoptionRecord(
        root=root,
        native_project_id="global",
        contract_sha256=t.profile.sha256,
        qualification_sha256=digest(asdict(lineage) | {"operations": sorted(lineage.operations)}),
        graph_sha256=observation.graph_sha256,
        nodes=tuple(reversed(nodes)) if reverse_nodes else nodes,
        observed_owner_epoch=observation.owner_epoch,
        observed_at=observation.observed_at,
    )
    context = GraphResourceContext(proofs, guard, record)
    # Real child facades are assembled by this synthetic controller fixture;
    # the factory stages only the original created Root.
    entries = {root: stage.entry}
    for node in observation.nodes:
        if node.reference != root:
            leaf = V2LeafResourceProofs(factory.feed, p.projects)
            child_guard = V2ProjectPolicyGuard(leaf, policies)
            child_execution = V2ExecutionClient(t, p.projects, proofs=leaf, scope_guard=child_guard)
            child_reader = V2TurnResourceReader(
                child_execution, attestation=anchor.results.attestation
            )
            child_reader.qualify(node.reference)
            attach_graph_generation(leaf, child_guard, factory.registry.publication, root, lineage)
            entries[node.reference] = RegisteredSession(
                node.reference,
                t.profile.sha256,
                child_execution,
                child_execution.models,
                child_reader,
                AsyncMock(return_value=()),
                transcript=V2TranscriptReader(child_reader),
                metadata=V2NativeMetadataReader(child_execution, node.reference),
            )
    prepared = factory.registry.prepare_generation(
        record, entries, expected=None, enrollments=policies, context=context
    )
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=REF.backend_id,
                identity=REF.backend_identity,
                contract_hash=t.profile.sha256,
                version="synthetic",
                enabled=True,
                verified=True,
            )
        )
        session.add(
            EnrolledProject(
                id=REF.project_id,
                backend_id=REF.backend_id,
                realm_id="realm",
                canonical_directory=REF.canonical_directory,
                enabled=True,
            )
        )
    holder = "synthetic-stage-metadata"
    fence = await DurableStore(db).acquire_lease(holder, ttl=120)
    journal = SessionRegistrationJournal(db, ConsumerFence(holder, fence))

    async def locked(session):
        await journal.fence.lock(session)  # Internal metadata fixture, not Human ACL proof.

    durable = await journal.prepare(
        "realm",
        record,
        lock_authority=locked,
        current=lambda: all(proofs.current_proof(n.reference) is not None for n in record.nodes),
    )
    candidate = factory.registry.bind_receipt(prepared, durable)
    return graph, stage, candidate, context, journal


@pytest.mark.parametrize("reverse_nodes", [False, True])
async def test_created_restore_stage_public_cell_record_copy_publishes_exact_originals(
    db, reverse_nodes
):
    graph, stage, candidate, context, journal = await staged_graph(
        db, child=True, reverse_nodes=reverse_nodes
    )
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    try:
        before = f.registry.publication.snapshot()
        assert stage.entry.reference not in f.registry.sessions and not f._records
        assert (
            candidate.generation.record == context.record
            and candidate.generation.record is not context.record
        )
        entry = f.publish_restore(stage, candidate)
        assert f.registry.sessions[entry.reference] is entry and f.registry.sessions[REF] is anchor
        assert (
            f._records[entry.reference].entry is entry
            and f.registry.publication.snapshot() is not before
        )
        assert candidate.generation.enrollments[entry.reference] is stage.policy
        assert stage.policy.operations == frozenset({"prompt"}) and not writes
    finally:
        await finish(p, t)


async def test_created_restore_stage_rechecks_earliest_deadline_after_proof_loop(db, monkeypatch):
    from jt_oz_bridge.services import created_root_factory as module

    graph, stage, candidate, context, journal = await staged_graph(db)
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    try:
        expiry = f._restore_stages[stage].expires_at
        clock = [expiry - 0.01]
        monkeypatch.setattr(module, "time", SimpleNamespace(time=lambda: clock[0]))
        original = context.proofs.current_proof

        def proof(ref):
            result = original(ref)
            assert result is not None  # Actual Native proof remains live on its real clock.
            clock[0] = expiry + 0.01
            return result

        context.proofs.current_proof = proof
        before = f.registry.publication.snapshot()
        with pytest.raises(ValueError):
            f.publish_restore(stage, candidate)
        assert f.registry.publication.snapshot() is before and not f._records and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["assembly", "base"])
async def test_created_restore_rechecks_stage_and_base_after_native_proof_loop(
    db, monkeypatch, fault
):
    graph, stage, candidate, context, journal = await staged_graph(db)
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    before = f.registry.publication.snapshot()
    original = context.proofs.current_proof
    try:

        def proof(ref):
            result = original(ref)
            assert result is not None
            if fault == "assembly":
                stage.entry.execution.models = copy.copy(stage.entry.execution.models)
            else:
                # Identity drift after a real Native proof, not a replacement graph.
                monkeypatch.setattr(f.registry.publication, "_state", copy.copy(before))
            return result

        context.proofs.current_proof = proof
        with pytest.raises(ValueError):
            f.publish_restore(stage, candidate)
        assert not f._records and stage.entry.reference not in f.registry.sessions and not writes
        assert all(ref == REF for ref in f.registry.sessions)
    finally:
        await finish(p, t)


@pytest.mark.parametrize("fault", ["models", "metadata", "results_proofs", "attachments"])
async def test_created_restore_stage_rejects_mutated_reader_assembly_before_publish(db, fault):
    graph, stage, candidate, context, journal = await staged_graph(db)
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    try:
        entry = stage.entry
        if fault == "models":
            entry.execution.models = copy.copy(entry.execution.models)
        elif fault == "metadata":
            entry.metadata.client = copy.copy(entry.execution)
        elif fault == "results_proofs":
            entry.results.proofs = copy.copy(entry.execution.proofs)
        else:
            entry.results.attachments = object()
        with pytest.raises(ValueError):
            f.require_restore(stage)
        assert entry.reference not in f.registry.sessions and not f._records and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault",
    [
        "copy",
        "replace",
        "cross_task",
        "expired",
        "early_base",
        "transport",
        "guard",
        "transcript",
        "pending",
        "workspace_attachments",
    ],
)
async def test_created_restore_stage_sealed_issuer_task_and_assembly_refuse_drift(
    db, monkeypatch, fault
):
    from jt_oz_bridge.services import created_root_factory as module

    graph, stage, candidate, context, journal = await staged_graph(db)
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    before = f.registry.publication.snapshot()
    try:
        selected = stage
        if fault == "copy":
            selected = copy.copy(stage)
        elif fault == "replace":
            selected = replace(stage)
        elif fault == "cross_task":

            async def other():
                with pytest.raises(ValueError):
                    f.require_restore(stage)

            await asyncio.create_task(other())
            f.require_restore(stage)  # Same original task remains valid.
            return
        elif fault == "expired":
            monkeypatch.setattr(
                module, "time", SimpleNamespace(time=lambda: f._restore_stages[stage].expires_at)
            )
        elif fault == "early_base":
            # Controlled pointer-corruption negative, not a fabricated Native graph.
            monkeypatch.setattr(f.registry.publication, "_state", copy.copy(before))
        elif fault == "transport":
            stage.entry.execution.transport = copy.copy(t)
        elif fault == "guard":
            stage.entry.execution.scope_guard = copy.copy(stage.entry.execution.scope_guard)
        elif fault == "transcript":
            stage.entry.transcript.client = copy.copy(stage.entry.execution)
        elif fault == "pending":
            object.__setattr__(stage.entry, "pending", AsyncMock(return_value=()))
        else:
            stage.entry.execution.workspace_attachments = object()
        with pytest.raises(ValueError):
            f.require_restore(selected)
        assert not f._records and stage.entry.reference not in f.registry.sessions and not writes
    finally:
        await finish(p, t)


async def test_created_restore_publishes_once_and_normal_recovery_keeps_exact_record(db):
    graph, stage, candidate, context, journal = await staged_graph(db, child=True)
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    try:
        entry = f.publish_restore(stage, candidate)
        published = f.registry.publication.snapshot()
        for invoke in (
            lambda: f.require_restore(stage),
            lambda: f.publish_restore(stage, candidate),
        ):
            with pytest.raises(ValueError):
                invoke()
        again = await f.register(
            intent, receipt, authorize=AsyncMock(return_value=True), restore=True
        )
        assert again is entry and f.registry.publication.snapshot() is published
        f.registered(intent, receipt, entry)
        for ref in candidate.generation.entries:
            assert (await f.registry.snapshot(ref)).reconciled
        assert f.registry.sessions[REF] is anchor and not writes
    finally:
        await finish(p, t)


@pytest.mark.parametrize(
    "fault", ["missing", "leaf", "backend", "schema", "semantics", "evidence", "operations"]
)
async def test_created_restore_unqualified_tree_fails_before_any_native_get(fault):
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LINEAGE_SEMANTICS,
        LineageResourceAttestation,
    )
    from jt_oz_bridge.adapters.opencode.resources import READS

    p, t, d, f, intent, receipt, state, calls, writes, anchor = await setup()
    try:
        lineage = LineageResourceAttestation(
            REF.backend_id,
            REF.backend_identity,
            t.profile.sha256,
            LINEAGE_SEMANTICS,
            "e" * 64,
            READS,
        )
        fields = {
            "leaf": {"qualification_scope": "leaf"},
            "backend": {"backend_identity": "foreign"},
            "schema": {"contract_sha256": "f" * 64},
            "semantics": {"semantics": "foreign"},
            "evidence": {"installed_evidence_sha256": "no"},
            "operations": {"operations": frozenset()},
        }
        selected = None if fault == "missing" else replace(lineage, **fields[fault])
        calls.clear()
        with pytest.raises(ValueError):
            await f.prepare_restore(
                intent, receipt, authorize=AsyncMock(return_value=True), lineage=selected
            )
        assert not calls and not writes and not f._records and set(f.registry.sessions) == {REF}
    finally:
        await finish(p, t)


@pytest.mark.parametrize("scope", ["session", "backend"])
async def test_created_restore_preserves_original_model_codec_qualification(scope):
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LINEAGE_SEMANTICS,
        LineageResourceAttestation,
    )
    from jt_oz_bridge.adapters.opencode.model_settings import (
        MODEL_SETTING_SEMANTICS,
        ModelSettingsAttestation,
    )
    from jt_oz_bridge.adapters.opencode.resources import READS

    p, t, d, f, intent, receipt, state, calls, writes, anchor = await setup()
    try:
        settings = ModelSettingsAttestation(
            REF, t.profile.sha256, MODEL_SETTING_SEMANTICS, "b" * 64, qualification_scope=scope
        )
        p.model_settings = settings
        factory = V2CreatedRootFactory(f.creator, f.policies, f.registry)
        lineage = LineageResourceAttestation(
            REF.backend_id,
            REF.backend_identity,
            t.profile.sha256,
            LINEAGE_SEMANTICS,
            "e" * 64,
            READS,
        )
        if scope == "session":
            with pytest.raises(ValueError):
                await factory.prepare_restore(
                    intent, receipt, authorize=AsyncMock(return_value=True), lineage=lineage
                )
        else:
            stage = await factory.prepare_restore(
                intent, receipt, authorize=AsyncMock(return_value=True), lineage=lineage
            )
            assert stage.entry.execution.proofs.model_settings is settings
            assert stage.policy.operations == frozenset({"prompt"})
            factory.require_restore(stage)
        assert not factory._records and set(factory.registry.sessions) == {REF} and not writes
    finally:
        await finish(p, t)


async def test_created_restore_sql_prepared_cancel_keeps_real_head_without_partial_root(db):
    graph, stage, candidate, context, journal = await staged_graph(db)
    p, t, d, f, intent, receipt, state, calls, writes, anchor = graph
    try:

        async def locked(session):
            await journal.fence.lock(session)

        # Genuine metadata SQL already committed. Cancel before memory publication.
        current = asyncio.current_task()
        current.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.sleep(0)
        saved = await journal.recovery_records(
            "realm", REF.project_id, lock_authority=locked, current=lambda: True
        )
        assert len(saved) == 1 and saved[0].state == "prepared"
        assert (
            saved[0].receipt == candidate.generation.receipt
            and saved[0].record == candidate.generation.record
        )
        again = await f.prepare_restore(
            intent,
            receipt,
            authorize=AsyncMock(return_value=True),
            lineage=context.proofs.lineage_attestation,
        )
        assert again is not stage and again.entry.reference == stage.entry.reference
        assert not f._records and set(f.registry.sessions) == {REF} and not writes
        # This reissues provenance only. Full saved-head graph recovery still
        # belongs to the future real activation/controller integration.
    finally:
        await finish(p, t)
