"""Short chat replies to requests of descendant sessions, end to end.

Real ownDB, real router/InteractionService/Dispatcher/SessionRegistry and
synthetic Zulip HTTP. Registered execution peers are domain fixtures, not
installed lineage evidence. No Native session, Human source, upstream approval
or formal acceptance is produced.
"""

import copy
import json
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.existing_session_graph import MAX_GRAPH_DEPTH
from jt_oz_bridge.adapters.zulip.client import ZulipError
from jt_oz_bridge.domain.control import Choice, InteractionSnapshot, QuestionField
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.interactions import InteractionService, short_code
from jt_oz_bridge.storage.control_models import PendingInteraction
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_replies import REPLY_OPERATIONS
from tests.contract.test_lineage_resources import TARGET
from tests.contract.test_public_live_feed import REAL
from tests.integration.test_consumer_runtime import rows, visible
from tests.integration.test_descendant_pending_notices import (
    CHILD,
    GRANDCHILD,
    deliver_all,
    tree_pipeline,
)
from tests.integration.test_router import message as router_message
from tests.integration.test_session_adoption import setup as adoption_setup
from tests.support import REF


def permission(reference, identity="per_shared"):
    return InteractionSnapshot(
        reference=reference,
        upstream_request_id=identity,
        generation="source:1",
        kind="permission",
        pending=True,
        description="Run approved project checks",
        operation="shell.execute",
        resources=("pytest -q",),
    )


def question(reference, identity="que_shared"):
    return InteractionSnapshot(
        reference=reference,
        upstream_request_id=identity,
        generation="source:1",
        kind="form",
        pending=True,
        description="Which branch?",
        fields=(
            QuestionField(
                id="branch",
                label="Which branch?",
                kind="single",
                choices=(Choice(id="main", label="main"), Choice(id="dev", label="dev")),
            ),
        ),
    )


async def announce(pipeline, db, nodes, *requests, start=True):
    for value in requests:
        nodes[value.reference].add_request(value)
    await pipeline.pending_notices_once()
    saved = {
        InteractionSnapshot.model_validate(row.snapshot).reference: row
        for row in await rows(db, PendingInteraction)
    }
    await deliver_all(pipeline, db)
    if start:
        await pipeline.consumer.start()
    return saved


async def say(pipeline, server, text, mid, author=7):
    server.input(text, mid, author)
    await pipeline.consumer.poll()


def sent(nodes):
    return {ref: list(native.submitted) for ref, native in nodes.items() if native.submitted}


@pytest.mark.parametrize("target", [CHILD, GRANDCHILD])
@pytest.mark.parametrize(("command", "decision"), [("!ok", "once"), ("!no", "reject")])
async def test_quick_permission_reply_reaches_only_the_requesting_descendant(
    db, target, command, decision
):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, binding, _calls = env
        # The same Native request ID on the Root and the descendant stays separate.
        saved = await announce(pipeline, db, nodes, permission(REF), permission(target))
        code = short_code(saved[target].id)
        assert code != short_code(saved[REF].id)
        await say(pipeline, server, f"{command} {code}", 301)
        (action,) = await rows(db, Action)
        assert action.binding_id == binding.id and action.payload["decision"] == decision
        assert action.payload["reference"] == target.model_dump()
        await pipeline.dispatch_once()
        assert (await pipeline.dispatcher.load(action.id)).state == "completed"
        submitted = sent(nodes)
        assert list(submitted) == [target]
        ((reference, payload, _),) = submitted[target]
        assert reference == target and payload["request_id"] == "per_shared"
        assert payload["source"]["text"] == f"{command} {code}"
        states = {
            InteractionSnapshot.model_validate(row.snapshot).reference: row.state
            for row in await rows(db, PendingInteraction)
        }
        assert states == {REF: "pending", target: "resolved"}
        # The same reply again is a resolved request, not a second POST.
        await say(pipeline, server, f"{command} {code}", 302)
        await pipeline.dispatch_once()
        assert len(await rows(db, Action)) == 1 and len(nodes[target].submitted) == 1


@pytest.mark.parametrize(("answer", "chosen"), [("1", "main"), ("2", "dev")])
async def test_quick_answer_reaches_the_grandchild_form(db, answer, chosen):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, question(GRANDCHILD))
        code = short_code(saved[GRANDCHILD].id)
        notice = [visible(post["content"]) for post in server.posts]
        assert any(f"!a {code}" in body for body in notice)
        await say(pipeline, server, f"!a {code} {answer}", 301)
        (action,) = await rows(db, Action)
        assert action.payload["operation"] == "form.reply"
        assert action.payload["reference"] == GRANDCHILD.model_dump()
        await pipeline.dispatch_once()
        ((reference, payload, _),) = sent(nodes)[GRANDCHILD]
        assert reference == GRANDCHILD and payload["request_id"] == "que_shared"
        assert payload["answers"]["branch"]["selected"] == [chosen]
        assert not sent(nodes).keys() - {GRANDCHILD}


async def test_desktop_buttons_name_the_requesting_descendant(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        nodes[CHILD].add_request(permission(CHILD))
        nodes[GRANDCHILD].add_request(question(GRANDCHILD))
        nodes[REF].add_request(permission(REF, "per_root"))
        await pipeline.pending_notices_once()
        deliveries = await deliver_all(pipeline, db)
        headings = {}
        for delivery in deliveries:
            widget = json.loads(delivery.payload["widget"])
            headings[delivery.dedupe_key] = widget["extra_data"]["heading"]
        named = [h for h in headings.values() if CHILD.upstream_session_id in h]
        assert len(named) == 1 and REF.upstream_session_id in named[0]
        assert len([h for h in headings.values() if GRANDCHILD.upstream_session_id in h]) == 1
        root_only = [h for h in headings.values() if "original-" not in h]
        assert len(root_only) == 1


@pytest.mark.parametrize("change", ["removed", "foreign_directory", "foreign_project"])
async def test_descendant_outside_the_current_lineage_cannot_be_answered(db, change):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, permission(GRANDCHILD))
        if change == "removed":
            nodes[REF].descendants = (CHILD,)
        else:
            field = "canonical_directory" if change == "foreign_directory" else "project_id"
            foreign = GRANDCHILD.model_copy(
                update={field: "/foreign" if field == "canonical_directory" else "foreign"}
            )
            nodes[REF].descendants = (CHILD, foreign)
        await say(pipeline, server, f"!ok {short_code(saved[GRANDCHILD].id)}", 301)
        await pipeline.dispatch_once()
        assert not await rows(db, Action) and not sent(nodes)


async def test_lineage_change_after_queueing_holds_the_reply_without_any_send(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, permission(GRANDCHILD))
        await say(pipeline, server, f"!ok {short_code(saved[GRANDCHILD].id)}", 301)
        (action,) = await rows(db, Action)
        nodes[REF].descendants = (CHILD,)
        await pipeline.dispatch_once()
        assert (await pipeline.dispatcher.load(action.id)).state in {"held", "rejected"}
        assert not sent(nodes)


async def test_request_answered_in_opencode_first_sends_nothing(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, permission(CHILD))
        nodes[CHILD].resolved = True
        await say(pipeline, server, f"!ok {short_code(saved[CHILD].id)}", 301)
        await pipeline.dispatch_once()
        assert not await rows(db, Action) and not sent(nodes)


async def test_request_answered_after_queueing_is_reconciled_not_sent(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, permission(CHILD))
        await say(pipeline, server, f"!no {short_code(saved[CHILD].id)}", 301)
        (action,) = await rows(db, Action)
        nodes[CHILD].resolved = True
        await pipeline.dispatch_once()
        assert (await pipeline.dispatcher.load(action.id)).state != "completed"
        assert not sent(nodes)
        (row,) = await rows(db, PendingInteraction)
        assert row.state == "resolved"


@pytest.mark.parametrize("change", ["revoked", "outsider", "public_channel"])
async def test_revoked_or_foreign_audience_cannot_answer_a_descendant(db, change):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, permission(GRANDCHILD))
        author = 7
        if change == "revoked":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        elif change == "outsider":
            author = 99
        else:
            server.private = False
        text = f"!ok {short_code(saved[GRANDCHILD].id)}"
        if change == "public_channel":
            with pytest.raises(ZulipError):
                await say(pipeline, server, text, 301, author)
        else:
            await say(pipeline, server, text, 301, author)
        await pipeline.dispatch_once()
        assert not await rows(db, Action) and not sent(nodes)


async def test_revocation_after_queueing_refuses_the_descendant_reply_before_send(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        saved = await announce(pipeline, db, nodes, permission(GRANDCHILD))
        await say(pipeline, server, f"!ok {short_code(saved[GRANDCHILD].id)}", 301)
        (action,) = await rows(db, Action)
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        await pipeline.dispatch_once()
        assert (await pipeline.dispatcher.load(action.id)).state == "rejected"
        assert not sent(nodes)


async def test_restart_between_descendant_notice_and_reply(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _registry, _binding, _calls = env
        # The first process announces, then stops before reading any reply.
        saved = await announce(pipeline, db, nodes, permission(GRANDCHILD), start=False)
        old = pipeline.fence
        await DurableStore(db).release_lease(old.holder, old.fencing)
        fencing = await DurableStore(db).acquire_lease("successor", ttl=120)
        successor = ConsumerPipeline(
            db,
            ConsumerFence("successor", fencing),
            pipeline.scope,
            dict(pipeline.backends),
            interval=0.02,
            delivery_interval=0,
        )
        # The restarted consumer neither announces the request again nor loses it.
        await successor.pending_notices_once()
        assert len(await rows(db, PendingInteraction)) == 1
        await successor.consumer.start()
        await say(successor, server, f"!ok {short_code(saved[GRANDCHILD].id)}", 301)
        (action,) = await rows(db, Action)
        await successor.dispatch_once()
        assert (await successor.dispatcher.load(action.id)).state == "completed"
        assert list(sent(nodes)) == [GRANDCHILD]


async def adopted(db):
    """An adopted original leaf Root, connected to the topic before any subagent exists."""
    controller, item, _audience, _source, factory, state, writes, anchor, t = await adoption_setup(
        db, leaf=True
    )
    t.attestation = replace(
        t.attestation, verified_operations=t.attestation.verified_operations | REPLY_OPERATIONS
    )
    posted = []
    inner = t.client._transport

    def handler(request):
        if request.method == "POST":
            posted.append(request.url.path)
            return httpx.Response(204)
        return inner.handler(request)

    t.client._transport = httpx.MockTransport(handler)
    async with db.sessions.begin() as session:
        for user in (7, 8):
            session.add(
                Grant(realm_id="realm", user_id=user, project_id=TARGET.project_id, role="approver")
            )
    await controller.adopt(item, TARGET)
    binding = await controller.bindings.bind("realm", 7, 10, "Original work", TARGET)
    return controller, factory, state, writes, anchor, t, binding, posted


def spawn(state, nested):
    """The Root's agent starts `nested` subagents, each one inside the previous."""
    tree, parent, chain = state["metadata_tree"], TARGET, []
    for index in range(1, nested + 1):
        node = TARGET.model_copy(update={"upstream_session_id": f"ses_subagent_{index}"})
        row = copy.deepcopy(tree["rows"][TARGET])
        row.update(id=node.upstream_session_id, parentID=parent.upstream_session_id, agent="task")
        row["time"]["created"] = 100 + index
        tree["rows"][node] = row
        tree["edges"].setdefault(parent, []).append(node)
        state["resources"][node] = copy.deepcopy(state["resources"][TARGET])
        state["active"][node.upstream_session_id] = {"type": "running"}
        chain.append(node)
        parent = node
    return chain


async def test_subagent_spawned_mid_turn_is_connected_then_its_permission_is_answered(db):
    controller, factory, state, writes, anchor, t, binding, posted = await adopted(db)
    try:
        chain = spawn(state, 2)
        leaf = chain[-1]
        raw = copy.deepcopy(next(e["data"] for e in REAL if e["type"] == "permission.asked"))
        raw["sessionID"] = leaf.upstream_session_id
        state["resources"][leaf]["permission"] = [raw]
        interactions = InteractionService(controller.bindings)
        with pytest.raises((Conflict, AccessDenied, ContractError, KeyError, ValueError)):
            snapshot = await controller.bindings.control.interaction(leaf, raw["id"])
            await interactions.observe(binding, snapshot)
        # The trusted GET-only maintenance connects the new original subagents.
        assert await controller.maintain_root(
            "realm",
            TARGET.project_id,
            TARGET,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        )
        root = await controller.bindings.control.snapshot(TARGET)
        assert set(root.descendants) == set(chain)
        snapshot = await controller.bindings.control.interaction(leaf, raw["id"])
        assert snapshot.reference == leaf and snapshot.pending
        identity = await interactions.observe(binding, snapshot)
        code = short_code(identity)
        token = await interactions.issue(identity, "realm", 7)
        source = router_message(f"!no {code}", 301)
        action_id = await interactions.reply(
            token, "realm", 7, decision="reject", source=source, code=code
        )
        (action,) = await rows(db, Action)
        assert action.id == action_id and action.payload["reference"] == leaf.model_dump()
        # The subagent keeps its own observed Native policy; nothing is copied or widened.
        generation = factory.registry.publication.generation(TARGET)
        node = next(n for n in generation.record.nodes if n.reference == leaf)
        assert generation.enrollments[leaf].fingerprint_sha256 == node.policy_sha256
        result = await factory.registry.submit(leaf, action.payload, action.id)
        assert result.status == "completed"
        assert posted == [f"/api/session/{leaf.upstream_session_id}/permission/{raw['id']}/reply"]
        assert not writes
    finally:
        await finish(anchor, t)


async def test_subagent_nesting_beyond_the_bound_is_never_connected(db):
    controller, factory, state, writes, anchor, t, _binding, posted = await adopted(db)
    try:
        chain = spawn(state, MAX_GRAPH_DEPTH + 1)
        with pytest.raises(ContractError, match="depth_exceeded"):
            await controller.maintain_root(
                "realm",
                TARGET.project_id,
                TARGET,
                authorize=AsyncMock(return_value=True),
                lock_authority=AsyncMock(),
            )
        assert not any(node in factory.registry.sessions for node in chain)
        assert not posted and not writes
    finally:
        await finish(anchor, t)
