"""Real SQL dispatcher, leaf proofs and project policy guard over a synthetic Native.

The Native double reproduces the readback that follows a declined permission.
It is not live Native, Human or mobile evidence.
"""

import copy
import json
from dataclasses import replace

import httpx

from jt_oz_bridge.adapters.opencode.project_policy import V2ProjectPolicyGuard
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.dispatch import Dispatcher
from jt_oz_bridge.services.interactions import InteractionService, short_code
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import DurableStore
from jt_oz_bridge.storage.models import Grant
from tests.contract.test_aborted_turn_tail import installed, observed
from tests.contract.test_leaf_resources import REF, finish
from tests.contract.test_native_project_policy import setup as native_setup
from tests.contract.test_public_live_feed import REAL
from tests.integration.test_dispatch import SyntheticReader, message
from tests.support import SyntheticAudience


class DecliningNative:
    """One Root waiting on a permission; `reject` ends the turn without an idle."""

    def __init__(self, data):
        e = observed()
        head, user, idle, previous = e["messages_desc"]
        self.data, self.replies, self.prompts = data, [], []
        self.permission = copy.deepcopy(
            next(x for x in REAL if x["type"] == "permission.asked")["data"]
        )
        self.permission["sessionID"] = REF.upstream_session_id
        running = installed(head)
        running["time"] = {"created": head["time"]["created"]}
        del running["error"], running["finish"]
        self.messages = [
            running,
            installed(user, "synthetic rejected task"),
            installed(idle),
            installed(previous),
        ]
        self.declined = installed(head)
        info = data["session.get"]["data"]
        info["outcome"] = e["session"]["outcome"]
        info["time"].update(idle=e["session"]["time"]["idle"], updated=head["time"]["created"])
        data["session.active"]["data"][REF.upstream_session_id] = {"type": "running"}
        data["session.permission.list"]["data"] = [self.permission]

    def decline(self):
        # Exactly the observed resources: inactive, nothing pending, newest entry
        # the aborted step, retained idle and outcome from the previous turn.
        self.data["session.active"]["data"] = {}
        self.data["session.permission.list"]["data"] = []
        self.messages[0] = copy.deepcopy(self.declined)
        self.data["session.get"]["data"]["time"]["updated"] = self.declined["time"]["completed"]

    def page(self, request):
        limit = int(request.url.params["limit"])
        rows = self.messages[:limit]
        more = "older" if len(self.messages) > limit else None
        return httpx.Response(200, json={"data": rows, "cursor": {"next": more}})


async def worker(db):
    proofs, transport, data, _guard, client, _policy_calls, writes = await native_setup()
    transport.attestation = replace(
        transport.attestation,
        verified_operations=transport.attestation.verified_operations
        | {"session.permission.reply"},
    )
    native = DecliningNative(data)
    inner = transport.client._transport

    def handler(request):
        path = request.url.path
        if request.method == "GET" and path.endswith("/message"):
            return native.page(request)
        if request.method == "POST" and path.endswith("/reply"):
            native.replies.append(json.loads(request.content))
            native.decline()
            return httpx.Response(204)
        if request.method == "POST" and path.endswith("/prompt"):
            native.prompts.append(json.loads(request.content)["text"])
        return inner.handler(request)

    transport.client._transport = httpx.MockTransport(handler)
    await proofs.watch(REF)  # The replaced attestation needs a fresh original watch.
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=REF.backend_id,
                identity=REF.backend_identity,
                contract_hash=transport.profile.sha256,
                version="synthetic-fixture",
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
        for user in (7, 8):
            for role in ("operator", "approver", "administrator"):
                session.add(
                    Grant(realm_id="realm", user_id=user, project_id=REF.project_id, role=role)
                )
    bindings = BindingService(db, client, SyntheticAudience())
    binding = await bindings.bind("realm", 7, 10, "Original work", REF)
    reader = SyntheticReader()
    fencing = await DurableStore(db).acquire_lease("fixture-rejected-permission", ttl=30)
    assert fencing
    dispatcher = Dispatcher(bindings, client, reader, "fixture-rejected-permission", fencing)
    return dispatcher, binding, reader, native, writes, proofs, transport


async def test_human_no_then_a_new_prompt_in_the_topic_is_dispatched_to_the_original_root(db):
    dispatcher, binding, reader, native, writes, proofs, transport = await worker(db)
    try:
        assert type(dispatcher.client.scope_guard) is V2ProjectPolicyGuard  # The real guard.
        await proofs.watch(REF)
        snapshot = await dispatcher.client.interaction(REF, native.permission["id"])
        assert snapshot.pending and snapshot.kind == "permission"
        interactions = InteractionService(dispatcher.bindings)
        identity = await interactions.observe(binding, snapshot)
        code = short_code(identity)
        token = await interactions.issue(identity, "realm", 7)
        no = message(message_id=201, text="!no " + code, revision=0)
        reader.messages[no.message_id] = no
        reply = await interactions.reply(token, "realm", 7, decision="reject", source=no, code=code)
        assert await dispatcher.advance(reply) == "completed"
        assert native.replies == [{"decision": "reject"}]

        follow = message(message_id=202, text="Try a different way instead", revision=0)
        reader.messages[follow.message_id] = follow
        queued = await dispatcher.queue.receive(binding.id, follow)
        assert await dispatcher.advance(queued.action_id) == "admitted"
        assert native.prompts == ["Try a different way instead"]
        witness = proofs.witnesses[REF]
        assert witness.last_outcome == "interrupted"  # never the previous success
        assert len([w for w in writes if w.url.path.endswith("/prompt")]) == 1
    finally:
        await finish(proofs, transport)


async def test_without_the_decline_tail_the_same_followup_is_not_sent(db):
    dispatcher, binding, reader, native, writes, proofs, transport = await worker(db)
    try:
        native.decline()
        native.messages[0]["error"] = {"type": "provider", "message": "Step interrupted"}
        follow = message(message_id=202, text="Try a different way instead", revision=0)
        reader.messages[follow.message_id] = follow
        queued = await dispatcher.queue.receive(binding.id, follow)
        assert await dispatcher.advance(queued.action_id) != "admitted"
        assert native.prompts == [] and not writes
    finally:
        await finish(proofs, transport)
