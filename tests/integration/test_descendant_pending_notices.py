"""Recursive pending notices with real ownDB and synthetic Zulip HTTP.

Registered execution peers are domain fixtures, not installed lineage evidence.
No Native session, Human source, upstream approval or formal acceptance is produced.
"""

from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest
from sqlalchemy import update

from jt_oz_bridge.adapters.opencode.contracts import ContractError
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA
from jt_oz_bridge.domain.control import ExecutionState, InteractionSnapshot, QuestionField
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.control_models import Binding, PendingInteraction
from jt_oz_bridge.storage.models import Action, Delivery, Grant
from tests.integration.test_consumer_runtime import rows, setup, visible
from tests.integration.test_dispatch import SyntheticExecution
from tests.integration.test_model_commands import Catalog
from tests.integration.test_resource_execution_results import Reader
from tests.support import REF

CHILD = REF.model_copy(update={"upstream_session_id": "original-child"})
GRANDCHILD = REF.model_copy(update={"upstream_session_id": "original-grandchild"})


class OriginalNode(SyntheticExecution):
    """Independent, exactly scoped peers behind the real SessionRegistry."""

    def __init__(self, reference, descendants, pending_calls):
        super().__init__()
        self.ref, self.contract_hash = reference, INSTALLED_SCHEMA
        self.state = ExecutionState.RUNNING
        self.descendants, self.pending_calls = descendants, pending_calls
        self.snapshot_changes = {}
        self.unsupported = set()
        self.removed_before_preview = set()
        self.on_pending = None

    def add_request(self, value, *, unsupported=False):
        assert value.reference == self.ref
        self.requests[value.upstream_request_id] = value
        self.state = ExecutionState.WAITING_INPUT
        if unsupported:
            self.unsupported.add(value.upstream_request_id)

    async def snapshot(self, reference):
        assert reference == self.ref
        value = await super().snapshot(reference)
        return value.model_copy(update=self.snapshot_changes)

    async def pending(self, reference):
        assert reference == self.ref
        self.pending_calls.append(reference)
        if self.on_pending is not None:
            await self.on_pending()
        return tuple(self.requests)

    async def interaction(self, reference, request_id):
        assert reference == self.ref
        if request_id in self.removed_before_preview:
            self.calls.append(("interaction", reference))
            self.requests.pop(request_id, None)
            raise ContractError("v2_permission_pending_not_proven")
        if request_id in self.unsupported:
            self.calls.append(("interaction", reference))
            raise ContractError("synthetic_child_preview_not_qualified")
        return await super().interaction(reference, request_id)


def request(reference, identity="shared-original-request"):
    return InteractionSnapshot(
        reference=reference,
        upstream_request_id=identity,
        generation="synthetic-original-request-generation",
        kind="form",
        pending=True,
        description="Private request for " + reference.upstream_session_id,
        fields=(QuestionField(id="answer", label="Original field", kind="text"),),
    )


@asynccontextmanager
async def tree_pipeline(db):
    previous, server, _, _, _, pulse = await setup(db, bound=False)
    pending_calls = []
    nodes = {
        REF: OriginalNode(REF, (CHILD, GRANDCHILD), pending_calls),
        CHILD: OriginalNode(CHILD, (GRANDCHILD,), pending_calls),
        GRANDCHILD: OriginalNode(GRANDCHILD, (), pending_calls),
    }
    entries = {
        reference: RegisteredSession(
            reference,
            INSTALLED_SCHEMA,
            native,
            Catalog(reference, INSTALLED_SCHEMA),
            Reader(),
            native.pending,
        )
        for reference, native in nodes.items()
    }
    registry = SessionRegistry(entries)
    old = previous.backends[REF.backend_id]
    backend = replace(
        old,
        registered=RegisteredBackend(
            REF.backend_identity, INSTALLED_SCHEMA, old.registered.projects, registry
        ),
        models=registry.models,
        results=registry.results,
        references=tuple(nodes),
        pending=registry.pending,
        pulse=pulse,
        reference_provider=registry.reference_snapshot,
    )
    pipeline = ConsumerPipeline(
        db,
        previous.fence,
        previous.scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    try:
        binding = await pipeline.bindings.bind("realm", 7, 10, "Original work", REF)
        # Binding setup is outside the behavior under test.
        for native in nodes.values():
            native.calls.clear()
        yield pipeline, server, nodes, registry, binding, pending_calls
    finally:
        await previous.scope.client.close()


async def deliver_all(pipeline, db):
    deliveries = await rows(db, Delivery)
    for delivery in deliveries:
        assert await pipeline.bound_delivery.advance(delivery.id) == "delivered"
    return deliveries


@pytest.mark.parametrize("locale", ["en", "zh-TW"])
async def test_recursive_pending_keeps_colliding_ids_separate_in_original_binding_and_http(
    db, locale
):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, registry, binding, calls = env
        async with db.sessions.begin() as session:
            await session.execute(
                update(Binding).where(Binding.id == binding.id).values(locale=locale)
            )
        originals = dict(registry.sessions)
        for ref, native in nodes.items():
            native.add_request(request(ref))

        await pipeline.pending_notices_once()
        await pipeline.pending_notices_once()

        saved = await rows(db, PendingInteraction)
        assert len(saved) == 3
        assert {InteractionSnapshot.model_validate(row.snapshot).reference for row in saved} == set(
            nodes
        )
        assert {
            InteractionSnapshot.model_validate(row.snapshot).upstream_request_id for row in saved
        } == {"shared-original-request"}
        assert {row.binding_id for row in saved} == {binding.id}
        assert {row.binding_revision for row in saved} == {binding.revision}
        assert len({row.identity_key for row in saved}) == 3
        assert set(calls) == set(nodes)
        deliveries = await deliver_all(pipeline, db)
        assert len(deliveries) == len(server.posts) == 3
        assert all(row.payload["topic"] == binding.topic for row in deliveries)
        assert all(
            post["subject"] == binding.topic and post["sender_id"] == 11 for post in server.posts
        )
        parent_label, requester_label = (
            ("Main conversation: ", "Asked by subagent: ")
            if locale == "en"
            else ("主對話：", "提出要求的子 agent：")
        )
        shown = [visible(post["content"]) for post in server.posts]
        child_notices = [body for body in shown if requester_label in body]
        assert len(child_notices) == 2
        for ref in (CHILD, GRANDCHILD):
            matching = [
                body for body in child_notices if requester_label + ref.upstream_session_id in body
            ]
            assert len(matching) == 1
            assert parent_label + REF.upstream_session_id in matching[0]
        assert len([body for body in shown if parent_label not in body]) == 1
        assert all(registry.sessions[ref] is original for ref, original in originals.items())
        assert all(not native.submitted for native in nodes.values())
        assert not await rows(db, Action)
        await pipeline.pending_notices_once()
        assert len(await rows(db, Delivery)) == 3


async def test_unsupported_child_preview_does_not_become_a_root_request_or_collapse_siblings(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, binding, _ = env
        for ref in (CHILD, GRANDCHILD):
            nodes[ref].add_request(request(ref), unsupported=True)
        await pipeline.pending_notices_once()
        await pipeline.pending_notices_once()
        assert not await rows(db, PendingInteraction)
        deliveries = await deliver_all(pipeline, db)
        assert len(deliveries) == 2
        assert len({row.dedupe_key for row in deliveries}) == 2
        assert all(row.binding_id == binding.id for row in deliveries)
        assert all("shown here" in post["content"] for post in server.posts)
        assert not any("Private request" in post["content"] for post in server.posts)
        assert not any(kind == "interaction" for kind, _ in nodes[REF].calls)
        assert all(not native.submitted for native in nodes.values())


@pytest.mark.parametrize(
    "fault",
    [
        "foreign_backend",
        "foreign_identity",
        "foreign_project",
        "foreign_directory",
        "unregistered",
        "duplicate",
        "root_self",
        "unreconciled",
        "unknown",
        "disconnected",
        "wrong_reference",
    ],
)
async def test_invalid_complete_lineage_cannot_be_used_for_pending_reads_or_notices(db, fault):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, _, calls = env
        root = nodes[REF]
        root.add_request(request(REF))
        if fault.startswith("foreign_"):
            field = {
                "foreign_backend": "backend_id",
                "foreign_identity": "backend_identity",
                "foreign_project": "project_id",
                "foreign_directory": "canonical_directory",
            }[fault]
            foreign = CHILD.model_copy(
                update={field: "/foreign" if field == "canonical_directory" else "foreign"}
            )
            root.snapshot_changes = {"descendants": (foreign,)}
        else:
            root.snapshot_changes = {
                "unregistered": {
                    "descendants": (CHILD.model_copy(update={"upstream_session_id": "missing"}),)
                },
                "duplicate": {"descendants": (CHILD, CHILD)},
                "root_self": {"descendants": (REF,)},
                "unreconciled": {"reconciled": False},
                "unknown": {"state": ExecutionState.UNKNOWN},
                "disconnected": {"state": ExecutionState.DISCONNECTED},
                "wrong_reference": {"reference": CHILD},
            }[fault]
        await pipeline.pending_notices_once()
        assert not calls
        assert not await rows(db, PendingInteraction)
        assert not await rows(db, Delivery)
        assert not server.posts


async def test_tui_resolved_grandchild_request_is_reconciled_without_a_new_notice(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, _, _ = env
        nodes[GRANDCHILD].add_request(request(GRANDCHILD))
        nodes[GRANDCHILD].resolved = True
        await pipeline.pending_notices_once()
        assert ("interaction", GRANDCHILD) in nodes[GRANDCHILD].calls
        assert not await rows(db, PendingInteraction)
        assert not await rows(db, Delivery)
        assert not server.posts


async def test_tui_removal_between_catalog_and_preview_is_not_an_unsupported_notice(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, _, _ = env
        value = request(CHILD)
        nodes[CHILD].add_request(value)
        nodes[CHILD].removed_before_preview.add(value.upstream_request_id)
        await pipeline.pending_notices_once()
        assert ("interaction", CHILD) in nodes[CHILD].calls
        assert not nodes[CHILD].requests
        assert not await rows(db, PendingInteraction)
        assert not await rows(db, Delivery)
        assert not server.posts


@pytest.mark.parametrize("unsupported", [False, True])
async def test_child_removed_from_lineage_during_pending_read_cannot_publish_notice(
    db, unsupported
):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, _, _ = env
        nodes[CHILD].add_request(request(CHILD), unsupported=unsupported)

        async def remove_child():
            nodes[REF].descendants = ()

        nodes[CHILD].on_pending = remove_child
        await pipeline.pending_notices_once()
        assert ("interaction", CHILD) in nodes[CHILD].calls
        assert not await rows(db, PendingInteraction)
        assert not await rows(db, Delivery)
        assert not server.posts


async def test_actual_scope_read_outage_defers_then_recovers_one_child_notice(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, binding, _ = env
        nodes[CHILD].add_request(request(CHILD))
        outage = True
        attempted = 0

        def unavailable(request):
            nonlocal attempted
            if request.url.path.endswith("/streams/10"):
                attempted += 1
                if outage:
                    raise httpx.ReadTimeout("synthetic current audience unavailable")

        server.hook = unavailable
        await pipeline.pending_notices_once()
        assert attempted > 0
        assert not await rows(db, PendingInteraction)
        assert not await rows(db, Delivery)
        assert not server.posts
        outage = False
        await pipeline.pending_notices_once()
        await pipeline.pending_notices_once()
        saved = await rows(db, PendingInteraction)
        assert len(saved) == 1 and saved[0].binding_id == binding.id
        assert InteractionSnapshot.model_validate(saved[0].snapshot).reference == CHILD
        deliveries = await deliver_all(pipeline, db)
        assert len(deliveries) == len(server.posts) == 1
        assert server.posts[0]["subject"] == binding.topic
        assert not await rows(db, Action) and not nodes[CHILD].submitted


@pytest.mark.parametrize("change", ["revoke", "public_channel", "moved_topic"])
async def test_revocation_or_topic_audience_change_blocks_descendant_notices(db, change):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, binding, _ = env
        nodes[GRANDCHILD].add_request(request(GRANDCHILD))
        if change == "revoke":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        elif change == "public_channel":
            server.private = False
        else:
            for message in server.messages.values():
                message["subject"] = "Moved original topic"
        await pipeline.pending_notices_once()
        assert not await rows(db, PendingInteraction)
        assert not await rows(db, Delivery)
        assert not server.posts and not await rows(db, Action)
        current = (await rows(db, Binding))[0]
        assert current.id == binding.id and current.session_id == REF.upstream_session_id


async def test_revocation_after_queueing_prevents_actual_http_delivery_of_child_notice(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, _, _ = env
        nodes[CHILD].add_request(request(CHILD))
        await pipeline.pending_notices_once()
        deliveries = await rows(db, Delivery)
        assert len(deliveries) == 1
        async with db.sessions.begin() as session:
            await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
        assert await pipeline.bound_delivery.advance(deliveries[0].id) == "held"
        assert not server.posts


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("audience_read", [1, 2])
async def test_authentication_failure_is_not_a_retryable_pending_scope_outage(
    db, status, audience_read
):
    from jt_oz_bridge.adapters.zulip.client import ZulipError

    async with tree_pipeline(db) as env:
        pipeline, server, nodes, _, _, _ = env
        nodes[CHILD].add_request(request(CHILD))
        normal = server.handle

        attempted = 0

        def rejected(original):
            nonlocal attempted
            if original.url.path.endswith("/streams/10"):
                attempted += 1
            if original.url.path.endswith("/streams/10") and attempted >= audience_read:
                return httpx.Response(
                    status,
                    json={
                        "result": "error",
                        "code": "UNAUTHORIZED",
                        "msg": "PRIVATE_SYNTHETIC_SERVER_DETAIL",
                    },
                )
            return normal(original)

        pipeline.scope.client.client._transport = httpx.MockTransport(rejected)
        with pytest.raises(ZulipError, match="^authentication_failed$") as error:
            await pipeline.pending_notices_once()
        assert "PRIVATE" not in str(error.value)
        assert "pending_not_current_or_authorized" not in pipeline.deferred
        assert attempted == audience_read
        assert (
            nodes[CHILD].pending_calls.count(CHILD) == 1
        )  # No Native fallback/retry on lost auth.
        assert not await rows(db, PendingInteraction) and not await rows(db, Delivery)
        assert not server.posts and not any(native.submitted for native in nodes.values())


async def test_a_quiet_topic_is_scanned_again_on_an_arrival_in_its_directory_or_after_a_while(db):
    async with tree_pipeline(db) as env:
        pipeline, server, nodes, registry, binding, calls = env
        fence = ["before"]
        pipeline._feed_directory_fence = lambda ref: fence[0] if ref == REF else None
        await pipeline.pending_notices_once()
        scanned = list(calls)
        assert set(scanned) == set(nodes)
        # Nothing arrived in its directory: no Native read at all.
        nodes[CHILD].add_request(request(CHILD))
        await pipeline.pending_notices_once()
        assert calls == scanned and not await rows(db, PendingInteraction)
        # The permission's own event moves the directory fence: scanned at once.
        fence[0] = "after"
        await pipeline.pending_notices_once()
        assert len(calls) > len(scanned)
        (saved,) = await rows(db, PendingInteraction)
        assert InteractionSnapshot.model_validate(saved.snapshot).reference == CHILD
        # Quiet again, yet the announced notice is kept, never sent twice.
        count = len(calls)
        await pipeline.pending_notices_once()
        assert len(calls) == count
        pipeline.pending_quiet_seconds = 0
        await pipeline.pending_notices_once()
        assert len(calls) > count
        assert len(await rows(db, Delivery)) == 1
