"""Synthetic Human events through real Source/Native services, never live acceptance."""

import asyncio
import copy
import re
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.catalog import V2CatalogProject
from jt_oz_bridge.adapters.opencode.execution import V2ExecutionClient
from jt_oz_bridge.adapters.opencode.git_review import (
    REVIEW_OPERATIONS,
    REVIEW_SEMANTICS,
    GitReviewAttestation,
    V2NativeGitReview,
)
from jt_oz_bridge.adapters.opencode.live import V2PublicFeed, VolatileFeedIndex
from jt_oz_bridge.adapters.opencode.project_policy import (
    GUARDED_OPERATIONS,
    PERMISSION_SOURCE,
    POLICY_READS,
    NativePolicyEnrollment,
    V2ProjectPolicyGuard,
    policy_fingerprint,
)
from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, READS, V2LeafResourceProofs
from jt_oz_bridge.adapters.opencode.transport import ContractAttestation, V2HTTPTransport
from jt_oz_bridge.adapters.opencode.worktree_switch import (
    V2WorktreeSwitchObserver,
    WorktreeSwitchEnrollment,
)
from jt_oz_bridge.domain.catalog import ProjectScope
from jt_oz_bridge.domain.output_target import DiscoveryTarget
from jt_oz_bridge.domain.worktree_switch import WorkspaceConcurrencyPolicy
from jt_oz_bridge.services.backend_registry import RegisteredBackend
from jt_oz_bridge.services.bindings import reference
from jt_oz_bridge.services.consumer_runtime import ConsumerPipeline, RuntimeBackend
from jt_oz_bridge.services.discovery import RegisteredCatalog
from jt_oz_bridge.services.runtime_enrollment import ZulipRuntimeIdentity
from jt_oz_bridge.services.session_registry import RegisteredSession, SessionRegistry
from jt_oz_bridge.storage.command_models import CommandReceipt
from jt_oz_bridge.storage.control_models import Binding, ControlToken, EnrolledProject
from jt_oz_bridge.storage.models import Action, Delivery, DeliveryBatch, Grant
from tests.contract.test_leaf_resources import fixture_data
from tests.contract.test_public_live_feed import CONNECTED, OWNER, PROFILE, frame
from tests.contract.test_public_live_feed import REF as NATIVE_REF
from tests.integration.test_consumer_runtime import Sessions, rows, setup
from tests.integration.test_model_commands import Catalog
from tests.integration.test_resource_execution_results import Reader
from tests.support import REF as BASE_REF
from tests.support_directory_scope import SyntheticDirectoryScope

REF = BASE_REF.model_copy(update={"upstream_session_id": NATIVE_REF.upstream_session_id})

TARGET = REF.model_copy(
    update={
        "project_id": "target-project",
        "canonical_directory": "/workspace/other-tree",
        "upstream_session_id": NATIVE_REF.upstream_session_id[:-1] + "X",
    }
)


async def native(ref, *, inode):
    def rebase(v):
        if isinstance(v, dict):
            return {k: rebase(a) for k, a in v.items()}
        if isinstance(v, list):
            return [rebase(a) for a in v]
        if v == NATIVE_REF.canonical_directory:
            return ref.canonical_directory
        if v == NATIVE_REF.upstream_session_id:
            return ref.upstream_session_id
        return v

    data = rebase(fixture_data())
    data["session.get"]["data"].update(
        agent="build", permissions=[{"action": "*", "resource": "*", "effect": "deny"}]
    )
    loc = {"directory": ref.canonical_directory}
    data.update(
        {
            "agent.get": {
                "location": loc,
                "data": {
                    "id": "build",
                    "name": "Build",
                    "request": {"settings": {}, "headers": {}, "body": {}},
                    "mode": "primary",
                    "hidden": False,
                    "permissions": [{"action": "*", "resource": "*", "effect": "allow"}],
                },
            },
            "plugin.list": {"location": loc, "data": []},
            "permission.saved.list": {"data": []},
            "mcp.list": {"location": loc, "data": []},
        }
    )
    calls, hook = [], [None]

    def handle(request):
        assert request.method == "GET", "no Native mutation in switch fixture"
        calls.append(request)
        path = request.url.path
        direct = {
            "/api/agent/build": "agent.get",
            "/api/plugin": "plugin.list",
            "/api/permission/saved": "permission.saved.list",
            "/api/mcp": "mcp.list",
            "/api/shell": "shell.list",
            "/api/session": "session.list",
            "/api/session/active": "session.active",
        }
        if path == "/api/worktree":
            value = [
                {"directory": REF.canonical_directory, "strategy": "git"},
                {"directory": TARGET.canonical_directory, "strategy": "git"},
            ]
        elif path == "/api/vcs/diff":
            value = {"location": loc, "data": []}
        elif path == "/api/location":
            value = {
                "directory": ref.canonical_directory,
                "project": {
                    "id": "global",
                    "directory": ref.canonical_directory,
                    "canonical": REF.canonical_directory,
                },
            }
        else:
            op = direct.get(path, "session.get")
            for suffix, name in (
                ("inbox", "session.inbox.list"),
                ("message", "session.message.list"),
                ("permission", "session.permission.list"),
                ("form", "session.form.list"),
            ):
                if path.endswith("/" + suffix):
                    op = name
            value = copy.deepcopy(data[op])
        if hook[0]:
            hook[0](request, value)
        return httpx.Response(200, json=value)

    t = V2HTTPTransport(
        "http://127.0.0.1:4096",
        PROFILE,
        attestation=ContractAttestation(
            PROFILE.sha256, ref.backend_identity, "2.0.32", READS | POLICY_READS | REVIEW_OPERATIONS
        ),
        transport=httpx.MockTransport(handle),
        verify_identity=AsyncMock(return_value=True),
    )
    owner = SimpleNamespace(
        enrollment=SimpleNamespace(
            backend_id=ref.backend_id,
            backend_identity=ref.backend_identity,
            version="2.0.32",
            url="http://127.0.0.1:4096",
        ),
        read=AsyncMock(
            return_value=SimpleNamespace(
                owner_epoch=OWNER, model_dump=lambda **k: {"synthetic_owner": OWNER}
            )
        ),
    )
    feed = V2PublicFeed(t, owner, (ref,))
    feed.index = VolatileFeedIndex(PROFILE, (ref,), OWNER)
    feed.index.accept(frame(CONNECTED))
    feed.task = asyncio.create_task(asyncio.Event().wait())
    project = V2CatalogProject(
        ProjectScope(**ref.model_dump(exclude={"upstream_session_id"})), "global"
    )
    proofs = V2LeafResourceProofs(feed, {ref.project_id: project})
    await proofs.watch(ref)
    fingerprint = policy_fingerprint(
        ref,
        "global",
        data["session.get"]["data"],
        data["agent.get"],
        data["plugin.list"],
        data["permission.saved.list"],
        data["mcp.list"],
    )
    policy = NativePolicyEnrollment(
        format="native-project-policy-v1",
        reference=ref,
        native_project_id="global",
        contract_sha256=PROFILE.sha256,
        permission_source_sha256=PERMISSION_SOURCE,
        fingerprint_sha256=fingerprint,
        operations=GUARDED_OPERATIONS,
    )
    guard = V2ProjectPolicyGuard(proofs, {ref: policy})
    execution = V2ExecutionClient(t, proofs.projects, proofs=proofs, scope_guard=guard)
    physical = SyntheticDirectoryScope(ref)
    physical.generation = inode
    physical.enrolled = SimpleNamespace(
        roots=(SimpleNamespace(directory=ref.canonical_directory, device=1, inode=inode + 1),)
    )
    review = V2NativeGitReview(
        execution,
        {
            ref: GitReviewAttestation(
                ref, PROFILE.sha256, fingerprint, REVIEW_SEMANTICS, "a" * 64, REVIEW_OPERATIONS
            )
        },
        directories=physical,
    )
    return SimpleNamespace(
        ref=ref,
        execution=execution,
        review=review,
        proofs=proofs,
        transport=t,
        physical=physical,
        data=data,
        calls=calls,
        hook=hook,
    )


@asynccontextmanager
async def environment(db):
    initial, server, _, _, _, _ = await setup(db, bound=False)
    client = initial.scope.client
    delegate = client.client._transport

    def peer(request):
        route = request.url.path.removeprefix("/api/v1/")
        if route == "users/me":
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "user_id": 11,
                    "is_bot": True,
                    "is_active": True,
                    "bot_owner_id": 7,
                    "role": 400,
                },
            )
        if route == "server_settings":
            return httpx.Response(
                200,
                json={
                    "result": "success",
                    "realm_url": client.url,
                    "zulip_version": "12.3",
                    "zulip_feature_level": 500,
                },
            )
        return delegate.handler(request)

    client.client._transport = httpx.MockTransport(peer)
    client.verify_identity = ZulipRuntimeIdentity(
        client,
        SimpleNamespace(
            bot_user_id=11, bot_owner_id=7, url=client.url, zulip_version="12.3", feature_level=500
        ),
    )
    first, second = await native(REF, inode=1), await native(TARGET, inode=2)

    async def pending(ref):
        return ()

    entries = {
        v.ref: RegisteredSession(
            v.ref,
            INSTALLED_SCHEMA,
            v.execution,
            Catalog(v.ref, INSTALLED_SCHEMA),
            Reader(),
            pending,
        )
        for v in (first, second)
    }
    registry = SessionRegistry(entries)
    async with db.sessions.begin() as session:
        session.add(
            EnrolledProject(
                id=TARGET.project_id,
                backend_id=TARGET.backend_id,
                realm_id="realm",
                canonical_directory=TARGET.canonical_directory,
                enabled=True,
            )
        )
        for user in (7, 8):
            session.add(
                Grant(
                    realm_id="realm",
                    user_id=user,
                    project_id=TARGET.project_id,
                    role="administrator",
                )
            )
    backend = RuntimeBackend(
        RegisteredBackend(REF.backend_identity, INSTALLED_SCHEMA, registry.projects, registry),
        RegisteredCatalog(REF.backend_identity, INSTALLED_SCHEMA, registry.projects, Sessions()),
        registry.models,
        registry.results,
        (REF, TARGET),
        pending,
        AsyncMock(),
        (),
    )
    pipeline = ConsumerPipeline(
        db,
        initial.fence,
        initial.scope,
        {REF.backend_id: backend},
        interval=0.02,
        delivery_interval=0,
    )
    old = await pipeline.bindings.bind("realm", 7, 10, "Original work", REF)
    observer = V2WorktreeSwitchObserver(
        registry,
        first.review,
        second.review,
        WorktreeSwitchEnrollment(REF, TARGET, "git", REF.canonical_directory, "b" * 64),
    )
    pipeline.configure_worktree_switch({(REF, TARGET): observer})
    env = SimpleNamespace(
        p=pipeline,
        server=server,
        client=client,
        old=old,
        first=first,
        second=second,
        observer=observer,
        registry=registry,
    )
    try:
        await pipeline.consumer.start()
        yield env
    finally:
        await client.close()
        for v in (first, second):
            await v.proofs.feed.close()
            await v.transport.close()


async def command(env, text, *, deliver=True, author=7):
    mid = max(env.server.messages) + 1
    env.server.input(text, mid, author=author, topic="Original work")
    env.server.next_mid = mid + 1
    statuses = await env.p.consumer.poll()
    if deliver:
        await env.p.deliver_once()
    async with env.p.db.sessions() as session:
        receipt = await session.scalar(
            select(CommandReceipt).where(CommandReceipt.message_id == mid)
        )
    return receipt, tuple(v for v in statuses if v != "ignored")


def token(receipt):
    return re.findall(r"!oz worktree switch ([A-Za-z0-9_-]+)", receipt.response["text"])[-1]


async def preview(env):
    selected, _ = await command(env, "!oz worktree switch")
    shown, _ = await command(env, "!oz worktree switch " + token(selected))
    return shown


async def test_real_closed_source_and_original_native_switch_create_new_binding_atomically(db):
    async with environment(db) as e:
        shown = await preview(e)
        result, statuses = await command(e, "!oz worktree switch " + token(shown))
        assert statuses == ("reply",)
        bindings = await rows(db, Binding)
        old = next(v for v in bindings if v.id == e.old.id)
        new = next(v for v in bindings if v.id != old.id)
        assert old.state == "unbound" and reference(old) == REF and old.dispatch_paused
        assert new.state == "active" and reference(new) == TARGET and new.id != old.id
        assert result.response["binding_id"] == new.id and result.response["queued_batch_id"]
        assert len(e.server.posts) == 3 and not await rows(db, Action)
        assert all(r.method == "GET" for n in (e.first, e.second) for r in n.calls)


@pytest.mark.parametrize(
    "project,user", [("project", 7), ("project", 8), ("target-project", 7), ("target-project", 8)]
)
async def test_revocation_after_preview_blocks_confirmation_and_preserves_binding(
    db, project, user
):
    async with environment(db) as e:
        shown = await preview(e)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant)
                .where(Grant.project_id == project, Grant.user_id == user)
                .values(active=False)
            )
        result, statuses = await command(e, "!oz worktree switch " + token(shown))
        assert statuses == ("held",) and len(await rows(db, Binding)) == 1
        assert (await rows(db, Binding))[0].state == "active" and len(e.server.posts) == 2


async def test_preview_queued_then_target_revoked_never_discloses_target_path(db):
    async with environment(db) as e:
        receipt, _ = await command(e, "!oz worktree switch", deliver=False)
        async with db.sessions.begin() as session:
            await session.execute(
                update(Grant)
                .where(Grant.project_id == TARGET.project_id, Grant.user_id == 8)
                .values(active=False)
            )
        await e.p.deliver_once()
        assert not e.server.posts
        assert all(v.state == "held" for v in await rows(db, Delivery))
        assert receipt.state == "completed"


async def test_constructed_or_copied_target_cannot_use_producer_writer(db):
    async with environment(db) as e:
        receipt, _ = await command(e, "!oz worktree switch", deliver=False)
        target = e.p.router.worktree_switch.scoped.destinations.decode(
            (
                await rows(
                    db,
                    __import__(
                        "jt_oz_bridge.storage.output_models", fromlist=["OutputDestination"]
                    ).OutputDestination,
                )
            )[0]
        )
        with pytest.raises(ValueError, match="issuer"):
            await e.p.discovery_outbox.queue_scope_batch(
                "forged",
                target.model_copy(),
                ("leak",),
                renderer_version="test",
                message_limit=1000,
                topic_limit=60,
            )
        assert len(await rows(db, DeliveryBatch)) == 1


async def test_legacy_discovery_still_refuses_bound_topic(db):
    async with environment(db) as e:
        receipt, _ = await command(e, "!oz worktree switch", deliver=False)
        saved = (
            await rows(
                db,
                __import__(
                    "jt_oz_bridge.storage.output_models", fromlist=["OutputDestination"]
                ).OutputDestination,
            )
        )[0]
        data = {
            k: v
            for k, v in saved.authorization.items()
            if k not in {"format", "original_scope", "target_reference", "operation_sha256"}
        }
        legacy = DiscoveryTarget.model_validate(data)
        with pytest.raises(ValueError, match="bound"):
            await e.p.discovery_outbox.destinations.authorize(legacy)


@pytest.mark.parametrize("fault", ["owner", "physical", "policy", "worktree", "location"])
async def test_native_drift_never_switches_or_publishes_confirmation(db, fault):
    async with environment(db) as e:
        shown = await preview(e)
        if fault == "owner":
            e.second.proofs.feed.index.invalidate("synthetic-owner-change")
        elif fault == "physical":
            e.second.physical.enabled = False
        elif fault == "policy":
            e.second.data["session.get"]["data"]["permissions"] = []
        elif fault == "worktree":
            e.first.hook[0] = lambda req, v: v.clear() if req.url.path == "/api/worktree" else None
        else:
            e.second.hook[0] = lambda req, v: (
                v.update(directory="/wrong") if req.url.path == "/api/location" else None
            )
        _, statuses = await command(e, "!oz worktree switch " + token(shown))
        assert statuses == ("held",) and len(await rows(db, Binding)) == 1
        # Preview, its confirmation prompt, then only the plain held notice.
        assert len(e.server.posts) == 3 and held_notice(e.server.posts[-1])


def held_notice(post):
    """The held reply names a reason and `!status`, never a token or a switch."""
    return (
        "!status" in post["content"]
        and "!oz" not in post["content"]
        and "!ok" not in post["content"]
        and "widget_content" not in post
    )


async def test_running_roots_are_qualified_without_adding_idle_or_leaf_only_policy(db):
    async with environment(db) as e:
        for n in (e.first, e.second):
            n.data["session.active"]["data"][n.ref.upstream_session_id] = {"type": "running"}
        shown = await preview(e)
        _, statuses = await command(e, "!oz worktree switch " + token(shown))
        assert statuses == ("reply",) and len(await rows(db, Binding)) == 2


async def test_old_queue_rows_and_held_evidence_are_unchanged_and_never_replayed(db):
    async with environment(db) as e:
        ids = []
        for state in ("queued", "held", "ambiguous"):
            action = Action(
                binding_id=e.old.id,
                binding_revision=e.old.revision,
                actor_id=7,
                dedupe_key="old-" + state,
                operation_digest="a" * 64,
                state=state,
                operation="prompt",
                payload={"operation": "prompt", "source": {"synthetic": state}},
            )
            async with db.sessions.begin() as session:
                session.add(action)
                await session.flush()
                ids.append(action.id)
        before = [dict(v.__dict__) for v in await rows(db, Action)]
        shown = await preview(e)
        await command(e, "!oz worktree switch " + token(shown))
        e.first.calls.clear()
        e.second.calls.clear()
        await e.p.dispatch_once()
        for identity in ids:
            assert await e.p.dispatcher.advance(identity) in {"queued", "held", "ambiguous"}
        after = [dict(v.__dict__) for v in await rows(db, Action)]
        for values in (before, after):
            for v in values:
                v.pop("_sa_instance_state", None)
        assert before == after and not e.first.calls and not e.second.calls


async def test_source_changed_inside_native_get_cannot_publish_or_switch(db):
    async with environment(db) as e:

        def change(req, value):
            mid = max(e.server.messages)
            e.server.messages[mid]["content"] = "edited"

        e.first.hook[0] = change
        _, statuses = await command(e, "!oz worktree switch")
        assert statuses == ("held",) and not e.server.posts
        assert not await rows(db, ControlToken) and not await rows(db, DeliveryBatch)


async def test_same_physical_worktree_is_refused_even_with_distinct_root_and_path(db):
    async with environment(db) as e:
        e.second.physical.generation = e.first.physical.generation
        _, statuses = await command(e, "!oz worktree switch")
        assert statuses == ("held",) and len(e.server.posts) == 1
        assert held_notice(e.server.posts[0])


async def test_preview_other_actor_and_changed_binding_cas_are_refused(db):
    async with environment(db) as e:
        shown = await preview(e)
        _, statuses = await command(e, "!oz worktree switch " + token(shown), author=8)
        assert statuses == ("held",) and len(await rows(db, Binding)) == 1


async def test_workspace_exclusive_final_claim_rechecks_after_unblocked_hint(db):
    from tests.integration.test_dispatch import dispatcher, message

    worker, binding, execution, reader = await dispatcher(db)
    policy = WorkspaceConcurrencyPolicy(
        backend_id=REF.backend_id,
        backend_identity=REF.backend_identity,
        canonical_directory=REF.canonical_directory,
        device=1,
        inode=2,
        mode="exclusive",
    )
    worker.configure_workspace_policies((policy,))
    receipt = await worker.queue.receive(binding.id, message())
    action = await worker.load(receipt.action_id)
    assert not await worker.blocked_by_workspace(action.id)
    async with db.sessions.begin() as session:
        session.add(
            Action(
                binding_id=binding.id,
                binding_revision=binding.revision,
                actor_id=7,
                dedupe_key="other-running",
                operation_digest="b" * 64,
                state="ambiguous",
                operation="prompt",
                payload={"operation": "prompt"},
            )
        )
    assert not await worker.claim(
        action,
        binding,
        __import__("jt_oz_bridge.security.policy", fromlist=["Permission"]).Permission.OPERATE,
    )
    assert await worker.blocked_by_workspace(action.id) and not execution.submitted


@pytest.mark.parametrize("fault", ["grant", "cancel"])
async def test_after_binding_flush_fault_rolls_back_tokens_both_bindings_and_ack(
    db, monkeypatch, fault
):
    from sqlalchemy.ext.asyncio import AsyncSession

    async with environment(db) as e:
        shown = await preview(e)
        before = await rows(db, ControlToken)
        expected_tokens = [(v.token_hash, v.used) for v in before]
        flush, injected = AsyncSession.flush, False

        async def late(session, *args, **kwargs):
            nonlocal injected
            await flush(session, *args, **kwargs)
            if not injected and any(
                isinstance(v, Binding) and v.project_id == TARGET.project_id
                for v in session.identity_map.values()
            ):
                injected = True
                if fault == "cancel":
                    raise asyncio.CancelledError
                await session.execute(
                    update(Grant)
                    .where(Grant.project_id == TARGET.project_id, Grant.user_id == 7)
                    .values(active=False)
                )

        monkeypatch.setattr(AsyncSession, "flush", late)
        if fault == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await command(e, "!oz worktree switch " + token(shown))
        else:
            _, statuses = await command(e, "!oz worktree switch " + token(shown))
            assert statuses == ("held",)
        assert injected
        bindings = await rows(db, Binding)
        assert len(bindings) == 1 and bindings[0].state == "active"
        assert reference(bindings[0]) == REF and bindings[0].revision == e.old.revision
        assert [(v.token_hash, v.used) for v in await rows(db, ControlToken)] == expected_tokens
        assert len(await rows(db, DeliveryBatch)) == 2 and len(e.server.posts) == 2


async def test_target_already_bound_does_not_take_over_and_consumed_token_rolls_back(db):
    async with environment(db) as e:
        shown = await preview(e)
        e.server.message("Existing other topic", 89)
        e.server.messages[89]["subject"] = "Another topic"
        reserved = await e.p.bindings.bind("realm", 7, 10, "Another topic", TARGET)
        before = [(v.token_hash, v.used) for v in await rows(db, ControlToken)]
        _, statuses = await command(e, "!oz worktree switch " + token(shown))
        assert statuses == ("held",)
        bindings = await rows(db, Binding)
        assert len(bindings) == 2 and all(v.state == "active" for v in bindings)
        assert next(v for v in bindings if v.id == reserved.id).topic == "Another topic"
        assert [(v.token_hash, v.used) for v in await rows(db, ControlToken)] == before
        assert len(await rows(db, DeliveryBatch)) == 2


async def test_duplicate_original_confirm_reuses_existing_ack_without_rebinding(db):
    async with environment(db) as e:
        shown = await preview(e)
        receipt, _ = await command(e, "!oz worktree switch " + token(shown))
        source = await e.p.source.read("realm", receipt.message_id)
        before = [(v.id, v.revision, v.state) for v in await rows(db, Binding)]
        count = len(await rows(db, DeliveryBatch))
        routed = await e.p.router.route(source)
        batch = await e.p.reply_publisher.publish(routed)
        assert batch.id == receipt.response["queued_batch_id"]
        assert [(v.id, v.revision, v.state) for v in await rows(db, Binding)] == before
        assert len(await rows(db, DeliveryBatch)) == count


async def test_final_source_close_cannot_renew_expired_native_observation(db, monkeypatch):
    from jt_oz_bridge.adapters.opencode import worktree_switch as native_module

    async with environment(db) as e:
        shown = await preview(e)
        consume = e.p.scope.consume_observation
        clock = native_module.time.monotonic

        def expire(*args, **kwargs):
            result = consume(*args, **kwargs)
            monkeypatch.setattr(
                native_module, "time", SimpleNamespace(monotonic=lambda: clock() + 6)
            )
            return result

        monkeypatch.setattr(e.p.scope, "consume_observation", expire)
        _, statuses = await command(e, "!oz worktree switch " + token(shown))
        assert statuses == ("held",) and len(await rows(db, Binding)) == 1
        assert len(await rows(db, DeliveryBatch)) == 2


async def test_native_observation_is_same_task_and_cannot_be_forged_into_issuer(db):
    from jt_oz_bridge.domain.worktree_switch import ObservedWorktreeSwitch

    async with environment(db) as e:

        async def admitted():
            pass  # Adapter read proof only; this is not Source write authority.

        native = await e.observer.observe(authorize=admitted)

        async def elsewhere():
            with pytest.raises(ValueError, match="current"):
                native.require_current()

        await asyncio.create_task(elsewhere())
        source = e.server.input("!oz worktree switch", 500, topic="Original work")
        await e.p.journal.capture(e.p.consumer.queue_id, [source])
        message = await e.p.source.read("realm", 500)

        async def read_only(audience):
            forged = ObservedWorktreeSwitch(native.selection, native.snapshot, lambda: None)
            with pytest.raises(ValueError, match="issuer_native_stage"):
                await e.p.router.worktree_switch.previews.issue(
                    message, audience, e.old, TARGET, "a" * 64, forged
                )

        observed = await e.p.scope.observe_sources(e.p.source, (message,), read_only=read_only)
        e.p.scope.consume_observation(observed, e.p.source, (message,))
        assert not await rows(db, DeliveryBatch)


async def test_create_and_switch_configurations_keep_distinct_real_router_entries(db):
    """Synthetic Human events through the real service pipeline; no Native writes."""
    from tests.integration.test_worktree_commands import SyntheticWorktree

    async with environment(db) as e:
        producer = SyntheticWorktree(INSTALLED_SCHEMA)
        producer.template = producer.template.model_copy(update={"reference": REF})
        e.p.configure_worktrees({REF: producer})
        inventory, _ = await command(e, "!oz worktrees")
        assert "!oz worktree create " in inventory.response["text"]
        assert "!oz worktree switch " not in inventory.response["text"]
        create_token = re.search(r"!oz worktree create (\S+)`", inventory.response["text"])[1]
        creation, _ = await command(e, "!oz worktree create " + create_token)
        assert "!oz worktree confirm " in creation.response["text"]
        choices, _ = await command(e, "!oz worktree switch")
        assert "!oz worktree switch " in choices.response["text"]
        assert "!oz worktree create " not in choices.response["text"]
        shown, _ = await command(e, "!oz worktree switch " + token(choices))
        done, _ = await command(e, "!oz worktree switch " + token(shown))
        assert done.state == "completed"
        assert not producer.posts
        async with db.sessions() as session:
            bindings = list((await session.scalars(select(Binding))).all())
        assert len(bindings) == 2
        assert next(v for v in bindings if v.id == e.old.id).state != "active"
        assert reference(next(v for v in bindings if v.state == "active")) == TARGET
