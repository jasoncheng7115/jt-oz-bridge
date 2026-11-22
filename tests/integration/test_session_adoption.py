"""Real adapters plus isolated ownDB, using synthetic Native/Source peers only."""

import copy
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import func, select, update

from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.backend_registry import BackendRegistry, RegisteredBackend
from jt_oz_bridge.services.bindings import BindingService
from jt_oz_bridge.services.session_adoption import SessionAdoptionService
from jt_oz_bridge.storage.control_models import Binding, EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Action, Grant
from jt_oz_bridge.storage.session_registration_models import SessionRegistration
from tests.contract.test_existing_session_factory import setup as factory_setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import CHILD, GRANDCHILD, SIBLING, TARGET
from tests.integration.test_router import Source, message
from tests.support import SyntheticAudience


async def setup(db, *, leaf=False, routed=False, tree_qualification=True):
    anchor, transport, factory, tree, state, writes, original = await factory_setup(
        leaf=leaf, tree_qualification=tree_qualification
    )
    state["metadata_tree"] = tree
    async with db.sessions.begin() as session:
        session.add(
            EnrolledBackend(
                id=TARGET.backend_id,
                identity=TARGET.backend_identity,
                contract_hash=factory.policy.contract_sha256,
                enabled=True,
                verified=True,
                version="synthetic",
            )
        )
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
                Grant(realm_id="realm", user_id=user, project_id=TARGET.project_id, role="operator")
            )
    fencing = await DurableStore(db).acquire_lease("synthetic-adopter", ttl=120)
    fence = ConsumerFence("synthetic-adopter", fencing)
    audience, source = SyntheticAudience(), Source()
    control = factory.registry
    if routed:
        control = BackendRegistry(
            {
                TARGET.backend_id: RegisteredBackend(
                    TARGET.backend_identity,
                    factory.policy.contract_sha256,
                    factory.registry.projects,
                    factory.registry,
                )
            }
        )
    bindings = BindingService(db, control, audience)
    controller = SessionAdoptionService(bindings, source, fence, {TARGET.project_id: factory})
    item = message("!oz choose " + "x" * 32 + " 1")
    source.messages[item.message_id] = item
    return controller, item, audience, source, factory, state, writes, anchor, transport


async def states(db):
    async with db.sessions() as session:
        rows = list((await session.scalars(select(SessionRegistration))).all())
        assert await session.scalar(select(func.count()).select_from(Binding)) == 0
        assert await session.scalar(select(func.count()).select_from(Action)) == 0
        return [row.state for row in rows]


@pytest.mark.parametrize("running", [False, True])
@pytest.mark.parametrize("leaf", [False, True])
async def test_original_idle_and_running_graph_are_journaled_without_binding_or_native_send(
    db, running, leaf
):
    controller, item, audience, source, factory, state, writes, anchor, t = await setup(
        db, leaf=leaf
    )
    try:
        before = dict(factory.registry.sessions)
        if running:
            state["active"][TARGET.upstream_session_id] = {"type": "running"}
        entries = await controller.adopt(item, TARGET)
        assert TARGET in entries and (len(entries) == (1 if leaf else 4))
        assert all(factory.registry.sessions[ref] is value for ref, value in before.items())
        snapshot = await factory.registry.snapshot(TARGET)
        assert snapshot.state == (ExecutionState.RUNNING if running else ExecutionState.IDLE)
        assert await states(db) == ["active"]
        again = await controller.adopt(item, TARGET)
        assert all(again[ref] is value for ref, value in entries.items())
        assert await states(db) == ["active"] and not writes
        assert all(request.method == "GET" for request in state["resource_calls"])
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize(
    "fault",
    [
        "bot",
        "deleted",
        "edited",
        "text_changed",
        "public",
        "audience_member",
        "audience_bot",
        "actor_grant",
        "viewer_grant",
    ],
)
async def test_current_human_source_private_audience_and_all_grants_are_required(db, fault):
    controller, item, audience, source, factory, state, writes, anchor, t = await setup(
        db, leaf=True
    )
    try:
        if fault in {"bot", "deleted", "edited"}:
            field, value = {
                "bot": ("is_bot", True),
                "deleted": ("deleted", True),
                "edited": ("revision", 1),
            }[fault]
            item = item.model_copy(update={field: value})
            source.messages[item.message_id] = item
        elif fault == "text_changed":
            source.messages[item.message_id] = item.model_copy(update={"text": "other"})
        elif fault == "public":
            audience.private = False
        elif fault == "audience_member":
            audience.users = frozenset({8})
        elif fault == "audience_bot":
            original = audience.inspect

            async def inspect(*args):
                return (await original(*args)).model_copy(
                    update={"untrusted_bot_ids": frozenset({90})}
                )

            audience.inspect = inspect
        else:
            async with db.sessions.begin() as session:
                await session.execute(
                    update(Grant)
                    .where(Grant.user_id == (7 if fault == "actor_grant" else 8))
                    .values(active=False)
                )
        with pytest.raises(AccessDenied):
            await controller.adopt(item, TARGET)
        assert TARGET not in factory.registry.sessions and await states(db) == [] and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fault", ["edit", "audience", "grant", "cancel"])
async def test_change_after_prepared_commit_leaves_identity_but_no_registered_graph(db, fault):
    controller, item, audience, source, factory, state, writes, anchor, t = await setup(
        db, leaf=True
    )
    save = controller.journal.prepare

    async def intercept(*args, **kwargs):
        receipt = await save(*args, **kwargs)
        if fault == "edit":
            source.messages[item.message_id] = item.model_copy(update={"revision": 1})
        elif fault == "audience":
            audience.revision = "changed"
        elif fault == "grant":
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 7).values(active=False))
        else:
            import asyncio

            raise asyncio.CancelledError()
        return receipt

    controller.journal.prepare = intercept
    try:
        import asyncio

        with pytest.raises(asyncio.CancelledError if fault == "cancel" else AccessDenied):
            await controller.adopt(item, TARGET)
        assert TARGET not in factory.registry.sessions
        assert await states(db) == ["prepared"] and not writes
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("fail_after_registry", [False, True])
async def test_new_factory_restores_prepared_or_active_identity_by_fresh_get_without_human_replay(
    db, fail_after_registry
):
    controller, item, audience, source, factory, state, writes, anchor, t = await setup(
        db, leaf=True
    )
    next_anchor = next_t = None
    try:
        if fail_after_registry:
            controller.journal.activate = AsyncMock(
                side_effect=RuntimeError("crash after registry update")
            )
            with pytest.raises(RuntimeError, match="crash"):
                await controller.adopt(item, TARGET)
            assert await states(db) == ["prepared"]
        else:
            await controller.adopt(item, TARGET)
            assert await states(db) == ["active"]
        next_anchor, next_t, fresh_factory, _, fresh_state, fresh_writes, _ = await factory_setup(
            leaf=True
        )
        assert TARGET not in fresh_factory.registry.sessions
        empty_source = Source()
        fresh = SessionAdoptionService(
            BindingService(db, fresh_factory.registry, SyntheticAudience()),
            empty_source,
            controller.journal.fence,
            {TARGET.project_id: fresh_factory},
        )

        async def locked(session):
            assert session.in_transaction()

        recovered = await fresh.recover_project(
            "realm",
            TARGET.project_id,
            authorize=AsyncMock(return_value=True),
            lock_authority=locked,
        )
        assert recovered == (TARGET,) and TARGET in fresh_factory.registry.sessions
        assert not empty_source.calls and not fresh_writes and not writes
        assert all(request.method == "GET" for request in fresh_state["resource_calls"])
        assert await states(db) == ["active"]
        assert fresh_factory.registry.sessions[TARGET] is not factory.registry.sessions[TARGET]
    finally:
        if next_anchor is not None:
            await finish(next_anchor, next_t)
        await finish(anchor, t)


async def test_restore_rejects_changed_original_without_native_mutation_or_replacement(db):
    controller, item, audience, source, factory, state, writes, anchor, t = await setup(
        db, leaf=True
    )
    next_anchor = next_t = None
    try:
        await controller.adopt(item, TARGET)
        (
            next_anchor,
            next_t,
            fresh_factory,
            tree,
            fresh_state,
            fresh_writes,
            _,
        ) = await factory_setup(leaf=True)
        tree["rows"][TARGET]["time"]["created"] += 1
        fresh = SessionAdoptionService(
            BindingService(db, fresh_factory.registry, SyntheticAudience()),
            Source(),
            controller.journal.fence,
            {TARGET.project_id: fresh_factory},
        )
        with pytest.raises(Conflict, match="historical_original_identity_changed"):
            await fresh.recover_project(
                "realm",
                TARGET.project_id,
                authorize=AsyncMock(return_value=True),
                lock_authority=AsyncMock(),
            )
        assert TARGET not in fresh_factory.registry.sessions and not fresh_writes and not writes
        assert await states(db) == ["active"]  # Historical row was not rewritten or deleted.
    finally:
        if next_anchor is not None:
            await finish(next_anchor, next_t)
        await finish(anchor, t)


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("running", [False, True])
async def test_get_only_recovery_extends_historical_graph_for_children_added_while_offline(
    db, active, running
):
    """A real encrypted journal and actual adapter tree, never a Native clone."""
    controller, item, _, _, factory, _, writes, anchor, t = await setup(db, leaf=True)
    next_anchor = next_t = None
    try:
        if not active:
            controller.journal.activate = AsyncMock(side_effect=RuntimeError("synthetic crash"))
            with pytest.raises(RuntimeError, match="synthetic crash"):
                await controller.adopt(item, TARGET)
        else:
            await controller.adopt(item, TARGET)
        before = (
            await controller.journal.recovery_records(
                "realm", TARGET.project_id, lock_authority=AsyncMock(), current=lambda: True
            )
        )[0]
        assert before.state == ("active" if active else "prepared")
        assert tuple(node.reference for node in before.record.nodes) == (TARGET,)
        (
            next_anchor,
            next_t,
            fresh_factory,
            _,
            fresh_state,
            fresh_writes,
            original,
        ) = await factory_setup()
        if running:
            fresh_state["active"][TARGET.upstream_session_id] = {"type": "running"}
            fresh_state["active"][GRANDCHILD.upstream_session_id] = {"type": "running"}
        source = Source()
        fresh = SessionAdoptionService(
            BindingService(db, fresh_factory.registry, SyntheticAudience()),
            source,
            controller.journal.fence,
            {TARGET.project_id: fresh_factory},
        )
        recovered = await fresh.recover_project(
            "realm",
            TARGET.project_id,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        )
        assert recovered == (TARGET,)
        after = (
            await fresh.journal.recovery_records(
                "realm", TARGET.project_id, lock_authority=AsyncMock(), current=lambda: True
            )
        )[0]
        assert after.state == "active" and after.extension_count == 1
        assert after.record.root == before.record.root
        assert after.record.nodes[0] == before.record.nodes[0]
        assert {node.reference for node in after.record.nodes} == {
            TARGET,
            CHILD,
            GRANDCHILD,
            SIBLING,
        }
        history = await fresh.journal.history(
            after, lock_authority=AsyncMock(), current=lambda: True
        )
        assert len(history) == 1 and history[0].predecessor == before
        assert {node.reference for node in history[0].added_nodes} == {CHILD, GRANDCHILD, SIBLING}
        assert fresh_factory.registry.sessions[original.reference] is original
        assert (await fresh_factory.registry.snapshot(TARGET)).state == (
            ExecutionState.RUNNING if running else ExecutionState.IDLE
        )
        assert await states(db) == ["active"]
        assert not source.calls and not writes and not fresh_writes
        assert all(request.method == "GET" for request in fresh_state["resource_calls"])
    finally:
        if next_anchor is not None:
            await finish(next_anchor, next_t)
        await finish(anchor, t)


@pytest.mark.parametrize("running", [False, True])
async def test_trusted_get_only_maintenance_connects_original_leaf_child_and_grandchild(
    db, running
):
    controller, item, _, source, factory, state, writes, anchor, t = await setup(db, leaf=True)
    try:
        await controller.adopt(item, TARGET)
        original = factory.registry.selected(TARGET)
        stable = {}
        before_source_calls = list(source.calls)
        tree = state["metadata_tree"]
        for child, parent, created in ((CHILD, TARGET, 90), (GRANDCHILD, CHILD, 100)):
            row = copy.deepcopy(tree["rows"][TARGET])
            row.update(
                id=child.upstream_session_id, parentID=parent.upstream_session_id, agent="task"
            )
            row["time"]["created"] = created
            tree["rows"][child] = row
            tree["edges"].setdefault(parent, []).append(child)
            state["resources"][child] = copy.deepcopy(state["resources"][TARGET])
            if running:
                state["active"][child.upstream_session_id] = {"type": "running"}
            assert child not in factory.registry.sessions
            assert await controller.maintain_root(
                "realm",
                TARGET.project_id,
                TARGET,
                authorize=AsyncMock(return_value=True),
                lock_authority=AsyncMock(),
            )
            assert factory.registry.selected(TARGET) is original
            for ref, entry in stable.items():
                assert factory.registry.selected(ref) is entry
            stable[child] = factory.registry.selected(child)
            snapshot = await factory.registry.snapshot(child)
            assert snapshot.state == (ExecutionState.RUNNING if running else ExecutionState.IDLE)
            assert not writes and source.calls == before_source_calls
        saved = (
            await controller.journal.recovery_records(
                "realm", TARGET.project_id, lock_authority=AsyncMock(), current=lambda: True
            )
        )[0]
        assert saved.state == "active" and saved.extension_count == 2
        assert {node.reference for node in saved.record.nodes} == {TARGET, CHILD, GRANDCHILD}
        assert not await controller.maintain_root(
            "realm",
            TARGET.project_id,
            TARGET,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        )
        assert not writes and await states(db) == ["active"]
    finally:
        await finish(anchor, t)


async def test_original_backend_registry_can_adopt_unregistered_session_without_bypassing_scope(db):
    controller, item, audience, source, factory, state, writes, anchor, t = await setup(
        db, leaf=True, routed=True
    )
    try:
        assert TARGET not in factory.registry.sessions
        await controller.adopt(item, TARGET)
        snapshot = await controller.bindings.control.snapshot(TARGET)
        assert snapshot.reference == TARGET and snapshot.reconciled and not writes
        with pytest.raises(AccessDenied):
            await controller.adopt(
                item, TARGET.model_copy(update={"backend_identity": "replacement"})
            )
        assert await states(db) == ["active"]
    finally:
        await finish(anchor, t)


@pytest.mark.parametrize("running", [False, True])
async def test_trusted_maintenance_initializes_actual_original_anchor_without_human_or_history(
    db, running
):
    controller, _, _, source, factory, state, writes, anchor, transport = await setup(db, leaf=True)
    root = factory.policy.anchor
    original_transport = transport.client._transport

    def complete_leaf_peer(request):
        if request.url.path == "/api/session" and request.url.params.get("limit") == "1":
            assert request.method == "GET" and request.url.params["order"] == "desc"
            parent = root.model_copy(update={"upstream_session_id": request.url.params["parentID"]})
            tree = state["metadata_tree"]
            return httpx.Response(
                200,
                json={
                    "data": [
                        copy.deepcopy(tree["rows"][ref])
                        for ref in tree["edges"].get(parent, [])[:1]
                    ],
                    "cursor": {},
                },
            )
        return original_transport.handler(request)

    transport.client._transport = httpx.MockTransport(complete_leaf_peer)
    try:
        original = factory.registry.selected(root)
        if running:
            state["active"][root.upstream_session_id] = {"type": "running"}
        assert await states(db) == []
        assert await controller.maintain_root(
            "realm",
            root.project_id,
            root,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        )
        saved = await controller.journal.recovery_records(
            "realm",
            root.project_id,
            lock_authority=AsyncMock(),
            current=lambda: True,
        )
        assert len(saved) == 1
        assert saved[0].state == "active" and saved[0].extension_count == 0
        assert saved[0].record.root == root and len(saved[0].record.nodes) == 1
        assert factory.registry.selected(root) is original
        assert (await factory.registry.snapshot(root)).state == (
            ExecutionState.RUNNING if running else ExecutionState.IDLE
        )
        assert not source.calls and not writes
        assert not await controller.maintain_root(
            "realm",
            root.project_id,
            root,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        )
        # A startup recovery must preserve the configured original entry;
        # factory.prepare cannot replace an already registered anchor.
        assert await controller.recover_project(
            "realm",
            root.project_id,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        ) == (root,)
        assert factory.registry.selected(root) is original
        tree = state["metadata_tree"]
        child = root.model_copy(update={"upstream_session_id": CHILD.upstream_session_id})
        row = copy.deepcopy(tree["rows"][TARGET])
        row.update(id=child.upstream_session_id, parentID=root.upstream_session_id, agent="task")
        row["time"]["created"] = 100
        tree["rows"][child] = row
        tree["edges"][root] = [child]
        state["resources"][child] = copy.deepcopy(state["resources"][TARGET])
        assert await controller.recover_project(
            "realm",
            root.project_id,
            authorize=AsyncMock(return_value=True),
            lock_authority=AsyncMock(),
        ) == (root,)
        assert factory.registry.selected(root) is original
        assert factory.registry.selected(child).reference == child
        saved = await controller.journal.recovery_records(
            "realm",
            root.project_id,
            lock_authority=AsyncMock(),
            current=lambda: True,
        )
        assert saved[0].state == "active" and saved[0].extension_count == 1
        assert len(saved[0].record.nodes) == 2
        assert not source.calls and not writes
    finally:
        await finish(anchor, transport)
