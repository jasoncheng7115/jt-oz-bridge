"""GET-only real adapters + encrypted ownSQLite; no Native/Human qualification."""

import asyncio
import copy
import json
import time
from dataclasses import replace
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import select, update

from jt_oz_bridge.adapters.opencode.model_settings import (
    MODEL_SETTING_SEMANTICS,
    ModelSettingsAttestation,
)
from jt_oz_bridge.domain.control import ExecutionState
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services.existing_session_updates import OriginalSessionGraphUpdates
from jt_oz_bridge.services.session_registration_journal import SessionRegistrationJournal
from jt_oz_bridge.storage.control_models import EnrolledBackend, EnrolledProject
from jt_oz_bridge.storage.durable import Conflict, DurableStore
from jt_oz_bridge.storage.fencing import ConsumerFence
from jt_oz_bridge.storage.models import Grant
from tests.contract.test_existing_session_factory import setup as factory_setup
from tests.contract.test_leaf_resources import finish
from tests.contract.test_lineage_resources import CHILD, GRANDCHILD, TARGET
from tests.contract.test_public_live_feed import REAL, REF, frame, text_delta
from tests.integration.test_session_registration_extension import raw_state


async def environment(db, *, root_settings=None, journal_initial=True):
    anchor, transport, factory, tree, state, writes, original_anchor = await factory_setup()
    saved = copy.deepcopy((tree["rows"], tree["edges"], state["resources"]))
    for ref in tuple(tree["rows"]):
        if ref != TARGET:
            del tree["rows"][ref]
            del state["resources"][ref]
    tree["edges"].clear()
    # The actual leaf codec uses an independent limit=1/desc presence query.
    old_transport = transport.client._transport

    def native_peer(request):
        if request.url.path == "/api/session" and request.url.params.get("limit") == "1":
            assert request.method == "GET" and request.url.params["order"] == "desc"
            parent = TARGET.model_copy(
                update={"upstream_session_id": request.url.params["parentID"]}
            )
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
        return old_transport.handler(request)

    transport.client._transport = httpx.MockTransport(native_peer)
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
        session.add(
            Grant(realm_id="realm", user_id=7, project_id=TARGET.project_id, role="operator")
        )
    holder = "synthetic-updates"
    fencing = await DurableStore(db).acquire_lease(holder, ttl=120)
    journal = SessionRegistrationJournal(db, ConsumerFence(holder, fencing))

    async def locked_authority(session):
        grant = await session.scalar(
            select(Grant)
            .where(Grant.active.is_(True), Grant.user_id == 7)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if grant is None:
            raise AccessDenied("synthetic_update_grant_revoked")

    async def authority():
        async with db.sessions.begin() as session:
            await locked_authority(session)
        return True

    candidate = await factory.prepare(TARGET, authorize=authority)
    if root_settings is not None:
        # Explicit synthetic installed root codec, before its first journal / publication.
        qualification = ModelSettingsAttestation(
            TARGET,
            factory.policy.contract_sha256,
            MODEL_SETTING_SEMANTICS,
            "b" * 64,
            qualification_scope=root_settings,
        )
        candidate.proofs.model_settings = qualification
        await candidate.proofs.watch_graph(authorize=authority)
        await candidate.entries[TARGET].execution.qualified_snapshot(TARGET)
    receipt = None

    async def save_initial(record):
        nonlocal receipt
        receipt = await journal.prepare(
            "realm",
            record,
            lock_authority=locked_authority,
            current=lambda: factory.observer.current(candidate.observation),
        )

    entries = await factory.commit(
        candidate, authorize=authority, before_commit=save_initial if journal_initial else None
    )
    if journal_initial:
        await journal.activate(
            receipt,
            lock_authority=locked_authority,
            current=lambda: factory.observer.current(candidate.observation),
        )
        previous = (
            await journal.recovery_records(
                "realm", TARGET.project_id, lock_authority=locked_authority, current=lambda: True
            )
        )[0]
    else:
        previous = None
    updates = OriginalSessionGraphUpdates(factory)
    return {
        "db": db,
        "anchor": anchor,
        "transport": transport,
        "factory": factory,
        "tree": tree,
        "state": state,
        "writes": writes,
        "saved": saved,
        "journal": journal,
        "locked": locked_authority,
        "authority": authority,
        "previous": previous,
        "updates": updates,
        "original_entries": entries,
        "original_anchor": original_anchor,
    }


def grow(env, *, grandchild=False):
    refs = [TARGET, CHILD, *([GRANDCHILD] if grandchild else [])]
    rows, edges, resources = env["saved"]
    for ref in refs:
        env["tree"]["rows"][ref] = copy.deepcopy(rows[ref])
        env["state"]["resources"][ref] = copy.deepcopy(resources[ref])
    env["tree"]["edges"] = {
        parent: [child for child in children if child in refs]
        for parent, children in edges.items()
        if parent in refs
    }


async def recover(env):
    return (
        await env["journal"].recovery_records(
            "realm", TARGET.project_id, lock_authority=env["locked"], current=lambda: True
        )
    )[0]


async def commit(env, candidate, *, previous=None, after_journal=None, activate=True):
    previous = previous or candidate.previous

    async def before_commit(record):
        if previous is None or record.graph_sha256 == previous.record.graph_sha256:
            result = await env["journal"].prepare(
                "realm",
                record,
                lock_authority=env["locked"],
                current=lambda: env["updates"].current(candidate),
            )
        else:
            result = await env["journal"].extend(
                previous,
                record,
                lock_authority=env["locked"],
                current=lambda: env["updates"].current(candidate),
            )
        if after_journal is not None:
            await after_journal()
        return result

    result = await env["updates"].commit(
        candidate, authorize=env["authority"], before_commit=before_commit
    )
    head = await recover(env)
    if activate:
        await env["journal"].activate(
            head.receipt,
            lock_authority=env["locked"],
            current=lambda: env["updates"].current(candidate),
        )
    return result


@pytest.mark.parametrize("running", [False, True])
async def test_real_leaf_child_grandchild_extension_retains_original_facades_and_no_native_write(
    db, running
):
    env = await environment(db)
    try:
        original = env["original_entries"][TARGET]
        proofs, guard = original.execution.proofs, original.execution.scope_guard
        policy = guard.enrollments[TARGET]
        baseline = env["previous"]
        grow(env)
        if running:
            env["state"]["active"][CHILD.upstream_session_id] = {"type": "running"}
        candidate = await env["updates"].prepare(TARGET, baseline, authorize=env["authority"])
        assert env["updates"].current(candidate)
        assert CHILD not in env["factory"].registry.sessions
        with pytest.raises(AccessDenied):
            env["factory"].registry.selected(CHILD)
        # New permanent facades are metadata-only until the cell publishes.
        with pytest.raises(ValueError):
            await candidate.entries[CHILD].execution.snapshot(CHILD)
        first = await commit(env, candidate)
        assert first[TARGET] is original
        assert original.execution.proofs is proofs and original.execution.scope_guard is guard
        assert guard.enrollments[TARGET] is policy
        assert env["updates"].current(candidate)
        snapshot = await env["factory"].registry.snapshot(CHILD)
        assert snapshot.state == (ExecutionState.RUNNING if running else ExecutionState.IDLE)
        previous = await recover(env)
        grow(env, grandchild=True)
        if running:
            env["state"]["active"][GRANDCHILD.upstream_session_id] = {"type": "running"}
        second = await env["updates"].prepare(TARGET, previous, authorize=env["authority"])
        entries = await commit(env, second)
        assert entries[TARGET] is original and entries[CHILD] is first[CHILD]
        assert original.execution.proofs is proofs and guard.enrollments[TARGET] is policy
        assert env["factory"].registry.selected(GRANDCHILD) is entries[GRANDCHILD]
        assert not env["updates"].current(candidate)
        assert (
            await env["updates"].prepare(TARGET, await recover(env), authorize=env["authority"])
            is None
        )
        assert not env["writes"] and all(
            request.method == "GET" for request in env["state"]["resource_calls"]
        )
        assert entries[CHILD].execution.attachments is None
        assert not entries[CHILD].execution.capabilities(CHILD)["check.run"].supported
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize("active", [TARGET, CHILD])
async def test_live_extension_accepts_continuous_original_ephemeral_text_without_replacing_readers(
    db, active
):
    env = await environment(db)
    try:
        root = env["factory"].registry.selected(TARGET)
        grow(env)
        env["state"]["active"][active.upstream_session_id] = {"type": "running"}
        fragments = 0

        def stream(request, state):
            nonlocal fragments
            if request.url.path == "/api/session/" + active.upstream_session_id:
                fragments += 1
                raw = json.loads(
                    json.dumps(text_delta(f"evt_update_live_{fragments}")).replace(
                        REF.upstream_session_id, active.upstream_session_id
                    )
                )
                env["factory"]._feed.index.accept(frame(raw))

        env["state"]["hook"] = stream
        candidate = await env["updates"].prepare(
            TARGET, env["previous"], authorize=env["authority"]
        )
        prepared_fragments = fragments
        entries = await commit(env, candidate)
        assert prepared_fragments > 1 and fragments > prepared_fragments
        assert entries[TARGET] is root and env["updates"].current(candidate)
        assert (await env["factory"].registry.snapshot(active)).state == ExecutionState.RUNNING
        assert not env["writes"] and all(
            request.method == "GET" for request in env["state"]["resource_calls"]
        )
        # A real interaction event remains a boundary even while text continues.
        raw = json.loads(
            json.dumps(REAL[0]).replace(REF.upstream_session_id, active.upstream_session_id)
        )
        env["factory"]._feed.index.accept(frame(raw))
        assert not env["updates"].current(candidate)
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize("fault", ["created", "policy", "qualification", "removed", "foreign"])
async def test_changed_original_identity_policy_or_scope_cannot_become_extension(db, fault):
    env = await environment(db)
    try:
        grow(env)
        if fault == "created":
            env["tree"]["rows"][TARGET]["time"]["created"] += 1
        elif fault == "policy":
            env["tree"]["rows"][TARGET]["permissions"] = []
        elif fault == "qualification":
            env["factory"].lineage = replace(env["factory"].lineage)
        elif fault == "removed":
            del env["tree"]["rows"][TARGET]
            env["tree"]["hook"] = lambda request, tree: (
                httpx.Response(404, json={"error": "fixture missing"})
                if request.url.path == "/api/session/" + TARGET.upstream_session_id
                else None
            )
        else:
            env["tree"]["rows"][CHILD]["location"] = {"directory": "/foreign"}
        before = await raw_state(db)
        with pytest.raises(ValueError):
            await env["updates"].prepare(TARGET, env["previous"], authorize=env["authority"])
        assert CHILD not in env["factory"].registry.sessions
        assert await raw_state(db) == before and not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


async def test_stale_complete_sql_head_cas_rejects_commit_without_partial_publication(db):
    env = await environment(db)
    try:
        grow(env)
        candidate = await env["updates"].prepare(
            TARGET, env["previous"], authorize=env["authority"]
        )
        refreshed = env["previous"].record.model_copy(update={"observed_at": time.time()})
        await env["journal"].prepare(
            "realm", refreshed, lock_authority=env["locked"], current=lambda: True
        )
        before = await raw_state(db)
        with pytest.raises(Conflict, match="predecessor_changed"):
            await commit(env, candidate)
        assert await raw_state(db) == before
        assert CHILD not in env["factory"].registry.sessions
        assert not env["updates"].current(candidate)
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize("when", ["before_prepare", "before_journal", "after_journal"])
async def test_live_sql_grant_revocation_never_publishes_or_invents_a_human(db, when):
    env = await environment(db)
    try:
        grow(env)
        candidate = (
            None
            if when == "before_prepare"
            else await env["updates"].prepare(TARGET, env["previous"], authorize=env["authority"])
        )

        async def revoke():
            async with db.sessions.begin() as session:
                await session.execute(update(Grant).values(active=False))

        if when != "after_journal":
            await revoke()
        with pytest.raises(AccessDenied):
            if when == "before_prepare":
                await env["updates"].prepare(TARGET, env["previous"], authorize=env["authority"])
            else:
                await commit(
                    env, candidate, after_journal=revoke if when == "after_journal" else None
                )
        assert CHILD not in env["factory"].registry.sessions and not env["writes"]
        # Inspect only the synthetic own head without pretending revoked authority.
        async with db.sessions() as session:
            from jt_oz_bridge.storage.session_registration_models import SessionRegistration

            row = (await session.scalars(select(SessionRegistration))).one()
            assert len(row.payload["nodes"]) == (2 if when == "after_journal" else 1)
            assert row.state == ("prepared" if when == "after_journal" else "active")
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize(
    "fault", ["cancel", "unknown_event", "policy", "reader", "feed_task", "late_head"]
)
async def test_post_journal_cancel_or_late_native_change_retains_prepared_recovery_without_publication(
    db, fault
):
    env = await environment(db)
    original_task = env["factory"]._feed.task
    try:
        grow(env)
        candidate = await env["updates"].prepare(
            TARGET, env["previous"], authorize=env["authority"]
        )
        original = env["factory"].registry.selected(TARGET)

        async def interrupt():
            if fault == "cancel":
                raise asyncio.CancelledError()
            if fault == "unknown_event":
                raw = json.loads(
                    json.dumps(REAL[0]).replace(
                        REF.upstream_session_id, "ses_unknown_pending_child"
                    )
                )
                env["factory"]._feed.index.accept(frame(raw))
            elif fault == "policy":
                original.execution.scope_guard.enrollments = dict(
                    original.execution.scope_guard.enrollments
                )
            elif fault == "reader":
                original.results.client = copy.copy(original.execution)
            elif fault == "feed_task":
                env["factory"]._feed.task = asyncio.create_task(asyncio.sleep(0))
                await env["factory"]._feed.task
            else:
                # Same resources, independent root baseline metadata publication:
                # the early whole-backend head must still reject the pending graph.
                registry = env["factory"].registry
                anchor_gen = registry.publication.generation(REF)
                detached = registry.publication.prepare_legacy(
                    REF, anchor_gen.entries, anchor_gen.parents
                )
                registry.publication.publish(detached)
                # A no-op does not advance a head; publish a real new leaf root.
                extra = TARGET.model_copy(update={"upstream_session_id": "ses_unrelated_root"})
                from tests.integration.test_session_registry import new_entry

                entry = new_entry(extra)
                registry.publication.publish(
                    registry.publication.prepare_legacy(extra, {extra: entry}, {extra: None})
                )

        with pytest.raises(asyncio.CancelledError if fault == "cancel" else ValueError):
            await commit(env, candidate, after_journal=interrupt)
        assert CHILD not in env["factory"].registry.sessions
        head = await recover(env)
        assert head.state == "prepared" and len(head.record.nodes) == 2
        assert not env["updates"].current(candidate) and not env["writes"]
    finally:
        env["factory"]._feed.task = original_task
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize("scope", ["session", "backend"])
async def test_model_settings_original_root_pin_is_preserved_without_borrowing_session_scope(
    db, scope
):
    env = await environment(db, root_settings=scope)
    try:
        original = env["original_entries"][TARGET]
        qualification = original.execution.proofs.model_settings
        grow(env)
        candidate = await env["updates"].prepare(
            TARGET, env["previous"], authorize=env["authority"]
        )
        assert candidate.context.proofs.model_settings is qualification
        assert candidate.context.proofs.model_settings_for(TARGET) is qualification
        expected = qualification if scope == "backend" else None
        assert candidate.context.proofs.model_settings_for(CHILD) is expected
        entries = await commit(env, candidate)
        assert original.execution.proofs.model_settings is qualification
        assert entries[CHILD].execution.proofs.model_settings is expected
        assert (entries[CHILD].execution.proofs is original.execution.proofs) == (
            scope == "backend"
        )
        assert not entries[CHILD].execution.policy_available(CHILD, "model.switch")
        assert entries[CHILD].results.client is entries[CHILD].execution
        assert not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


async def test_true_same_graph_legacy_baseline_is_published_without_an_extension_or_fake_receipt(
    db,
):
    env = await environment(db)
    try:
        registry = env["factory"].registry
        old = registry.publication.generation(TARGET)
        assert old.record is None and old.context is None
        candidate = await env["updates"].prepare(
            TARGET, env["previous"], authorize=env["authority"]
        )
        assert candidate.record.graph_sha256 == env["previous"].record.graph_sha256
        entries = await commit(env, candidate)
        actual = registry.publication.generation(TARGET)
        head = await recover(env)
        assert actual is not old and actual.context is candidate.context
        assert actual.entries[TARGET] is entries[TARGET] is env["original_entries"][TARGET]
        assert head.state == "active" and head.extension_count == 0
        assert head.record == candidate.record
        assert await env["updates"].prepare(TARGET, head, authorize=env["authority"]) is None
        assert not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


async def test_prepared_sql_extension_ahead_of_published_graph_is_reproved_and_published_without_replay(
    db,
):
    env = await environment(db)
    try:
        grow(env)
        first = await env["updates"].prepare(TARGET, env["previous"], authorize=env["authority"])
        entries = await commit(env, first)
        original_generation = env["factory"].registry.publication.generation(TARGET)
        previous = await recover(env)
        grow(env, grandchild=True)
        interrupted = await env["updates"].prepare(TARGET, previous, authorize=env["authority"])

        async def cancel_after_sql():
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await commit(env, interrupted, after_journal=cancel_after_sql)
        prepared = await recover(env)
        assert prepared.state == "prepared" and prepared.extension_count == 2
        assert env["factory"].registry.publication.generation(TARGET) is original_generation
        assert GRANDCHILD not in env["factory"].registry.sessions
        assert not env["updates"].current(interrupted)

        with pytest.raises(AccessDenied):
            await env["updates"].prepare(TARGET, prepared, authorize=AsyncMock(return_value=False))
        # A supposedly active SQL head cannot excuse a different live head.
        with pytest.raises(Conflict, match="historical_generation_changed"):
            await env["updates"].prepare(
                TARGET, replace(prepared, state="active"), authorize=env["authority"]
            )
        created = env["tree"]["rows"][GRANDCHILD]["time"]["created"]
        env["tree"]["rows"][GRANDCHILD]["time"]["created"] = created + 1
        with pytest.raises(Conflict):
            await env["updates"].prepare(TARGET, prepared, authorize=env["authority"])
        env["tree"]["rows"][GRANDCHILD]["time"]["created"] = created
        assert (await recover(env)).receipt == prepared.receipt
        assert env["factory"].registry.publication.generation(TARGET) is original_generation

        recovered = await env["updates"].prepare(TARGET, prepared, authorize=env["authority"])
        final = await commit(env, recovered)
        head = await recover(env)
        assert head.state == "active" and head.extension_count == 2
        assert final[TARGET] is entries[TARGET] and final[CHILD] is entries[CHILD]
        assert env["factory"].registry.selected(GRANDCHILD) is final[GRANDCHILD]
        assert head.receipt.revision > prepared.receipt.revision
        assert not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


async def test_published_prepared_journal_same_graph_refreshes_and_activates_without_replacing_readers(
    db,
):
    env = await environment(db)
    try:
        grow(env)
        first = await env["updates"].prepare(TARGET, env["previous"], authorize=env["authority"])
        entries = await commit(env, first, activate=False)
        saved = await recover(env)
        assert saved.state == "prepared" and saved.extension_count == 1
        old_generation = env["factory"].registry.publication.generation(TARGET)
        refresh = await env["updates"].prepare(TARGET, saved, authorize=env["authority"])
        assert refresh is not None and refresh.record.graph_sha256 == saved.record.graph_sha256
        new_entries = await commit(env, refresh)
        assert all(new_entries[ref] is entry for ref, entry in entries.items())
        head = await recover(env)
        assert head.state == "active" and head.extension_count == 1
        assert head.receipt.revision > saved.receipt.revision
        assert env["factory"].registry.publication.generation(TARGET) is not old_generation
        assert not env["updates"].current(first) and env["updates"].current(refresh)
        assert (
            len(
                await env["journal"].history(
                    head, lock_authority=env["locked"], current=lambda: True
                )
            )
            == 1
        )
        assert not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize(
    "fault", ["copy", "expires", "index", "truthy_authority", "native_policy", "wrong_receipt"]
)
async def test_unissued_expired_or_changed_candidate_never_runs_journal_or_publishes(db, fault):
    env = await environment(db)
    try:
        grow(env)
        candidate = await env["updates"].prepare(
            TARGET, env["previous"], authorize=env["authority"]
        )
        if fault == "copy":
            candidate = replace(candidate)
        elif fault == "expires":
            object.__setattr__(candidate, "expires_at", 0)
        elif fault == "index":
            env["factory"]._feed.index = copy.copy(env["factory"]._feed.index)
        elif fault == "native_policy":
            env["tree"]["rows"][CHILD]["permissions"] = []
        journal = AsyncMock(return_value=env["previous"].receipt)
        before = await raw_state(db)
        with pytest.raises(ValueError):
            await env["updates"].commit(
                candidate,
                authorize=AsyncMock(return_value=1)
                if fault == "truthy_authority"
                else env["authority"],
                before_commit=journal,
            )
        if fault != "wrong_receipt":
            journal.assert_not_awaited()
        else:
            journal.assert_awaited_once()
        assert CHILD not in env["factory"].registry.sessions
        assert await raw_state(db) == before and not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


@pytest.mark.parametrize("category", ["configured_anchor", "registered_original"])
@pytest.mark.parametrize("running", [False, True])
async def test_first_real_baseline_uses_original_entry_proofs_without_inventing_saved_receipt(
    db, category, running
):
    env = await environment(db, journal_initial=False)
    root = REF if category == "configured_anchor" else TARGET
    try:
        if running:
            env["state"]["active"][root.upstream_session_id] = {"type": "running"}
        original = env["factory"].registry.selected(root)
        candidate = await env["updates"].prepare_initial(root, authorize=env["authority"])
        assert candidate.previous is None
        assert candidate.entries[root] is original and len(candidate.record.nodes) == 1
        assert (
            await env["journal"].recovery_records(
                "realm", root.project_id, lock_authority=env["locked"], current=lambda: True
            )
            == ()
        )
        await commit(env, candidate)
        head = await recover(env)
        assert head.record.root == root and head.state == "active" and head.extension_count == 0
        assert env["factory"].registry.selected(root) is original
        assert not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


async def test_initial_leaf_with_new_unproven_child_is_not_given_a_fake_singleton_baseline(db):
    env = await environment(db, journal_initial=False)
    try:
        grow(env)
        with pytest.raises(ValueError):
            await env["updates"].prepare_initial(TARGET, authorize=env["authority"])
        assert env["factory"].registry.publication.generation(TARGET).record is None
        assert (
            await env["journal"].recovery_records(
                "realm", TARGET.project_id, lock_authority=env["locked"], current=lambda: True
            )
            == ()
        )
        assert CHILD not in env["factory"].registry.sessions and not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])


async def test_created_root_first_baseline_and_extension_keep_real_creation_ledger_and_entry(db):
    from jt_oz_bridge.adapters.opencode.existing_session_graph import V2ExistingSessionGraphObserver
    from jt_oz_bridge.adapters.opencode.existing_sessions import (
        ExistingSessionProtocol,
        V2ExistingSessionObserver,
    )
    from jt_oz_bridge.adapters.opencode.lineage_resources import (
        LINEAGE_SEMANTICS,
        LineageResourceAttestation,
    )
    from jt_oz_bridge.adapters.opencode.project_policy import POLICY_READS
    from jt_oz_bridge.adapters.opencode.resources import INSTALLED_SCHEMA, READS
    from jt_oz_bridge.domain.session_adoption import SessionAdoptionPolicy
    from jt_oz_bridge.services.existing_session_factory import V2ExistingSessionFactory
    from tests.integration.test_session_creation_activation import setup as creation_setup

    created = await creation_setup(db)
    try:
        await created["service"].reconcile(created["identity"])
        registry = created["factory"].registry
        root = TARGET.model_copy(
            update={"upstream_session_id": created["intent"].native_session_id}
        )
        original = registry.selected(root)
        provenance = created["factory"]._records[root]
        creation_action, creation_binding = await created["journal"].load(created["identity"])
        original_result = copy.deepcopy(creation_action.native_result)
        original_binding = (
            creation_binding.id,
            creation_binding.revision,
            creation_binding.session_id,
        )
        t = created["t"]
        protocol = ExistingSessionProtocol(
            REF.backend_id,
            REF.backend_identity,
            INSTALLED_SCHEMA,
            "e" * 64,
            POLICY_READS | {"session.list"},
        )
        observer = V2ExistingSessionGraphObserver(
            V2ExistingSessionObserver(created["anchor"].execution.scope_guard, protocol, REF)
        )
        policy = SessionAdoptionPolicy(
            anchor=REF,
            contract_sha256=INSTALLED_SCHEMA,
            installed_protocol_evidence_sha256="e" * 64,
            protocol_scope="backend",
            operations=frozenset({"prompt"}),
        )
        qualification = LineageResourceAttestation(
            REF.backend_id,
            REF.backend_identity,
            INSTALLED_SCHEMA,
            LINEAGE_SEMANTICS,
            "e" * 64,
            READS,
        )
        factory = V2ExistingSessionFactory(observer, registry, policy, lineage=qualification)
        updates = OriginalSessionGraphUpdates(factory)
        journal = SessionRegistrationJournal(db, created["journal"].fence)

        async def locked(session):
            assert (
                await session.scalar(
                    select(Grant).where(Grant.active.is_(True), Grant.user_id == 7)
                )
                is not None
            )

        async def authority():
            async with db.sessions.begin() as session:
                await locked(session)
            return True

        env = {"updates": updates, "journal": journal, "locked": locked, "authority": authority}
        baseline = await updates.prepare_initial(root, authorize=authority)
        assert baseline.previous is None and baseline.entries[root] is original
        await commit(env, baseline)
        child = root.model_copy(update={"upstream_session_id": "ses_created_root_original_child"})
        row = copy.deepcopy(created["state"]["info"])
        row.update(
            id=child.upstream_session_id,
            parentID=root.upstream_session_id,
            agent="task",
            outcome="succeeded",
        )
        row["time"] = {"created": 101, "updated": 110, "idle": 110}
        created["state"]["children"] = [row]
        previous_transport = t.client._transport

        def native_peer(request):
            if request.url.path == "/api/session/" + child.upstream_session_id:
                return httpx.Response(200, json={"data": copy.deepcopy(row)})
            if request.url.path == "/api/agent/task":
                agent = copy.deepcopy(created["d"]["agent.get"])
                agent["data"].update(id="task", mode="subagent")
                return httpx.Response(200, json=agent)
            if (
                request.url.path == "/api/session"
                and request.url.params.get("parentID") == child.upstream_session_id
            ):
                return httpx.Response(200, json={"data": [], "cursor": {}})
            if request.url.path.startswith("/api/session/" + child.upstream_session_id + "/"):
                suffix = request.url.path.rsplit("/", 1)[-1]
                value = {"data": []}
                if suffix == "message":
                    value = {
                        "data": [
                            {
                                "id": "msg_created_child_idle",
                                "type": "idle",
                                "time": {"created": 110},
                                "outcome": "succeeded",
                            }
                        ],
                        "cursor": {},
                    }
                return httpx.Response(200, json=value)
            return previous_transport.handler(request)

        t.client._transport = httpx.MockTransport(native_peer)
        candidate = await updates.prepare(root, await recover(env), authorize=authority)
        entries = await commit(env, candidate)
        assert entries[root] is original and registry.selected(child) is entries[child]
        assert created["factory"]._records[root] is provenance
        action, binding = await created["journal"].load(created["identity"])
        assert action.native_result == original_result
        assert (binding.id, binding.revision, binding.session_id) == original_binding
        assert not created["writes"] and all(
            request.method == "GET" for request in created["calls"]
        )
    finally:
        await finish(created["p"], created["t"])


@pytest.mark.parametrize("fault", ["revoked", "truthy", "replaced_guard", "late_unknown_event"])
async def test_first_baseline_current_authority_and_original_witness_are_not_optional(db, fault):
    env = await environment(db, journal_initial=False)
    try:
        calls = 0

        async def authorize():
            nonlocal calls
            calls += 1
            if fault == "revoked":
                return False
            if fault == "truthy":
                return 1
            return await env["authority"]()

        if fault == "replaced_guard":
            root = env["factory"].registry.selected(TARGET)
            root.execution.scope_guard.enrollments = dict(root.execution.scope_guard.enrollments)
        if fault == "late_unknown_event":
            lists_before = len(env["tree"]["list_calls"])

            async def with_event():
                result = await authorize()
                if len(env["tree"]["list_calls"]) > lists_before:
                    raw = json.loads(
                        json.dumps(REAL[0]).replace(
                            REF.upstream_session_id, "ses_initial_unknown_child"
                        )
                    )
                    env["factory"]._feed.index.accept(frame(raw))
                return result

            authority = with_event
        else:
            authority = authorize
        with pytest.raises(ValueError):
            await env["updates"].prepare_initial(TARGET, authorize=authority)
        assert calls >= 1 or fault == "replaced_guard"
        assert env["factory"].registry.publication.generation(TARGET).record is None
        assert (
            await env["journal"].recovery_records(
                "realm", TARGET.project_id, lock_authority=env["locked"], current=lambda: True
            )
            == ()
        )
        assert not env["writes"]
    finally:
        await finish(env["anchor"], env["transport"])
