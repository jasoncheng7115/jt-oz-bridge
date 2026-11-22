"""Actual composed created-Root restart using synthetic HTTP and real own ledgers.

No live Human or installed qualification; no Native create/fork/prompt writes.
"""

import asyncio
import copy
import logging
import time
from types import SimpleNamespace

import httpx
import pytest

from jt_oz_bridge.domain.session_adoption import RECORD_FORMAT
from jt_oz_bridge.security.policy import AccessDenied
from jt_oz_bridge.services import runtime_enrollment as module
from jt_oz_bridge.services.session_registration_journal import registration_key
from jt_oz_bridge.storage.durable import digest
from tests.contract.test_host_owner import evidence
from tests.contract.test_v2_catalog import native
from tests.integration.test_original_qualification_scope import (
    edited_manifest,
    old_rule,
    write_legacy_head,
)
from tests.integration.test_router import Source, message
from tests.integration.test_runtime_enrollment import (
    adoption_enrollment,
    configured_anchor_startup_peer,
    creation_enrollment,
)
from tests.integration.test_runtime_enrollment import (
    enrolled as enrolled,
)
from tests.integration.test_session_registration_extension import raw_state
from tests.support import SyntheticAudience

# Full Zulip audience reads during one restart that restores a created tree Root.
MAX_RESTART_ZULIP_READS = 6


async def test_actual_created_root_restart_restores_true_history_with_offline_child(
    enrolled, db, monkeypatch
):
    await _actual_created_restart(enrolled, db, monkeypatch)


@pytest.mark.parametrize(
    "scenario",
    [
        "same-head-restart",
        "same-head-cas",
        "no-metadata-head",
        "late-grant",
        "late-owner",
        "late-expiry",
        "head-cas",
        "grant-after-sql",
        "cancel-after-sql",
        "legacy-head",
        "legacy-head-child",
        "hung-restore",
        "anchor-child-restart",
        "compacted-notice",
        "forged-notice",
    ],
)
async def test_created_offline_recovery_preserves_ledger_cas_and_late_guards(
    enrolled, db, monkeypatch, scenario
):
    await _actual_created_restart(enrolled, db, monkeypatch, scenario=scenario)


async def test_tree_project_roots_keep_their_own_watches_across_pulses(
    enrolled, db, monkeypatch, caplog
):
    """A healthy tree Root was reported lost every 5 s and re-watched, forever.

    The watch keeper read a graph-published facade's own (stale) watch map while
    watch() and certification run on its active generation's provider.
    """

    async def after(second, graph, root, child):
        backend = second.backends[graph.root.backend_id]
        group = backend.resources[0].start.__self__
        cell = backend.registered.client.publication
        configured = next(item for item in group.roots if item.ref == graph.root)
        created = dict(group.created())[root]

        def watch(ref):
            return cell.generation(ref).context.proofs._watched.get(ref)

        async def pulses(count):
            for _ in range(count):
                for item in group.roots:
                    item.retry_at = 0
                group._created_retry.clear()
                await group.pulse()

        def logged():
            return [r.getMessage() for r in caplog.records if "root_watch_" in r.getMessage()]

        held = {graph.root: watch(graph.root), root: watch(root)}
        assert all(held.values())
        assert not configured.lost_watch() and created.holds_watch(root)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="jt_oz_bridge"):
            await pulses(4)
            assert not logged()
            assert all(watch(ref) is context for ref, context in held.items())
            # A real loss of one Root is still seen and restored, that Root alone. The
            # watch lives on the active generation's provider, so that is where it is lost.
            cell.generation(root).context.proofs.revoke_watch(root)
            assert not created.holds_watch(root) and not configured.lost_watch()
            await pulses(1)
            assert created.holds_watch(root) and watch(graph.root) is held[graph.root]
            assert watch(root) is not held[root]
            held[root] = watch(root)
            cell.generation(graph.root).context.proofs.revoke_watch(graph.root)
            assert configured.lost_watch() and created.holds_watch(root)
            await pulses(1)
            assert not configured.lost_watch() and watch(root) is held[root]
            assert logged() == [
                "root_watch_lost session=" + root.upstream_session_id,
                "root_watch_restored session=" + root.upstream_session_id,
                "root_watch_lost session=" + graph.root.upstream_session_id,
                "root_watch_restored session=" + graph.root.upstream_session_id,
            ]

    await _actual_created_restart(enrolled, db, monkeypatch, after=after)


async def test_a_restored_tree_root_reads_its_witness_from_the_active_generation(
    enrolled, db, monkeypatch
):
    """After a restart, finished turns of a chat-created tree Root must not be
    refused as unwatched ("no_witness"): the turn reader reads the active provider,
    not the graph-published facade's own empty witness map.
    """

    async def after(second, graph, root, child):
        backend = second.backends[graph.root.backend_id]
        group = backend.resources[0].start.__self__
        cell = backend.registered.client.publication
        created = dict(group.created())[root]
        active = cell.generation(root).context.proofs.witnesses.get(root)
        assert active is not None and created.witnesses.get(root) is None
        assert created.current_witness(root) is active

    await _actual_created_restart(enrolled, db, monkeypatch, after=after)


async def test_tree_created_restart_reads_zulip_in_full_only_a_bounded_number_of_times(
    enrolled, db, monkeypatch
):
    """A full Zulip check is slow enough that dozens of them would outlive the 5 s windows."""
    counted = {"inspect": None}

    def before_restart(audience):
        original = audience.inspect
        counted["inspect"] = 0

        async def inspect(*args):
            counted["inspect"] += 1
            return await original(*args)

        audience.inspect = inspect

    async def after(second, graph, root, child):
        assert root in second.backends[graph.root.backend_id].registered.client.sessions
        assert counted["inspect"] <= MAX_RESTART_ZULIP_READS

    await _actual_created_restart(
        enrolled, db, monkeypatch, after=after, before_restart=before_restart
    )


async def _actual_created_restart(
    enrolled, db, monkeypatch, *, scenario="normal", after=None, before_restart=None
):

    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    certificate = creation_enrollment(enrolled)
    owner = evidence(backend_id=graph.root.backend_id, backend_identity=graph.root.backend_identity)
    certificate.request["intent"]["owner_epoch"] = owner["owner_epoch"]
    certificate.request["intent_sha256"] = digest(certificate.request["intent"])
    certificate.certificate["owner_epoch"] = owner["owner_epoch"]
    certificate.certificate["request_record"] = enrolled.pin(
        "create-request.json", certificate.request
    )
    certificate.qualification["rpc_evidence"] = enrolled.pin(
        "creation-rpc.json", certificate.certificate
    )
    # The independent adoption pin must include the final reviewed operation set.
    adoption_enrollment(enrolled, lineage="tree")
    value, sha = module.read_enrollment(enrolled.settings)
    state = {"root": None, "row": None, "offline_child": False, "calls": []}
    child = graph.root.model_copy(update={"upstream_session_id": "ses_created_offline_child"})
    original_transport = module.V2HTTPTransport

    def transport(*args, **kwargs):
        client = original_transport(*args, **kwargs)
        peer = client.client._transport

        def handle(request):
            state["calls"].append(request)
            assert request.method == "GET", "restart must never recreate or prompt Native"
            root, row = state["root"], state["row"]
            if root is None:
                return peer.handler(request)
            child_row = copy.deepcopy(row)
            child_row.update(
                id=child.upstream_session_id,
                parentID=root.upstream_session_id,
                agent="task",
                outcome="succeeded",
                time={"created": 101, "updated": 110, "idle": 110},
            )
            if request.url.path == "/api/session/" + root.upstream_session_id:
                return httpx.Response(200, json={"data": copy.deepcopy(row)})
            if request.url.path == "/api/session/" + child.upstream_session_id:
                return httpx.Response(200, json={"data": child_row})
            if (
                request.url.path == "/api/session"
                and request.url.params["parentID"] == root.upstream_session_id
            ):
                return httpx.Response(
                    200, json={"data": [child_row] if state["offline_child"] else [], "cursor": {}}
                )
            if (
                request.url.path == "/api/session"
                and request.url.params["parentID"] == child.upstream_session_id
            ):
                return httpx.Response(200, json={"data": [], "cursor": {}})
            if request.url.path == "/api/agent/task":
                agent = copy.deepcopy(graph.data["agent.get"])
                agent["data"].update(id="task", mode="subagent")
                return httpx.Response(200, json=agent)
            for ref in (root, child):
                if request.url.path.startswith("/api/session/" + ref.upstream_session_id + "/"):
                    response = {"data": []}
                    if request.url.path.endswith("/message"):
                        response["cursor"] = {}
                        if ref == child:
                            response["data"] = [
                                {
                                    "id": "msg_created_offline_idle",
                                    "type": "idle",
                                    "time": {"created": 110},
                                    "outcome": "succeeded",
                                }
                            ]
                    return httpx.Response(200, json=response)
            return peer.handler(request)

        client.client._transport = httpx.MockTransport(handle)
        return client

    monkeypatch.setattr(module, "V2HTTPTransport", transport)
    source, audience = Source(), SyntheticAudience()
    audience.users = frozenset({8})

    def build():
        pipeline = module.build_pipeline(
            enrolled.settings, value, sha, db, module.ConsumerFence(graph.holder, graph.epoch)
        )
        # Synthetic authority is confined to this ownDB/HTTP fixture. The real
        # coordinator, ledger, activation, factory and startup resources remain.
        pipeline.bindings.audience = audience
        pipeline.creation.journal.reader = source
        return pipeline

    first, second = build(), None
    try:
        backend = first.backends[graph.root.backend_id]
        await backend.resources[0].start()
        service = first.creation
        journal = service.journal
        offered = message(
            "!oz projects",
            100,
            realm_id="2",
            channel_id=4,
            author_id=8,
            topic="Created offline original",
        )
        source.messages[100] = offered
        token = await journal.offer(graph.root.project_id, offered)
        command = message(
            "!oz new " + token + " Created offline original",
            101,
            realm_id="2",
            channel_id=4,
            author_id=8,
            topic=offered.topic,
        )
        source.messages[101] = command
        identity = await journal.reserve(command, "en")
        claim = await journal.claim(identity)
        assert claim is not None
        action, binding, _ = claim
        _, intent, _ = journal.payload(action, binding)
        factory = service.factories[graph.root.project_id]
        state["root"] = root = graph.root.model_copy(
            update={"upstream_session_id": intent.native_session_id}
        )
        state["row"] = native(
            **factory.creator.body(intent),
            projectID="global",
            time={"created": 100, "updated": 100},
        )
        candidate = await factory.creator.observe(intent)
        assert await journal.record(action, factory.creator, candidate) == "admitted"
        await service.reconcile(identity)
        if scenario != "no-metadata-head":
            await first.restore_adopted()
            for resource in backend.post_restoration_resources:
                await resource.start()
        authority = first.graph_authority(graph.root.project_id)
        saved = await first.adoption.journal.recovery_records(
            "2", graph.root.project_id, lock_authority=authority[1], current=lambda: True
        )
        if scenario == "no-metadata-head":
            # A genuine completed creation can crash before its first metadata
            # baseline; no historical graph or SavedRegistration is fabricated.
            assert not any(record.record.root == root for record in saved)
        else:
            historical = next(record for record in saved if record.record.root == root)
            assert historical.state == "active" and len(historical.record.nodes) == 1
        action, binding = await journal.load(identity)
        assert action.state == "completed" and binding.state == "active"
        original_intent = copy.deepcopy(action.payload["intent"])
        original_native_result = copy.deepcopy(action.native_result)
        original_binding = (binding.id, binding.revision, binding.session_id)
        before_restart_calls = len(state["calls"])
        legacy = old_rule(first.adoption.factories[graph.root.project_id])
        await graph.close(first)

        # No fabricated SavedRegistration: the actual authenticated ledger and
        # first graph head survive while only the synthetic Native tree grows.
        state["offline_child"] = True
        if scenario.startswith("anchor-child"):
            # Only the anchor ran a subagent; the created Root itself stays childless.
            state["offline_child"] = False
            graph.state["child"] = True
        if scenario in {"compacted-notice", "forged-notice"}:
            # A week after delivery, retention keeps only a tombstone of each page.
            forged = await _compact_notice(db, graph, action, forge=scenario == "forged-notice")
        if scenario.startswith("legacy"):
            # Both heads as an older release wrote them, then any manifest edit.
            await write_legacy_head(db, legacy)
            state["offline_child"] = scenario == "legacy-head-child"
            value, sha = edited_manifest(enrolled)
        if before_restart is not None:
            before_restart(audience)
        second = build()
        assert root not in second.backends[graph.root.backend_id].registered.client.sessions
        graph_factory = second.adoption.factories[graph.root.project_id]
        metadata = second.adoption.journal
        if scenario in {"late-grant", "late-owner"}:
            observe = graph_factory.prepare_record

            async def changed_after_observation(*args, **kwargs):
                candidate = await observe(*args, **kwargs)
                if scenario == "late-owner":
                    graph.state["owner"] = True
                else:
                    from sqlalchemy import update

                    from jt_oz_bridge.storage.models import Grant

                    async with db.sessions.begin() as session:
                        await session.execute(update(Grant).values(active=False))
                return candidate

            monkeypatch.setattr(graph_factory, "prepare_record", changed_after_observation)
        elif scenario == "late-expiry":
            from jt_oz_bridge.services import created_root_factory as factory_module

            created = second.creation.factories[graph.root.project_id]
            publish = created.publish_restore

            def expired_before_publish(stage, candidate):
                expiry = created._restore_stages[stage].expires_at
                monkeypatch.setattr(factory_module, "time", SimpleNamespace(time=lambda: expiry))
                return publish(stage, candidate)

            monkeypatch.setattr(created, "publish_restore", expired_before_publish)
        elif scenario == "hung-restore":
            # A Native read that never answers is cut by the restore's own 5 s window.
            created = second.creation.factories[graph.root.project_id]

            async def hung(*args, **kwargs):
                await asyncio.Event().wait()

            monkeypatch.setattr(created.creator, "observe_existing", hung)
        elif scenario in {"head-cas", "grant-after-sql", "cancel-after-sql"}:
            extend = metadata.extend

            async def changed_at_sql(previous, record, **kwargs):
                if scenario == "head-cas":
                    # A genuine competing metadata prepare supersedes this
                    # authenticated expected head under the same consumer fence.
                    await metadata.prepare(
                        "2",
                        previous.record,
                        lock_authority=kwargs["lock_authority"],
                        current=lambda: True,
                    )
                    return await extend(previous, record, **kwargs)
                result = await extend(previous, record, **kwargs)
                if scenario == "grant-after-sql":
                    from sqlalchemy import update

                    from jt_oz_bridge.storage.models import Grant

                    async with db.sessions.begin() as session:
                        await session.execute(update(Grant).values(active=False))
                    return result
                raise asyncio.CancelledError("controlled after real SQL commit")

            monkeypatch.setattr(metadata, "extend", changed_at_sql)
        if scenario in {
            "legacy-head-child",
            "late-expiry",
            "head-cas",
            "hung-restore",
            "forged-notice",
        }:
            # Only this created Root fails: it alone stays unregistered (never
            # adopted under the project's policy) and the Bridge still starts.
            key = registration_key("2", root)
            before = [row for row in (await raw_state(db))[0] if key in tuple(row)]
            assert len(before) == 1
            names = await graph.start(second)
            assert "zulip-consumer" in names
            registered = second.backends[graph.root.backend_id].registered.client
            assert root not in registered.sessions and graph.root in registered.sessions
            assert second.creation.unrestored_roots() == frozenset({root})
            assert not second.creation.factories[graph.root.project_id]._records
            assert not graph.writes
            if scenario == "legacy-head-child":
                # Its head was not resealed, extended or adopted either.
                assert [row for row in (await raw_state(db))[0] if key in tuple(row)] == before
                # Once the topic is unbound, the retry drops it instead of failing.
                from sqlalchemy import update

                from jt_oz_bridge.storage.control_models import Binding

                async with db.sessions.begin() as session:
                    await session.execute(
                        update(Binding)
                        .where(Binding.id == original_binding[0])
                        .values(state="unbound")
                    )
                second.creation._retry_at.clear()
                await second.creation.retry_restores()
                assert not second.creation.unrestored_roots()
                assert root not in registered.sessions
                return
            # The fault passes: a later GET-only retry restores the same Root.
            if scenario == "late-expiry":
                monkeypatch.setattr(factory_module, "time", time)
                monkeypatch.delattr(created, "publish_restore")
            elif scenario == "hung-restore":
                monkeypatch.delattr(created.creator, "observe_existing")
            elif scenario == "forged-notice":
                await forged()
            else:
                monkeypatch.delattr(metadata, "extend")
            second.creation._retry_at.clear()
            await second.creation.retry_restores()
            assert root in registered.sessions and not second.creation.unrestored_roots()
            snapshot = await registered.snapshot(root)
            assert snapshot.reference == root and snapshot.reconciled
            assert all(request.method == "GET" for request in state["calls"])
            assert not graph.writes
            return
        if scenario in {
            "late-grant",
            "late-owner",
            "grant-after-sql",
            "cancel-after-sql",
        }:
            expected_error = (
                asyncio.CancelledError
                if scenario == "cancel-after-sql"
                else (ValueError, AccessDenied)
            )
            with pytest.raises(expected_error):
                await graph.start(second)
            assert root not in second.backends[graph.root.backend_id].registered.client.sessions
            assert not second.creation.factories[graph.root.project_id]._records
            current_action, current_binding = await second.creation.journal.load(identity)
            assert current_action.payload["intent"] == original_intent
            assert current_action.native_result == original_native_result
            assert (
                current_binding.id,
                current_binding.revision,
                current_binding.session_id,
            ) == original_binding
            assert not graph.writes
            if scenario != "cancel-after-sql":
                return
            # This reads the real sealed prepared head produced by extend(),
            # then exercises a brand-new composed startup, not a fake receipt.
            authority = second.graph_authority(graph.root.project_id)
            prepared_heads = await metadata.recovery_records(
                "2", graph.root.project_id, lock_authority=authority[1], current=lambda: True
            )
            prepared_head = next(row for row in prepared_heads if row.record.root == root)
            assert prepared_head.state == "prepared" and len(prepared_head.record.nodes) == 2
            await graph.close(second)
            second = build()
        names = await graph.start(second)
        if scenario == "anchor-child-restart":
            # The anchor's head now holds its child; the next startup reads it as saved.
            assert root in second.backends[graph.root.backend_id].registered.client.sessions
            await graph.close(second)
            second = build()
            names = await graph.start(second)
            assert not second.creation.unrestored_roots()
        if scenario in {"same-head-restart", "same-head-cas"}:
            authority = second.graph_authority(graph.root.project_id)
            current_heads = await second.adoption.journal.recovery_records(
                "2", graph.root.project_id, lock_authority=authority[1], current=lambda: True
            )
            before_head = next(row for row in current_heads if row.record.root == root)
            await graph.close(second)
            second = build()
            if scenario == "same-head-cas":
                current_journal = second.adoption.journal
                prepare = current_journal.prepare
                competing_authority = second.graph_authority(graph.root.project_id)

                async def competing_prepare(*args, **kwargs):
                    # A distinct legitimate metadata operation supersedes the
                    # head once. Do not reuse/consume the controller's closure.
                    monkeypatch.setattr(current_journal, "prepare", prepare)
                    await prepare(
                        "2",
                        before_head.record,
                        lock_authority=competing_authority[1],
                        current=lambda: True,
                    )
                    return await prepare(*args, **kwargs)

                monkeypatch.setattr(current_journal, "prepare", competing_prepare)
                # The superseded head fails this created Root alone; it stays
                # unregistered and the Bridge still starts.
                names = await graph.start(second)
                assert "zulip-consumer" in names
                assert root not in second.backends[graph.root.backend_id].registered.client.sessions
                assert second.creation.unrestored_roots() == frozenset({root})
                assert not second.creation.factories[graph.root.project_id]._records
                return
            names = await graph.start(second)
            authority = second.graph_authority(graph.root.project_id)
            after_heads = await second.adoption.journal.recovery_records(
                "2", graph.root.project_id, lock_authority=authority[1], current=lambda: True
            )
            after_head = next(row for row in after_heads if row.record.root == root)
            assert (
                after_head.state == "active"
                and after_head.receipt.revision > before_head.receipt.revision
            )
            assert after_head.extension_count == before_head.extension_count

        assert names.index("session-restoration") < names.index("original-session-restoration")
        restored = second.backends[graph.root.backend_id].registered.client
        entry = restored.selected(root)
        refs = (root, child) if state["offline_child"] else (root,)
        if scenario == "legacy-head":
            authority = second.graph_authority(graph.root.project_id)
            resealed = await second.adoption.journal.recovery_records(
                "2", graph.root.project_id, lock_authority=authority[1], current=lambda: True
            )
            assert len(resealed) == 2 and child not in restored.sessions
            assert all(
                head.state == "active" and head.record.format == RECORD_FORMAT for head in resealed
            )
            assert historical.receipt.identity_hash in {
                head.receipt.identity_hash for head in resealed
            }
        elif state["offline_child"]:
            assert restored.selected(child).reference == child
        for ref in refs:
            snapshot = await restored.snapshot(ref)
            assert snapshot.reference == ref and snapshot.reconciled
            assert await restored.pending(ref) == ()
            transcript = await restored.transcripts[ref].snapshot(ref)
            assert transcript.reference == ref and transcript.reconciled
        if scenario == "normal":
            before_repeat = len(state["calls"])
            with pytest.raises(ValueError, match="original_recovery_composition"):
                second.creation.configure_graph_recovery(second.adoption, second.graph_authority)
            assert len(state["calls"]) == before_repeat
        assert entry.reference.upstream_session_id == intent.native_session_id
        second.creation.factories[graph.root.project_id].registered(intent, candidate, entry)
        current_action, current_binding = await second.creation.journal.load(identity)
        assert current_action.payload["intent"] == original_intent
        assert current_action.native_result == original_native_result
        assert (
            current_binding.id,
            current_binding.revision,
            current_binding.session_id,
        ) == original_binding
        assert all(request.method == "GET" for request in state["calls"][before_restart_calls:])
        assert not graph.writes
        if after is not None:
            await after(second, graph, root, child)
    finally:
        await graph.close(second or first)
        await graph.store.release_lease(graph.holder, graph.epoch)


async def _compact_notice(db, graph, action, *, forge=False):
    from sqlalchemy import select, update

    from jt_oz_bridge.config import Retention
    from jt_oz_bridge.services.retention import DAY, RetentionExecutor
    from jt_oz_bridge.storage.models import Delivery

    batch = action.native_result["activation"]["notice_batch_id"]
    old = time.time() - 8 * DAY
    async with db.sessions.begin() as session:
        await session.execute(
            update(Delivery)
            .where(Delivery.batch_id == batch)
            .values(state="delivered", posted_message_id=9001, updated_at=old)
        )
    retention = RetentionExecutor(
        db, module.ConsumerFence(graph.holder, graph.epoch), Retention(), batch_size=1000
    )
    for _ in range(8):  # One sweep scans one category first; cover all of them.
        await retention.sweep()
    async with db.sessions() as session:
        rows = (await session.scalars(select(Delivery).where(Delivery.batch_id == batch))).all()
    assert rows and all(row.payload_compacted_at is not None for row in rows)
    assert all(set(row.payload) >= {"original_hash", "compacted_at"} for row in rows)
    if not forge:
        return None
    # A tombstone that no longer names the page's original hash is not the notice.
    first, tombstone = rows[0].id, rows[0].payload

    async def write(payload):
        async with db.sessions.begin() as session:
            row = await session.get(Delivery, first)
            row.payload = payload

    await write({**tombstone, "original_hash": "0" * 64})

    async def restore():
        await write(tombstone)

    return restore


@pytest.mark.parametrize("scenario", ["first-baseline", "revoked", "unknown-child"])
async def test_created_after_composition_first_baseline_preserves_original_authority(
    enrolled, db, monkeypatch, scenario
):
    graph = await configured_anchor_startup_peer(enrolled, db, monkeypatch)
    certificate = creation_enrollment(enrolled)
    owner = evidence(backend_id=graph.root.backend_id, backend_identity=graph.root.backend_identity)
    certificate.request["intent"]["owner_epoch"] = owner["owner_epoch"]
    certificate.request["intent_sha256"] = digest(certificate.request["intent"])
    certificate.certificate["owner_epoch"] = owner["owner_epoch"]
    certificate.certificate["request_record"] = enrolled.pin(
        "create-request.json", certificate.request
    )
    certificate.qualification["rpc_evidence"] = enrolled.pin(
        "creation-rpc.json", certificate.certificate
    )
    # The independent adoption pin must include the final reviewed operation set.
    adoption_enrollment(enrolled, lineage="tree")
    value, sha = module.read_enrollment(enrolled.settings)
    state = {"root": None, "row": None, "offline_child": False, "calls": []}
    child = graph.root.model_copy(update={"upstream_session_id": "ses_created_offline_child"})
    original_transport = module.V2HTTPTransport

    def transport(*args, **kwargs):
        client = original_transport(*args, **kwargs)
        peer = client.client._transport

        def handle(request):
            state["calls"].append(request)
            assert request.method == "GET", "restart must never recreate or prompt Native"
            root, row = state["root"], state["row"]
            if root is None:
                return peer.handler(request)
            child_row = copy.deepcopy(row)
            child_row.update(
                id=child.upstream_session_id,
                parentID=root.upstream_session_id,
                agent="task",
                outcome="succeeded",
                time={"created": 101, "updated": 110, "idle": 110},
            )
            if request.url.path == "/api/session/" + root.upstream_session_id:
                return httpx.Response(200, json={"data": copy.deepcopy(row)})
            if request.url.path == "/api/session/" + child.upstream_session_id:
                return httpx.Response(200, json={"data": child_row})
            if (
                request.url.path == "/api/session"
                and request.url.params["parentID"] == root.upstream_session_id
            ):
                return httpx.Response(
                    200, json={"data": [child_row] if state["offline_child"] else [], "cursor": {}}
                )
            if (
                request.url.path == "/api/session"
                and request.url.params["parentID"] == child.upstream_session_id
            ):
                return httpx.Response(200, json={"data": [], "cursor": {}})
            if request.url.path == "/api/agent/task":
                agent = copy.deepcopy(graph.data["agent.get"])
                agent["data"].update(id="task", mode="subagent")
                return httpx.Response(200, json=agent)
            for ref in (root, child):
                if request.url.path.startswith("/api/session/" + ref.upstream_session_id + "/"):
                    response = {"data": []}
                    if request.url.path.endswith("/message"):
                        response["cursor"] = {}
                        if ref == child:
                            response["data"] = [
                                {
                                    "id": "msg_created_offline_idle",
                                    "type": "idle",
                                    "time": {"created": 110},
                                    "outcome": "succeeded",
                                }
                            ]
                    return httpx.Response(200, json=response)
            return peer.handler(request)

        client.client._transport = httpx.MockTransport(handle)
        return client

    monkeypatch.setattr(module, "V2HTTPTransport", transport)
    source, audience = Source(), SyntheticAudience()
    audience.users = frozenset({8})

    def build():
        pipeline = module.build_pipeline(
            enrolled.settings, value, sha, db, module.ConsumerFence(graph.holder, graph.epoch)
        )
        # Synthetic authority is confined to this ownDB/HTTP fixture. The real
        # coordinator, ledger, activation, factory and startup resources remain.
        pipeline.bindings.audience = audience
        pipeline.creation.journal.reader = source
        return pipeline

    first = build()
    try:
        backend = first.backends[graph.root.backend_id]
        await backend.resources[0].start()
        service = first.creation
        journal = service.journal
        offered = message(
            "!oz projects",
            100,
            realm_id="2",
            channel_id=4,
            author_id=8,
            topic="Created offline original",
        )
        source.messages[100] = offered
        token = await journal.offer(graph.root.project_id, offered)
        command = message(
            "!oz new " + token + " Created offline original",
            101,
            realm_id="2",
            channel_id=4,
            author_id=8,
            topic=offered.topic,
        )
        source.messages[101] = command
        identity = await journal.reserve(command, "en")
        claim = await journal.claim(identity)
        assert claim is not None
        action, binding, _ = claim
        _, intent, _ = journal.payload(action, binding)
        factory = service.factories[graph.root.project_id]
        state["root"] = root = graph.root.model_copy(
            update={"upstream_session_id": intent.native_session_id}
        )
        state["row"] = native(
            **factory.creator.body(intent),
            projectID="global",
            time={"created": 100, "updated": 100},
        )
        candidate = await factory.creator.observe(intent)
        assert await journal.record(action, factory.creator, candidate) == "admitted"
        await service.reconcile(identity)

        registry = backend.registered.client
        original_entry = registry.selected(root)
        original_execution = original_entry.execution
        original_proofs, original_guard = original_execution.proofs, original_execution.scope_guard
        original_policy = original_guard.enrollments[root]
        updates = first.adoption.updates[root.project_id]
        assert getattr(original_proofs, "_graph_publication", None) is None
        assert registry.publication.generation(root).record is None
        if scenario == "revoked":
            from sqlalchemy import update

            from jt_oz_bridge.security.policy import AccessDenied
            from jt_oz_bridge.storage.models import Grant

            async with db.sessions.begin() as session:
                await session.execute(update(Grant).where(Grant.user_id == 8).values(active=False))
            authorize, _ = first.graph_authority(root.project_id)
            with pytest.raises(AccessDenied):
                await updates.prepare_initial(root, authorize=authorize)
            # No attach or first baseline can bypass failed current authority.
            assert getattr(original_proofs, "_graph_publication", None) is None
        elif scenario == "unknown-child":
            from jt_oz_bridge.adapters.opencode.contracts import ContractError

            state["offline_child"] = True
            authorize, _ = first.graph_authority(root.project_id)
            with pytest.raises(ContractError, match="leaf_descendants_require_qualification"):
                await updates.prepare_initial(root, authorize=authorize)
            assert child not in registry.sessions
            assert registry.publication.generation(root).record is None
        else:
            await first.restore_adopted()
            published = registry.publication.generation(root)
            assert published.record is not None and len(published.record.nodes) == 1
            authorize, locked = first.graph_authority(root.project_id)
            assert await authorize() is True
            saved = await first.adoption.journal.recovery_records(
                "2", root.project_id, lock_authority=locked, current=lambda: True
            )
            historical = next(item for item in saved if item.record.root == root)
            assert historical.state == "active" and len(historical.record.nodes) == 1
            assert getattr(original_proofs, "_graph_publication", None) is not None
        assert registry.selected(root) is original_entry
        assert original_entry.execution is original_execution
        assert original_execution.proofs is original_proofs
        assert original_execution.scope_guard is original_guard
        assert original_guard.enrollments[root] is original_policy
        if scenario != "first-baseline":
            from sqlalchemy import select

            from jt_oz_bridge.storage.session_registration_models import SessionRegistration

            async with db.sessions() as session:
                assert not await session.scalar(
                    select(SessionRegistration.key).where(
                        SessionRegistration.key
                        == digest({"realm_id": "2", "root": root.model_dump(mode="json")})
                    )
                )
        loaded_action, loaded_binding = await journal.load(identity)
        assert loaded_action.state == "completed" and loaded_binding.state == "active"
        factory.registered(intent, candidate, original_entry)
        assert all(request.method == "GET" for request in state["calls"])
        assert not graph.writes
    finally:
        await graph.close(first)
        await graph.store.release_lease(graph.holder, graph.epoch)
